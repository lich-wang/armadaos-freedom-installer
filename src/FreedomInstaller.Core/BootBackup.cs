using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

namespace FreedomInstaller.Core;

/// <summary>Expected size and hash of one boot partition slot as declared by the caller.</summary>
public record BootSlotDescriptor(string Slot, long Length, string Sha256);

/// <summary>Backup request: identity, destination root and exactly the two named boot slots.</summary>
public record BootBackupRequest(DeviceIdentity Identity, string DestinationRoot, IReadOnlyList<BootSlotDescriptor> Slots);

/// <summary>
/// What the backed up bytes say about the slot they came from. <see cref="Unknown"/> is the default and
/// only means "not all zero"; it is never a claim that the backup is stock or bootable. All-0xFF content is
/// deliberately left <see cref="Unknown"/> instead of being given a guessed meaning.
/// </summary>
public enum BootContentState
{
    Unknown = 0,
    Empty = 1,
}

/// <summary>Metadata of one raw backup file; raw bytes only, not proof of stock/bootable content.</summary>
public record BootBackupRecord(string Slot, string FileName, long Length, string Sha256)
{
    /// <summary>All-zero content seen while streaming; every other file stays <see cref="BootContentState.Unknown"/>.</summary>
    public BootContentState ContentState { get; init; } = BootContentState.Unknown;

    /// <summary>Always false: a raw copy of unexamined bytes does not prove the slot version or format is recoverable.</summary>
    public bool RecoveryUsable => false;
}

/// <summary>Backup outcome: directory, completion flag, per-slot records and an optional error.</summary>
public record BootBackupResult(string Directory, bool IsComplete, IReadOnlyList<BootBackupRecord> Records, string? Error);

/// <summary>Read-only access to boot slot content; the only external I/O of the backup flow.</summary>
public interface IBootReader
{
    Task<Stream> OpenReadAsync(string slot, CancellationToken cancellationToken = default);
}

/// <summary>
/// Raw backup of the two boot slots. The request is validated before any directory or reader work,
/// slots are copied sequentially into a fresh unique subdirectory while length and SHA-256 are checked
/// in flight, and every written file is then reopened read-only and re-checked on disk, so a record is
/// only added for bytes that really reached the file. backup.json is marked complete only after both
/// slots verify on disk. Nothing here reads or writes userdata, deletes earlier backups, or infers
/// stock/bootable content from the bytes.
/// </summary>
public static class BootBackup
{
    private const string SlotA = "a";
    private const string SlotB = "b";
    private const string BootAFileName = "boot_a.img";
    private const string BootBFileName = "boot_b.img";
    private const string ManifestFileName = "backup.json";
    private const string TempManifestSuffix = ".tmp";
    private const string DirectoryPrefix = "bootbackup-";
    private const string CancelledError = "boot backup was cancelled; the backup directory stays incomplete.";
    private const int CopyBufferSize = 64 * 1024;

    private static readonly JsonSerializerOptions ManifestJson =
        new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static async Task<BootBackupResult> CreateAsync(
        BootBackupRequest request,
        IBootReader reader,
        CancellationToken cancellationToken = default)
    {
        // Caller cancellation first: a cancelled caller must not even validate-then-touch the disk.
        cancellationToken.ThrowIfCancellationRequested();
        Validate(request, reader);

        var destinationRoot = Path.GetFullPath(request.DestinationRoot);
        var backupDirectory = CreateUniqueBackupDirectory(destinationRoot);
        var manifestPath = Path.Combine(backupDirectory, ManifestFileName);
        var records = new List<BootBackupRecord>(2);

        try
        {
            // Incomplete manifest first: a failure mid-copy must never look like a finished backup.
            WriteManifest(manifestPath, request.Identity, records, isComplete: false, error: null);

            foreach (var descriptor in request.Slots.OrderBy(s => s.Slot == SlotA ? 0 : 1))
            {
                cancellationToken.ThrowIfCancellationRequested();
                records.Add(await CopyAndVerifySlotAsync(descriptor, reader, backupDirectory, cancellationToken)
                    .ConfigureAwait(false));
                WriteManifest(manifestPath, request.Identity, records, isComplete: false, error: null);
            }

            WriteManifest(manifestPath, request.Identity, records, isComplete: true, error: null);
            return new BootBackupResult(backupDirectory, true, records.ToArray(), null);
        }
        catch (OperationCanceledException)
        {
            // Persisted without the token so the directory still records the incomplete attempt.
            TryWriteIncompleteManifest(manifestPath, request.Identity, records, CancelledError);
            throw;
        }
        catch (Exception ex)
        {
            // I/O, length and hash failures keep the verified records and their partial files.
            var error = string.IsNullOrWhiteSpace(ex.Message) ? ex.GetType().Name : ex.Message;
            TryWriteIncompleteManifest(manifestPath, request.Identity, records, error);
            return new BootBackupResult(backupDirectory, false, records.ToArray(), error);
        }
    }

    private static async Task<BootBackupRecord> CopyAndVerifySlotAsync(
        BootSlotDescriptor descriptor,
        IBootReader reader,
        string backupDirectory,
        CancellationToken cancellationToken)
    {
        var fileName = descriptor.Slot == SlotA ? BootAFileName : BootBFileName;
        var filePath = Path.Combine(backupDirectory, fileName);
        var buffer = new byte[CopyBufferSize];
        long written = 0;
        var anyNonZero = false;
        string writtenSha256;

        await using (var source = await reader.OpenReadAsync(descriptor.Slot, cancellationToken).ConfigureAwait(false))
        await using (var target = new FileStream(filePath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                         CopyBufferSize, FileOptions.Asynchronous))
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            while (true)
            {
                var read = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                // Reject an over-long stream before a single byte beyond the declared length is written.
                if (written + read > descriptor.Length)
                {
                    throw new InvalidDataException(
                        $"slot '{descriptor.Slot}' stream is longer than the declared {descriptor.Length} bytes.");
                }

                // Zero detection rides along with the copy: each byte is inspected once and never buffered.
                if (!anyNonZero && AnyNonZero(buffer.AsSpan(0, read)))
                {
                    anyNonZero = true;
                }

                hash.AppendData(buffer, 0, read);
                await target.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                written += read;
            }

            await target.FlushAsync(cancellationToken).ConfigureAwait(false);
            target.Flush(flushToDisk: true);
            writtenSha256 = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
        }

        if (written != descriptor.Length)
        {
            throw new InvalidDataException(
                $"slot '{descriptor.Slot}' ended after {written} bytes, expected {descriptor.Length} bytes.");
        }

        if (!string.Equals(writtenSha256, descriptor.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"slot '{descriptor.Slot}' SHA-256 {writtenSha256} does not match the declared {descriptor.Sha256}.");
        }

        // The in-flight hash only proves what passed through the buffer, so the closed file is verified again.
        var persisted = await ReadBackAndVerifyAsync(filePath, descriptor, cancellationToken).ConfigureAwait(false);

        return new BootBackupRecord(descriptor.Slot, fileName, persisted.Length, persisted.Sha256)
        {
            ContentState = anyNonZero ? BootContentState.Unknown : BootContentState.Empty,
        };
    }

    /// <summary>
    /// Reopens the written file read-only after its writer closed and re-checks length and SHA-256 from disk,
    /// streaming asynchronously so no file is ever held in memory. Anything that does not match the declared
    /// descriptor throws, which keeps the slot out of the records and the manifest incomplete.
    /// </summary>
    private static async Task<(long Length, string Sha256)> ReadBackAndVerifyAsync(
        string filePath,
        BootSlotDescriptor descriptor,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[CopyBufferSize];
        var name = Path.GetFileName(filePath);
        long readBackLength;
        string readBackSha256;

        await using (var persisted = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read,
                         CopyBufferSize, FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            var length = persisted.Length;
            if (length != descriptor.Length)
            {
                throw new InvalidDataException(
                    $"slot '{descriptor.Slot}' readback of '{name}' is {length} bytes on disk, expected {descriptor.Length} bytes.");
            }

            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long hashed = 0;
            while (true)
            {
                var read = await persisted.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                if (hashed + read > descriptor.Length)
                {
                    throw new InvalidDataException(
                        $"slot '{descriptor.Slot}' readback of '{name}' delivered more than the declared {descriptor.Length} bytes.");
                }

                hash.AppendData(buffer, 0, read);
                hashed += read;
            }

            if (hashed != length)
            {
                throw new InvalidDataException(
                    $"slot '{descriptor.Slot}' readback of '{name}' delivered {hashed} bytes, but the file reports {length} bytes.");
            }

            readBackLength = hashed;
            readBackSha256 = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
        }

        if (!string.Equals(readBackSha256, descriptor.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"slot '{descriptor.Slot}' readback SHA-256 {readBackSha256} of '{name}' does not match the declared {descriptor.Sha256}.");
        }

        return (readBackLength, readBackSha256);
    }

    private static bool AnyNonZero(ReadOnlySpan<byte> bytes)
    {
        foreach (var value in bytes)
        {
            if (value != 0)
            {
                return true;
            }
        }

        return false;
    }

    private static void Validate(BootBackupRequest request, IBootReader reader)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (reader is null)
        {
            throw new ArgumentNullException(nameof(reader));
        }

        // The identity is a known sealed record, so its members are validated directly instead of by shape.
        var identity = request.Identity;
        if (identity is null)
        {
            throw new ArgumentException("device identity is required.", nameof(request));
        }

        if (string.IsNullOrWhiteSpace(identity.Serial))
        {
            throw new ArgumentException("device serial number must not be blank.", nameof(request));
        }

        if (identity.Model is not ("TB322FC" or "TB323FU"))
        {
            throw new ArgumentException(
                $"device model '{identity.Model}' is not supported; only TB322FC and TB323FU are.", nameof(request));
        }

        if (identity.BootloaderState != BootloaderState.Unlocked)
        {
            throw new ArgumentException("bootloader must be unlocked before a boot backup.", nameof(request));
        }

        if (string.IsNullOrWhiteSpace(request.DestinationRoot))
        {
            throw new ArgumentException("destination root must not be blank.", nameof(request));
        }

        var slots = request.Slots;
        if (slots is null || slots.Count != 2)
        {
            throw new ArgumentException("exactly the two boot slots 'a' and 'b' must be declared.", nameof(request));
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var descriptor in slots)
        {
            if (descriptor is null)
            {
                throw new ArgumentException("slot descriptor must not be null.", nameof(request));
            }

            if (descriptor.Slot is not (SlotA or SlotB))
            {
                throw new ArgumentException(
                    $"slot name '{descriptor.Slot}' is not a supported boot slot ('a' or 'b').", nameof(request));
            }

            if (!seen.Add(descriptor.Slot))
            {
                throw new ArgumentException($"slot '{descriptor.Slot}' is declared more than once.", nameof(request));
            }

            if (descriptor.Length <= 0)
            {
                throw new ArgumentException($"slot '{descriptor.Slot}' must declare a positive length.", nameof(request));
            }

            if (!IsSha256Hex(descriptor.Sha256))
            {
                throw new ArgumentException(
                    $"slot '{descriptor.Slot}' must declare a 64 character hex SHA-256.", nameof(request));
            }
        }
    }

    private static bool IsSha256Hex(string? value)
    {
        if (value is null || value.Length != 64)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!Uri.IsHexDigit(character))
            {
                return false;
            }
        }

        return true;
    }

    private static string CreateUniqueBackupDirectory(string destinationRoot)
    {
        Directory.CreateDirectory(destinationRoot);

        // Constant prefix plus timestamp and guid: no serial/model text reaches the path, and the name
        // cannot collide with (or overwrite) an earlier backup directory.
        var name = DirectoryPrefix
                   + DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmssfff", CultureInfo.InvariantCulture)
                   + "-"
                   + Guid.NewGuid().ToString("N");

        var backupDirectory = Path.Combine(destinationRoot, name);
        Directory.CreateDirectory(backupDirectory);
        return backupDirectory;
    }

    private static void WriteManifest(
        string manifestPath,
        DeviceIdentity identity,
        IReadOnlyList<BootBackupRecord> records,
        bool isComplete,
        string? error)
    {
        var manifest = new BootBackupManifest(identity, records.ToArray(), isComplete, error);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(manifest, ManifestJson);

        // Owned temp file inside the new backup directory, so a torn write never yields a half manifest.
        var tempPath = manifestPath + TempManifestSuffix;
        File.WriteAllBytes(tempPath, bytes);
        File.Move(tempPath, manifestPath, overwrite: true);
    }

    private static void TryWriteIncompleteManifest(
        string manifestPath,
        DeviceIdentity identity,
        IReadOnlyList<BootBackupRecord> records,
        string error)
    {
        try
        {
            WriteManifest(manifestPath, identity, records, isComplete: false, error);
        }
        catch (Exception)
        {
            // Best effort only: the caller already gets an incomplete result or the rethrown cancellation.
        }
    }

    private sealed record BootBackupManifest(
        DeviceIdentity Identity,
        IReadOnlyList<BootBackupRecord> Records,
        bool IsComplete,
        string? Error);
}
