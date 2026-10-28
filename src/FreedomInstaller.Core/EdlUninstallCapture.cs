using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// One whole region read back over a live EDL session. The record is fully declared
/// here because it is part of the frozen EB001 contract; no behavior hides inside it.
/// </summary>
public sealed record EdlCapturedRegion(
    string Role,
    int Lun,
    long StartSector,
    long SectorCount,
    int SectorSize,
    string? PartUuid,
    string FilePath,
    long Length,
    string Sha256);

/// <summary>
/// A capture represents ONLY fresh reads taken through an actual EDL session. It is
/// never proof of a Linux boot, a RAM-disk boot or an HTTP response, and it never
/// executes a process, writes to a device, resets a device or reboots one.
///
/// The capture is limited to LUN0: the two raw GPT copies plus the whole actual "misc"
/// partition found by parsing that very GPT pair. No LUN4 range and no boot/vbmeta
/// range is probed, read or required here.
///
/// The metadata is immutable and stays readable after <see cref="Dispose"/>; an open
/// capture only owns the read locks on the files it created itself.
/// </summary>
public sealed class EdlUninstallCapture : IDisposable
{
    // Both GPT copies are 64 sectors: 32 for the entry array plus the header block.
    private const int ProbeSectors = 64;
    private const int MinimumTotalSectors = 129;
    private const int FileBufferBytes = 64 * 1024;

    // One fixed role, never derived from an assumed G4 offset.
    private static readonly string[] PartitionRoleOrder =
    {
        "misc",
    };

    private readonly EdlEntryResult _binding;
    private readonly string _directoryPath;
    private readonly EdlGeometry _lun0Geometry;
    private readonly GptTable _lun0Table;
    private readonly IReadOnlyDictionary<string, EdlCapturedRegion> _regions;
    private readonly List<FileStream> _locks;
    private int _disposed;

    private EdlUninstallCapture(
        EdlEntryResult binding,
        string directoryPath,
        EdlGeometry lun0Geometry,
        GptTable lun0Table,
        Dictionary<string, EdlCapturedRegion> regions,
        List<FileStream> locks)
    {
        _binding = binding;
        _directoryPath = directoryPath;
        _lun0Geometry = lun0Geometry;
        _lun0Table = lun0Table;
        _locks = locks;

        var copy = new Dictionary<string, EdlCapturedRegion>(StringComparer.Ordinal);
        foreach (KeyValuePair<string, EdlCapturedRegion> pair in regions)
        {
            copy.Add(pair.Key, pair.Value);
        }

        _regions = new ReadOnlyDictionary<string, EdlCapturedRegion>(copy);
    }

    public EdlEntryResult Binding => _binding;

    public string DirectoryPath => _directoryPath;

    public EdlGeometry Lun0Geometry => _lun0Geometry;

    public GptTable Lun0Table => _lun0Table;

    public IReadOnlyDictionary<string, EdlCapturedRegion> Regions => _regions;

    /// <summary>
    /// Reads the two GPT copies of LUN0 plus the whole "misc" partition those copies
    /// actually declare into a new caller-supplied directory. The result exists only
    /// when every one of the three files was verified against the read evidence
    /// actually returned for that request.
    /// </summary>
    public static async Task<EdlUninstallCapture> CaptureAsync(
        EdlClient client,
        EdlToolchain tools,
        EdlEntryResult binding,
        string newDirectory,
        CancellationToken token = default)
    {
        if (client is null)
        {
            throw new ArgumentNullException(nameof(client));
        }

        if (tools is null)
        {
            throw new ArgumentNullException(nameof(tools));
        }

        if (binding is null)
        {
            throw new ArgumentNullException(nameof(binding));
        }

        // The capture must be bound to the very session that was probed: no foreign
        // toolchain, no substituted entry result, no second device identity.
        if (!ReferenceEquals(client.Toolchain, tools))
        {
            throw new InvalidOperationException(
                "The capture client was not built from the supplied toolchain; a foreign toolchain instance is rejected.");
        }

        if (!Equals(client.Binding, binding))
        {
            throw new InvalidOperationException(
                "The capture binding is not the client's own entry result; a substituted binding is rejected.");
        }

        token.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(newDirectory))
        {
            throw new ArgumentException(
                "A new, unused capture directory path is required.", nameof(newDirectory));
        }

        string directory = Path.GetFullPath(newDirectory);
        if (File.Exists(directory) || Directory.Exists(directory))
        {
            throw new IOException(
                "The capture directory must not exist yet: '" + directory + "'.");
        }

        var locks = new List<FileStream>();
        var createdFiles = new List<string>();

        try
        {
            // LUN0 is probed first and carries the initial loader only while the client
            // has no Sahara proof yet; every later capture reuses the live session.
            EdlGeometry lun0 = await ProbeAsync(client, 0, !client.HasInitialSaharaProof, token)
                .ConfigureAwait(false);

            Directory.CreateDirectory(directory);

            (string Path, long Length, string Sha256) lun0Primary = await ReadSliceAsync(
                client, lun0, 0, "gpt_lun0_primary.bin", directory, token, locks, createdFiles)
                .ConfigureAwait(false);
            (string Path, long Length, string Sha256) lun0Backup = await ReadSliceAsync(
                client, lun0, lun0.TotalSectors - ProbeSectors, "gpt_lun0_backup.bin", directory, token, locks, createdFiles)
                .ConfigureAwait(false);

            // The parser still owns header/array CRC and layout rules; the two raw GPT
            // slices are small enough (<= 256 KiB each) to hand over as byte arrays.
            byte[] primary0 = await File.ReadAllBytesAsync(lun0Primary.Path, token).ConfigureAwait(false);
            byte[] backup0 = await File.ReadAllBytesAsync(lun0Backup.Path, token).ConfigureAwait(false);

            GptTable table0 = ParseTable(primary0, backup0, lun0);

            // Any missing or duplicated target rejects here, before a single partition
            // range is read and before any script runner could be involved.
            PartitionTarget misc = MapPartition(table0, lun0);

            var regions = new Dictionary<string, EdlCapturedRegion>(StringComparer.Ordinal);

            // The two GPT slices are declared with the metadata of the very reads that
            // produced them: no independent hash, no re-read, no borrowed range.
            regions.Add("gpt_lun0_primary", new EdlCapturedRegion(
                "gpt_lun0_primary", lun0.Lun, 0, ProbeSectors, lun0.SectorSize, null,
                lun0Primary.Path, lun0Primary.Length, lun0Primary.Sha256));
            regions.Add("gpt_lun0_backup", new EdlCapturedRegion(
                "gpt_lun0_backup", lun0.Lun, lun0.TotalSectors - ProbeSectors, ProbeSectors, lun0.SectorSize, null,
                lun0Backup.Path, lun0Backup.Length, lun0Backup.Sha256));

            foreach (string role in PartitionRoleOrder)
            {
                regions.Add(role, await ReadPartitionAsync(
                    client, role, misc, directory, token, locks, createdFiles)
                    .ConfigureAwait(false));
            }

            return new EdlUninstallCapture(
                binding, directory, lun0, table0, regions, locks);
        }
        catch
        {
            foreach (FileStream stream in locks)
            {
                stream.Dispose();
            }

            locks.Clear();

            // The contract preserves every file and the directory on every failure: the
            // partial capture is evidence, never deleted. Only owned locks are released.
            throw;
        }
    }

    /// <summary>
    /// Releases only the read locks this capture owns. It never deletes backups or
    /// captured files, never disposes the toolchain and never resets the client.
    /// Calling it twice is safe, and all metadata stays readable afterwards.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        foreach (FileStream stream in _locks)
        {
            stream.Dispose();
        }

        _locks.Clear();
    }

    private static async Task<EdlGeometry> ProbeAsync(
        EdlClient client,
        int lun,
        bool initialLoader,
        CancellationToken token)
    {
        EdlProbeEvidence probe = await client.ProbeAsync(lun, initialLoader, token)
            .ConfigureAwait(false);

        if (probe is null || probe.Geometry is null)
        {
            throw new InvalidOperationException(
                "The probe of LUN" + lun + " returned no geometry; the physical layout is unknown.");
        }

        EdlGeometry geometry = probe.Geometry;
        if (geometry.Lun != lun)
        {
            throw new InvalidOperationException(
                "The probe returned geometry for LUN" + geometry.Lun + " instead of the requested LUN" + lun + ".");
        }

        if (geometry.SectorSize != 512 && geometry.SectorSize != 4096)
        {
            throw new InvalidOperationException(
                "LUN" + lun + " reported an unsupported sector size of " + geometry.SectorSize + " bytes.");
        }

        if (geometry.TotalSectors < MinimumTotalSectors)
        {
            throw new InvalidOperationException(
                "LUN" + lun + " reported only " + geometry.TotalSectors + " sectors, which cannot hold a GPT.");
        }

        try
        {
            long diskBytes = checked(geometry.TotalSectors * geometry.SectorSize);
            if (diskBytes <= 0)
            {
                throw new InvalidOperationException(
                    "LUN" + lun + " reported a non-positive disk size.");
            }
        }
        catch (OverflowException)
        {
            throw new InvalidOperationException(
                "LUN" + lun + " reported a disk size that overflows a 64-bit byte count.");
        }

        return geometry;
    }

    private static async Task<(string Path, long Length, string Sha256)> ReadSliceAsync(
        EdlClient client,
        EdlGeometry geometry,
        long startSector,
        string fileName,
        string directory,
        CancellationToken token,
        List<FileStream> locks,
        List<string> createdFiles)
    {
        if (startSector < 0 || startSector + ProbeSectors > geometry.TotalSectors)
        {
            throw new InvalidOperationException(
                "The GPT slice '" + fileName + "' falls outside LUN" + geometry.Lun + ".");
        }

        return await ReadAndSealAsync(
            client, geometry, startSector, ProbeSectors, directory, fileName, token, locks, createdFiles)
            .ConfigureAwait(false);
    }

    private static async Task<EdlCapturedRegion> ReadPartitionAsync(
        EdlClient client,
        string role,
        PartitionTarget target,
        string directory,
        CancellationToken token,
        List<FileStream> locks,
        List<string> createdFiles)
    {
        GptPartition partition = target.Partition;

        (string Path, long Length, string Sha256) sealedFile = await ReadAndSealAsync(
            client,
            target.Geometry,
            partition.StartSector,
            partition.SectorCount,
            directory,
            role + ".bin",
            token,
            locks,
            createdFiles)
            .ConfigureAwait(false);

        return new EdlCapturedRegion(
            role,
            target.Geometry.Lun,
            partition.StartSector,
            partition.SectorCount,
            target.Geometry.SectorSize,
            partition.PartUuid,
            sealedFile.Path,
            sealedFile.Length,
            sealedFile.Sha256);
    }

    private static async Task<(string Path, long Length, string Sha256)> ReadAndSealAsync(
        EdlClient client,
        EdlGeometry geometry,
        long startSector,
        long sectorCount,
        string directory,
        string fileName,
        CancellationToken token,
        List<FileStream> locks,
        List<string> createdFiles)
    {
        string path = Path.Combine(directory, fileName);

        long expectedLength;
        try
        {
            expectedLength = checked(sectorCount * geometry.SectorSize);
        }
        catch (OverflowException)
        {
            throw new InvalidOperationException(
                "The requested range for '" + fileName + "' overflows a 64-bit byte count.");
        }

        if (expectedLength <= 0)
        {
            throw new InvalidOperationException(
                "The requested range for '" + fileName + "' is empty.");
        }

        createdFiles.Add(path);

        EdlReadEvidence evidence = await client
            .ReadAsync(geometry.Lun, startSector, sectorCount, path, token)
            .ConfigureAwait(false);

        VerifyRead(evidence, geometry, startSector, sectorCount, expectedLength, path);

        (long Length, string Sha256) sealedFile = await SealAsync(
            path, expectedLength, evidence.Sha256, locks, token)
            .ConfigureAwait(false);

        return (path, sealedFile.Length, sealedFile.Sha256);
    }

    private static void VerifyRead(
        EdlReadEvidence evidence,
        EdlGeometry geometry,
        long startSector,
        long sectorCount,
        long expectedLength,
        string path)
    {
        if (evidence is null)
        {
            throw new InvalidOperationException(
                "The read of '" + path + "' returned no evidence.");
        }

        if (evidence.Geometry is null
            || evidence.Geometry.Lun != geometry.Lun
            || evidence.Geometry.SectorSize != geometry.SectorSize
            || evidence.Geometry.TotalSectors != geometry.TotalSectors)
        {
            throw new InvalidOperationException(
                "The read of '" + path + "' reported a geometry that does not match LUN" + geometry.Lun + ".");
        }

        if (evidence.StartSector != startSector || evidence.SectorCount != sectorCount)
        {
            throw new InvalidOperationException(
                "The read of '" + path + "' covered a different sector range than requested.");
        }

        if (evidence.Length != expectedLength)
        {
            throw new InvalidOperationException(
                "The read of '" + path + "' returned " + evidence.Length + " bytes instead of " + expectedLength + ".");
        }

        if (!SamePath(evidence.FilePath, path))
        {
            throw new InvalidOperationException(
                "The read of '" + path + "' reported a different output file.");
        }
    }

    /// <summary>
    /// Confirms the freshly written file against the read evidence, makes its bytes
    /// durable, and then takes the read lock that keeps it immutable for this capture.
    /// </summary>
    private static async Task<(long Length, string Sha256)> SealAsync(
        string path,
        long expectedLength,
        string expectedSha256,
        List<FileStream> locks,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        var info = new FileInfo(path);
        if (!info.Exists)
        {
            throw new InvalidOperationException("The read did not produce the file '" + path + "'.");
        }

        if (info.Length != expectedLength)
        {
            throw new InvalidOperationException(
                "The file '" + path + "' holds " + info.Length + " bytes instead of " + expectedLength + ".");
        }

        string actualSha256 = await HashFileAsync(path, token).ConfigureAwait(false);

        if (string.IsNullOrEmpty(expectedSha256)
            || !string.Equals(actualSha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The whole-file SHA-256 of '" + path + "' does not match the read evidence.");
        }

        token.ThrowIfCancellationRequested();

        // FlushToDisk: the only writable handle is opened on our own new capture file and
        // closed again before the permanent read-only lock is taken.
        FlushDurable(path);

        var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, FileBufferBytes, FileOptions.None);

        locks.Add(stream);

        return (expectedLength, actualSha256);
    }

    private static void FlushDurable(string path)
    {
        using (var writable = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            writable.Flush(true);
        }
    }

    private static async Task<string> HashFileAsync(string path, CancellationToken token)
    {
        using (var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, FileBufferBytes, FileOptions.SequentialScan))
        {
            byte[] hash = await SHA256.HashDataAsync(stream, token).ConfigureAwait(false);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
    }

    private static GptTable ParseTable(byte[] primary, byte[] backup, EdlGeometry geometry)
    {
        long diskBytes;
        try
        {
            diskBytes = checked(geometry.TotalSectors * geometry.SectorSize);
        }
        catch (OverflowException)
        {
            throw new InvalidOperationException(
                "LUN" + geometry.Lun + " reported a disk size that overflows a 64-bit byte count.");
        }

        GptTable table = OriginalGptImporter.Parse(primary, backup, geometry.SectorSize, diskBytes);

        if (table is null)
        {
            throw new InvalidOperationException(
                "The GPT of LUN" + geometry.Lun + " could not be parsed.");
        }

        if (table.SectorSize != geometry.SectorSize)
        {
            throw new InvalidOperationException(
                "The GPT of LUN" + geometry.Lun + " describes a different sector size than the device.");
        }

        if (table.DiskBytes != diskBytes)
        {
            throw new InvalidOperationException(
                "The GPT of LUN" + geometry.Lun + " describes a different disk size than the device.");
        }

        return table;
    }

    private static PartitionTarget MapPartition(GptTable lun0Table, EdlGeometry lun0)
    {
        var targets = new Dictionary<string, PartitionTarget>(StringComparer.Ordinal);

        foreach (GptPartition partition in lun0Table.Partitions)
        {
            string? name = partition.Name;
            if (string.IsNullOrEmpty(name) || Array.IndexOf(PartitionRoleOrder, name) < 0)
            {
                continue;
            }

            if (targets.ContainsKey(name))
            {
                throw new InvalidOperationException(
                    "The captured GPT contains more than one '" + name + "' partition.");
            }

            ValidatePartition(partition, lun0, name);
            targets.Add(name, new PartitionTarget(partition, lun0));
        }

        foreach (string role in PartitionRoleOrder)
        {
            if (!targets.ContainsKey(role))
            {
                throw new InvalidOperationException(
                    "The captured GPT does not contain the required '" + role + "' partition.");
            }
        }

        return targets["misc"];
    }

    private static void ValidatePartition(GptPartition partition, EdlGeometry geometry, string role)
    {
        if (partition.StartSector < 2 || partition.SectorCount <= 0)
        {
            throw new InvalidOperationException(
                "The '" + role + "' partition has an empty or unusable sector range.");
        }

        try
        {
            long diskBytes = checked(geometry.TotalSectors * geometry.SectorSize);
            long offsetBytes = checked(partition.StartSector * geometry.SectorSize);
            long lengthBytes = checked(partition.SectorCount * geometry.SectorSize);

            if (offsetBytes + lengthBytes > diskBytes)
            {
                throw new InvalidOperationException(
                    "The '" + role + "' partition extends past the end of LUN" + geometry.Lun + ".");
            }
        }
        catch (OverflowException)
        {
            throw new InvalidOperationException(
                "The '" + role + "' partition range overflows a 64-bit byte count.");
        }

        if (string.IsNullOrWhiteSpace(partition.PartUuid))
        {
            throw new InvalidOperationException(
                "The '" + role + "' partition has no partition UUID.");
        }
    }

    private static bool SamePath(string? left, string right)
    {
        if (string.IsNullOrEmpty(left))
        {
            return false;
        }

        string leftFull;
        string rightFull;

        try
        {
            leftFull = Path.GetFullPath(left);
            rightFull = Path.GetFullPath(right);
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (NotSupportedException)
        {
            return false;
        }

        return string.Equals(leftFull, rightFull, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class PartitionTarget
    {
        internal PartitionTarget(GptPartition partition, EdlGeometry geometry)
        {
            Partition = partition;
            Geometry = geometry;
        }

        internal GptPartition Partition { get; }

        internal EdlGeometry Geometry { get; }
    }
}
