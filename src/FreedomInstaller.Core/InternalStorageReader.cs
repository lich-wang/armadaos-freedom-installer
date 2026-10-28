using System.Globalization;
using System.Text.Json;

namespace FreedomInstaller.Core;

/// <summary>
/// Where an <see cref="InternalStorageSnapshot"/> came from. The two sources are not interchangeable:
/// only <see cref="MaintenanceLayout"/> carries a real <see cref="DiskLayout"/> and table fingerprint,
/// while <see cref="AndroidFileSystem"/> carries capacity numbers only.
/// </summary>
public enum InternalStorageSource
{
    /// <summary>Parsed output of the on-device <c>armada-installer inspect-layout --json</c> helper.</summary>
    MaintenanceLayout = 0,

    /// <summary>Capacity fallback parsed from <c>df -k /data</c> inside Android.</summary>
    AndroidFileSystem = 1,
}

/// <summary>
/// One read-only storage snapshot. <see cref="Layout"/> and <see cref="TableFingerprint"/> are non-null
/// only for <see cref="InternalStorageSource.MaintenanceLayout"/>; an Android fallback never invents a
/// partition table. <see cref="UsedBytes"/> and <see cref="AvailableBytes"/> are null when the helper
/// reports capacity but not free space.
/// </summary>
public sealed record InternalStorageSnapshot(
    InternalStorageSource Source,
    long TotalBytes,
    long? UsedBytes,
    long? AvailableBytes,
    DiskLayout? Layout,
    string? TableFingerprint);

/// <summary>Why an internal storage read failed.</summary>
public enum InternalStorageReadFailure
{
    /// <summary>The query could not be run or was denied; there is no usable alternative output.</summary>
    Unavailable = 0,

    /// <summary>The command produced output, but it did not satisfy the storage contract.</summary>
    InvalidResponse = 1,
}

/// <summary>
/// Friendly, typed failure for a storage read. It is an <see cref="IOException"/> so callers can keep
/// treating device I/O uniformly, while <see cref="Failure"/> stays machine-readable and
/// <see cref="Diagnostic"/> is a bounded, user-facing excerpt instead of a raw parser exception.
/// </summary>
public sealed class InternalStorageReadException : IOException
{
    /// <summary>Creates the exception from a classified failure and a bounded diagnostic.</summary>
    public InternalStorageReadException(InternalStorageReadFailure failure, string diagnostic)
        : base(diagnostic)
    {
        Failure = failure;
        Diagnostic = diagnostic;
    }

    /// <summary>Machine-readable failure class.</summary>
    public InternalStorageReadFailure Failure { get; }

    /// <summary>Bounded diagnostic text; never a raw JSON parser stack trace.</summary>
    public string Diagnostic { get; }
}

/// <summary>
/// Reads internal storage through the on-device maintenance helper and, when the helper is unavailable
/// or its answer is unusable, through exactly one serial-bound <c>df -k /data</c> fallback.
/// <para>
/// Every external command goes through <see cref="ICommandRunner"/>, so tests substitute a fake and no
/// test starts a real adb process or touches a device. Every query is read-only, carries the fixed
/// 20 second timeout, and is validated before its values are used; nothing is cached between reads.
/// </para>
/// </summary>
public sealed class InternalStorageReader
{
    /// <summary>The maintained helper on the device; the only source of a real partition layout.</summary>
    private const string HelperPath = "/usr/libexec/armada/armada-installer";

    private const string UserdataName = "userdata";
    private const string DataMount = "/data";

    /// <summary>
    /// The one accepted alias for <see cref="DataMount"/>. ZUI answers the fixed <c>df -k /data</c> with
    /// this bind mount; read-only mountinfo on the tablet shows it is the same file system as <c>/data</c>.
    /// </summary>
    private const string DataBindMountAlias = "/data/user/0";

    private const string NoDiagnostic = "(no diagnostic output)";

    private const long KiB = 1024L;

    /// <summary>Filesystem, 1K-blocks, Used, Available, Use% and mount point: one <c>df</c> row.</summary>
    private const int RowWidth = 6;

    private const int MaxDiagnosticLength = 512;

    /// <summary>
    /// The fixed, finite timeout every storage query carries. A hung adb session must fail with a
    /// readable error instead of blocking the installer, and a timeout never triggers a second command.
    /// </summary>
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(20);

    private readonly string _adbPath;
    private readonly ICommandRunner _runner;

    /// <summary>Stores the adb executable and the command boundary. No command is started here.</summary>
    public InternalStorageReader(string adbPath, ICommandRunner runner)
    {
        _adbPath = adbPath;
        _runner = runner;
    }

    /// <summary>
    /// Reads the storage snapshot of <paramref name="serial"/>.
    /// <para>
    /// One helper query runs first, using <c>shell -T</c> and the fixed argv of the maintenance helper.
    /// Its answer is used only when the exit code is 0 and the JSON satisfies the layout contract: a
    /// <c>device</c> string, a 512 or 4096 byte sector size, a non-empty table fingerprint and at least
    /// one well-formed partition with exactly one <c>userdata</c> extent. Any other answer (missing
    /// helper, "not found" text with exit 0, denial, malformed or semantically invalid JSON) leads to
    /// exactly one <c>df -k /data</c> query; that fallback carries capacity numbers only and never
    /// invents a partition table, UUID or fingerprint.
    /// </para>
    /// <para>
    /// A blank <paramref name="serial"/> is rejected before any process starts, because an empty
    /// <c>-s</c> value would target whichever device adb happens to pick. Cancellation and timeouts
    /// propagate unchanged and never fall back, since a second 20 second wait is not evidence. Failures
    /// of the fallback surface as <see cref="InternalStorageReadException"/> with a machine-readable
    /// <see cref="InternalStorageReadFailure"/> and a diagnostic of at most 512 characters.
    /// </para>
    /// </summary>
    public async Task<InternalStorageSnapshot> ReadAsync(string serial, CancellationToken cancellationToken = default)
    {
        // A blank -s value would let adb pick a device, so nothing may be started for it.
        ArgumentException.ThrowIfNullOrWhiteSpace(serial);

        var helper = await RunHelperAsync(serial, cancellationToken).ConfigureAwait(false);

        if (helper is not null
            && helper.ExitCode == 0
            && TryReadLayout(helper.StandardOutput, out var layout, out var fingerprint, out var layoutTotal))
        {
            // Only the helper may describe capacity from its own layout; df never fills these fields.
            return new InternalStorageSnapshot(
                InternalStorageSource.MaintenanceLayout, layoutTotal, null, null, layout, fingerprint);
        }

        // Missing, denied, non-JSON or semantically unusable: exactly one df query follows.
        return await ReadFileSystemAsync(serial, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Runs the single maintenance query. Only a process that could not be started is treated as "no
    /// helper answer"; cancellation and timeouts are the caller's outcome and are never turned into a
    /// fallback. A non-zero exit code is a normal result and is judged by the caller.
    /// </summary>
    private async Task<ProcessResult?> RunHelperAsync(string serial, CancellationToken cancellationToken)
    {
        var command = new ProcessCommand(
            _adbPath,
            new[] { "-s", serial, "shell", "-T", HelperPath, "inspect-layout", "--json" },
            QueryTimeout);

        try
        {
            return await _runner.RunAsync(command, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (TimeoutException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException)
        {
            // The helper could not be started at all: the one bounded fallback still gets its chance.
            return null;
        }
    }

    /// <summary>
    /// Runs the one <c>df -k /data</c> fallback. Its exit code and row are validated separately from the
    /// helper, so a denied query is <see cref="InternalStorageReadFailure.Unavailable"/> while output
    /// that does not describe <c>/data</c> is <see cref="InternalStorageReadFailure.InvalidResponse"/>.
    /// </summary>
    private async Task<InternalStorageSnapshot> ReadFileSystemAsync(string serial, CancellationToken cancellationToken)
    {
        var command = new ProcessCommand(
            _adbPath,
            new[] { "-s", serial, "shell", "-T", "df", "-k", "/data" },
            QueryTimeout);

        ProcessResult result;
        try
        {
            result = await _runner.RunAsync(command, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (TimeoutException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException)
        {
            throw new InternalStorageReadException(
                InternalStorageReadFailure.Unavailable,
                Bound($"unable to execute df -k /data: {exception.Message}"));
        }

        if (result.ExitCode != 0)
        {
            // A non-zero df says nothing usable about /data; denial and a missing tool look the same here.
            throw new InternalStorageReadException(
                InternalStorageReadFailure.Unavailable,
                Bound($"df -k /data failed (exit code {result.ExitCode}): {Describe(result)}"));
        }

        if (!TryParseDataRow(result.StandardOutput, out var totalBytes, out var usedBytes, out var availableBytes))
        {
            throw new InternalStorageReadException(
                InternalStorageReadFailure.InvalidResponse,
                Bound($"df -k /data produced no usable /data capacity row: {Describe(result)}"));
        }

        return new InternalStorageSnapshot(
            InternalStorageSource.AndroidFileSystem, totalBytes, usedBytes, availableBytes, null, null);
    }

    /// <summary>
    /// Validates a helper answer against the maintained <c>inspect_layout</c> contract before any value is
    /// used. The root key is <c>device</c> (not the C# property name <c>DeviceId</c>); sectors stay in the
    /// table's own unit and the total is derived only from the reported <c>userdata</c> extent. Returns
    /// false for every structural, semantic or numeric violation instead of throwing, so the caller can
    /// fall back without ever seeing a <see cref="JsonException"/>.
    /// </summary>
    private static bool TryReadLayout(
        string json,
        out DiskLayout? layout,
        out string? fingerprint,
        out long totalBytes)
    {
        layout = null;
        fingerprint = null;
        totalBytes = 0;

        if (string.IsNullOrWhiteSpace(json))
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;

            if (root.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            if (!root.TryGetProperty("device", out var deviceElement)
                || deviceElement.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            var device = deviceElement.GetString();
            if (string.IsNullOrWhiteSpace(device))
            {
                return false;
            }

            if (!root.TryGetProperty("sectorSize", out var sectorSizeElement)
                || sectorSizeElement.ValueKind != JsonValueKind.Number
                || !sectorSizeElement.TryGetInt32(out var sectorSize)
                || (sectorSize != 512 && sectorSize != 4096))
            {
                return false;
            }

            if (!root.TryGetProperty("tableFingerprint", out var fingerprintElement)
                || fingerprintElement.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            var tableFingerprint = fingerprintElement.GetString();
            if (string.IsNullOrWhiteSpace(tableFingerprint))
            {
                return false;
            }

            if (!root.TryGetProperty("partitions", out var partitionsElement)
                || partitionsElement.ValueKind != JsonValueKind.Array)
            {
                return false;
            }

            var partitions = new List<DiskPartition>();
            var numbers = new HashSet<long>();
            DiskPartition? userdata = null;

            foreach (var item in partitionsElement.EnumerateArray())
            {
                if (!TryReadPartition(item, out var partition))
                {
                    return false;
                }

                if (!numbers.Add(partition.Number))
                {
                    return false;
                }

                if (string.Equals(partition.Name.Trim(), UserdataName, StringComparison.OrdinalIgnoreCase))
                {
                    if (userdata is not null)
                    {
                        // Two userdata extents are ambiguous, so no single total may be chosen.
                        return false;
                    }

                    userdata = partition;
                }

                partitions.Add(partition);
            }

            if (partitions.Count == 0 || userdata is null)
            {
                return false;
            }

            // The total comes from the reported extent alone; a missing or overflowing extent is refused.
            totalBytes = checked(userdata.SectorCount * sectorSize);

            layout = new DiskLayout(device!, sectorSize, partitions);
            fingerprint = tableFingerprint;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (OverflowException)
        {
            return false;
        }
    }

    /// <summary>Validates one partition object: every field is required and every number must be sound.</summary>
    private static bool TryReadPartition(JsonElement element, out DiskPartition partition)
    {
        partition = null!;

        if (element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        if (!TryReadInt64(element, "number", out var number) || number <= 0)
        {
            return false;
        }

        if (!element.TryGetProperty("name", out var nameElement)
            || nameElement.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        var name = nameElement.GetString();
        if (name is null)
        {
            return false;
        }

        if (!TryReadInt64(element, "startSector", out var startSector) || startSector < 0)
        {
            return false;
        }

        if (!TryReadInt64(element, "sectorCount", out var sectorCount) || sectorCount <= 0)
        {
            return false;
        }

        // The end must stay representable, so the extent is never silently wrapped.
        if (startSector > long.MaxValue - sectorCount)
        {
            return false;
        }

        if (!element.TryGetProperty("typeGuid", out var typeElement)
            || typeElement.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        var typeGuid = typeElement.GetString();
        if (string.IsNullOrWhiteSpace(typeGuid))
        {
            return false;
        }

        if (!element.TryGetProperty("partUuid", out var uuidElement)
            || uuidElement.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        var partUuid = uuidElement.GetString();
        if (partUuid is null)
        {
            return false;
        }

        partition = new DiskPartition(number, name, startSector, sectorCount, typeGuid!, partUuid);
        return true;
    }

    /// <summary>Reads one integer property without accepting fractions, strings or out-of-range values.</summary>
    private static bool TryReadInt64(JsonElement element, string propertyName, out long value)
    {
        value = 0;
        return element.TryGetProperty(propertyName, out var property)
            && property.ValueKind == JsonValueKind.Number
            && property.TryGetInt64(out value);
    }

    /// <summary>
    /// Parses exactly one <c>/data</c> row out of <c>df -k</c> output, counting the <c>/data/user/0</c>
    /// bind mount ZUI reports for <c>/data</c> as that same row. Lines are joined until a row has six
    /// fields, so a filesystem name that the shell wrapped onto its own line is reassembled; header lines
    /// and rows about other mounts are not evidence. The 1K-blocks column is the total: it is never
    /// recomputed as used plus available, and only that column is converted to bytes.
    /// </summary>
    internal static bool TryParseDataRow(
        string output,
        out long totalBytes,
        out long usedBytes,
        out long availableBytes)
    {
        totalBytes = 0;
        usedBytes = 0;
        availableBytes = 0;

        if (string.IsNullOrWhiteSpace(output))
        {
            return false;
        }

        var buffer = new List<string>();
        var matches = 0;

        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim('\r', ' ', '\t');
            if (line.Length == 0)
            {
                continue;
            }

            var fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);

            // The header names no mount; it is skipped instead of being validated as a row.
            if (buffer.Count == 0 && fields.Length > 0 && fields[0] == "Filesystem")
            {
                continue;
            }

            buffer.AddRange(fields);

            while (buffer.Count >= RowWidth)
            {
                var row = new string[RowWidth];
                for (var index = 0; index < RowWidth; index++)
                {
                    row[index] = buffer[index];
                }

                buffer.RemoveRange(0, RowWidth);

                // Another mount is not evidence about /data: only the exact /data name and its one
                // verified bind-mount alias count, so other profiles, children and the mirror are skipped.
                if (row[5] != DataMount && row[5] != DataBindMountAlias)
                {
                    continue;
                }

                if (!TryParseKiB(row[1], out var total)
                    || !TryParseKiB(row[2], out var used)
                    || !TryParseKiB(row[3], out var available))
                {
                    return false;
                }

                // All three columns are unsigned, so used <= total makes total - used safe. Reserved
                // blocks make total != used + available normal, so only the impossible directions fail.
                if (total <= 0 || used > total || available > total - used)
                {
                    return false;
                }

                matches++;
                totalBytes = total;
                usedBytes = used;
                availableBytes = available;
            }
        }

        // A half row means the output was truncated or is not df output at all.
        if (buffer.Count != 0)
        {
            return false;
        }

        // No /data row, or more than one: neither may be turned into a single capacity answer.
        return matches == 1;
    }

    /// <summary>
    /// Converts one unsigned 1K-blocks column to bytes. Only ASCII digits are accepted, so a negative or
    /// signed value is rejected; overflow is refused instead of wrapping.
    /// </summary>
    private static bool TryParseKiB(string text, out long bytes)
    {
        bytes = 0;

        if (text.Length == 0)
        {
            return false;
        }

        foreach (var character in text)
        {
            if (character < '0' || character > '9')
            {
                return false;
            }
        }

        if (!long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var blocks))
        {
            return false;
        }

        if (blocks > long.MaxValue / KiB)
        {
            return false;
        }

        bytes = blocks * KiB;
        return true;
    }

    /// <summary>The captured error text if there is any, otherwise whatever the tool printed.</summary>
    private static string Describe(ProcessResult result)
    {
        var error = result.StandardError.Trim();
        if (error.Length > 0)
        {
            return error;
        }

        var output = result.StandardOutput.Trim();
        return output.Length > 0 ? output : NoDiagnostic;
    }

    /// <summary>Keeps a diagnostic user-facing: trimmed, never empty and never longer than 512 characters.</summary>
    private static string Bound(string diagnostic)
    {
        var trimmed = diagnostic.Trim();
        if (trimmed.Length == 0)
        {
            trimmed = NoDiagnostic;
        }

        return trimmed.Length <= MaxDiagnosticLength ? trimmed : trimmed[..MaxDiagnosticLength];
    }
}
