using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace FreedomInstaller.Core;

/// <summary>
/// One immutable, fully validated RAM install request. Its exact UTF-8 bytes are serialized once in
/// the constructor and the SHA-256 of those bytes is the request identity the helper binds to.
/// </summary>
/// <remarks>
/// The DTO owns no caller list or array: every collection is copied into a read-only view and every
/// GUID is normalized to the lowercase canonical form. Lengths, extents and sums are checked with
/// 64-bit checked arithmetic. Nothing here is a planner and nothing demands unrelated Android
/// partition names; only the three fixed ARMADA labels and the canonical <c>userdata</c> window are
/// interpreted.
/// <para>
/// The request carries no token. Callers may build it from strings or from a
/// <see cref="RamInstallSession"/>, but the session values are only copied here; the client still
/// compares the live session with this request before any I/O.
/// </para>
/// </remarks>
public sealed class RamInstallRequest
{
    /// <summary>The only accepted request schema version.</summary>
    public const int ContractSchemaVersion = 1;

    /// <summary>The only accepted model code.</summary>
    public const string ModelCode = "TB322FC";

    /// <summary>The only accepted target device.</summary>
    public const string DevicePath = "/dev/sda";

    /// <summary>Fixed ARMADA boot partition label.</summary>
    public const string BootLabel = "ARMADA_BOOT";

    /// <summary>Fixed ARMADA root partition label.</summary>
    public const string RootLabel = "ARMADA_ROOT";

    /// <summary>Fixed ARMADA backup partition label.</summary>
    public const string BackupLabel = "ARMADA_BACKUP";

    private const long Gibibyte = 1024L * 1024L * 1024L;

    private const long Mebibyte = 1024L * 1024L;

    private const long MinimumUserdataBytes = 16L * Gibibyte;

    private const long MinimumLinuxBytes = 64L * Gibibyte;

    private const long BackupBytes = 2L * Gibibyte;

    private const string UserdataLabel = "userdata";

    private const int MaxRequestBytes = 1 << 20;

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
    };

    private readonly byte[] _requestBytes;

    private readonly string _requestSha256;

    /// <summary>Builds the request from explicit identity strings.</summary>
    /// <exception cref="ArgumentException">Any contract field or the table geometry is invalid.</exception>
    public RamInstallRequest(
        string expectedSocSerial,
        string expectedBootId,
        int userdataGiB,
        long originalUserdataEndSector,
        string bootPartUuid,
        string rootPartUuid,
        string backupPartUuid,
        ExpectedTable expectedTable,
        RamInstallSeed seed,
        RamInstallBootConfig? boot = null)
    {
        ArgumentNullException.ThrowIfNull(expectedTable);
        ArgumentNullException.ThrowIfNull(seed);

        ExpectedSocSerial = RamInstallValidation.RequireCanonicalSocSerial(expectedSocSerial);
        ExpectedBootId = RamInstallValidation.NormalizeUuid(expectedBootId, nameof(expectedBootId));

        if (userdataGiB < 16)
        {
            throw new ArgumentException("userdataGiB must be at least 16.", nameof(userdataGiB));
        }

        UserdataGiB = userdataGiB;

        if (originalUserdataEndSector <= 0)
        {
            throw new ArgumentException(
                "originalUserdataEndSector must be a positive end-exclusive sector.",
                nameof(originalUserdataEndSector));
        }

        OriginalUserdataEndSector = originalUserdataEndSector;
        BootPartUuid = RamInstallValidation.NormalizeUuid(bootPartUuid, nameof(bootPartUuid));
        RootPartUuid = RamInstallValidation.NormalizeUuid(rootPartUuid, nameof(rootPartUuid));
        BackupPartUuid = RamInstallValidation.NormalizeUuid(backupPartUuid, nameof(backupPartUuid));
        ExpectedTable = expectedTable;
        Seed = seed;
        Boot = boot;

        ValidateGeometry();

        _requestBytes = JsonSerializer.SerializeToUtf8Bytes(this, SerializerOptions);
        if (_requestBytes.Length > MaxRequestBytes)
        {
            throw new ArgumentException(
                "The serialized request exceeds the 1 MiB wire limit.",
                nameof(expectedTable));
        }

        _requestSha256 = Convert.ToHexString(SHA256.HashData(_requestBytes)).ToLowerInvariant();
    }

    /// <summary>
    /// Builds the request from the fresh session's proven identity. The session's model is not
    /// trusted here; the client compares it with <see cref="ModelCode"/> before any I/O.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="session"/> is null.</exception>
    public RamInstallRequest(
        RamInstallSession session,
        int userdataGiB,
        long originalUserdataEndSector,
        string bootPartUuid,
        string rootPartUuid,
        string backupPartUuid,
        ExpectedTable expectedTable,
        RamInstallSeed seed,
        RamInstallBootConfig? boot = null)
        : this(
            SessionSocSerial(session),
            SessionBootId(session),
            userdataGiB,
            originalUserdataEndSector,
            bootPartUuid,
            rootPartUuid,
            backupPartUuid,
            expectedTable,
            seed,
            boot)
    {
    }

    [JsonPropertyName("schemaVersion")]
    public int SchemaVersion => ContractSchemaVersion;

    [JsonPropertyName("model")]
    public string Model => ModelCode;

    [JsonPropertyName("device")]
    public string Device => DevicePath;

    [JsonPropertyName("expectedSocSerial")]
    public string ExpectedSocSerial { get; }

    [JsonPropertyName("expectedBootId")]
    public string ExpectedBootId { get; }

    [JsonPropertyName("userdataGiB")]
    public int UserdataGiB { get; }

    [JsonPropertyName("originalUserdataEndSector")]
    public long OriginalUserdataEndSector { get; }

    [JsonPropertyName("bootPartUuid")]
    public string BootPartUuid { get; }

    [JsonPropertyName("rootPartUuid")]
    public string RootPartUuid { get; }

    [JsonPropertyName("backupPartUuid")]
    public string BackupPartUuid { get; }

    [JsonPropertyName("expectedTable")]
    public ExpectedTable ExpectedTable { get; }

    [JsonPropertyName("seed")]
    public RamInstallSeed Seed { get; }

    /// <summary>
    /// Optional frozen boot-material block. Null keeps the exact original field set and bytes; when
    /// present it is serialized once under <c>boot</c> and never changes for the session.
    /// </summary>
    [JsonPropertyName("boot")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public RamInstallBootConfig? Boot { get; }

    /// <summary>Lowercase SHA-256 of the exact request bytes. Never a token or a signature.</summary>
    [JsonIgnore]
    public string RequestSha256 => _requestSha256;

    /// <summary>Returns a private copy of the exact request bytes. Used by the client only.</summary>
    internal byte[] CopyRequestBytes() => (byte[])_requestBytes.Clone();

    /// <summary>Redacted representation: no seed details and no token are ever present.</summary>
    public override string ToString() =>
        nameof(RamInstallRequest)
        + " { Model = " + Model
        + ", Device = " + Device
        + ", RequestSha256 = " + RequestSha256
        + " }";

    private static string SessionSocSerial(RamInstallSession session)
    {
        ArgumentNullException.ThrowIfNull(session);
        return session.SocSerial;
    }

    private static string SessionBootId(RamInstallSession session)
    {
        ArgumentNullException.ThrowIfNull(session);
        return session.BootId;
    }

    private void ValidateGeometry()
    {
        var table = ExpectedTable;
        long totalSectors = table.DiskBytes / table.SectorSize;
        if (totalSectors <= 0)
        {
            throw new ArgumentException("expectedTable.diskBytes does not contain one whole sector.");
        }

        try
        {
            var partitions = table.Partitions;
            var numbers = new HashSet<long>();
            var names = new HashSet<string>(StringComparer.Ordinal);
            var partUuids = new HashSet<string>(StringComparer.Ordinal);
            var ranges = new List<(long Start, long End)>(partitions.Count);
            long maximumEnd = -1;

            foreach (var partition in partitions)
            {
                if (partition is null)
                {
                    throw new ArgumentException("expectedTable.partitions contains a null entry.");
                }

                if (!numbers.Add(partition.Number))
                {
                    throw new ArgumentException("Partition numbers must be unique.");
                }

                if (!names.Add(partition.Name))
                {
                    throw new ArgumentException("Partition names must be unique.");
                }

                if (!partUuids.Add(partition.PartUuid))
                {
                    throw new ArgumentException("Partition UUIDs must be unique.");
                }

                long end = checked(partition.StartSector + partition.SectorCount);
                if (end > totalSectors)
                {
                    throw new ArgumentException("A partition extends past the declared disk size.");
                }

                _ = checked(partition.StartSector * table.SectorSize);
                _ = checked(partition.SectorCount * table.SectorSize);
                _ = checked(end * table.SectorSize);

                ranges.Add((partition.StartSector, end));
                maximumEnd = Math.Max(maximumEnd, end);
            }

            ranges.Sort(static (left, right) => left.Start.CompareTo(right.Start));
            for (var index = 1; index < ranges.Count; index++)
            {
                if (ranges[index].Start < ranges[index - 1].End)
                {
                    throw new ArgumentException("Two partitions overlap.");
                }
            }

            var boot = FindRequired(table.Partitions, BootLabel, StringComparison.Ordinal);
            var root = FindRequired(table.Partitions, RootLabel, StringComparison.Ordinal);
            var backup = FindRequired(table.Partitions, BackupLabel, StringComparison.Ordinal);
            var userdata = FindRequired(table.Partitions, UserdataLabel, StringComparison.OrdinalIgnoreCase);

            if (!string.Equals(boot.PartUuid, BootPartUuid, StringComparison.Ordinal) ||
                !string.Equals(root.PartUuid, RootPartUuid, StringComparison.Ordinal) ||
                !string.Equals(backup.PartUuid, BackupPartUuid, StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "The ARMADA partition UUIDs do not match the request's referenced UUIDs.");
            }

            long bootBytes = checked(boot.SectorCount * table.SectorSize);
            long rootBytes = checked(root.SectorCount * table.SectorSize);
            long backupByteCount = checked(backup.SectorCount * table.SectorSize);
            long userdataBytes = checked(userdata.SectorCount * table.SectorSize);

            if (backupByteCount != BackupBytes)
            {
                throw new ArgumentException("ARMADA_BACKUP must be exactly 2 GiB.");
            }

            if (checked(bootBytes + rootBytes) < MinimumLinuxBytes)
            {
                throw new ArgumentException("ARMADA_BOOT plus ARMADA_ROOT must be at least 64 GiB.");
            }

            if (userdataBytes < MinimumUserdataBytes)
            {
                throw new ArgumentException("userdata must be at least 16 GiB.");
            }

            long expectedUserdataBytes = checked((long)UserdataGiB * Gibibyte);
            if (userdataBytes != expectedUserdataBytes)
            {
                throw new ArgumentException("userdataGiB does not match the userdata partition size.");
            }

            long bootEnd = checked(boot.StartSector + boot.SectorCount);
            long rootEnd = checked(root.StartSector + root.SectorCount);
            long backupEnd = checked(backup.StartSector + backup.SectorCount);
            long userdataEnd = checked(userdata.StartSector + userdata.SectorCount);

            if (userdata.StartSector > boot.StartSector ||
                userdataEnd > boot.StartSector ||
                boot.StartSector >= root.StartSector ||
                bootEnd > root.StartSector ||
                root.StartSector >= backup.StartSector ||
                rootEnd > backup.StartSector)
            {
                throw new ArgumentException(
                    "The userdata, ARMADA_BOOT, ARMADA_ROOT and ARMADA_BACKUP extents must be ordered and disjoint.");
            }

            if (backupEnd != maximumEnd)
            {
                throw new ArgumentException("ARMADA_BACKUP must be the final partition of the table.");
            }

            if (OriginalUserdataEndSector < backupEnd ||
                OriginalUserdataEndSector > totalSectors ||
                OriginalUserdataEndSector <= userdata.StartSector)
            {
                throw new ArgumentException(
                    "originalUserdataEndSector does not close the original userdata tail.");
            }

            long tailSlackSectors = OriginalUserdataEndSector - backupEnd;
            long alignmentSectors = Mebibyte / table.SectorSize;
            if (tailSlackSectors >= alignmentSectors)
            {
                throw new ArgumentException(
                    "originalUserdataEndSector leaves more than one alignment MiB of tail slack.");
            }
        }
        catch (OverflowException exception)
        {
            throw new ArgumentException(
                "The install request geometry overflows the 64-bit sector or byte space.",
                exception);
        }
    }

    private static ExpectedPartition FindRequired(
        IReadOnlyList<ExpectedPartition> partitions,
        string label,
        StringComparison comparison)
    {
        ExpectedPartition? found = null;
        foreach (var partition in partitions)
        {
            if (!string.Equals(partition.Name, label, comparison))
            {
                continue;
            }

            if (found is not null)
            {
                throw new ArgumentException("The required partition label appears more than once.");
            }

            found = partition;
        }

        return found ?? throw new ArgumentException("A required partition label is missing.");
    }
}

/// <summary>
/// The complete expected partition table. The constructor copies the caller's sequence into a
/// read-only view; the caller cannot mutate the table afterwards.
/// </summary>
public sealed class ExpectedTable
{
    private readonly ReadOnlyCollection<ExpectedPartition> _partitions;

    /// <exception cref="ArgumentException">The table geometry is not usable.</exception>
    public ExpectedTable(
        int sectorSize,
        long diskBytes,
        string diskGuid,
        IEnumerable<ExpectedPartition> partitions)
    {
        if (sectorSize != 512 && sectorSize != 4096)
        {
            throw new ArgumentException("sectorSize must be 512 or 4096.", nameof(sectorSize));
        }

        if (diskBytes <= 0)
        {
            throw new ArgumentException("diskBytes must be a positive integer.", nameof(diskBytes));
        }

        if (diskBytes % sectorSize != 0)
        {
            throw new ArgumentException("diskBytes must be a whole number of sectors.", nameof(diskBytes));
        }

        ArgumentNullException.ThrowIfNull(partitions);

        var copy = partitions.ToArray();
        if (copy.Length == 0)
        {
            throw new ArgumentException("partitions must not be empty.", nameof(partitions));
        }

        foreach (var partition in copy)
        {
            if (partition is null)
            {
                throw new ArgumentException("partitions contains a null entry.", nameof(partitions));
            }
        }

        SectorSize = sectorSize;
        DiskBytes = diskBytes;
        DiskGuid = RamInstallValidation.NormalizeUuid(diskGuid, nameof(diskGuid));
        _partitions = Array.AsReadOnly(copy);
    }

    [JsonPropertyName("sectorSize")]
    public int SectorSize { get; }

    [JsonPropertyName("diskBytes")]
    public long DiskBytes { get; }

    [JsonPropertyName("diskGuid")]
    public string DiskGuid { get; }

    [JsonPropertyName("partitions")]
    public IReadOnlyList<ExpectedPartition> Partitions => _partitions;
}

/// <summary>One immutable partition row of the expected table.</summary>
public sealed class ExpectedPartition
{
    /// <exception cref="ArgumentException">A field is outside the contract.</exception>
    public ExpectedPartition(
        long number,
        string name,
        long startSector,
        long sectorCount,
        string typeGuid,
        string partUuid)
    {
        if (number <= 0)
        {
            throw new ArgumentException("Partition number must be positive.", nameof(number));
        }

        if (string.IsNullOrEmpty(name) || name.Any(character => char.IsControl(character)))
        {
            throw new ArgumentException("Partition name must be a non-empty, control-free string.", nameof(name));
        }

        if (startSector < 0)
        {
            throw new ArgumentException("Partition startSector must be non-negative.", nameof(startSector));
        }

        if (sectorCount <= 0)
        {
            throw new ArgumentException("Partition sectorCount must be positive.", nameof(sectorCount));
        }

        Number = number;
        Name = name;
        StartSector = startSector;
        SectorCount = sectorCount;
        TypeGuid = RamInstallValidation.NormalizeUuid(typeGuid, nameof(typeGuid));
        PartUuid = RamInstallValidation.NormalizeUuid(partUuid, nameof(partUuid));
    }

    [JsonPropertyName("number")]
    public long Number { get; }

    [JsonPropertyName("name")]
    public string Name { get; }

    [JsonPropertyName("startSector")]
    public long StartSector { get; }

    [JsonPropertyName("sectorCount")]
    public long SectorCount { get; }

    [JsonPropertyName("typeGuid")]
    public string TypeGuid { get; }

    [JsonPropertyName("partUuid")]
    public string PartUuid { get; }
}

/// <summary>
/// Validated seed identity. The length is a 64-bit byte count with no 512 MiB ceiling; the client
/// streams exactly this many bytes with a 128 KiB working buffer.
/// </summary>
public sealed class RamInstallSeed
{
    /// <exception cref="ArgumentException">A seed field is outside the contract.</exception>
    public RamInstallSeed(long length, string sha256, string commit, string manifestDigest, string origin)
    {
        if (length <= 0)
        {
            throw new ArgumentException("seed.length must be a positive 64-bit integer.", nameof(length));
        }

        Length = length;
        Sha256 = RamInstallValidation.RequireLowerSha256(sha256, nameof(sha256));
        Commit = RamInstallValidation.RequireLowerSha256(commit, nameof(commit));
        ManifestDigest = RamInstallValidation.RequireManifestDigest(manifestDigest);
        Origin = RamInstallValidation.RequireFreedomOrigin(origin);
    }

    [JsonPropertyName("length")]
    public long Length { get; }

    [JsonPropertyName("sha256")]
    public string Sha256 { get; }

    [JsonPropertyName("commit")]
    public string Commit { get; }

    [JsonPropertyName("manifestDigest")]
    public string ManifestDigest { get; }

    [JsonPropertyName("origin")]
    public string Origin { get; }
}

/// <summary>
/// Small validation helpers shared by the request types. The Freedom origin rules mirror the exact
/// rules of the reviewed package reader (private <c>PackageReader.IsProjectOrigin</c>): only the
/// project image repository, a stable/beta/testing channel and an optional pinned
/// <c>@sha256:&lt;64 lowercase hex&gt;</c> are accepted.
/// </summary>
internal static class RamInstallValidation
{
    private const int Sha256HexLength = 64;

    private const string OriginPrefix = "ostree-image-signed:docker://ghcr.io/mydanyi/armadaos-freedom:";

    private const string ManifestDigestPrefix = "sha256:";

    private static readonly string[] OriginChannels = { "stable", "beta", "testing" };

    public static string RequireCanonicalSocSerial(string value)
    {
        if (value is null ||
            value.Length == 0 ||
            value.Length > 20 ||
            value[0] < '1' || value[0] > '9')
        {
            throw new ArgumentException(
                "expectedSocSerial must be a canonical positive decimal string.",
                nameof(value));
        }

        foreach (var character in value)
        {
            if (character < '0' || character > '9')
            {
                throw new ArgumentException(
                    "expectedSocSerial must be a canonical positive decimal string.",
                    nameof(value));
            }
        }

        if (!ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) ||
            parsed == 0)
        {
            throw new ArgumentException(
                "expectedSocSerial must be a canonical positive decimal string.",
                nameof(value));
        }

        return parsed.ToString(CultureInfo.InvariantCulture);
    }

    public static bool IsDecimalDigits(string? value)
    {
        if (value is null || value.Length == 0 || value.Length > 20)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (character < '0' || character > '9')
            {
                return false;
            }
        }

        return true;
    }

    public static string NormalizeUuid(string? value, string parameterName)
    {
        if (value is null || !Guid.TryParseExact(value, "D", out var guid))
        {
            throw new ArgumentException("A canonical UUID string is required.", parameterName);
        }

        return guid.ToString("D");
    }

    public static bool IsLowerSha256(string? value)
    {
        if (value is null || value.Length != Sha256HexLength)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (character is >= '0' and <= '9' or >= 'a' and <= 'f')
            {
                continue;
            }

            return false;
        }

        return true;
    }

    public static string RequireLowerSha256(string? value, string parameterName)
    {
        if (!IsLowerSha256(value))
        {
            throw new ArgumentException(
                "A 64-character lowercase hexadecimal SHA-256 is required.",
                parameterName);
        }

        return value!;
    }

    public static string RequireManifestDigest(string? value)
    {
        if (value is null ||
            !value.StartsWith(ManifestDigestPrefix, StringComparison.Ordinal) ||
            !IsLowerSha256(value[ManifestDigestPrefix.Length..]))
        {
            throw new ArgumentException(
                "manifestDigest must be sha256:<64 lowercase hex>.",
                nameof(value));
        }

        return value;
    }

    public static string RequireFreedomOrigin(string? value)
    {
        if (!IsFreedomOrigin(value))
        {
            throw new ArgumentException(
                "seed.origin is not a supported Freedom origin.",
                nameof(value));
        }

        return value!;
    }

    private static bool IsFreedomOrigin(string? origin)
    {
        if (origin is null || !origin.StartsWith(OriginPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        var tail = origin[OriginPrefix.Length..];
        var separator = tail.IndexOf('@');
        var channel = separator < 0 ? tail : tail[..separator];

        if (Array.IndexOf(OriginChannels, channel) < 0)
        {
            return false;
        }

        if (separator < 0)
        {
            return true;
        }

        var pinned = tail[(separator + 1)..];
        return pinned.StartsWith(ManifestDigestPrefix, StringComparison.Ordinal) &&
            IsLowerSha256(pinned[ManifestDigestPrefix.Length..]);
    }
}
