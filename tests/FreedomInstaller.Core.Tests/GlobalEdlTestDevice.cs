using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Synthetic six-LUN EDL device backed by real memory. Each LUN holds a small in-memory sector array with a
/// genuinely CRC-valid GPT (primary at 0..2, backup at total-2..total-1) and deterministic partition payloads.
/// This is a fixture for the protocol surface only: it never represents, imitates or validates against a
/// production device, and it exposes no backup API.
/// </summary>
internal sealed class GlobalEdlTestDevice
{
    internal const int SectorSize = 4096;

    private const string AndroidType = "1B81E7E6-F50D-419B-A739-2AEEF8DA3335";
    private const string LinuxType = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";

    private static readonly string[] Lun0 =
    {
        "proinfo", "lenovolock", "lenovocust", "lenovoraw", "ssd", "persist", "misc",
        "keystore", "frp", "metadata", "vbmeta_system_a", "vbmeta_system_b", "super", "userdata",
    };

    private static readonly string[] Lun1 = { "xbl_a", "xbl_config_a", "extra_lun1", "rawdump" };
    private static readonly string[] Lun2 = { "xbl_b", "xbl_config_b" };
    private static readonly string[] Lun3 = { "cdt" };
    private static readonly string[] Lun4 =
    {
        "boot_a", "boot_b", "init_boot_a", "init_boot_b", "vendor_boot_a", "vendor_boot_b",
        "dtbo_a", "dtbo_b", "vbmeta_a", "vbmeta_b", "recovery_a", "recovery_b", "devinfo",
        "uefivarstore", "secdata", "connsec", "spunvm", "abl_a", "abl_b", "efisp",
    };

    private static readonly string[] Lun5 = { "modemst1", "modemst2", "fsg", "fsc", "modem" };

    private readonly Dictionary<int, byte[]> _disks = new();
    private readonly Dictionary<int, IReadOnlyList<GptPartitionSpec>> _partitions = new();
    private readonly Dictionary<string, GptPartitionSpec> _specByLabel = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _lunByLabel = new(StringComparer.Ordinal);
    private readonly bool _linuxTypeOnly;
    private readonly string? _linuxName;
    private readonly int _superSectors;
    private readonly bool _userdataLinuxType;
    private readonly bool _shortMisc;

    internal GlobalEdlTestDevice(
        bool gen5 = false,
        string? linuxName = null,
        bool linuxTypeOnly = false,
        bool multiChunkSuper = false,
        bool userdataLinuxType = false,
        bool shortMisc = false)
    {
        _linuxName = linuxName;
        _linuxTypeOnly = linuxTypeOnly;
        _superSectors = multiChunkSuper ? 16385 : 16;
        _userdataLinuxType = userdataLinuxType;
        _shortMisc = shortMisc;

        for (var lun = 0; lun < 6; lun++)
        {
            BuildLun(lun, gen5);
        }

        Disks = _disks;
        Partitions = _partitions;
    }

    internal IReadOnlyDictionary<int, byte[]> Disks { get; }

    internal IReadOnlyDictionary<int, IReadOnlyList<GptPartitionSpec>> Partitions { get; }

    internal long TotalSectors(int lun) => RequireDisk(lun).LongLength / SectorSize;

    internal GptPartitionSpec Partition(string label) =>
        _specByLabel.TryGetValue(label, out GptPartitionSpec? spec)
            ? spec
            : throw new KeyNotFoundException($"fixture: no partition named '{label}'");

    internal int LunOf(string label) =>
        _lunByLabel.TryGetValue(label, out int lun)
            ? lun
            : throw new KeyNotFoundException($"fixture: no partition named '{label}'");

    internal byte[] Read(int lun, long start, long count)
    {
        byte[] disk = RequireDisk(lun);
        ValidateRange(disk, start, count, lun);

        var result = new byte[count * SectorSize];
        Array.Copy(disk, start * SectorSize, result, 0, result.Length);
        return result;
    }

    internal void Write(int lun, long start, byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length % SectorSize != 0)
        {
            throw new ArgumentException("fixture: write payload is not sector aligned", nameof(bytes));
        }

        byte[] disk = RequireDisk(lun);
        long count = bytes.Length / SectorSize;
        ValidateRange(disk, start, count, lun);
        Array.Copy(bytes, 0, disk, start * SectorSize, bytes.Length);
    }

    /// <summary>
    /// XORs the payload of every partition except the excluded set (userdata, rawdump, metadata, any case),
    /// leaving both GPT copies intact. The excluded payloads stay byte-identical so a roundtrip test can prove
    /// they were neither backed up nor written.
    /// </summary>
    internal void CorruptAllNonUserdata()
    {
        foreach ((int lun, IReadOnlyList<GptPartitionSpec> specs) in _partitions)
        {
            byte[] disk = _disks[lun];
            foreach (GptPartitionSpec spec in specs)
            {
                if (IsExcludedName(spec.Name))
                {
                    continue;
                }

                long offset = spec.StartSector * SectorSize;
                long length = spec.SectorCount * SectorSize;
                for (long index = 0; index < length; index++)
                {
                    disk[offset + index] ^= 0xFF;
                }
            }
        }
    }

    internal static bool IsExcludedName(string name) =>
        string.Equals(name, "userdata", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(name, "rawdump", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(name, "metadata", StringComparison.OrdinalIgnoreCase);

    internal byte[] SnapshotPartition(string label)
    {
        GptPartitionSpec spec = Partition(label);
        int offset = checked((int)(spec.StartSector * SectorSize));
        var copy = new byte[spec.SectorCount * SectorSize];
        Array.Copy(_disks[LunOf(label)], offset, copy, 0, copy.Length);
        return copy;
    }

    /// <summary>Number of partitions in the whole fixture, not counting the excluded payloads.</summary>
    internal int ExpectedPartitionCount =>
        _specByLabel.Count - _specByLabel.Keys.Count(IsExcludedName);

    private byte[] RequireDisk(int lun) =>
        _disks.TryGetValue(lun, out byte[]? disk)
            ? disk
            : throw new ArgumentOutOfRangeException(nameof(lun), $"fixture: no LUN {lun}");

    private static void ValidateRange(byte[] disk, long start, long count, int lun)
    {
        long total = disk.LongLength / SectorSize;
        if (start < 0 || count < 0 || start > total || count > total - start)
        {
            throw new ArgumentOutOfRangeException(
                nameof(start),
                $"fixture: LUN {lun} range {start}+{count} is outside {total} sectors");
        }
    }

    private void BuildLun(int lun, bool gen5)
    {
        List<string> labels = LabelsFor(lun, gen5).ToList();
        bool hasUserdata = labels.Remove("userdata");

        if (lun == 0)
        {
            if (!string.IsNullOrEmpty(_linuxName))
            {
                labels.Add(_linuxName);
            }

            if (_linuxTypeOnly)
            {
                labels.Add("extra_unknown");
            }
        }

        long used = labels.Sum(SizeOf);
        long userdataCount = hasUserdata ? ((_superSectors > 16) ? 256 : 129) : 0;
        long total = lun == 0 ? Math.Max(512, used + userdataCount + 6) : 512;

        // userdata ends exactly at LastUsable (total - 3).
        long userdataStart = hasUserdata ? total - userdataCount - 2 : 0;

        var specs = new List<GptPartitionSpec>();
        long cursor = 3;
        var number = 1;

        foreach (string label in labels)
        {
            long count = SizeOf(label);
            if (hasUserdata && cursor + count > userdataStart)
            {
                throw new InvalidOperationException(
                    $"fixture: '{label}' would overlap userdata on LUN {lun}");
            }

            specs.Add(new GptPartitionSpec(
                number++, label, TypeOf(label), MakeGuid(lun, number, label), cursor, count, 0ul));
            cursor += count;
        }

        if (hasUserdata)
        {
            specs.Add(new GptPartitionSpec(
                number, "userdata", _userdataLinuxType ? LinuxType : AndroidType, MakeGuid(lun, number, "userdata"),
                userdataStart, userdataCount, 0ul));
        }

        var image = new GptImage(
            SectorSize,
            total * SectorSize,
            MakeGuid(lun, 0, "disk"),
            3,
            total - 3,
            specs.ToArray());

        var disk = new byte[checked((int)(total * SectorSize))];
        Array.Fill(disk, (byte)0x5A);

        for (var index = 0; index < specs.Count; index++)
        {
            GptPartitionSpec spec = specs[index];
            FillPartition(disk, lun, index, spec);
        }

        byte[] primary = image.BuildPrimaryFragment();
        Array.Copy(primary, 0, disk, 0, 3 * SectorSize);

        byte[] backup = image.BuildBackupFragment();
        int backupBytes = 2 * SectorSize;
        Array.Copy(backup, backup.Length - backupBytes, disk, disk.Length - backupBytes, backupBytes);

        _disks[lun] = disk;
        _partitions[lun] = specs;

        foreach (GptPartitionSpec spec in specs)
        {
            _specByLabel[spec.Name] = spec;
            _lunByLabel[spec.Name] = lun;
        }
    }

    private long SizeOf(string label) =>
        label == "super" ? _superSectors :
        label == "misc" ? (_shortMisc ? 8 : 16) :
        2;

    private void FillPartition(byte[] disk, int lun, int index, GptPartitionSpec spec)
    {
        int offset = checked((int)(spec.StartSector * SectorSize));
        int length = checked((int)(spec.SectorCount * SectorSize));
        int seed = 1 + (lun * 53 + index * 29 + spec.Name.Length * 11) % 255;

        for (var i = 0; i < length; i++)
        {
            disk[offset + i] = (byte)(1 + (seed + i) % 255);
        }

        if (spec.Name == "misc")
        {
            // The BCB lives in the first sector; the remainder must stay non-zero.
            Array.Clear(disk, offset, SectorSize);
            if (length >= 32768 + 64)
            {
                // Minimal Virtual A/B COW descriptor with a Completed status.
                Array.Clear(disk, offset + 32768, 64);
                disk[offset + 32768] = 2;
                disk[offset + 32768 + 1] = 0xB0;
                disk[offset + 32768 + 2] = 0x0A;
                disk[offset + 32768 + 3] = 0x74;
                disk[offset + 32768 + 4] = 0x56;
                disk[offset + 32768 + 5] = 0;
                disk[offset + 32768 + 6] = 0;
            }
        }
    }

    private static IReadOnlyList<string> LabelsFor(int lun, bool gen5) => lun switch
    {
        0 => gen5 ? Lun0.Skip(4).ToArray() : Lun0,
        1 => Lun1,
        2 => Lun2,
        3 => Lun3,
        4 => Lun4,
        5 => Lun5,
        _ => Array.Empty<string>(),
    };

    private string TypeOf(string label) =>
        (_linuxTypeOnly && label == "extra_unknown")
            ? "B921B045-1DF0-41C3-AF44-4C6F280D3FAE"
            : label == _linuxName ? LinuxType : AndroidType;

    private static string MakeGuid(int lun, int number, string name)
    {
        var bytes = new byte[16];
        bytes[0] = (byte)lun;
        bytes[1] = (byte)number;
        for (var i = 0; i < name.Length; i++)
        {
            bytes[2 + i % 13] ^= (byte)(name[i] + i);
        }

        bytes[15] = 0x41;
        return new Guid(bytes).ToString("D").ToUpperInvariant();
    }
}

internal sealed record GlobalEdlTestIo(int Lun, long StartSector, long SectorCount, string Path);

/// <summary>
/// Scripted <see cref="ICommandRunner"/> that interprets the real EDL argv against a
/// <see cref="GlobalEdlTestDevice"/>. It never starts a process and never touches a production device; the
/// output strings are the same protocol-shaped text the real CLI prints.
/// </summary>
internal sealed class GlobalEdlTestRunner : ICommandRunner
{
    private readonly GlobalEdlTestDevice _device;
    private bool _saharaEmitted;

    internal GlobalEdlTestRunner(
        GlobalEdlTestDevice device,
        string hardwareId,
        string busSerialHex = E003EdlTestData.BusSerialHex)
    {
        _device = device ?? throw new ArgumentNullException(nameof(device));
        HardwareId = hardwareId;
        BusSerialHex = busSerialHex;
    }

    internal string BusSerialHex { get; set; }

    internal string HardwareId { get; set; }

    internal List<GlobalEdlTestIo> Reads { get; } = new();

    internal List<GlobalEdlTestIo> Writes { get; } = new();

    internal List<ProcessCommand> Commands { get; } = new();

    internal int ResetCount { get; private set; }

    internal bool IgnoreWrites { get; set; }

    internal bool CorruptNextReadback { get; set; }

    internal bool FailNextWrite { get; set; }

    internal Func<int, long?>? GeometryOverride { get; set; }

    internal bool WasWriteSeen { get; private set; }

    public Task<ProcessResult> RunAsync(ProcessCommand command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        cancellationToken.ThrowIfCancellationRequested();
        Commands.Add(command);

        return Task.FromResult(new ProcessResult(0, Execute(command, cancellationToken), string.Empty));
    }

    private string Execute(ProcessCommand command, CancellationToken cancellationToken)
    {
        if (command.Arguments.Count == 0)
        {
            throw new InvalidOperationException("fixture: the synthetic EDL command has no arguments");
        }

        string verb = command.Arguments[0];
        switch (verb)
        {
            case "printgpt":
                return PrintGpt(LunOf(command), cancellationToken);

            case "read-sector":
                return ReadSector(command, cancellationToken);

            case "write-sector":
                return WriteSector(command, cancellationToken);

            case "reset":
                ResetCount++;
                return ReplaceBus(E003EdlTestData.ResetSuccess());

            default:
                throw new InvalidOperationException($"fixture: unsupported synthetic EDL command '{verb}'");
        }
    }

    private string PrintGpt(int lun, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var text = new StringBuilder();
        text.AppendLine(E003EdlTestData.Selected(BusSerialHex));

        if (!_saharaEmitted)
        {
            text.AppendLine(E003EdlTestData.Sahara(BusSerialHex, HardwareId));
            _saharaEmitted = true;
        }

        long total = GeometryOverride?.Invoke(lun) ?? _device.TotalSectors(lun);
        text.Append(E003EdlTestData.Geometry(lun, total));
        return text.ToString();
    }

    private string ReadSector(ProcessCommand command, CancellationToken cancellationToken)
    {
        long start = ParseLong(command, 1);
        long count = ParseLong(command, 2);
        string path = command.Arguments[3];
        int lun = LunOf(command);

        cancellationToken.ThrowIfCancellationRequested();
        byte[] bytes = _device.Read(lun, start, count);

        if (CorruptNextReadback && WasWriteSeen && bytes.Length > 0)
        {
            // One-shot readback corruption: only the first byte, only after a write was applied.
            bytes[0] ^= 0xFF;
            CorruptNextReadback = false;
        }

        File.WriteAllBytes(path, bytes);
        Reads.Add(new GlobalEdlTestIo(lun, start, count, path));

        var log = new StringBuilder();
        log.AppendLine(E003EdlTestData.Selected(BusSerialHex));

        if (!_saharaEmitted)
        {
            log.AppendLine(E003EdlTestData.Sahara(BusSerialHex, HardwareId));
            _saharaEmitted = true;
        }

        long total = GeometryOverride?.Invoke(lun) ?? _device.TotalSectors(lun);
        string geometry = string.Join(
            "\n",
            E003EdlTestData.Geometry(lun, total)
                .Split('\n')
                .Where(line =>
                    !line.Contains("GPT Header", StringComparison.Ordinal) &&
                    !line.Contains("'printgpt' command finished", StringComparison.Ordinal)));

        log.AppendLine(geometry);
        log.Append(ReplaceBus(E003EdlTestData.ReadSuccess(lun, start, count, bytes.Length, path)));
        return log.ToString();
    }

    private string WriteSector(ProcessCommand command, CancellationToken cancellationToken)
    {
        long start = ParseLong(command, 1);
        string path = command.Arguments[2];
        int lun = LunOf(command);

        cancellationToken.ThrowIfCancellationRequested();
        byte[] bytes = File.ReadAllBytes(path);
        long count = bytes.Length / GlobalEdlTestDevice.SectorSize;

        // Captured before the injected failure so the test can still see the attempted write phase.
        Writes.Add(new GlobalEdlTestIo(lun, start, count, path));

        if (FailNextWrite)
        {
            FailNextWrite = false;
            throw new IOException("fixture: injected write-sector failure after the invocation started");
        }

        if (!IgnoreWrites)
        {
            _device.Write(lun, start, bytes);
        }

        WasWriteSeen = true;
        return ReplaceBus(E003EdlTestData.WriteSuccess(lun, start, count, bytes.Length));
    }

    private string ReplaceBus(string text) =>
        text.Replace(E003EdlTestData.BusSerialHex, BusSerialHex, StringComparison.Ordinal);

    private static long ParseLong(ProcessCommand command, int index) =>
        long.Parse(command.Arguments[index], CultureInfo.InvariantCulture);

    /// <summary>Finds the value that follows a literal <c>--lun</c> token.</summary>
    private static int LunOf(ProcessCommand command)
    {
        IReadOnlyList<string> arguments = command.Arguments;
        for (var index = 0; index + 1 < arguments.Count; index++)
        {
            if (arguments[index] == "--lun")
            {
                return int.Parse(arguments[index + 1], CultureInfo.InvariantCulture);
            }
        }

        throw new InvalidOperationException("fixture: the synthetic EDL command has no --lun value");
    }
}
