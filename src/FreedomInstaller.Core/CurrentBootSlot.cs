using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// Read-only active-slot facts resolved from one verified internal backup. The current slot is the AOSP
/// misc boot-control active slot when the control block is present; on a Qualcomm Y700 whose control block
/// is entirely zero it is resolved from the verified primary/backup GPT pair's slot flags. Facts carry no
/// device-write authority. The virtual A/B source_slot, historical metadata and other partition flags are
/// never used.
/// </summary>
public sealed record CurrentBootSlotFacts(
    string CurrentSlot,
    string ControlSha256,
    bool NeedsBootloaderAttention = false,
    string Source = "aosp-misc",
    uint? Crc32 = null);

/// <summary>
/// Read-only resolver for the active boot slot of one verified internal backup. Reads the captured misc
/// region with FileShare.Read, verifies its whole-file length and SHA-256, then reads the 32-byte AOSP
/// boot_control block at offset 2048. Delegates non-zero blocks to <see cref="BootSlotControl"/> unchanged.
/// For an all-zero block only, accepts the exact Qualcomm Y700 models and resolves the slot from the
/// verified GPT pair of the boot_a/boot_b LUN using its slot attribute flags. Never mutates a file or
/// issues any device command.
/// </summary>
public static class CurrentBootSlot
{
    private const int ControlOffset = 2048;
    private const int ControlLength = 32;
    private const int MinimumMiscLength = 2080;
    private const long CaptureSectors = 64;

    private const string ModelA = "TB322FC";
    private const string ModelB = "TB323FU";

    private const ulong PriorityMask = 0x3UL;
    private const ulong ActiveBit = 1UL << 50;
    private const ulong RetriesMask = 0x7UL;
    private const ulong SuccessfulBit = 1UL << 54;
    private const ulong UnbootableBit = 1UL << 55;

    public static async Task<CurrentBootSlotFacts> ReadAsync(InternalBackupSet backup, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(backup);
        token.ThrowIfCancellationRequested();

        if (!backup.Files.TryGetValue("misc", out EdlCapturedRegion? misc) || misc is null)
        {
            throw new InvalidDataException(
                "boot-slot-control-invalid: the backup set contains no misc capture, so the active slot cannot be verified.");
        }

        byte[] miscBytes = await ReadAndVerifyAsync(misc, token).ConfigureAwait(false);
        if (miscBytes.Length < MinimumMiscLength)
        {
            throw new InvalidDataException(
                "boot-slot-control-invalid: the misc capture is " + miscBytes.Length.ToString(CultureInfo.InvariantCulture)
                + " bytes but at least " + MinimumMiscLength.ToString(CultureInfo.InvariantCulture)
                + " are required for the boot-control block.");
        }

        if (!IsAllZero(miscBytes.AsSpan(ControlOffset, ControlLength)))
        {
            BootSlotControlFacts aosp = await BootSlotControl
                .ReadAsync(new VerifiedEdlFile(misc.FilePath, misc.Length, misc.Sha256), token)
                .ConfigureAwait(false);
            return new CurrentBootSlotFacts(aosp.CurrentSlot, aosp.ControlSha256, aosp.NeedsBootloaderAttention, Crc32: aosp.Crc32);
        }

        string controlSha = Sha256Hex(miscBytes.AsSpan(ControlOffset, ControlLength));
        return await ResolveFromGptAsync(backup, controlSha, token).ConfigureAwait(false);
    }

    private static async Task<CurrentBootSlotFacts> ResolveFromGptAsync(
        InternalBackupSet backup, string controlSha, CancellationToken token)
    {
        if (string.IsNullOrEmpty(backup.Model)
            || (!string.Equals(backup.Model, ModelA, StringComparison.Ordinal)
                && !string.Equals(backup.Model, ModelB, StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "boot-slot-control-invalid: the misc control block is all zero and model '" + (backup.Model ?? "")
                + "' is not an accepted Qualcomm Y700 model; the GPT active slot cannot be authorized.");
        }

        int lun = FindBootLun(backup);
        string lunText = lun.ToString(CultureInfo.InvariantCulture);

        if (!backup.Geometries.TryGetValue(lun, out EdlGeometry? geometry) || geometry is null
            || geometry.SectorSize <= 0 || geometry.TotalSectors <= 0)
        {
            throw new InvalidDataException(
                "boot-slot-control-invalid: no positive captured geometry exists for LUN " + lunText + ".");
        }

        long sectorSize = geometry.SectorSize;
        long totalSectors = geometry.TotalSectors;
        long diskBytes = checked(totalSectors * sectorSize);

        EdlCapturedRegion primary = RequireGpt(backup, "gpt_lun" + lunText + "_primary");
        EdlCapturedRegion backupGpt = RequireGpt(backup, "gpt_lun" + lunText + "_backup");

        if (primary.Lun != lun || backupGpt.Lun != lun)
        {
            throw new InvalidDataException(
                "boot-slot-control-invalid: a captured GPT region for LUN " + lunText + " records the wrong LUN.");
        }

        if (primary.StartSector != 0 || primary.SectorCount != CaptureSectors || primary.Length != CaptureSectors * sectorSize)
        {
            throw new InvalidDataException(
                "boot-slot-control-invalid: the captured primary GPT is not the expected " + CaptureSectors
                + "-sector window at sector 0.");
        }

        long expectedBackupStart = totalSectors - CaptureSectors;
        if (expectedBackupStart < 0 || backupGpt.StartSector != expectedBackupStart
            || backupGpt.SectorCount != CaptureSectors || backupGpt.Length != CaptureSectors * sectorSize)
        {
            throw new InvalidDataException(
                "boot-slot-control-invalid: the captured backup GPT is not the expected " + CaptureSectors
                + "-sector tail window ending at total sector " + totalSectors.ToString(CultureInfo.InvariantCulture) + ".");
        }

        byte[] primaryBytes = await ReadAndVerifyAsync(primary, token).ConfigureAwait(false);
        byte[] backupBytes = await ReadAndVerifyAsync(backupGpt, token).ConfigureAwait(false);

        GptTable parsed;
        try
        {
            parsed = OriginalGptImporter.Parse(primaryBytes, backupBytes, checked((int)sectorSize), diskBytes);
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentException or OverflowException or FormatException)
        {
            throw new InvalidDataException(
                "boot-slot-control-invalid: the captured LUN " + lunText + " GPT pair failed verification: " + ex.Message, ex);
        }

        if (!backup.Tables.TryGetValue(lun, out GptTable? captured) || captured is null
            || !string.Equals(captured.SourceFingerprint, parsed.SourceFingerprint, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "boot-slot-control-invalid: the verified LUN " + lunText + " GPT pair does not match the captured table.");
        }

        GptPartition bootA = FindSingle(parsed, "boot_a");
        GptPartition bootB = FindSingle(parsed, "boot_b");

        bool activeA = (bootA.Attributes & ActiveBit) != 0;
        bool activeB = (bootB.Attributes & ActiveBit) != 0;
        if (activeA == activeB)
        {
            throw new InvalidDataException(
                "boot-slot-control-invalid: exactly one of boot_a/boot_b must carry the raw active bit, but "
                + (activeA ? "both" : "neither") + " do.");
        }

        GptPartition chosen = activeA ? bootA : bootB;
        ulong priority = (chosen.Attributes >> 48) & PriorityMask;
        ulong retries = (chosen.Attributes >> 51) & RetriesMask;
        bool successful = (chosen.Attributes & SuccessfulBit) != 0;
        bool unbootable = (chosen.Attributes & UnbootableBit) != 0;
        if (priority == 0 || unbootable || !(successful || retries > 0))
        {
            throw new InvalidDataException(
                "boot-slot-control-invalid: the sole raw-active slot '" + (activeA ? "a" : "b")
                + " is not eligible (priority > 0, not unbootable, successful or retries > 0 required).");
        }

        string authority = BuildAuthority(lun, primary.Sha256, backupGpt.Sha256, controlSha);
        return new CurrentBootSlotFacts(activeA ? "a" : "b", authority, Source: "qualcomm-gpt");
    }

    private static string BuildAuthority(int lun, string primarySha, string backupSha, string controlSha)
    {
        string material = "qcom-gpt-v1|lun=" + lun.ToString(CultureInfo.InvariantCulture)
            + "|primary=" + primarySha.ToLowerInvariant()
            + "|backup=" + backupSha.ToLowerInvariant()
            + "|control32=" + controlSha;
        return Sha256Hex(System.Text.Encoding.ASCII.GetBytes(material));
    }

    private static int FindBootLun(InternalBackupSet backup)
    {
        int bootA = -1;
        int bootB = -1;
        foreach (var pair in backup.Tables)
        {
            foreach (GptPartition partition in pair.Value.Partitions)
            {
                if (string.Equals(partition.Name, "boot_a", StringComparison.Ordinal))
                {
                    if (bootA >= 0) throw Ambiguous("boot_a");
                    bootA = pair.Key;
                }
                else if (string.Equals(partition.Name, "boot_b", StringComparison.Ordinal))
                {
                    if (bootB >= 0) throw Ambiguous("boot_b");
                    bootB = pair.Key;
                }
            }
        }

        if (bootA < 0 || bootB < 0)
        {
            throw new InvalidDataException(
                "boot-slot-control-invalid: the captured GPT tables do not contain exactly one boot_a and one boot_b.");
        }

        if (bootA != bootB)
        {
            throw new InvalidDataException(
                "boot-slot-control-invalid: boot_a and boot_b were captured on different LUNs, so the active slot is ambiguous.");
        }

        return bootA;
    }

    private static InvalidDataException Ambiguous(string name) => new(
        "boot-slot-control-invalid: '" + name + "' appears more than once across the captured GPT tables.");

    private static GptPartition FindSingle(GptTable table, string name)
    {
        GptPartition? found = null;
        foreach (GptPartition partition in table.Partitions)
        {
            if (!string.Equals(partition.Name, name, StringComparison.Ordinal)) continue;
            if (found is not null) throw Ambiguous(name);
            found = partition;
        }

        if (found is null)
        {
            throw new InvalidDataException(
                "boot-slot-control-invalid: the verified GPT pair does not contain the expected '" + name + "' partition.");
        }

        return found;
    }

    private static EdlCapturedRegion RequireGpt(InternalBackupSet backup, string role)
    {
        if (!backup.Files.TryGetValue(role, out EdlCapturedRegion? region) || region is null)
        {
            throw new InvalidDataException("boot-slot-control-invalid: the backup set contains no '" + role + "' capture.");
        }

        return region;
    }

    private static async Task<byte[]> ReadAndVerifyAsync(EdlCapturedRegion region, CancellationToken token)
    {
        byte[] bytes = new byte[checked((int)region.Length)];
        int offset = 0;
        await using (var stream = new FileStream(
            region.FilePath, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 1, FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            if (stream.Length != region.Length)
            {
                throw new InvalidDataException(
                    "boot-slot-control-invalid: the capture '" + region.FilePath + "' is not the claimed length.");
            }

            while (offset < bytes.Length)
            {
                token.ThrowIfCancellationRequested();
                int read = await stream.ReadAsync(bytes.AsMemory(offset), token).ConfigureAwait(false);
                if (read <= 0) break;
                offset += read;
            }
        }

        if (offset != bytes.Length)
        {
            throw new InvalidDataException(
                "boot-slot-control-invalid: the capture '" + region.FilePath + "' ended early.");
        }

        if (!string.Equals(Sha256Hex(bytes), region.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "boot-slot-control-invalid: the capture '" + region.FilePath + "' does not match its claimed SHA-256.");
        }

        return bytes;
    }

    private static bool IsAllZero(ReadOnlySpan<byte> span)
    {
        foreach (byte value in span)
        {
            if (value != 0) return false;
        }

        return true;
    }

    private static string Sha256Hex(ReadOnlySpan<byte> span)
        => Convert.ToHexString(SHA256.HashData(span)).ToLowerInvariant();
}
