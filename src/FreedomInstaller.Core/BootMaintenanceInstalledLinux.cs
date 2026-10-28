// BM05: minimal actual installed-Linux boot evidence reader for OTA repair.
// Scope boundary (root-approved): this reader proves ONLY that the CURRENT selected
// ARMADA_BOOT BLS default entry, its actual kernel/initrd bytes and the CURRENT
// ARMADA_ROOT Btrfs FSID still match the chosen repair package. It proves reuse of
// the installed boot configuration. It is NOT a statement of complete Btrfs
// deployment-tree health and NOT OS acceptance. There is no Btrfs tree reader, no
// mount, no remote command and no device write/reset here; the root tree contents
// are never read. The TF (SD card) owner keeps its own separate API; this reader is
// bound to the internal EDL LUN0 ARMADA_BOOT/ARMADA_ROOT domain only.
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// Verified facts about the currently installed Linux boot on the device, established only from
/// freshly read device bytes. Every value is an observation of the actual on-device boot
/// configuration after it was bound to the repair package by exact equality; nothing is copied
/// out of the package declarations alone.
/// <para>
/// <see cref="ScopeDescription"/> is the factual boundary statement: the Btrfs root deployment
/// tree was NOT verified and these facts are not OS acceptance.
/// </para>
/// </summary>
internal sealed class InstalledLinuxBootFacts
{
    internal InstalledLinuxBootFacts(
        Guid bootUuid,
        Guid rootUuid,
        string selectedEntryPath,
        string bootChecksum,
        string kernelSha256,
        string initramfsSha256,
        string kernelPath,
        string initramfsPath,
        IReadOnlyList<VerifiedEdlFile> evidenceFiles,
        string scopeDescription)
    {
        BootUuid = bootUuid;
        RootUuid = rootUuid;
        SelectedEntryPath = selectedEntryPath;
        BootChecksum = bootChecksum;
        KernelSha256 = kernelSha256;
        InitramfsSha256 = initramfsSha256;
        KernelPath = kernelPath;
        InitramfsPath = initramfsPath;
        EvidenceFiles = new ReadOnlyCollection<VerifiedEdlFile>(new List<VerifiedEdlFile>(evidenceFiles));
        ScopeDescription = scopeDescription;
    }

    /// <summary>Actual ext4 UUID read from the current boot filesystem superblock.</summary>
    public Guid BootUuid { get; }

    /// <summary>Actual Btrfs FSID read from the current root superblock at partition byte 65536.</summary>
    public Guid RootUuid { get; }

    /// <summary>The BLS entry path the CURRENT loader default actually resolved to.</summary>
    public string SelectedEntryPath { get; }

    /// <summary>
    /// The ostree boot checksum exactly as it was read out of the selected entry's options and
    /// matched, by exact equality, against the package deployment boot checksum.
    /// </summary>
    public string BootChecksum { get; }

    /// <summary>SHA-256 (lowercase hex) of the whole actual selected kernel file.</summary>
    public string KernelSha256 { get; }

    /// <summary>SHA-256 (lowercase hex) of the whole actual selected initramfs file.</summary>
    public string InitramfsSha256 { get; }

    /// <summary>The linux path exactly as declared by the selected BLS entry.</summary>
    public string KernelPath { get; }

    /// <summary>The initrd path exactly as declared by the selected BLS entry.</summary>
    public string InitramfsPath { get; }

    /// <summary>
    /// Read-only copies of the evidence files the native factory created; empty for the pure
    /// <c>VerifyCaptured</c> path, which owns no files.
    /// </summary>
    public IReadOnlyList<VerifiedEdlFile> EvidenceFiles { get; }

    /// <summary>Factual description of what was and was not verified.</summary>
    public string ScopeDescription { get; }
}

/// <summary>
/// INTERNAL factory that reads the CURRENT installed Linux boot evidence over one live EDL
/// session and binds it to one repair package by exact equality. Mismatches and unsupported
/// actual layouts always reject; there is no success fallback and no package-only substitution.
/// <para>
/// Reads are minimal: the whole current ARMADA_BOOT partition and one aligned region of the
/// current ARMADA_ROOT partition head carrying the real Btrfs superblock at partition byte
/// 65536, both into unique new evidence files under the caller's explicit existing evidence
/// directory. userdata, super and the rest of the root tree are never read; the device is never
/// written, reset or mounted.
/// </para>
/// <para>
/// The parent backend owns global freshness; this type additionally cross-checks the current
/// LUN0 geometry against the geometry proven by the supplied current backup set, requires the
/// exact binding reference of that set, and finds ARMADA_BOOT/ARMADA_ROOT exactly once each in
/// the freshly parsed current LUN0 table - never at guessed offsets. A package or recipe whose
/// domain is not this internal LUN0 domain fails structurally here (no ARMADA_BOOT/ARMADA_ROOT
/// pair, or disagreeing UUIDs), never by name confusion with a TF recipe.
/// </para>
/// </summary>
internal static class BootMaintenanceInstalledLinux
{
    private const string BootRole = "ARMADA_BOOT";
    private const string RootRole = "ARMADA_ROOT";
    private const string MismatchPrefix = "maintenance-installed-linux-mismatch: ";

    /// <summary>The frozen factual scope statement carried by every produced facts object.</summary>
    private const string ScopeText =
        "BM05 verified only the currently selected ARMADA_BOOT BLS default entry, its actual "
        + "kernel and initramfs bytes, and the ARMADA_ROOT Btrfs FSID against the repair package. "
        + "The Btrfs root deployment tree was NOT verified; this is not a statement of complete "
        + "root filesystem health and not OS acceptance.";

    private const int MinimumLunTotalSectors = 129;
    private const int CopyBufferBytes = 64 * 1024;

    // ------------------------------------------------------------------ ext4 on-disk constants

    private const long Ext4SuperblockOffset = 1024L;
    private const int Ext4SuperblockBytes = 0x160;
    private const int Ext4InodesCountOffset = 0x00;
    private const int Ext4BlocksCountLowOffset = 0x04;
    private const int Ext4FirstDataBlockOffset = 0x14;
    private const int Ext4LogBlockSizeOffset = 0x18;
    private const int Ext4BlocksPerGroupOffset = 0x20;
    private const int Ext4InodesPerGroupOffset = 0x28;
    private const int Ext4MagicOffset = 0x38;
    private const int Ext4InodeSizeOffset = 0x58;
    private const int Ext4FeatureIncompatOffset = 0x60;
    private const int Ext4UuidOffset = 0x68;
    private const int Ext4DescSizeOffset = 0xFE;
    private const int Ext4BlocksCountHighOffset = 0x150;

    private const ushort Ext4Magic = 0xEF53;
    private const uint Ext4IncompatFileType = 0x2u;
    private const uint Ext4IncompatExtents = 0x40u;
    private const uint Ext4Incompat64Bit = 0x80u;
    private const uint Ext4IncompatFlexBg = 0x200u;

    /// <summary>The only incompatible features this bounded reader accepts.</summary>
    private const uint Ext4IncompatAccepted =
        Ext4IncompatFileType | Ext4IncompatExtents | Ext4Incompat64Bit | Ext4IncompatFlexBg;

    private const uint Ext4MaxLogBlockSize = 6;
    private const int Ext4DescriptorBytes32 = 32;
    private const int Ext4DescriptorInodeTableLowOffset = 0x08;
    private const int Ext4DescriptorInodeTableHighOffset = 0x28;

    private const uint RootInodeNumber = 2u;
    private const int InodeBytesRead = 0x70;
    private const int InodeModeOffset = 0x00;
    private const int InodeSizeLowOffset = 0x04;
    private const int InodeBlocksLowOffset = 0x1C;
    private const int InodeFlagsOffset = 0x20;
    private const int InodeBlockAreaOffset = 0x28;
    private const int InodeBlockAreaBytes = 60;
    private const int InodeSizeHighOffset = 0x6C;

    private const ushort InodeModeTypeMask = 0xF000;
    private const ushort InodeModeDirectory = 0x4000;
    private const ushort InodeModeRegular = 0x8000;
    private const ushort InodeModeSymlink = 0xA000;
    private const uint InodeFlagExtents = 0x80000u;

    private const ushort ExtentMagic = 0xF30A;
    private const int ExtentHeaderBytes = 12;
    private const int ExtentEntryBytes = 12;
    private const int ExtentHeaderDepthOffset = 6;
    private const ushort ExtentUnwrittenMarker = 0x8000;
    private const int MaxExtentDepth = 5;

    private const int MaxPathComponents = 64;
    private const int MaxSymlinkFollows = 8;
    private const int MaxSymlinkTargetBytes = 4096;
    private const int FastSymlinkMaxBytes = 60;
    private const long MaxVerifiedFileBytes = 512L * 1024 * 1024;
    private const long MaxDirectoryBytes = 16L * 1024 * 1024;
    private const long MaxGroupTableBytes = 16L * 1024 * 1024;
    private const long MaxLoaderConfBytes = 1024L * 1024;
    private const long MaxBlsEntryBytes = 64L * 1024;

    // ----------------------------------------------------------------- btrfs superblock constants

    private const long BtrfsSuperblockOffset = 65536L;
    private const int RootSuperReadBytes = 4096;
    private const int BtrfsSuperblockBytes = 148;
    private const int BtrfsFsidOffset = 32;
    private const int BtrfsBytenrOffset = 48;
    private const int BtrfsMagicOffset = 64;
    private const int BtrfsMagicLength = 8;
    private const int BtrfsTotalBytesOffset = 112;
    private const int BtrfsSectorSizeOffset = 144;

    /// <summary>Exactly the eight ASCII bytes a primary Btrfs superblock carries at +64.</summary>
    private static readonly byte[] BtrfsSuperblockMagic = Encoding.ASCII.GetBytes("_BHRfS_M");

    private static readonly UTF8Encoding StrictUtf8Encoding =
        new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private static readonly char[] SpaceTab = { ' ', '\t' };

    // ------------------------------------------------------------------ native entry

    /// <summary>
    /// Reads the CURRENT installed Linux boot evidence over <paramref name="client"/>'s live
    /// session and verifies it against <paramref name="package"/>, using the current LUN0 table
    /// of <paramref name="currentBackup"/> for the actual ARMADA_BOOT/ARMADA_ROOT placement.
    /// Returns facts only when every binding check succeeded; every mismatch or unsupported
    /// actual layout throws <see cref="InvalidOperationException"/> with the stable
    /// <c>maintenance-installed-linux-mismatch:</c> code prefix.
    /// </summary>
    internal static async Task<InstalledLinuxBootFacts> VerifyAsync(
        EdlClient client,
        InternalBackupSet currentBackup,
        EdlRawPackageContract package,
        string evidenceDirectory,
        CancellationToken ct = default)
    {
        if (client is null)
        {
            throw new ArgumentNullException(nameof(client));
        }

        if (currentBackup is null)
        {
            throw new ArgumentNullException(nameof(currentBackup));
        }

        if (package is null)
        {
            throw new ArgumentNullException(nameof(package));
        }

        ct.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(evidenceDirectory))
        {
            throw new ArgumentException(
                "An existing evidence directory path is required.", nameof(evidenceDirectory));
        }

        // The current backup set must belong to this exact session binding; a foreign or
        // substituted binding is rejected before any read, mirroring the capture precedent.
        if (!ReferenceEquals(client.Binding, currentBackup.Binding))
        {
            throw new InvalidOperationException(
                "The current backup set was not taken from this exact EDL session binding; "
                + "a foreign binding is rejected.");
        }

        if (!string.Equals(client.Toolchain.Model, currentBackup.Model, StringComparison.Ordinal)
            || !string.Equals(client.Toolchain.HardwareId, currentBackup.HardwareId, StringComparison.OrdinalIgnoreCase))
        {
            throw Mismatch(
                "the loaded toolchain model or hardware id does not match the current backup set");
        }

        string directory = Path.GetFullPath(evidenceDirectory);
        if (!Directory.Exists(directory))
        {
            throw new IOException(
                "The BM05 evidence directory does not exist: '" + directory + "'.");
        }

        // Warm probe when the session already proved the initial loader; the actual initial
        // probe otherwise. The probe itself re-proves the bound bus identity and endpoint.
        EdlProbeEvidence probe = await client
            .ProbeAsync(0, initialLoader: !client.HasInitialSaharaProof, ct)
            .ConfigureAwait(false);

        EdlGeometry lun0 = RequireLun0Geometry(probe);

        if (!currentBackup.Geometries.TryGetValue(0, out EdlGeometry? backupGeometry)
            || backupGeometry is null
            || backupGeometry.SectorSize != lun0.SectorSize
            || backupGeometry.TotalSectors != lun0.TotalSectors)
        {
            throw Mismatch(
                "the current LUN0 geometry does not match the geometry proven by the current backup set");
        }

        if (!currentBackup.Tables.TryGetValue(0, out GptTable? table) || table is null)
        {
            throw Mismatch("the current backup set carries no LUN0 table");
        }

        if (table.SectorSize != lun0.SectorSize)
        {
            throw Mismatch("the LUN0 table sector size differs from the current LUN0 geometry");
        }

        GptPartition boot = RequireSinglePartition(table, BootRole, lun0);
        GptPartition root = RequireSinglePartition(table, RootRole, lun0);

        long bootBytes = CheckedMulL(boot.SectorCount, lun0.SectorSize, "'" + BootRole + "' byte length overflows.");
        long rootBytes = CheckedMulL(root.SectorCount, lun0.SectorSize, "'" + RootRole + "' byte length overflows.");
        if (rootBytes < BtrfsSuperblockOffset + RootSuperReadBytes)
        {
            throw Mismatch(
                "'" + RootRole + "' is too small to carry a Btrfs superblock at partition byte "
                + BtrfsSuperblockOffset.ToString(System.Globalization.CultureInfo.InvariantCulture) + ".");
        }

        long superSectorCount =
            (BtrfsSuperblockOffset + RootSuperReadBytes + lun0.SectorSize - 1) / lun0.SectorSize;
        if (superSectorCount > lun0.TotalSectors - root.StartSector)
        {
            throw Mismatch("the '" + RootRole + "' superblock region lies beyond LUN0.");
        }

        string bootPath = NewEvidencePath(directory, "bm05-armada-boot-");
        EdlReadEvidence bootEvidence = await client
            .ReadAsync(0, boot.StartSector, boot.SectorCount, bootPath, ct)
            .ConfigureAwait(false);
        VerifyReadEvidence(bootEvidence, lun0, boot.StartSector, boot.SectorCount, bootBytes, bootPath);
        (long bootLength, string bootSha) =
            await SealFileAsync(bootPath, bootBytes, bootEvidence.Sha256, ct).ConfigureAwait(false);

        string rootPath = NewEvidencePath(directory, "bm05-armada-root-super-");
        long rootRegionBytes = CheckedMulL(superSectorCount, lun0.SectorSize, "root super region overflows.");
        EdlReadEvidence rootEvidence = await client
            .ReadAsync(0, root.StartSector, superSectorCount, rootPath, ct)
            .ConfigureAwait(false);
        VerifyReadEvidence(rootEvidence, lun0, root.StartSector, superSectorCount, rootRegionBytes, rootPath);
        (long rootLength, string rootSha) =
            await SealFileAsync(rootPath, rootRegionBytes, rootEvidence.Sha256, ct).ConfigureAwait(false);

        byte[] rootRegion = await File.ReadAllBytesAsync(rootPath, ct).ConfigureAwait(false);
        ReadOnlySpan<byte> super = rootRegion.AsSpan((int)BtrfsSuperblockOffset, RootSuperReadBytes);

        // Native-only partition bound on top of the shared parser: the declared Btrfs total
        // bytes must fit inside the actual current ARMADA_ROOT partition.
        long declaredRootBytes =
            BinaryPrimitives.ReadInt64LittleEndian(super.Slice(BtrfsTotalBytesOffset, 8));
        if (declaredRootBytes <= 0 || declaredRootBytes > rootBytes)
        {
            throw Mismatch(
                "the Btrfs total_bytes of " + declaredRootBytes.ToString(System.Globalization.CultureInfo.InvariantCulture)
                + " does not fit the actual '" + RootRole + "' partition of "
                + rootBytes.ToString(System.Globalization.CultureInfo.InvariantCulture) + " bytes.");
        }

        InstalledLinuxBootFacts parsed;
        FileStream bootStream = new(
            bootPath, FileMode.Open, FileAccess.Read, FileShare.Read, CopyBufferBytes,
            FileOptions.SequentialScan);
        try
        {
            parsed = VerifyCaptured(bootStream, super, package, ct);
        }
        finally
        {
            bootStream.Dispose();
        }

        var evidence = new List<VerifiedEdlFile>
        {
            new(bootPath, bootLength, bootSha),
            new(rootPath, rootLength, rootSha),
        };

        return new InstalledLinuxBootFacts(
            parsed.BootUuid,
            parsed.RootUuid,
            parsed.SelectedEntryPath,
            parsed.BootChecksum,
            parsed.KernelSha256,
            parsed.InitramfsSha256,
            parsed.KernelPath,
            parsed.InitramfsPath,
            evidence,
            parsed.ScopeDescription);
    }

    /// <summary>
    /// Pure, file-free core of the verification: parses the captured boot ext4 stream (the
    /// filesystem begins at stream offset 0) and the captured root superblock bytes (the Btrfs
    /// primary superblock at partition byte 65536) and binds both to
    /// <paramref name="package"/> by exact equality. This is the same parser path the native
    /// entry uses; it exists so real behavior tests can drive it without a device.
    /// <para>
    /// The method is synchronous because the frozen <c>ReadOnlySpan&lt;byte&gt;</c> parameter
    /// cannot cross an async boundary. Cancellation is honored through
    /// <paramref name="ct"/> at the loop checkpoints. <see cref="InstalledLinuxBootFacts.EvidenceFiles"/>
    /// is empty here: the pure path owns no files.
    /// </para>
    /// </summary>
    internal static InstalledLinuxBootFacts VerifyCaptured(
        Stream bootFilesystem,
        ReadOnlySpan<byte> rootSuperblock,
        EdlRawPackageContract package,
        CancellationToken ct = default)
    {
        if (bootFilesystem is null)
        {
            throw new ArgumentNullException(nameof(bootFilesystem));
        }

        if (package is null)
        {
            throw new ArgumentNullException(nameof(package));
        }

        ct.ThrowIfCancellationRequested();

        if (!bootFilesystem.CanRead || !bootFilesystem.CanSeek)
        {
            throw new ArgumentException(
                "The boot filesystem stream must be readable and seekable.", nameof(bootFilesystem));
        }

        if (rootSuperblock.Length < BtrfsSuperblockBytes)
        {
            throw Mismatch(
                "the captured root superblock region is too short for a Btrfs primary superblock");
        }

        // The package must be self-consistent in both UUID domains before the device is judged.
        if (package.BootRecipe.BootUuid != package.BootImage.FsUuid)
        {
            throw Mismatch("the package boot image FS UUID and boot recipe boot UUID disagree");
        }

        if (package.BootRecipe.RootUuid != package.RootImage.FsUuid)
        {
            throw Mismatch("the package root image FS UUID and boot recipe root UUID disagree");
        }

        Ext4Volume volume = Ext4Volume.Open(bootFilesystem, package.BootRecipe.BootUuid);
        Guid rootUuid = VerifyBtrfsRoot(rootSuperblock, package);

        (uint loaderIno, ushort loaderMode) = volume.ResolvePath("/loader", "/loader", ct);
        RequireDirectory(loaderMode, "/loader");

        (uint confIno, ushort confMode) = volume.ResolvePath("/loader/loader.conf", "/loader/loader.conf", ct);
        if ((confMode & InodeModeTypeMask) != InodeModeRegular)
        {
            throw Mismatch("'/loader/loader.conf' is not a regular file");
        }

        string loaderText = StrictUtf8(
            volume.ReadFileBytes(confIno, MaxLoaderConfBytes, "/loader/loader.conf", ct),
            "/loader/loader.conf");

        (uint entriesIno, ushort entriesMode) = volume.ResolvePath("/loader/entries", "/loader/entries", ct);
        RequireDirectory(entriesMode, "/loader/entries");

        (string selectedFileName, uint selectedIno) =
            SelectEntry(volume, entriesIno, ReadLoaderDefault(loaderText), ct);
        string selectedPath = "/loader/entries/" + selectedFileName;

        string entryText = StrictUtf8(
            volume.ReadFileBytes(selectedIno, MaxBlsEntryBytes, selectedPath, ct), selectedPath);
        (string linuxPath, string initrdPath, string options) = ParseBlsEntry(entryText, selectedPath);

        string bootChecksum = BindOptions(package, options, selectedPath);

        uint kernelIno = volume.ResolvePath(linuxPath, "the BLS linux path of " + selectedPath, ct).Ino;
        (ulong kernelLength, string kernelSha256) =
            volume.HashRegularFile(kernelIno, "the selected kernel '" + linuxPath + "'", ct);
        VerifyArtifact(package, "kernel", kernelLength, kernelSha256, linuxPath);

        uint initrdIno = volume.ResolvePath(initrdPath, "the BLS initrd path of " + selectedPath, ct).Ino;
        (ulong initrdLength, string initrdSha256) =
            volume.HashRegularFile(initrdIno, "the selected initramfs '" + initrdPath + "'", ct);
        VerifyArtifact(package, "initramfs", initrdLength, initrdSha256, initrdPath);

        return new InstalledLinuxBootFacts(
            volume.BootUuid,
            rootUuid,
            selectedPath,
            bootChecksum,
            kernelSha256,
            initrdSha256,
            linuxPath,
            initrdPath,
            Array.Empty<VerifiedEdlFile>(),
            ScopeText);
    }

    // ------------------------------------------------------------------ native helpers

    private static EdlGeometry RequireLun0Geometry(EdlProbeEvidence probe)
    {
        if (probe?.Geometry is null)
        {
            throw new InvalidOperationException("The LUN0 probe returned no geometry.");
        }

        EdlGeometry geometry = probe.Geometry;
        if (geometry.Lun != 0)
        {
            throw Mismatch("the probe returned LUN" + geometry.Lun + " geometry instead of LUN0");
        }

        if (geometry.SectorSize != 512 && geometry.SectorSize != 4096)
        {
            throw Mismatch("LUN0 reported an unsupported sector size of " + geometry.SectorSize + " bytes");
        }

        if (geometry.TotalSectors < MinimumLunTotalSectors)
        {
            throw Mismatch("LUN0 reported too few sectors to carry a GPT disk");
        }

        return geometry;
    }

    private static GptPartition RequireSinglePartition(GptTable table, string name, EdlGeometry lun0)
    {
        GptPartition? found = null;
        foreach (GptPartition partition in table.Partitions)
        {
            if (!string.Equals(partition.Name, name, StringComparison.Ordinal))
            {
                continue;
            }

            if (found is not null)
            {
                throw Mismatch("the current LUN0 table contains '" + name + "' more than once");
            }

            found = partition;
        }

        if (found is null)
        {
            throw Mismatch("the current LUN0 table does not contain '" + name + "'");
        }

        if (found.StartSector < 2 || found.SectorCount <= 0)
        {
            throw Mismatch("the current '" + name + "' partition has an empty or unusable sector range");
        }

        if (found.StartSector > lun0.TotalSectors
            || found.SectorCount > lun0.TotalSectors - found.StartSector)
        {
            throw Mismatch("the current '" + name + "' partition extends past the end of LUN0");
        }

        return found;
    }

    private static string NewEvidencePath(string directory, string stem) =>
        Path.Combine(directory, stem + Guid.NewGuid().ToString("N") + ".bin");

    private static void VerifyReadEvidence(
        EdlReadEvidence evidence,
        EdlGeometry geometry,
        long startSector,
        long sectorCount,
        long expectedLength,
        string path)
    {
        if (evidence is null)
        {
            throw new InvalidOperationException("The read of '" + path + "' returned no evidence.");
        }

        if (evidence.Geometry is null
            || evidence.Geometry.Lun != geometry.Lun
            || evidence.Geometry.SectorSize != geometry.SectorSize
            || evidence.Geometry.TotalSectors != geometry.TotalSectors)
        {
            throw new InvalidOperationException(
                "The read of '" + path + "' reported a geometry that does not match LUN0.");
        }

        if (evidence.StartSector != startSector || evidence.SectorCount != sectorCount)
        {
            throw new InvalidOperationException(
                "The read of '" + path + "' covered a different sector range than requested.");
        }

        if (evidence.Length != expectedLength)
        {
            throw new InvalidOperationException(
                "The read of '" + path + "' returned " + evidence.Length + " bytes instead of "
                + expectedLength + ".");
        }

        if (string.IsNullOrEmpty(evidence.FilePath) || !SamePath(evidence.FilePath, path))
        {
            throw new InvalidOperationException(
                "The read of '" + path + "' reported a different output file.");
        }
    }

    private static async Task<(long Length, string Sha256)> SealFileAsync(
        string path,
        long expectedLength,
        string evidenceSha256,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var info = new FileInfo(path);
        if (!info.Exists)
        {
            throw new IOException("The read did not produce the evidence file '" + path + "'.");
        }

        if (info.Length != expectedLength)
        {
            throw new IOException(
                "The evidence file '" + path + "' holds " + info.Length + " bytes instead of "
                + expectedLength + ".");
        }

        string sha256;
        using (FileStream stream = new(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, CopyBufferBytes,
            FileOptions.SequentialScan))
        {
            sha256 = Convert.ToHexString(
                await SHA256.HashDataAsync(stream, ct).ConfigureAwait(false)).ToLowerInvariant();
        }

        if (string.IsNullOrEmpty(evidenceSha256)
            || !string.Equals(sha256, evidenceSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException(
                "The whole-file SHA-256 of '" + path + "' does not match the read evidence.");
        }

        return (expectedLength, sha256);
    }

    private static bool SamePath(string? left, string right)
    {
        if (string.IsNullOrEmpty(left))
        {
            return false;
        }

        try
        {
            return string.Equals(
                Path.GetFullPath(left), Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase);
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (NotSupportedException)
        {
            return false;
        }
    }

    // ------------------------------------------------------------------ btrfs root superblock

    private static Guid VerifyBtrfsRoot(ReadOnlySpan<byte> super, EdlRawPackageContract package)
    {
        if (!super.Slice(BtrfsMagicOffset, BtrfsMagicLength).SequenceEqual(BtrfsSuperblockMagic))
        {
            throw Mismatch("the captured '" + RootRole + "' superblock does not carry the Btrfs magic at 65536+64");
        }

        if (BinaryPrimitives.ReadInt64LittleEndian(super.Slice(BtrfsBytenrOffset, 8)) != BtrfsSuperblockOffset)
        {
            throw Mismatch("the captured Btrfs superblock bytenr is not 65536");
        }

        var fsid = new Guid(super.Slice(BtrfsFsidOffset, 16), bigEndian: true);
        if (fsid != package.BootRecipe.RootUuid)
        {
            throw Mismatch(
                "the actual Btrfs FSID '" + fsid + "' does not match the package root UUID '"
                + package.BootRecipe.RootUuid + "'");
        }

        long totalBytes = BinaryPrimitives.ReadInt64LittleEndian(super.Slice(BtrfsTotalBytesOffset, 8));
        if (totalBytes <= 0)
        {
            throw Mismatch("the captured Btrfs superblock declares non-positive total bytes");
        }

        int sectorSize = BinaryPrimitives.ReadInt32LittleEndian(super.Slice(BtrfsSectorSizeOffset, 4));
        if (sectorSize < 4096 || sectorSize > 65536 || (sectorSize & (sectorSize - 1)) != 0)
        {
            throw Mismatch(
                "the captured Btrfs superblock declares an unusable sector size of " + sectorSize + " bytes");
        }

        return fsid;
    }

    // ------------------------------------------------------------------ loader.conf and BLS parsing

    private static string? ReadLoaderDefault(string text)
    {
        string? value = null;
        bool seen = false;

        foreach (string raw in text.Split('\n'))
        {
            string line = raw.Trim();
            if (line.Length == 0 || line[0] == '#')
            {
                continue;
            }

            int split = line.IndexOfAny(SpaceTab);
            if (split <= 0)
            {
                continue;
            }

            if (!string.Equals(line[..split], "default", StringComparison.Ordinal))
            {
                continue;
            }

            if (seen)
            {
                throw Mismatch("loader.conf declares 'default' more than once; the selected entry is ambiguous");
            }

            seen = true;
            value = line[(split + 1)..].Trim();
            if (value.Length == 0)
            {
                throw Mismatch("loader.conf declares an empty 'default'");
            }
        }

        return seen ? value : null;
    }

    private static (string FileName, uint Ino) SelectEntry(
        Ext4Volume volume,
        uint entriesDirIno,
        string? defaultValue,
        CancellationToken ct)
    {
        IReadOnlyDictionary<string, (uint Ino, byte Type)> dirEntries =
            volume.ReadDirectory(entriesDirIno, "/loader/entries", ct);

        var candidates = new List<(string Id, string FileName, uint Ino)>();
        foreach (KeyValuePair<string, (uint Ino, byte Type)> pair in dirEntries)
        {
            if (!pair.Key.EndsWith(".conf", StringComparison.Ordinal))
            {
                continue;
            }

            ushort mode = volume.ModeOfInode(pair.Value.Ino, "/loader/entries/" + pair.Key);
            if ((mode & InodeModeTypeMask) != InodeModeRegular)
            {
                continue;
            }

            candidates.Add((pair.Key[..^".conf".Length], pair.Key, pair.Value.Ino));
        }

        if (candidates.Count == 0)
        {
            throw Mismatch("'/loader/entries' carries no BLS '.conf' entry");
        }

        if (defaultValue is null)
        {
            if (candidates.Count != 1)
            {
                throw Mismatch(
                    "loader.conf declares no default and '/loader/entries' carries "
                    + candidates.Count + " entries; the selected entry is ambiguous");
            }

            return (candidates[0].FileName, candidates[0].Ino);
        }

        if (string.Equals(defaultValue, "@saved", StringComparison.Ordinal))
        {
            throw Mismatch(
                "loader.conf declares 'default @saved'; a saved-choice default is not a readable installed fact");
        }

        List<(string Id, string FileName, uint Ino)> matches;
        if (defaultValue.IndexOf('*') >= 0 || defaultValue.IndexOf('?') >= 0)
        {
            matches = candidates
                .Where(entry => GlobMatch(defaultValue, entry.Id) || GlobMatch(defaultValue, entry.FileName))
                .ToList();
        }
        else
        {
            matches = candidates
                .Where(entry => string.Equals(entry.Id, defaultValue, StringComparison.Ordinal)
                    || string.Equals(entry.FileName, defaultValue, StringComparison.Ordinal))
                .ToList();
        }

        if (matches.Count == 0)
        {
            throw Mismatch("the loader default '" + defaultValue + "' does not match any BLS entry in '/loader/entries'");
        }

        if (matches.Count > 1)
        {
            throw Mismatch(
                "the loader default '" + defaultValue + "' matches " + matches.Count
                + " BLS entries; the selected entry is ambiguous");
        }

        return (matches[0].FileName, matches[0].Ino);
    }

    private static (string LinuxPath, string InitrdPath, string Options) ParseBlsEntry(string text, string path)
    {
        string? linux = null;
        string? initrd = null;
        string? options = null;

        foreach (string raw in text.Split('\n'))
        {
            string line = raw.Trim();
            if (line.Length == 0 || line[0] == '#')
            {
                continue;
            }

            int split = line.IndexOfAny(SpaceTab);
            if (split <= 0)
            {
                continue;
            }

            string key = line[..split];
            string value = line[(split + 1)..].Trim();

            if (string.Equals(key, "linux", StringComparison.Ordinal))
            {
                if (linux is not null)
                {
                    throw Mismatch(path + " declares 'linux' more than once");
                }

                RequireNonEmpty(value, "'linux'", path);
                linux = value;
            }
            else if (string.Equals(key, "initrd", StringComparison.Ordinal))
            {
                if (initrd is not null)
                {
                    throw Mismatch(path + " declares 'initrd' more than once");
                }

                RequireNonEmpty(value, "'initrd'", path);
                initrd = value;
            }
            else if (string.Equals(key, "options", StringComparison.Ordinal))
            {
                if (options is not null)
                {
                    throw Mismatch(path + " declares 'options' more than once");
                }

                RequireNonEmpty(value, "'options'", path);
                options = value;
            }
        }

        if (linux is null || initrd is null || options is null)
        {
            throw Mismatch(
                path + " does not declare exactly one 'linux', one 'initrd' and one 'options' line");
        }

        return (linux, initrd, options);
    }

    private static void RequireNonEmpty(string value, string key, string path)
    {
        if (value.Length == 0)
        {
            throw Mismatch(path + " declares an empty " + key + " value");
        }
    }

    /// <summary>
    /// Binds the selected entry's options to the actual package root UUID and extracts the
    /// ostree boot checksum from the BLS path itself; the checksum only passes after exact
    /// equality with the package deployment boot checksum, and the returned value is the one
    /// read out of the entry, never the package value echoed.
    /// </summary>
    private static string BindOptions(EdlRawPackageContract package, string options, string path)
    {
        string? rootToken = null;
        string? ostreeToken = null;

        foreach (string token in options.Split(SpaceTab, StringSplitOptions.RemoveEmptyEntries))
        {
            if (token.StartsWith("root=", StringComparison.Ordinal))
            {
                if (rootToken is not null)
                {
                    throw Mismatch(path + " declares root= more than once");
                }

                rootToken = token;
            }
            else if (token.StartsWith("ostree=", StringComparison.Ordinal))
            {
                if (ostreeToken is not null)
                {
                    throw Mismatch(path + " declares ostree= more than once");
                }

                ostreeToken = token;
            }
        }

        if (rootToken is null)
        {
            throw Mismatch(path + " declares no root= option");
        }

        string expectedRoot = "root=UUID=" + package.BootRecipe.RootUuid.ToString();
        if (!string.Equals(rootToken, expectedRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw Mismatch(
                path + " binds '" + rootToken + "', not the package root UUID '"
                + package.BootRecipe.RootUuid + "'");
        }

        if (ostreeToken is null)
        {
            throw Mismatch(path + " declares no ostree= boot path");
        }

        // The package's own sole ostree= token declares the deployment's actual state root. The
        // installed generation may rotate between the boot.0/boot.1 generations the validated
        // package reader accepts; stateroot and checksum are exact. The closed token shape is
        // ostree=/ostree/boot.<0|1>/<state root>/<64-character checksum>/<numeric index>.
        string[] declaredOstreeTokens = package.BootRecipe.NormalBootArgs
            .Split(SpaceTab, StringSplitOptions.RemoveEmptyEntries)
            .Where(token => token.StartsWith("ostree=", StringComparison.Ordinal))
            .ToArray();
        if (declaredOstreeTokens.Length != 1)
        {
            throw Mismatch(
                "the package boot recipe declares " + declaredOstreeTokens.Length
                + " ostree= options; exactly one is required");
        }

        string[] declaredComponents = declaredOstreeTokens[0].Split('/');
        if (declaredComponents.Length != 6
            || declaredComponents[0] != "ostree="
            || declaredComponents[1] != "ostree"
            || (declaredComponents[2] != "boot.0" && declaredComponents[2] != "boot.1")
            || declaredComponents[3].Length == 0
            || declaredComponents[4].Length != 64
            || !string.Equals(declaredComponents[4], package.Deployment.BootChecksum, StringComparison.Ordinal)
            || declaredComponents[5].Length == 0
            || !declaredComponents[5].All(char.IsAsciiDigit))
        {
            throw Mismatch(
                "the package boot recipe ostree option '" + declaredOstreeTokens[0]
                + "' is not an ostree boot path of the form "
                + "ostree=/ostree/boot.<0|1>/<state root>/<64-character checksum>/<index>");
        }

        string declaredStateRoot = declaredComponents[3];

        string[] actualComponents = ostreeToken.Split('/');
        if (actualComponents.Length != 6
            || actualComponents[0] != "ostree="
            || actualComponents[1] != "ostree"
            || actualComponents[4].Length != 64)
        {
            throw Mismatch(
                path + " carries '" + ostreeToken + "', which is not an ostree boot path of the form "
                + "ostree=/ostree/boot.<0|1>/<state root>/<64-character checksum>/<index>");
        }

        if (actualComponents[2] != "boot.0" && actualComponents[2] != "boot.1")
        {
            throw Mismatch(
                path + " boots generation '" + actualComponents[2]
                + "', which is neither the boot.0 nor the boot.1 deployment generation");
        }

        if (!string.Equals(actualComponents[3], declaredStateRoot, StringComparison.Ordinal))
        {
            throw Mismatch(
                path + " boots ostree state root '" + actualComponents[3]
                + "', not the package state root '" + declaredStateRoot + "'");
        }

        string checksum = actualComponents[4];
        string index = actualComponents[5];
        if (index.Length == 0 || !index.All(char.IsAsciiDigit))
        {
            throw Mismatch(path + " carries an ostree boot path without a numeric deployment index");
        }

        if (!string.Equals(checksum, package.Deployment.BootChecksum, StringComparison.Ordinal))
        {
            throw Mismatch(
                path + " boots ostree checksum '" + checksum + "', not the package boot checksum '"
                + package.Deployment.BootChecksum + "'");
        }

        return checksum;
    }

    private static void VerifyArtifact(
        EdlRawPackageContract package,
        string role,
        ulong actualLength,
        string actualSha256,
        string path)
    {
        if (!package.Artifacts.TryGetValue(role, out EdlRawArtifact? claim) || claim is null)
        {
            throw Mismatch("the package declares no '" + role + "' artifact to verify against");
        }

        if (actualLength != (ulong)claim.Bytes)
        {
            throw Mismatch(
                "the installed " + role + " '" + path + "' is " + actualLength
                + " bytes, but the package declares " + claim.Bytes);
        }

        if (!string.Equals(actualSha256, claim.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw Mismatch(
                "the installed " + role + " '" + path + "' does not match the package '"
                + role + "' artifact SHA-256");
        }
    }

    private static bool GlobMatch(string pattern, string value) =>
        GlobMatchCore(pattern, 0, value, 0);

    private static bool GlobMatchCore(string pattern, int patternIndex, string value, int valueIndex)
    {
        while (patternIndex < pattern.Length)
        {
            char current = pattern[patternIndex];
            if (current == '*')
            {
                for (int skip = valueIndex; skip <= value.Length; skip++)
                {
                    if (GlobMatchCore(pattern, patternIndex + 1, value, skip))
                    {
                        return true;
                    }
                }

                return false;
            }

            if (valueIndex >= value.Length)
            {
                return false;
            }

            if (current != '?' && current != value[valueIndex])
            {
                return false;
            }

            patternIndex++;
            valueIndex++;
        }

        return valueIndex == value.Length;
    }

    private static void RequireDirectory(ushort mode, string path)
    {
        if ((mode & InodeModeTypeMask) != InodeModeDirectory)
        {
            throw Mismatch("'" + path + "' is not a directory");
        }
    }

    private static string StrictUtf8(byte[] bytes, string what)
    {
        try
        {
            return StrictUtf8Encoding.GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            throw Mismatch("'" + what + "' is not valid UTF-8 text");
        }
    }

    private static InvalidOperationException Mismatch(string detail) =>
        new(MismatchPrefix + detail);

    private static long CheckedMulL(long left, long right, string message)
    {
        try
        {
            return checked(left * right);
        }
        catch (OverflowException)
        {
            throw Mismatch(message);
        }
    }

    // ------------------------------------------------------------------ bounded ext4 reader

    /// <summary>
    /// One bounded, strictly read-only view of the captured boot ext4 filesystem. Only what the
    /// verification needs is implemented: group descriptors, inode lookup, extent-mapped
    /// directory/regular/symlink content and whole-file hashing. Block-mapped files,
    /// uninitialized extents, holes and out-of-range mappings always reject; nothing here
    /// writes, repairs or interprets the filesystem beyond path resolution and hashing.
    /// </summary>
    private sealed class Ext4Volume
    {
        private Ext4Volume(
            Stream stream,
            int blockSize,
            ulong blocksCount,
            long fsBytes,
            int inodeSize,
            uint inodesPerGroup,
            int descriptorSize,
            byte[] descriptors,
            ulong groupCount,
            Guid bootUuid)
        {
            Stream = stream;
            BlockSize = blockSize;
            BlocksCount = blocksCount;
            FsBytes = fsBytes;
            InodeSize = inodeSize;
            InodesPerGroup = inodesPerGroup;
            DescriptorSize = descriptorSize;
            Descriptors = descriptors;
            GroupCount = groupCount;
            BootUuid = bootUuid;
        }

        internal Stream Stream { get; }

        internal int BlockSize { get; }

        internal ulong BlocksCount { get; }

        internal long FsBytes { get; }

        internal int InodeSize { get; }

        internal uint InodesPerGroup { get; }

        internal int DescriptorSize { get; }

        internal byte[] Descriptors { get; }

        internal ulong GroupCount { get; }

        internal Guid BootUuid { get; }

        private Dictionary<uint, Dictionary<string, (uint Ino, byte Type)>> DirectoryCache { get; } = new();

        internal static Ext4Volume Open(Stream stream, Guid expectedBootUuid)
        {
            if (stream.Length < Ext4SuperblockOffset + Ext4SuperblockBytes)
            {
                throw Mismatch("the captured boot partition is too small for an ext4 superblock");
            }

            byte[] super = ReadExactAt(stream, Ext4SuperblockOffset, Ext4SuperblockBytes);

            if (BinaryPrimitives.ReadUInt16LittleEndian(super.AsSpan(Ext4MagicOffset)) != Ext4Magic)
            {
                throw Mismatch("the captured boot partition does not carry the ext4 magic 0xEF53 at 1024+0x38");
            }

            var bootUuid = new Guid(super.AsSpan(Ext4UuidOffset, 16), bigEndian: true);
            if (bootUuid != expectedBootUuid)
            {
                throw Mismatch(
                    "the actual boot filesystem UUID '" + bootUuid + "' does not match the package boot UUID '"
                    + expectedBootUuid + "'");
            }

            uint logBlockSize = BinaryPrimitives.ReadUInt32LittleEndian(super.AsSpan(Ext4LogBlockSizeOffset));
            if (logBlockSize > Ext4MaxLogBlockSize)
            {
                throw Mismatch("the boot ext4 declares an impossible block size");
            }

            int blockSize = 1024 << (int)logBlockSize;

            uint incompat = BinaryPrimitives.ReadUInt32LittleEndian(super.AsSpan(Ext4FeatureIncompatOffset));
            if ((incompat & ~Ext4IncompatAccepted) != 0)
            {
                throw Mismatch(
                    "the boot ext4 declares unsupported incompatible features 0x"
                    + (incompat & ~Ext4IncompatAccepted).ToString("X", System.Globalization.CultureInfo.InvariantCulture));
            }

            if ((incompat & Ext4IncompatExtents) == 0)
            {
                throw Mismatch("the boot ext4 does not declare the extents feature; block-mapped layouts are unsupported");
            }

            bool is64Bit = (incompat & Ext4Incompat64Bit) != 0;

            ulong blocksCount = BinaryPrimitives.ReadUInt32LittleEndian(super.AsSpan(Ext4BlocksCountLowOffset));
            if (is64Bit)
            {
                blocksCount |= (ulong)BinaryPrimitives.ReadUInt32LittleEndian(super.AsSpan(Ext4BlocksCountHighOffset)) << 32;
            }

            if (blocksCount == 0)
            {
                throw Mismatch("the boot ext4 declares an empty filesystem");
            }

            ulong fsBytes = CheckedMulU(blocksCount, (ulong)blockSize, "the boot ext4 size overflows");
            if (fsBytes > (ulong)stream.Length)
            {
                throw Mismatch(
                    "the boot ext4 declares " + fsBytes + " bytes, more than the captured boot partition holds");
            }

            uint firstDataBlock = BinaryPrimitives.ReadUInt32LittleEndian(super.AsSpan(Ext4FirstDataBlockOffset));
            if ((blockSize == 1024 && firstDataBlock != 1) || (blockSize > 1024 && firstDataBlock != 0))
            {
                throw Mismatch("the boot ext4 declares an unexpected first data block");
            }

            if (blocksCount <= firstDataBlock)
            {
                throw Mismatch("the boot ext4 declares fewer blocks than its first data block");
            }

            uint blocksPerGroup = BinaryPrimitives.ReadUInt32LittleEndian(super.AsSpan(Ext4BlocksPerGroupOffset));
            uint inodesPerGroup = BinaryPrimitives.ReadUInt32LittleEndian(super.AsSpan(Ext4InodesPerGroupOffset));
            if (blocksPerGroup == 0 || inodesPerGroup == 0)
            {
                throw Mismatch("the boot ext4 declares non-positive group geometry");
            }

            int inodeSize = BinaryPrimitives.ReadUInt16LittleEndian(super.AsSpan(Ext4InodeSizeOffset));
            if (inodeSize < 128 || inodeSize > blockSize || (inodeSize & (inodeSize - 1)) != 0)
            {
                throw Mismatch("the boot ext4 declares an unusable inode size");
            }

            int descriptorSize = Ext4DescriptorBytes32;
            if (is64Bit)
            {
                descriptorSize = BinaryPrimitives.ReadUInt16LittleEndian(super.AsSpan(Ext4DescSizeOffset));
                if (descriptorSize < 64 || descriptorSize > 1024 || (descriptorSize & 7) != 0)
                {
                    throw Mismatch("the 64bit boot ext4 declares an unusable group descriptor size");
                }
            }

            ulong groupCount = DivCeil(blocksCount - firstDataBlock, blocksPerGroup);
            if (groupCount > 0x100000ul)
            {
                throw Mismatch("the boot ext4 declares an unusable group count");
            }

            ulong gdtStart = CheckedMulU((ulong)firstDataBlock + 1u, (ulong)blockSize, "the group descriptor table offset overflows");
            ulong gdtBytes = CheckedMulU(groupCount, (ulong)descriptorSize, "the group descriptor table size overflows");
            if (gdtBytes > (ulong)MaxGroupTableBytes)
            {
                throw Mismatch("the boot ext4 group descriptor table exceeds the bounded reader size");
            }

            if (gdtStart > fsBytes || gdtBytes > fsBytes - gdtStart)
            {
                throw Mismatch("the boot ext4 group descriptor table lies outside the filesystem");
            }

            byte[] descriptors = ReadExactAt(stream, (long)gdtStart, (int)gdtBytes);

            return new Ext4Volume(
                stream, blockSize, blocksCount, (long)fsBytes, inodeSize, inodesPerGroup,
                descriptorSize, descriptors, groupCount, bootUuid);
        }

        internal ushort ModeOfInode(uint ino, string what) => ModeOf(ReadInode(ino, what));

        internal byte[] ReadInode(uint ino, string what)
        {
            if (ino == 0)
            {
                throw Mismatch("'" + what + "' uses inode 0");
            }

            ulong zeroBased = ino - 1u;
            ulong group = zeroBased / InodesPerGroup;
            ulong index = zeroBased % InodesPerGroup;
            if (group >= GroupCount)
            {
                throw Mismatch("'" + what + "' uses inode " + ino + " outside the declared group count");
            }

            int descOffset = checked((int)(group * (ulong)DescriptorSize));
            int neededBytes = DescriptorSize >= 64 ? Ext4DescriptorInodeTableHighOffset + 4 : Ext4DescriptorInodeTableLowOffset + 4;
            if (descOffset + neededBytes > Descriptors.Length)
            {
                throw Mismatch("the boot ext4 group descriptor for inode " + ino + " lies outside the descriptor table");
            }

            ulong tableBlock = BinaryPrimitives.ReadUInt32LittleEndian(
                Descriptors.AsSpan(descOffset + Ext4DescriptorInodeTableLowOffset));
            if (DescriptorSize >= 64)
            {
                tableBlock |= (ulong)BinaryPrimitives.ReadUInt32LittleEndian(
                    Descriptors.AsSpan(descOffset + Ext4DescriptorInodeTableHighOffset)) << 32;
            }

            if (tableBlock >= BlocksCount)
            {
                throw Mismatch("the boot ext4 inode table of group " + group + " maps outside the filesystem");
            }

            ulong offset = CheckedAddU(
                CheckedMulU(tableBlock, (ulong)BlockSize, "the inode table byte offset overflows"),
                CheckedMulU(index, (ulong)InodeSize, "the inode byte offset overflows"),
                "the inode byte offset overflows");

            if (offset + (ulong)InodeBytesRead > (ulong)FsBytes)
            {
                throw Mismatch("the '" + what + "' inode lies outside the filesystem");
            }

            return ReadExactAt(Stream, (long)offset, InodeBytesRead);
        }

        internal IReadOnlyDictionary<string, (uint Ino, byte Type)> ReadDirectory(
            uint ino, string what, CancellationToken ct)
        {
            if (DirectoryCache.TryGetValue(ino, out Dictionary<string, (uint Ino, byte Type)>? cached))
            {
                return cached;
            }

            byte[] inode = ReadInode(ino, what);
            if ((ModeOf(inode) & InodeModeTypeMask) != InodeModeDirectory)
            {
                throw Mismatch("'" + what + "' (inode " + ino + ") is not a directory");
            }

            RequireExtentMapping(inode, what);
            ulong size = SizeOf(inode, includeHigh: false);
            if (size == 0 || size > (ulong)MaxDirectoryBytes)
            {
                throw Mismatch("'" + what + "' directory content is empty or beyond the bounded reader size");
            }

            byte[] content = CopyFileBytes(inode, size, what, ct);
            Dictionary<string, (uint Ino, byte Type)> entries = ParseDirectory(content, what);
            DirectoryCache.Add(ino, entries);
            return entries;
        }

        internal (uint Ino, ushort Mode) ResolvePath(string path, string what, CancellationToken ct)
        {
            List<string> comps = SplitPath(path, what);
            if (comps.Count == 0)
            {
                throw Mismatch("'" + what + "' resolves to the filesystem root, which is not a usable target");
            }

            if (comps.Count > MaxPathComponents)
            {
                throw Mismatch("'" + what + "' carries more than " + MaxPathComponents + " path components");
            }

            return ResolveComponent(RootInodeNumber, comps, 0, MaxSymlinkFollows, ct);
        }

        internal (ulong Length, string Sha256) HashRegularFile(uint ino, string what, CancellationToken ct)
        {
            byte[] inode = ReadInode(ino, what);
            if ((ModeOf(inode) & InodeModeTypeMask) != InodeModeRegular)
            {
                throw Mismatch("'" + what + "' (inode " + ino + ") is not a regular file");
            }

            RequireExtentMapping(inode, what);
            ulong size = SizeOf(inode, includeHigh: true);
            if (size > (ulong)MaxVerifiedFileBytes)
            {
                throw Mismatch("'" + what + "' is " + size + " bytes, beyond the verified file bound");
            }

            using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            byte[] buffer = new byte[CopyBufferBytes];
            ulong total = 0;

            foreach ((long offset, int count) in FileChunks(inode, size, what))
            {
                ct.ThrowIfCancellationRequested();
                ReadExactAt(Stream, offset, buffer, 0, count);
                hash.AppendData(buffer, 0, count);
                total += (ulong)count;
            }

            if (total != size)
            {
                throw Mismatch("'" + what + "' hashed " + total + " bytes instead of " + size);
            }

            return (size, Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant());
        }

        internal byte[] ReadFileBytes(uint ino, long cap, string what, CancellationToken ct)
        {
            byte[] inode = ReadInode(ino, what);
            if ((ModeOf(inode) & InodeModeTypeMask) != InodeModeRegular)
            {
                throw Mismatch("'" + what + "' is not a regular file");
            }

            RequireExtentMapping(inode, what);
            ulong size = SizeOf(inode, includeHigh: false);
            if (size == 0 || size > (ulong)cap)
            {
                throw Mismatch("'" + what + "' is empty or beyond the " + cap + "-byte bound");
            }

            return CopyFileBytes(inode, size, what, ct);
        }

        internal string ReadSymlinkTarget(uint ino, string what, CancellationToken ct)
        {
            byte[] inode = ReadInode(ino, what);
            if ((ModeOf(inode) & InodeModeTypeMask) != InodeModeSymlink)
            {
                throw Mismatch("'" + what + "' (inode " + ino + ") is not a symlink");
            }

            ulong size = SizeOf(inode, includeHigh: false);
            if (size == 0 || size > (ulong)MaxSymlinkTargetBytes)
            {
                throw Mismatch("'" + what + "' target length is unusable");
            }

            bool extents = (BinaryPrimitives.ReadUInt32LittleEndian(inode.AsSpan(InodeFlagsOffset)) & InodeFlagExtents) != 0;
            if (extents)
            {
                ushort inlineMagic = BinaryPrimitives.ReadUInt16LittleEndian(inode.AsSpan(InodeBlockAreaOffset));
                if (inlineMagic != ExtentMagic)
                {
                    // Fast symlink: the target sits inline in the i_block area.
                    if (size > (ulong)FastSymlinkMaxBytes)
                    {
                        throw Mismatch("'" + what + "' inline target is longer than the fast symlink bound");
                    }

                    byte[] inlineBytes = new byte[size];
                    Array.Copy(inode, InodeBlockAreaOffset, inlineBytes, 0, (long)size);
                    return StrictUtf8(inlineBytes, what);
                }

                // Slow symlink: read the target through the extent mapping like a small file.
                byte[] target = CopyFileBytes(inode, size, what, ct);
                return StrictUtf8(target, what);
            }

            if (size <= (ulong)FastSymlinkMaxBytes
                && BinaryPrimitives.ReadUInt32LittleEndian(inode.AsSpan(InodeBlocksLowOffset)) == 0)
            {
                byte[] inlineBytes = new byte[size];
                Array.Copy(inode, InodeBlockAreaOffset, inlineBytes, 0, (long)size);
                return StrictUtf8(inlineBytes, what);
            }

            throw Mismatch("'" + what + "' is a block-mapped slow symlink; only extent-mapped symlinks are supported");
        }

        private (uint Ino, ushort Mode) ResolveComponent(
            uint dirIno,
            List<string> comps,
            int index,
            int followsLeft,
            CancellationToken ct)
        {
            if (followsLeft < 0)
            {
                throw Mismatch("the path carries a symlink chain deeper than " + MaxSymlinkFollows + " follows");
            }

            IReadOnlyDictionary<string, (uint Ino, byte Type)> entries =
                ReadDirectory(dirIno, "the directory at inode " + dirIno, ct);

            if (!entries.TryGetValue(comps[index], out (uint Ino, byte Type) entry))
            {
                throw Mismatch("the path component '" + comps[index] + "' does not exist");
            }

            ushort childMode = ModeOfInode(entry.Ino, comps[index]);

            if ((childMode & InodeModeTypeMask) == InodeModeSymlink)
            {
                if (followsLeft == 0)
                {
                    throw Mismatch("the path carries more than " + MaxSymlinkFollows + " symlink follows");
                }

                string target = ReadSymlinkTarget(entry.Ino, "the symlink '" + comps[index] + "'", ct);
                List<string> targetComps = SplitPath(target, "the symlink target of '" + comps[index] + "'");
                uint baseDir = target.StartsWith("/", StringComparison.Ordinal) ? RootInodeNumber : dirIno;

                (uint linkedIno, ushort linkedMode) =
                    ResolveComponent(baseDir, targetComps, 0, followsLeft - 1, ct);

                if (index + 1 == comps.Count)
                {
                    return (linkedIno, linkedMode);
                }

                if ((linkedMode & InodeModeTypeMask) != InodeModeDirectory)
                {
                    throw Mismatch("the symlink target of '" + comps[index] + "' is not a directory");
                }

                return ResolveComponent(linkedIno, comps, index + 1, followsLeft, ct);
            }

            if (index + 1 == comps.Count)
            {
                return (entry.Ino, childMode);
            }

            if ((childMode & InodeModeTypeMask) != InodeModeDirectory)
            {
                throw Mismatch("the path component '" + comps[index] + "' is not a directory");
            }

            return ResolveComponent(entry.Ino, comps, index + 1, followsLeft, ct);
        }

        private byte[] CopyFileBytes(byte[] inode, ulong size, string what, CancellationToken ct)
        {
            byte[] content = new byte[size];
            int written = 0;

            foreach ((long offset, int count) in FileChunks(inode, size, what))
            {
                ct.ThrowIfCancellationRequested();
                ReadExactAt(Stream, offset, content, written, count);
                written += count;
            }

            return content;
        }

        /// <summary>
        /// Validates the extent mapping of one file against its declared size - exact
        /// contiguous coverage of every logical block, initialized extents only, in-range
        /// physical blocks only - and yields the bounded byte chunks to read from the stream.
        /// All validation happens before the first chunk is produced.
        /// </summary>
        private IEnumerable<(long Offset, int Count)> FileChunks(byte[] inode, ulong size, string what)
        {
            List<(ulong Logical, ulong Physical, ulong Blocks)> extents = CollectExtents(inode, what);
            ulong logicalBlocks = DivCeil(size, (ulong)BlockSize);
            ulong expected = 0;

            foreach ((ulong logical, ulong physical, ulong blocks) in extents)
            {
                if (logical != expected)
                {
                    throw Mismatch(
                        "'" + what + "' extents are not contiguous from block zero (hole at block " + expected + ")");
                }

                if (physical >= BlocksCount || blocks > BlocksCount - physical)
                {
                    throw Mismatch("'" + what + "' carries an extent mapping outside the filesystem");
                }

                expected = CheckedAddU(logical, blocks, "'" + what + "' extent end overflows");
                if (expected > logicalBlocks)
                {
                    throw Mismatch("'" + what + "' carries an extent beyond its own end");
                }
            }

            if (expected != logicalBlocks)
            {
                throw Mismatch("'" + what + "' does not cover all of its " + logicalBlocks + " logical blocks");
            }

            foreach ((ulong logical, ulong physical, ulong blocks) in extents)
            {
                ulong extentBytes = CheckedMulU(blocks, (ulong)BlockSize, "'" + what + "' extent byte length overflows");
                ulong take = Math.Min(extentBytes, size - CheckedMulU(logical, (ulong)BlockSize, "'" + what + "' extent offset overflows"));
                long source = (long)(physical * (ulong)BlockSize);
                ulong done = 0;

                while (done < take)
                {
                    int chunk = (int)Math.Min(take - done, (ulong)CopyBufferBytes);
                    yield return (source + (long)done, chunk);
                    done += (ulong)chunk;
                }
            }
        }

        private List<(ulong Logical, ulong Physical, ulong Blocks)> CollectExtents(byte[] inode, string what)
        {
            var extents = new List<(ulong Logical, ulong Physical, ulong Blocks)>();
            byte[] inline = new byte[InodeBlockAreaBytes];
            Array.Copy(inode, InodeBlockAreaOffset, inline, 0, InodeBlockAreaBytes);
            CollectExtentsNode(inline, what, extents, MaxExtentDepth);
            return extents;
        }

        private void CollectExtentsNode(
            byte[] node,
            string what,
            List<(ulong Logical, ulong Physical, ulong Blocks)> extents,
            int depthLeft)
        {
            if (node.Length < ExtentHeaderBytes)
            {
                throw Mismatch("'" + what + "' carries an extent node shorter than the extent header");
            }

            ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(node.AsSpan(0));
            ushort entries = BinaryPrimitives.ReadUInt16LittleEndian(node.AsSpan(2));
            ushort depth = BinaryPrimitives.ReadUInt16LittleEndian(node.AsSpan(ExtentHeaderDepthOffset));

            if (magic != ExtentMagic)
            {
                throw Mismatch("'" + what + "' carries an extent node without the 0xF30A magic");
            }

            if (depth > MaxExtentDepth || depthLeft <= 0)
            {
                throw Mismatch("'" + what + "' carries an extent tree deeper than the bounded reader depth");
            }

            int maxEntries = (node.Length - ExtentHeaderBytes) / ExtentEntryBytes;
            if (entries > maxEntries)
            {
                throw Mismatch("'" + what + "' carries an extent node with more entries than its block holds");
            }

            if (depth == 0)
            {
                for (int i = 0; i < entries; i++)
                {
                    int o = ExtentHeaderBytes + (i * ExtentEntryBytes);
                    uint eeBlock = BinaryPrimitives.ReadUInt32LittleEndian(node.AsSpan(o));
                    ushort eeLen = BinaryPrimitives.ReadUInt16LittleEndian(node.AsSpan(o + 4));
                    ushort eeStartHigh = BinaryPrimitives.ReadUInt16LittleEndian(node.AsSpan(o + 6));
                    uint eeStartLow = BinaryPrimitives.ReadUInt32LittleEndian(node.AsSpan(o + 8));

                    if (eeLen >= ExtentUnwrittenMarker)
                    {
                        throw Mismatch(
                            "'" + what + "' carries an uninitialized extent; uninitialized storage is never "
                            + "presented as verified payload");
                    }

                    if (eeLen == 0)
                    {
                        throw Mismatch("'" + what + "' carries a zero-length extent");
                    }

                    ulong physical = ((ulong)eeStartHigh << 32) | eeStartLow;
                    extents.Add((eeBlock, physical, eeLen));
                }

                return;
            }

            for (int i = 0; i < entries; i++)
            {
                int o = ExtentHeaderBytes + (i * ExtentEntryBytes);
                ulong child = BinaryPrimitives.ReadUInt32LittleEndian(node.AsSpan(o + 4))
                    | ((ulong)BinaryPrimitives.ReadUInt16LittleEndian(node.AsSpan(o + 8)) << 32);

                if (child >= BlocksCount)
                {
                    throw Mismatch("'" + what + "' carries an extent index node outside the filesystem");
                }

                byte[] childNode = ReadExactAt(Stream, (long)(child * (ulong)BlockSize), BlockSize);
                CollectExtentsNode(childNode, what, extents, depthLeft - 1);
            }
        }

        private void RequireExtentMapping(byte[] inode, string what)
        {
            uint flags = BinaryPrimitives.ReadUInt32LittleEndian(inode.AsSpan(InodeFlagsOffset));
            if ((flags & InodeFlagExtents) == 0)
            {
                throw Mismatch("'" + what + "' is block-mapped; only extent-mapped files are supported");
            }
        }

        private static Dictionary<string, (uint Ino, byte Type)> ParseDirectory(byte[] content, string what)
        {
            var entries = new Dictionary<string, (uint Ino, byte Type)>(StringComparer.Ordinal);
            int offset = 0;

            while (offset < content.Length)
            {
                if (content.Length - offset < 8)
                {
                    throw Mismatch("'" + what + "' ends inside a directory entry header");
                }

                uint ino = BinaryPrimitives.ReadUInt32LittleEndian(content.AsSpan(offset));
                ushort recLen = BinaryPrimitives.ReadUInt16LittleEndian(content.AsSpan(offset + 4));
                byte nameLen = content[offset + 6];
                byte fileType = content[offset + 7];

                if (recLen < 8 || (recLen & 3) != 0 || recLen > content.Length - offset)
                {
                    throw Mismatch("'" + what + "' carries a malformed directory record length");
                }

                if (ino == 0)
                {
                    // A deleted slot carries no name; it is skipped, never accepted.
                    offset += recLen;
                    continue;
                }

                if (nameLen == 0 || nameLen > recLen - 8)
                {
                    throw Mismatch("'" + what + "' carries a malformed directory name length");
                }

                byte[] nameBytes = content.AsSpan(offset + 8, nameLen).ToArray();
                foreach (byte b in nameBytes)
                {
                    if (b < 0x20 || b > 0x7E || b == '/')
                    {
                        throw Mismatch("'" + what + "' carries a directory name with an unusable byte");
                    }
                }

                string name = Encoding.ASCII.GetString(nameBytes);
                if (!entries.TryAdd(name, (ino, fileType)))
                {
                    throw Mismatch("'" + what + "' declares the name '" + name + "' more than once");
                }

                offset += recLen;
            }

            return entries;
        }

        private static List<string> SplitPath(string path, string what)
        {
            if (string.IsNullOrEmpty(path) || path[0] != '/')
            {
                throw Mismatch("'" + what + "' is not an absolute path");
            }

            var comps = new List<string>();
            foreach (string part in path.Split('/'))
            {
                if (part.Length == 0 || part == ".")
                {
                    continue;
                }

                if (part == "..")
                {
                    throw Mismatch("'" + what + "' contains a '..' component; path escapes are never accepted");
                }

                comps.Add(part);
            }

            return comps;
        }

        private static ulong SizeOf(byte[] inode, bool includeHigh)
        {
            ulong low = BinaryPrimitives.ReadUInt32LittleEndian(inode.AsSpan(InodeSizeLowOffset));
            if (!includeHigh)
            {
                return low;
            }

            return low | ((ulong)BinaryPrimitives.ReadUInt32LittleEndian(inode.AsSpan(InodeSizeHighOffset)) << 32);
        }

        private static ushort ModeOf(byte[] inode) =>
            BinaryPrimitives.ReadUInt16LittleEndian(inode.AsSpan(InodeModeOffset));

        private static ulong DivCeil(ulong value, ulong unit) => (value + unit - 1) / unit;

        private static ulong CheckedMulU(ulong left, ulong right, string message)
        {
            try
            {
                return checked(left * right);
            }
            catch (OverflowException)
            {
                throw Mismatch(message);
            }
        }

        private static ulong CheckedAddU(ulong left, ulong right, string message)
        {
            try
            {
                return checked(left + right);
            }
            catch (OverflowException)
            {
                throw Mismatch(message);
            }
        }

        private static byte[] ReadExactAt(Stream stream, long offset, int count)
        {
            byte[] buffer = new byte[count];
            ReadExactAt(stream, offset, buffer, 0, count);
            return buffer;
        }

        private static void ReadExactAt(Stream stream, long offset, byte[] target, int targetOffset, int count)
        {
            if (offset < 0 || count < 0 || targetOffset < 0
                || offset > stream.Length || count > stream.Length - offset
                || targetOffset > target.Length || count > target.Length - targetOffset)
            {
                throw Mismatch(
                    "the bounded read range " + offset + "+" + count + " does not fit the captured stream of "
                    + stream.Length + " bytes");
            }

            stream.Position = offset;
            int read = 0;
            while (read < count)
            {
                int chunk = stream.Read(target, targetOffset + read, count - read);
                if (chunk <= 0)
                {
                    throw Mismatch("the captured stream ended before its declared length");
                }

                read += chunk;
            }
        }
    }
}
