using System;
using System.IO;
using System.Linq;
using System.Text;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Discovery-level gate for the one test in this file that needs the REAL raw EDL captures. Without the
/// mounted evidence directory the test is meaningless, so xunit must report it as skipped instead of passing
/// it; the decision is taken at discovery time from the environment.
/// </summary>
public sealed class UninstallEdlDeviceEvidenceFactAttribute : FactAttribute
{
    public UninstallEdlDeviceEvidenceFactAttribute()
    {
        if (string.IsNullOrWhiteSpace(
                Environment.GetEnvironmentVariable(UninstallEdlEvidenceTests.EvidenceRootVariable)))
        {
            Skip = UninstallEdlEvidenceTests.EvidenceRootVariable
                + " is not set, so the raw EDL captures ("
                + UninstallEdlEvidenceTests.BeforeMainFileName + ", "
                + UninstallEdlEvidenceTests.BeforeBackupFileName + ", "
                + UninstallEdlEvidenceTests.AfterMainFileName + ", "
                + UninstallEdlEvidenceTests.AfterBackupFileName
                + ") are not mounted for this run.";
        }
    }
}

/// <summary>
/// Contract for <see cref="UninstallEvidenceValidator.ValidateEdl"/>, the EDL-shaped entry point where both
/// tables are raw GPT bytes instead of one raw capture plus an sfdisk document. Every synthetic table below
/// is decoded by the real <see cref="OriginalGptImporter.Parse"/> from the byte-level fixture builders of
/// <see cref="OriginalGptImporterTests"/>; no <see cref="GptTable"/> is constructed directly and no sfdisk
/// document is forged for an accepted case. No file, process or device is touched by the synthetic tests.
/// </summary>
public sealed class UninstallEdlEvidenceTests
{
    /// <summary>Directory holding the four mounted raw EDL capture files.</summary>
    public const string EvidenceRootVariable = "UNINSTALL_DEVICE_EVIDENCE_ROOT";

    public const string BeforeMainFileName = "before-main.bin";
    public const string BeforeBackupFileName = "before-backup.bin";
    public const string AfterMainFileName = "after-main.bin";
    public const string AfterBackupFileName = "after-backup.bin";

    private const string EdlDeviceId = "edl:ufs:lun:0";

    // The real tablet is a 4Kn disk: 507,376,566,272 bytes in 4096-byte sectors.
    private const int SectorSize = 4096;
    private const long DiskBytes = 507_376_566_272L;

    // ---------------------------------------------------------------- accepted raw evidence

    [Fact]
    public void ValidateEdl_RawFactoryAndRawInstalledTables_ReturnEdlMarkedEvidence()
    {
        var identity = Identity();
        var original = OriginalTable();
        var currentRaw = CurrentRawTable();

        var inputs = UninstallEvidenceValidator.ValidateEdl(identity, original, currentRaw, 0);

        Assert.Equal(identity, inputs.Identity);

        // The EDL path labels its own snapshot: it neither borrows a live node nor hands on a null one.
        Assert.Equal(EdlDeviceId, inputs.CurrentTable.DeviceId);
        Assert.Equal(EdlDeviceId, inputs.Record.DeviceId);

        // Both raw captures keep their own provenance: factory bytes and after-install bytes.
        Assert.Equal(original.SourceFingerprint, inputs.OriginalGptFingerprint);
        Assert.Equal(currentRaw.SourceFingerprint, inputs.CurrentTable.SourceFingerprint);
        Assert.Equal(currentRaw.SourceFingerprint, inputs.CurrentTableFingerprint);

        // The snapshot copies the raw table unchanged apart from its device marker.
        Assert.Equal(currentRaw.SectorSize, inputs.CurrentTable.SectorSize);
        Assert.Equal(currentRaw.DiskBytes, inputs.CurrentTable.DiskBytes);
        Assert.Equal(currentRaw.DiskGuid, inputs.CurrentTable.DiskGuid);
        Assert.Equal(currentRaw.FirstUsableSector, inputs.CurrentTable.FirstUsableSector);
        Assert.Equal(currentRaw.LastUsableSector, inputs.CurrentTable.LastUsableSector);
        Assert.Equal(currentRaw.Partitions.Count, inputs.CurrentTable.Partitions.Count);
        Assert.Equal(
            GptFixture.CurrentUserdataCount,
            GptFixture.Partition(inputs.CurrentTable, 2).SectorCount);
        Assert.Equal(GptFixture.BootStart, GptFixture.Partition(inputs.CurrentTable, 3).StartSector);

        // The plan restores the factory userdata extent and drops exactly the two owned Linux slots.
        Assert.Equal(123_871_227L, inputs.Record.OriginalUserdataEndSector);
        Assert.Equal(5_972_392L, inputs.Plan.UserdataStartSector);
        Assert.Equal(123_871_227L, inputs.Plan.UserdataEndSectorExclusive);
        Assert.Equal(482_913_628_160L, inputs.Plan.RestoredAndroidBytes); // 117,898,835 sectors of 4096
        Assert.Equal(2, inputs.Plan.RemovedPartitionNumbers.Count);
        Assert.Contains(3L, inputs.Plan.RemovedPartitionNumbers);
        Assert.Contains(4L, inputs.Plan.RemovedPartitionNumbers);

        Assert.Equal(original.SourceFingerprint, inputs.OriginalTable.SourceFingerprint);
        Assert.False(string.IsNullOrWhiteSpace(inputs.EvidenceFingerprint));
    }

    [Fact]
    public void ValidateEdl_LeavesInputsUntouchedAndRepeatsDeterministically()
    {
        var identity = Identity();
        var original = OriginalTable();
        var currentRaw = CurrentRawTable();

        var originalSnapshot = Describe(original);
        var currentSnapshot = Describe(currentRaw);

        var first = UninstallEvidenceValidator.ValidateEdl(identity, original, currentRaw, 0);
        var second = UninstallEvidenceValidator.ValidateEdl(identity, original, currentRaw, 0);

        // Neither input table may be relabelled or rewritten in place: both stay raw captures.
        Assert.Null(original.DeviceId);
        Assert.Null(currentRaw.DeviceId);
        Assert.Equal(originalSnapshot, Describe(original));
        Assert.Equal(currentSnapshot, Describe(currentRaw));

        // Repeating the same validation over the same bytes must produce the same evidence token.
        Assert.Equal(first.CurrentTableFingerprint, second.CurrentTableFingerprint);
        Assert.Equal(first.OriginalGptFingerprint, second.OriginalGptFingerprint);
        Assert.Equal(first.EvidenceFingerprint, second.EvidenceFingerprint);
        Assert.Equal(first.Plan.UserdataStartSector, second.Plan.UserdataStartSector);
        Assert.Equal(first.Plan.UserdataEndSectorExclusive, second.Plan.UserdataEndSectorExclusive);
        Assert.Equal(first.Plan.RestoredAndroidBytes, second.Plan.RestoredAndroidBytes);
    }

    [Fact]
    public void ValidateEdl_KeepsChangedCurrentAttributesAndBindsThemIntoEvidence()
    {
        var identity = Identity();
        var original = OriginalTable();

        // Same geometry, two legal OTA states. Attributes are the one field allowed to move after capture.
        const ulong firstAttributes = 1UL << 50;
        const ulong secondAttributes = 1UL << 60;

        var firstRaw = CurrentRawTable(proinfoAttributes: firstAttributes);
        var secondRaw = CurrentRawTable(proinfoAttributes: secondAttributes);

        var first = UninstallEvidenceValidator.ValidateEdl(identity, original, firstRaw, 0);
        var second = UninstallEvidenceValidator.ValidateEdl(identity, original, secondRaw, 0);

        // The validated snapshot carries the CURRENT words, not the original ones.
        Assert.Equal(firstAttributes, GptFixture.Partition(first.CurrentTable, 1).Attributes);
        Assert.Equal(secondAttributes, GptFixture.Partition(second.CurrentTable, 1).Attributes);
        Assert.Equal(0UL, GptFixture.Partition(first.OriginalTable, 1).Attributes);

        // Attributes are part of the evidence: two otherwise identical captures must not collapse to one token.
        Assert.NotEqual(first.EvidenceFingerprint, second.EvidenceFingerprint);

        // The restore plan itself is unaffected by attributes.
        Assert.Equal(first.Plan.RemovedPartitionNumbers, second.Plan.RemovedPartitionNumbers);
        Assert.Equal(first.Plan.RestoredAndroidBytes, second.Plan.RestoredAndroidBytes);
    }

    // ---------------------------------------------------------------- rejected raw evidence

    [Fact]
    public void ValidateEdl_RejectsTablesThatDidNotComeFromRawBytes()
    {
        var identity = Identity();
        var original = OriginalTable();
        var currentRaw = CurrentRawTable();

        // A table read off the wire names a POSIX node and cannot stand in for captured raw bytes, in either
        // position. The factory-shaped document below agrees with the original's geometry, so only the
        // provenance check can reject it.
        var sfdiskOriginal = UninstallEvidenceValidator.ReadCurrentSfdisk(
            Sfdisk.Json(userdataSize: GptFixture.UserdataCount, includeLinuxPartitions: false),
            GptFixture.DiskBytes4096);
        var sfdiskCurrent = UninstallEvidenceValidator.ReadCurrentSfdisk(
            Sfdisk.Json(), GptFixture.DiskBytes4096);

        Assert.Throws<ArgumentException>(
            () => UninstallEvidenceValidator.ValidateEdl(identity, sfdiskOriginal, currentRaw, 0));
        Assert.Throws<ArgumentException>(
            () => UninstallEvidenceValidator.ValidateEdl(identity, original, sfdiskCurrent, 0));

        // The original entry point is not weakened either: it still requires a node-bearing current table.
        Assert.Throws<ArgumentException>(
            () => UninstallEvidenceValidator.Validate(
                identity, original, currentRaw, currentRaw.SourceFingerprint));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(1)]
    [InlineData(int.MaxValue)]
    public void ValidateEdl_RejectsLunsOtherThanZero(int lun)
    {
        // Only LUN 0 belongs to this profile; an out-of-range value must never be interpreted as another unit.
        Assert.ThrowsAny<ArgumentException>(
            () => UninstallEvidenceValidator.ValidateEdl(Identity(), OriginalTable(), CurrentRawTable(), lun));
    }

    [Fact]
    public void ValidateEdl_RejectsMovedVendorPartitionInAValidRawTable()
    {
        // Moving proinfo keeps every checksum intact, so the regenerated pair parses successfully first.
        // Only the semantic cross-check inside ValidateEdl can reject it; a failure must not come from the
        // importer's CRC gate.
        var moved = CurrentRawTable(proinfoStart: 1_000L);
        Assert.Equal(1_000L, GptFixture.Partition(moved, 1).StartSector);

        Assert.Throws<InvalidDataException>(
            () => UninstallEvidenceValidator.ValidateEdl(Identity(), OriginalTable(), moved, 0));
    }

    [Fact]
    public void ValidateEdl_RejectsNullArguments()
    {
        var identity = Identity();
        var original = OriginalTable();
        var currentRaw = CurrentRawTable();

        Assert.Throws<ArgumentNullException>(
            () => UninstallEvidenceValidator.ValidateEdl(null!, original, currentRaw, 0));
        Assert.Throws<ArgumentNullException>(
            () => UninstallEvidenceValidator.ValidateEdl(identity, null!, currentRaw, 0));
        Assert.Throws<ArgumentNullException>(
            () => UninstallEvidenceValidator.ValidateEdl(identity, original, null!, 0));
    }

    // ------------------------------------------------------------- real captured evidence

    /// <summary>
    /// Runs the EDL path over the four mounted raw captures of the real tablet: the factory pair and the
    /// after-install pair. Exactly those four names are read; a missing file fails the test rather than
    /// falling back to another name or searching the tree.
    /// </summary>
    [UninstallEdlDeviceEvidenceFact]
    public void RealEdlCapture_BeforeAndAfterRawPairs_ValidateIntoTheLegacyRestorePlan()
    {
        // The attribute already gated discovery; execution must still fail loudly if the variable vanished.
        var evidenceRoot = Environment.GetEnvironmentVariable(EvidenceRootVariable);
        Assert.False(
            string.IsNullOrWhiteSpace(evidenceRoot),
            EvidenceRootVariable + " must name the directory with the raw EDL captures while this test runs.");

        var beforeMain = File.ReadAllBytes(Path.Combine(evidenceRoot!, BeforeMainFileName));
        var beforeBackup = File.ReadAllBytes(Path.Combine(evidenceRoot!, BeforeBackupFileName));
        var afterMain = File.ReadAllBytes(Path.Combine(evidenceRoot!, AfterMainFileName));
        var afterBackup = File.ReadAllBytes(Path.Combine(evidenceRoot!, AfterBackupFileName));

        var original = OriginalGptImporter.Parse(beforeMain, beforeBackup, SectorSize, DiskBytes);
        var currentRaw = OriginalGptImporter.Parse(afterMain, afterBackup, SectorSize, DiskBytes);

        // Both captures are raw bytes, so neither names a device node.
        Assert.Null(original.DeviceId);
        Assert.Null(currentRaw.DeviceId);

        var originalUserdata = original.Partitions.Single(partition => partition.Name == "userdata");
        Assert.Equal(5_972_392L, originalUserdata.StartSector);
        Assert.Equal(
            123_871_227L,
            originalUserdata.StartSector + originalUserdata.SectorCount);

        var currentUserdata = currentRaw.Partitions.Single(partition => partition.Name == "userdata");
        Assert.Equal(33_554_432L, currentUserdata.SectorCount);

        var identity = new DeviceIdentity("DEVICE-EDL-EVIDENCE-TEST", "TB322FC", BootloaderState.Unlocked);
        var validated = UninstallEvidenceValidator.ValidateEdl(identity, original, currentRaw, 0);

        Assert.Equal(EdlDeviceId, validated.CurrentTable.DeviceId);
        Assert.Equal(EdlDeviceId, validated.Record.DeviceId);

        // The raw digests survive verbatim on both sides of the validated token.
        Assert.Equal(original.SourceFingerprint, validated.OriginalGptFingerprint);
        Assert.Equal(currentRaw.SourceFingerprint, validated.CurrentTableFingerprint);
        Assert.Equal(currentRaw.SourceFingerprint, validated.CurrentTable.SourceFingerprint);

        Assert.Equal(5_972_392L, validated.Plan.UserdataStartSector);
        Assert.Equal(123_871_227L, validated.Plan.UserdataEndSectorExclusive);
        Assert.Equal(482_913_628_160L, validated.Plan.RestoredAndroidBytes); // 117,898,835 sectors of 4096

        // The real capture puts the owned Linux partitions in slots 17 and 18, not in the synthetic 3/4.
        Assert.Equal(new long[] { 17L, 18L }, validated.Plan.RemovedPartitionNumbers);
    }

    // --------------------------------------------------------------------------- helpers

    /// <summary>
    /// A concrete, non-placeholder identity naming one of the supported models, so no negative case trips the
    /// unsupported-model gate instead of the behaviour under test. The serial is synthetic.
    /// </summary>
    private static DeviceIdentity Identity()
        => new("R58EDLTEST01", "TB322FC", BootloaderState.Unlocked);

    /// <summary>Parses a fixture pair through the real importer, never by constructing a GptTable directly.</summary>
    private static GptTable ParseRaw(GptImage image)
        => OriginalGptImporter.Parse(
            image.BuildPrimaryFragment(),
            image.BuildBackupFragment(),
            GptFixture.SectorSize4096,
            GptFixture.DiskBytes4096);

    private static GptTable OriginalTable()
        => ParseRaw(GptFixture.RealLike4096());

    /// <summary>
    /// The installed disk as raw bytes: the factory vendor partition, the shrunk userdata and the two owned
    /// Linux partitions at the legacy geometry (88-sector gap, boot 1 GiB, root ending on userdata's old end).
    /// </summary>
    private static GptTable CurrentRawTable(
        ulong proinfoAttributes = 0UL,
        long proinfoStart = GptFixture.ProinfoStart,
        long proinfoCount = GptFixture.ProinfoCount)
        => ParseRaw(new GptImage(
            GptFixture.SectorSize4096,
            GptFixture.DiskBytes4096,
            GptFixture.DiskGuid,
            6L,
            GptFixture.LastUsable4096,
            new GptPartitionSpec(
                1, "proinfo", GptFixture.ProinfoType, GptFixture.ProinfoUuid,
                proinfoStart, proinfoCount, proinfoAttributes),
            new GptPartitionSpec(
                2, "userdata", GptFixture.UserdataType, GptFixture.UserdataUuid,
                GptFixture.UserdataStart, GptFixture.CurrentUserdataCount, 0UL),
            new GptPartitionSpec(
                3, "ARMADA_BOOT", GptFixture.LinuxType, GptFixture.BootUuid,
                GptFixture.BootStart, GptFixture.BootCount, 0UL),
            new GptPartitionSpec(
                4, "ARMADA_ROOT", GptFixture.LinuxType, GptFixture.RootUuid,
                GptFixture.RootStart, GptFixture.RootCount, 0UL)));

    /// <summary>Everything observable about a table, so an in-place mutation between two calls is visible.</summary>
    private static string Describe(GptTable table)
    {
        var builder = new StringBuilder();
        builder.Append(table.DeviceId ?? "<null>")
            .Append('|').Append(table.SectorSize)
            .Append('|').Append(table.DiskBytes)
            .Append('|').Append(table.DiskGuid)
            .Append('|').Append(table.FirstUsableSector)
            .Append('|').Append(table.LastUsableSector)
            .Append('|').Append(table.SourceFingerprint);

        foreach (var partition in table.Partitions)
        {
            builder.Append(';')
                .Append(partition.Number).Append(',')
                .Append(partition.Name).Append(',')
                .Append(partition.TypeGuid).Append(',')
                .Append(partition.PartUuid).Append(',')
                .Append(partition.StartSector).Append(',')
                .Append(partition.SectorCount).Append(',')
                .Append(partition.Attributes);
        }

        return builder.ToString();
    }
}
