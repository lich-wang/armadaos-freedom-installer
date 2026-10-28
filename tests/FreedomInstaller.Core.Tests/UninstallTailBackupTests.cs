using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Regression contract for the CURRENT installer tail layout: the factory <c>userdata</c> extent is split
/// into the shrunk <c>userdata</c>, <c>ARMADA_BOOT</c> (exactly 1 GiB), <c>ARMADA_ROOT</c> (shortened by
/// exactly the fixed 2 GiB the backup occupies) and <c>ARMADA_BACKUP</c> (exactly 2 GiB) immediately after
/// the root, ending on the factory userdata end. Uninstall keeps the recovery copy: only ARMADA_BOOT and
/// ARMADA_ROOT are removed, ARMADA_BACKUP is preserved with its exact extent, PARTUUID, type, name,
/// attributes and content, and userdata is enlarged to the backup's first sector.
/// <para>
/// Every table below is a raw GPT pair decoded by the real <see cref="OriginalGptImporter.Parse"/> from the
/// byte-level fixture builders of <see cref="OriginalGptImporterTests"/>; no <see cref="GptTable"/> is built
/// by hand and no sfdisk document stands in for captured bytes. The legacy two-Linux-partition layout stays
/// accepted, so the new-layout cases below are additive rather than a replacement.
/// </para>
/// <para>
/// The accepted three-partition cases are expected to fail against a validator that still allows exactly two
/// new partitions; the negative cases and the legacy case do not depend on that gap.
/// </para>
/// </summary>
public sealed class UninstallTailBackupTests
{
    /// <summary>A synthetic fixture backup PARTUUID for this layout; the installer does not fix one globally.</summary>
    private const string BackupUuid = "9ABF724F-5CE5-4ADC-8B71-C16040A2DFE3";

    /// <summary>A second, distinct PARTUUID used only to prove the UUID is part of the evidence.</summary>
    private const string OtherBackupUuid = "7C1D3B52-0F4A-4D6E-9B28-5E6C1A0D9F34";

    /// <summary>A distinct PARTUUID for a partition this install does not own.</summary>
    private const string ExtraTailUuid = "5D0E5F21-3C4B-4A99-8F60-2B7D1C6E4A10";

    private const long TwoGiBInSectors = 2L * 1024 * 1024 * 1024 / GptFixture.SectorSize4096;
    private const long OneGiBInSectors = 1L * 1024 * 1024 * 1024 / GptFixture.SectorSize4096;

    /// <summary>ARMADA_ROOT shortens by exactly the 2 GiB that ARMADA_BACKUP then occupies.</summary>
    private const long ShortenedRootCount = GptFixture.RootCount - TwoGiBInSectors;

    /// <summary>First sector of the new backup: the original userdata end minus exactly 2 GiB.</summary>
    private const long BackupStartSector = GptFixture.UserdataEndExclusive - TwoGiBInSectors;

    // ---------------------------------------------------------------- accepted layouts

    [Theory]
    [InlineData("TB322FC", BootloaderState.Unlocked)]
    [InlineData("TB323FU", BootloaderState.Locked)]
    public void ValidateEdl_CurrentLayoutWithRetainedBackup_PlansBootRootOnlyRestore(
        string model, BootloaderState bootloaderState)
    {
        var identity = new DeviceIdentity("R58EDLTAIL01", model, bootloaderState);
        var original = OriginalTable();
        var current = InstalledTable(ShortenedRootCount, Backup(BackupUuid));
        var originalSnapshot = Describe(original);

        var inputs = UninstallEvidenceValidator.ValidateEdl(identity, original, current, 0);

        // The factory extent comes back to the backup's first sector, not all the way to the factory end.
        Assert.Equal(GptFixture.UserdataStart, inputs.Plan.UserdataStartSector);
        Assert.Equal(BackupStartSector, inputs.Plan.UserdataEndSectorExclusive);
        Assert.Equal(GptFixture.RestoredAndroidBytes - TwoGiBInSectors * GptFixture.SectorSize4096, inputs.Plan.RestoredAndroidBytes);
        Assert.Equal(GptFixture.UserdataEndExclusive, inputs.Record.OriginalUserdataEndSector);

        // Exactly boot and root go; the retained backup slot 5 keeps its exact identity and geometry.
        Assert.Equal(2, inputs.Plan.RemovedPartitionNumbers.Count);
        Assert.Contains(3L, inputs.Plan.RemovedPartitionNumbers);
        Assert.Contains(4L, inputs.Plan.RemovedPartitionNumbers);
        Assert.DoesNotContain(5L, inputs.Plan.RemovedPartitionNumbers);

        var retainedBackup = GptFixture.Partition(current, 5);
        Assert.Equal(BackupUuid, retainedBackup.PartUuid);
        Assert.Equal(BackupStartSector, retainedBackup.StartSector);
        Assert.Equal(TwoGiBInSectors, retainedBackup.SectorCount);

        // The factory table is evidence only: validating must not relabel or rewrite it.
        Assert.Null(original.DeviceId);
        Assert.Equal(2, original.Partitions.Count);
        Assert.Equal(originalSnapshot, Describe(original));
    }

    [Fact]
    public void ValidateEdl_BackupUuidIsBoundIntoTheEvidenceFingerprint()
    {
        var identity = new DeviceIdentity("R58EDLTAIL02", "TB322FC", BootloaderState.Unlocked);
        var original = OriginalTable();
        var fixedBackup = InstalledTable(ShortenedRootCount, Backup(BackupUuid));
        var otherBackup = InstalledTable(ShortenedRootCount, Backup(OtherBackupUuid));

        // The two tables differ in one field only: the PARTUUID of slot 5.
        Assert.Equal(5, fixedBackup.Partitions.Count);
        Assert.Equal(5, otherBackup.Partitions.Count);
        Assert.Equal(BackupUuid, GptFixture.Partition(fixedBackup, 5).PartUuid);
        Assert.Equal(OtherBackupUuid, GptFixture.Partition(otherBackup, 5).PartUuid);

        var fixedInputs = UninstallEvidenceValidator.ValidateEdl(identity, original, fixedBackup, 0);
        var otherInputs = UninstallEvidenceValidator.ValidateEdl(identity, original, otherBackup, 0);

        // Two legal tables that name a different backup must never collapse to one evidence token.
        Assert.NotEqual(fixedInputs.CurrentTableFingerprint, otherInputs.CurrentTableFingerprint);
        Assert.NotEqual(fixedInputs.EvidenceFingerprint, otherInputs.EvidenceFingerprint);

        // The boot/root-only restore is still the same: the UUID names the retained backup's ownership,
        // it does not change the restore geometry.
        Assert.Equal(fixedInputs.Plan.UserdataEndSectorExclusive, otherInputs.Plan.UserdataEndSectorExclusive);
        Assert.Equal(fixedInputs.Plan.RestoredAndroidBytes, otherInputs.Plan.RestoredAndroidBytes);
        Assert.Equal(fixedInputs.Plan.RemovedPartitionNumbers, otherInputs.Plan.RemovedPartitionNumbers);
    }

    [Fact]
    public void ValidateEdl_LegacyTwoLinuxTail_IsStillAcceptedAndRemovesBootAndRoot()
    {
        var identity = new DeviceIdentity("R58EDLTAIL03", "TB323FU", BootloaderState.Locked);
        var original = OriginalTable();

        // The pre-backup layout: userdata, 1 GiB boot and a root that still ends on the factory userdata end.
        var current = InstalledTable(GptFixture.RootCount);

        var inputs = UninstallEvidenceValidator.ValidateEdl(identity, original, current, 0);

        Assert.Equal(2, inputs.Plan.RemovedPartitionNumbers.Count);
        Assert.Contains(3L, inputs.Plan.RemovedPartitionNumbers);
        Assert.Contains(4L, inputs.Plan.RemovedPartitionNumbers);
        Assert.Equal(GptFixture.UserdataEndExclusive, inputs.Plan.UserdataEndSectorExclusive);
        Assert.Equal(GptFixture.RestoredAndroidBytes, inputs.Plan.RestoredAndroidBytes);
    }

    // ---------------------------------------------------------------- rejected layouts

    [Fact]
    public void ValidateEdl_RejectsBackupThatIsNotExactlyTwoGiB()
    {
        // ROOT gives up exactly 1 GiB, so the tail is still contiguous and still ends on the factory end;
        // only the fixed 2 GiB size of the backup is wrong.
        var current = InstalledTable(
            GptFixture.RootCount - OneGiBInSectors,
            new GptPartitionSpec(
                5, "ARMADA_BACKUP", GptFixture.LinuxType, BackupUuid,
                GptFixture.UserdataEndExclusive - OneGiBInSectors, OneGiBInSectors, 0UL));

        AssertParsedTail(current, 5, GptFixture.UserdataEndExclusive);
        AssertRejected(current);
    }

    [Fact]
    public void ValidateEdl_RejectsBackupWithANonLinuxType()
    {
        var current = InstalledTable(
            ShortenedRootCount,
            new GptPartitionSpec(
                5, "ARMADA_BACKUP", GptFixture.UserdataType, BackupUuid,
                BackupStartSector, TwoGiBInSectors, 0UL));

        AssertParsedTail(current, 5, GptFixture.UserdataEndExclusive);
        Assert.Equal(GptFixture.UserdataType, GptFixture.Partition(current, 5).TypeGuid);
        AssertRejected(current);
    }

    [Fact]
    public void ValidateEdl_RejectsOneSectorGapBetweenRootAndBackup()
    {
        // ROOT stops one sector short and the backup keeps its exact 2 GiB, so a single unowned sector is
        // left between them while the tail still ends on the factory userdata end.
        var rootCount = ShortenedRootCount - 1;
        var rootEnd = GptFixture.RootStart + rootCount;
        var current = InstalledTable(
            rootCount,
            new GptPartitionSpec(
                5, "ARMADA_BACKUP", GptFixture.LinuxType, BackupUuid,
                rootEnd + 1, TwoGiBInSectors, 0UL));

        AssertParsedTail(current, 5, GptFixture.UserdataEndExclusive);
        Assert.Equal(rootEnd + 1, GptFixture.Partition(current, 5).StartSector);
        AssertRejected(current);
    }

    [Fact]
    public void ValidateEdl_RejectsUnknownTailAfterTheBackup()
    {
        // ROOT and the backup keep their exact sizes; a 4 MiB partition this install does not own is fitted
        // after the backup by shortening ROOT, so the GPT stays valid and still ends on the factory end.
        const long extraSectors = 1024L;
        var rootCount = ShortenedRootCount - extraSectors;
        var backupStart = GptFixture.RootStart + rootCount;
        var current = InstalledTable(
            rootCount,
            new GptPartitionSpec(
                5, "ARMADA_BACKUP", GptFixture.LinuxType, BackupUuid,
                backupStart, TwoGiBInSectors, 0UL),
            new GptPartitionSpec(
                6, "vendor_extra", GptFixture.LinuxType, ExtraTailUuid,
                backupStart + TwoGiBInSectors, extraSectors, 0UL));

        AssertParsedTail(current, 6, GptFixture.UserdataEndExclusive);
        Assert.Equal("vendor_extra", GptFixture.Partition(current, 6).Name);
        AssertRejected(current);
    }

    [Fact]
    public void ValidateEdl_RejectsASecondBackupLabelWithADistinctUuid()
    {
        // Two 1 GiB halves, both labelled ARMADA_BACKUP, both Linux, together exactly the 2 GiB tail. Only
        // the second label is unowned, so a name-only check would accept it.
        var half = TwoGiBInSectors / 2;
        var current = InstalledTable(
            ShortenedRootCount,
            new GptPartitionSpec(
                5, "ARMADA_BACKUP", GptFixture.LinuxType, BackupUuid,
                BackupStartSector, half, 0UL),
            new GptPartitionSpec(
                6, "ARMADA_BACKUP", GptFixture.LinuxType, OtherBackupUuid,
                BackupStartSector + half, TwoGiBInSectors - half, 0UL));

        AssertParsedTail(current, 6, GptFixture.UserdataEndExclusive);
        Assert.NotEqual(
            GptFixture.Partition(current, 5).PartUuid, GptFixture.Partition(current, 6).PartUuid);
        AssertRejected(current);
    }

    [Fact]
    public void ValidateEdl_RejectsAnInstalledSnapshotPresentedAsTheOriginal()
    {
        // Both sides are the installed layout. It is a self-consistent GPT, so it parses; what makes it
        // unusable is that a factory table cannot carry an ARMADA_BACKUP of its own.
        var installed = InstalledTable(ShortenedRootCount, Backup(BackupUuid));
        var current = InstalledTable(ShortenedRootCount, Backup(BackupUuid));

        Assert.Null(installed.DeviceId);
        Assert.Equal(5, installed.Partitions.Count);
        Assert.Equal("ARMADA_BACKUP", GptFixture.Partition(installed, 5).Name);

        AssertRejected(installed, current, originalIsInstalled: true);
    }

    // --------------------------------------------------------------------------- helpers

    private static DeviceIdentity Identity() => new("R58EDLTAIL99", "TB322FC", BootloaderState.Unlocked);

    /// <summary>The factory table of the real-like 4Kn disk: proinfo plus the full-size userdata.</summary>
    private static GptTable OriginalTable() => Parse(GptFixture.RealLike4096());

    /// <summary>
    /// The installed disk as raw bytes: the vendor slot, the shrunk userdata, the 1 GiB boot and a root of
    /// <paramref name="rootCount"/> sectors followed by whatever tail slots the caller appends.
    /// </summary>
    private static GptTable InstalledTable(long rootCount, params GptPartitionSpec[] tail)
    {
        var partitions = new List<GptPartitionSpec>
        {
            new(1, "proinfo", GptFixture.ProinfoType, GptFixture.ProinfoUuid,
                GptFixture.ProinfoStart, GptFixture.ProinfoCount, 0UL),
            new(2, "userdata", GptFixture.UserdataType, GptFixture.UserdataUuid,
                GptFixture.UserdataStart, GptFixture.CurrentUserdataCount, 0UL),
            new(3, "ARMADA_BOOT", GptFixture.LinuxType, GptFixture.BootUuid,
                GptFixture.BootStart, GptFixture.BootCount, 0UL),
            new(4, "ARMADA_ROOT", GptFixture.LinuxType, GptFixture.RootUuid,
                GptFixture.RootStart, rootCount, 0UL),
        };

        partitions.AddRange(tail);

        return Parse(new GptImage(
            GptFixture.SectorSize4096,
            GptFixture.DiskBytes4096,
            GptFixture.DiskGuid,
            6L,
            GptFixture.LastUsable4096,
            partitions.ToArray()));
    }

    private static GptPartitionSpec Backup(string partUuid) => new(
        5, "ARMADA_BACKUP", GptFixture.LinuxType, partUuid, BackupStartSector, TwoGiBInSectors, 0UL);

    /// <summary>Decodes a fixture pair with the real importer, never by constructing a table directly.</summary>
    private static GptTable Parse(GptImage image) => OriginalGptImporter.Parse(
        image.BuildPrimaryFragment(),
        image.BuildBackupFragment(),
        GptFixture.SectorSize4096,
        GptFixture.DiskBytes4096);

    /// <summary>
    /// Proves a negative fixture is a legal GPT before anything is asserted about validation: the tail count
    /// and its end sector are checked on the parsed table, so a rejection can never come from a CRC or import
    /// failure.
    /// </summary>
    private static void AssertParsedTail(GptTable table, int partitionCount, long expectedEndExclusive)
    {
        Assert.Null(table.DeviceId);
        Assert.Equal(partitionCount, table.Partitions.Count);

        var tail = table.Partitions[partitionCount - 1];
        Assert.Equal(expectedEndExclusive, tail.StartSector + tail.SectorCount);
    }

    /// <summary>
    /// Asserts the evidence layer refuses the table, whatever business rule fires first. The validator
    /// documents its rejections as <see cref="InvalidDataException"/>, <see cref="ArgumentException"/> or
    /// <see cref="InvalidOperationException"/>; the exact message is deliberately not pinned.
    /// </summary>
    private static void AssertRejected(GptTable current)
        => AssertRejected(OriginalTable(), current, originalIsInstalled: false);

    private static void AssertRejected(GptTable original, GptTable current, bool originalIsInstalled)
    {
        var identity = originalIsInstalled
            ? new DeviceIdentity("R58EDLTAIL98", "TB323FU", BootloaderState.Locked)
            : Identity();

        var exception = Record.Exception(
            () => UninstallEvidenceValidator.ValidateEdl(identity, original, current, 0));

        Assert.NotNull(exception);
        Assert.True(
            exception is InvalidDataException or ArgumentException or InvalidOperationException,
            "expected a validation rejection but got " + exception!.GetType().FullName);
    }

    /// <summary>Everything observable about a table, so an in-place mutation between two reads is visible.</summary>
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
