using System;
using System.Buffers.Binary;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class TfCardLayoutTests
{
    private const long GiB = 1024L * 1024 * 1024;
    private const long CardBytes64GiB = 64L * GiB;
    private const long BootImage1GiB = GiB;
    private const long RootImage32GiB = 32L * GiB;
    private const long MinimumRoot32GiB = 32L * GiB;

    private static readonly Guid DiskGuid = new("3f2a1b6c-8d4e-4f70-9a12-5c3b7e8d9f01");
    private static readonly Guid BootGuid = new("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d");
    private static readonly Guid RootGuid = new("f0e1d2c3-b4a5-4687-9a0b-c1d2e3f4a5b6");

    // ------------------------------------------------------------- plan geometry

    [Fact]
    public void Create_512ByteSectors_MatchesTheFixedTicketGeometry()
    {
        var plan = TfCardLayout.Create(
            CardBytes64GiB, 512, BootImage1GiB, RootImage32GiB, MinimumRoot32GiB,
            DiskGuid, BootGuid, RootGuid);

        Assert.Equal(CardBytes64GiB, plan.CardBytes);
        Assert.Equal(512, plan.LogicalSectorSize);
        Assert.Equal(134_217_728L, plan.TotalSectors);
        Assert.Equal(2048L, plan.BootStartSector);
        Assert.Equal(2_097_152L, plan.BootSectorCount);
        Assert.Equal(2_099_200L, plan.RootStartSector);
        Assert.Equal(132_118_495L, plan.RootSectorCount);
        Assert.Equal(DiskGuid, plan.DiskGuid);
        Assert.Equal(BootGuid, plan.BootGuid);
        Assert.Equal(RootGuid, plan.RootGuid);
    }

    [Fact]
    public void Create_4096ByteSectors_MatchesTheFixedTicketGeometry()
    {
        var plan = TfCardLayout.Create(
            CardBytes64GiB, 4096, BootImage1GiB, RootImage32GiB, MinimumRoot32GiB,
            DiskGuid, BootGuid, RootGuid);

        Assert.Equal(4096, plan.LogicalSectorSize);
        Assert.Equal(16_777_216L, plan.TotalSectors);
        Assert.Equal(256L, plan.BootStartSector);
        Assert.Equal(262_144L, plan.BootSectorCount);
        Assert.Equal(262_400L, plan.RootStartSector);
        Assert.Equal(16_514_811L, plan.RootSectorCount);
    }

    // ------------------------------------------------------------- serialized bytes parse back

    [Fact]
    public void SerializeGpt_512ByteSectors_ProducesFragmentsTheRealImporterParses()
    {
        var writeSet = RoundTripAndCheckCommonFacts(
            512, CardBytes64GiB, BootImage1GiB, RootImage32GiB, MinimumRoot32GiB,
            expectedLastUsable: 134_217_694L,
            expectedBackupBytes: 33 * 512);

        Assert.Equal(0L, writeSet.PrimaryOffsetBytes);
        Assert.Equal(34 * 512, writeSet.PrimaryBytes.Length);
        Assert.Equal(CardBytes64GiB - writeSet.BackupBytes.Length, writeSet.BackupOffsetBytes);

        // MBR signature at LBA 0 and the protective EE entry at its fixed offset.
        Assert.Equal(0x55, writeSet.PrimaryBytes[510]);
        Assert.Equal(0xAA, writeSet.PrimaryBytes[511]);
        Assert.Equal(0xEE, writeSet.PrimaryBytes[446 + 4]);

        // Protective size = total logical sectors - 1 (512e disk: same count either way).
        Assert.Equal(
            (uint)(CardBytes64GiB / 512 - 1),
            BinaryPrimitives.ReadUInt32LittleEndian(writeSet.PrimaryBytes.AsSpan(446 + 12, 4)));
        AssertPmbrChsTuples(writeSet.PrimaryBytes);
    }

    [Fact]
    public void SerializeGpt_4096ByteSectors_ProducesFragmentsTheRealImporterParses()
    {
        var writeSet = RoundTripAndCheckCommonFacts(
            4096, CardBytes64GiB, BootImage1GiB, RootImage32GiB, MinimumRoot32GiB,
            expectedLastUsable: 16_777_210L,
            expectedBackupBytes: 5 * 4096);

        Assert.Equal(0L, writeSet.PrimaryOffsetBytes);
        Assert.Equal(6 * 4096, writeSet.PrimaryBytes.Length);
        Assert.Equal(CardBytes64GiB - writeSet.BackupBytes.Length, writeSet.BackupOffsetBytes);

        Assert.Equal(0x55, writeSet.PrimaryBytes[510]);
        Assert.Equal(0xAA, writeSet.PrimaryBytes[511]);
        Assert.Equal(0xEE, writeSet.PrimaryBytes[446 + 4]);

        // Protective size uses the 4096-byte logical count, not the 512e count.
        Assert.Equal(
            (uint)(CardBytes64GiB / 4096 - 1),
            BinaryPrimitives.ReadUInt32LittleEndian(writeSet.PrimaryBytes.AsSpan(446 + 12, 4)));
        AssertPmbrChsTuples(writeSet.PrimaryBytes);
    }

    // Start CHS (0, 2, 0) and end CHS (0xFF, 0xFF, 0xFF) as in util-linux gpt.c gpt_write_pmbr.
    private static void AssertPmbrChsTuples(byte[] primaryBytes)
    {
        Assert.Equal(0x00, primaryBytes[446 + 1]);
        Assert.Equal(0x02, primaryBytes[446 + 2]);
        Assert.Equal(0x00, primaryBytes[446 + 3]);
        Assert.Equal(0xFF, primaryBytes[446 + 5]);
        Assert.Equal(0xFF, primaryBytes[446 + 6]);
        Assert.Equal(0xFF, primaryBytes[446 + 7]);
    }
    private static TfGptWriteSet RoundTripAndCheckCommonFacts(
        int sectorSize,
        long cardBytes,
        long bootImageBytes,
        long rootImageBytes,
        long minimumRootBytes,
        long expectedLastUsable,
        int expectedBackupBytes)
    {
        var plan = TfCardLayout.Create(
            cardBytes, sectorSize, bootImageBytes, rootImageBytes, minimumRootBytes,
            DiskGuid, BootGuid, RootGuid);

        var writeSet = TfCardLayout.SerializeGpt(plan);
        Assert.Equal(expectedBackupBytes, writeSet.BackupBytes.Length);

        var table = OriginalGptImporter.Parse(
            writeSet.PrimaryBytes, writeSet.BackupBytes, sectorSize, cardBytes);

        Assert.Equal(sectorSize, table.SectorSize);
        Assert.Equal(cardBytes, table.DiskBytes);
        Assert.Equal("3F2A1B6C-8D4E-4F70-9A12-5C3B7E8D9F01", table.DiskGuid);
        Assert.Equal(expectedLastUsable, table.LastUsableSector);

        Assert.Equal(2, table.Partitions.Count);

        var boot = table.Partitions[0];
        Assert.Equal(1, boot.Number);
        Assert.Equal("ARMADA_TF_BOOT", boot.Name);
        Assert.Equal("0FC63DAF-8483-4772-8E79-3D69D8477DE4", boot.TypeGuid);
        Assert.Equal("A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D", boot.PartUuid);
        Assert.Equal(plan.BootStartSector, boot.StartSector);
        Assert.Equal(plan.BootSectorCount, boot.SectorCount);
        Assert.Equal(0UL, boot.Attributes);

        var root = table.Partitions[1];
        Assert.Equal(2, root.Number);
        Assert.Equal("ARMADA_TF_ROOT", root.Name);
        Assert.Equal("0FC63DAF-8483-4772-8E79-3D69D8477DE4", root.TypeGuid);
        Assert.Equal("F0E1D2C3-B4A5-4687-9A0B-C1D2E3F4A5B6", root.PartUuid);
        Assert.Equal(plan.RootStartSector, root.StartSector);
        Assert.Equal(plan.RootSectorCount, root.SectorCount);
        Assert.Equal(0UL, root.Attributes);

        return writeSet;
    }

    // ------------------------------------------------------------- rejections

    [Fact]
    public void Create_RejectsInvalidInputs_BeforeAnyIo()
    {
        // Card too small even for the fixed overhead: 63 GiB minimum root cannot fit.
        Assert.ThrowsAny<Exception>(() => TfCardLayout.Create(
            CardBytes64GiB, 512, BootImage1GiB, RootImage32GiB, 63L * GiB,
            DiskGuid, BootGuid, RootGuid));

        // Card too small for the boot image itself.
        Assert.ThrowsAny<Exception>(() => TfCardLayout.Create(
            2L * GiB, 512, BootImage1GiB, RootImage32GiB, MinimumRoot32GiB,
            DiskGuid, BootGuid, RootGuid));

        // Unsupported sector size.
        Assert.ThrowsAny<Exception>(() => TfCardLayout.Create(
            CardBytes64GiB, 1024, BootImage1GiB, RootImage32GiB, MinimumRoot32GiB,
            DiskGuid, BootGuid, RootGuid));

        // Misaligned image and card lengths.
        Assert.ThrowsAny<Exception>(() => TfCardLayout.Create(
            CardBytes64GiB, 512, BootImage1GiB + 1, RootImage32GiB, MinimumRoot32GiB,
            DiskGuid, BootGuid, RootGuid));
        Assert.ThrowsAny<Exception>(() => TfCardLayout.Create(
            CardBytes64GiB + 100, 512, BootImage1GiB, RootImage32GiB, MinimumRoot32GiB,
            DiskGuid, BootGuid, RootGuid));

        // Non-positive inputs.
        Assert.ThrowsAny<Exception>(() => TfCardLayout.Create(
            0, 512, BootImage1GiB, RootImage32GiB, MinimumRoot32GiB,
            DiskGuid, BootGuid, RootGuid));
        Assert.ThrowsAny<Exception>(() => TfCardLayout.Create(
            CardBytes64GiB, 512, -BootImage1GiB, RootImage32GiB, MinimumRoot32GiB,
            DiskGuid, BootGuid, RootGuid));
        Assert.ThrowsAny<Exception>(() => TfCardLayout.Create(
            CardBytes64GiB, 512, BootImage1GiB, 0, MinimumRoot32GiB,
            DiskGuid, BootGuid, RootGuid));
        Assert.ThrowsAny<Exception>(() => TfCardLayout.Create(
            CardBytes64GiB, 512, BootImage1GiB, RootImage32GiB, 0,
            DiskGuid, BootGuid, RootGuid));

        // Zero or duplicate GUIDs.
        Assert.ThrowsAny<Exception>(() => TfCardLayout.Create(
            CardBytes64GiB, 512, BootImage1GiB, RootImage32GiB, MinimumRoot32GiB,
            Guid.Empty, BootGuid, RootGuid));
        Assert.ThrowsAny<Exception>(() => TfCardLayout.Create(
            CardBytes64GiB, 512, BootImage1GiB, RootImage32GiB, MinimumRoot32GiB,
            DiskGuid, Guid.Empty, RootGuid));
        Assert.ThrowsAny<Exception>(() => TfCardLayout.Create(
            CardBytes64GiB, 512, BootImage1GiB, RootImage32GiB, MinimumRoot32GiB,
            DiskGuid, BootGuid, Guid.Empty));
        Assert.ThrowsAny<Exception>(() => TfCardLayout.Create(
            CardBytes64GiB, 512, BootImage1GiB, RootImage32GiB, MinimumRoot32GiB,
            DiskGuid, BootGuid, BootGuid));
    }

    [Fact]
    public void SerializeGpt_RejectsNullPlan()
    {
        Assert.Throws<ArgumentNullException>(() => TfCardLayout.SerializeGpt(null!));
    }
}
