using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;
using FreedomInstaller.Core;
using Xunit;
using Xunit.Sdk;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Contract for <see cref="OriginalGptImporter.Parse"/>. Every fixture below is a raw GPT byte array written
/// here field by field from the UEFI layout, with its own CRC32s, so the parser is exercised against the
/// on-disk format and never against anything the production code produced. No file, process or device is
/// touched. The tests that assert parsing or rejection behaviour are expected to fail with
/// <see cref="NotImplementedException"/> until the parser lands.
/// </summary>
public sealed class OriginalGptImporterTests
{
    // ------------------------------------------------------------- accepted tables

    [Fact]
    public void Parse_RealLike4096Disk_DecodesTheTableAndFindsTheBackupAtItsOwnOffset()
    {
        var image = GptFixture.RealLike4096();

        var table = OriginalGptImporter.Parse(
            image.BuildPrimaryFragment(),
            image.BuildBackupFragment(),
            GptFixture.SectorSize4096,
            GptFixture.DiskBytes4096);

        // Raw original bytes name no device node, so the identity of the disk is its GUID and nothing else.
        Assert.Null(table.DeviceId);
        Assert.Equal(4096, table.SectorSize);
        Assert.Equal(507_376_566_272L, table.DiskBytes);
        Assert.Equal("10BEF391-0EBA-9668-B82C-4E092F4C4467", table.DiskGuid);
        Assert.Equal(6L, table.FirstUsableSector);
        Assert.Equal(123_871_226L, table.LastUsableSector);
        Assert.False(string.IsNullOrWhiteSpace(table.SourceFingerprint));

        Assert.Equal(2, table.Partitions.Count);

        var userdata = GptFixture.Partition(table, 2);
        Assert.Equal("userdata", userdata.Name);
        Assert.Equal("1B81E7E6-F50D-419B-A739-2AEEF8DA3335", userdata.TypeGuid);
        Assert.Equal("7F6876B2-2CE6-51A0-505D-A7865864D1BD", userdata.PartUuid);
        Assert.Equal(5_972_392L, userdata.StartSector);
        Assert.Equal(117_898_835L, userdata.SectorCount);
        Assert.Equal(0UL, userdata.Attributes);

        var proinfo = GptFixture.Partition(table, 1);
        Assert.Equal("proinfo", proinfo.Name);
        Assert.Equal(6L, proinfo.StartSector);
        Assert.Equal(768L, proinfo.SectorCount);

        // The backup fragment holds the LAST 16 sectors of the disk: its header sits at offset 61,440
        // (= 123,871,231 - 123,871,216 sectors), not at offset 4,096. A parser that anchors both fragments
        // at LBA 1 reads the backup entry array as a header and cannot decode this pair.
    }

    [Fact]
    public void Parse_512SectorDisk_DecodesItsOwnLiteralSectorValues()
    {
        // Same shape, but every number below is expressed in 512-byte sectors: 4,000,000 sectors total,
        // backup header at 3,999,999 which is offset 65,024 inside the 128-sector backup fragment.
        var image = GptFixture.Small512();

        var table = OriginalGptImporter.Parse(
            image.BuildPrimaryFragment(),
            image.BuildBackupFragment(),
            512,
            GptFixture.DiskBytes512);

        Assert.Null(table.DeviceId);
        Assert.Equal(512, table.SectorSize);
        Assert.Equal(2_048_000_000L, table.DiskBytes);
        Assert.Equal("3C9A8E2B-5D41-4F6C-9A17-0B2E4D8C6F51", table.DiskGuid);
        Assert.Equal(34L, table.FirstUsableSector);
        Assert.Equal(3_999_959L, table.LastUsableSector);

        var userdata = GptFixture.Partition(table, 2);
        Assert.Equal(65_536L, userdata.StartSector);
        Assert.Equal(3_000_000L, userdata.SectorCount);

        var proinfo = GptFixture.Partition(table, 1);
        Assert.Equal(40L, proinfo.StartSector);
        Assert.Equal(2_048L, proinfo.SectorCount);
    }

    [Fact]
    public void Parse_SourceFingerprintFollowsTheSourceBytes()
    {
        var plain = GptFixture.RealLike4096();
        var withAttributes = GptFixture.RealLike4096(proinfoAttributes: (1UL << 50) | (1UL << 60));

        var first = OriginalGptImporter.Parse(
            plain.BuildPrimaryFragment(), plain.BuildBackupFragment(), GptFixture.SectorSize4096, GptFixture.DiskBytes4096);
        var second = OriginalGptImporter.Parse(
            withAttributes.BuildPrimaryFragment(), withAttributes.BuildBackupFragment(), GptFixture.SectorSize4096, GptFixture.DiskBytes4096);

        // Both tables are legal, but they were decoded from different bytes and must not share a fingerprint.
        Assert.False(string.IsNullOrWhiteSpace(first.SourceFingerprint));
        Assert.False(string.IsNullOrWhiteSpace(second.SourceFingerprint));
        Assert.NotEqual(first.SourceFingerprint, second.SourceFingerprint);
    }

    // ------------------------------------------------------- corrupted CRCs are refused

    [Fact]
    public void Parse_RejectsHeaderCrcThatDoesNotMatchTheHeader()
    {
        var image = GptFixture.RealLike4096();
        var primary = image.BuildPrimaryFragment();

        // Only the stored CRC is damaged: every header field is still legal and still matches the backup.
        var stored = GptBytes.ReadUInt32(primary, image.PrimaryHeaderOffset + GptBytes.HeaderCrcOffset);
        GptBytes.WriteUInt32(primary, image.PrimaryHeaderOffset + GptBytes.HeaderCrcOffset, stored ^ 0x1u);

        AssertInvalidData(() => OriginalGptImporter.Parse(
            primary, image.BuildBackupFragment(), GptFixture.SectorSize4096, GptFixture.DiskBytes4096));
    }

    [Fact]
    public void Parse_RejectsEntryArrayCrcThatDoesNotMatchTheArray()
    {
        var image = GptFixture.RealLike4096();
        var primary = image.BuildPrimaryFragment();

        // The array bytes stay identical to the backup's; only the CRC the header declares is wrong.
        var stored = GptBytes.ReadUInt32(primary, image.PrimaryHeaderOffset + GptBytes.EntryArrayCrcOffset);
        GptBytes.WriteUInt32(primary, image.PrimaryHeaderOffset + GptBytes.EntryArrayCrcOffset, stored ^ 0x1u);
        GptBytes.RefreshHeaderCrc(primary, image.PrimaryHeaderOffset, GptImage.HeaderSize);

        AssertInvalidData(() => OriginalGptImporter.Parse(
            primary, image.BuildBackupFragment(), GptFixture.SectorSize4096, GptFixture.DiskBytes4096));
    }

    // -------------------------------------- primary and backup that disagree are refused

    [Theory]
    [InlineData(GptDefect.SelfLba)]
    [InlineData(GptDefect.AlternateLba)]
    [InlineData(GptDefect.DiskGuid)]
    [InlineData(GptDefect.UsableBounds)]
    [InlineData(GptDefect.EntryArrayBytes)]
    public void Parse_RejectsPrimaryAndBackupThatDisagreeEvenWithFreshCrcs(GptDefect defect)
    {
        var image = GptFixture.RealLike4096();
        var primary = image.BuildPrimaryFragment();
        var backup = image.BuildBackupFragment();

        // Every mutation below is followed by refreshing the CRCs, so the bytes are internally intact and the
        // only defect left is that the two halves describe different tables. A parser that checks a CRC and
        // then compares nothing would wrongly accept each of these.
        switch (defect)
        {
            case GptDefect.SelfLba:
                GptBytes.WriteInt64(backup, image.BackupHeaderOffset + GptBytes.CurrentLbaOffset, image.LastLba - 1);
                GptBytes.RefreshHeaderCrc(backup, image.BackupHeaderOffset, GptImage.HeaderSize);
                break;

            case GptDefect.AlternateLba:
                // The primary header's alternate LBA no longer points at where the backup header really is.
                GptBytes.WriteInt64(primary, image.PrimaryHeaderOffset + GptBytes.AlternateLbaOffset, image.LastLba - 1);
                GptBytes.RefreshHeaderCrc(primary, image.PrimaryHeaderOffset, GptImage.HeaderSize);
                break;

            case GptDefect.DiskGuid:
                GptBytes.WriteGuid(backup.AsSpan(), image.BackupHeaderOffset + GptBytes.DiskGuidOffset, "99999999-8888-4777-8666-555544443333");
                GptBytes.RefreshHeaderCrc(backup, image.BackupHeaderOffset, GptImage.HeaderSize);
                break;

            case GptDefect.UsableBounds:
                GptBytes.WriteInt64(backup, image.BackupHeaderOffset + GptBytes.LastUsableOffset, image.LastUsableSector - 1);
                GptBytes.RefreshHeaderCrc(backup, image.BackupHeaderOffset, GptImage.HeaderSize);
                break;

            case GptDefect.EntryArrayBytes:
                // One name byte flips case ('p' -> 'P'); both CRCs are refreshed so only the mismatch remains.
                primary[image.PrimaryArrayOffset + 56] ^= 0x20;
                GptBytes.RefreshEntryArrayCrc(primary, image.PrimaryArrayOffset, image.ArrayBytes, image.PrimaryHeaderOffset);
                break;

            default:
                throw new InvalidOperationException("fixture: unknown defect " + defect);
        }

        AssertInvalidData(() => OriginalGptImporter.Parse(
            primary, backup, GptFixture.SectorSize4096, GptFixture.DiskBytes4096));
    }

    // ------------------------------------------------ truncated, misplaced or absurd arrays

    [Fact]
    public void Parse_RejectsPrimaryFragmentThatStopsBeforeTheEntryArray()
    {
        var image = GptFixture.RealLike4096();
        var primary = image.BuildPrimaryFragment();
        var truncated = new byte[2 * image.SectorSize]; // header at 4,096 is present, the array at 8,192 is not
        Array.Copy(primary, truncated, truncated.Length);

        AssertInvalidData(() => OriginalGptImporter.Parse(
            truncated, image.BuildBackupFragment(), GptFixture.SectorSize4096, GptFixture.DiskBytes4096));
    }

    [Fact]
    public void Parse_RejectsBackupFragmentThatDoesNotReachItsHeader()
    {
        var image = GptFixture.RealLike4096();
        var backup = image.BuildBackupFragment();
        var truncated = new byte[4 * image.SectorSize]; // the 61,440 offset header is gone
        Array.Copy(backup, truncated, truncated.Length);

        AssertInvalidData(() => OriginalGptImporter.Parse(
            image.BuildPrimaryFragment(), truncated, GptFixture.SectorSize4096, GptFixture.DiskBytes4096));
    }

    [Fact]
    public void Parse_RejectsDeclaredEntryArrayOutsideTheFragment()
    {
        var image = GptFixture.RealLike4096();
        var primary = image.BuildPrimaryFragment();

        // The header claims the array sits 1,000 sectors into the disk: far beyond the 16-sector fragment.
        GptBytes.WriteInt64(primary, image.PrimaryHeaderOffset + GptBytes.EntryArrayLbaOffset, 1_000);
        GptBytes.RefreshHeaderCrc(primary, image.PrimaryHeaderOffset, GptImage.HeaderSize);

        AssertInvalidData(() => OriginalGptImporter.Parse(
            primary, image.BuildBackupFragment(), GptFixture.SectorSize4096, GptFixture.DiskBytes4096));
    }

    [Fact]
    public void Parse_RejectsAbsurdDeclaredEntryCountInsteadOfAllocatingIt()
    {
        var image = GptFixture.RealLike4096();
        var primary = image.BuildPrimaryFragment();

        // 0x00FFFFFF entries x 128 bytes is about 2 GiB declared. The 4 MiB cap must reject this without
        // ever allocating the declared length, so this test finishes instead of exhausting the test host.
        GptBytes.WriteUInt32(primary, image.PrimaryHeaderOffset + GptBytes.EntryCountOffset, 0x00FF_FFFFu);
        GptBytes.RefreshHeaderCrc(primary, image.PrimaryHeaderOffset, GptImage.HeaderSize);

        AssertInvalidData(() => OriginalGptImporter.Parse(
            primary, image.BuildBackupFragment(), GptFixture.SectorSize4096, GptFixture.DiskBytes4096));
    }

    // ------------------------------------------------------------- invalid caller input

    [Theory]
    [InlineData(0)]
    [InlineData(1024)]
    [InlineData(-4096)]
    [InlineData(8192)]
    public void Parse_RejectsSectorSizesOtherThan512Or4096(int sectorSize)
    {
        var image = GptFixture.RealLike4096();

        Assert.Throws<ArgumentException>(() => OriginalGptImporter.Parse(
            image.BuildPrimaryFragment(), image.BuildBackupFragment(), sectorSize, GptFixture.DiskBytes4096));
    }

    [Fact]
    public void Parse_RejectsFragmentLengthThatIsNotSectorAligned()
    {
        var image = GptFixture.RealLike4096();
        var primary = image.BuildPrimaryFragment();
        var ragged = new byte[primary.Length - 1];
        Array.Copy(primary, ragged, ragged.Length);

        Assert.Throws<ArgumentException>(() => OriginalGptImporter.Parse(
            ragged, image.BuildBackupFragment(), GptFixture.SectorSize4096, GptFixture.DiskBytes4096));
    }

    [Fact]
    public void Parse_RejectsMissingFragment()
    {
        var image = GptFixture.RealLike4096();

        Assert.Throws<ArgumentNullException>(() => OriginalGptImporter.Parse(
            null!, image.BuildBackupFragment(), GptFixture.SectorSize4096, GptFixture.DiskBytes4096));

        Assert.Throws<ArgumentNullException>(() => OriginalGptImporter.Parse(
            image.BuildPrimaryFragment(), null!, GptFixture.SectorSize4096, GptFixture.DiskBytes4096));
    }

    [Fact]
    public void Parse_RejectsDiskLengthThatIsNotASectorMultiple()
    {
        var image = GptFixture.RealLike4096();

        Assert.Throws<ArgumentException>(() => OriginalGptImporter.Parse(
            image.BuildPrimaryFragment(), image.BuildBackupFragment(), GptFixture.SectorSize4096, GptFixture.DiskBytes4096 - 1));
    }

    // ----------------------------------------------------------------------- helpers

    private static void AssertInvalidData(Action action)
    {
        var exception = Record.Exception(action);

        Assert.NotNull(exception);
        Assert.True(
            exception is InvalidDataException,
            "expected InvalidDataException but got " + exception!.GetType().FullName);
    }
}

/// <summary>Which field of the pair is made to disagree, with the CRCs left valid.</summary>
public enum GptDefect
{
    SelfLba,
    AlternateLba,
    DiskGuid,
    UsableBounds,
    EntryArrayBytes,
}

/// <summary>One entry to write into the fixture's entry array.</summary>
internal sealed class GptPartitionSpec
{
    internal GptPartitionSpec(
        int number,
        string name,
        string typeGuid,
        string partUuid,
        long startSector,
        long sectorCount,
        ulong attributes)
    {
        Number = number;
        Name = name;
        TypeGuid = typeGuid;
        PartUuid = partUuid;
        StartSector = startSector;
        SectorCount = sectorCount;
        Attributes = attributes;
    }

    internal int Number { get; }

    internal string Name { get; }

    internal string TypeGuid { get; }

    internal string PartUuid { get; }

    internal long StartSector { get; }

    internal long SectorCount { get; }

    internal ulong Attributes { get; }
}

/// <summary>Offsets and primitives of the on-disk format, written out independently of the production code.</summary>
internal static class GptBytes
{
    internal const int SignatureOffset = 0;
    internal const int RevisionOffset = 8;
    internal const int HeaderSizeFieldOffset = 12;
    internal const int HeaderCrcOffset = 16;
    internal const int ReservedOffset = 20;
    internal const int CurrentLbaOffset = 24;
    internal const int AlternateLbaOffset = 32;
    internal const int FirstUsableOffset = 40;
    internal const int LastUsableOffset = 48;
    internal const int DiskGuidOffset = 56;
    internal const int EntryArrayLbaOffset = 72;
    internal const int EntryCountOffset = 80;
    internal const int EntrySizeOffset = 84;
    internal const int EntryArrayCrcOffset = 88;

    internal static uint ReadUInt32(byte[] buffer, int offset)
        => BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offset, 4));

    internal static void WriteUInt32(byte[] buffer, int offset, uint value)
        => BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset, 4), value);

    internal static void WriteInt64(byte[] buffer, int offset, long value)
        => BinaryPrimitives.WriteInt64LittleEndian(buffer.AsSpan(offset, 8), value);

    /// <summary>GPT stores GUIDs in the mixed-endian order <see cref="Guid"/> itself uses, so ToByteArray matches.</summary>
    internal static void WriteGuid(Span<byte> destination, int offset, string text)
    {
        if (!Guid.TryParse(text, out var guid))
        {
            throw new InvalidOperationException($"fixture: '{text}' is not a GUID");
        }

        guid.TryWriteBytes(destination.Slice(offset, 16));
    }

    /// <summary>CRC32 with the reflected IEEE polynomial 0xEDB88320, as GPT requires.</summary>
    internal static uint Crc32(byte[] data, int offset, int length)
    {
        var crc = 0xFFFF_FFFFu;
        for (var index = 0; index < length; index++)
        {
            crc ^= data[offset + index];
            for (var bit = 0; bit < 8; bit++)
            {
                crc = (crc & 1u) != 0u ? (crc >> 1) ^ 0xEDB8_8320u : crc >> 1;
            }
        }

        return ~crc;
    }

    /// <summary>Recomputes the header CRC over the header size with the CRC field zeroed.</summary>
    internal static void RefreshHeaderCrc(byte[] fragment, int headerOffset, int headerSize)
    {
        WriteUInt32(fragment, headerOffset + HeaderCrcOffset, 0u);
        WriteUInt32(fragment, headerOffset + HeaderCrcOffset, Crc32(fragment, headerOffset, headerSize));
    }

    /// <summary>Recomputes the entry array CRC into the header, then the header CRC that covers that field.</summary>
    internal static void RefreshEntryArrayCrc(byte[] fragment, int arrayOffset, int arrayLength, int headerOffset)
    {
        WriteUInt32(fragment, headerOffset + EntryArrayCrcOffset, Crc32(fragment, arrayOffset, arrayLength));
        RefreshHeaderCrc(fragment, headerOffset, GptImage.HeaderSize);
    }
}

/// <summary>
/// A logical disk written as two 64 KiB fragments: the primary one starting at LBA 0 and the backup one
/// ending at the last LBA. The disk itself is only declared by <see cref="DiskBytes"/>; no 500 GB is
/// allocated, only the two windows the parser is allowed to read.
/// </summary>
internal sealed class GptImage
{
    internal const int EntrySize = 128;
    internal const int EntryCount = 32;
    internal const int FragmentBytes = 64 * 1024;
    internal const int HeaderSize = 92;
    internal const int NameFieldBytes = 72;

    private readonly GptPartitionSpec[] _partitions;

    internal GptImage(
        int sectorSize,
        long diskBytes,
        string diskGuid,
        long firstUsableSector,
        long lastUsableSector,
        params GptPartitionSpec[] partitions)
    {
        if (diskBytes <= 0 || diskBytes % sectorSize != 0)
        {
            throw new InvalidOperationException("fixture: disk length must be a positive sector multiple");
        }

        if (FragmentBytes % sectorSize != 0)
        {
            throw new InvalidOperationException("fixture: 64 KiB fragment is not sector aligned");
        }

        SectorSize = sectorSize;
        DiskBytes = diskBytes;
        DiskGuid = diskGuid;
        FirstUsableSector = firstUsableSector;
        LastUsableSector = lastUsableSector;
        _partitions = partitions;
    }

    internal int SectorSize { get; }

    internal long DiskBytes { get; }

    internal string DiskGuid { get; }

    internal long FirstUsableSector { get; }

    internal long LastUsableSector { get; }

    internal long TotalSectors => DiskBytes / SectorSize;

    internal long LastLba => TotalSectors - 1;

    /// <summary>LBA the backup fragment starts at; the backup header is at <see cref="LastLba"/>.</summary>
    internal long BackupOriginLba => TotalSectors - (FragmentBytes / SectorSize);

    internal int ArrayBytes => EntryCount * EntrySize;

    internal int ArraySectors => ArrayBytes / SectorSize;

    internal long PrimaryArrayLba => 2;

    internal long BackupArrayLba => LastLba - ArraySectors;

    internal int PrimaryHeaderOffset => SectorSize;

    internal int PrimaryArrayOffset => 2 * SectorSize;

    internal int BackupHeaderOffset => checked((int)((LastLba - BackupOriginLba) * SectorSize));

    internal int BackupArrayOffset => checked((int)((BackupArrayLba - BackupOriginLba) * SectorSize));

    internal byte[] BuildPrimaryFragment()
    {
        var fragment = new byte[FragmentBytes];

        // Protective MBR in LBA 0, then the header in LBA 1 and the entry array from LBA 2.
        WriteProtectiveMbr(fragment);

        var entries = BuildEntryArray();
        RequireInsideFragment(PrimaryArrayOffset, entries.Length, "primary entry array");
        Buffer.BlockCopy(entries, 0, fragment, PrimaryArrayOffset, entries.Length);

        WriteHeader(
            fragment,
            PrimaryHeaderOffset,
            selfLba: 1,
            alternateLba: LastLba,
            firstUsable: FirstUsableSector,
            lastUsable: LastUsableSector,
            arrayLba: PrimaryArrayLba,
            diskGuid: DiskGuid,
            entryArrayCrc: GptBytes.Crc32(entries, 0, entries.Length));

        return fragment;
    }

    internal byte[] BuildBackupFragment()
    {
        var fragment = new byte[FragmentBytes];

        var entries = BuildEntryArray();
        RequireInsideFragment(BackupArrayOffset, entries.Length, "backup entry array");
        Buffer.BlockCopy(entries, 0, fragment, BackupArrayOffset, entries.Length);

        WriteHeader(
            fragment,
            BackupHeaderOffset,
            selfLba: LastLba,
            alternateLba: 1,
            firstUsable: FirstUsableSector,
            lastUsable: LastUsableSector,
            arrayLba: BackupArrayLba,
            diskGuid: DiskGuid,
            entryArrayCrc: GptBytes.Crc32(entries, 0, entries.Length));

        return fragment;
    }

    private static void WriteProtectiveMbr(byte[] fragment)
    {
        fragment[446 + 4] = 0xEE; // one GPT protective partition
        BinaryPrimitives.WriteUInt32LittleEndian(fragment.AsSpan(446 + 8, 4), 1u);
        BinaryPrimitives.WriteUInt32LittleEndian(fragment.AsSpan(446 + 12, 4), uint.MaxValue);
        fragment[510] = 0x55;
        fragment[511] = 0xAA;
    }

    private byte[] BuildEntryArray()
    {
        var entries = new byte[ArrayBytes];

        foreach (var partition in _partitions)
        {
            if (partition.Number < 1 || partition.Number > EntryCount)
            {
                throw new InvalidOperationException($"fixture: entry number {partition.Number} is outside the array");
            }

            var offset = (partition.Number - 1) * EntrySize;

            GptBytes.WriteGuid(entries.AsSpan(), offset, partition.TypeGuid);
            GptBytes.WriteGuid(entries.AsSpan(), offset + 16, partition.PartUuid);
            BinaryPrimitives.WriteInt64LittleEndian(entries.AsSpan(offset + 32, 8), partition.StartSector);

            // The entry stores the LAST sector of the extent, not its length.
            BinaryPrimitives.WriteInt64LittleEndian(
                entries.AsSpan(offset + 40, 8),
                partition.StartSector + partition.SectorCount - 1);

            BinaryPrimitives.WriteUInt64LittleEndian(entries.AsSpan(offset + 48, 8), partition.Attributes);

            var name = Encoding.Unicode.GetBytes(partition.Name);
            if (name.Length > NameFieldBytes)
            {
                throw new InvalidOperationException("fixture: partition name exceeds the 72 byte name field");
            }

            name.CopyTo(entries, offset + 56);
        }

        return entries;
    }

    private void WriteHeader(
        byte[] fragment,
        int headerOffset,
        long selfLba,
        long alternateLba,
        long firstUsable,
        long lastUsable,
        long arrayLba,
        string diskGuid,
        uint entryArrayCrc)
    {
        RequireInsideFragment(headerOffset, HeaderSize, "header");

        var header = fragment.AsSpan(headerOffset, HeaderSize);

        var signature = Encoding.ASCII.GetBytes("EFI PART");
        signature.AsSpan().CopyTo(header[GptBytes.SignatureOffset..]);
        BinaryPrimitives.WriteUInt32LittleEndian(header[GptBytes.RevisionOffset..], 0x0001_0000u);
        BinaryPrimitives.WriteUInt32LittleEndian(header[GptBytes.HeaderSizeFieldOffset..], HeaderSize);
        BinaryPrimitives.WriteUInt32LittleEndian(header[GptBytes.HeaderCrcOffset..], 0u);
        BinaryPrimitives.WriteUInt32LittleEndian(header[GptBytes.ReservedOffset..], 0u);
        BinaryPrimitives.WriteInt64LittleEndian(header[GptBytes.CurrentLbaOffset..], selfLba);
        BinaryPrimitives.WriteInt64LittleEndian(header[GptBytes.AlternateLbaOffset..], alternateLba);
        BinaryPrimitives.WriteInt64LittleEndian(header[GptBytes.FirstUsableOffset..], firstUsable);
        BinaryPrimitives.WriteInt64LittleEndian(header[GptBytes.LastUsableOffset..], lastUsable);
        GptBytes.WriteGuid(header, GptBytes.DiskGuidOffset, diskGuid);
        BinaryPrimitives.WriteInt64LittleEndian(header[GptBytes.EntryArrayLbaOffset..], arrayLba);
        BinaryPrimitives.WriteUInt32LittleEndian(header[GptBytes.EntryCountOffset..], EntryCount);
        BinaryPrimitives.WriteUInt32LittleEndian(header[GptBytes.EntrySizeOffset..], EntrySize);
        BinaryPrimitives.WriteUInt32LittleEndian(header[GptBytes.EntryArrayCrcOffset..], entryArrayCrc);

        BinaryPrimitives.WriteUInt32LittleEndian(
            header[GptBytes.HeaderCrcOffset..],
            GptBytes.Crc32(fragment, headerOffset, HeaderSize));
    }

    private static void RequireInsideFragment(int offset, int length, string what)
    {
        if (offset < 0 || length < 0 || offset + length > FragmentBytes)
        {
            throw new InvalidOperationException($"fixture: {what} does not fit into the {FragmentBytes} byte fragment");
        }
    }
}

/// <summary>
/// The literal geometry the tests use: a real-like 4,000,000-sector-class tablet disk at 4096 bytes per
/// sector, plus a standalone 512-byte disk whose numbers are expressed in 512-byte sectors only.
/// </summary>
internal static class GptFixture
{
    internal const int SectorSize4096 = 4096;
    internal const long DiskBytes4096 = 507_376_566_272; // 123,871,232 sectors
    internal const long LastUsable4096 = 123_871_226; // last LBA 123,871,231 minus the 5 reserved sectors

    internal const string DiskGuid = "10BEF391-0EBA-9668-B82C-4E092F4C4467";
    internal const string ProinfoType = "1DFD76D9-7E4F-434B-9DC6-28F9C983CD91";
    internal const string ProinfoUuid = "580CF933-BA9B-5048-B221-F683F755277C";
    internal const string UserdataType = "1B81E7E6-F50D-419B-A739-2AEEF8DA3335";
    internal const string UserdataUuid = "7F6876B2-2CE6-51A0-505D-A7865864D1BD";
    internal const string LinuxType = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
    internal const string BootUuid = "F7617F07-9D25-C653-DC40-E4F8C5816B6A";
    internal const string RootUuid = "C52E5589-00AB-799D-4253-F7A50A6E6191";

    internal const long ProinfoStart = 6;
    internal const long ProinfoCount = 768;
    internal const long UserdataStart = 5_972_392;
    internal const long UserdataCount = 117_898_835;
    internal const long UserdataEndExclusive = UserdataStart + UserdataCount; // 123,871,227

    internal const long CurrentUserdataCount = 33_554_432;
    internal const long BootStart = 39_526_912;
    internal const long BootCount = 262_144;
    internal const long RootStart = 39_789_056;
    internal const long RootCount = 84_082_171;
    internal const long RestoredAndroidBytes = 482_913_628_160;

    // 512-byte disk: 4,000,000 sectors of its own unit, with the backup header 127 sectors into its fragment.
    internal const long DiskBytes512 = 2_048_000_000;
    internal const long LastUsable512 = 3_999_959;
    internal const string DiskGuid512 = "3C9A8E2B-5D41-4F6C-9A17-0B2E4D8C6F51";
    internal const long ProinfoStart512 = 40;
    internal const long ProinfoCount512 = 2_048;
    internal const long UserdataStart512 = 65_536;
    internal const long UserdataCount512 = 3_000_000;

    /// <summary>The original Android table of the real-like disk: proinfo and the full-size userdata.</summary>
    internal static GptImage RealLike4096(ulong proinfoAttributes = 0UL) => new(
        SectorSize4096,
        DiskBytes4096,
        DiskGuid,
        6,
        LastUsable4096,
        new GptPartitionSpec(1, "proinfo", ProinfoType, ProinfoUuid, ProinfoStart, ProinfoCount, proinfoAttributes),
        new GptPartitionSpec(2, "userdata", UserdataType, UserdataUuid, UserdataStart, UserdataCount, 0UL));

    internal static GptImage Small512() => new(
        512,
        DiskBytes512,
        DiskGuid512,
        34,
        LastUsable512,
        new GptPartitionSpec(1, "proinfo", ProinfoType, ProinfoUuid, ProinfoStart512, ProinfoCount512, 0UL),
        new GptPartitionSpec(2, "userdata", UserdataType, UserdataUuid, UserdataStart512, UserdataCount512, 0UL));

    internal static GptPartition Partition(GptTable table, int number)
    {
        foreach (var partition in table.Partitions)
        {
            if (partition.Number == number)
            {
                return partition;
            }
        }

        throw new XunitException($"partition #{number} is missing from a table of {table.Partitions.Count} entries");
    }
}
