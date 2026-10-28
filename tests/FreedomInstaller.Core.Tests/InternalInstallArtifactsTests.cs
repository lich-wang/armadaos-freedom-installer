using System;
using System.Buffers.Binary;
using System.Collections;
using System.Collections.Generic;
using System.Formats.Tar;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;
using Xunit.Sdk;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Contract for <see cref="InternalInstallArtifacts"/>. The tests never touch a device, an EDL session, a process
/// or the network: they either drive an internal pure helper through reflection with tiny in-memory GPT images,
/// or they run the one full <see cref="InternalInstallArtifacts.PrepareAsync"/> integration against a 52 file
/// backup fixture whose image is the real, fixed 2 GiB layout.
/// <para>
/// The fixture builds every raw table from the UEFI on-disk layout through the existing
/// <see cref="GptImage"/>/<see cref="GptPartitionSpec"/>/<see cref="GptBytes"/> helpers, so nothing here is
/// produced by the code under test. All work happens below <c>EDL_CLIENT_TEST_WORK_ROOT</c>; there is no
/// temporary-directory or drive-root fallback.
/// </para>
/// <para>
/// The integration fixture creates a <see cref="InternalBackupSet"/> with
/// <see cref="RuntimeHelpers.GetUninitializedObject"/> and sets the private backing fields by reflection, failing
/// with an explicit message when a field is absent; no public fake factory or test-only constructor was added to
/// production.
/// </para>
/// </summary>
public sealed class InternalInstallArtifactsTests
{
    private const int SectorSize4096 = 4096;
    private const int SectorSize512 = 512;
    private const long OneGiB = 1L << 30;
    private const long TwoGiB = 2L << 30;
    private const int ManifestBytes = 64 * 1024;
    private const int Block = 512;
    private const long UserdataStart4096 = 5_972_392;
    private const long UserdataCount4096 = 26_214_400; // 100 GiB at 4096
    private const long UserdataStart512 = 5_972_392;
    private const long UserdataCount512 = 209_715_200; // 100 GiB at 512
    private const string LinuxType = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";

    private static readonly string[] Lun0Roles =
    {
        "proinfo", "lenovolock", "lenovocust", "lenovoraw", "ssd", "persist", "misc", "keystore", "frp",
        "metadata", "vbmeta_system_a", "vbmeta_system_b",
    };

    private static readonly string[] Lun1Roles = { "xbl_a", "xbl_config_a" };

    private static readonly string[] Lun2Roles = { "xbl_b", "xbl_config_b" };

    private static readonly string[] Lun3Roles = { "cdt" };

    private static readonly string[] Lun4Roles =
    {
        "boot_a", "boot_b", "init_boot_a", "init_boot_b", "vendor_boot_a", "vendor_boot_b", "dtbo_a", "dtbo_b",
        "vbmeta_a", "vbmeta_b", "recovery_a", "recovery_b", "devinfo", "uefivarstore", "secdata", "connsec",
        "spunvm", "abl_a", "abl_b",
    };

    private static readonly string[] Lun5Roles = { "modemst1", "modemst2", "fsg", "fsc" };

    /// <summary>The seven roles the loader-backup contract added on top of the original 45 files.</summary>
    private static readonly string[] AddedRoles =
    {
        "xbl_a", "xbl_config_a", "xbl_b", "xbl_config_b", "cdt", "abl_a", "abl_b",
    };

    private static readonly string[] FormerlyExcludedRoles =
    {
        "vendor_boot_a", "vendor_boot_b", "recovery_a", "recovery_b",
    };

    private static readonly string[] RequiredRoles = ContractRoles();
    private static readonly string[] BoardRoles = RequiredRoles.Where(role => role != "metadata").ToArray();

    /// <summary>The four LUN0 labels that only the G4 profile captures.</summary>
    private static readonly string[] G4OnlyRoles = { "proinfo", "lenovolock", "lenovocust", "lenovoraw" };

    /// <summary>The 48 roles the G5 contract requires: the 52 file set without the four G4-only labels.</summary>
    private static readonly string[] Gen5Roles = RequiredRoles
        .Where(role => !G4OnlyRoles.Contains(role, StringComparer.Ordinal))
        .ToArray();

    // ------------------------------------------------------------- argument handling

    [Fact]
    public async Task PrepareAsync_RejectsMissingOrImplicitParentWithoutCreatingAnything()
    {
        var work = CreateWorkRoot();
        var missing = Path.Combine(work, "missing-" + Guid.NewGuid().ToString("N"));

        // A set that was never populated is enough: the parent is refused before any property is read.
        var backup = NewUnpopulatedBackupSet();

        var parents = new[] { null, string.Empty, "   ", "relative/parent", missing };

        foreach (var parent in parents)
        {
            var exception = await Record.ExceptionAsync(() =>
                InternalInstallArtifacts.PrepareAsync(backup, 16, Storage(), parent!, CancellationToken.None));

            Assert.IsAssignableFrom<ArgumentException>(exception);
        }

        Assert.Empty(Directory.GetFileSystemEntries(work));
        Assert.False(Directory.Exists(missing));
    }

    [Fact]
    public async Task PrepareAsync_PreCancelledCreatesNoDirectory()
    {
        var work = CreateWorkRoot();
        var backup = NewUnpopulatedBackupSet();

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        var exception = await Record.ExceptionAsync(() =>
            InternalInstallArtifacts.PrepareAsync(backup, 16, Storage(), work, cancellation.Token));

        Assert.IsAssignableFrom<OperationCanceledException>(exception);
        Assert.Empty(Directory.GetFileSystemEntries(work));
    }

    [Fact]
    public async Task PrepareAsync_RejectsNonPositiveAndroidSize()
    {
        var work = CreateWorkRoot();
        var backup = NewUnpopulatedBackupSet();

        var exception = await Record.ExceptionAsync(() =>
            InternalInstallArtifacts.PrepareAsync(backup, 0, Storage(), work, CancellationToken.None));

        Assert.IsAssignableFrom<ArgumentOutOfRangeException>(exception);
        Assert.Empty(Directory.GetFileSystemEntries(work));
    }

    // ------------------------------------------------------------- archive sizing

    [Theory]
    [InlineData(new long[0], 66_048L + 1_024L)]
    [InlineData(new[] { 5L }, 66_048L + 1_024L + 1_024L)]
    [InlineData(new[] { 512L, 513L }, 66_048L + 2_560L + 1_024L)]
    [InlineData(new[] { 4_096L, 1L, 65_537L }, 66_048L + 4_608L + 1_024L + 66_560L + 1_024L)]
    public void ComputeRequiredArchiveBytes_MatchesTheExactUstarLayout(long[] payloadLengths, long expected)
    {
        var required = InvokeLong("ComputeRequiredArchiveBytes", 100, payloadLengths);

        // First manifest entry: 512 header + the fixed 64 KiB payload; then every payload's 512 byte header,
        // its data padded to a block; then the two zero terminal blocks.
        Assert.Equal(expected, required);
    }

    [Theory]
    [InlineData(0, new long[0])]
    [InlineData(ManifestBytes + 1, new long[0])]
    [InlineData(100, new[] { -1L })]
    [InlineData(100, new[] { long.MaxValue })]
    public void ComputeRequiredArchiveBytes_RejectsManifestCapAndUnrepresentableLayouts(int manifestLength, long[] payloadLengths)
    {
        var exception = Record.Exception(() => Invoke("ComputeRequiredArchiveBytes", manifestLength, payloadLengths));

        Assert.IsType<InvalidDataException>(exception);
    }

    [Fact]
    public void ComputeRequiredArchiveBytes_AcceptsAnExactUncompressedLayoutLargerThanTheFixedImage()
    {
        // The raw Ustar may exceed the 2 GiB image; only the compressed member has to fit it. The check still
        // reports the exact uncompressed length instead of refusing it against the image size.
        var required = InvokeLong("ComputeRequiredArchiveBytes", 100, new[] { TwoGiB });

        Assert.Equal(66_048L + Block + TwoGiB + 1_024L, required);
        Assert.True(required > TwoGiB);
    }

    [Fact]
    public void ComputePayloadLayout_PutsEveryPayloadHeaderOnTheNextBlockBoundary()
    {
        var layout = Invoke("ComputePayloadLayout", new[] { 5L, 512L, 513L })!;
        var headers = Field<long[]>(layout, "HeaderOffsets");
        var data = Field<long[]>(layout, "DataOffsets");

        Assert.Equal(new[] { 66_048L, 67_072L, 68_096L }, headers);
        Assert.Equal(new[] { 66_560L, 67_584L, 68_608L }, data);
        Assert.Equal(69_632L, Field<long>(layout, "End"));
    }

    // ------------------------------------------------------------------- GPT rewrite

    [Theory]
    [InlineData(SectorSize4096)]
    [InlineData(SectorSize512)]
    public void BuildGptRewrite_PreservesEveryOriginalByteExceptThePlannedFields(int sectorSize)
    {
        var image = RewriteImage(sectorSize);
        var head = image.BuildPrimaryFragment();
        var tail = image.BuildBackupFragment();

        // Bytes the GPT format does not own: header slack after the declared header size and the gap behind the
        // sector rounded entry array. Both must survive into the post-GPT captures untouched.
        head[image.PrimaryHeaderOffset + 100] = 0xA6;
        head[(2 * sectorSize) + image.ArrayBytes + 10] = 0xA5;

        var diskBytes = image.DiskBytes;
        var table = OriginalGptImporter.Parse(head, tail, sectorSize, diskBytes);
        var userdata = Partition(table, "userdata");
        var allocation = Plan(table, userdata, sectorSize, image.FirstUsableSector);

        var bootUuid = Guid.NewGuid();
        var rootUuid = Guid.NewGuid();
        var backupUuid = Guid.NewGuid();
        var rewrite = Invoke("BuildGptRewrite", head, tail, sectorSize, diskBytes, table, allocation, bootUuid, rootUuid, backupUuid)!;

        var descriptors = Members(rewrite, "WriteRegions");
        Assert.Equal(4, descriptors.Count);
        Assert.Equal("backup-array", Member(descriptors[0], "Role"));
        Assert.Equal("backup-header", Member(descriptors[1], "Role"));
        Assert.Equal("primary-array", Member(descriptors[2], "Role"));
        Assert.Equal("primary-header", Member(descriptors[3], "Role"));

        var entryBytes = GptImage.EntryCount * GptImage.EntrySize;
        var arraySectors = (entryBytes + sectorSize - 1) / sectorSize;
        var arrayLength = arraySectors * sectorSize;

        Assert.Equal(image.BackupArrayLba, Field<long>(descriptors[0], "StartSector"));
        Assert.Equal(arraySectors, Field<long>(descriptors[0], "SectorCount"));
        Assert.Equal(arrayLength, Field<long>(descriptors[0], "Length"));
        Assert.Equal(image.LastLba, Field<long>(descriptors[1], "StartSector"));
        Assert.Equal(1L, Field<long>(descriptors[1], "SectorCount"));
        Assert.Equal((long)sectorSize, Field<long>(descriptors[1], "Length"));
        Assert.Equal(image.PrimaryArrayLba, Field<long>(descriptors[2], "StartSector"));
        Assert.Equal((long)arrayLength, Field<long>(descriptors[2], "Length"));
        Assert.Equal(1L, Field<long>(descriptors[3], "StartSector"));

        var primaryHeader = Field<byte[]>(descriptors[3], "Bytes");
        var primaryArray = Field<byte[]>(descriptors[2], "Bytes");
        var backupArray = Field<byte[]>(descriptors[0], "Bytes");
        var backupHeader = Field<byte[]>(descriptors[1], "Bytes");

        Assert.True(primaryArray.AsSpan(0, entryBytes).SequenceEqual(backupArray.AsSpan(0, entryBytes)));

        // The four regions are the whole write set: header slack and the array's trailing gap are not covered by
        // any descriptor.
        Assert.Equal(sectorSize, primaryHeader.Length);
        Assert.Equal(arrayLength, primaryArray.Length);

        // Only the header CRC and the entry array CRC may differ inside the header sector.
        var originalHeader = head.AsSpan(image.PrimaryHeaderOffset, sectorSize).ToArray();
        for (var index = 0; index < sectorSize; index++)
        {
            var isHeaderCrc = index >= 16 && index < 20;
            var isArrayCrc = index >= 88 && index < 92;
            if (!isHeaderCrc && !isArrayCrc)
            {
                Assert.Equal(originalHeader[index], primaryHeader[index]);
            }
        }

        // The header CRC covers exactly headerSize bytes with its own field zeroed; the array CRC covers exactly
        // entryCount * 128 bytes, never the padding.
        var declaredArrayCrc = BinaryPrimitives.ReadUInt32LittleEndian(primaryHeader.AsSpan(88, 4));
        Assert.Equal(GptBytes.Crc32(primaryArray, 0, entryBytes), declaredArrayCrc);

        var headerCopy = (byte[])primaryHeader.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(headerCopy.AsSpan(16, 4), 0u);
        Assert.Equal(
            BinaryPrimitives.ReadUInt32LittleEndian(primaryHeader.AsSpan(16, 4)),
            GptBytes.Crc32(headerCopy, 0, GptImage.HeaderSize));

        // Every original entry is byte-for-byte intact except userdata's end LBA and the three new entries.
        var userdataOffset = (userdata.Number - 1) * GptImage.EntrySize;
        var originalArray = head.AsSpan(image.PrimaryArrayOffset, image.ArrayBytes).ToArray();
        var freeSlots = FreeSlots(originalArray, GptImage.EntryCount);
        Assert.True(freeSlots.Count >= 3);
        var newSlots = freeSlots.Take(3).ToArray();

        for (var entry = 0; entry < GptImage.EntryCount; entry++)
        {
            var offset = entry * GptImage.EntrySize;
            var original = head.AsSpan(image.PrimaryArrayOffset + offset, GptImage.EntrySize);
            var rewritten = primaryArray.AsSpan(offset, GptImage.EntrySize);

            if (newSlots.Contains(entry))
            {
                continue;
            }

            if (entry * GptImage.EntrySize == userdataOffset)
            {
                Assert.False(original.Slice(40, 8).SequenceEqual(rewritten.Slice(40, 8)));
                Assert.True(original[..40].SequenceEqual(rewritten[..40]));
                Assert.True(original.Slice(48).SequenceEqual(rewritten.Slice(48)));
                Assert.Equal(
                    allocation.AndroidEndSectorExclusive - 1,
                    BinaryPrimitives.ReadInt64LittleEndian(rewritten.Slice(40, 8)));
                continue;
            }

            Assert.True(original.SequenceEqual(rewritten), $"entry {entry + 1} was rewritten");
        }

        var expectedUuids = new[] { bootUuid, rootUuid, backupUuid };
        var expectedNames = new[] { "ARMADA_BOOT", "ARMADA_ROOT", "ARMADA_BACKUP" };
        var expectedStarts = new[]
        {
            allocation.LinuxBootStartSector, allocation.LinuxRootStartSector, allocation.BackupStartSector,
        };
        var expectedCounts = new[]
        {
            allocation.LinuxBootSectorCount, allocation.LinuxRootSectorCount, allocation.BackupSectorCount,
        };

        for (var index = 0; index < 3; index++)
        {
            var offset = newSlots[index] * GptImage.EntrySize;
            var entry = primaryArray.AsSpan(offset, GptImage.EntrySize);

            Assert.Equal(Guid.Parse(LinuxType), new Guid(entry.Slice(0, 16)));
            Assert.Equal(expectedUuids[index], new Guid(entry.Slice(16, 16)));
            Assert.Equal(expectedStarts[index], BinaryPrimitives.ReadInt64LittleEndian(entry.Slice(32, 8)));
            Assert.Equal(
                expectedStarts[index] + expectedCounts[index] - 1,
                BinaryPrimitives.ReadInt64LittleEndian(entry.Slice(40, 8)));
            Assert.Equal(0UL, BinaryPrimitives.ReadUInt64LittleEndian(entry.Slice(48, 8)));
            Assert.Equal(expectedNames[index], DecodeName(entry));
        }

        // The post-GPT pair is the complete capture with only the four planned regions overlaid, and the parser
        // accepts it as the planned table.
        var postPrimary = Field<byte[]>(rewrite, "PostPrimaryFragment");
        var postBackup = Field<byte[]>(rewrite, "PostBackupFragment");
        var postTable = Field<GptTable>(rewrite, "PostTable");

        Assert.Equal(head.Length, postPrimary.Length);
        Assert.Equal(tail.Length, postBackup.Length);
        AssertRegionPreserved(head, postPrimary, image.PrimaryHeaderOffset, sectorSize, image.PrimaryArrayOffset, arrayLength);
        AssertRegionPreserved(tail, postBackup, image.BackupHeaderOffset, sectorSize, image.BackupArrayOffset, arrayLength);

        // The protective MBR and both slack bytes survive, and the header slack inside the sector is kept.
        Assert.True(head.AsSpan(446, 66).SequenceEqual(postPrimary.AsSpan(446, 66)));
        Assert.Equal((byte)0xA5, postPrimary[(2 * sectorSize) + image.ArrayBytes + 10]);
        Assert.Equal((byte)0xA6, postPrimary[image.PrimaryHeaderOffset + 100]);
        Assert.Equal((byte)0xA6, primaryHeader[100]);

        Assert.Equal(table.Partitions.Count + 3, postTable.Partitions.Count);
        Assert.Equal(userdata.Number, Partition(postTable, "userdata").Number);
        Assert.Equal(allocation.AndroidSectorCount, Partition(postTable, "userdata").SectorCount);
        Assert.Equal(userdata.PartUuid, Partition(postTable, "userdata").PartUuid);
        Assert.Equal(userdata.StartSector, Partition(postTable, "userdata").StartSector);
        Assert.Equal(userdata.Attributes, Partition(postTable, "userdata").Attributes);

        foreach (var name in expectedNames)
        {
            Assert.NotNull(Partition(postTable, name));
        }

        // The UUIDs are fresh: distinct from each other and from every UUID the original table already carried.
        var existing = new HashSet<string>(table.Partitions.Select(p => p.PartUuid), StringComparer.OrdinalIgnoreCase);
        Assert.Equal(3, new[] { bootUuid, rootUuid, backupUuid }.Distinct().Count());
        foreach (var uuid in expectedUuids)
        {
            Assert.NotEqual(Guid.Empty, uuid);
            Assert.False(existing.Contains(uuid.ToString("D")));
        }

        var linuxBoot = Field<GptPartition>(rewrite, "LinuxBoot");
        var linuxRoot = Field<GptPartition>(rewrite, "LinuxRoot");
        var backupTail = Field<GptPartition>(rewrite, "BackupPartition");
        Assert.Equal(bootUuid, Guid.Parse(linuxBoot.PartUuid));
        Assert.Equal(rootUuid, Guid.Parse(linuxRoot.PartUuid));
        Assert.Equal(backupUuid, Guid.Parse(backupTail.PartUuid));
        Assert.Equal(0UL, linuxBoot.Attributes);
    }

    [Theory]
    [InlineData("ARMADA_BOOT")]
    [InlineData("ARMADA_ROOT")]
    [InlineData("ARMADA_BACKUP")]
    public void BuildGptRewrite_RejectsATableThatAlreadyOwnsAnArmadaLabel(string label)
    {
        var image = RewriteImage(SectorSize4096, extraPartitionName: label);
        var head = image.BuildPrimaryFragment();
        var tail = image.BuildBackupFragment();
        var table = OriginalGptImporter.Parse(head, tail, SectorSize4096, image.DiskBytes);
        var allocation = Plan(table, Partition(table, "userdata"), SectorSize4096, image.FirstUsableSector);

        var exception = Record.Exception(() => Invoke(
            "BuildGptRewrite",
            head,
            tail,
            SectorSize4096,
            image.DiskBytes,
            table,
            allocation,
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid()));

        Assert.IsType<InvalidDataException>(exception);
    }

    [Fact]
    public void BuildGptRewrite_RejectsATableWithFewerThanThreeFreeSlots()
    {
        var image = FullTableImage();
        var head = image.BuildPrimaryFragment();
        var tail = image.BuildBackupFragment();
        var table = OriginalGptImporter.Parse(head, tail, SectorSize4096, image.DiskBytes);
        var allocation = Plan(table, Partition(table, "userdata"), SectorSize4096, image.FirstUsableSector);

        var exception = Record.Exception(() => Invoke(
            "BuildGptRewrite",
            head,
            tail,
            SectorSize4096,
            image.DiskBytes,
            table,
            allocation,
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid()));

        Assert.IsType<InvalidDataException>(exception);
    }

    [Theory]
    [InlineData("corrupt-crc")]
    [InlineData("fingerprint")]
    public void ReadAndValidateOriginal_RejectsCorruptBytesAndAForeignFingerprint(string defect)
    {
        var image = RewriteImage(SectorSize4096);
        var head = image.BuildPrimaryFragment();
        var tail = image.BuildBackupFragment();
        var table = OriginalGptImporter.Parse(head, tail, SectorSize4096, image.DiskBytes);

        if (defect == "corrupt-crc")
        {
            // One flipped bit in the stored header CRC leaves every field legal but the bytes untrustworthy.
            head[image.PrimaryHeaderOffset + GptBytes.HeaderCrcOffset] ^= 0x1;
        }

        var expected = defect == "fingerprint" ? new string('0', 64) : table.SourceFingerprint;

        var exception = Record.Exception(() => Invoke(
            "ReadAndValidateOriginal", head, tail, SectorSize4096, image.DiskBytes, expected));

        Assert.IsType<InvalidDataException>(exception);
        Assert.Equal(table.SourceFingerprint, Invoke(
            "ReadAndValidateOriginal", image.BuildPrimaryFragment(), image.BuildBackupFragment(),
            SectorSize4096, image.DiskBytes, table.SourceFingerprint) is GptTable parsed
            ? parsed.SourceFingerprint
            : null);
    }

    // ------------------------------------------------------------- captured inputs

    [Fact]
    public void VerifyCapturedInputs_AcceptsTheCompleteRequiredSet()
    {
        using var fixture = CapturedInstallFixture.Create();

        var verified = Invoke(
            "VerifyCapturedInputs", fixture.Files, fixture.Geometries, fixture.Tables, "TB322FC",
            CancellationToken.None)!;

        var roles = ((IEnumerable)Member(verified, "Keys")!).Cast<string>().ToArray();
        Assert.Equal(RequiredRoles.Length, roles.Length);
        Assert.Equal(52, roles.Length);
        Assert.Equal(RequiredRoles.OrderBy(r => r, StringComparer.Ordinal), roles.OrderBy(r => r, StringComparer.Ordinal));
    }

    [Fact]
    public void VerifyCapturedInputs_RejectsAPayloadChangedAfterTheBackupVerifiedIt()
    {
        using var fixture = CapturedInstallFixture.Create();
        var region = fixture.Files["boot_a"];

        // Rewrite the capture with different bytes of the same length: only the recorded SHA-256 can catch this.
        var tampered = new byte[region.Length];
        for (var index = 0; index < tampered.Length; index++)
        {
            tampered[index] = (byte)(index * 7 + 3);
        }

        File.WriteAllBytes(region.FilePath, tampered);

        var exception = Record.Exception(() => Invoke(
            "VerifyCapturedInputs", fixture.Files, fixture.Geometries, fixture.Tables, "TB322FC",
            CancellationToken.None));

        Assert.IsType<InvalidDataException>(exception);
    }

    [Fact]
    public void VerifyCapturedInputs_SelectsTheRequiredRolesFromTheModel()
    {
        using var fixture = CapturedInstallFixture.Create(gen5: true);

        var verified = Invoke(
            "VerifyCapturedInputs", fixture.Files, fixture.Geometries, fixture.Tables, fixture.Model,
            CancellationToken.None)!;

        var roles = ((IEnumerable)Member(verified, "Keys")!).Cast<string>().ToArray();
        Assert.Equal(48, roles.Length);
        Assert.All(G4OnlyRoles, role => Assert.DoesNotContain(role, roles));

        // The same 48 G5 captures cannot satisfy the G4 contract, which still demands the four G4-only labels.
        var exception = Record.Exception(() => Invoke(
            "VerifyCapturedInputs", fixture.Files, fixture.Geometries, fixture.Tables, "TB322FC",
            CancellationToken.None));

        Assert.IsType<InvalidDataException>(exception);
    }

    [Fact]
    public void VerifyFileHash_RejectsAPcManifestChangedAfterTheBackupVerifiedIt()
    {
        using var fixture = CapturedInstallFixture.Create();

        File.WriteAllText(fixture.ManifestPath, "{\"schemaVersion\":1,\"kind\":\"tampered\"}");

        var exception = Record.Exception(() => Invoke(
            "VerifyFileHash", fixture.ManifestPath, fixture.ManifestSha256, "the backup manifest", CancellationToken.None));

        Assert.IsType<InvalidDataException>(exception);
    }

    [Fact]
    public void OpenVerifiedPayload_RefusesASourceThatChangedAfterTheFirstHash()
    {
        var work = CreateWorkRoot();
        var path = Path.Combine(work, "payload.bin");

        var original = Encoding.ASCII.GetBytes("armada-payload-v1");
        File.WriteAllBytes(path, original);
        var recordedSha = Sha256Hex(original);

        var changed = Encoding.ASCII.GetBytes("armada-payload-v2");
        File.WriteAllBytes(path, changed);

        using var stream = (Stream)Invoke("OpenVerifiedPayload", path, (long)changed.Length, recordedSha)!;

        var exception = Record.Exception(() =>
        {
            var buffer = new byte[64];
            while (stream.Read(buffer, 0, buffer.Length) > 0)
            {
            }
        });

        Assert.IsType<InvalidDataException>(exception);
    }

    // --------------------------------------------------------------- artifact set

    [Fact]
    public void InternalArtifactSet_DisposeReleasesOnlyItsOwnLocksAndKeepsEveryFile()
    {
        var work = CreateWorkRoot();
        var path = Path.Combine(work, "gpt-primary-header.bin");
        var bytes = Encoding.ASCII.GetBytes("planned-gpt-header");

        var stream = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read);
        stream.Write(bytes, 0, bytes.Length);
        stream.Flush(flushToDisk: true);

        var set = CreateArtifactSet(work, stream, path);

        var locked = Record.Exception(() => new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None).Dispose());
        Assert.IsAssignableFrom<IOException>(locked);

        set.Dispose();

        Assert.True(File.Exists(path));
        Assert.Equal(bytes, File.ReadAllBytes(path));
        Assert.Null(Record.Exception(() => set.Dispose()));

        using var reopened = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None);
        Assert.Equal(bytes.Length, reopened.Length);
    }

    // ---------------------------------------------------------------- integration

    [Fact]
    public async Task PrepareAsync_WritesTheExactTwoGiBArchiveAndEveryVerifiedArtifact()
    {
        using var fixture = CapturedInstallFixture.Create();
        var backup = fixture.CreateBackupSet();
        var artifacts = await InternalInstallArtifacts.PrepareAsync(
            backup, 16, Storage(), fixture.RootPath, CancellationToken.None);

        try
        {
            Assert.True(Directory.Exists(artifacts.DirectoryPath));
            Assert.StartsWith(fixture.RootPath, artifacts.DirectoryPath, StringComparison.Ordinal);

            // Four explicit write regions, in write order, and never the 64 sector captures.
            Assert.Equal(4, artifacts.GptWriteRegions.Count);
            Assert.Equal(
                new[] { "backup-array", "backup-header", "primary-array", "primary-header" },
                artifacts.GptWriteRegions.Select(region => region.Role));
            Assert.All(artifacts.GptWriteRegions, region => Assert.Equal(0, region.Lun));
            Assert.All(artifacts.GptWriteRegions, region => Assert.True(File.Exists(region.FilePath)));
            Assert.All(
                artifacts.GptWriteRegions,
                region => Assert.Equal(Sha256Hex(File.ReadAllBytes(region.FilePath)), region.Sha256));

            // The post-GPT pair is metadata evidence, not part of the write list.
            Assert.DoesNotContain(artifacts.GptWriteRegions, region => region.Role.StartsWith("post-gpt", StringComparison.Ordinal));
            Assert.Equal(0, artifacts.PostGptPrimary.StartSector);
            Assert.Equal(
                fixture.Geometries[0].TotalSectors - (artifacts.PostGptPrimary.Length / SectorSize4096),
                artifacts.PostGptBackup.StartSector);
            Assert.Equal(Sha256Hex(File.ReadAllBytes(artifacts.PostGptPrimary.FilePath)), artifacts.PostGptPrimary.Sha256);
            Assert.Equal(Sha256Hex(File.ReadAllBytes(artifacts.PostGptBackup.FilePath)), artifacts.PostGptBackup.Sha256);

            // The expected table is parsed, not fabricated, and carries exactly three new entries.
            Assert.Equal(3, artifacts.PostGpt.Partitions.Count - fixture.Tables[0].Partitions.Count);
            Assert.Equal("ARMADA_BOOT", artifacts.LinuxBoot.Name);
            Assert.Equal("ARMADA_ROOT", artifacts.LinuxRoot.Name);
            Assert.Equal("ARMADA_BACKUP", artifacts.BackupPartition.Name);
            Assert.Equal(artifacts.BackupPartition.PartUuid, artifacts.PostGpt.Partitions
                .Single(p => p.Number == artifacts.BackupPartition.Number).PartUuid);
            Assert.Equal(0UL, artifacts.LinuxBoot.Attributes);

            // The record's own bytes are the plan id; the record never names its own hash.
            Assert.Equal(Sha256Hex(File.ReadAllBytes(artifacts.InstallationRecordPath)), artifacts.PlanSha256);
            var record = JsonDocument.Parse(File.ReadAllBytes(artifacts.InstallationRecordPath));
            Assert.Equal(2, record.RootElement.GetProperty("schemaVersion").GetInt32());
            Assert.Equal("armada-internal-install", record.RootElement.GetProperty("kind").GetString());
            Assert.Equal("armada-gzip-ustar-v3", record.RootElement.GetProperty("boardFormat").GetString());
            Assert.Equal(0, record.RootElement.GetProperty("excludedRoles").GetArrayLength());
            Assert.Equal("prepared", record.RootElement.GetProperty("status").GetString());
            Assert.NotEqual("installed", record.RootElement.GetProperty("status").GetString());
            Assert.Equal(
                artifacts.InstallationId.ToString("D"),
                record.RootElement.GetProperty("installationId").GetString());
            Assert.Equal(fixture.ManifestSha256, record.RootElement.GetProperty("backupManifestSha256").GetString());
            Assert.Equal(
                fixture.Tables[0].SourceFingerprint,
                record.RootElement.GetProperty("originalLun0").GetProperty("sourceFingerprint").GetString());
            Assert.Equal(
                artifacts.Allocation.AndroidEndSectorExclusive - 1,
                record.RootElement.GetProperty("allocation").GetProperty("originalUserdata").GetProperty("startSector").GetInt64()
                    + record.RootElement.GetProperty("allocation").GetProperty("androidSectorCount").GetInt64() - 1);
            Assert.DoesNotContain("planSha256", record.RootElement.EnumerateObject().Select(p => p.Name));
            Assert.DoesNotContain("summaryManifestSha256", record.RootElement.EnumerateObject().Select(p => p.Name));

            var newPartitions = record.RootElement.GetProperty("newPartitions").EnumerateArray().ToArray();
            Assert.Equal(3, newPartitions.Length);
            Assert.Equal(
                new[] { "ARMADA_BOOT", "ARMADA_ROOT", "ARMADA_BACKUP" },
                newPartitions.Select(p => p.GetProperty("name").GetString()));
            Assert.Equal(LinuxType, newPartitions[0].GetProperty("typeGuid").GetString());
            Assert.Equal(3, newPartitions.Select(p => p.GetProperty("partUuid").GetString()).Distinct().Count());
            var existingUuids = new HashSet<string>(
                fixture.Tables[0].Partitions.Select(p => p.PartUuid), StringComparer.OrdinalIgnoreCase);
            foreach (var partition in newPartitions)
            {
                Assert.False(existingUuids.Contains(partition.GetProperty("partUuid").GetString()!));
                Assert.Equal(0, partition.GetProperty("attributes").GetInt32());
            }

            // The image is exactly 2 GiB and its first 64 KiB is the schema 2 outer header.
            var archivePath = artifacts.BoardSummary.FilePath;
            Assert.Equal("board-recovery.img", Path.GetFileName(archivePath));
            Assert.Equal(TwoGiB, new FileInfo(archivePath).Length);
            Assert.Equal(TwoGiB, artifacts.BoardSummary.Length);
            Assert.Equal(Sha256FileHex(archivePath), artifacts.BoardSummary.Sha256);
            Assert.Equal(artifacts.Allocation.BackupStartSector, artifacts.BoardSummary.StartSector);
            Assert.Equal(artifacts.Allocation.BackupSectorCount, artifacts.BoardSummary.SectorCount);

            byte[] headerBytes;
            byte[] compressed;
            byte[] manifestBytes;
            long compressedBytes;
            long uncompressedTarBytes;
            string compressedSha256;

            using (var image = new FileStream(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                Assert.Equal(TwoGiB, image.Length);
                headerBytes = new byte[ManifestBytes];
                ReadExactly(image, headerBytes, 0, headerBytes.Length);

                using var header = JsonDocument.Parse(headerBytes);
                var outer = header.RootElement;
                Assert.Equal(3, outer.GetProperty("schemaVersion").GetInt32());
                Assert.Equal("armada-board-recovery-image", outer.GetProperty("kind").GetString());
                Assert.Equal(TwoGiB, outer.GetProperty("imageBytes").GetInt64());
                Assert.Equal(ManifestBytes, outer.GetProperty("headerBytes").GetInt64());
                Assert.Equal(ManifestBytes, outer.GetProperty("payloadOffset").GetInt64());
                Assert.Equal("gzip", outer.GetProperty("compression").GetString());
                Assert.Equal("ustar", outer.GetProperty("tarFormat").GetString());
                compressedBytes = outer.GetProperty("compressedBytes").GetInt64();
                Assert.InRange(compressedBytes, 1, TwoGiB - ManifestBytes);
                uncompressedTarBytes = outer.GetProperty("uncompressedTarBytes").GetInt64();
                Assert.Equal(artifacts.InstallationId.ToString("D"), outer.GetProperty("installationId").GetString());
                Assert.Equal(artifacts.PlanSha256, outer.GetProperty("planSha256").GetString());
                compressedSha256 = outer.GetProperty("compressedSha256").GetString()!;
                Assert.Equal(Sha256RangeHex(image, ManifestBytes, compressedBytes), compressedSha256);

                compressed = new byte[checked((int)compressedBytes)];
                image.Position = ManifestBytes;
                ReadExactly(image, compressed, 0, compressed.Length);

                // Only the small synthetic member is ever held; the 2 GiB padding is sampled at both edges.
                image.Position = ManifestBytes + compressedBytes;
                var paddingLead = new byte[ManifestBytes];
                ReadExactly(image, paddingLead, 0, paddingLead.Length);
                Assert.All(paddingLead, value => Assert.Equal(0, value));
                image.Position = TwoGiB - ManifestBytes;
                var paddingTail = new byte[ManifestBytes];
                ReadExactly(image, paddingTail, 0, paddingTail.Length);

                Assert.Equal("KSCFGV3\0"u8.ToArray(), paddingTail[..8]);
                Assert.Equal(Guid.Parse(artifacts.BackupPartition.PartUuid).ToByteArray(bigEndian: true),
                    paddingTail[48..64]);
                Assert.Equal(artifacts.InstallationId.ToByteArray(bigEndian: true), paddingTail[64..80]);
                Assert.Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(paddingTail.AsSpan(88)));
                Assert.Equal(GptBytes.Crc32(paddingTail, 0, 4092),
                    BinaryPrimitives.ReadUInt32LittleEndian(paddingTail.AsSpan(4092)));
                Assert.All(paddingTail[4096..], value => Assert.Equal(0, value));

                // Independent bounded decompression through the standard gzip and tar readers.
                using var gzip = new GZipStream(new MemoryStream(compressed, writable: false), CompressionMode.Decompress);
                using var tar = new TarReader(gzip, leaveOpen: true);

                var manifestEntry = tar.GetNextEntry()!;
                Assert.Equal("armada-recovery-manifest.json", manifestEntry.Name);
                Assert.Equal(TarEntryType.RegularFile, manifestEntry.EntryType);
                Assert.Equal(ManifestBytes, manifestEntry.Length);
                manifestBytes = ReadEntry(manifestEntry, ManifestBytes);
                Assert.Equal(Sha256Hex(manifestBytes), outer.GetProperty("recoveryManifestSha256").GetString());

                using var manifest = JsonDocument.Parse(manifestBytes);
                var inner = manifest.RootElement;
                Assert.Equal(2, inner.GetProperty("schemaVersion").GetInt32());
                Assert.Equal("armada-board-recovery", inner.GetProperty("kind").GetString());
                Assert.Equal("uncompressed-tar", inner.GetProperty("offsetSpace").GetString());
                Assert.Equal(artifacts.InstallationId.ToString("D"), inner.GetProperty("installationId").GetString());
                Assert.Equal(artifacts.PlanSha256, inner.GetProperty("planSha256").GetString());
                Assert.Equal(0, inner.GetProperty("excludedRoles").GetArrayLength());
                Assert.Equal(fixture.ManifestSha256, inner.GetProperty("pcBackupManifestSha256").GetString());
                Assert.Equal(
                    artifacts.PostGpt.SourceFingerprint,
                    inner.GetProperty("postGptSourceFingerprint").GetString());

                var ownedUuids = inner.GetProperty("ownedPartitionUuids").EnumerateArray()
                    .Select(value => value.GetString()).ToArray();
                Assert.Equal(3, ownedUuids.Length);
                Assert.Equal(artifacts.LinuxBoot.PartUuid, ownedUuids[0]);
                Assert.Equal(artifacts.LinuxRoot.PartUuid, ownedUuids[1]);
                Assert.Equal(artifacts.BackupPartition.PartUuid, ownedUuids[2]);

                var entries = inner.GetProperty("entries").EnumerateArray().ToArray();
                Assert.Equal(BoardRoles.Length + 4, entries.Length);
                Assert.Equal(55, entries.Length);

                long cursor = Block + ManifestBytes;
                var seenRoles = new HashSet<string>(StringComparer.Ordinal);
                for (var index = 0; index < entries.Length; index++)
                {
                    var declared = entries[index];
                    var role = declared.GetProperty("role").GetString()!;
                    var path = declared.GetProperty("path").GetString()!;
                    var length = declared.GetProperty("length").GetInt64();

                    Assert.True(seenRoles.Add(role));
                    Assert.Equal(cursor, declared.GetProperty("tarHeaderOffset").GetInt64());
                    Assert.Equal(cursor + Block, declared.GetProperty("dataOffset").GetInt64());

                    var entry = tar.GetNextEntry()!;
                    Assert.Equal(path, entry.Name);
                    Assert.Equal(TarEntryType.RegularFile, entry.EntryType);
                    Assert.Equal(length, entry.Length);

                    var payload = ReadEntry(entry, length);
                    Assert.Equal(length, payload.LongLength);
                    Assert.Equal(declared.GetProperty("sha256").GetString(), Sha256Hex(payload));

                    if (index < BoardRoles.Length)
                    {
                        Assert.Equal(role + ".bin", path);
                        var capture = fixture.Files[role];
                        Assert.Equal(capture.Length, payload.LongLength);
                        Assert.Equal(capture.Sha256, Sha256Hex(payload));
                        Assert.Equal(File.ReadAllBytes(capture.FilePath), payload);
                    }
                    else
                    {
                        switch (role)
                        {
                            case "pc-backup-manifest":
                                Assert.Equal("pc-backup-manifest.json", path);
                                Assert.Equal(File.ReadAllBytes(fixture.ManifestPath), payload);
                                Assert.Equal(fixture.ManifestSha256, Sha256Hex(payload));
                                break;
                            case "post-gpt-primary":
                                Assert.Equal("post-gpt-primary.bin", path);
                                Assert.Equal(File.ReadAllBytes(artifacts.PostGptPrimary.FilePath), payload);
                                break;
                            case "post-gpt-backup":
                                Assert.Equal("post-gpt-backup.bin", path);
                                Assert.Equal(File.ReadAllBytes(artifacts.PostGptBackup.FilePath), payload);
                                break;
                            default:
                                Assert.Equal("installation-record", role);
                                Assert.Equal("installation-record.json", path);
                                Assert.Equal(File.ReadAllBytes(artifacts.InstallationRecordPath), payload);
                                Assert.Equal(artifacts.PlanSha256, Sha256Hex(payload));
                                break;
                        }
                    }

                    cursor += Block + Align(length);
                }

                Assert.Equal(55, seenRoles.Count);
                Assert.DoesNotContain("metadata", seenRoles);
                Assert.Equal(fixture.Files["metadata"].Sha256, Sha256FileHex(fixture.Files["metadata"].FilePath), ignoreCase: true);
                Assert.Equal(
                    BoardRoles.OrderBy(role => role, StringComparer.Ordinal),
                    entries.Take(BoardRoles.Length).Select(e => e.GetProperty("role").GetString()));
                foreach (var role in FormerlyExcludedRoles)
                {
                    Assert.Contains(role, seenRoles);
                }

                foreach (var role in AddedRoles)
                {
                    Assert.Contains(role, seenRoles);
                }

                Assert.Equal(cursor + 1_024L, uncompressedTarBytes);
                Assert.Null(tar.GetNextEntry());

                var drained = new byte[2_048];
                int trailing;
                while ((trailing = gzip.Read(drained, 0, drained.Length)) > 0)
                {
                    Assert.All(drained.Take(trailing), value => Assert.Equal(0, value));
                }

                // The frozen internal contract returns the validated manifest as a detached clone.
                image.Position = 0;
                var verified = (JsonElement)Invoke(
                    "VerifyBoardArchive", image, "TB322FC", CancellationToken.None)!;
                Assert.Equal(2, verified.GetProperty("schemaVersion").GetInt32());
                Assert.Equal(55, verified.GetProperty("entries").GetArrayLength());
                Assert.Equal("uncompressed-tar", verified.GetProperty("offsetSpace").GetString());
            }

            // The summary manifest names the archive and the recovery manifest, and is itself hashed.
            var summary = JsonDocument.Parse(File.ReadAllBytes(artifacts.SummaryManifestPath));
            Assert.Equal(
                Sha256Hex(File.ReadAllBytes(artifacts.SummaryManifestPath)),
                artifacts.SummaryManifestSha256);
            Assert.Equal(2, summary.RootElement.GetProperty("schemaVersion").GetInt32());
            Assert.Equal("armada-install-artifacts", summary.RootElement.GetProperty("kind").GetString());
            Assert.Equal("armada-gzip-ustar-v3", summary.RootElement.GetProperty("boardFormat").GetString());
            Assert.Equal(artifacts.PlanSha256, summary.RootElement.GetProperty("planSha256").GetString());
            Assert.Equal(0, summary.RootElement.GetProperty("excludedRoles").GetArrayLength());

            var boardArchive = summary.RootElement.GetProperty("boardArchive");
            Assert.Equal("board-recovery.img", boardArchive.GetProperty("fileName").GetString());
            Assert.Equal("armada-gzip-ustar-v3", boardArchive.GetProperty("format").GetString());
            Assert.Equal(ManifestBytes, boardArchive.GetProperty("payloadOffset").GetInt64());
            Assert.Equal(compressedBytes, boardArchive.GetProperty("compressedBytes").GetInt64());
            Assert.Equal(compressedSha256, boardArchive.GetProperty("compressedSha256").GetString());
            Assert.Equal(uncompressedTarBytes, boardArchive.GetProperty("uncompressedTarBytes").GetInt64());
            Assert.Equal(ManifestBytes + compressedBytes, artifacts.SummaryUsedBytes);
            Assert.Equal(artifacts.SummaryUsedBytes, boardArchive.GetProperty("usedBytes").GetInt64());
            Assert.Equal(TwoGiB, boardArchive.GetProperty("length").GetInt64());
            Assert.Equal(artifacts.BoardSummary.Sha256, boardArchive.GetProperty("sha256").GetString());
            Assert.Equal(ManifestBytes, summary.RootElement.GetProperty("recoveryManifest").GetProperty("length").GetInt32());
            Assert.Equal(
                Sha256Hex(manifestBytes),
                summary.RootElement.GetProperty("recoveryManifest").GetProperty("sha256").GetString());

            // Every one of the nine outputs is held with a genuinely read-only handle: a consumer opening
            // Read/ShareRead, exactly as the shipped consumers do, is accepted while the set is still alive.
            var heldOutputs = artifacts.GptWriteRegions
                .Select(region => region.FilePath)
                .Concat(new[]
                {
                    artifacts.PostGptPrimary.FilePath,
                    artifacts.PostGptBackup.FilePath,
                    artifacts.InstallationRecordPath,
                    artifacts.BoardSummary.FilePath,
                    artifacts.SummaryManifestPath,
                })
                .ToArray();
            Assert.Equal(9, heldOutputs.Length);
            Assert.Equal(9, heldOutputs.Distinct(StringComparer.OrdinalIgnoreCase).Count());
            foreach (var heldOutput in heldOutputs)
            {
                using var heldReader = new FileStream(heldOutput, FileMode.Open, FileAccess.Read, FileShare.Read);
                Assert.True(heldReader.CanRead);
                Assert.Equal(new FileInfo(heldOutput).Length, heldReader.Length);
                Assert.True(heldReader.ReadByte() >= 0);
            }

            // The set is read-locked while alive and disposal only releases locks.
            var locked = Record.Exception(() =>
                new FileStream(artifacts.PostGptPrimary.FilePath, FileMode.Open, FileAccess.Write, FileShare.None).Dispose());
            Assert.IsAssignableFrom<IOException>(locked);
        }
        finally
        {
            artifacts.Dispose();
        }

        // Files, metadata and the backup inputs all survive disposal untouched.
        Assert.True(File.Exists(artifacts.InstallationRecordPath));
        Assert.True(File.Exists(artifacts.BoardSummary.FilePath));
        Assert.True(File.Exists(artifacts.SummaryManifestPath));
        Assert.Equal(TwoGiB, new FileInfo(artifacts.BoardSummary.FilePath).Length);
        Assert.Equal(RequiredRoles.Length, fixture.Files.Count);
        Assert.True(File.Exists(fixture.ManifestPath));
        Assert.Null(Record.Exception(() => artifacts.Dispose()));

        foreach (var capture in fixture.Files.Values)
        {
            Assert.Equal(capture.Sha256, Sha256FileHex(capture.FilePath));
        }

        Assert.Equal(fixture.ManifestSha256, Sha256FileHex(fixture.ManifestPath));

        // Negative cases mutate only the small header/member window of the one positive image. No second 2 GiB
        // file is created and no 2 GiB padding scan runs: every case fails before the padding is reached.
        using (var image = new FileStream(
            artifacts.BoardSummary.FilePath, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
        {
            var originalHeader = new byte[ManifestBytes];
            image.Position = 0;
            ReadExactly(image, originalHeader, 0, originalHeader.Length);

            long memberBytes;
            using (var document = JsonDocument.Parse(originalHeader))
            {
                memberBytes = document.RootElement.GetProperty("compressedBytes").GetInt64();
            }

            var originalMember = new byte[checked((int)memberBytes)];
            image.Position = ManifestBytes;
            ReadExactly(image, originalMember, 0, originalMember.Length);

            void Apply(byte[] header, byte[]? member)
            {
                if (member is not null)
                {
                    image.Position = ManifestBytes;
                    image.Write(member, 0, member.Length);
                }

                image.Position = 0;
                image.Write(header, 0, header.Length);
                image.Flush(flushToDisk: true);
            }

            void Restore()
            {
                image.Position = ManifestBytes;
                image.Write(originalMember, 0, originalMember.Length);
                image.Position = 0;
                image.Write(originalHeader, 0, originalHeader.Length);
                image.Flush(flushToDisk: true);
            }

            InvalidDataException? Rejected()
            {
                image.Position = 0;
                return Record.Exception(() => Invoke(
                    "VerifyBoardArchive", image, "TB322FC", CancellationToken.None))
                    as InvalidDataException;
            }

            var crcBroken = (byte[])originalMember.Clone();
            crcBroken[^8] ^= 0x20;
            Apply(PatchBoardHeader(originalHeader, Sha256Hex(crcBroken)), crcBroken);
            Assert.NotNull(Rejected());
            Restore();

            var sizeBroken = (byte[])originalMember.Clone();
            sizeBroken[^1] ^= 0x20;
            Apply(PatchBoardHeader(originalHeader, Sha256Hex(sizeBroken)), sizeBroken);
            Assert.NotNull(Rejected());
            Restore();

            var truncated = originalMember.AsSpan(0, originalMember.Length - 8).ToArray();
            Apply(
                PatchBoardHeader(originalHeader, Sha256Hex(truncated), compressedBytes: truncated.Length),
                truncated);
            Assert.NotNull(Rejected());
            Restore();

            Apply(
                PatchBoardHeader(
                    originalHeader, string.Empty, compressedBytes: TwoGiB - ManifestBytes + 1),
                null);
            Assert.NotNull(Rejected());
            Restore();

            Apply(PatchBoardHeader(originalHeader, string.Empty, schemaVersion: 1), null);
            Assert.NotNull(Rejected());
            Restore();

            // Settings and torn writes affect neither the compressed backup nor its recovery validation.
            var originalTail = new byte[ManifestBytes];
            image.Position = TwoGiB - ManifestBytes;
            ReadExactly(image, originalTail, 0, originalTail.Length);
            var mutableTail = (byte[])originalTail.Clone();
            Array.Fill(mutableTail, (byte)0x5a, 4096, 8192);
            void Tail(byte[] bytes) {
                image.Position = TwoGiB - ManifestBytes;
                image.Write(bytes);
                image.Flush(flushToDisk: true);
            }
            Tail(mutableTail);
            Assert.Null(Rejected());
            mutableTail[48] ^= 1;
            Tail(mutableTail);
            Assert.NotNull(Rejected());
            mutableTail[48] ^= 1;
            mutableTail[12288] = 1;
            Tail(mutableTail);
            Assert.NotNull(Rejected());
            Tail(originalTail);

            // Legacy v2 recovery remains readable, but it never authorizes a mutable tail.
            Apply(PatchBoardHeader(originalHeader, Sha256Hex(originalMember), schemaVersion: 2), null);
            Tail(new byte[ManifestBytes]);
            Assert.Null(Rejected());
            Guid backupPartition;
            using (var document = JsonDocument.Parse(originalHeader))
                backupPartition = Guid.Parse(document.RootElement.GetProperty("configPartitionUuid").GetString()!);
            // Preparing an upgrade is read-only, validates the complete legacy archive,
            // and binds the patch to the partition identity supplied by the caller.
            Assert.Throws<InvalidDataException>(() =>
                BootSettingsUpgrade.Prepare(image, "TB322FC", Guid.NewGuid(), CancellationToken.None));
            var upgrade = BootSettingsUpgrade.Prepare(image, "TB322FC", backupPartition, CancellationToken.None);
            Assert.Equal(ManifestBytes, upgrade.BeforeHeader.Length);
            Assert.Equal(ManifestBytes, upgrade.AfterHeader.Length);
            Assert.Equal(new byte[ManifestBytes], upgrade.BeforeTail);
            image.Position = 0;
            var unchangedHeader = new byte[ManifestBytes];
            ReadExactly(image, unchangedHeader, 0, unchangedHeader.Length);
            Assert.Equal(upgrade.BeforeHeader, unchangedHeader);
            Assert.Equal(Sha256Hex(originalMember), upgrade.CompressedSha256);
            Assert.Equal(backupPartition, upgrade.PartitionUuid);
            Assert.Equal(TwoGiB - ManifestBytes, upgrade.TailOffset);
            Apply(upgrade.AfterHeader, null);
            Tail(upgrade.AfterTail);
            Assert.Null(Rejected());
            image.Position = ManifestBytes;
            var unchangedMember = new byte[originalMember.Length];
            ReadExactly(image, unchangedMember, 0, unchangedMember.Length);
            Assert.Equal(originalMember, unchangedMember);
            Assert.Throws<InvalidDataException>(() =>
                BootSettingsUpgrade.Prepare(image, "TB322FC", backupPartition, CancellationToken.None));
            // Original header and tail are sufficient to restore the exact old format.
            Apply(upgrade.BeforeHeader, null);
            Tail(upgrade.BeforeTail);
            Assert.Null(Rejected());
            Tail(originalTail);
            Assert.NotNull(Rejected());
            Assert.Throws<InvalidDataException>(() =>
                BootSettingsUpgrade.Prepare(image, "TB322FC", backupPartition, CancellationToken.None));
            Restore();
            using var shortImage = new MemoryStream(new byte[1_024], writable: false);
            Assert.IsType<InvalidDataException>(Record.Exception(() =>
                Invoke("VerifyBoardArchive", shortImage, "TB322FC", CancellationToken.None)));
        }
    }

    [Fact]
    public async Task PrepareAsync_WritesTheTwoGiBArchiveForTheFortyEightFileGen5Set()
    {
        using var fixture = CapturedInstallFixture.Create(gen5: true);

        // The uninitialised synthetic set owns no locks of its own; only the produced artifact set is disposed.
        var backup = fixture.CreateBackupSet();
        var artifacts = await InternalInstallArtifacts.PrepareAsync(
            backup, 16, Storage(), fixture.RootPath, CancellationToken.None);

        try
        {
            var archivePath = artifacts.BoardSummary.FilePath;
            Assert.Equal("board-recovery.img", Path.GetFileName(archivePath));
            Assert.Equal(TwoGiB, new FileInfo(archivePath).Length);
            Assert.Equal(TwoGiB, artifacts.BoardSummary.Length);
            Assert.True(artifacts.SummaryUsedBytes < TwoGiB);
            Assert.Equal(Sha256FileHex(archivePath), artifacts.BoardSummary.Sha256);

            using var image = new FileStream(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var verified = (JsonElement)Invoke(
                "VerifyBoardArchive", image, fixture.Model, CancellationToken.None)!;

            Assert.Equal(2, verified.GetProperty("schemaVersion").GetInt32());

            var entries = verified.GetProperty("entries").EnumerateArray().ToArray();
            Assert.Equal(51, entries.Length);

            var names = entries.Select(EntryName).ToArray();

            // 48 captures plus the four metadata entries the archive adds on top of them.
            var filteredGen5Roles = Gen5Roles.Where(role => role != "metadata").ToArray();
            Assert.All(filteredGen5Roles, role => Assert.Contains(role, names));
            Assert.DoesNotContain("metadata", names);
            Assert.Equal(fixture.Files["metadata"].Sha256, Sha256FileHex(fixture.Files["metadata"].FilePath), ignoreCase: true);
            Assert.Equal(4, names.Except(filteredGen5Roles, StringComparer.Ordinal).Count());
            Assert.All(G4OnlyRoles, role => Assert.DoesNotContain(role, names));

            // The two boot slots keep their own distinct payload hashes all the way into the manifest.
            var bootHashes = new[] { "boot_a", "boot_b" }
                .Select(role => EntrySha256(entries.Single(entry => EntryName(entry) == role)))
                .ToArray();
            Assert.Equal(2, bootHashes.Distinct(StringComparer.OrdinalIgnoreCase).Count());
            foreach (var role in new[] { "boot_a", "boot_b" })
            {
                var entry = entries.Single(candidate => EntryName(candidate) == role);
                Assert.Equal(
                    Sha256FileHex(fixture.Files[role].FilePath),
                    EntrySha256(entry),
                    ignoreCase: true);
            }
        }
        finally
        {
            artifacts.Dispose();
        }

        static string EntryName(JsonElement entry) => entry.GetProperty("role").GetString()!;

        static string EntrySha256(JsonElement entry) => entry.GetProperty("sha256").GetString()!;
    }

    // ------------------------------------------------------------------- fixture

    /// <summary>
    /// The 52 payload fixture: six freshly parsed tables, 12 raw GPT captures and 40 one sector partition
    /// captures, all written below one unique directory under <c>EDL_CLIENT_TEST_WORK_ROOT</c>.
    /// </summary>
    private sealed class CapturedInstallFixture : IDisposable
    {
        private readonly bool _gen5;

        private CapturedInstallFixture(bool gen5)
        {
            _gen5 = gen5;
        }

        internal string RootPath { get; private set; } = string.Empty;

        internal string DirectoryPath { get; private set; } = string.Empty;

        internal string ManifestPath { get; private set; } = string.Empty;

        internal string ManifestSha256 { get; private set; } = string.Empty;

        internal Dictionary<int, EdlGeometry> Geometries { get; } = new Dictionary<int, EdlGeometry>();

        internal Dictionary<int, GptTable> Tables { get; } = new Dictionary<int, GptTable>();

        internal Dictionary<string, EdlCapturedRegion> Files { get; } =
            new Dictionary<string, EdlCapturedRegion>(StringComparer.Ordinal);

        internal string ProfileId => _gen5 ? "g5-9008-y7005" : "g4-9008-259";

        internal string Model => _gen5 ? "TB323FU" : "TB322FC";

        internal string AndroidBuild => _gen5
            ? "TB323FU_CN_OPEN_USER_Q00020.0_A16_ZUXOS_2.0.11.043_ST_260309"
            : "TB322FC_ROW_OPEN_USER_V1.259";

        internal string HardwareId => _gen5 ? "002B40E100400000" : "0x0000A100";

        internal static CapturedInstallFixture Create(bool gen5 = false)
        {
            var root = CreateWorkRoot();
            var fixture = new CapturedInstallFixture(gen5)
            {
                RootPath = root,
                DirectoryPath = Path.Combine(root, "backup"),
            };

            System.IO.Directory.CreateDirectory(fixture.DirectoryPath);

            var roles = gen5 ? Gen5Roles : RequiredRoles;

            var geometries = new (int Lun, int SectorSize, long TotalSectors)[]
            {
                (0, SectorSize4096, 134_217_728),
                (1, SectorSize512, 131_072),
                (2, SectorSize4096, 16_777_216),
                (3, SectorSize4096, 16_777_216),
                (4, SectorSize4096, 16_777_216),
                (5, SectorSize512, 8_388_608),
            };

            foreach (var geometry in geometries)
            {
                var reserved = geometry.SectorSize == SectorSize512 ? 34L : 6L;
                var specs = TableSpecs(geometry.Lun);
                if (gen5 && geometry.Lun == 0)
                {
                    specs = specs
                        .Where(spec => !G4OnlyRoles.Contains(spec.Name, StringComparer.Ordinal))
                        .ToArray();
                }

                var image = new GptImage(
                    geometry.SectorSize,
                    geometry.TotalSectors * geometry.SectorSize,
                    DeterministicGuid("disk:" + geometry.Lun),
                    reserved,
                    geometry.TotalSectors - reserved,
                    specs);

                var sectorSize = geometry.SectorSize;
                var rawHead = image.BuildPrimaryFragment();
                var rawTail = image.BuildBackupFragment();

                // The helper emits fixed 64 KiB windows, but the capture contract is exactly 64 sectors of this
                // geometry. Re-anchor the windows on the disk edges so every GPT byte offset stays valid.
                var targetLength = checked((int)(64 * (long)sectorSize));
                var headBytes = new byte[targetLength];
                Array.Copy(rawHead, 0, headBytes, 0, Math.Min(rawHead.Length, targetLength));

                var tailBytes = new byte[targetLength];
                var tailCopy = Math.Min(rawTail.Length, targetLength);
                Array.Copy(rawTail, rawTail.Length - tailCopy, tailBytes, targetLength - tailCopy, tailCopy);

                var headPath = Path.Combine(fixture.DirectoryPath, $"gpt_lun{geometry.Lun}_primary.bin");
                var tailPath = Path.Combine(fixture.DirectoryPath, $"gpt_lun{geometry.Lun}_backup.bin");
                File.WriteAllBytes(headPath, headBytes);
                File.WriteAllBytes(tailPath, tailBytes);

                fixture.Geometries.Add(geometry.Lun, new EdlGeometry(geometry.Lun, sectorSize, geometry.TotalSectors));
                fixture.Tables.Add(
                    geometry.Lun,
                    OriginalGptImporter.Parse(
                        headBytes,
                        tailBytes,
                        sectorSize,
                        geometry.TotalSectors * (long)sectorSize));

                fixture.Files.Add(
                    $"gpt_lun{geometry.Lun}_primary",
                    Capture("gpt_lun" + geometry.Lun + "_primary", geometry.Lun, 0, 64, sectorSize, null, headPath, headBytes));
                fixture.Files.Add(
                    $"gpt_lun{geometry.Lun}_backup",
                    Capture(
                        "gpt_lun" + geometry.Lun + "_backup",
                        geometry.Lun,
                        geometry.TotalSectors - 64,
                        64,
                        sectorSize,
                        null,
                        tailPath,
                        tailBytes));
            }

            foreach (var role in roles.Where(role => !role.StartsWith("gpt_lun", StringComparison.Ordinal)))
            {
                var lun = LunForRole(role);
                if (lun < 0)
                {
                    throw new InvalidOperationException($"fixture: no LUN is declared for the role '{role}'");
                }

                var table = fixture.Tables[lun];
                var partition = Partition(table, role);
                var sectorSize = fixture.Geometries[lun].SectorSize;
                var length = partition.SectorCount * sectorSize;

                var bytes = DeterministicBytes(role, (int)length);
                var path = Path.Combine(fixture.DirectoryPath, role + ".bin");
                File.WriteAllBytes(path, bytes);

                fixture.Files.Add(role, Capture(
                    role,
                    lun,
                    partition.StartSector,
                    partition.SectorCount,
                    sectorSize,
                    partition.PartUuid,
                    path,
                    bytes));
            }

            if (fixture.Files.Count != roles.Length)
            {
                throw new InvalidOperationException(
                    $"fixture: built {fixture.Files.Count} captures instead of {roles.Length}");
            }

            fixture.ManifestPath = Path.Combine(fixture.DirectoryPath, "backup-manifest.json");
            var manifest = Encoding.UTF8.GetBytes(
                "{\"schemaVersion\":1,\"kind\":\"armada-internal-backup\",\"profileId\":\"" + fixture.ProfileId
                + "\",\"files\":" + roles.Length + "}");
            File.WriteAllBytes(fixture.ManifestPath, manifest);
            fixture.ManifestSha256 = Sha256Hex(manifest);

            return fixture;
        }

        internal InternalBackupSet CreateBackupSet()
        {
            var set = (InternalBackupSet)RuntimeHelpers.GetUninitializedObject(typeof(InternalBackupSet));

            SetStoredValue(set, "DirectoryPath", DirectoryPath);
            SetStoredValue(set, "ManifestPath", ManifestPath);
            SetStoredValue(set, "ManifestSha256", ManifestSha256);
            SetStoredValue(set, "ProfileId", ProfileId);
            SetStoredValue(set, "Model", Model);
            SetStoredValue(set, "AndroidBuild", AndroidBuild);
            SetStoredValue(set, "HardwareId", HardwareId);
            SetStoredValue(set, "Geometries", (IReadOnlyDictionary<int, EdlGeometry>)Geometries);
            SetStoredValue(set, "Tables", (IReadOnlyDictionary<int, GptTable>)Tables);
            SetStoredValue(set, "Files", (IReadOnlyDictionary<string, EdlCapturedRegion>)Files);

            return set;
        }

        public void Dispose()
        {
            try
            {
                if (System.IO.Directory.Exists(RootPath))
                {
                    System.IO.Directory.Delete(RootPath, recursive: true);
                }
            }
            catch (IOException)
            {
                // A leftover work directory is diagnostic material, never a test failure.
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        private static EdlCapturedRegion Capture(
            string role,
            int lun,
            long startSector,
            long sectorCount,
            int sectorSize,
            string? partUuid,
            string path,
            byte[] bytes) =>
            new(role, lun, startSector, sectorCount, sectorSize, partUuid, path, bytes.LongLength, Sha256Hex(bytes));

        private static GptPartitionSpec[] TableSpecs(int lun)
        {
            switch (lun)
            {
                case 0:
                    return Lun0Specs();
                case 1:
                    return Lun1Specs();
                case 2:
                    return Lun2Specs();
                case 3:
                    return Lun3Specs();
                case 4:
                    return Lun4Specs();
                case 5:
                    return Lun5Specs();
                default:
                    throw new InvalidOperationException($"fixture: unknown LUN {lun}");
            }
        }

        private static int LunForRole(string role)
        {
            if (Lun0Roles.Contains(role, StringComparer.Ordinal))
            {
                return 0;
            }

            if (Lun1Roles.Contains(role, StringComparer.Ordinal))
            {
                return 1;
            }

            if (Lun2Roles.Contains(role, StringComparer.Ordinal))
            {
                return 2;
            }

            if (Lun3Roles.Contains(role, StringComparer.Ordinal))
            {
                return 3;
            }

            if (Lun4Roles.Contains(role, StringComparer.Ordinal))
            {
                return 4;
            }

            if (Lun5Roles.Contains(role, StringComparer.Ordinal))
            {
                return 5;
            }

            return -1;
        }

        private static GptPartitionSpec[] Lun1Specs() => new[]
        {
            Spec(1, "xbl_a", 100, 1),
            Spec(2, "xbl_config_a", 101, 1),
        };

        private static GptPartitionSpec[] Lun2Specs() => new[]
        {
            Spec(1, "xbl_b", 100, 1),
            Spec(2, "xbl_config_b", 101, 1),
        };

        private static GptPartitionSpec[] Lun3Specs() => new[]
        {
            Spec(1, "cdt", 100, 1),
        };

        private static GptPartitionSpec[] Lun0Specs()
        {
            var specs = new List<GptPartitionSpec>();
            var number = 1;
            foreach (var role in Lun0Roles)
            {
                specs.Add(Spec(number++, role, 6 + specs.Count, 1));
            }

            specs.Add(Spec(number++, "userdata", UserdataStart4096, UserdataCount4096, 0UL));

            // Vendor entries after userdata, each with the high attribute bits a real vendor partition carries.
            for (var index = 0; index < 15; index++)
            {
                specs.Add(Spec(
                    number++,
                    "vendor_" + index,
                    100_000_000 + (index * 8),
                    1,
                    (1UL << 60) | (1UL << 50) | 0x1UL));
            }

            return specs.ToArray();
        }

        private static GptPartitionSpec[] Lun4Specs()
        {
            var specs = new List<GptPartitionSpec>();
            var number = 1;
            foreach (var role in Lun4Roles)
            {
                specs.Add(Spec(number++, role, 1_000 + specs.Count, 1));
            }

            for (var index = 0; index < 5; index++)
            {
                specs.Add(Spec(number++, "lun4extra_" + index, 5_000 + index, 1, (1UL << 55) | 0x4UL));
            }

            return specs.ToArray();
        }

        private static GptPartitionSpec[] Lun5Specs()
        {
            var specs = new List<GptPartitionSpec>();
            var number = 1;
            foreach (var role in Lun5Roles)
            {
                specs.Add(Spec(number++, role, 100 + specs.Count, 1));
            }

            return specs.ToArray();
        }
    }

    // --------------------------------------------------------------- test helpers

    private static InternalArtifactSet CreateArtifactSet(string directory, FileStream stream, string path)
    {
        var setType = typeof(InternalArtifactSet);
        var stateType = setType.GetNestedType("State", BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("production type InternalArtifactSet.State is missing");

        var state = Activator.CreateInstance(stateType, nonPublic: true)
            ?? throw new InvalidOperationException("production type InternalArtifactSet.State has no usable constructor");

        stateType.GetField("DirectoryPath", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(state, directory);
        stateType.GetField("InstallationRecordPath", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(state, path);
        stateType.GetField("PlanSha256", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(state, "plan");
        stateType.GetField("InstallationId", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(state, Guid.NewGuid());

        var locks = (List<FileStream>)stateType
            .GetField("Locks", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(state)!;
        locks.Add(stream);

        var constructor = setType.GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic, null, new[] { stateType }, null)
            ?? throw new InvalidOperationException("production type InternalArtifactSet has no internal state constructor");

        return (InternalArtifactSet)constructor.Invoke(new[] { state });
    }

    private static void SetStoredValue(object target, string propertyName, object? value)
    {
        var type = target.GetType();
        var backing = "<" + propertyName + ">k__BackingField";
        var conventional = "_" + char.ToLowerInvariant(propertyName[0]) + propertyName.Substring(1);

        foreach (var name in new[] { conventional, backing, propertyName })
        {
            var field = type.GetField(name, BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
            if (field is not null)
            {
                field.SetValue(target, value);
                return;
            }
        }

        throw new InvalidOperationException(
            $"fixture: InternalBackupSet stores '{propertyName}' in no field this fixture knows "
            + $"('{conventional}' or '{backing}'). Adapt the fixture once IB002 provides the production backup metadata; "
            + "no test-only constructor or public fake factory is added to production.");
    }

    private static InternalBackupSet NewUnpopulatedBackupSet() =>
        (InternalBackupSet)RuntimeHelpers.GetUninitializedObject(typeof(InternalBackupSet));

    private static PackageStorage Storage() =>
        new(1L << 30, 8L << 30, 4L << 30, 1L << 30);

    private static object? Invoke(string name, params object?[] args)
    {
        var method = typeof(InternalInstallArtifacts).GetMethod(
            name, BindingFlags.NonPublic | BindingFlags.Static);

        if (method is null)
        {
            throw new MissingMethodException(
                $"production helper '{name}' is missing from InternalInstallArtifacts");
        }

        try
        {
            return method.Invoke(null, args);
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }
    }

    private static long InvokeLong(string name, params object?[] args) => (long)Invoke(name, args)!;

    private static object? Member(object target, string name)
    {
        var type = target.GetType();

        var property = type.GetProperty(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        if (property is not null)
        {
            return property.GetValue(target);
        }

        var field = type.GetField(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        if (field is not null)
        {
            return field.GetValue(target);
        }

        throw new InvalidOperationException($"production type {type.Name} has no member '{name}'");
    }

    private static T Field<T>(object target, string name) => (T)Member(target, name)!;

    private static List<object> Members(object target, string name) =>
        ((IEnumerable)Member(target, name)!).Cast<object>().ToList();

    private static string CreateWorkRoot()
    {
        var root = Environment.GetEnvironmentVariable("EDL_CLIENT_TEST_WORK_ROOT");

        if (string.IsNullOrWhiteSpace(root))
        {
            throw new InvalidOperationException(
                "fixture: EDL_CLIENT_TEST_WORK_ROOT must name the test work directory; "
                + "this suite never falls back to a temporary directory or a drive root.");
        }

        if (!Path.IsPathFullyQualified(root))
        {
            throw new InvalidOperationException(
                "fixture: EDL_CLIENT_TEST_WORK_ROOT must be an absolute path.");
        }

        Directory.CreateDirectory(root);

        var unique = Path.Combine(root, "ia001-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(unique);
        return unique;
    }

    private static GptImage RewriteImage(int sectorSize, string? extraPartitionName = null)
    {
        var diskBytes = 512L << 30;
        var totalSectors = diskBytes / sectorSize;
        var userdataStart = sectorSize == SectorSize4096 ? UserdataStart4096 : UserdataStart512;
        var userdataCount = sectorSize == SectorSize4096 ? UserdataCount4096 : UserdataCount512;

        // The 32 x 128 byte entry array is eight 512 byte sectors from LBA 2, so a 512 byte disk reserves the
        // first and last 34 sectors; a 4K disk keeps the classic six sector head and tail.
        var reserved = sectorSize == SectorSize512 ? 34L : 6L;
        var lastUsable = totalSectors - reserved;
        var vendorStart = sectorSize == SectorSize4096 ? 100_000_000L : 900_000_000L;

        var specs = new List<GptPartitionSpec>
        {
            Spec(1, "proinfo", reserved, 768),
            Spec(2, "userdata", userdataStart, userdataCount, 0UL),
        };

        // Plenty of vendor entries with the high attribute bits set: the rewrite must not move or reformat them.
        for (var index = 0; index < 20; index++)
        {
            specs.Add(Spec(
                3 + index,
                "vendor_" + index,
                vendorStart + (index * 8),
                1,
                (1UL << 60) | (1UL << 50) | 0x3UL));
        }

        if (extraPartitionName is not null)
        {
            specs.Add(Spec(30, extraPartitionName, vendorStart + 1_000_000L, 1));
        }

        return new GptImage(
            sectorSize,
            diskBytes,
            DeterministicGuid("disk:rewrite:" + sectorSize),
            reserved,
            lastUsable,
            specs.ToArray());
    }

    private static GptImage FullTableImage()
    {
        var specs = new List<GptPartitionSpec>();
        specs.Add(Spec(1, "userdata", UserdataStart4096, UserdataCount4096, 0UL));

        for (var index = 1; index < GptImage.EntryCount; index++)
        {
            specs.Add(Spec(
                index + 1,
                "vendor_" + index,
                100_000_000 + (index * 8),
                1,
                (1UL << 60) | 0x1UL));
        }

        return new GptImage(
            SectorSize4096,
            512L << 30,
            DeterministicGuid("disk:full"),
            6,
            134_217_722,
            specs.ToArray());
    }

    private static InternalAllocationPlan Plan(
        GptTable table, GptPartition userdata, int sectorSize, long firstUsableSector)
    {
        _ = firstUsableSector;

        var androidGiB = 16L;
        var androidBytes = androidGiB * OneGiB;
        var androidSectorCount = androidBytes / sectorSize;
        var androidEnd = userdata.StartSector + androidSectorCount;

        var alignment = sectorSize == SectorSize4096 ? 256L : 2_048L;
        var bootStart = AlignUp(androidEnd, alignment);
        var bootCount = 262_144L;
        var rootStart = bootStart + bootCount;
        var rootCount = 20_000_000L;
        var backupStart = AlignUp(rootStart + rootCount, alignment);
        var backupCount = TwoGiB / sectorSize;
        var backupEnd = backupStart + backupCount;

        var originalEnd = userdata.StartSector + userdata.SectorCount;
        if (backupEnd > originalEnd)
        {
            throw new InvalidOperationException("fixture: the synthetic plan does not fit the fixture userdata");
        }

        return new InternalAllocationPlan(
            userdata,
            sectorSize,
            originalEnd,
            androidBytes,
            androidSectorCount,
            androidEnd,
            (bootCount + rootCount) * sectorSize,
            bootCount * sectorSize,
            rootCount * sectorSize,
            (rootCount * sectorSize) - (8L << 30),
            bootStart,
            bootCount,
            rootStart,
            rootCount,
            TwoGiB,
            backupStart,
            backupCount,
            backupEnd,
            bootStart - androidEnd,
            originalEnd - backupEnd,
            ((bootStart - androidEnd) + (originalEnd - backupEnd)) * sectorSize);
    }

    private static GptPartitionSpec Spec(int number, string name, long start, long count, ulong attributes = 0UL) =>
        new GptPartitionSpec(
            number,
            name,
            DeterministicGuid("type:" + name),
            DeterministicGuid("uuid:" + name),
            start,
            count,
            attributes);

    private static GptPartition Partition(GptTable table, string name)
    {
        foreach (var partition in table.Partitions)
        {
            if (string.Equals(partition.Name, name, StringComparison.Ordinal))
            {
                return partition;
            }
        }

        throw new XunitException($"partition '{name}' is missing from a table of {table.Partitions.Count} entries");
    }

    private static string DeterministicGuid(string seed)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(seed));
        return new Guid(hash.AsSpan(0, 16)).ToString("D").ToUpperInvariant();
    }

    private static byte[] DeterministicBytes(string seed, int length)
    {
        var bytes = new byte[length];
        var state = 17u;
        foreach (var character in seed)
        {
            state = (state * 31u) + character;
        }

        for (var index = 0; index < length; index++)
        {
            state = (state * 1_664_525u) + 1_013_904_223u;
            bytes[index] = (byte)(state >> 16);
        }

        return bytes;
    }

    private static List<int> FreeSlots(byte[] array, int entryCount)
    {
        var slots = new List<int>();
        for (var index = 0; index < entryCount; index++)
        {
            var offset = index * GptImage.EntrySize;
            if (array.AsSpan(offset, 16).IndexOfAnyExcept((byte)0) < 0)
            {
                slots.Add(index);
            }
        }

        return slots;
    }

    private static string DecodeName(ReadOnlySpan<byte> entry)
    {
        var characters = new char[GptImage.NameFieldBytes / 2];
        var length = 0;
        for (var index = 0; index < characters.Length; index++)
        {
            var unit = BinaryPrimitives.ReadUInt16LittleEndian(entry.Slice(56 + (index * 2), 2));
            if (unit == 0)
            {
                break;
            }

            characters[length++] = (char)unit;
        }

        return new string(characters, 0, length);
    }

    private static void AssertRegionPreserved(
        byte[] original, byte[] rewritten, int headerOffset, int headerBytes, int arrayOffset, int arrayBytes)
    {
        Assert.Equal(original.Length, rewritten.Length);

        for (var index = 0; index < original.Length; index++)
        {
            var inHeader = index >= headerOffset && index < headerOffset + headerBytes;
            var inArray = index >= arrayOffset && index < arrayOffset + arrayBytes;
            if (inHeader || inArray)
            {
                continue;
            }

            if (original[index] != rewritten[index])
            {
                throw new XunitException(
                    $"byte {index} outside the four planned regions changed from {original[index]} to {rewritten[index]}");
            }
        }
    }

    private static long Align(long value) => (value + Block - 1) / Block * Block;

    private static long AlignUp(long value, long alignment) => (value + alignment - 1) / alignment * alignment;

    private static string Sha256Hex(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));

    /// <summary>Hashes a file of any size without ever holding its contents in memory.</summary>
    private static string Sha256FileHex(string path)
    {
        using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string Sha256RangeHex(FileStream stream, long offset, long length)
    {
        stream.Position = offset;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[64 * 1024];
        var remaining = length;
        while (remaining > 0)
        {
            var read = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
            if (read <= 0)
            {
                throw new XunitException("the compressed window ends before its declared length");
            }

            hash.AppendData(buffer, 0, read);
            remaining -= read;
        }

        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static void ReadExactly(Stream stream, byte[] buffer, int offset, int count)
    {
        while (count > 0)
        {
            var read = stream.Read(buffer, offset, count);
            if (read <= 0)
            {
                throw new XunitException("unexpected end of stream in the board image");
            }

            offset += read;
            count -= read;
        }
    }

    private static byte[] ReadEntry(TarEntry entry, long length)
    {
        if (length > int.MaxValue)
        {
            throw new XunitException($"entry '{entry.Name}' is too large for this fixture");
        }

        var bytes = new byte[(int)length];
        ReadExactly(entry.DataStream!, bytes, 0, bytes.Length);
        return bytes;
    }

    /// <summary>Rewrites only the small outer header of the sole image, keeping its padded 64 KiB slot.</summary>
    private static byte[] PatchBoardHeader(
        byte[] original,
        string compressedSha256,
        long? compressedBytes = null,
        int? schemaVersion = null)
    {
        using var document = JsonDocument.Parse(original);
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            foreach (var property in document.RootElement.EnumerateObject())
            {
                switch (property.Name)
                {
                    case "compressedSha256":
                        writer.WriteString(property.Name, compressedSha256);
                        break;
                    case "compressedBytes":
                        writer.WriteNumber(property.Name, compressedBytes ?? property.Value.GetInt64());
                        break;
                    case "schemaVersion":
                        writer.WriteNumber(property.Name, schemaVersion ?? property.Value.GetInt32());
                        break;
                    default:
                        property.WriteTo(writer);
                        break;
                }
            }

            writer.WriteEndObject();
        }

        var json = buffer.ToArray();
        var padded = new byte[ManifestBytes];
        Array.Fill(padded, (byte)' ');
        json.CopyTo(padded, 0);
        return padded;
    }

    private static string[] ContractRoles()
    {
        var roles = new List<string>(52);
        for (var lun = 0; lun < 6; lun++)
        {
            roles.Add("gpt_lun" + lun + "_primary");
            roles.Add("gpt_lun" + lun + "_backup");
        }

        roles.AddRange(Lun0Roles);
        roles.AddRange(Lun1Roles);
        roles.AddRange(Lun2Roles);
        roles.AddRange(Lun3Roles);
        roles.AddRange(Lun4Roles);
        roles.AddRange(Lun5Roles);
        return roles.ToArray();
    }
}
