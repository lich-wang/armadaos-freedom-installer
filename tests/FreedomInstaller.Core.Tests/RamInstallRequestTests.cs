using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Focused coverage for <see cref="RamInstallRequest"/>: exact contract field names and bytes,
/// 64-bit geometry arithmetic, a real clone of the table, fixed target labels and a validated seed.
/// </summary>
public sealed class RamInstallRequestTests
{
    [Fact]
    public void ValidRequest_UsesExactContractKeysAndHashesTheExactBytes()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        byte[] bytes = Rh002TestData.RequestBytes(request);

        Assert.Equal((byte)'{', bytes[0]);
        Assert.Equal(
            request.RequestSha256,
            Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant());

        using var document = JsonDocument.Parse(bytes);
        var root = document.RootElement;
        Assert.Equal(
            new[]
            {
                "schemaVersion", "model", "device", "expectedSocSerial", "expectedBootId",
                "userdataGiB", "originalUserdataEndSector", "bootPartUuid", "rootPartUuid",
                "backupPartUuid", "expectedTable", "seed",
            }.OrderBy(name => name, StringComparer.Ordinal),
            root.EnumerateObject().Select(property => property.Name)
                .OrderBy(name => name, StringComparer.Ordinal));

        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("TB322FC", root.GetProperty("model").GetString());
        Assert.Equal("/dev/sda", root.GetProperty("device").GetString());
        Assert.Equal(Rh002TestData.SocSerial, root.GetProperty("expectedSocSerial").GetString());
        Assert.Equal(Rh002TestData.BootId, root.GetProperty("expectedBootId").GetString());
        Assert.Equal(Rh002TestData.UserdataGiB, root.GetProperty("userdataGiB").GetInt32());

        Assert.Equal(
            new[] { "sectorSize", "diskBytes", "diskGuid", "partitions" }
                .OrderBy(name => name, StringComparer.Ordinal),
            root.GetProperty("expectedTable").EnumerateObject()
                .Select(property => property.Name)
                .OrderBy(name => name, StringComparer.Ordinal));

        Assert.Equal(
            new[] { "number", "name", "startSector", "sectorCount", "typeGuid", "partUuid" }
                .OrderBy(name => name, StringComparer.Ordinal),
            root.GetProperty("expectedTable").GetProperty("partitions")[0]
                .EnumerateObject()
                .Select(property => property.Name)
                .OrderBy(name => name, StringComparer.Ordinal));

        Assert.Equal(
            new[] { "length", "sha256", "commit", "manifestDigest", "origin" }
                .OrderBy(name => name, StringComparer.Ordinal),
            root.GetProperty("seed").EnumerateObject()
                .Select(property => property.Name)
                .OrderBy(name => name, StringComparer.Ordinal));

        string json = Encoding.UTF8.GetString(bytes);
        Assert.DoesNotContain("RequestSha256", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"requestSha256\"", json, StringComparison.Ordinal);
        Assert.Contains("\"seed\":{\"length\":", json, StringComparison.Ordinal);
        Assert.Contains("\"manifestDigest\":\"sha256:", json, StringComparison.Ordinal);
    }

    [Fact]
    public void SessionConstructor_CopiesTheProvenIdentity()
    {
        RamInstallSession session = Rh002TestData.CreateSession(new Rh002NoopConsole());
        var request = new RamInstallRequest(
            session,
            Rh002TestData.UserdataGiB,
            Rh002TestData.OriginalUserdataEndSector,
            Rh002TestData.BootUuid,
            Rh002TestData.RootUuid,
            Rh002TestData.BackupUuid,
            new ExpectedTable(
                Rh002TestData.SectorSize,
                Rh002TestData.DiskBytes,
                Rh002TestData.DiskGuid,
                Rh002TestData.DefaultPartitions()),
            Rh002TestData.CreateSeed());

        Assert.Equal(session.SocSerial, request.ExpectedSocSerial);
        Assert.Equal(session.BootId, request.ExpectedBootId);
        Assert.Equal(RamInstallRequest.ModelCode, request.Model);
        Assert.Equal(RamInstallRequest.DevicePath, request.Device);
    }

    [Fact]
    public void Table_IsClonedIntoAReadOnlyView()
    {
        ExpectedPartition[] partitions = Rh002TestData.DefaultPartitions();
        var table = new ExpectedTable(
            Rh002TestData.SectorSize,
            Rh002TestData.DiskBytes,
            Rh002TestData.DiskGuid,
            partitions);

        var request = new RamInstallRequest(
            Rh002TestData.SocSerial,
            Rh002TestData.BootId,
            Rh002TestData.UserdataGiB,
            Rh002TestData.OriginalUserdataEndSector,
            Rh002TestData.BootUuid,
            Rh002TestData.RootUuid,
            Rh002TestData.BackupUuid,
            table,
            Rh002TestData.CreateSeed());

        string firstName = request.ExpectedTable.Partitions[0].Name;
        partitions[0] = partitions[1];

        Assert.Equal(firstName, request.ExpectedTable.Partitions[0].Name);
        Assert.Equal(Rh002TestData.DefaultPartitions().Length, request.ExpectedTable.Partitions.Count);

        var mutable = Assert.IsAssignableFrom<IList<ExpectedPartition>>(request.ExpectedTable.Partitions);
        Assert.Throws<NotSupportedException>(() => mutable.Add(partitions[1]));
        Assert.Throws<NotSupportedException>(() => mutable.Clear());
    }

    [Fact]
    public void RejectsSerializedRequestAboveTheOneMiBWireLimit()
    {
        ExpectedPartition[] partitions = Rh002TestData.DefaultPartitions();
        partitions[0] = Rh002TestData.Copy(
            partitions[0],
            name: new string('x', (1 << 20) + 1));

        Assert.Throws<ArgumentException>(() => Rh002TestData.CreateRequest(partitions: partitions));
    }

    [Fact]
    public void Accepts64BitGeometryAndSeedLength()
    {
        RamInstallRequest request = Rh002TestData.CreateLargeRequest();

        Assert.True(request.ExpectedTable.DiskBytes > int.MaxValue);
        Assert.True(request.ExpectedTable.Partitions.Any(partition => partition.SectorCount > int.MaxValue));

        ExpectedPartition userdata = request.ExpectedTable.Partitions
            .Single(partition => string.Equals(partition.Name, "userdata", StringComparison.Ordinal));
        Assert.True(userdata.SectorCount > int.MaxValue);
        Assert.Equal((long)Rh002TestData.LargeUserdataGiB * 1024L * 1024L * 1024L,
            userdata.SectorCount * request.ExpectedTable.SectorSize);

        Assert.True(request.Seed.Length > int.MaxValue);
        Assert.Equal(64, request.RequestSha256.Length);
        Assert.Equal(
            request.RequestSha256,
            Convert.ToHexString(SHA256.HashData(Rh002TestData.RequestBytes(request))).ToLowerInvariant());
    }

    [Fact]
    public void Seed_AcceptsPinnedFreedomOrigin()
    {
        var seed = new RamInstallSeed(
            4096,
            Rh002TestData.SeedSha256,
            Rh002TestData.SeedCommit,
            "sha256:" + Rh002TestData.SeedManifest,
            Rh002TestData.Origin + "@sha256:" + new string('d', 64));

        Assert.Equal(4096, seed.Length);
        Assert.Equal(Rh002TestData.Origin + "@sha256:" + new string('d', 64), seed.Origin);
    }

    [Theory]
    [InlineData(1024)]
    [InlineData(0)]
    [InlineData(8192)]
    public void RejectsUnsupportedSectorSize(int sectorSize)
    {
        Assert.Throws<ArgumentException>(() => new ExpectedTable(
            sectorSize,
            Rh002TestData.DiskBytes,
            Rh002TestData.DiskGuid,
            Rh002TestData.DefaultPartitions()));
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(-1L)]
    [InlineData(513L)]
    public void RejectsDiskLengthThatIsNotAPositiveWholeNumberOfSectors(long diskBytes)
    {
        Assert.Throws<ArgumentException>(() => new ExpectedTable(
            Rh002TestData.SectorSize,
            diskBytes,
            Rh002TestData.DiskGuid,
            Rh002TestData.DefaultPartitions()));
    }

    [Fact]
    public void RejectsEmptyPartitionList()
    {
        Assert.Throws<ArgumentException>(() => new ExpectedTable(
            Rh002TestData.SectorSize,
            Rh002TestData.DiskBytes,
            Rh002TestData.DiskGuid,
            Array.Empty<ExpectedPartition>()));
    }

    [Fact]
    public void RejectsDuplicatePartitionNumber()
    {
        ExpectedPartition[] partitions = Rh002TestData.DefaultPartitions();
        partitions[0] = Rh002TestData.Copy(partitions[0], number: 2);

        Assert.Throws<ArgumentException>(() => Rh002TestData.CreateRequest(partitions: partitions));
    }

    [Fact]
    public void RejectsDuplicatePartitionName()
    {
        ExpectedPartition[] partitions = Rh002TestData.DefaultPartitions();
        partitions[0] = Rh002TestData.Copy(partitions[0], name: "userdata");

        Assert.Throws<ArgumentException>(() => Rh002TestData.CreateRequest(partitions: partitions));
    }

    [Fact]
    public void RejectsDuplicatePartitionUuid()
    {
        ExpectedPartition[] partitions = Rh002TestData.DefaultPartitions();
        partitions[0] = Rh002TestData.Copy(partitions[0], partUuid: Rh002TestData.UserdataUuid);

        Assert.Throws<ArgumentException>(() => Rh002TestData.CreateRequest(partitions: partitions));
    }

    [Fact]
    public void RejectsOverlappingPartitions()
    {
        ExpectedPartition[] partitions = Rh002TestData.DefaultPartitions();
        partitions[2] = Rh002TestData.Copy(partitions[2], startSector: Rh002TestData.UserdataStart);

        Assert.Throws<ArgumentException>(() => Rh002TestData.CreateRequest(partitions: partitions));
    }

    [Fact]
    public void RejectsPartitionPastTheDeclaredDisk()
    {
        ExpectedPartition[] partitions = Rh002TestData.DefaultPartitions();
        partitions[4] = Rh002TestData.Copy(
            partitions[4],
            startSector: (Rh002TestData.DiskBytes / Rh002TestData.SectorSize) - 10,
            sectorCount: 100);

        Assert.Throws<ArgumentException>(() => Rh002TestData.CreateRequest(partitions: partitions));
    }

    [Fact]
    public void RejectsOverflowingExtent()
    {
        ExpectedPartition[] partitions = Rh002TestData.DefaultPartitions();
        partitions[4] = Rh002TestData.Copy(
            partitions[4],
            startSector: long.MaxValue - 2,
            sectorCount: 10);

        Assert.Throws<ArgumentException>(() => Rh002TestData.CreateRequest(partitions: partitions));
    }

    [Fact]
    public void RejectsWrongBackupSize()
    {
        ExpectedPartition[] partitions = Rh002TestData.DefaultPartitions();
        partitions[4] = Rh002TestData.Copy(partitions[4], sectorCount: 4096);

        Assert.Throws<ArgumentException>(() => Rh002TestData.CreateRequest(partitions: partitions));
    }

    [Fact]
    public void AcceptsExactlyTwoGiBBackupForBothSectorSizes()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        Assert.Equal(512, request.ExpectedTable.SectorSize);
        ExpectedPartition backup = request.ExpectedTable.Partitions
            .Single(partition => string.Equals(partition.Name, "ARMADA_BACKUP", StringComparison.Ordinal));
        ExpectedPartition boot = request.ExpectedTable.Partitions
            .Single(partition => string.Equals(partition.Name, "ARMADA_BOOT", StringComparison.Ordinal));
        Assert.Equal(2L * Rh002TestData.Gibibyte, backup.SectorCount * 512);
        Assert.Equal(Rh002TestData.Gibibyte, boot.SectorCount * 512);

        RamInstallRequest large = Rh002TestData.CreateLargeRequest();
        Assert.Equal(4096, large.ExpectedTable.SectorSize);
        backup = large.ExpectedTable.Partitions
            .Single(partition => string.Equals(partition.Name, "ARMADA_BACKUP", StringComparison.Ordinal));
        boot = large.ExpectedTable.Partitions
            .Single(partition => string.Equals(partition.Name, "ARMADA_BOOT", StringComparison.Ordinal));
        Assert.Equal(2L * Rh002TestData.Gibibyte, backup.SectorCount * 4096L);
        Assert.Equal(Rh002TestData.Gibibyte, boot.SectorCount * 4096L);
    }

    [Fact]
    public void RejectsOldOneGiBBackupIndependentlyOfTailSlack()
    {
        ExpectedPartition[] partitions = Rh002TestData.DefaultPartitions();
        long oldBackupCount = 1L * Rh002TestData.Gibibyte / Rh002TestData.SectorSize;
        partitions[4] = Rh002TestData.Copy(partitions[4], sectorCount: oldBackupCount);

        var error = Assert.Throws<ArgumentException>(() => Rh002TestData.CreateRequest(
            originalUserdataEndSector: Rh002TestData.BackupStart + oldBackupCount + 256L,
            partitions: partitions));

        Assert.Contains("ARMADA_BACKUP must be exactly 2 GiB.", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsBootPlusRootBelow64GiB()
    {
        ExpectedPartition[] partitions = Rh002TestData.DefaultPartitions();
        partitions[3] = Rh002TestData.Copy(partitions[3], sectorCount: 32L * 1024 * 1024 * 1024 / 512);

        Assert.Throws<ArgumentException>(() => Rh002TestData.CreateRequest(partitions: partitions));
    }

    [Fact]
    public void RejectsUserdataBelow16GiB()
    {
        ExpectedPartition[] partitions = Rh002TestData.DefaultPartitions();
        partitions[1] = Rh002TestData.Copy(
            partitions[1],
            sectorCount: 8L * 1024 * 1024 * 1024 / 512);

        Assert.Throws<ArgumentException>(() => Rh002TestData.CreateRequest(
            userdataGiB: 8,
            partitions: partitions));
    }

    [Fact]
    public void RejectsUserdataGiBThatDoesNotMatchThePartition()
    {
        Assert.Throws<ArgumentException>(() => Rh002TestData.CreateRequest(userdataGiB: 33));
    }

    [Fact]
    public void RejectsMissingArmadaLabel()
    {
        ExpectedPartition[] partitions = Rh002TestData.DefaultPartitions();
        var withoutBackup = partitions
            .Where(partition => !string.Equals(partition.Name, "ARMADA_BACKUP", StringComparison.Ordinal))
            .ToArray();

        Assert.Throws<ArgumentException>(() => Rh002TestData.CreateRequest(partitions: withoutBackup));
    }

    [Fact]
    public void RejectsReferencedUuidThatDoesNotMatchTheLabel()
    {
        Assert.Throws<ArgumentException>(() => Rh002TestData.CreateRequest(
            backupUuid: "99999999-9999-4999-8999-999999999999"));
    }

    [Theory]
    [InlineData("below-backup")]
    [InlineData("past-disk")]
    [InlineData("before-userdata")]
    public void RejectsOriginalUserdataEndThatDoesNotCloseTheTail(string kind)
    {
        long originalEnd = kind switch
        {
            "below-backup" => Rh002TestData.BackupStart,
            "past-disk" => (Rh002TestData.DiskBytes / Rh002TestData.SectorSize) + 1,
            "before-userdata" => Rh002TestData.UserdataStart - 1,
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };

        Assert.Throws<ArgumentException>(() => Rh002TestData.CreateRequest(originalUserdataEndSector: originalEnd));
    }

    [Theory]
    [InlineData("0")]
    [InlineData("0123")]
    [InlineData("0x10")]
    [InlineData("-1")]
    [InlineData("")]
    public void RejectsNonCanonicalSocSerial(string serial)
    {
        Assert.Throws<ArgumentException>(() => Rh002TestData.CreateRequest(expectedSocSerial: serial));
    }

    [Theory]
    [InlineData("not-a-guid")]
    [InlineData("{3f2b8c1a-5d4e-4a6b-9c7d-8e9f0a1b2c3d}")]
    [InlineData("")]
    public void RejectsInvalidBootId(string bootId)
    {
        Assert.Throws<ArgumentException>(() => Rh002TestData.CreateRequest(expectedBootId: bootId));
    }

    [Fact]
    public void RejectsUserdataBelowTheContractMinimum()
    {
        Assert.Throws<ArgumentException>(() => Rh002TestData.CreateRequest(userdataGiB: 15));
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(-1L)]
    public void RejectsNonPositiveSeedLength(long length)
    {
        Assert.Throws<ArgumentException>(() => Rh002TestData.CreateSeed(length));
    }

    [Theory]
    [InlineData("uppercase")]
    [InlineData("short")]
    [InlineData("nonhex")]
    public void RejectsUnusableSeedSha256(string kind)
    {
        string sha = kind switch
        {
            "uppercase" => new string('A', 64),
            "short" => new string('a', 63),
            "nonhex" => new string('z', 64),
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };

        Assert.Throws<ArgumentException>(() => new RamInstallSeed(
            1,
            sha,
            Rh002TestData.SeedCommit,
            "sha256:" + Rh002TestData.SeedManifest,
            Rh002TestData.Origin));
    }

    [Theory]
    [InlineData("md5:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("sha256:short")]
    public void RejectsUnusableManifestDigest(string digest)
    {
        Assert.Throws<ArgumentException>(() => new RamInstallSeed(
            1,
            Rh002TestData.SeedSha256,
            Rh002TestData.SeedCommit,
            digest,
            Rh002TestData.Origin));
    }

    [Theory]
    [InlineData("ostree-image-signed:docker://ghcr.io/other/armadaos-freedom:stable")]
    [InlineData("ostree-image-signed:docker://ghcr.io/mydanyi/armadaos-freedom:edge")]
    [InlineData("ostree-image-signed:docker://ghcr.io/mydanyi/armadaos-freedom:stable@sha256:ABCDEF")]
    [InlineData("docker://ghcr.io/mydanyi/armadaos-freedom:stable")]
    [InlineData("")]
    public void RejectsNonFreedomOrigin(string origin)
    {
        Assert.Throws<ArgumentException>(() => new RamInstallSeed(
            1,
            Rh002TestData.SeedSha256,
            Rh002TestData.SeedCommit,
            "sha256:" + Rh002TestData.SeedManifest,
            origin));
    }
}

/// <summary>
/// Shared RH002 data builders. The default geometry is a coherent 128 GiB table: one arbitrary
/// Android partition, a 32 GiB userdata window, a 1 GiB Linux boot, a 71 GiB root immediately after
/// it, a 2 GiB backup immediately after the root, and less than one alignment MiB of tail slack.
/// The large fixture uses a 16 TiB disk and 8192 GiB userdata so a real 64-bit sector count exceeds
/// int.MaxValue, with the same 1 GiB boot / 71 GiB root / 2 GiB backup tail.
/// </summary>
internal static class Rh002TestData
{
    public const long Gibibyte = 1024L * 1024L * 1024L;

    public const int SectorSize = 512;
    public const long DiskBytes = 128L * Gibibyte;
    public const int UserdataGiB = 32;
    public const long UserdataStart = 2048L;
    public const long UserdataCount = (long)UserdataGiB * Gibibyte / SectorSize;
    public const long BootCount = 1L * Gibibyte / SectorSize;
    public const long BootStart = UserdataStart + UserdataCount;
    public const long RootCount = 71L * Gibibyte / SectorSize;
    public const long RootStart = BootStart + BootCount;
    public const long BackupCount = 2L * Gibibyte / SectorSize;
    public const long BackupStart = RootStart + RootCount;
    public const long OriginalUserdataEndSector = BackupStart + BackupCount + 256L;

    public const int LargeUserdataGiB = 8192;

    public const string SocSerial = "3251823604";
    public const string BootId = "3f2b8c1a-5d4e-4a6b-9c7d-8e9f0a1b2c3d";
    public const string DiskGuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    public const string BootUuid = "33333333-3333-4333-8333-333333333333";
    public const string RootUuid = "44444444-4444-4444-8444-444444444444";
    public const string BackupUuid = "55555555-5555-4555-8555-555555555555";
    public const string UserdataUuid = "22222222-2222-4222-8222-222222222222";

    public const string Token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    public const string SeedSha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    public const string SeedCommit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    public const string SeedManifest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    public const string Origin = "ostree-image-signed:docker://ghcr.io/mydanyi/armadaos-freedom:stable";
    public const long SeedLength = 5L * 1024L * 1024L * 1024L;

    public const string JsonPrefix = "FREEDOM_INSTALL_JSON ";
    public const string CommandMarker = "FREEDOM_INSTALL_CMD_DONE";
    public const string InitMarker = "FREEDOM_INSTALL_REQUEST_V1_OK";

    public static ExpectedPartition[] DefaultPartitions()
    {
        return new[]
        {
            new ExpectedPartition(
                1,
                "super",
                34,
                2014,
                "0fc63daf-8483-4772-8e79-3d69d8477de4",
                "11111111-1111-4111-8111-111111111111"),
            new ExpectedPartition(
                2,
                "userdata",
                UserdataStart,
                UserdataCount,
                "0fc63daf-8483-4772-8e79-3d69d8477de4",
                UserdataUuid),
            new ExpectedPartition(
                3,
                "ARMADA_BOOT",
                BootStart,
                BootCount,
                "0fc63daf-8483-4772-8e79-3d69d8477de4",
                BootUuid),
            new ExpectedPartition(
                4,
                "ARMADA_ROOT",
                RootStart,
                RootCount,
                "0fc63daf-8483-4772-8e79-3d69d8477de4",
                RootUuid),
            new ExpectedPartition(
                5,
                "ARMADA_BACKUP",
                BackupStart,
                BackupCount,
                "0fc63daf-8483-4772-8e79-3d69d8477de4",
                BackupUuid),
        };
    }

    public static RamInstallRequest CreateRequest(
        string? expectedSocSerial = null,
        string? expectedBootId = null,
        int userdataGiB = UserdataGiB,
        long originalUserdataEndSector = OriginalUserdataEndSector,
        string? bootUuid = null,
        string? rootUuid = null,
        string? backupUuid = null,
        ExpectedPartition[]? partitions = null,
        RamInstallSeed? seed = null)
    {
        return new RamInstallRequest(
            expectedSocSerial ?? SocSerial,
            expectedBootId ?? BootId,
            userdataGiB,
            originalUserdataEndSector,
            bootUuid ?? BootUuid,
            rootUuid ?? RootUuid,
            backupUuid ?? BackupUuid,
            new ExpectedTable(
                SectorSize,
                DiskBytes,
                DiskGuid,
                partitions ?? DefaultPartitions()),
            seed ?? CreateSeed());
    }

    public static RamInstallRequest CreateLargeRequest()
    {
        const int sectorSize = 4096;
        const long userdataStart = 256L;
        const long diskBytes = 16L * 1024L * Gibibyte;
        const long bootCount = 1L * Gibibyte / sectorSize;
        const long rootCount = 71L * Gibibyte / sectorSize;
        const long backupCount = 2L * Gibibyte / sectorSize;

        long userdataCount = checked((long)LargeUserdataGiB * Gibibyte / sectorSize);
        long bootStart = checked(userdataStart + userdataCount);
        long rootStart = checked(bootStart + bootCount);
        long backupStart = checked(rootStart + rootCount);
        long backupEnd = checked(backupStart + backupCount);
        long originalEnd = checked(backupEnd + 128L); // less than 1 MiB / 4096 = 256 sectors
        long diskSectors = checked(diskBytes / sectorSize);

        if (originalEnd > diskSectors)
        {
            throw new InvalidOperationException("The large fixture does not fit its 16 TiB disk.");
        }

        var partitions = new[]
        {
            new ExpectedPartition(
                1,
                "userdata",
                userdataStart,
                userdataCount,
                "0fc63daf-8483-4772-8e79-3d69d8477de4",
                UserdataUuid),
            new ExpectedPartition(
                2,
                "ARMADA_BOOT",
                bootStart,
                bootCount,
                "0fc63daf-8483-4772-8e79-3d69d8477de4",
                BootUuid),
            new ExpectedPartition(
                3,
                "ARMADA_ROOT",
                rootStart,
                rootCount,
                "0fc63daf-8483-4772-8e79-3d69d8477de4",
                RootUuid),
            new ExpectedPartition(
                4,
                "ARMADA_BACKUP",
                backupStart,
                backupCount,
                "0fc63daf-8483-4772-8e79-3d69d8477de4",
                BackupUuid),
        };

        return new RamInstallRequest(
            SocSerial,
            BootId,
            LargeUserdataGiB,
            originalEnd,
            BootUuid,
            RootUuid,
            BackupUuid,
            new ExpectedTable(sectorSize, diskBytes, DiskGuid, partitions),
            CreateSeed(6L * Gibibyte));
    }

    public static RamInstallSeed CreateSeed(long length = SeedLength)
    {
        return new RamInstallSeed(
            length,
            SeedSha256,
            SeedCommit,
            "sha256:" + SeedManifest,
            Origin);
    }

    public static ExpectedPartition Copy(
        ExpectedPartition source,
        long? number = null,
        string? name = null,
        long? startSector = null,
        long? sectorCount = null,
        string? typeGuid = null,
        string? partUuid = null)
    {
        return new ExpectedPartition(
            number ?? source.Number,
            name ?? source.Name,
            startSector ?? source.StartSector,
            sectorCount ?? source.SectorCount,
            typeGuid ?? source.TypeGuid,
            partUuid ?? source.PartUuid);
    }

    public static byte[] RequestBytes(RamInstallRequest request)
    {
        var method = typeof(RamInstallRequest).GetMethod(
            "CopyRequestBytes",
            BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new InvalidOperationException("RamInstallRequest.CopyRequestBytes is missing.");
        return (byte[])method.Invoke(request, null)!;
    }

    public static RamInstallSession CreateSession(
        IMaintenanceConsole console,
        string? socSerial = null,
        string? bootId = null,
        string? model = null,
        string? token = null)
    {
        var constructor = typeof(RamInstallSession).GetConstructor(
            BindingFlags.NonPublic | BindingFlags.Instance,
            binder: null,
            new[]
            {
                typeof(string),
                typeof(string),
                typeof(string),
                typeof(string),
                typeof(IMaintenanceConsole),
                typeof(string),
            },
            modifiers: null)
            ?? throw new InvalidOperationException("RamInstallSession internal constructor is missing.");

        return (RamInstallSession)constructor.Invoke(new object?[]
        {
            model ?? RamInstallRequest.ModelCode,
            "SM8750",
            socSerial ?? SocSerial,
            bootId ?? BootId,
            console,
            token ?? Token,
        });
    }

    public static JsonObject InspectEnvelope(RamInstallRequest request)
    {
        var partitions = new JsonArray();
        foreach (ExpectedPartition partition in request.ExpectedTable.Partitions)
        {
            partitions.Add(new JsonObject
            {
                ["number"] = partition.Number,
                ["name"] = partition.Name,
                ["startSector"] = partition.StartSector,
                ["sectorCount"] = partition.SectorCount,
                ["typeGuid"] = partition.TypeGuid,
                ["partUuid"] = partition.PartUuid,
            });
        }

        var result = new JsonObject
        {
            ["model"] = RamInstallRequest.ModelCode,
            ["socSerial"] = request.ExpectedSocSerial,
            ["bootId"] = request.ExpectedBootId,
            ["device"] = RamInstallRequest.DevicePath,
            ["sectorSize"] = request.ExpectedTable.SectorSize,
            ["diskBytes"] = request.ExpectedTable.DiskBytes,
            ["diskGuid"] = request.ExpectedTable.DiskGuid,
            ["linuxTableFingerprint"] = new string('f', 64),
            ["partitions"] = partitions,
        };

        return new JsonObject
        {
            ["schemaVersion"] = 1,
            ["requestSha256"] = request.RequestSha256,
            ["action"] = "inspect",
            ["state"] = "succeeded",
            ["pid"] = null,
            ["pidStartTicks"] = null,
            ["exitCode"] = 0,
            ["result"] = result,
            ["error"] = null,
        };
    }

    public static JsonObject JobEnvelope(
        RamInstallRequest request,
        string action,
        string state,
        JsonNode? result = null,
        long? pid = null,
        string? pidStartTicks = null,
        int? exitCode = null,
        string? error = null)
    {
        return new JsonObject
        {
            ["schemaVersion"] = 1,
            ["requestSha256"] = request.RequestSha256,
            ["action"] = action,
            ["state"] = state,
            ["pid"] = pid.HasValue ? JsonValue.Create(pid.Value) : null,
            ["pidStartTicks"] = pidStartTicks,
            ["exitCode"] = exitCode.HasValue ? JsonValue.Create(exitCode.Value) : null,
            ["result"] = result,
            ["error"] = error,
        };
    }

    public static string Transcript(JsonObject envelope)
    {
        return JsonPrefix + envelope.ToJsonString() + "\n" + CommandMarker + "\n";
    }

    public static string DecodeToken(string script)
    {
        const string prefix = "token=$(printf '";
        int start = script.IndexOf(prefix, StringComparison.Ordinal);
        if (start < 0)
        {
            throw new InvalidOperationException("The script does not contain an octal token command.");
        }

        start += prefix.Length;
        int end = script.IndexOf("')", start, StringComparison.Ordinal);
        if (end < 0)
        {
            throw new InvalidOperationException("The octal token command is not terminated.");
        }

        string encoded = script[start..end];
        var decoded = new StringBuilder(encoded.Length / 4);
        for (var index = 0; index < encoded.Length; index += 4)
        {
            if (encoded[index] != '\\')
            {
                throw new InvalidOperationException("The token command is not octal encoded.");
            }

            decoded.Append((char)Convert.ToInt32(encoded.Substring(index + 1, 3), 8));
        }

        return decoded.ToString();
    }

    public static byte[] ExtractInitializationBytes(string script)
    {
        const string prefix = "printf '%s' '";
        int start = script.IndexOf(prefix, StringComparison.Ordinal);
        if (start < 0)
        {
            throw new InvalidOperationException("The script does not contain a base64 request.");
        }

        start += prefix.Length;
        int end = script.IndexOf("' | busybox base64 -d", start, StringComparison.Ordinal);
        if (end < 0)
        {
            throw new InvalidOperationException("The base64 request is not terminated.");
        }

        return Convert.FromBase64String(script[start..end]);
    }
}

/// <summary>Collects progress samples without changing the transfer outcome.</summary>
internal sealed class Rh002Progress : IProgress<RamInstallSeedProgress>
{
    public List<RamInstallSeedProgress> Reports { get; } = new();

    public void Report(RamInstallSeedProgress value) => Reports.Add(value);
}

/// <summary>A console that is never expected to run a command in the request-only tests.</summary>
internal sealed class Rh002NoopConsole : IMaintenanceConsole
{
    public Task<string> RunCommandAsync(
        string script,
        string expectedMarker,
        TimeSpan timeout,
        CancellationToken cancellationToken = default) =>
        throw new InvalidOperationException("No console command is expected.");
}
