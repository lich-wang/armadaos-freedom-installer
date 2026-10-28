using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Behavioural specifications for the four core entry points. Every call currently reaches
/// <see cref="NotImplementedException"/>: these tests are red on purpose and must not be weakened.
/// </summary>
public sealed class BehavioralTests
{
    private const long GiB = TestSizes.GiB;

    private const string PartitionTypeEsp = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
    private const string PartitionTypeLinux = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
    private const string PartUuidSystem = "11111111-2222-3333-4444-555555555555";
    private const string PartUuidUserdata = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE";

    // ---------------------------------------------------------------- adb devices

    [Fact]
    public void ParseAdbDevices_KeepsAuthorizedAndUnauthorizedAndSkipsHeader()
    {
        const string output =
            "List of devices attached\n" +
            "R58M12345ABC\tdevice\n" +
            "R58M99999XYZ\tunauthorized\n" +
            "\n";

        var devices = DeviceProbe.ParseAdbDevices(output);

        Assert.Equal(2, devices.Count);
        Assert.Equal("R58M12345ABC", devices[0].Serial);
        Assert.Equal(ConnectionState.Authorized, devices[0].ConnectionState);
        Assert.Equal("R58M99999XYZ", devices[1].Serial);
        Assert.Equal(ConnectionState.Unauthorized, devices[1].ConnectionState);
    }

    [Fact]
    public void ParseAdbDevices_DistinguishesOfflineAndHandlesEmptyInput()
    {
        var devices = DeviceProbe.ParseAdbDevices("List of devices attached\nemulator-5554\toffline\n");

        var device = Assert.Single(devices);
        Assert.Equal("emulator-5554", device.Serial);
        Assert.Equal(ConnectionState.Offline, device.ConnectionState);

        Assert.Empty(DeviceProbe.ParseAdbDevices(string.Empty));
        Assert.Empty(DeviceProbe.ParseAdbDevices("List of devices attached\n\n"));
    }

    // ------------------------------------------------------------ bootloader state

    [Fact]
    public void ParseBootloaderState_ReadsFastbootYesNoAndDeviceUnlockedTrueFalse()
    {
        Assert.Equal(BootloaderState.Unlocked, DeviceProbe.ParseBootloaderState("(bootloader) unlocked: yes"));
        Assert.Equal(BootloaderState.Locked, DeviceProbe.ParseBootloaderState("(bootloader) unlocked: no"));

        Assert.Equal(BootloaderState.Unlocked, DeviceProbe.ParseBootloaderState("Device unlocked: true"));
        Assert.Equal(BootloaderState.Locked, DeviceProbe.ParseBootloaderState("Device unlocked: false"));
    }

    [Fact]
    public void ParseBootloaderState_CriticalOnlyGarbageAndConflictsAreUnknown()
    {
        Assert.Equal(BootloaderState.Unknown, DeviceProbe.ParseBootloaderState("(bootloader) critical unlocked: true"));
        Assert.Equal(BootloaderState.Unknown, DeviceProbe.ParseBootloaderState("ERROR: no devices"));
        Assert.Equal(BootloaderState.Unknown, DeviceProbe.ParseBootloaderState(string.Empty));
        Assert.Equal(
            BootloaderState.Unknown,
            DeviceProbe.ParseBootloaderState("(bootloader) unlocked: yes\nDevice unlocked: false"));
    }

    // ---------------------------------------------------------------- model identity

    [Fact]
    public void IdentifyModel_CanonicalizesExactTicketModels()
    {
        Assert.Equal(
            "TB322FC",
            DeviceProbe.IdentifyModel("[ro.product.model]: [TB322FC]\n[ro.product.vendor.model]: [TB322FC]"));

        Assert.Equal("TB322FC", DeviceProbe.IdentifyModel("[ro.product.model]: [Lenovo TB322FC]"));

        Assert.Equal(
            "TB322FC",
            DeviceProbe.IdentifyModel("[ro.product.name]: [TB322FC_PRC]\n[ro.product.model]: [TB322FC]"));

        Assert.Equal(
            "TB323FU",
            DeviceProbe.IdentifyModel("[ro.product.model]: [TB323FU]\n[ro.product.vendor.model]: [TB323FU]"));

        Assert.Equal("TB323FU", DeviceProbe.IdentifyModel("[ro.product.model]: [Lenovo TB323FU_PRC]"));
    }

    [Fact]
    public void IdentifyModel_RejectsOtherModelsAndSubstringMatches()
    {
        Assert.Null(DeviceProbe.IdentifyModel("[ro.product.model]: [TB324ZC]"));
        Assert.Null(DeviceProbe.IdentifyModel("[ro.product.model]: [NOTTB322FC]"));
        Assert.Null(DeviceProbe.IdentifyModel(string.Empty));
    }

    [Fact]
    public void IdentifyModel_ContradictoryModelFieldsAreUnknown()
    {
        Assert.Null(DeviceProbe.IdentifyModel(
            "[ro.product.model]: [TB322FC]\n[ro.product.vendor.model]: [TB323FU]"));
    }

    // -------------------------------------------------------------- partition planner

    [Fact]
    public void Plan_Sector512_YieldsExpectedBytesAndAbsoluteSectors()
    {
        var layout = LayoutSector512();

        var plan = PartitionPlanner.Plan(layout, androidGiB: 96, androidMinimumGiB: 16, TicketStorage());

        Assert.Equal(96 * GiB, plan.AndroidBytes);
        Assert.Equal(128 * GiB, plan.LinuxBytes);
        Assert.Equal(1 * GiB, plan.LinuxBootBytes);
        Assert.Equal(127 * GiB, plan.LinuxRootBytes);
        Assert.Equal(107 * GiB, plan.EstimatedLinuxDataBytes);

        Assert.Equal(8_388_608L, plan.UserdataStartSector);     // 4 GiB / 512
        Assert.Equal(201_326_592L, plan.AndroidSectorCount);    // 96 GiB / 512
        Assert.Equal(209_715_200L, plan.LinuxBootStartSector);  // 100 GiB / 512
        Assert.Equal(211_812_352L, plan.LinuxRootStartSector);  // 101 GiB / 512
        Assert.Equal(478_150_656L, plan.EndSectorExclusive);    // 228 GiB / 512
    }

    [Fact]
    public void Plan_Sector4096_YieldsSameBytesWithSectorScaledOffsets()
    {
        var at512 = PartitionPlanner.Plan(LayoutSector512(), 96, 16, TicketStorage());
        var at4096 = PartitionPlanner.Plan(LayoutSector4096(), 96, 16, TicketStorage());

        Assert.Equal(at512.AndroidBytes, at4096.AndroidBytes);
        Assert.Equal(at512.LinuxBytes, at4096.LinuxBytes);
        Assert.Equal(at512.LinuxBootBytes, at4096.LinuxBootBytes);
        Assert.Equal(at512.LinuxRootBytes, at4096.LinuxRootBytes);
        Assert.Equal(at512.EstimatedLinuxDataBytes, at4096.EstimatedLinuxDataBytes);

        Assert.Equal(1_048_576L, at4096.UserdataStartSector);    // 4 GiB / 4096
        Assert.Equal(25_165_824L, at4096.AndroidSectorCount);    // 96 GiB / 4096
        Assert.Equal(26_214_400L, at4096.LinuxBootStartSector);  // 100 GiB / 4096
        Assert.Equal(26_476_544L, at4096.LinuxRootStartSector);  // 101 GiB / 4096
        Assert.Equal(59_768_832L, at4096.EndSectorExclusive);    // 228 GiB / 4096
    }

    [Fact]
    public void Plan_KeepsEarlierPartitionsOutsideTheUserdataExtent()
    {
        var layout = LayoutSector512();
        var system = layout.Partitions[0];

        var plan = PartitionPlanner.Plan(layout, 96, 16, TicketStorage());

        Assert.Equal(2, layout.Partitions.Count);
        Assert.Equal("system", layout.Partitions[0].Name);
        Assert.Equal(2L, layout.Partitions[1].Number);
        Assert.True(system.StartSector + system.SectorCount <= plan.UserdataStartSector);
        Assert.Equal(layout.Partitions[1].StartSector, plan.UserdataStartSector);
    }

    [Fact]
    public void Plan_RejectsAndroidBelowMinimum()
    {
        Assert.Throws<ArgumentException>(() => PartitionPlanner.Plan(LayoutSector512(), 16, 32, TicketStorage()));
    }

    [Fact]
    public void Plan_RejectsLinuxExtentThatCannotHostSystemAndData()
    {
        // 220 GiB Android leaves 4 GiB Linux: 1 GiB boot and a root too small for the 20 GiB system.
        Assert.Throws<ArgumentException>(() => PartitionPlanner.Plan(LayoutSector512(), 220, 16, TicketStorage()));
    }

    [Fact]
    public void Plan_RejectsDuplicateUserdataPartition()
    {
        var layout = LayoutSector512();
        var duplicated = new DiskLayout(
            "sdb",
            512,
            new[]
            {
                layout.Partitions[0],
                layout.Partitions[1],
                layout.Partitions[1] with { Number = 3 },
            });

        Assert.Throws<InvalidOperationException>(() => PartitionPlanner.Plan(duplicated, 96, 16, TicketStorage()));
    }

    [Fact]
    public void Plan_RejectsAnyPartitionAfterUserdata()
    {
        var layout = LayoutSector512();
        var withTail = new DiskLayout(
            "sdb",
            512,
            new[]
            {
                layout.Partitions[0],
                layout.Partitions[1],
                new DiskPartition(3, "metadata", 478_150_656, 2_048, PartitionTypeLinux, PartUuidUserdata),
            });

        Assert.Throws<InvalidOperationException>(() => PartitionPlanner.Plan(withTail, 96, 16, TicketStorage()));
    }

    [Fact]
    public void Plan_RejectsOverlappingEarlierPartitions()
    {
        var overlapping = new DiskLayout(
            "sdb",
            512,
            new[]
            {
                new DiskPartition(1, "system", 2_048, 8_192_000, PartitionTypeEsp, PartUuidSystem),
                new DiskPartition(2, "boot", 7_000_000, 2_000_000, PartitionTypeLinux, PartUuidUserdata),
                new DiskPartition(3, "userdata", 8_388_608, 469_762_048, PartitionTypeLinux, PartUuidUserdata),
            });

        Assert.Throws<InvalidOperationException>(() => PartitionPlanner.Plan(overlapping, 96, 16, TicketStorage()));
    }

    [Fact]
    public void Plan_RejectsZeroAndNegativeSizes()
    {
        Assert.Throws<ArgumentException>(() => PartitionPlanner.Plan(LayoutSector512(), 0, 0, TicketStorage()));
        Assert.Throws<ArgumentException>(() => PartitionPlanner.Plan(LayoutSector512(), -8, 0, TicketStorage()));
        Assert.Throws<ArgumentException>(() => PartitionPlanner.Plan(LayoutSector512(), 96, -1, TicketStorage()));

        Assert.Throws<ArgumentException>(() => PartitionPlanner.Plan(
            LayoutSector512(), 96, 16, new PackageStorage(0, 20 * GiB, 2 * GiB, 8 * GiB)));
        Assert.Throws<ArgumentException>(() => PartitionPlanner.Plan(
            LayoutSector512(), 96, 16, new PackageStorage(1 * GiB, -1 * GiB, 2 * GiB, 8 * GiB)));
        Assert.Throws<ArgumentException>(() => PartitionPlanner.Plan(
            LayoutSector512(), 96, 16, new PackageStorage(1 * GiB, 20 * GiB, 2 * GiB, -1 * GiB)));
    }

    [Fact]
    public void Plan_RejectsArithmeticOverflow()
    {
        var oversizedExtent = new DiskLayout(
            "sdb",
            512,
            new[] { new DiskPartition(1, "userdata", 0, long.MaxValue / 256, PartitionTypeLinux, PartUuidUserdata) });

        Assert.Throws<ArgumentException>(() => PartitionPlanner.Plan(oversizedExtent, 96, 16, TicketStorage()));
        Assert.Throws<ArgumentException>(() => PartitionPlanner.Plan(LayoutSector512(), 9_000_000_000, 16, TicketStorage()));
    }

    // ---------------------------------------------------------------------- readiness

    [Fact]
    public void Evaluate_FullyVerifiedInputsAreReady()
    {
        var readiness = InstallationReadiness.Evaluate(
            UnlockedIdentity(),
            backupsVerified: true,
            ValidPackage(),
            maintenanceValidated: true,
            ExpectedPlan());

        Assert.True(readiness.IsReady, string.Join("; ", readiness.Reasons));
        Assert.Empty(readiness.Reasons);
    }

    [Fact]
    public void Evaluate_MissingPackageIsNeverReadyEvenWhenEverythingElseIsTrue()
    {
        var readiness = InstallationReadiness.Evaluate(
            UnlockedIdentity(),
            backupsVerified: true,
            package: null,
            maintenanceValidated: true,
            ExpectedPlan());

        Assert.False(readiness.IsReady);
        Assert.NotEmpty(readiness.Reasons);
    }

    [Fact]
    public void Evaluate_MissingIdentityOrPlanIsNotReady()
    {
        var noIdentity = InstallationReadiness.Evaluate(null, true, ValidPackage(), true, ExpectedPlan());
        var noPlan = InstallationReadiness.Evaluate(UnlockedIdentity(), true, ValidPackage(), true, null);

        Assert.False(noIdentity.IsReady);
        Assert.NotEmpty(noIdentity.Reasons);
        Assert.False(noPlan.IsReady);
        Assert.NotEmpty(noPlan.Reasons);
    }

    [Fact]
    public void Evaluate_LockedOrUnknownBootloaderIsNotReady()
    {
        var locked = new DeviceIdentity("R58M12345ABC", "TB322FC", BootloaderState.Locked);
        var unknown = new DeviceIdentity("R58M12345ABC", "TB322FC", BootloaderState.Unknown);

        var lockedResult = InstallationReadiness.Evaluate(locked, true, ValidPackage(), true, ExpectedPlan());
        var unknownResult = InstallationReadiness.Evaluate(unknown, true, ValidPackage(), true, ExpectedPlan());

        Assert.False(lockedResult.IsReady);
        Assert.NotEmpty(lockedResult.Reasons);
        Assert.False(unknownResult.IsReady);
        Assert.NotEmpty(unknownResult.Reasons);
    }

    [Fact]
    public void Evaluate_UnverifiedBackupsOrInvalidPackageIsNotReady()
    {
        var noBackups = InstallationReadiness.Evaluate(UnlockedIdentity(), false, ValidPackage(), true, ExpectedPlan());
        var invalidPackage = InstallationReadiness.Evaluate(
            UnlockedIdentity(),
            true,
            new PackageValidationResult(false, new[] { "hash mismatch" }, null),
            true,
            ExpectedPlan());

        Assert.False(noBackups.IsReady);
        Assert.NotEmpty(noBackups.Reasons);
        Assert.False(invalidPackage.IsReady);
        Assert.NotEmpty(invalidPackage.Reasons);
    }

    // ----------------------------------------------------------------- package reader

    [Fact]
    public void Validate_MissingDirectoryIsInvalid()
    {
        var missing = Path.Combine(
            TestArtifactRoot.Resolve(),
            "package-that-does-not-exist-" + Guid.NewGuid().ToString("N"));

        var result = PackageReader.Validate(missing, "TB322FC");

        Assert.False(result.IsValid);
        Assert.NotEmpty(result.Reasons);
    }

    [Fact]
    public void Validate_FixturePackageForAnotherModelIsInvalid()
    {
        using var fixture = new TempPackageDirectory();
        PackageFixture.WritePackage(fixture.Path, "TB323FU");

        var result = PackageReader.Validate(fixture.Path, "TB322FC");

        Assert.False(result.IsValid);
        Assert.NotEmpty(result.Reasons);
    }

    [Fact]
    public void Validate_PartialArtifactsAndHashMismatchAreInvalid()
    {
        using var partial = new TempPackageDirectory();
        PackageFixture.WritePackage(partial.Path, "TB322FC");
        File.Delete(Path.Combine(partial.Path, PackageFixture.SystemFileName));
        var partialResult = PackageReader.Validate(partial.Path, "TB322FC");

        using var tampered = new TempPackageDirectory();
        PackageFixture.WritePackage(tampered.Path, "TB322FC");
        File.WriteAllBytes(
            Path.Combine(tampered.Path, PackageFixture.LinuxBootFileName),
            new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });
        var tamperedResult = PackageReader.Validate(tampered.Path, "TB322FC");

        Assert.False(partialResult.IsValid);
        Assert.NotEmpty(partialResult.Reasons);
        Assert.False(tamperedResult.IsValid);
        Assert.NotEmpty(tamperedResult.Reasons);
    }

    [Fact]
    public void Validate_CompleteFixturePackageIsValidAndReportsStorage()
    {
        using var fixture = new TempPackageDirectory();
        PackageFixture.WritePackage(fixture.Path, "TB322FC");

        var result = PackageReader.Validate(fixture.Path, "TB322FC");

        Assert.True(result.IsValid, string.Join("; ", result.Reasons));
        Assert.Empty(result.Reasons);
        Assert.NotNull(result.Storage);
        Assert.Equal(1 * GiB, result.Storage!.LinuxBootBytes);
        Assert.Equal(20 * GiB, result.Storage.SystemRequiredBytes);
        Assert.Equal(2 * GiB, result.Storage.DeploymentScratchBytes);
        Assert.Equal(8 * GiB, result.Storage.MinimumLinuxDataBytes);
    }

    // ------------------------------------------------------------------------ helpers

    private static DiskLayout LayoutSector512() => new(
        "sdb",
        512,
        new[]
        {
            new DiskPartition(1, "system", 2_048, 8_192_000, PartitionTypeEsp, PartUuidSystem),
            new DiskPartition(2, "userdata", 8_388_608, 469_762_048, PartitionTypeLinux, PartUuidUserdata),
        });

    private static DiskLayout LayoutSector4096() => new(
        "sdb",
        4096,
        new[]
        {
            new DiskPartition(1, "system", 2_048, 1_024_000, PartitionTypeEsp, PartUuidSystem),
            new DiskPartition(2, "userdata", 1_048_576, 58_720_256, PartitionTypeLinux, PartUuidUserdata),
        });

    private static PackageStorage TicketStorage() => new(1 * GiB, 20 * GiB, 2 * GiB, 8 * GiB);

    private static DeviceIdentity UnlockedIdentity() =>
        new("R58M12345ABC", "TB322FC", BootloaderState.Unlocked);

    private static PackageValidationResult ValidPackage() =>
        new(true, Array.Empty<string>(), TicketStorage());

    // Literal snapshot of the expected plan, so readiness tests never depend on the planner stub.
    private static AllocationPlan ExpectedPlan() => new(
        AndroidBytes: 96 * GiB,
        LinuxBytes: 128 * GiB,
        LinuxBootBytes: 1 * GiB,
        LinuxRootBytes: 127 * GiB,
        EstimatedLinuxDataBytes: 107 * GiB,
        UserdataStartSector: 8_388_608,
        AndroidSectorCount: 201_326_592,
        LinuxBootStartSector: 209_715_200,
        LinuxRootStartSector: 211_812_352,
        EndSectorExclusive: 478_150_656);
}

internal static class TestSizes
{
    internal const long GiB = 1024L * 1024 * 1024;
}

internal static class TestArtifactRoot
{
    /// <summary>
    /// Test-only scratch root. TEST_ARTIFACT_ROOT is set by the remote test run (pointing at
    /// /evidence/tmp); without it the framework temp path is used. Production code never creates a
    /// temp directory on its own.
    /// </summary>
    internal static string Resolve()
    {
        var configured = Environment.GetEnvironmentVariable("TEST_ARTIFACT_ROOT");
        var root = string.IsNullOrWhiteSpace(configured) ? System.IO.Path.GetTempPath() : configured!;
        Directory.CreateDirectory(root);
        return root;
    }
}

internal sealed class TempPackageDirectory : IDisposable
{
    internal TempPackageDirectory()
    {
        Path = System.IO.Path.Combine(TestArtifactRoot.Resolve(), "fixture-package-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    internal string Path { get; }

    public void Dispose()
    {
        // Only the directory created by this helper is removed.
        try
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}

/// <summary>
/// Tiny placeholder package for contract v1: a few bytes per artefact plus test-only metadata. These
/// files are not firmware, they are not flashable and no vendor boot image is distributed here.
/// <para>
/// The three original fixture file names are kept (the existing assertions depend on them) but they
/// now carry the contract roles ostree-seed / kernel / dtb; a fourth, tiny runtime artefact is added.
/// </para>
/// </summary>
internal static class PackageFixture
{
    internal const string MetadataFileName = "package.json";
    internal const string LinuxBootFileName = "linux-boot.img";
    internal const string LinuxRootFileName = "linux-root.squashfs";
    internal const string SystemFileName = "system.vhdx.part";
    internal const string RuntimeFileName = "runtime.bin";

    internal const string PackageId = "armadaos-freedom-example";
    internal const string PackageVersion = "1.0.0";
    internal const string Commit = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    internal const string ManifestDigest = "sha256:" + Commit;
    internal const string ProjectOrigin = "ostree-image-signed:docker://ghcr.io/mydanyi/armadaos-freedom:stable";
    internal const long BootPartitionBytes = 100_663_296L;

    private static readonly byte[] LinuxBootPayload = { 0x41, 0x4E, 0x44, 0x52, 0x4F, 0x49, 0x44, 0x00 };
    private static readonly byte[] LinuxRootPayload = { 0x73, 0x71, 0x66, 0x73, 0x2D, 0x66, 0x69 };
    private static readonly byte[] SystemPayload = { 0x56, 0x48, 0x44, 0x58, 0x2D, 0x73, 0x00 };
    private static readonly byte[] RuntimePayload = { 0x52, 0x54, 0x00 };

    private static readonly JsonSerializerOptions SerializerOptions = new() { WriteIndented = true };

    internal static string MetadataPath(string directory) => Path.Combine(directory, MetadataFileName);

    internal static void WritePackage(string directory, string deviceModel)
    {
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Path.Combine(directory, LinuxBootFileName), LinuxBootPayload);
        File.WriteAllBytes(Path.Combine(directory, LinuxRootFileName), LinuxRootPayload);
        File.WriteAllBytes(Path.Combine(directory, SystemFileName), SystemPayload);
        File.WriteAllBytes(Path.Combine(directory, RuntimeFileName), RuntimePayload);

        var isTB323FU = string.Equals(deviceModel, "TB323FU", StringComparison.OrdinalIgnoreCase);

        var metadata = new Dictionary<string, object?>
        {
            ["schemaVersion"] = 1,
            ["packageId"] = PackageId,
            ["version"] = PackageVersion,
            ["deviceModel"] = deviceModel,
            ["testOnly"] = true,
            ["compatible"] = new Dictionary<string, object?>
            {
                ["soc"] = isTB323FU ? "SM8850" : "SM8750",
                ["device"] = isTB323FU ? "baldur" : "elden",
            },
            ["artifacts"] = new object[]
            {
                DescribeArtifact("ostree-seed", directory, LinuxRootFileName),
                DescribeArtifact("kernel", directory, LinuxBootFileName),
                DescribeArtifact("dtb", directory, SystemFileName),
                DescribeArtifact("runtime", directory, RuntimeFileName),
            },
            ["deployment"] = new Dictionary<string, object?>
            {
                ["kind"] = "ostree-offline-seed",
                ["commit"] = Commit,
                ["manifestDigest"] = ManifestDigest,
                ["origin"] = ProjectOrigin,
            },
            ["storage"] = new Dictionary<string, object?>
            {
                ["linuxBootBytes"] = 1L * TestSizes.GiB,
                ["systemRequiredBytes"] = 20L * TestSizes.GiB,
                ["deploymentScratchBytes"] = 2L * TestSizes.GiB,
                ["minimumLinuxDataBytes"] = 8L * TestSizes.GiB,
            },
            ["bootCompatibility"] = new Dictionary<string, object?>
            {
                ["format"] = "android-boot-v4",
                ["partitionBytes"] = BootPartitionBytes,
                ["firmwareVersions"] = new object[] { deviceModel + "-example-firmware-1.0.0" },
            },
            ["toolsCompatibility"] = new Dictionary<string, object?>
            {
                ["installerProtocol"] = 1,
                ["maintenanceProtocol"] = 1,
            },
        };

        File.WriteAllText(MetadataPath(directory), JsonSerializer.Serialize(metadata, SerializerOptions));
    }

    private static Dictionary<string, object?> DescribeArtifact(string role, string directory, string fileName)
    {
        var payload = File.ReadAllBytes(Path.Combine(directory, fileName));
        return new Dictionary<string, object?>
        {
            ["role"] = role,
            ["file"] = fileName,
            ["bytes"] = payload.LongLength,
            ["sha256"] = Convert.ToHexString(SHA256.HashData(payload)),
        };
    }
}
