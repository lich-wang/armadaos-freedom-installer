using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Behavioural specifications for the TF card installation target: discovery report parsing, the
/// capacity-only space plan, the two read-only discovery commands and the target aware package
/// validation overload. These specifications are now satisfied by the production implementation and
/// must not be weakened.
/// </summary>
public sealed class TfCardSupportTests
{
    private const long GiB = TestSizes.GiB;
    private const long MiB = 1024L * 1024;

    private static readonly TimeSpan MaxDiscoveryTimeout = TimeSpan.FromSeconds(20);

    // ---------------------------------------------------------------- discovery fixtures

    private static JsonObject Medium(
        string key = "mmcblk1",
        string path = "/dev/block/mmcblk1",
        string displayName = "SanDisk Extreme 64GB",
        long sizeBytes = 64 * GiB,
        int logicalSectorSize = 512,
        string mediumEvidence = "SD",
        bool readOnly = false,
        bool isSystemDisk = false,
        bool isOffline = false,
        bool? mounted = null,
        string androidUsage = "none")
    {
        return new JsonObject
        {
            ["key"] = key,
            ["path"] = path,
            ["displayName"] = displayName,
            ["sizeBytes"] = sizeBytes,
            ["logicalSectorSize"] = logicalSectorSize,
            ["mediumEvidence"] = mediumEvidence,
            ["readOnly"] = readOnly,
            ["isSystemDisk"] = isSystemDisk,
            ["isOffline"] = isOffline,
            ["mounted"] = mounted is null ? null : JsonValue.Create(mounted.Value),
            ["androidUsage"] = androidUsage,
        };
    }

    private static string Report(TfCardSource source, params JsonNode?[] media)
    {
        var array = new JsonArray();
        foreach (var item in media)
        {
            array.Add(item);
        }

        return new JsonObject
        {
            ["schemaVersion"] = 1,
            ["source"] = source == TfCardSource.Tablet ? "tablet" : "reader",
            ["media"] = array,
        }.ToJsonString();
    }

    private static TfCardCandidate Card(
        string key = "mmcblk1",
        long sizeBytes = 64 * GiB,
        int logicalSectorSize = 512,
        string mediumEvidence = "SD",
        bool readOnly = false,
        bool isSystemDisk = false,
        bool isOffline = false,
        bool? mounted = null,
        string androidUsage = "none")
    {
        return new TfCardCandidate(
            "tablet:" + key,
            "/dev/block/" + key,
            "SanDisk Extreme 64GB",
            sizeBytes,
            logicalSectorSize,
            mediumEvidence,
            readOnly,
            isSystemDisk,
            isOffline,
            mounted,
            androidUsage);
    }

    // ---------------------------------------------------------------- parsing

    [Fact]
    public void ParseCandidates_TabletSdCard_KeepsReportedIdentityAndPrefixesKey()
    {
        var candidates = TfCardSupport.ParseCandidates(Report(TfCardSource.Tablet, Medium()), TfCardSource.Tablet);

        var card = Assert.Single(candidates);
        Assert.Equal("tablet:mmcblk1", card.Key);
        Assert.Equal("/dev/block/mmcblk1", card.Path);
        Assert.Equal("SanDisk Extreme 64GB", card.DisplayName);
        Assert.Equal(64 * GiB, card.SizeBytes);
        Assert.Equal(512, card.LogicalSectorSize);
        Assert.Equal("SD", card.MediumEvidence);
        Assert.False(card.ReadOnly);
        Assert.False(card.IsSystemDisk);
        Assert.False(card.IsOffline);
        Assert.Null(card.Mounted);
        Assert.Equal("none", card.AndroidUsage);
    }

    [Theory]
    [InlineData("MMC", 512)]
    [InlineData("USB", 4096)]
    public void ParseCandidates_ReaderAcceptsMmcAndUsb_WithReaderPrefix(string evidence, int sectorSize)
    {
        var candidates = TfCardSupport.ParseCandidates(
            Report(TfCardSource.Reader, Medium(key: "disk2", mediumEvidence: evidence, logicalSectorSize: sectorSize)),
            TfCardSource.Reader);

        var card = Assert.Single(candidates);
        Assert.Equal("reader:disk2", card.Key);
        Assert.Equal(evidence, card.MediumEvidence);
        Assert.Equal(sectorSize, card.LogicalSectorSize);
    }

    [Fact]
    public void ParseCandidates_TabletRejectsUsbOnlyEvidence()
    {
        var candidates = TfCardSupport.ParseCandidates(
            Report(TfCardSource.Tablet, Medium(mediumEvidence: "USB")),
            TfCardSource.Tablet);

        Assert.Empty(candidates);
    }

    [Fact]
    public void ParseCandidates_EmptyMediaListIsValid()
    {
        Assert.Empty(TfCardSupport.ParseCandidates(Report(TfCardSource.Tablet), TfCardSource.Tablet));
        Assert.Empty(TfCardSupport.ParseCandidates(Report(TfCardSource.Reader), TfCardSource.Reader));
    }

    [Fact]
    public void ParseCandidates_RejectsRootSchemaAndSourceMismatch()
    {
        var wrongSchema = JsonNode.Parse(Report(TfCardSource.Tablet, Medium()))!.AsObject();
        wrongSchema["schemaVersion"] = 2;

        var wrongSource = JsonNode.Parse(Report(TfCardSource.Tablet, Medium()))!.AsObject();
        wrongSource["source"] = "reader";

        var missingSource = JsonNode.Parse(Report(TfCardSource.Tablet, Medium()))!.AsObject();
        missingSource.Remove("source");

        Assert.ThrowsAny<ArgumentException>(() => TfCardSupport.ParseCandidates(wrongSchema.ToJsonString(), TfCardSource.Tablet));
        Assert.ThrowsAny<ArgumentException>(() => TfCardSupport.ParseCandidates(wrongSource.ToJsonString(), TfCardSource.Tablet));
        Assert.ThrowsAny<ArgumentException>(() => TfCardSupport.ParseCandidates(missingSource.ToJsonString(), TfCardSource.Tablet));
    }

    [Theory]
    [InlineData("", 512)]
    [InlineData("mmcblk1", 0)]
    [InlineData("mmcblk1", 513)]
    public void ParseCandidates_RejectsMissingIdentityAndInvalidSectorSize(string key, int sectorSize)
    {
        var json = Report(TfCardSource.Reader, Medium(key: key, logicalSectorSize: sectorSize));

        Assert.ThrowsAny<ArgumentException>(() => TfCardSupport.ParseCandidates(json, TfCardSource.Reader));
    }

    [Fact]
    public void ParseCandidates_FiltersSystemReadOnlyOfflineAndAdoptedCards()
    {
        var json = Report(
            TfCardSource.Reader,
            Medium(key: "sd-ok"),
            Medium(key: "sd-system", mediumEvidence: "MMC", isSystemDisk: true),
            Medium(key: "sd-readonly", readOnly: true),
            Medium(key: "sd-offline", isOffline: true),
            Medium(key: "sd-adopted", androidUsage: "Adopted"));

        var candidates = TfCardSupport.ParseCandidates(json, TfCardSource.Reader);

        var card = Assert.Single(candidates);
        Assert.Equal("reader:sd-ok", card.Key);
    }

    // ---------------------------------------------------------------- space plan

    [Fact]
    public void Plan_AllocatesRootAndDataFromWholeCardCapacity()
    {
        var card = Card();
        var storage = new PackageStorage(1 * GiB, 8 * GiB, 1 * GiB, 4 * GiB);

        var plan = TfCardSupport.Plan(card, storage);

        Assert.Equal("tablet:mmcblk1", plan.TargetKey);
        Assert.Equal(64 * GiB, plan.TotalBytes);
        Assert.Equal(2 * MiB, plan.ReservedBytes);
        Assert.Equal(1 * GiB, plan.LinuxBootBytes);
        Assert.Equal(63 * GiB - 2 * MiB, plan.LinuxRootBytes);
        Assert.Equal(55 * GiB - 2 * MiB, plan.EstimatedLinuxDataBytes);
    }

    [Fact]
    public void Plan_FloorsCapacityToMiBAndRoundsBootUpToMiB()
    {
        var card = Card(sizeBytes: 64 * GiB + (MiB / 2));
        var storage = new PackageStorage(1 * GiB + 1, 8 * GiB, 1 * GiB, 4 * GiB);

        var plan = TfCardSupport.Plan(card, storage);

        Assert.Equal(64 * GiB, plan.TotalBytes);
        Assert.Equal(1 * GiB + MiB, plan.LinuxBootBytes);
        Assert.Equal(63 * GiB - 3 * MiB, plan.LinuxRootBytes);
        Assert.Equal(55 * GiB - 3 * MiB, plan.EstimatedLinuxDataBytes);
        Assert.Equal(2 * MiB, plan.ReservedBytes);
        Assert.Equal(64 * GiB + (MiB / 2), card.SizeBytes);
    }

    [Fact]
    public void Plan_RejectsCardsBelowTheRootFloor()
    {
        // 8 GiB card cannot carry the 32 GiB root floor plus the 2 MiB reserve.
        AssertPlanRejected(Card(sizeBytes: 8 * GiB), new PackageStorage(1 * GiB, 8 * GiB, 1 * GiB, 4 * GiB));
    }

    [Fact]
    public void Plan_RejectsOverflowingBootSize()
    {
        AssertPlanRejected(Card(), new PackageStorage(long.MaxValue - 1, 8 * GiB, 1 * GiB, 4 * GiB));
    }

    [Fact]
    public void Plan_RejectsUnsafeCandidates()
    {
        var storage = new PackageStorage(1 * GiB, 8 * GiB, 1 * GiB, 4 * GiB);

        AssertPlanRejected(Card(readOnly: true), storage);
        AssertPlanRejected(Card(isSystemDisk: true), storage);
        AssertPlanRejected(Card(isOffline: true), storage);
        AssertPlanRejected(Card(androidUsage: "adopted"), storage);
    }

    // ---------------------------------------------------------------- discovery commands

    [Fact]
    public void BuildTabletCommand_UsesAdbExecOutInspectionForOneSerialWithFiniteTimeout()
    {
        var command = TfCardDiscovery.BuildTabletCommand("/usr/bin/adb", "R5CT9001ABC");

        Assert.Equal("/usr/bin/adb", command.Executable);
        Assert.Equal(
            new[] { "-s", "R5CT9001ABC", "exec-out", "/usr/libexec/armada/armada-inspect-tf", "--json" },
            command.Arguments);
        Assert.True(command.Timeout > TimeSpan.Zero);
        Assert.True(command.Timeout <= MaxDiscoveryTimeout, $"timeout must stay finite and short: {command.Timeout}");
    }

    [Fact]
    public void BuildTabletCommand_RejectsMissingOrBroadSerial()
    {
        Assert.ThrowsAny<ArgumentException>(() => TfCardDiscovery.BuildTabletCommand("/usr/bin/adb", string.Empty));
        Assert.ThrowsAny<ArgumentException>(() => TfCardDiscovery.BuildTabletCommand("/usr/bin/adb", "   "));
        Assert.ThrowsAny<ArgumentException>(() => TfCardDiscovery.BuildTabletCommand("/usr/bin/adb", "all"));
        Assert.ThrowsAny<ArgumentException>(() => TfCardDiscovery.BuildTabletCommand("/usr/bin/adb", "-s all"));
    }

    [Fact]
    public void BuildReaderCommand_IsReadOnlyGetDiskWithNoMutatingVerb()
    {
        var command = TfCardDiscovery.BuildReaderCommand();

        var executable = command.Executable.ToLowerInvariant();
        Assert.True(
            executable.Contains("powershell") || executable.Contains("pwsh"),
            $"unexpected reader executable: {command.Executable}");

        var joined = string.Join(' ', command.Arguments).ToLowerInvariant();
        Assert.Contains("get-disk", joined);
        foreach (var forbidden in new[]
                 {
                     "format-volume", "clear-disk", "initialize-disk", "set-disk",
                     "new-partition", "remove-partition", "write",
                 })
        {
            Assert.DoesNotContain(forbidden, joined);
        }

        Assert.True(command.Timeout > TimeSpan.Zero);
        Assert.True(command.Timeout <= MaxDiscoveryTimeout, $"timeout must stay finite and short: {command.Timeout}");
    }

    // ---------------------------------------------------------------- target aware package validation

    [Fact]
    public void LegacyPackageWithoutInstallTargets_IsInternalOnly()
    {
        _ = RequireArtifactRoot();
        using var package = new TempPackageDirectory();
        PackageFixture.WritePackage(package.Path, "TB322FC");

        var legacy = PackageReader.Validate(package.Path, "TB322FC");
        Assert.True(legacy.IsValid);
        Assert.NotNull(legacy.Storage);

        var internalTarget = PackageReader.Validate(package.Path, "TB322FC", InstallationTarget.Internal);
        Assert.True(internalTarget.IsValid);

        var tfTarget = PackageReader.Validate(package.Path, "TB322FC", InstallationTarget.TfCard);
        Assert.False(tfTarget.IsValid);
        Assert.NotEmpty(tfTarget.Reasons);
        Assert.Null(tfTarget.Storage);
    }

    [Fact]
    public void DeclaredInstallTargets_DecideWhichTargetsAcceptThePackage()
    {
        _ = RequireArtifactRoot();
        using var package = new TempPackageDirectory();
        PackageFixture.WritePackage(package.Path, "TB322FC");

        var metadata = ReadMetadata(package.Path);
        metadata["installTargets"] = new JsonArray("internal", "tf");
        WriteMetadata(package.Path, metadata);

        Assert.True(PackageReader.Validate(package.Path, "TB322FC").IsValid);
        Assert.True(PackageReader.Validate(package.Path, "TB322FC", InstallationTarget.Internal).IsValid);

        var bothTargets = PackageReader.Validate(package.Path, "TB322FC", InstallationTarget.TfCard);
        Assert.True(bothTargets.IsValid);
        Assert.True(bothTargets.TestOnly);

        metadata = ReadMetadata(package.Path);
        metadata["installTargets"] = new JsonArray("tf");
        WriteMetadata(package.Path, metadata);

        Assert.True(PackageReader.Validate(package.Path, "TB322FC", InstallationTarget.TfCard).IsValid);

        var internalOnly = PackageReader.Validate(package.Path, "TB322FC", InstallationTarget.Internal);
        Assert.False(internalOnly.IsValid);
        Assert.NotEmpty(internalOnly.Reasons);
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("[\"bogus\"]")]
    [InlineData("[\"tf\",\"tf\"]")]
    [InlineData("\"tf\"")]
    public void MalformedInstallTargets_AreRejectedForEveryTarget(string targetsJson)
    {
        _ = RequireArtifactRoot();
        using var package = new TempPackageDirectory();
        PackageFixture.WritePackage(package.Path, "TB322FC");

        var metadata = ReadMetadata(package.Path);
        metadata["installTargets"] = JsonNode.Parse(targetsJson);
        WriteMetadata(package.Path, metadata);

        Assert.False(PackageReader.Validate(package.Path, "TB322FC", InstallationTarget.TfCard).IsValid);
        Assert.False(PackageReader.Validate(package.Path, "TB322FC", InstallationTarget.Internal).IsValid);
    }

    [Fact]
    public void TargetAwareValidation_StillEnforcesFileAndHashContract()
    {
        _ = RequireArtifactRoot();
        using var package = new TempPackageDirectory();
        PackageFixture.WritePackage(package.Path, "TB322FC");

        var metadata = ReadMetadata(package.Path);
        metadata["installTargets"] = new JsonArray("internal", "tf");
        WriteMetadata(package.Path, metadata);

        // Replace one artefact with content that cannot match the declared bytes / SHA-256.
        File.WriteAllBytes(Path.Combine(package.Path, PackageFixture.LinuxBootFileName), new byte[] { 0x00, 0x01, 0x02 });

        var legacy = PackageReader.Validate(package.Path, "TB322FC");
        Assert.False(legacy.IsValid);
        Assert.NotEmpty(legacy.Reasons);

        var tfTarget = PackageReader.Validate(package.Path, "TB322FC", InstallationTarget.TfCard);
        Assert.False(tfTarget.IsValid);
        Assert.NotEmpty(tfTarget.Reasons);
        Assert.Null(tfTarget.Storage);
    }

    // ---------------------------------------------------------------- helpers

    private static void AssertPlanRejected(TfCardCandidate card, PackageStorage storage)
    {
        var thrown = Record.Exception(() => TfCardSupport.Plan(card, storage));

        Assert.NotNull(thrown);
        Assert.True(
            thrown is ArgumentException or InvalidOperationException,
            $"expected ArgumentException or InvalidOperationException, got {thrown!.GetType().Name}: {thrown.Message}");
    }

    /// <summary>
    /// The suite never invents its own scratch location: the managed test run has to provide
    /// TEST_ARTIFACT_ROOT, and a missing value is a test failure rather than a silent fallback.
    /// </summary>
    private static string RequireArtifactRoot()
    {
        var root = Environment.GetEnvironmentVariable("TEST_ARTIFACT_ROOT");
        Assert.False(
            string.IsNullOrWhiteSpace(root),
            "TEST_ARTIFACT_ROOT must be set by the test manager before this suite runs.");
        return root!;
    }

    private static JsonObject ReadMetadata(string directory)
        => JsonNode.Parse(File.ReadAllText(PackageFixture.MetadataPath(directory)))!.AsObject();

    private static void WriteMetadata(string directory, JsonNode metadata)
        => File.WriteAllText(
            PackageFixture.MetadataPath(directory),
            metadata.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
}
