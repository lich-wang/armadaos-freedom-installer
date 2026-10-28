using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Behavioural specifications for the package contract v1. Every test builds the shared on-disk
/// fixture, mutates exactly one field of package.json through <see cref="JsonObject"/> and asserts the
/// public result of <see cref="PackageReader.Validate"/>. Nothing here matches implementation source
/// text: the assertions are about observable behaviour only.
/// <para>
/// The fixture package is a few bytes per artefact. It is not firmware, it is not flashable and it
/// never contains a vendor boot image.
/// </para>
/// </summary>
public sealed class PackageContractTests
{
    private const string ModelA = "TB322FC";
    private const string ModelB = "TB323FU";

    private static readonly JsonSerializerOptions WriteOptions = new() { WriteIndented = true };

    // ------------------------------------------------------------ the two supported generations

    [Theory]
    [InlineData(ModelA)]
    [InlineData(ModelB)]
    public void Validate_ValidPackageForBothGenerationsIsAcceptedAndExposesMetadata(string deviceModel)
    {
        using var fixture = new TempPackageDirectory();
        PackageFixture.WritePackage(fixture.Path, deviceModel);

        var result = PackageReader.Validate(fixture.Path, deviceModel);

        Assert.True(result.IsValid, string.Join("; ", result.Reasons));
        Assert.Empty(result.Reasons);
        Assert.NotNull(result.Storage);
        Assert.True(result.TestOnly);
        Assert.Equal(PackageFixture.PackageId, result.PackageId);
        Assert.Equal(PackageFixture.PackageVersion, result.Version);
        Assert.Null(result.DeploymentKind);

        var expectedFingerprint = Convert.ToHexString(
            SHA256.HashData(File.ReadAllBytes(PackageFixture.MetadataPath(fixture.Path))));
        Assert.Equal(expectedFingerprint, result.ManifestFingerprint);
    }

    [Fact]
    public void Validate_PackageForOneGenerationIsRejectedForTheOther()
    {
        using var fixture = new TempPackageDirectory();
        PackageFixture.WritePackage(fixture.Path, ModelB);

        var result = PackageReader.Validate(fixture.Path, ModelA);

        AssertRejected(result, "deviceModel");
    }

    [Fact]
    public void Validate_TestOnlyFalseStaysStructurallyValidButIsStillFlaggedAsTestOnly()
    {
        var result = ValidateMutated(ModelA, metadata => metadata["testOnly"] = false);

        Assert.True(result.IsValid, string.Join("; ", result.Reasons));
        Assert.False(result.TestOnly);
        Assert.Equal(PackageFixture.PackageId, result.PackageId);
    }

    // ---------------------------------------------------------------- required identity fields

    [Fact]
    public void Validate_MissingPackageIdIsRejected()
    {
        var result = ValidateMutated(ModelA, metadata => metadata.Remove("packageId"));

        AssertRejected(result, "packageId");
    }

    [Fact]
    public void Validate_EmptyPackageIdIsRejected()
    {
        var result = ValidateMutated(ModelA, metadata => metadata["packageId"] = "   ");

        AssertRejected(result, "packageId");
    }

    [Fact]
    public void Validate_MissingOrEmptyVersionIsRejected()
    {
        AssertRejected(ValidateMutated(ModelA, metadata => metadata.Remove("version")), "version");
        AssertRejected(ValidateMutated(ModelA, metadata => metadata["version"] = string.Empty), "version");
    }

    [Fact]
    public void Validate_VersionLatestIsRejected()
    {
        AssertRejected(ValidateMutated(ModelA, metadata => metadata["version"] = "latest"), "version");
        AssertRejected(ValidateMutated(ModelA, metadata => metadata["version"] = "LATEST"), "version");
    }

    [Fact]
    public void Validate_LegacyModelFieldIsNeverUsedAsFallback()
    {
        var result = ValidateMutated(
            ModelA,
            metadata =>
            {
                metadata.Remove("deviceModel");
                metadata["model"] = ModelA;
            });

        AssertRejected(result, "deviceModel");
    }

    [Fact]
    public void Validate_MissingTestOnlyIsRejectedAndResultStaysFailSafe()
    {
        var result = ValidateMutated(ModelA, metadata => metadata.Remove("testOnly"));

        // A package without testOnly must never be readable as a production package.
        AssertRejected(result, "testOnly");
        Assert.True(result.TestOnly);
    }

    [Fact]
    public void Validate_NonBooleanTestOnlyIsRejected()
    {
        AssertRejected(ValidateMutated(ModelA, metadata => metadata["testOnly"] = "true"), "testOnly");
    }

    [Fact]
    public void Validate_UnknownSchemaVersionIsRejected()
    {
        // Schema 2 is the direct EDL raw contract and is covered by EdlRawPackageContractTests; only a
        // genuinely unknown version number is rejected here.
        AssertRejected(ValidateMutated(ModelA, metadata => metadata["schemaVersion"] = 3), "schemaVersion");
        AssertRejected(ValidateMutated(ModelA, metadata => metadata["schemaVersion"] = 0), "schemaVersion");
    }

    // ----------------------------------------------------------------------- compatible block

    [Fact]
    public void Validate_CompatibleMustMatchTheDeviceModel()
    {
        AssertRejected(
            ValidateMutated(ModelA, metadata => metadata["compatible"]!.AsObject()["soc"] = "SM9999"),
            "compatible.soc");

        // elden belongs to TB322FC, baldur to TB323FU.
        AssertRejected(
            ValidateMutated(ModelA, metadata => metadata["compatible"]!.AsObject()["device"] = "baldur"),
            "compatible.device");

        AssertRejected(
            ValidateMutated(ModelB, metadata => metadata["compatible"]!.AsObject()["soc"] = "SM8750"),
            "compatible.soc");
    }

    [Fact]
    public void Validate_MissingCompatibleBlockIsRejected()
    {
        AssertRejected(ValidateMutated(ModelA, metadata => metadata.Remove("compatible")), "compatible");
        AssertRejected(
            ValidateMutated(ModelA, metadata => metadata["compatible"]!.AsObject().Remove("device")),
            "compatible.device");
    }

    // ------------------------------------------------------------------------ deployment block

    [Fact]
    public void Validate_OriginOutsideTheProjectRegistryIsRejected()
    {
        // Upstream project but not the allowed image path scope.
        AssertRejected(
            ValidateMutated(
                ModelA,
                metadata => Deployment(metadata)["origin"] = "ostree-image-signed:docker://ghcr.io/other/armadaos-freedom:stable"),
            "origin");

        // Arbitrary registry.
        AssertRejected(
            ValidateMutated(
                ModelA,
                metadata => Deployment(metadata)["origin"] = "ostree-image-signed:docker://evil.example/armadaos-freedom:stable"),
            "origin");

        // Plain https origin instead of the signed ostree form.
        AssertRejected(
            ValidateMutated(
                ModelA,
                metadata => Deployment(metadata)["origin"] = "https://ghcr.io/mydanyi/armadaos-freedom:stable"),
            "origin");
    }

    [Fact]
    public void Validate_OriginChannelMustBeStableBetaOrTesting()
    {
        AssertRejected(
            ValidateMutated(
                ModelA,
                metadata => Deployment(metadata)["origin"] = "ostree-image-signed:docker://ghcr.io/mydanyi/armadaos-freedom:nightly"),
            "origin");

        AssertRejected(
            ValidateMutated(
                ModelA,
                metadata => Deployment(metadata)["origin"] = "ostree-image-signed:docker://ghcr.io/mydanyi/armadaos-freedom:stable:extra"),
            "origin");
    }

    [Fact]
    public void Validate_OriginWithPinnedManifestDigestIsAccepted()
    {
        var result = ValidateMutated(
            ModelA,
            metadata => Deployment(metadata)["origin"] = PackageFixture.ProjectOrigin + "@sha256:" + PackageFixture.Commit);

        Assert.True(result.IsValid, string.Join("; ", result.Reasons));
    }

    [Fact]
    public void Validate_DeploymentKindMustBeOstreeOfflineSeed()
    {
        AssertRejected(
            ValidateMutated(ModelA, metadata => Deployment(metadata)["kind"] = "raw-disk-image"),
            "deployment.kind");
    }

    [Fact]
    public void Validate_CommitAndManifestDigestMustBeLowerCaseSha256()
    {
        AssertRejected(
            ValidateMutated(ModelA, metadata => Deployment(metadata)["commit"] = PackageFixture.Commit.ToUpperInvariant()),
            "deployment.commit");

        AssertRejected(
            ValidateMutated(ModelA, metadata => Deployment(metadata)["commit"] = "0123456789abcdef"),
            "deployment.commit");

        AssertRejected(
            ValidateMutated(ModelA, metadata => Deployment(metadata)["manifestDigest"] = PackageFixture.Commit),
            "deployment.manifestDigest");

        AssertRejected(
            ValidateMutated(ModelA, metadata => Deployment(metadata)["manifestDigest"] = "sha512:" + PackageFixture.Commit),
            "deployment.manifestDigest");
    }

    [Fact]
    public void Validate_MissingDeploymentBlockIsRejected()
    {
        AssertRejected(ValidateMutated(ModelA, metadata => metadata.Remove("deployment")), "deployment");
    }

    // ------------------------------------------------------------------------- artifacts rules

    [Fact]
    public void Validate_MissingRequiredRoleIsRejected()
    {
        AssertRejected(
            ValidateMutated(ModelA, metadata => Artifacts(metadata).Remove(Artifact(metadata, "kernel"))),
            "kernel");

        AssertRejected(
            ValidateMutated(ModelA, metadata => Artifacts(metadata).Remove(Artifact(metadata, "runtime"))),
            "runtime");
    }

    [Fact]
    public void Validate_ProvisionalRolesAreNoLongerAccepted()
    {
        var result = ValidateMutated(
            ModelA,
            metadata =>
            {
                Artifact(metadata, "ostree-seed")["role"] = "linux-root";
                Artifact(metadata, "kernel")["role"] = "linux-boot";
                Artifact(metadata, "dtb")["role"] = "system-image";
            });

        AssertRejected(result, "ostree-seed");
    }

    [Fact]
    public void Validate_RelativeTraversalInArtifactPathIsRejected()
    {
        AssertRejected(
            ValidateMutated(ModelA, metadata => Artifact(metadata, "kernel")["file"] = "../outside.bin"),
            "artifact");

        AssertRejected(
            ValidateMutated(ModelA, metadata => Artifact(metadata, "kernel")["file"] = "/etc/passwd"),
            "artifact");
    }

    [Fact]
    public void Validate_CorruptedArtifactHashIsRejected()
    {
        AssertRejected(
            ValidateMutated(ModelA, metadata => Artifact(metadata, "kernel")["sha256"] = new string('0', 64)),
            "kernel");
    }

    [Fact]
    public void Validate_WrongDeclaredLengthIsRejected()
    {
        AssertRejected(
            ValidateMutated(ModelA, metadata => Artifact(metadata, "runtime")["bytes"] = 4096),
            "runtime");
    }

    // ----------------------------------------------------------------- storage and boot profile

    [Fact]
    public void Validate_MissingStorageFieldIsRejected()
    {
        AssertRejected(
            ValidateMutated(ModelA, metadata => metadata["storage"]!.AsObject().Remove("deploymentScratchBytes")),
            "deploymentScratchBytes");
    }

    [Fact]
    public void Validate_WrongBootFormatOrPartitionBytesIsRejected()
    {
        AssertRejected(
            ValidateMutated(ModelA, metadata => Boot(metadata)["format"] = "android-boot-v3"),
            "bootCompatibility.format");

        AssertRejected(
            ValidateMutated(ModelA, metadata => Boot(metadata)["partitionBytes"] = 67_108_864),
            "bootCompatibility.partitionBytes");
    }

    [Fact]
    public void Validate_EmptyFirmwareVersionsIsRejected()
    {
        AssertRejected(
            ValidateMutated(ModelA, metadata => Boot(metadata)["firmwareVersions"] = new JsonArray()),
            "firmwareVersions");

        AssertRejected(
            ValidateMutated(ModelA, metadata => Boot(metadata)["firmwareVersions"] = new JsonArray(JsonValue.Create("  "))),
            "firmwareVersions");
    }

    [Fact]
    public void Validate_MissingBootCompatibilityIsRejected()
    {
        AssertRejected(ValidateMutated(ModelA, metadata => metadata.Remove("bootCompatibility")), "bootCompatibility");
    }

    // ------------------------------------------------------------------ tools compatibility

    [Fact]
    public void Validate_UnsupportedToolProtocolIsRejected()
    {
        AssertRejected(
            ValidateMutated(ModelA, metadata => Tools(metadata)["installerProtocol"] = 2),
            "installerProtocol");

        AssertRejected(
            ValidateMutated(ModelA, metadata => Tools(metadata)["maintenanceProtocol"] = 0),
            "maintenanceProtocol");

        AssertRejected(
            ValidateMutated(ModelA, metadata => Tools(metadata).Remove("maintenanceProtocol")),
            "maintenanceProtocol");
    }

    [Fact]
    public void Validate_MissingToolsCompatibilityIsRejected()
    {
        AssertRejected(ValidateMutated(ModelA, metadata => metadata.Remove("toolsCompatibility")), "toolsCompatibility");
    }

    // ------------------------------------------------------------- default value of the result

    [Fact]
    public void Validate_ResultDefaultsToTestOnlyAndCarriesNoMetadataBeforeSuccess()
    {
        var failed = new PackageValidationResult(false, new[] { "synthetic failure" }, null);

        Assert.True(failed.TestOnly);
        Assert.Null(failed.PackageId);
        Assert.Null(failed.Version);
        Assert.Null(failed.ManifestFingerprint);
    }

    // ------------------------------------------------------------------------ helpers

    private static PackageValidationResult ValidateMutated(string deviceModel, Action<JsonObject> mutate)
    {
        using var fixture = new TempPackageDirectory();
        PackageFixture.WritePackage(fixture.Path, deviceModel);

        var metadata = JsonNode.Parse(File.ReadAllText(PackageFixture.MetadataPath(fixture.Path)))!.AsObject();
        mutate(metadata);
        File.WriteAllText(PackageFixture.MetadataPath(fixture.Path), metadata.ToJsonString(WriteOptions));

        return PackageReader.Validate(fixture.Path, deviceModel);
    }

    private static JsonObject Deployment(JsonObject metadata) => metadata["deployment"]!.AsObject();

    private static JsonObject Boot(JsonObject metadata) => metadata["bootCompatibility"]!.AsObject();

    private static JsonObject Tools(JsonObject metadata) => metadata["toolsCompatibility"]!.AsObject();

    private static JsonArray Artifacts(JsonObject metadata) => metadata["artifacts"]!.AsArray();

    private static JsonObject Artifact(JsonObject metadata, string role) =>
        Artifacts(metadata)
            .Select(entry => entry!.AsObject())
            .First(entry => entry["role"]!.GetValue<string>() == role);

    /// <summary>
    /// A rejected package must report reasons, must not expose storage and must not expose any
    /// declared metadata: those values are filled in only when the whole package validated.
    /// </summary>
    private static void AssertRejected(PackageValidationResult result, string fieldHint)
    {
        Assert.False(result.IsValid);
        Assert.NotEmpty(result.Reasons);
        Assert.Null(result.Storage);
        Assert.Null(result.PackageId);
        Assert.Null(result.Version);
        Assert.Null(result.ManifestFingerprint);
        Assert.True(result.TestOnly);
        Assert.Contains(result.Reasons, reason => reason.Contains(fieldHint, StringComparison.OrdinalIgnoreCase));
    }
}
