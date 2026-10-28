using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Contract v1 / API-v3 (package schema 2, direct EDL raw) specifications: the approved metadata
/// declarations (model, optional coupled Android profile/firmware group), artifacts, payload hashes,
/// raw image declarations and boot recipe.
/// <para>
/// The device model, profile id, hardware id and declared builds are generic package metadata: they are
/// shape and consistency checked, never pinned to one device. Accepting them here is not a device
/// support, loader, Complete or physical-test statement, and a standard common package without the
/// optional group is equally not a permission to write any device.
/// </para>
/// <para>
/// The fixture is synthetic and tiny: the two "compressed" raw roles are real gzip streams of a few KiB
/// whose declared expanded image is only a standalone declaration, because this reader validates the
/// declarations and the physical compressed/ordinary file length and SHA-256 - it does not expand an
/// image, read a filesystem superblock or claim that any of these files is Ready, bootable or flashable.
/// The ordinary runtime role is 4194304 bytes because the contract fixes that size. No real package,
/// raw image, backup or device input is touched.
/// </para>
/// </summary>
public sealed class EdlRawPackageContractTests
{
    private const long GiB = 1073741824L;

    /// <summary>
    /// A well-formed producer revision after the legacy one. Rejection tests that do not touch the source
    /// commit declare it, so their diagnostic can never come from a stale pinned source revision.
    /// </summary>
    private const string FutureSourceCommit = "3c786ba2e7582461c619072bbf23650b39efcd51";

    // ------------------------------------------------------------------------ direct read success

    [Fact]
    public void ReadEdlRawContract_ReturnsTheCompleteApprovedG4Metadata()
    {
        using var fixture = EdlRawFixture.Create();

        var contract = PackageReader.ReadEdlRawContract(fixture.Path, EdlRawFixture.Model);

        Assert.Equal(Path.GetFullPath(fixture.Path), contract.PackageDirectory);
        Assert.Equal(EdlRawFixture.PackageId, contract.PackageId);
        Assert.Equal(EdlRawFixture.PackageVersion, contract.Version);
        Assert.Equal("TB322FC", contract.DeviceModel);
        Assert.Equal(EdlRawFixture.SourceCommit, contract.SourceCommit);
        Assert.Equal(40, contract.SourceCommit.Length);
        Assert.True(contract.TestOnly);
        Assert.Equal(fixture.ManifestFingerprint, contract.ManifestFingerprint);

        Assert.Equal(1L * GiB, contract.Storage.LinuxBootBytes);
        Assert.Equal(20L * GiB, contract.Storage.SystemRequiredBytes);
        Assert.Equal(0L, contract.Storage.DeploymentScratchBytes);
        Assert.Equal(8L * GiB, contract.Storage.MinimumLinuxDataBytes);

        Assert.Equal(EdlRawFixture.ProfileId, contract.EdlProfileId);
        Assert.Equal(EdlRawFixture.HardwareId, contract.HardwareId);
        Assert.Equal(EdlRawFixture.AndroidBuild, contract.AndroidBuild);
        Assert.Equal(new[] { EdlRawFixture.AndroidBuild }, contract.FirmwareVersions);
    }

    [Fact]
    public void ReadEdlRawContract_ResolvesTheSevenArtifactsAndTheirObservedHashes()
    {
        using var fixture = EdlRawFixture.Create();

        var contract = PackageReader.ReadEdlRawContract(fixture.Path, EdlRawFixture.Model);

        Assert.Equal(7, contract.Artifacts.Count);
        foreach (var role in EdlRawFixture.Roles)
        {
            Assert.True(contract.Artifacts.ContainsKey(role), role);
        }

        var kernel = contract.Artifacts["kernel"];
        Assert.Equal("kernel", kernel.Role);
        Assert.Equal(EdlRawFixture.KernelFile, kernel.RelativePath);
        Assert.Equal(
            Path.GetFullPath(Path.Combine(fixture.Path, EdlRawFixture.KernelFile)),
            kernel.FullPath);
        Assert.Equal(fixture.BytesOf(EdlRawFixture.KernelFile), kernel.Bytes);
        Assert.Equal(fixture.Sha256Of(EdlRawFixture.KernelFile), kernel.Sha256);

        // Hashes are normalised to uppercase hexadecimal, so a declaration and the observed value are
        // directly comparable and a caller never has to guess a case.
        Assert.Equal(kernel.Sha256, kernel.Sha256.ToUpperInvariant());

        // The contract fixes the runtime payload at exactly 4194304 bytes.
        var runtime = contract.Artifacts["runtime"];
        Assert.Equal(4194304L, runtime.Bytes);
        Assert.Equal(4194304L, new FileInfo(runtime.FullPath).Length);
    }

    [Fact]
    public void ReadEdlRawContract_DescribesBootAndRootImagesFromTheirDeclarations()
    {
        using var fixture = EdlRawFixture.Create();

        var contract = PackageReader.ReadEdlRawContract(fixture.Path, EdlRawFixture.Model);

        var boot = contract.BootImage;
        Assert.Equal("linux-boot-raw", boot.Artifact.Role);
        Assert.Equal(EdlRawFixture.BootImageFile, boot.Artifact.RelativePath);
        Assert.Equal(
            Path.GetFullPath(Path.Combine(fixture.Path, EdlRawFixture.BootImageFile)),
            boot.Artifact.FullPath);
        Assert.Equal(fixture.BytesOf(EdlRawFixture.BootImageFile), boot.Artifact.Bytes);
        Assert.Equal(fixture.Sha256Of(EdlRawFixture.BootImageFile), boot.Artifact.Sha256);
        Assert.Equal("gzip", boot.Compression);
        Assert.Equal(boot.Artifact.Bytes, boot.CompressedBytes);
        Assert.Equal(boot.Artifact.Sha256, boot.CompressedSha256);
        Assert.Equal(1L * GiB, boot.ExpandedBytes);
        Assert.Equal(EdlRawFixture.BootExpandedSha, boot.ExpandedSha256);
        Assert.Equal(4096, boot.SectorSize);
        Assert.Equal("ext4", boot.FsType);
        Assert.Equal(Guid.Parse(EdlRawFixture.BootUuid), boot.FsUuid);
        Assert.IsType<Guid>(boot.FsUuid);
        Assert.Equal(1L * GiB, boot.MinimumPartitionBytes);

        var root = contract.RootImage;
        Assert.Equal("linux-root-raw", root.Artifact.Role);
        Assert.Equal(EdlRawFixture.RootImageFile, root.Artifact.RelativePath);
        Assert.Equal(fixture.BytesOf(EdlRawFixture.RootImageFile), root.CompressedBytes);
        Assert.Equal(fixture.Sha256Of(EdlRawFixture.RootImageFile), root.CompressedSha256);
        Assert.Equal(EdlRawFixture.RootExpandedBytes, root.ExpandedBytes);
        Assert.Equal(EdlRawFixture.RootExpandedSha, root.ExpandedSha256);

        // The declared root image is 4096 aligned, at least that big and reported as btrfs.
        Assert.Equal(0L, root.ExpandedBytes % 4096);
        Assert.Equal(4096, root.SectorSize);
        Assert.Equal("btrfs", root.FsType);
        Assert.Equal(Guid.Parse(EdlRawFixture.RootUuid), root.FsUuid);
        Assert.True(root.MinimumPartitionBytes >= root.ExpandedBytes);
        Assert.Equal(0L, root.MinimumPartitionBytes % 4096);
    }

    [Fact]
    public void ReadEdlRawContract_KeepsDeploymentCommitAndBootChecksumIndependent()
    {
        using var fixture = EdlRawFixture.Create();

        var contract = PackageReader.ReadEdlRawContract(fixture.Path, EdlRawFixture.Model);

        Assert.Equal("edl-raw-v1", contract.Deployment.Kind);
        Assert.Equal(EdlRawFixture.DeploymentCommit, contract.Deployment.Commit);
        Assert.Equal("sha256:" + EdlRawFixture.DeploymentCommit, contract.Deployment.ManifestDigest);
        Assert.Equal(EdlRawFixture.Origin, contract.Deployment.Origin);
        Assert.Equal(EdlRawFixture.BootChecksum, contract.Deployment.BootChecksum);

        // Two separate producer facts: the reader must neither derive one from the other nor assume
        // they are equal.
        Assert.NotEqual(contract.Deployment.Commit, contract.Deployment.BootChecksum);
    }

    [Fact]
    public void ReadEdlRawContract_BindsTheBootRecipeToTheImageUuids()
    {
        using var fixture = EdlRawFixture.Create();

        var contract = PackageReader.ReadEdlRawContract(fixture.Path, EdlRawFixture.Model);

        var recipe = contract.BootRecipe;
        Assert.IsType<Guid>(recipe.BootUuid);
        Assert.IsType<Guid>(recipe.RootUuid);
        Assert.Equal(Guid.Parse(EdlRawFixture.BootUuid), recipe.BootUuid);
        Assert.Equal(Guid.Parse(EdlRawFixture.RootUuid), recipe.RootUuid);
        Assert.NotEqual(Guid.Empty, recipe.BootUuid);
        Assert.NotEqual(Guid.Empty, recipe.RootUuid);
        Assert.NotEqual(recipe.BootUuid, recipe.RootUuid);
        Assert.Equal(contract.BootImage.FsUuid, recipe.BootUuid);
        Assert.Equal(contract.RootImage.FsUuid, recipe.RootUuid);

        Assert.Equal(EdlRawFixture.NormalBootArgs, recipe.NormalBootArgs);
        Assert.Equal(EdlRawFixture.NormalBootArgs + EdlRawFixture.DiagnosticSuffix, recipe.DiagnosticBootArgs);
        Assert.Equal("android", recipe.DefaultEntry);

        Assert.Equal(1, CountOccurrences(recipe.NormalBootArgs, "root=UUID=" + EdlRawFixture.RootUuid));
        Assert.Equal(1, CountOccurrences(recipe.NormalBootArgs, "boot=UUID=" + EdlRawFixture.BootUuid));
        Assert.Contains(
            "/ostree/boot.0/default/" + EdlRawFixture.BootChecksum + "/0",
            recipe.NormalBootArgs,
            StringComparison.Ordinal);
    }

    [Fact]
    public void ReadEdlRawContract_TestOnlyFalseIsReadWithoutBecomingAReadinessClaim()
    {
        using var fixture = EdlRawFixture.Create();
        var metadata = fixture.ReadMetadata();
        metadata["testOnly"] = false;
        fixture.WriteMetadata(metadata);

        var contract = PackageReader.ReadEdlRawContract(fixture.Path, EdlRawFixture.Model);

        Assert.False(contract.TestOnly);
        Assert.Equal(EdlRawFixture.PackageId, contract.PackageId);
    }

    [Theory]
    [InlineData("boot.0")]
    [InlineData("boot.1")]
    [InlineData("extra-argument")]
    public void ReadEdlRawContract_AcceptsBothOstreeIndexesAndExtraProducerArguments(string variant)
    {
        using var fixture = EdlRawFixture.Create();
        var metadata = fixture.ReadMetadata();

        var normal = variant switch
        {
            "boot.1" => EdlRawFixture.NormalBootArgs.Replace("/boot.0/", "/boot.1/", StringComparison.Ordinal),
            "extra-argument" => "quiet " + EdlRawFixture.NormalBootArgs,
            _ => EdlRawFixture.NormalBootArgs,
        };

        SetBootArgs(metadata, normal);
        fixture.WriteMetadata(metadata);

        var contract = PackageReader.ReadEdlRawContract(fixture.Path, EdlRawFixture.Model);

        Assert.Equal(normal, contract.BootRecipe.NormalBootArgs);
        Assert.Equal(normal + EdlRawFixture.DiagnosticSuffix, contract.BootRecipe.DiagnosticBootArgs);
        Assert.Equal(1, CountOccurrences(contract.BootRecipe.NormalBootArgs, "root=UUID=" + EdlRawFixture.RootUuid));
    }

    // ----------------------------------------------------------------- source commit provenance

    [Theory]
    [InlineData("244b74516d99d06cb0518609ce4b842ab278be8a")]
    [InlineData("16b2a2b73526c8c3325936795af13200563d7dda")]
    [InlineData("3c786ba2e7582461c619072bbf23650b39efcd51")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("0000000000000000000000000000000000000001")]
    public void ReadEdlRawContract_AcceptsAndPreservesValidSourceCommits(string sourceCommit)
    {
        using var fixture = EdlRawFixture.Create();
        var metadata = fixture.ReadMetadata();

        // Only the source commit differs from the otherwise valid fixture.
        metadata["sourceCommit"] = sourceCommit;
        fixture.WriteMetadata(metadata);

        var contract = PackageReader.ReadEdlRawContract(fixture.Path, EdlRawFixture.Model);

        // The producer revision is a declared package fact: any well-formed revision is handed back with
        // exactly its declared spelling, never replaced by a pinned constant or rewritten in any case.
        Assert.Equal(sourceCommit, contract.SourceCommit);

        // The same fixture must be accepted by the other real entry point too: acceptance belongs to the
        // shared contract, not to one of the two code paths.
        var result = PackageReader.Validate(fixture.Path, EdlRawFixture.Model, InstallationTarget.Internal);

        Assert.True(result.IsValid, string.Join("; ", result.Reasons));
    }

    // ------------------------------------------------------- existing Validate dispatch for schema 2

    [Fact]
    public void Validate_DirectEdlSchema2IsAcceptedForInternalAndExposesTheCommonFields()
    {
        using var fixture = EdlRawFixture.Create();

        var result = PackageReader.Validate(fixture.Path, EdlRawFixture.Model, InstallationTarget.Internal);

        Assert.True(result.IsValid, string.Join("; ", result.Reasons));
        Assert.Empty(result.Reasons);
        Assert.NotNull(result.Storage);
        Assert.Equal(1L * GiB, result.Storage!.LinuxBootBytes);
        Assert.Equal(20L * GiB, result.Storage.SystemRequiredBytes);
        Assert.Equal(0L, result.Storage.DeploymentScratchBytes);
        Assert.Equal(8L * GiB, result.Storage.MinimumLinuxDataBytes);
        Assert.True(result.TestOnly);
        Assert.Equal(EdlRawFixture.PackageId, result.PackageId);
        Assert.Equal(EdlRawFixture.PackageVersion, result.Version);
        Assert.Equal(fixture.ManifestFingerprint, result.ManifestFingerprint);
        Assert.Equal("edl-raw-v1", result.DeploymentKind);
    }

    [Fact]
    public void Validate_DirectEdlSchema2TestOnlyFalseIsStillStructurallyValid()
    {
        using var fixture = EdlRawFixture.Create();
        var metadata = fixture.ReadMetadata();
        metadata["testOnly"] = false;
        fixture.WriteMetadata(metadata);

        // The two argument overload is internal only, and schema 2 is internal only.
        var result = PackageReader.Validate(fixture.Path, EdlRawFixture.Model);

        Assert.True(result.IsValid, string.Join("; ", result.Reasons));
        Assert.False(result.TestOnly);
    }

    [Fact]
    public void Validate_DirectEdlSchema2RejectsTheTfTarget()
    {
        using var fixture = EdlRawFixture.Create();

        var result = PackageReader.Validate(fixture.Path, EdlRawFixture.Model, InstallationTarget.TfCard);

        Assert.False(result.IsValid);
        Assert.NotEmpty(result.Reasons);
        Assert.Null(result.Storage);
        Assert.Null(result.PackageId);
        Assert.True(result.TestOnly);
        Assert.Contains(result.Reasons, reason => reason.Contains("tf", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Validate_DirectEdlSchema2RejectsAnotherGeneration()
    {
        using var fixture = EdlRawFixture.Create();

        var result = PackageReader.Validate(fixture.Path, "TB323FU");

        Assert.False(result.IsValid);
        Assert.Contains(result.Reasons, reason => reason.Contains("deviceModel", StringComparison.OrdinalIgnoreCase));
    }

    // ------------------------------------------------------------- schema 1 is never reinterpreted

    [Fact]
    public void ReadEdlRawContract_RejectsSchema1SeedPackages()
    {
        using var fixture = new TempPackageDirectory();
        PackageFixture.WritePackage(fixture.Path, EdlRawFixture.Model);

        Assert.Throws<InvalidDataException>(
            () => PackageReader.ReadEdlRawContract(fixture.Path, EdlRawFixture.Model));
    }

    [Fact]
    public void ReadEdlRawContract_OldSeedPackageWithOnlySchemaVersionBumpedCannotBecomeDirect()
    {
        using var fixture = new TempPackageDirectory();
        PackageFixture.WritePackage(fixture.Path, EdlRawFixture.Model);

        var metadata = JsonNode.Parse(File.ReadAllText(PackageFixture.MetadataPath(fixture.Path)))!.AsObject();
        metadata["schemaVersion"] = 2;
        File.WriteAllText(PackageFixture.MetadataPath(fixture.Path), metadata.ToJsonString(EdlRawFixture.WriteOptions));

        Assert.Throws<InvalidDataException>(
            () => PackageReader.ReadEdlRawContract(fixture.Path, EdlRawFixture.Model));
    }

    // ----------------------------------------------- malformed, blank or padded metadata at the boundary

    [Fact]
    public void ReadEdlRawContract_MalformedMetadataJsonIsRejectedAsInvalidData()
    {
        using var fixture = EdlRawFixture.Create();
        File.WriteAllText(fixture.MetadataPath, "{ \"schemaVersion\": 2, \"packageId\": ");

        var exception = Assert.Throws<InvalidDataException>(
            () => PackageReader.ReadEdlRawContract(fixture.Path, EdlRawFixture.Model));

        Assert.False(string.IsNullOrWhiteSpace(exception.Message));
        Assert.Contains(EdlRawFixture.MetadataFileName, exception.Message, StringComparison.Ordinal);
        Assert.NotNull(exception.InnerException);
    }

    [Theory]
    [InlineData("packageId")]
    [InlineData("version")]
    public void ReadEdlRawContract_RejectsWhitespaceOnlyIdentity(string field)
    {
        AssertRejected((_, metadata) => metadata[field] = "   ");
    }

    [Fact]
    public void ReadEdlRawContract_RejectsLatestVersionPaddedWithWhitespace()
    {
        AssertRejected((_, metadata) => metadata["version"] = "  latest  ");
    }

    // --------------------------------------------------------------------------- exactly seven roles

    [Theory]
    [InlineData("missing-role")]
    [InlineData("duplicate-role")]
    [InlineData("extra-role")]
    [InlineData("ostree-seed-role")]
    [InlineData("generic-dtb")]
    [InlineData("duplicate-file")]
    [InlineData("duplicate-resolved-path")]
    public void ReadEdlRawContract_RequiresExactlyTheSevenContractRoles(string mutation)
    {
        AssertRejected((fixture, metadata) =>
        {
            var artifacts = metadata["artifacts"]!.AsArray();

            switch (mutation)
            {
                case "missing-role":
                    artifacts.RemoveAt(IndexOfRole(artifacts, "kernel"));
                    break;
                case "duplicate-role":
                    fixture.WriteFile(EdlRawFixture.KernelCopyFile, fixture.ReadFile(EdlRawFixture.KernelFile));
                    artifacts.Add(fixture.Describe("kernel", EdlRawFixture.KernelCopyFile));
                    break;
                case "extra-role":
                    fixture.WriteFile(EdlRawFixture.SeedFile, EdlRawFixture.Payload(64, 0x5A));
                    artifacts.Add(fixture.Describe("ostree-seed", EdlRawFixture.SeedFile));
                    break;
                case "ostree-seed-role":
                    Artifact(metadata, "linux-root-raw")["role"] = "ostree-seed";
                    break;
                case "generic-dtb":
                    Artifact(metadata, "dtb-normal")["role"] = "dtb";
                    break;
                case "duplicate-file":
                    CopyDeclaration(metadata, "dtb-normal", "dtb-diagnostic");
                    break;
                case "duplicate-resolved-path":
                    CopyDeclaration(metadata, "dtb-normal", "dtb-diagnostic");
                    Artifact(metadata, "dtb-diagnostic")["file"] = "./" + EdlRawFixture.DtbNormalFile;
                    break;
            }
        });
    }

    // --------------------------------------------------- profile shape, build list and source commit

    [Theory]
    [InlineData("profile-id-space")]
    [InlineData("profile-id-leading-hyphen")]
    [InlineData("profile-id-non-ascii")]
    [InlineData("hardware-id-nonhex")]
    [InlineData("hardware-id-short")]
    [InlineData("hardware-id-long")]
    [InlineData("android-build-blank")]
    [InlineData("android-build-not-declared")]
    [InlineData("neighbouring-build")]
    [InlineData("duplicate-firmware-versions")]
    [InlineData("empty-firmware-versions")]
    [InlineData("soc")]
    [InlineData("device")]
    [InlineData("source-uppercase")]
    [InlineData("source-nonhex")]
    [InlineData("source-all-zero")]
    [InlineData("source-short")]
    [InlineData("source-too-long")]
    [InlineData("source-leading-space")]
    [InlineData("source-trailing-space")]
    [InlineData("source-embedded-space")]
    [InlineData("source-newline")]
    public void ReadEdlRawContract_RequiresAValidProfileAndSourceCommit(string mutation)
    {
        AssertRejected((fixture, metadata) =>
        {
            switch (mutation)
            {
                case "profile-id-space":
                    Profile(metadata)["id"] = "g4 9008 259";
                    break;
                case "profile-id-leading-hyphen":
                    Profile(metadata)["id"] = "-g4-9008-259";
                    break;
                case "profile-id-non-ascii":
                    Profile(metadata)["id"] = "g4-9008-259配置";
                    break;
                case "hardware-id-nonhex":
                    Profile(metadata)["hardwareId"] = "0028D0E10040000Z";
                    break;
                case "hardware-id-short":
                    Profile(metadata)["hardwareId"] = "0028D0E10040000";
                    break;
                case "hardware-id-long":
                    Profile(metadata)["hardwareId"] = "0028D0E1004000000";
                    break;
                case "android-build-blank":
                    Profile(metadata)["androidBuild"] = "   ";
                    break;
                case "android-build-not-declared":
                    // The neighbouring build is itself valid metadata, but it is not one of the declared
                    // firmware versions, so the exact membership rule still rejects the package.
                    Profile(metadata)["androidBuild"] = EdlRawFixture.NeighbouringBuild;
                    break;
                case "neighbouring-build":
                    Boot(metadata)["firmwareVersions"] = new JsonArray(EdlRawFixture.NeighbouringBuild);
                    break;
                case "duplicate-firmware-versions":
                    Boot(metadata)["firmwareVersions"] =
                        new JsonArray(EdlRawFixture.AndroidBuild, EdlRawFixture.AndroidBuild);
                    break;
                case "empty-firmware-versions":
                    Boot(metadata)["firmwareVersions"] = new JsonArray();
                    break;
                case "soc":
                    // Foreign platform tag: the shared compatible map rejects it for the declared model.
                    Compatible(metadata)["soc"] = "SM8850";
                    break;
                case "device":
                    Compatible(metadata)["device"] = "baldur";
                    break;
                case "source-uppercase":
                    metadata["sourceCommit"] = EdlRawFixture.SourceCommit.ToUpperInvariant();
                    break;
                case "source-nonhex":
                    // Right width, wrong alphabet: the shape rule rejects it without any value being pinned.
                    metadata["sourceCommit"] = "g" + new string('a', 39);
                    break;
                case "source-all-zero":
                    metadata["sourceCommit"] = new string('0', 40);
                    break;
                case "source-short":
                    metadata["sourceCommit"] = EdlRawFixture.SourceCommit[..39];
                    break;
                case "source-too-long":
                    metadata["sourceCommit"] = EdlRawFixture.SourceCommit + "0";
                    break;
                case "source-leading-space":
                    metadata["sourceCommit"] = " " + EdlRawFixture.SourceCommit;
                    break;
                case "source-trailing-space":
                    metadata["sourceCommit"] = EdlRawFixture.SourceCommit + " ";
                    break;
                case "source-embedded-space":
                    metadata["sourceCommit"] =
                        EdlRawFixture.SourceCommit[..20] + " " + EdlRawFixture.SourceCommit[20..];
                    break;
                case "source-newline":
                    metadata["sourceCommit"] = EdlRawFixture.SourceCommit + "\n";
                    break;
            }
        });
    }

    [Fact]
    public void ReadEdlRawContract_RejectsAMismatchedExpectedModel()
    {
        using var fixture = EdlRawFixture.Create();
        var metadata = fixture.ReadMetadata();

        // A well-formed future producer revision, so the mismatch is reported on its own and not hidden
        // behind a stale source pin.
        metadata["sourceCommit"] = FutureSourceCommit;
        fixture.WriteMetadata(metadata);

        var exception = Assert.Throws<InvalidDataException>(
            () => PackageReader.ReadEdlRawContract(fixture.Path, "TB323FU"));

        Assert.Contains("deviceModel", exception.Message, StringComparison.Ordinal);
    }

    // ------------------------------------------------- generic declarations outside one device family

    [Fact]
    public void ReadEdlRawContract_AcceptsSyntheticG5MetadataAsADeclarationOnly()
    {
        const string g5Build = "TB323FU_CN_OPEN_USER_Q00042.1_W_ZUXOS_1.6.0.300_ST_260701";

        using var fixture = EdlRawFixture.Create();
        var metadata = fixture.ReadMetadata();
        metadata["deviceModel"] = "TB323FU";
        Compatible(metadata)["soc"] = "SM8850";
        Compatible(metadata)["device"] = "baldur";
        Profile(metadata)["id"] = "g5-9008-300";
        Profile(metadata)["hardwareId"] = "a1b2c3d4e5f60718";
        Profile(metadata)["androidBuild"] = g5Build;
        Boot(metadata)["firmwareVersions"] = new JsonArray(g5Build);
        fixture.WriteMetadata(metadata);

        var contract = PackageReader.ReadEdlRawContract(fixture.Path, "TB323FU");

        // Metadata only: this is not a G5 loader, a Complete profile, a factory image or a device proof.
        Assert.Equal("TB323FU", contract.DeviceModel);
        Assert.Equal("g5-9008-300", contract.EdlProfileId);
        Assert.Equal("A1B2C3D4E5F60718", contract.HardwareId);
        Assert.Equal(g5Build, contract.AndroidBuild);
        Assert.Equal(new[] { g5Build }, contract.FirmwareVersions);
        Assert.Equal(EdlRawFixture.SourceCommit, contract.SourceCommit);

        // The seven roles and the tool protocols are the same for every declared model.
        Assert.Equal(7, contract.Artifacts.Count);
        Assert.Equal("edl-raw-v1", contract.Deployment.Kind);
    }

    [Fact]
    public void ReadEdlRawContract_AcceptsMultipleDeclaredBuildsAndPreservesTheDeclaredProfile()
    {
        const string otherBuild = "TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.258_ST_260601";

        using var fixture = EdlRawFixture.Create();
        var metadata = fixture.ReadMetadata();
        metadata["deviceModel"] = "tb322fc";
        Profile(metadata)["id"] = "G4.9008_259-test";
        Profile(metadata)["hardwareId"] = "0028d0e100400000";
        Boot(metadata)["firmwareVersions"] = new JsonArray(otherBuild, EdlRawFixture.AndroidBuild);
        fixture.WriteMetadata(metadata);

        var contract = PackageReader.ReadEdlRawContract(fixture.Path, EdlRawFixture.Model);

        // The model keeps the shared canonicalisation, the profile id its declared spelling, and the
        // hardware id is normalised to upper case without pinning any device value.
        Assert.Equal("TB322FC", contract.DeviceModel);
        Assert.Equal("G4.9008_259-test", contract.EdlProfileId);
        Assert.Equal("0028D0E100400000", contract.HardwareId);
        Assert.Equal(EdlRawFixture.AndroidBuild, contract.AndroidBuild);
        Assert.Equal(new[] { otherBuild, EdlRawFixture.AndroidBuild }, contract.FirmwareVersions);
    }

    // ----------------------------------- optional Android profile/firmware declaration group

    [Theory]
    [InlineData("TB322FC", "SM8750", "elden")]
    [InlineData("TB323FU", "SM8850", "baldur")]
    public void ReadEdlRawContract_AcceptsACommonPackageWithoutTheAndroidGroup(
        string model,
        string soc,
        string device)
    {
        using var fixture = EdlRawFixture.Create();
        var metadata = fixture.ReadMetadata();
        metadata["deviceModel"] = model;
        Compatible(metadata)["soc"] = soc;
        Compatible(metadata)["device"] = device;
        metadata.Remove("edlProfile");
        Boot(metadata).Remove("firmwareVersions");
        fixture.WriteMetadata(metadata);

        var contract = PackageReader.ReadEdlRawContract(fixture.Path, model);

        // A standard common package carries no Android restriction claim at all: three real nulls and an
        // empty read-only list, never an empty identifier, a zero hardware id or a permissive entry.
        Assert.Null(contract.EdlProfileId);
        Assert.Null(contract.HardwareId);
        Assert.Null(contract.AndroidBuild);
        Assert.NotNull(contract.FirmwareVersions);
        Assert.Empty(contract.FirmwareVersions);
        Assert.Throws<NotSupportedException>(
            () => ((IList<string>)contract.FirmwareVersions).Add(EdlRawFixture.NeighbouringBuild));

        // Everything outside the optional group is unchanged.
        Assert.Equal(model, contract.DeviceModel);
        Assert.Equal(7, contract.Artifacts.Count);
        Assert.Equal("edl-raw-v1", contract.Deployment.Kind);
        Assert.Equal(EdlRawFixture.DeploymentCommit, contract.Deployment.Commit);
        Assert.Equal(EdlRawFixture.NormalBootArgs, contract.BootRecipe.NormalBootArgs);
        Assert.Equal(Guid.Parse(EdlRawFixture.BootUuid), contract.BootRecipe.BootUuid);
        Assert.Equal(1L * GiB, contract.Storage.LinuxBootBytes);
    }

    [Theory]
    [InlineData("profile-only")]
    [InlineData("firmware-only")]
    [InlineData("null-profile")]
    [InlineData("null-firmware")]
    public void ReadEdlRawContract_RejectsAHalfDeclaredAndroidGroup(string mutation)
    {
        AssertRejected((fixture, metadata) =>
        {
            switch (mutation)
            {
                case "profile-only":
                    Boot(metadata).Remove("firmwareVersions");
                    break;
                case "firmware-only":
                    metadata.Remove("edlProfile");
                    break;
                case "null-profile":
                    // An explicit null is a present property with the wrong shape, never an omission.
                    metadata["edlProfile"] = null;
                    break;
                case "null-firmware":
                    Boot(metadata)["firmwareVersions"] = null;
                    break;
            }
        });
    }

    [Theory]
    [InlineData("id")]
    [InlineData("hardwareId")]
    [InlineData("androidBuild")]
    public void ReadEdlRawContract_RejectsAnIncompleteAndroidProfile(string missingField)
    {
        AssertRejected((fixture, metadata) =>
        {
            Profile(metadata).Remove(missingField);
        });
    }

    // ------------------------------------------------------------------ required tool protocols

    [Theory]
    [InlineData("installer-protocol-1")]
    [InlineData("installer-protocol-missing")]
    [InlineData("installer-protocol-string")]
    [InlineData("builder-protocol-2")]
    [InlineData("builder-protocol-missing")]
    [InlineData("tools-missing")]
    public void ReadEdlRawContract_RequiresTheDirectRouteToolProtocols(string mutation)
    {
        AssertRejected((fixture, metadata) =>
        {
            switch (mutation)
            {
                case "installer-protocol-1":
                    Tools(metadata)["installerProtocol"] = 1;
                    break;
                case "installer-protocol-missing":
                    Tools(metadata).Remove("installerProtocol");
                    break;
                case "installer-protocol-string":
                    Tools(metadata)["installerProtocol"] = "2";
                    break;
                case "builder-protocol-2":
                    Tools(metadata)["bootBuilderProtocol"] = 2;
                    break;
                case "builder-protocol-missing":
                    Tools(metadata).Remove("bootBuilderProtocol");
                    break;
                case "tools-missing":
                    metadata.Remove("toolsCompatibility");
                    break;
            }
        });
    }

    // ------------------------------------------------------- payload declarations versus real files

    [Theory]
    [InlineData("compressed-bytes")]
    [InlineData("compressed-sha")]
    [InlineData("truncated-file")]
    [InlineData("tampered-file")]
    [InlineData("missing-file")]
    [InlineData("ordinary-sha")]
    [InlineData("ordinary-tampered")]
    [InlineData("runtime-bytes")]
    [InlineData("rooted-path")]
    [InlineData("traversal-path")]
    [InlineData("unc-path")]
    [InlineData("drive-path")]
    public void ReadEdlRawContract_RejectsPayloadsThatDoNotMatchTheirDeclarations(string mutation)
    {
        AssertRejected((fixture, metadata) =>
        {
            switch (mutation)
            {
                case "compressed-bytes":
                    Artifact(metadata, "linux-boot-raw")["bytes"] =
                        fixture.BytesOf(EdlRawFixture.BootImageFile) + 1;
                    break;
                case "compressed-sha":
                    Artifact(metadata, "linux-boot-raw")["sha256"] = new string('0', 64);
                    break;
                case "truncated-file":
                    fixture.Truncate(EdlRawFixture.BootImageFile);
                    break;
                case "tampered-file":
                    fixture.Tamper(EdlRawFixture.RootImageFile);
                    break;
                case "missing-file":
                    fixture.Delete(EdlRawFixture.KernelFile);
                    break;
                case "ordinary-sha":
                    Artifact(metadata, "kernel")["sha256"] = new string('a', 64);
                    break;
                case "ordinary-tampered":
                    fixture.Tamper(EdlRawFixture.KernelFile);
                    break;
                case "runtime-bytes":
                    Artifact(metadata, "runtime")["bytes"] = 4096L;
                    break;
                case "rooted-path":
                    Artifact(metadata, "kernel")["file"] = "/etc/kernel";
                    break;
                case "traversal-path":
                    Artifact(metadata, "kernel")["file"] = "../outside.bin";
                    break;
                case "unc-path":
                    Artifact(metadata, "kernel")["file"] = @"\\server\share\kernel";
                    break;
                case "drive-path":
                    Artifact(metadata, "kernel")["file"] = "C:/kernel";
                    break;
            }
        }, sourceCommit: FutureSourceCommit);
    }

    // -------------------------------------------------------------- expanded raw image declarations

    [Theory]
    [InlineData("boot-expanded-not-1gib")]
    [InlineData("expanded-not-aligned")]
    [InlineData("expanded-zero")]
    [InlineData("sector-512")]
    [InlineData("compression-zstd")]
    [InlineData("compression-missing")]
    [InlineData("boot-fstype")]
    [InlineData("root-fstype")]
    [InlineData("minimum-below-expanded")]
    [InlineData("minimum-not-aligned")]
    [InlineData("fsuuid-zero")]
    [InlineData("fsuuid-not-distinct")]
    [InlineData("ordinary-with-gzip")]
    [InlineData("ordinary-with-expanded")]
    [InlineData("ordinary-with-sector")]
    public void ReadEdlRawContract_RejectsInvalidRawImageDeclarations(string mutation)
    {
        AssertRejected((fixture, metadata) =>
        {
            switch (mutation)
            {
                case "boot-expanded-not-1gib":
                    Artifact(metadata, "linux-boot-raw")["expandedBytes"] = 1073741823L;
                    break;
                case "expanded-not-aligned":
                    Artifact(metadata, "linux-root-raw")["expandedBytes"] = 16380L;
                    break;
                case "expanded-zero":
                    Artifact(metadata, "linux-boot-raw")["expandedBytes"] = 0L;
                    break;
                case "sector-512":
                    Artifact(metadata, "linux-boot-raw")["sectorSize"] = 512;
                    break;
                case "compression-zstd":
                    Artifact(metadata, "linux-boot-raw")["compression"] = "zstd";
                    break;
                case "compression-missing":
                    Artifact(metadata, "linux-root-raw").Remove("compression");
                    break;
                case "boot-fstype":
                    Artifact(metadata, "linux-boot-raw")["fsType"] = "btrfs";
                    break;
                case "root-fstype":
                    Artifact(metadata, "linux-root-raw")["fsType"] = "ext4";
                    break;
                case "minimum-below-expanded":
                    Artifact(metadata, "linux-root-raw")["minimumPartitionBytes"] = 8192L;
                    break;
                case "minimum-not-aligned":
                    Artifact(metadata, "linux-root-raw")["minimumPartitionBytes"] = 16500L;
                    break;
                case "fsuuid-zero":
                    Artifact(metadata, "linux-boot-raw")["fsUuid"] = "00000000-0000-0000-0000-000000000000";
                    break;
                case "fsuuid-not-distinct":
                    Artifact(metadata, "linux-boot-raw")["fsUuid"] = EdlRawFixture.RootUuid;
                    Recipe(metadata)["bootUuid"] = EdlRawFixture.RootUuid;
                    break;
                case "ordinary-with-gzip":
                    Artifact(metadata, "kernel")["compression"] = "gzip";
                    break;
                case "ordinary-with-expanded":
                    Artifact(metadata, "kernel")["expandedBytes"] = 4096L;
                    break;
                case "ordinary-with-sector":
                    Artifact(metadata, "dtb-normal")["sectorSize"] = 4096;
                    break;
            }
        });
    }

    // ------------------------------------------------------------------------- boot recipe details

    [Theory]
    [InlineData("root-uuid-mismatch")]
    [InlineData("boot-uuid-mismatch")]
    [InlineData("recipe-uuids-equal")]
    [InlineData("missing-ostree")]
    [InlineData("ostree-boot2")]
    [InlineData("ostree-wrong-osname")]
    [InlineData("ostree-wrong-checksum")]
    [InlineData("ostree-no-deploy-index")]
    [InlineData("duplicate-root-argument")]
    [InlineData("duplicate-boot-argument")]
    [InlineData("root-uuid-lowercase-prefix")]
    [InlineData("boot-uuid-lowercase-prefix")]
    [InlineData("duplicate-ostree")]
    [InlineData("diagnostic-differs")]
    [InlineData("diagnostic-missing-suffix")]
    [InlineData("normal-missing")]
    [InlineData("newline")]
    [InlineData("nul")]
    [InlineData("too-long")]
    [InlineData("default-entry")]
    public void ReadEdlRawContract_RejectsBrokenBootRecipes(string mutation)
    {
        AssertRejected((fixture, metadata) =>
        {
            var normal = EdlRawFixture.NormalBootArgs;

            switch (mutation)
            {
                case "root-uuid-mismatch":
                    Recipe(metadata)["rootUuid"] = "11111111-2222-4333-8444-555555555555";
                    break;
                case "boot-uuid-mismatch":
                    Recipe(metadata)["bootUuid"] = "11111111-2222-4333-8444-555555555555";
                    break;
                case "recipe-uuids-equal":
                    Recipe(metadata)["rootUuid"] = EdlRawFixture.BootUuid;
                    break;
                case "missing-ostree":
                    SetBootArgs(
                        metadata,
                        normal.Replace(
                            " ostree=/ostree/boot.0/default/" + EdlRawFixture.BootChecksum + "/0",
                            string.Empty,
                            StringComparison.Ordinal));
                    break;
                case "ostree-boot2":
                    SetBootArgs(metadata, normal.Replace("/boot.0/", "/boot.2/", StringComparison.Ordinal));
                    break;
                case "ostree-wrong-osname":
                    SetBootArgs(
                        metadata,
                        normal.Replace("/ostree/boot.0/default/", "/ostree/boot.0/armadaos/", StringComparison.Ordinal));
                    break;
                case "ostree-wrong-checksum":
                    SetBootArgs(
                        metadata,
                        normal.Replace(EdlRawFixture.BootChecksum, new string('0', 64), StringComparison.Ordinal));
                    break;
                case "ostree-no-deploy-index":
                    SetBootArgs(
                        metadata,
                        normal.Replace(
                            "/" + EdlRawFixture.BootChecksum + "/0",
                            "/" + EdlRawFixture.BootChecksum,
                            StringComparison.Ordinal));
                    break;
                case "duplicate-root-argument":
                    SetBootArgs(metadata, normal + " root=UUID=" + EdlRawFixture.RootUuid);
                    break;
                case "duplicate-boot-argument":
                    SetBootArgs(metadata, normal + " boot=UUID=" + EdlRawFixture.BootUuid);
                    break;
                case "root-uuid-lowercase-prefix":
                    SetBootArgs(metadata, normal.Replace("root=UUID=", "root=uuid=", StringComparison.Ordinal));
                    break;
                case "boot-uuid-lowercase-prefix":
                    SetBootArgs(metadata, normal.Replace("boot=UUID=", "boot=uuid=", StringComparison.Ordinal));
                    break;
                case "duplicate-ostree":
                    SetBootArgs(
                        metadata,
                        normal
                        + " ostree=/ostree/boot.1/default/"
                        + EdlRawFixture.BootChecksum
                        + "/0");
                    break;
                case "diagnostic-differs":
                    Recipe(metadata)["diagnosticBootArgs"] = normal + " rd.break=shell";
                    break;
                case "diagnostic-missing-suffix":
                    Recipe(metadata)["diagnosticBootArgs"] = normal;
                    break;
                case "normal-missing":
                    Recipe(metadata).Remove("normalBootArgs");
                    break;
                case "newline":
                    SetBootArgs(metadata, normal + "\nquiet");
                    break;
                case "nul":
                    SetBootArgs(metadata, normal + "\0");
                    break;
                case "too-long":
                    SetBootArgs(metadata, normal + " " + new string('x', 4096));
                    break;
                case "default-entry":
                    Recipe(metadata)["defaultEntry"] = "linux";
                    break;
            }
        }, sourceCommit: FutureSourceCommit);
    }

    // --------------------------------------------------------------------------- cancellation token

    [Fact]
    public void ReadEdlRawContract_PreCancelledTokenIsPreserved()
    {
        using var fixture = EdlRawFixture.Create();
        using var source = new CancellationTokenSource();
        source.Cancel();

        Assert.ThrowsAny<OperationCanceledException>(
            () => PackageReader.ReadEdlRawContract(fixture.Path, EdlRawFixture.Model, source.Token));
    }

    // ---------------------------------------------------------------------------- immutable surface

    [Fact]
    public void ContractTypesAreSealedAndExposeNoWritableMembers()
    {
        var types = new[]
        {
            typeof(EdlRawPackageContract),
            typeof(EdlRawArtifact),
            typeof(EdlRawImage),
            typeof(EdlRawDeployment),
            typeof(EdlRawBootRecipe),
        };

        foreach (var type in types)
        {
            Assert.True(type.IsSealed, type.Name);

            foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            {
                Assert.False(property.CanWrite, type.Name + "." + property.Name);
            }

            Assert.DoesNotContain(
                type.GetConstructors(BindingFlags.Public | BindingFlags.Instance),
                constructor => constructor.GetParameters().Length > 0);
        }

        Assert.Equal(
            typeof(IReadOnlyDictionary<string, EdlRawArtifact>),
            typeof(EdlRawPackageContract).GetProperty("Artifacts")!.PropertyType);
        Assert.Equal(
            typeof(IReadOnlyList<string>),
            typeof(EdlRawPackageContract).GetProperty("FirmwareVersions")!.PropertyType);
        Assert.Equal(typeof(PackageStorage), typeof(EdlRawPackageContract).GetProperty("Storage")!.PropertyType);
        Assert.Equal(typeof(Guid), typeof(EdlRawImage).GetProperty("FsUuid")!.PropertyType);
        Assert.Equal(typeof(Guid), typeof(EdlRawBootRecipe).GetProperty("BootUuid")!.PropertyType);

        // Ordinary roles carry no compressed-image metadata: that lives on EdlRawImage only.
        Assert.DoesNotContain(
            typeof(EdlRawArtifact).GetProperties(BindingFlags.Public | BindingFlags.Instance),
            property => property.Name is "Compression" or "ExpandedBytes" or "ExpandedSha256" or "SectorSize");
    }

    [Fact]
    public void ReturnedCollectionsCannotBeMutatedThroughThePublicSurface()
    {
        using var fixture = EdlRawFixture.Create();

        var contract = PackageReader.ReadEdlRawContract(fixture.Path, EdlRawFixture.Model);

        Assert.NotNull(contract.Artifacts);
        Assert.NotNull(contract.FirmwareVersions);

        // A read-only wrapper may also implement the mutable interface; every write must then throw.
        if (contract.Artifacts is IDictionary<string, EdlRawArtifact> mutableArtifacts)
        {
            Assert.Throws<NotSupportedException>(
                () => mutableArtifacts["kernel"] = contract.Artifacts["kernel"]);
        }

        if (contract.FirmwareVersions is IList<string> mutableVersions)
        {
            Assert.Throws<NotSupportedException>(() => mutableVersions.Add("another-build"));
        }
    }

    // ------------------------------------------------------------------------------------ helpers

    /// <summary>
    /// Rewrites the fixture with one deliberate contract violation and requires the direct reader to
    /// reject it as <see cref="InvalidDataException"/>. A stub or any other exception is a failure, so a
    /// missing implementation can never be mistaken for a semantic rejection.
    /// <para>
    /// When <paramref name="sourceCommit"/> is supplied the metadata declares that valid revision instead
    /// of the fixture default, and the diagnostic must not name the <c>sourceCommit</c> field: a generic
    /// source-commit error, with or without the revision quoted, can then never stand in for the mutation
    /// under test.
    /// </para>
    /// </summary>
    private static void AssertRejected(
        Action<EdlRawFixture, JsonObject> mutate,
        string expectedModel = EdlRawFixture.Model,
        string? sourceCommit = null)
    {
        using var fixture = EdlRawFixture.Create();

        var metadata = fixture.ReadMetadata();
        mutate(fixture, metadata);

        if (sourceCommit is not null)
        {
            metadata["sourceCommit"] = sourceCommit;
        }

        fixture.WriteMetadata(metadata);

        var exception = Assert.Throws<InvalidDataException>(
            () => PackageReader.ReadEdlRawContract(fixture.Path, expectedModel));

        Assert.False(string.IsNullOrWhiteSpace(exception.Message));

        if (sourceCommit is not null)
        {
            // The field name rather than the value: a source-commit diagnostic never satisfies this guard.
            Assert.DoesNotContain("sourceCommit", exception.Message, StringComparison.Ordinal);
        }
    }

    private static void SetBootArgs(JsonObject metadata, string normal)
    {
        var recipe = Recipe(metadata);
        recipe["normalBootArgs"] = normal;
        recipe["diagnosticBootArgs"] = normal + EdlRawFixture.DiagnosticSuffix;
    }

    private static void CopyDeclaration(JsonObject metadata, string sourceRole, string targetRole)
    {
        var source = Artifact(metadata, sourceRole);
        var target = Artifact(metadata, targetRole);
        target["file"] = source["file"]!.GetValue<string>();
        target["bytes"] = source["bytes"]!.GetValue<long>();
        target["sha256"] = source["sha256"]!.GetValue<string>();
    }

    private static int IndexOfRole(JsonArray artifacts, string role)
    {
        for (var index = 0; index < artifacts.Count; index++)
        {
            if (artifacts[index] is JsonObject entry
                && entry["role"] is JsonValue value
                && value.GetValue<string>() == role)
            {
                return index;
            }
        }

        throw new InvalidOperationException("fixture has no artifact role " + role);
    }

    private static JsonObject Artifact(JsonObject metadata, string role) =>
        metadata["artifacts"]!.AsArray()
            .Select(entry => entry!.AsObject())
            .First(entry => entry["role"]!.GetValue<string>() == role);

    private static JsonObject Profile(JsonObject metadata) => metadata["edlProfile"]!.AsObject();

    private static JsonObject Compatible(JsonObject metadata) => metadata["compatible"]!.AsObject();

    private static JsonObject Boot(JsonObject metadata) => metadata["bootCompatibility"]!.AsObject();

    private static JsonObject Tools(JsonObject metadata) => metadata["toolsCompatibility"]!.AsObject();

    private static JsonObject Recipe(JsonObject metadata) => metadata["bootRecipe"]!.AsObject();

    private static int CountOccurrences(string haystack, string needle)
    {
        var count = 0;
        var index = 0;

        while ((index = haystack.IndexOf(needle, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += needle.Length;
        }

        return count;
    }
}

/// <summary>
/// G5 verbose diagnostic recipe metadata contract. The reader must accept a hand-written
/// normal/diagnostic pair on a metadata-only TB323FU declaration and hand both strings back byte for
/// byte, must keep the legacy " rd.break=pre-mount" diagnostic working for both models, and must still
/// reject the new verbose diagnostic form on G4. Foreign boot identities and diagnostic-only edits stay
/// rejected. Every expected string here is written out by hand; nothing below is a loader, factory image
/// or device proof.
/// </summary>
public sealed class EdlRawDiagnosticRecipeTests
{
    private const string G4Model = "TB322FC";
    private const string G5Model = "TB323FU";

    private const string VerboseExtras =
        " loglevel=8 ignore_loglevel printk.time=1 initcall_debug rd.debug";

    private static readonly string BaldurBootArgs = EdlRawFixture.NormalBootArgs.Replace(
        "androidboot.hardware=elden", "androidboot.hardware=baldur", StringComparison.Ordinal);

    private static readonly string CleanVerbose = BaldurBootArgs + VerboseExtras;

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void ReadEdlRawContract_G5AcceptsVerboseDiagnosticRecipeVerbatim(int index)
    {
        var normal = index == 0
            ? "quiet loglevel=4 rd.break rd.break=pre-mount " + BaldurBootArgs + " printk.time=0"
            : "\tquiet  loglevel=8 " + BaldurBootArgs + " ignore_loglevel ignore_loglevel rd.debug printk.time=1  ";

        var diagnostic = index == 0
            ? BaldurBootArgs + " printk.time=0 loglevel=8 ignore_loglevel printk.time=1 initcall_debug rd.debug"
            : BaldurBootArgs + " ignore_loglevel ignore_loglevel rd.debug printk.time=1 loglevel=8 initcall_debug";

        using var fixture = Prepare(G5Model, normal, diagnostic);
        var contract = PackageReader.ReadEdlRawContract(fixture.Path, G5Model);

        Assert.Equal(G5Model, contract.DeviceModel);
        Assert.Equal(normal, contract.BootRecipe.NormalBootArgs);
        Assert.Equal(diagnostic, contract.BootRecipe.DiagnosticBootArgs);
    }

    [Theory]
    [InlineData(G4Model)]
    [InlineData(G5Model)]
    public void ReadEdlRawContract_BothModelsAcceptLegacyDiagnosticSuffixVerbatim(string model)
    {
        var normal = model == G5Model ? BaldurBootArgs : EdlRawFixture.NormalBootArgs;
        var diagnostic = normal + EdlRawFixture.DiagnosticSuffix;

        using var fixture = Prepare(model, normal, diagnostic);
        var contract = PackageReader.ReadEdlRawContract(fixture.Path, model);

        Assert.Equal(normal, contract.BootRecipe.NormalBootArgs);
        Assert.Equal(diagnostic, contract.BootRecipe.DiagnosticBootArgs);
    }

    [Fact]
    public void ReadEdlRawContract_G4RejectsVerboseDiagnosticRecipe()
    {
        AssertRejected(
            G4Model,
            EdlRawFixture.NormalBootArgs,
            EdlRawFixture.NormalBootArgs + VerboseExtras);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void ReadEdlRawContract_G5RejectsNormalBootArgsCarryingForeignIdentity(int index)
    {
        const string foreignUuid = "11111111-2222-4333-8444-555555555555";

        var normal = index switch
        {
            0 => BaldurBootArgs.Replace(EdlRawFixture.RootUuid, foreignUuid, StringComparison.Ordinal),
            1 => BaldurBootArgs.Replace(EdlRawFixture.BootUuid, foreignUuid, StringComparison.Ordinal),
            _ => BaldurBootArgs.Replace(EdlRawFixture.BootChecksum, new string('0', 64), StringComparison.Ordinal),
        };

        AssertRejected(G5Model, normal, normal + VerboseExtras);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void ReadEdlRawContract_G5RejectsDiagnosticOnlyMutations(int index)
    {
        var diagnostic = index switch
        {
            0 => CleanVerbose.Replace(" rd.debug", string.Empty, StringComparison.Ordinal),
            1 => CleanVerbose + " rd.break",
            2 => CleanVerbose + " surprise=value",
            _ => "console=tty0 whatever=1",
        };

        AssertRejected(G5Model, BaldurBootArgs, diagnostic);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void ReadEdlRawContract_G5RejectsDiagnosticThatIsNotPlainBoundedText(int index)
    {
        var diagnostic = index == 0
            ? CleanVerbose + "\0"
            : CleanVerbose + new string('界', 1400);

        AssertRejected(G5Model, BaldurBootArgs, diagnostic);
    }

    private static EdlRawFixture Prepare(string model, string normal, string diagnostic)
    {
        var isG5 = model == G5Model;

        var fixture = EdlRawFixture.Create();
        var metadata = fixture.ReadMetadata();
        metadata["deviceModel"] = model;

        var platform = metadata["compatible"]!.AsObject();
        platform["soc"] = isG5 ? "SM8850" : "SM8750";
        platform["device"] = isG5 ? "baldur" : "elden";

        if (isG5)
        {
            metadata.Remove("edlProfile");
            metadata["bootCompatibility"]!.AsObject().Remove("firmwareVersions");
        }

        var recipe = metadata["bootRecipe"]!.AsObject();
        recipe["normalBootArgs"] = normal;
        recipe["diagnosticBootArgs"] = diagnostic;
        fixture.WriteMetadata(metadata);

        return fixture;
    }

    private static void AssertRejected(string model, string normal, string diagnostic)
    {
        using var fixture = Prepare(model, normal, diagnostic);

        Assert.Throws<InvalidDataException>(
            () => PackageReader.ReadEdlRawContract(fixture.Path, model));
    }
}

/// <summary>
/// Synthetic schema 2 (direct EDL raw) package. All payloads are tiny placeholders written into a temp
/// directory inside the test artifact root; the runtime role is exactly 4194304 bytes because the
/// contract fixes that size. The two raw roles are real gzip streams of a few KiB: their declared
/// expanded image and expanded hash are standalone declarations and are deliberately not expanded by
/// the reader under test, so nothing here is a Ready, flashable or device proof.
/// </summary>
internal sealed class EdlRawFixture : IDisposable
{
    internal const long GiB = 1073741824L;

    internal const string Model = "TB322FC";
    internal const string PackageId = "armadaos-freedom-edl-g4";
    internal const string PackageVersion = "1.5.10.259";
    internal const string SourceCommit = "244b74516d99d06cb0518609ce4b842ab278be8a";
    internal const string ProfileId = "g4-9008-259";
    internal const string HardwareId = "0028D0E100400000";

    internal const string AndroidBuild =
        "TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.259_ST_260611";

    internal const string NeighbouringBuild =
        "TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.260_ST_260612";

    internal const string DeploymentCommit =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    internal const string BootChecksum =
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    internal const string BootUuid = "0b7c1e6a-2f17-4a0e-9b4f-1c2d3e4f5a6b";
    internal const string RootUuid = "7d3e5f21-8c4a-4b6d-a1e2-5f60718293a4";

    internal const string Origin = "ostree-image-signed:docker://ghcr.io/mydanyi/armadaos-freedom:stable";

    internal const string DiagnosticSuffix = " rd.break=pre-mount";

    internal const string MetadataFileName = "package.json";
    internal const string BootImageFile = "images/linux-boot.img.gz";
    internal const string RootImageFile = "images/linux-root.img.gz";
    internal const string KernelFile = "images/kernel";
    internal const string RuntimeFile = "images/runtime.bin";
    internal const string InitramfsFile = "images/initramfs.img";
    internal const string DtbNormalFile = "images/dtb-normal.dtb";
    internal const string DtbDiagnosticFile = "images/dtb-diagnostic.dtb";
    internal const string KernelCopyFile = "images/kernel-copy";
    internal const string SeedFile = "images/seed.bin";

    internal const long RootExpandedBytes = 16384L;

    internal static readonly string[] Roles =
    {
        "linux-boot-raw",
        "linux-root-raw",
        "kernel",
        "runtime",
        "initramfs",
        "dtb-normal",
        "dtb-diagnostic",
    };

    internal static readonly JsonSerializerOptions WriteOptions = new() { WriteIndented = true };

    private static readonly byte[] BootExpandedImage = Payload(4096, 0x11);
    private static readonly byte[] RootExpandedImage = Payload(16384, 0x77);

    private EdlRawFixture()
    {
        Path = System.IO.Path.Combine(TestArtifactRoot.Resolve(), "edl-raw-package-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    internal string Path { get; }

    internal static string BootExpandedSha => Sha256Hex(BootExpandedImage);

    internal static string RootExpandedSha => Sha256Hex(RootExpandedImage);

    internal static string NormalBootArgs =>
        "console=ttyMSM0,115200n8 androidboot.hardware=elden root=UUID=" + RootUuid
        + " boot=UUID=" + BootUuid
        + " ostree=/ostree/boot.0/default/" + BootChecksum + "/0";

    internal string MetadataPath => System.IO.Path.Combine(Path, MetadataFileName);

    internal string ManifestFingerprint => Sha256Hex(File.ReadAllBytes(MetadataPath));

    internal static EdlRawFixture Create()
    {
        var fixture = new EdlRawFixture();
        fixture.WriteDefaultPayloads();
        fixture.WriteMetadata(fixture.BuildMetadata());
        return fixture;
    }

    internal JsonObject ReadMetadata() =>
        JsonNode.Parse(File.ReadAllText(MetadataPath))!.AsObject();

    internal void WriteMetadata(JsonObject metadata) =>
        File.WriteAllText(MetadataPath, metadata.ToJsonString(WriteOptions));

    internal JsonObject Describe(string role, string relativePath)
    {
        var fullPath = System.IO.Path.Combine(Path, relativePath);
        return new JsonObject
        {
            ["role"] = role,
            ["file"] = relativePath,
            ["bytes"] = new FileInfo(fullPath).Length,
            ["sha256"] = Sha256Of(relativePath),
        };
    }

    internal string Sha256Of(string relativePath) =>
        Sha256Hex(File.ReadAllBytes(System.IO.Path.Combine(Path, relativePath)));

    internal long BytesOf(string relativePath) =>
        new FileInfo(System.IO.Path.Combine(Path, relativePath)).Length;

    internal byte[] ReadFile(string relativePath) =>
        File.ReadAllBytes(System.IO.Path.Combine(Path, relativePath));

    internal void WriteFile(string relativePath, byte[] bytes)
    {
        var fullPath = System.IO.Path.Combine(Path, relativePath);
        var directory = System.IO.Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllBytes(fullPath, bytes);
    }

    internal void Tamper(string relativePath)
    {
        var bytes = ReadFile(relativePath);
        bytes[0] ^= 0xFF;
        WriteFile(relativePath, bytes);
    }

    internal void Truncate(string relativePath)
    {
        var bytes = ReadFile(relativePath);
        WriteFile(relativePath, bytes[..^1]);
    }

    internal void Delete(string relativePath) =>
        File.Delete(System.IO.Path.Combine(Path, relativePath));

    internal static byte[] Payload(int length, byte seed)
    {
        var bytes = new byte[length];
        for (var index = 0; index < length; index++)
        {
            bytes[index] = (byte)((seed + index) & 0xFF);
        }

        return bytes;
    }

    internal static string Sha256Hex(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));

    public void Dispose()
    {
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

    private void WriteDefaultPayloads()
    {
        WriteFile(BootImageFile, Gzip(BootExpandedImage));
        WriteFile(RootImageFile, Gzip(RootExpandedImage));
        WriteFile(KernelFile, Payload(4096, 0x4B));
        WriteFile(RuntimeFile, Payload(4194304, 0x52));
        WriteFile(InitramfsFile, Payload(2048, 0x21));
        WriteFile(DtbNormalFile, Payload(1024, 0x6E));
        WriteFile(DtbDiagnosticFile, Payload(1024, 0x64));
    }

    private JsonObject DescribeRaw(string role, string relativePath, bool boot)
    {
        var entry = Describe(role, relativePath);
        entry["compression"] = "gzip";
        entry["expandedBytes"] = boot ? 1L * GiB : RootExpandedBytes;
        entry["expandedSha256"] = boot ? BootExpandedSha : RootExpandedSha;
        entry["sectorSize"] = 4096;
        entry["fsType"] = boot ? "ext4" : "btrfs";
        entry["fsUuid"] = boot ? BootUuid : RootUuid;
        entry["minimumPartitionBytes"] = boot ? 1L * GiB : RootExpandedBytes;
        return entry;
    }

    private JsonObject BuildMetadata() => new()
    {
        ["schemaVersion"] = 2,
        ["packageId"] = PackageId,
        ["version"] = PackageVersion,
        ["deviceModel"] = Model,
        ["sourceCommit"] = SourceCommit,
        ["testOnly"] = true,
        ["compatible"] = new JsonObject
        {
            ["soc"] = "SM8750",
            ["device"] = "elden",
        },
        ["installTargets"] = new JsonArray("internal"),
        ["edlProfile"] = new JsonObject
        {
            ["id"] = ProfileId,
            ["hardwareId"] = HardwareId,
            ["androidBuild"] = AndroidBuild,
        },
        ["bootCompatibility"] = new JsonObject
        {
            ["format"] = "android-boot-v4",
            ["partitionBytes"] = 100_663_296L,
            ["firmwareVersions"] = new JsonArray(AndroidBuild),
        },
        ["toolsCompatibility"] = new JsonObject
        {
            ["installerProtocol"] = 2,
            ["bootBuilderProtocol"] = 1,
        },
        ["storage"] = new JsonObject
        {
            ["linuxBootBytes"] = 1L * GiB,
            ["systemRequiredBytes"] = 20L * GiB,
            ["deploymentScratchBytes"] = 0L,
            ["minimumLinuxDataBytes"] = 8L * GiB,
        },
        ["artifacts"] = new JsonArray
        {
            DescribeRaw("linux-boot-raw", BootImageFile, boot: true),
            DescribeRaw("linux-root-raw", RootImageFile, boot: false),
            Describe("kernel", KernelFile),
            Describe("runtime", RuntimeFile),
            Describe("initramfs", InitramfsFile),
            Describe("dtb-normal", DtbNormalFile),
            Describe("dtb-diagnostic", DtbDiagnosticFile),
        },
        ["deployment"] = new JsonObject
        {
            ["kind"] = "edl-raw-v1",
            ["commit"] = DeploymentCommit,
            ["manifestDigest"] = "sha256:" + DeploymentCommit,
            ["origin"] = Origin,
            ["bootChecksum"] = BootChecksum,
        },
        ["bootRecipe"] = new JsonObject
        {
            ["bootUuid"] = BootUuid,
            ["rootUuid"] = RootUuid,
            ["normalBootArgs"] = NormalBootArgs,
            ["diagnosticBootArgs"] = NormalBootArgs + DiagnosticSuffix,
            ["defaultEntry"] = "android",
        },
    };

    private static byte[] Gzip(byte[] payload)
    {
        using var buffer = new MemoryStream();
        using (var gzip = new GZipStream(buffer, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            gzip.Write(payload, 0, payload.Length);
        }

        return buffer.ToArray();
    }
}
