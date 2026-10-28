using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Contract specifications of the schema 2 TF-card raw target: the same strict shared parser under the
/// closed TfCard selector, the exact <c>tf</c> root medium, the nonzero distinct source internal UUID
/// pair, and the one optional ordinary <c>tf-maintenance-initramfs</c> role.
/// <para>
/// Every fixture is a minimal metadata mutation of <see cref="EdlRawFixture"/>; the real gzip/ordinary
/// payloads and their actual hashes are preserved untouched. Accepting a package here is metadata and
/// file-hash validation only — never a disk, Ready, boot-chain, device or completion proof, and never a
/// statement that the maintenance initramfs would boot or fit any budget. The real internal snapshot
/// factory must refuse a successfully imported TF package before any expansion.
/// </para>
/// </summary>
public sealed class TfRawPackageContractTests
{
    private const long GiB = EdlRawFixture.GiB;

    private const string TfSourceBootUuid = "5e9f8a3c-1b2d-4c6e-8a70-d4e5f6a7b8c9";

    private const string TfSourceRootUuid = "9a4c7e15-3d68-42f0-b5a1-c8e2d7f40b63";

    private const string MaintenanceFile = "images/tf-maintenance-initramfs.img";

    private const string MaintenanceRole = "tf-maintenance-initramfs";

    private const string OtherMaintenanceFile = "images/tf-maintenance-initramfs-copy.img";

    // ------------------------------------------------------------------------ valid TF contracts

    [Fact]
    public void ReadTfRawContract_ValidSevenRoleTfPackage_ForwardsFactsAndHasNoMaintenanceRole()
    {
        using var fixture = CreateTfFixture();

        var contract = PackageReader.ReadTfRawContract(fixture.Path, EdlRawFixture.Model);

        Assert.Equal("tf", contract.RootMedium);
        Assert.Equal("tf-raw-v1", contract.Deployment.Kind);
        Assert.Equal(Guid.Parse(TfSourceBootUuid), contract.SourceInternalBootUuid);
        Assert.Equal(Guid.Parse(TfSourceRootUuid), contract.SourceInternalRootUuid);
        Assert.NotEqual(contract.SourceInternalBootUuid, contract.SourceInternalRootUuid);
        Assert.NotEqual(Guid.Empty, contract.SourceInternalBootUuid);
        Assert.NotEqual(Guid.Empty, contract.SourceInternalRootUuid);
        Assert.Null(contract.MaintenanceInitramfs);

        // Forwarded immutable facts stay exactly the shared parser's values.
        Assert.Equal(Path.GetFullPath(fixture.Path), contract.PackageDirectory);
        Assert.Equal(EdlRawFixture.PackageId, contract.PackageId);
        Assert.Equal(EdlRawFixture.PackageVersion, contract.Version);
        Assert.Equal("TB322FC", contract.DeviceModel);
        Assert.True(contract.Raw.TestOnly);
        Assert.Equal(fixture.ManifestFingerprint, contract.ManifestFingerprint);
        Assert.Equal(1L * GiB, contract.Storage.LinuxBootBytes);
        Assert.Equal(7, contract.Artifacts.Count);
        Assert.Equal(Guid.Parse(EdlRawFixture.BootUuid), contract.BootRecipe.BootUuid);
        Assert.Equal(Guid.Parse(EdlRawFixture.RootUuid), contract.BootRecipe.RootUuid);
        Assert.Equal(Guid.Parse(EdlRawFixture.BootUuid), contract.BootImage.FsUuid);
        Assert.Equal(Guid.Parse(EdlRawFixture.RootUuid), contract.RootImage.FsUuid);
        Assert.Equal(EdlRawFixture.NormalBootArgs, contract.BootRecipe.NormalBootArgs);
    }

    [Fact]
    public void Validate_TfCardAcceptsAValidTfPackageWithTheExactRouteMetadata()
    {
        using var fixture = CreateTfFixture();

        var result = PackageReader.Validate(fixture.Path, EdlRawFixture.Model, InstallationTarget.TfCard);

        Assert.True(result.IsValid, string.Join("; ", result.Reasons));
        Assert.Empty(result.Reasons);
        Assert.Equal("tf-raw-v1", result.DeploymentKind);
        Assert.Equal(fixture.ManifestFingerprint, result.ManifestFingerprint);
        Assert.Equal(EdlRawFixture.PackageId, result.PackageId);
        Assert.Equal(EdlRawFixture.PackageVersion, result.Version);
        Assert.NotNull(result.Storage);
        Assert.Equal(1L * GiB, result.Storage!.LinuxBootBytes);
    }

    [Fact]
    public void ReadTfRawContract_EighthMaintenanceRoleIsExposedWithExactGetterFacts()
    {
        using var fixture = CreateTfFixture(withMaintenance: true);

        var contract = PackageReader.ReadTfRawContract(fixture.Path, EdlRawFixture.Model);

        Assert.Equal(8, contract.Artifacts.Count);
        Assert.NotNull(contract.MaintenanceInitramfs);
        Assert.Same(contract.Artifacts[MaintenanceRole], contract.MaintenanceInitramfs);
        Assert.Equal(MaintenanceRole, contract.MaintenanceInitramfs!.Role);
        Assert.Equal(MaintenanceFile, contract.MaintenanceInitramfs.RelativePath);
        Assert.Equal(fixture.BytesOf(MaintenanceFile), contract.MaintenanceInitramfs.Bytes);
        Assert.Equal(fixture.Sha256Of(MaintenanceFile), contract.MaintenanceInitramfs.Sha256);

        // The eighth role is ordinary: it never became a raw image role and the images stay the two
        // shared ones.
        Assert.Equal("gzip", contract.BootImage.Compression);
        Assert.Equal("btrfs", contract.RootImage.FsType);
    }

    [Fact]
    public void Validate_TfCardAcceptsAValidTfPackageWithTheEighthRole()
    {
        using var fixture = CreateTfFixture(withMaintenance: true, production: true);

        var result = PackageReader.Validate(fixture.Path, EdlRawFixture.Model, InstallationTarget.TfCard);

        Assert.True(result.IsValid, string.Join("; ", result.Reasons));
        Assert.Equal("tf-raw-v1", result.DeploymentKind);
        Assert.False(result.TestOnly);
    }

    // ------------------------------------------------------------- optional eighth role is strict

    [Theory]
    [InlineData("duplicate-role")]
    [InlineData("unknown-extra-role")]
    [InlineData("missing-file")]
    [InlineData("mismatched-bytes")]
    [InlineData("mismatched-sha")]
    [InlineData("image-only-compression")]
    [InlineData("image-only-fsuuid")]
    public void ReadTfRawContract_RejectsBrokenOptionalMaintenanceRole(string mutation)
    {
        using var fixture = CreateTfFixture(withMaintenance: mutation == "duplicate-role");

        var metadata = fixture.ReadMetadata();
        var artifacts = metadata["artifacts"]!.AsArray();

        switch (mutation)
        {
            case "duplicate-role":
                fixture.WriteFile(OtherMaintenanceFile, EdlRawFixture.Payload(32, 0x2A));
                artifacts.Add(fixture.Describe(MaintenanceRole, OtherMaintenanceFile));
                break;
            case "unknown-extra-role":
                fixture.WriteFile(OtherMaintenanceFile, EdlRawFixture.Payload(32, 0x2A));
                artifacts.Add(fixture.Describe("tf-ram-extra", OtherMaintenanceFile));
                break;
            case "missing-file":
                artifacts.Add(new JsonObject
                {
                    ["role"] = MaintenanceRole,
                    ["file"] = MaintenanceFile,
                    ["bytes"] = 128L,
                    ["sha256"] = EdlRawFixture.Sha256Hex(EdlRawFixture.Payload(128, 0x11)),
                });
                break;
            case "mismatched-bytes":
                fixture.WriteFile(MaintenanceFile, EdlRawFixture.Payload(64, 0x5A));
                artifacts.Add(fixture.Describe(MaintenanceRole, MaintenanceFile));
                Artifact(metadata, MaintenanceRole)["bytes"] =
                    fixture.BytesOf(MaintenanceFile) + 1;
                break;
            case "mismatched-sha":
                fixture.WriteFile(MaintenanceFile, EdlRawFixture.Payload(64, 0x5A));
                artifacts.Add(fixture.Describe(MaintenanceRole, MaintenanceFile));
                Artifact(metadata, MaintenanceRole)["sha256"] = new string('a', 64);
                break;
            case "image-only-compression":
                fixture.WriteFile(MaintenanceFile, EdlRawFixture.Payload(64, 0x5A));
                artifacts.Add(fixture.Describe(MaintenanceRole, MaintenanceFile));
                Artifact(metadata, MaintenanceRole)["compression"] = "gzip";
                break;
            case "image-only-fsuuid":
                fixture.WriteFile(MaintenanceFile, EdlRawFixture.Payload(64, 0x5A));
                artifacts.Add(fixture.Describe(MaintenanceRole, MaintenanceFile));
                Artifact(metadata, MaintenanceRole)["fsUuid"] = EdlRawFixture.BootUuid;
                break;
        }

        fixture.WriteMetadata(metadata);

        Assert.Throws<InvalidDataException>(
            () => PackageReader.ReadTfRawContract(fixture.Path, EdlRawFixture.Model));
    }

    [Fact]
    public void ReadEdlRawContract_RejectsTheMaintenanceRoleOnAnInternalPackage()
    {
        using var fixture = EdlRawFixture.Create();
        var metadata = fixture.ReadMetadata();
        fixture.WriteFile(MaintenanceFile, EdlRawFixture.Payload(64, 0x5A));
        metadata["artifacts"]!.AsArray().Add(fixture.Describe(MaintenanceRole, MaintenanceFile));
        fixture.WriteMetadata(metadata);

        Assert.Throws<InvalidDataException>(
            () => PackageReader.ReadEdlRawContract(fixture.Path, EdlRawFixture.Model));
    }

    [Fact]
    public void ReadEdlRawContract_StillAcceptsTheOriginalSevenRoleInternalPackage()
    {
        using var fixture = EdlRawFixture.Create();

        var contract = PackageReader.ReadEdlRawContract(fixture.Path, EdlRawFixture.Model);

        Assert.Equal(7, contract.Artifacts.Count);
        Assert.Equal("edl-raw-v1", contract.Deployment.Kind);
    }

    // ------------------------------------------------------------------ cross-target rejections

    [Fact]
    public void InternalPackageSucceedsOnInternalRouteAndFailsOnBothTfRoutes()
    {
        using var fixture = EdlRawFixture.Create();

        var contract = PackageReader.ReadEdlRawContract(fixture.Path, EdlRawFixture.Model);
        Assert.Equal("edl-raw-v1", contract.Deployment.Kind);

        var result = PackageReader.Validate(fixture.Path, EdlRawFixture.Model, InstallationTarget.Internal);
        Assert.True(result.IsValid, string.Join("; ", result.Reasons));

        Assert.Throws<InvalidDataException>(
            () => PackageReader.ReadTfRawContract(fixture.Path, EdlRawFixture.Model));

        var tfResult = PackageReader.Validate(fixture.Path, EdlRawFixture.Model, InstallationTarget.TfCard);
        Assert.False(tfResult.IsValid);
        Assert.NotEmpty(tfResult.Reasons);

        // An invalid result never exposes successful contract metadata.
        Assert.Null(tfResult.PackageId);
        Assert.Null(tfResult.Storage);
        Assert.Null(tfResult.DeploymentKind);
        Assert.Null(tfResult.ManifestFingerprint);
    }

    [Fact]
    public void TfPackageSucceedsOnTfRouteAndFailsOnBothInternalRoutes()
    {
        using var fixture = CreateTfFixture();

        var contract = PackageReader.ReadTfRawContract(fixture.Path, EdlRawFixture.Model);
        Assert.Equal("tf-raw-v1", contract.Deployment.Kind);

        var result = PackageReader.Validate(fixture.Path, EdlRawFixture.Model, InstallationTarget.TfCard);
        Assert.True(result.IsValid, string.Join("; ", result.Reasons));

        Assert.Throws<InvalidDataException>(
            () => PackageReader.ReadEdlRawContract(fixture.Path, EdlRawFixture.Model));

        var internalResult = PackageReader.Validate(fixture.Path, EdlRawFixture.Model, InstallationTarget.Internal);
        Assert.False(internalResult.IsValid);
        Assert.NotEmpty(internalResult.Reasons);
        Assert.Null(internalResult.PackageId);
        Assert.Null(internalResult.Storage);
        Assert.Null(internalResult.DeploymentKind);
    }

    [Fact]
    public void ReadEdlRawContract_RejectsAValidTfPackage()
    {
        using var fixture = CreateTfFixture();

        Assert.Throws<InvalidDataException>(
            () => PackageReader.ReadEdlRawContract(fixture.Path, EdlRawFixture.Model));
    }

    [Theory]
    [InlineData("mixed")]
    [InlineData("missing")]
    [InlineData("duplicate-tf")]
    [InlineData("unknown-target")]
    [InlineData("empty")]
    public void InstallTargetMutationsRejectOnBothRoutes(string mutation)
    {
        // TF route on a mutated TF fixture...
        using var tfFixture = CreateTfFixture();
        var tfMetadata = tfFixture.ReadMetadata();
        MutateTargets(tfMetadata, mutation, "tf");
        tfFixture.WriteMetadata(tfMetadata);

        Assert.Throws<InvalidDataException>(
            () => PackageReader.ReadTfRawContract(tfFixture.Path, EdlRawFixture.Model));
        Assert.False(PackageReader.Validate(tfFixture.Path, EdlRawFixture.Model, InstallationTarget.TfCard).IsValid);

        // ...and the mirrored mutation on an internal fixture for the internal route.
        using var internalFixture = EdlRawFixture.Create();
        var internalMetadata = internalFixture.ReadMetadata();
        MutateTargets(internalMetadata, mutation, "internal");
        internalFixture.WriteMetadata(internalMetadata);

        Assert.Throws<InvalidDataException>(
            () => PackageReader.ReadEdlRawContract(internalFixture.Path, EdlRawFixture.Model));
        Assert.False(PackageReader.Validate(internalFixture.Path, EdlRawFixture.Model, InstallationTarget.Internal).IsValid);
    }

    [Theory]
    [InlineData("internal")]
    [InlineData("tfcard-on-internal")]
    public void DeploymentKindMismatchRejectsOnItsOwnRoute(string direction)
    {
        if (direction == "internal")
        {
            // A TF package that still declares the internal kind fails every TF route.
            using var fixture = CreateTfFixture();
            var metadata = fixture.ReadMetadata();
            metadata["deployment"]!["kind"] = "edl-raw-v1";
            fixture.WriteMetadata(metadata);

            Assert.Throws<InvalidDataException>(
                () => PackageReader.ReadTfRawContract(fixture.Path, EdlRawFixture.Model));
            Assert.False(PackageReader.Validate(fixture.Path, EdlRawFixture.Model, InstallationTarget.TfCard).IsValid);
        }
        else
        {
            // An internal package that declares the TF kind fails every internal route.
            using var fixture = EdlRawFixture.Create();
            var metadata = fixture.ReadMetadata();
            metadata["deployment"]!["kind"] = "tf-raw-v1";
            fixture.WriteMetadata(metadata);

            Assert.Throws<InvalidDataException>(
                () => PackageReader.ReadEdlRawContract(fixture.Path, EdlRawFixture.Model));
            Assert.False(PackageReader.Validate(fixture.Path, EdlRawFixture.Model, InstallationTarget.Internal).IsValid);
        }
    }

    // -------------------------------------------------------------- TF-only recipe requirements

    [Theory]
    [InlineData("root-medium-missing")]
    [InlineData("root-medium-internal")]
    [InlineData("root-medium-wrong-type")]
    [InlineData("source-boot-missing")]
    [InlineData("source-root-missing")]
    [InlineData("source-boot-malformed")]
    [InlineData("source-root-malformed")]
    [InlineData("source-boot-zero")]
    [InlineData("source-root-zero")]
    [InlineData("source-pair-equal")]
    [InlineData("boot-eq-source-boot")]
    [InlineData("boot-eq-source-root")]
    [InlineData("root-eq-source-boot")]
    [InlineData("root-eq-source-root")]
    public void ReadTfRawContract_RejectsBrokenTfRecipeFacts(string mutation)
    {
        using var fixture = CreateTfFixture();
        var metadata = fixture.ReadMetadata();
        var recipe = Recipe(metadata);

        switch (mutation)
        {
            case "root-medium-missing":
                recipe.Remove("rootMedium");
                break;
            case "root-medium-internal":
                recipe["rootMedium"] = "internal";
                break;
            case "root-medium-wrong-type":
                recipe["rootMedium"] = 42;
                break;
            case "source-boot-missing":
                recipe.Remove("sourceInternalBootUuid");
                break;
            case "source-root-missing":
                recipe.Remove("sourceInternalRootUuid");
                break;
            case "source-boot-malformed":
                recipe["sourceInternalBootUuid"] = "not-a-guid";
                break;
            case "source-root-malformed":
                recipe["sourceInternalRootUuid"] = "5e9f8a3c";
                break;
            case "source-boot-zero":
                recipe["sourceInternalBootUuid"] = "00000000-0000-0000-0000-000000000000";
                break;
            case "source-root-zero":
                recipe["sourceInternalRootUuid"] = "00000000-0000-0000-0000-000000000000";
                break;
            case "source-pair-equal":
                recipe["sourceInternalRootUuid"] = TfSourceBootUuid;
                break;
            case "boot-eq-source-boot":
                recipe["sourceInternalBootUuid"] = EdlRawFixture.BootUuid;
                break;
            case "boot-eq-source-root":
                recipe["sourceInternalRootUuid"] = EdlRawFixture.BootUuid;
                break;
            case "root-eq-source-boot":
                recipe["sourceInternalBootUuid"] = EdlRawFixture.RootUuid;
                break;
            case "root-eq-source-root":
                recipe["sourceInternalRootUuid"] = EdlRawFixture.RootUuid;
                break;
        }

        fixture.WriteMetadata(metadata);

        var exception = Assert.Throws<InvalidDataException>(
            () => PackageReader.ReadTfRawContract(fixture.Path, EdlRawFixture.Model));

        if (mutation is "boot-eq-source-boot" or "boot-eq-source-root"
            or "root-eq-source-boot" or "root-eq-source-root")
        {
            Assert.Contains("TF 来源", exception.Message, StringComparison.Ordinal);
        }
    }

    // -------------------------------------------------- shared strict path still fully enforced

    [Fact]
    public void ReadTfRawContract_RejectsATamperedPayloadThroughTheSharedPath()
    {
        using var fixture = CreateTfFixture();
        fixture.Tamper(EdlRawFixture.KernelFile);

        Assert.Throws<InvalidDataException>(
            () => PackageReader.ReadTfRawContract(fixture.Path, EdlRawFixture.Model));
    }

    [Fact]
    public void ReadTfRawContract_RejectsAMismatchedExpectedModel()
    {
        using var fixture = CreateTfFixture();

        var exception = Assert.Throws<InvalidDataException>(
            () => PackageReader.ReadTfRawContract(fixture.Path, "TB323FU"));

        Assert.Contains("deviceModel", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ReadTfRawContract_PreCancelledTokenIsPreserved()
    {
        using var fixture = CreateTfFixture();
        using var source = new CancellationTokenSource();
        source.Cancel();

        Assert.ThrowsAny<OperationCanceledException>(
            () => PackageReader.ReadTfRawContract(fixture.Path, EdlRawFixture.Model, source.Token));
    }

    // ------------------------------------------------------------------- immutable TF surface

    [Fact]
    public void TfContractTypeIsSealedAndExposesNoWritableMembers()
    {
        var type = typeof(TfRawPackageContract);

        Assert.True(type.IsSealed);
        Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance));

        foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            Assert.False(property.CanWrite, type.Name + "." + property.Name);
        }

        Assert.Equal(typeof(EdlRawPackageContract), type.GetProperty("Raw")!.PropertyType);
        Assert.Equal(typeof(string), type.GetProperty("RootMedium")!.PropertyType);
        Assert.Equal(typeof(Guid), type.GetProperty("SourceInternalBootUuid")!.PropertyType);
        Assert.Equal(typeof(Guid), type.GetProperty("SourceInternalRootUuid")!.PropertyType);
        Assert.Equal(typeof(EdlRawArtifact), type.GetProperty("MaintenanceInitramfs")!.PropertyType);
    }

    // --------------------------------------------- the real internal snapshot factory refuses TF

    [Fact]
    public async Task InternalSnapshotFactory_RefusesASuccessfullyImportedTfPackageBeforeExpansion()
    {
        using var fixture = CreateTfFixture(withMaintenance: true, production: true);
        using var workParent = new TempPackageDirectory();
        using var expansionParent = new TempPackageDirectory();

        using var imported = await PackageImporter.ImportAsync(
            fixture.Path,
            EdlRawFixture.Model,
            InstallationTarget.TfCard,
            workParent.Path);

        Assert.True(imported.Validation.IsValid, string.Join("; ", imported.Validation.Reasons));
        Assert.Equal("tf-raw-v1", imported.Validation.DeploymentKind);

        // ImportedPackage carries no Target property by design: the isolation being tested is that the
        // downstream internal-only re-read refuses, not the import claim.
        var error = await Assert.ThrowsAsync<InvalidDataException>(
            () => CaptureRawAsync(imported, SyntheticIdentity(), expansionParent.Path));

        Assert.Contains("installTargets", error.Message, StringComparison.Ordinal);
        Assert.Contains("internal", error.Message, StringComparison.Ordinal);

        // No expansion output of any kind was generated before the refusal.
        Assert.Empty(Directory.EnumerateFileSystemEntries(expansionParent.Path));
    }

    // ------------------------------------------------------------------------------------ helpers

    /// <summary>
    /// Builds a valid TF fixture by changing only the metadata of the shared seven-role fixture: the
    /// exact ["tf"] target list, the tf-raw-v1 kind, the tf root medium and a nonzero source UUID pair
    /// distinct from the fixture's own BootUuid/RootUuid. Every payload file and its actual hash stay
    /// exactly as built.
    /// </summary>
    private static EdlRawFixture CreateTfFixture(bool withMaintenance = false, bool production = false)
    {
        var fixture = EdlRawFixture.Create();

        if (withMaintenance)
        {
            fixture.WriteFile(MaintenanceFile, EdlRawFixture.Payload(64, 0x5A));
        }

        var metadata = fixture.ReadMetadata();
        metadata["installTargets"] = new JsonArray("tf");
        metadata["deployment"]!.AsObject()["kind"] = "tf-raw-v1";

        var recipe = metadata["bootRecipe"]!.AsObject();
        recipe["rootMedium"] = "tf";
        recipe["sourceInternalBootUuid"] = TfSourceBootUuid;
        recipe["sourceInternalRootUuid"] = TfSourceRootUuid;

        if (production)
        {
            metadata["testOnly"] = false;
        }

        if (withMaintenance)
        {
            metadata["artifacts"]!.AsArray()
                .Add(fixture.Describe(MaintenanceRole, MaintenanceFile));
        }

        fixture.WriteMetadata(metadata);
        return fixture;
    }

    private static void MutateTargets(JsonObject metadata, string mutation, string expectedTarget)
    {
        switch (mutation)
        {
            case "mixed":
                metadata["installTargets"] = new JsonArray("internal", "tf");
                break;
            case "missing":
                metadata.Remove("installTargets");
                break;
            case "duplicate-tf":
                metadata["installTargets"] = new JsonArray(expectedTarget, expectedTarget);
                break;
            case "unknown-target":
                metadata["installTargets"] = new JsonArray("sdcard");
                break;
            case "empty":
                metadata["installTargets"] = new JsonArray();
                break;
        }
    }

    private static JsonObject Artifact(JsonObject metadata, string role) =>
        metadata["artifacts"]!.AsArray()
            .Select(entry => entry!.AsObject())
            .First(entry => entry["role"]!.GetValue<string>() == role);

    private static JsonObject Recipe(JsonObject metadata) => metadata["bootRecipe"]!.AsObject();

    // Narrow reflection bridge for the internal factory, in the exact pattern of
    // InternalInstallEdlRawSnapshotTests. Only CaptureEdlRawAsync is resolved; a missing method or type
    // is a test error, never an accepted rejection.
    private static readonly Type SnapshotType =
        typeof(PackageReader).Assembly.GetType(
            "FreedomInstaller.Core.InternalInstallPackageSnapshot",
            throwOnError: true)!;

    private static readonly MethodInfo CaptureRawMethod =
        SnapshotType.GetMethod(
            "CaptureEdlRawAsync",
            BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("The approved CaptureEdlRawAsync entry point is missing.");

    private static async Task CaptureRawAsync(
        ImportedPackage package,
        DeviceIdentity identity,
        string expansionParent,
        CancellationToken cancellationToken = default)
    {
        object? task;
        try
        {
            task = CaptureRawMethod.Invoke(
                null, new object?[] { package, identity, expansionParent, cancellationToken });
        }
        catch (TargetInvocationException failure) when (failure.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(failure.InnerException!).Throw();
            throw;
        }

        await ((Task)task!).ConfigureAwait(false);
    }

    /// <summary>A complete synthetic identity; no pinned build is required by the direct entry guards.</summary>
    private static DeviceIdentity SyntheticIdentity() =>
        new("TF-READER-01-SYNTHETIC", EdlRawFixture.Model, BootloaderState.Unknown)
        {
            Firmware = new FirmwareSnapshot(
                "TF-READER-01-DISPLAY-ID",
                "Lenovo/elden_prc_wifi/elden:15/TFREADER/1:user/release-keys",
                "15",
                "2026-06-01",
                BootloaderState.Unknown),
        };
}
