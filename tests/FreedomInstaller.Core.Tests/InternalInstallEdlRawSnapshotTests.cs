using System.Buffers.Binary;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Behaviour specifications for the schema-2 direct EDL raw route of the INTERNAL
/// <c>InternalInstallPackageSnapshot</c> (BD001).
/// <para>
/// The type is internal and no <c>InternalsVisibleTo</c> exists, so this file carries one narrow
/// reflection bridge: it resolves exactly <c>CaptureEdlRawAsync</c>, the legacy <c>CaptureAsync</c> baseline,
/// <c>RevalidateAsync</c> and the approved getters. Nothing else is reflected, and the bridge never converts
/// <see cref="NotImplementedException"/> into an accepted refusal.
/// </para>
/// <para>
/// Every fixture is synthetic: a compressible zero gzip whose first block carries a synthetic ext4
/// superblock, a 17-sector Btrfs-shaped root image and two packed v17 FDTs. They are not firmware, not
/// bootable and contain no vendor image, deployment tree, device output, backup byte or credential. The
/// real <see cref="PackageReader.ReadEdlRawContract"/> and the real <c>EdlRawDtbValidator</c> stay in the
/// loop; nothing here re-implements either.
/// </para>
/// </summary>
public sealed class InternalInstallEdlRawSnapshotTests : IClassFixture<EdlRawSharedInput>
{
    private const string Model = RawFacts.Model;
    private const string AndroidBuild = RawFacts.AndroidBuild;
    private const string DeploymentCommit = RawFacts.DeploymentCommit;
    private const string BootChecksum = RawFacts.BootChecksum;
    private const string ManifestDigest = RawFacts.ManifestDigest;
    private static readonly string NormalBootArgs = RawFacts.NormalBootArgs;
    private static readonly string DiagnosticBootArgs = RawFacts.DiagnosticBootArgs;
    private const string MetadataFileName = "package.json";
    private const long BootExpandedBytes = SyntheticRawImages.BootExpandedBytes;
    private const int RootImageBytes = SyntheticRawImages.RootImageBytes;

    private static readonly Guid BootUuid = RawFacts.BootUuid;
    private static readonly Guid RootUuid = RawFacts.RootUuid;
    private static readonly Guid OtherUuid = RawFacts.OtherUuid;

    private static readonly PackageStorage ExpectedStorage = RawFacts.Storage;

    private static readonly JsonSerializerOptions WriteOptions = new() { WriteIndented = true };

    private static readonly Type SnapshotType =
        typeof(PackageReader).Assembly.GetType(
            "FreedomInstaller.Core.InternalInstallPackageSnapshot",
            throwOnError: true)!;

    private static readonly MethodInfo CaptureRawMethod =
        SnapshotType.GetMethod(
            "CaptureEdlRawAsync",
            BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("The approved CaptureEdlRawAsync entry point is missing.");

    private static readonly MethodInfo CaptureLegacyMethod =
        SnapshotType.GetMethod(
            "CaptureAsync",
            BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("The frozen CaptureAsync factory is missing.");

    private static readonly MethodInfo RevalidateMethod =
        SnapshotType.GetMethod(
            "RevalidateAsync",
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("The frozen RevalidateAsync member is missing.");

    private static readonly ConstructorInfo ImportedPackageConstructor =
        typeof(ImportedPackage).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            new[]
            {
                typeof(string), typeof(string), typeof(string),
                typeof(PackageValidationResult), typeof(string), typeof(string),
            },
            modifiers: null)
        ?? throw new InvalidOperationException("The internal ImportedPackage constructor is missing.");

    private readonly EdlRawSharedInput _fixture;

    public InternalInstallEdlRawSnapshotTests(EdlRawSharedInput fixture) => _fixture = fixture;

    // ---------------------------------------------------------------- complete direct capture

    [Fact]
    public async Task CaptureEdlRaw_ValidDirectPackage_ExposesActualExpandedFactsAndContract()
    {
        Assert.Equal(MaintenanceProfiles.AndroidBuild, AndroidBuild);

        using var package = RawPackage.Create(_fixture);
        using var expansion = new TempPackageDirectory();

        // The real Reader is the schema authority for the fixture, not this test's opinion.
        var contract = PackageReader.ReadEdlRawContract(package.Directory, Model);
        Assert.Equal(Model, contract.DeviceModel);
        Assert.Equal(BootExpandedBytes, contract.BootImage.ExpandedBytes);
        Assert.Equal((long)RootImageBytes, contract.RootImage.ExpandedBytes);

        // The real validator is the FDT authority: the synthetic bytes are a valid normal-image DTB and
        // bind the exact chosen bootargs of the reviewed recipe.
        var evidence = EdlRawDtbValidator.Validate(
            _fixture.DtbNormal, NormalBootArgs, EdlRawDtbKind.Normal, Model);
        Assert.Equal(NormalBootArgs, evidence.BootArgs);
        Assert.Equal("os", evidence.BootStage);
        Assert.Equal("internal", evidence.RootMedium);
        Assert.Equal(5u, evidence.InitrdEntryIndex);
        Assert.Contains("lenovo,elden", evidence.Compatible);
        Assert.Contains("qcom,sm8750", evidence.Compatible);

        using var imported = CreateClaimed(package, contract);
        var snapshot = await CaptureRawAsync(imported, Identity(), expansion.Path);

        try
        {
            var held = Get<EdlRawPackageContract>(snapshot, "EdlRawContract");
            Assert.Equal(BootUuid, held.BootRecipe.BootUuid);
            Assert.Equal(RootUuid, held.BootRecipe.RootUuid);
            Assert.NotEqual(held.BootRecipe.BootUuid, held.BootRecipe.RootUuid);
            Assert.Equal(NormalBootArgs, held.BootRecipe.NormalBootArgs);
            Assert.Equal(DiagnosticBootArgs, held.BootRecipe.DiagnosticBootArgs);

            // Deployment metadata stays hash-bound producer metadata: commit and bootChecksum are distinct
            // facts, and no deployment-tree content is claimed to have been observed on Windows.
            Assert.Equal("edl-raw-v1", held.Deployment.Kind);
            Assert.Equal(DeploymentCommit, held.Deployment.Commit);
            Assert.Equal(BootChecksum, held.Deployment.BootChecksum);
            Assert.NotEqual(held.Deployment.Commit, held.Deployment.BootChecksum);
            Assert.Equal(ManifestDigest, held.Deployment.ManifestDigest);
            Assert.Equal(RawFacts.Origin, held.Deployment.Origin);

            // The exposed raw facts are the ACTUAL expanded images, under the explicit expansion parent,
            // with the complete expanded length and an independently computed digest.
            var boot = Get<VerifiedEdlFile>(snapshot, "LinuxBootRaw");
            Assert.Equal(BootExpandedBytes, boot.Length);
            Assert.Equal(_fixture.BootExpandedSha256, boot.Sha256, ignoreCase: true);
            AssertUnder(expansion.Path, boot.Path);
            AssertActualExt4(boot.Path, BootUuid);

            var root = Get<VerifiedEdlFile>(snapshot, "LinuxRootRaw");
            Assert.Equal((long)RootImageBytes, root.Length);
            Assert.Equal(_fixture.RootExpandedSha256, root.Sha256, ignoreCase: true);
            AssertUnder(expansion.Path, root.Path);
            AssertActualBtrfs(root.Path, RootUuid);

            // The exposed digests must belong to the bytes actually written, so each returned path is hashed
            // again in one streamed pass — the 1 GiB boot image is never materialised as an array — and both
            // the expected full-image digest and the returned VerifiedEdlFile digest must agree with it.
            var bootActual = await Sha256OfFileAsync(boot.Path);
            Assert.Equal(_fixture.BootExpandedSha256, bootActual, ignoreCase: true);
            Assert.Equal(boot.Sha256, bootActual, ignoreCase: true);

            var rootActual = await Sha256OfFileAsync(root.Path);
            Assert.Equal(_fixture.RootExpandedSha256, rootActual, ignoreCase: true);
            Assert.Equal(root.Sha256, rootActual, ignoreCase: true);

            // Payloads keeps describing the held package files, which stay COMPRESSED for both raw roles.
            var payloads = Get<IReadOnlyDictionary<string, VerifiedEdlFile>>(snapshot, "Payloads");
            Assert.Equal(7, payloads.Count);
            Assert.False(payloads.ContainsKey("ostree-seed"));
            Assert.Equal(_fixture.BootCompressedBytes, package.Artifact("linux-boot-raw").Length);
            Assert.Equal(
                _fixture.BootCompressedSha256,
                package.Artifact("linux-boot-raw").Sha256,
                ignoreCase: true);
            Assert.Equal(package.Artifact("linux-boot-raw").Length, payloads["linux-boot-raw"].Length);
            Assert.Equal(
                package.Artifact("linux-boot-raw").Sha256,
                payloads["linux-boot-raw"].Sha256,
                ignoreCase: true);
            Assert.NotEqual(boot.Length, payloads["linux-boot-raw"].Length);

            // A direct capture never fabricates the legacy seed or a RAM receipt.
            AssertNotProvided(snapshot, "Seed");

            await RevalidateAsync(snapshot);
        }
        finally
        {
            DisposeQuietly(snapshot);
        }
    }

    // ---------------------------------------------------------------- optional common-package group

    [Fact]
    public async Task CaptureEdlRaw_CommonPackageWithoutAndroidProfile_StillExposesActualFacts()
    {
        using var package = RawPackage.Create(_fixture);
        using var expansion = new TempPackageDirectory();

        // A standard common system package declares neither the Android profile group nor the coupled
        // firmware list. Only those two optional declarations are removed; every artifact stays as built.
        package.EditManifest(
            metadata =>
            {
                metadata.Remove("edlProfile");
                metadata["bootCompatibility"]!.AsObject().Remove("firmwareVersions");
            });

        var contract = PackageReader.ReadEdlRawContract(package.Directory, Model);
        Assert.Null(contract.EdlProfileId);
        Assert.Null(contract.HardwareId);
        Assert.Null(contract.AndroidBuild);
        Assert.Empty(contract.FirmwareVersions);

        // The real reader and the real validator stay the only authorities for this actual package.
        using var imported = CreateClaimed(package, contract);
        var snapshot = await CaptureRawAsync(imported, Identity(), expansion.Path);

        try
        {
            // The returned typed contract still carries the absent optional group: no default profile and
            // no synthesized identity were invented to fill the gap.
            var held = Get<EdlRawPackageContract>(snapshot, "EdlRawContract");
            Assert.Null(held.EdlProfileId);
            Assert.Null(held.HardwareId);
            Assert.Null(held.AndroidBuild);
            Assert.Empty(held.FirmwareVersions);
            Assert.Equal(Model, held.DeviceModel);

            // The observed identity is exposed as observed, not replaced by the missing package claim.
            var firmware = Get<FirmwareSnapshot>(snapshot, "Firmware");
            Assert.Equal(AndroidBuild, firmware.DisplayId);
            Assert.Equal(RawFacts.BuildFingerprint, firmware.BuildFingerprint);
            Assert.Equal("15", firmware.AndroidRelease);
            Assert.Equal("2026-06-01", firmware.SecurityPatch);

            var boot = Get<VerifiedEdlFile>(snapshot, "LinuxBootRaw");
            Assert.Equal(BootExpandedBytes, boot.Length);
            Assert.Equal(_fixture.BootExpandedSha256, boot.Sha256, ignoreCase: true);
            AssertUnder(expansion.Path, boot.Path);

            var root = Get<VerifiedEdlFile>(snapshot, "LinuxRootRaw");
            Assert.Equal((long)RootImageBytes, root.Length);
            Assert.Equal(_fixture.RootExpandedSha256, root.Sha256, ignoreCase: true);
            AssertUnder(expansion.Path, root.Path);

            var bootActual = await Sha256OfFileAsync(boot.Path);
            Assert.Equal(boot.Sha256, bootActual, ignoreCase: true);
            var rootActual = await Sha256OfFileAsync(root.Path);
            Assert.Equal(root.Sha256, rootActual, ignoreCase: true);

            // A package without the optional group never manufactures a seed, RAM receipt or profile claim.
            AssertNotProvided(snapshot, "Seed");
            Assert.Equal(7, Get<IReadOnlyDictionary<string, VerifiedEdlFile>>(snapshot, "Payloads").Count);

            await RevalidateAsync(snapshot);
        }
        finally
        {
            DisposeQuietly(snapshot);
        }
    }

    // ---------------------------------------------------------------- schema 1 stays on its own route

    [Fact]
    public async Task CaptureEdlRaw_RefusesSchema1WhileLegacyCaptureKeepsItsOwnFacts()
    {
        using var package = LegacyPackage.Write();
        using var expansion = new TempPackageDirectory();

        var validation = PackageReader.Validate(package.Directory, Model, InstallationTarget.Internal);
        Assert.True(validation.IsValid, string.Join("; ", validation.Reasons));

        using var imported = CreateClaimed(package.Directory, validation);

        // The legacy baseline keeps working and keeps exactly its own seed fact.
        var legacy = await CaptureAsync(imported, Identity());
        try
        {
            Assert.NotNull(Get<RamInstallSeed>(legacy, "Seed"));
            AssertNotProvided(legacy, "EdlRawContract");
            AssertNotProvided(legacy, "LinuxBootRaw");
            AssertNotProvided(legacy, "LinuxRootRaw");

            await RevalidateAsync(legacy);
        }
        finally
        {
            DisposeQuietly(legacy);
        }

        // Even with a plausible imported verdict, the direct entry never synthesizes a schema-1 package.
        await AssertRawRefusedAsync(imported, Identity(), expansion.Path);
        Assert.Empty(Directory.EnumerateFileSystemEntries(expansion.Path));
    }

    // ---------------------------------------------------------------- stale trust after import

    [Fact]
    public async Task CaptureEdlRaw_ManifestChangedAfterImportClaim_IsRefused()
    {
        using var package = RawPackage.Create(_fixture);
        using var expansion = new TempPackageDirectory();

        using var imported = CreateClaimed(package);
        var claimedFingerprint = package.ManifestFingerprint;

        // A harmless rewrite: still a structurally valid direct package, but no longer the imported bytes.
        package.EditManifest(metadata => metadata["version"] = "1.0.1");
        Assert.True(PackageReader.ReadEdlRawContract(package.Directory, Model).BootRecipe.RootUuid == RootUuid);
        Assert.NotEqual(claimedFingerprint, package.ManifestFingerprint);

        await AssertRawRefusedAsync(imported, Identity(), expansion.Path);
    }

    [Fact]
    public async Task CaptureEdlRaw_CompressedPayloadChangedAfterImportClaim_IsRefused()
    {
        using var package = RawPackage.Create(_fixture);
        using var expansion = new TempPackageDirectory();

        using var imported = CreateClaimed(package);

        // Same length, different compressed bytes: only the held-lease hash check can notice this.
        var target = package.ArtifactPath("linux-root-raw");
        var before = new FileInfo(target).Length;
        FlipOneByte(target);
        Assert.Equal(before, new FileInfo(target).Length);

        await AssertRawRefusedAsync(imported, Identity(), expansion.Path);
    }

    // ---------------------------------------------------------------- expanded size and digest

    [Theory]
    [InlineData("expanded-sha")]
    [InlineData("declared-larger")]
    [InlineData("declared-smaller")]
    public async Task CaptureEdlRaw_WrongExpandedDigestOrSize_IsRefused(string change)
    {
        using var package = RawPackage.Create(_fixture);
        using var expansion = new TempPackageDirectory();

        switch (change)
        {
            case "expanded-sha":
                package.EditManifest(
                    _ => package.ArtifactNode("linux-root-raw")["expandedSha256"] = new string('A', 64));
                break;
            case "declared-larger":
                // The gzip output ends before the declared length: a short expansion.
                package.EditManifest(
                    _ => package.ArtifactNode("linux-root-raw")["expandedBytes"] = (long)RootImageBytes + 4096);
                break;
            default:
                // The gzip output exceeds the declared length: the bounded writer must stop promptly.
                package.EditManifest(
                    _ => package.ArtifactNode("linux-root-raw")["expandedBytes"] = (long)RootImageBytes - 4096);
                break;
        }

        using var imported = CreateClaimed(package);
        await AssertRawRefusedAsync(imported, Identity(), expansion.Path);
    }

    // ---------------------------------------------------------------- actual filesystem facts

    [Theory]
    [InlineData("uuid")]
    [InlineData("magic")]
    [InlineData("length")]
    public async Task CaptureEdlRaw_ActualFilesystemFactsMustMatchTheContract(string change)
    {
        using var package = RawPackage.Create(_fixture);
        using var expansion = new TempPackageDirectory();

        // Declarations stay self-consistent, so only the actual superblock can catch the disagreement.
        var image = change switch
        {
            "uuid" => SyntheticRawImages.CreateRootImage(OtherUuid),
            "magic" => SyntheticRawImages.CreateRootImage(RootUuid, magic: "_BHRfS_X"),
            _ => SyntheticRawImages.CreateRootImage(RootUuid, totalBytes: RootImageBytes + 4096),
        };
        package.RewriteArtifact("linux-root-raw", SyntheticRawImages.Gzip(image));

        // Keep every declaration the reviewed contract owns, and make the remaining declarations describe
        // the mutated image truthfully: the compressed bytes/hash already do, and the expanded digest must
        // too. The declared byte length and declared UUID stay as reviewed, so only the actual superblock of
        // the expanded image can still disagree — that supervision is what these cases exercise.
        package.EditManifest(
            _ => package.ArtifactNode("linux-root-raw")["expandedSha256"] =
                Convert.ToHexString(SHA256.HashData(image)));

        using var imported = CreateClaimed(package);
        await AssertRawRefusedAsync(imported, Identity(), expansion.Path);
    }

    // ---------------------------------------------------------------- DTB binding through the sole validator

    [Theory]
    [InlineData("normal-is-diagnostic")]
    [InlineData("diagnostic-is-normal")]
    [InlineData("normal-foreign-uuid")]
    public async Task CaptureEdlRaw_DtbFactsMustMatchBothRecipes(string change)
    {
        using var package = RawPackage.Create(_fixture);
        using var expansion = new TempPackageDirectory();

        switch (change)
        {
            case "normal-is-diagnostic":
                package.RewriteArtifact("dtb-normal", _fixture.DtbDiagnostic);
                break;
            case "diagnostic-is-normal":
                package.RewriteArtifact("dtb-diagnostic", _fixture.DtbNormal);
                break;
            default:
                package.RewriteArtifact(
                    "dtb-normal",
                    SyntheticRawImages.CreateDtb(
                        "root=UUID=" + OtherUuid.ToString("D")
                        + " boot=UUID=" + BootUuid.ToString("D")
                        + " ostree=" + RawFacts.OstreeArgument,
                        "os"));
                break;
        }

        using var imported = CreateClaimed(package);
        await AssertRawRefusedAsync(imported, Identity(), expansion.Path);
    }

    // ---------------------------------------------------------------- truncated gzip trailer

    [Fact]
    public async Task CaptureEdlRaw_TruncatedGzipTrailer_IsRefused()
    {
        using var package = RawPackage.Create(_fixture);
        using var expansion = new TempPackageDirectory();

        // Only the CRC/size trailer is gone: every preceding byte, including the whole output prefix, is
        // still intact, so a prefix-only reader would wrongly accept this stream.
        var truncated = _fixture.RootGzip[..^8];
        package.RewriteArtifact("linux-root-raw", truncated);

        using var imported = CreateClaimed(package);
        await AssertRawRefusedAsync(imported, Identity(), expansion.Path);
    }

    // ---------------------------------------------------------------- cancellation and lease ownership

    [Fact]
    public async Task CaptureEdlRaw_PreCancelled_IsRefusedBeforeAnyWork()
    {
        using var package = RawPackage.Create(_fixture);
        using var expansion = new TempPackageDirectory();
        using var imported = CreateClaimed(package);

        var before = Tree(package.Directory);

        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        var error = await Record.ExceptionAsync(
            () => CaptureRawAsync(imported, Identity(), expansion.Path, cancelled.Token));

        Assert.IsAssignableFrom<OperationCanceledException>(error);
        Assert.Equal(before, Tree(package.Directory));
        Assert.Empty(Directory.EnumerateFileSystemEntries(expansion.Path));
    }

    [Fact]
    public async Task CaptureEdlRaw_FailureReleasesOnlyOwnedLeases()
    {
        using var package = RawPackage.Create(_fixture);
        using var expansion = new TempPackageDirectory();
        using var imported = CreateClaimed(package);

        FlipOneByte(package.ArtifactPath("linux-root-raw"));

        await AssertRawRefusedAsync(imported, Identity(), expansion.Path);

        // No partial expansion may survive a refusal, and every lease opened on the way must be released.
        Assert.Empty(Directory.EnumerateFileSystemEntries(expansion.Path));
        AssertCanWrite(package.ArtifactPath("linux-boot-raw"));
        AssertCanWrite(package.ArtifactPath("kernel"));
        Assert.True(File.Exists(package.ManifestPath));
    }

    [Fact]
    public async Task CaptureEdlRaw_RevalidateAndDisposeKeepOnlyOwnedLeases()
    {
        using var package = RawPackage.Create(_fixture);
        using var expansion = new TempPackageDirectory();
        using var imported = CreateClaimed(package);

        // A caller-owned file directly under the expansion parent. The snapshot may only remove the unique
        // child it creates itself, so this file stands in for the caller's own state under that parent.
        var sentinel = Path.Combine(expansion.Path, "caller-sentinel.bin");
        var sentinelBytes = Encoding.ASCII.GetBytes("Caller-owned sentinel, never owned by the snapshot.");
        File.WriteAllBytes(sentinel, sentinelBytes);

        var snapshot = await CaptureRawAsync(imported, Identity(), expansion.Path);
        var bootPayload = package.ArtifactPath("linux-boot-raw");

        // The expanded raw output this route produced, not just the compressed package input.
        var rootRaw = Get<VerifiedEdlFile>(snapshot, "LinuxRootRaw");
        Assert.True(File.Exists(rootRaw.Path));

        // The derived work lives in one unique child the snapshot created underneath the caller's parent,
        // never directly in the parent itself: that exact child is the full disposal scope.
        var ownedChild = Path.GetDirectoryName(Path.GetFullPath(rootRaw.Path))!;
        Assert.True(Directory.Exists(ownedChild));
        AssertUnder(expansion.Path, ownedChild);
        Assert.NotEqual(
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(expansion.Path)),
            Path.TrimEndingDirectorySeparator(ownedChild),
            StringComparer.Ordinal);

        try
        {
            using (var reader = new FileStream(
                package.ManifestPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                Assert.True(reader.ReadByte() >= 0);
            }

            await RevalidateAsync(snapshot);

            if (OperatingSystem.IsWindows())
            {
                AssertBlocked(
                    () =>
                    {
                        using var writer = new FileStream(
                            bootPayload, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                    });
                AssertBlocked(() => File.Delete(bootPayload));

                // The expanded raw output is a fact this snapshot owns too, so it must stay unmutatable and
                // undeletable for as long as the snapshot lives.
                AssertBlocked(
                    () =>
                    {
                        using var writer = new FileStream(
                            rootRaw.Path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                    });
                AssertBlocked(() => File.Delete(rootRaw.Path));
            }
            else
            {
                // POSIX has no sharing denial, so the claim is that revalidation re-reads the held bytes
                // instead of trusting the capture-time verdict. The expanded raw output is one of those bytes.
                FlipOneByte(rootRaw.Path);
                var tampered = await Record.ExceptionAsync(() => RevalidateAsync(snapshot));
                Assert.NotNull(tampered);
                Assert.IsNotType<ObjectDisposedException>(tampered);
            }

            DisposeQuietly(snapshot);
            DisposeQuietly(snapshot);

            var afterDispose = await Record.ExceptionAsync(() => RevalidateAsync(snapshot));
            Assert.IsType<ObjectDisposedException>(afterDispose);

            Assert.True(Directory.Exists(imported.PackageDirectory));
            Assert.True(File.Exists(package.ManifestPath));
            Assert.True(File.Exists(bootPayload));

            // Disposal removes exactly the derived work it created: the actual raw output and the unique
            // child holding it are gone, because no consumer needs them once the snapshot is disposed.
            Assert.False(File.Exists(rootRaw.Path));
            Assert.False(Directory.Exists(ownedChild));

            // The caller's expansion parent and the file the caller put there are untouched.
            Assert.True(Directory.Exists(expansion.Path));
            Assert.Equal(sentinelBytes, File.ReadAllBytes(sentinel));

            if (OperatingSystem.IsWindows())
            {
                AssertCanWrite(bootPayload);
            }
        }
        finally
        {
            DisposeQuietly(snapshot);
        }
    }

    // ---------------------------------------------------------------- reflection bridge

    /// <summary>
    /// Invokes the approved direct entry. A synchronous throw is unwrapped; an asynchronous failure is
    /// observed by awaiting the returned task; the snapshot is read from <c>Result</c> only afterwards.
    /// </summary>
    private static async Task<object> CaptureRawAsync(
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

        var actual = (Task)task!;
        await actual.ConfigureAwait(false);
        return actual.GetType().GetProperty("Result")!.GetValue(actual)!;
    }

    private static async Task<object> CaptureAsync(
        ImportedPackage package,
        DeviceIdentity identity,
        CancellationToken cancellationToken = default)
    {
        object? task;
        try
        {
            task = CaptureLegacyMethod.Invoke(null, new object?[] { package, identity, cancellationToken });
        }
        catch (TargetInvocationException failure) when (failure.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(failure.InnerException!).Throw();
            throw;
        }

        var actual = (Task)task!;
        await actual.ConfigureAwait(false);
        return actual.GetType().GetProperty("Result")!.GetValue(actual)!;
    }

    private static async Task RevalidateAsync(object snapshot, CancellationToken cancellationToken = default)
    {
        object? task;
        try
        {
            task = RevalidateMethod.Invoke(snapshot, new object?[] { cancellationToken });
        }
        catch (TargetInvocationException failure) when (failure.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(failure.InnerException!).Throw();
            throw;
        }

        await ((Task)task!).ConfigureAwait(false);
    }

    private static PropertyInfo Property(string name) =>
        SnapshotType.GetProperty(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("The approved getter " + name + " is missing.");

    private static T Get<T>(object snapshot, string name) => (T)Property(name).GetValue(snapshot)!;

    /// <summary>
    /// Requires that a fact the route does not own is refused explicitly instead of being synthesized.
    /// The direct route has no seed, and the legacy route has no raw facts.
    /// </summary>
    private static void AssertNotProvided(object snapshot, string name)
    {
        Exception? error = Record.Exception(() => Property(name).GetValue(snapshot));
        if (error is TargetInvocationException wrapped)
        {
            error = wrapped.InnerException;
        }

        Assert.IsType<InvalidOperationException>(error);
    }

    private static void DisposeQuietly(object snapshot) => ((IDisposable)snapshot).Dispose();

    /// <summary>
    /// Asserts a real content refusal. <see cref="NotImplementedException"/> is the RED stub and is never a
    /// decision; cancellation is asserted separately where it is the expected outcome.
    /// </summary>
    private static async Task<Exception> AssertRawRefusedAsync(
        ImportedPackage package,
        DeviceIdentity identity,
        string expansionParent,
        CancellationToken cancellationToken = default)
    {
        var error = await Record.ExceptionAsync(
            () => CaptureRawAsync(package, identity, expansionParent, cancellationToken));

        Assert.NotNull(error);
        Assert.False(
            error is NotImplementedException,
            "The direct entry is still the RED stub; a refusal must be a real decision, not "
            + "NotImplementedException.");
        Assert.True(
            error is InvalidDataException || error is InvalidOperationException || error is IOException,
            "Expected a content refusal (InvalidDataException/InvalidOperationException/IOException), got "
            + error!.GetType().Name + ": " + error.Message);

        return error!;
    }

    // ---------------------------------------------------------------- fixture helpers

    private static ImportedPackage CreateClaimed(RawPackage package, EdlRawPackageContract contract) =>
        CreateClaimed(
            package.Directory,
            new PackageValidationResult(true, Array.Empty<string>(), contract.Storage)
            {
                TestOnly = contract.TestOnly,
                PackageId = contract.PackageId,
                Version = contract.Version,
                ManifestFingerprint = contract.ManifestFingerprint,
            });

    /// <summary>
    /// Presents a plausible, self-consistent imported verdict. The claim is only a caller statement: the
    /// fingerprint names the current manifest bytes so a refusal can only come from the actual package.
    /// </summary>
    private static ImportedPackage CreateClaimed(RawPackage package) =>
        CreateClaimed(
            package.Directory,
            new PackageValidationResult(true, Array.Empty<string>(), ExpectedStorage)
            {
                TestOnly = false,
                PackageId = RawFacts.PackageId,
                Version = RawFacts.PackageVersion,
                ManifestFingerprint = package.ManifestFingerprint,
            });

    private static ImportedPackage CreateClaimed(string directory, PackageValidationResult validation) =>
        (ImportedPackage)ImportedPackageConstructor.Invoke(
            new object?[] { directory, directory, Model, validation, null, null });

    private static DeviceIdentity Identity(FirmwareSnapshot? firmware = null) =>
        new(RawFacts.Serial, Model, BootloaderState.Unknown) { Firmware = firmware ?? Firmware() };

    private static FirmwareSnapshot Firmware() =>
        new(AndroidBuild, RawFacts.BuildFingerprint, "15", "2026-06-01", BootloaderState.Unknown);

    private static void AssertUnder(string parent, string path)
    {
        var root = Path.GetFullPath(parent);
        if (!root.EndsWith(Path.DirectorySeparatorChar))
        {
            root += Path.DirectorySeparatorChar;
        }

        Assert.StartsWith(root, Path.GetFullPath(path), StringComparison.Ordinal);
    }

    /// <summary>Reads the actual expanded ext4 superblock: block count, block size, magic and UUID.</summary>
    private static void AssertActualExt4(string path, Guid expectedUuid)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        Assert.Equal(BootExpandedBytes, stream.Length);

        var superblock = new byte[0x78];
        stream.Position = 1024;
        stream.ReadExactly(superblock);

        var blocks = BinaryPrimitives.ReadUInt32LittleEndian(superblock.AsSpan(0x04));
        var logBlockSize = BinaryPrimitives.ReadUInt32LittleEndian(superblock.AsSpan(0x18));
        Assert.Equal(262144u, blocks);
        Assert.Equal(2u, logBlockSize);
        Assert.Equal(0xEF53, (int)BinaryPrimitives.ReadUInt16LittleEndian(superblock.AsSpan(0x38)));
        Assert.Equal(expectedUuid, new Guid(superblock.AsSpan(0x68, 16), bigEndian: true));
        Assert.Equal(stream.Length, (long)blocks * (1024L << (int)logBlockSize));
    }

    /// <summary>Reads the actual expanded Btrfs primary superblock: fsid, bytenr, magic, length, geometry.</summary>
    private static void AssertActualBtrfs(string path, Guid expectedFsid)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        Assert.Equal((long)RootImageBytes, stream.Length);

        var superblock = new byte[148];
        stream.Position = SyntheticRawImages.BtrfsSuperblockOffset;
        stream.ReadExactly(superblock);

        Assert.Equal(expectedFsid, new Guid(superblock.AsSpan(32, 16), bigEndian: true));
        Assert.Equal((long)SyntheticRawImages.BtrfsSuperblockOffset,
            BinaryPrimitives.ReadInt64LittleEndian(superblock.AsSpan(48)));
        Assert.Equal(SyntheticRawImages.BtrfsMagic, Encoding.ASCII.GetString(superblock.AsSpan(64, 8)));
        Assert.Equal(stream.Length, BinaryPrimitives.ReadInt64LittleEndian(superblock.AsSpan(112)));
        Assert.Equal(1L, BinaryPrimitives.ReadInt64LittleEndian(superblock.AsSpan(136)));
        Assert.Equal(4096, BinaryPrimitives.ReadInt32LittleEndian(superblock.AsSpan(144)));
    }

    private static void WriteFile(string root, string relativePath, byte[] bytes)
    {
        var fullPath = Path.Combine(root, relativePath.Replace('/', Path.DirectorySeparatorChar));
        var parent = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(parent))
        {
            Directory.CreateDirectory(parent);
        }

        File.WriteAllBytes(fullPath, bytes);
    }

    private static byte[] Payload(int length, int salt)
    {
        var payload = new byte[length];
        for (var index = 0; index < payload.Length; index++)
        {
            payload[index] = (byte)((index * 31 + salt) & 0xFF);
        }

        return payload;
    }

    private static void FlipOneByte(string path)
    {
        var bytes = File.ReadAllBytes(path);
        Assert.NotEmpty(bytes);
        bytes[0] ^= 0xFF;
        File.WriteAllBytes(path, bytes);
    }

    /// <summary>Independently hashes a file exactly as it is on disk, in a single streamed pass.</summary>
    private static async Task<string> Sha256OfFileAsync(string path)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 1024 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream));
    }

    private static string[] Tree(string root) =>
        Directory
            .EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(root, path))
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToArray();

    private static void AssertBlocked(Action action)
    {
        try
        {
            action();
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        throw new Xunit.Sdk.XunitException(
            "A held snapshot must keep its payload locked against writers and deletion.");
    }

    private static void AssertCanWrite(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        Assert.True(stream.CanWrite);
    }

    // ---------------------------------------------------------------- raw package fixture

    /// <summary>One written fixture artefact: declared relative name, absolute path, length and uppercase digest.</summary>
    internal readonly record struct FileFacts(string RelativePath, string FullPath, long Length, string Sha256);

    /// <summary>
    /// Synthetic schema-2 direct package: seven roles, a shared compressed boot image, a small compressed
    /// Btrfs-shaped root image and the two packed FDTs. Nothing here is a deployable OS tree.
    /// </summary>
    internal sealed class RawPackage : IDisposable
    {
        private readonly TempPackageDirectory _directory;
        private readonly JsonObject _metadata;

        private RawPackage(TempPackageDirectory directory, JsonObject metadata)
        {
            _directory = directory;
            _metadata = metadata;
        }

        internal string Directory => _directory.Path;

        internal string ManifestPath => Path.Combine(_directory.Path, MetadataFileName);

        internal string ManifestFingerprint =>
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(ManifestPath)));

        internal static RawPackage Create(EdlRawSharedInput shared)
        {
            var directory = new TempPackageDirectory();

            var bootRelative = "files/linux-boot-raw.img.gz";
            var bootFullPath = Path.Combine(
                directory.Path, bootRelative.Replace('/', Path.DirectorySeparatorChar));
            System.IO.Directory.CreateDirectory(Path.GetDirectoryName(bootFullPath)!);
            File.Copy(shared.BootGzipPath, bootFullPath);
            var bootCompressed = File.ReadAllBytes(bootFullPath);

            var rootCompressed = shared.RootGzip;
            WriteFile(directory.Path, "files/linux-root-raw.img.gz", rootCompressed);

            var kernel = Payload(96, 23);
            WriteFile(directory.Path, "files/kernel.bin", kernel);

            // Exact prepared runtime length; the bytes are zeros because this route never executes them.
            var runtime = new byte[(int)RawFacts.RuntimeBytes];
            WriteFile(directory.Path, "files/runtime.bin", runtime);

            var initramfs = Payload(40, 53);
            WriteFile(directory.Path, "files/initramfs.bin", initramfs);
            WriteFile(directory.Path, "files/dtb-normal.dtb", shared.DtbNormal);
            WriteFile(directory.Path, "files/dtb-diagnostic.dtb", shared.DtbDiagnostic);

            var artifacts = new JsonArray
            {
                new JsonObject
                {
                    ["role"] = "linux-boot-raw",
                    ["file"] = bootRelative,
                    ["bytes"] = bootCompressed.LongLength,
                    ["sha256"] = Convert.ToHexString(SHA256.HashData(bootCompressed)),
                    ["compression"] = "gzip",
                    ["expandedBytes"] = SyntheticRawImages.BootExpandedBytes,
                    ["expandedSha256"] = shared.BootExpandedSha256,
                    ["sectorSize"] = 4096,
                    ["fsType"] = "ext4",
                    ["fsUuid"] = RawFacts.BootUuid.ToString("D"),
                    ["minimumPartitionBytes"] = SyntheticRawImages.BootExpandedBytes,
                },
                new JsonObject
                {
                    ["role"] = "linux-root-raw",
                    ["file"] = "files/linux-root-raw.img.gz",
                    ["bytes"] = rootCompressed.LongLength,
                    ["sha256"] = Convert.ToHexString(SHA256.HashData(rootCompressed)),
                    ["compression"] = "gzip",
                    ["expandedBytes"] = (long)SyntheticRawImages.RootImageBytes,
                    ["expandedSha256"] = shared.RootExpandedSha256,
                    ["sectorSize"] = 4096,
                    ["fsType"] = "btrfs",
                    ["fsUuid"] = RawFacts.RootUuid.ToString("D"),
                    ["minimumPartitionBytes"] = 1L * TestSizes.GiB,
                },
                RawFile("kernel", "files/kernel.bin", kernel),
                RawFile("runtime", "files/runtime.bin", runtime),
                RawFile("initramfs", "files/initramfs.bin", initramfs),
                RawFile("dtb-normal", "files/dtb-normal.dtb", shared.DtbNormal),
                RawFile("dtb-diagnostic", "files/dtb-diagnostic.dtb", shared.DtbDiagnostic),
            };

            var metadata = new JsonObject
            {
                ["schemaVersion"] = 2,
                ["packageId"] = RawFacts.PackageId,
                ["version"] = RawFacts.PackageVersion,
                ["deviceModel"] = Model,
                ["compatible"] = new JsonObject
                {
                    ["soc"] = "SM8750",
                    ["device"] = "elden",
                },
                ["sourceCommit"] = RawFacts.SourceCommit,
                ["testOnly"] = false,
                ["installTargets"] = new JsonArray(JsonValue.Create("internal")),
                ["edlProfile"] = new JsonObject
                {
                    ["id"] = RawFacts.EdlProfileId,
                    ["hardwareId"] = RawFacts.HardwareId,
                    ["androidBuild"] = AndroidBuild,
                },
                ["bootCompatibility"] = new JsonObject
                {
                    ["format"] = "android-boot-v4",
                    ["partitionBytes"] = 100_663_296L,
                    ["firmwareVersions"] = new JsonArray(JsonValue.Create(AndroidBuild)),
                },
                ["toolsCompatibility"] = new JsonObject
                {
                    ["installerProtocol"] = 2,
                    ["bootBuilderProtocol"] = 1,
                },
                ["storage"] = new JsonObject
                {
                    ["linuxBootBytes"] = ExpectedStorage.LinuxBootBytes,
                    ["systemRequiredBytes"] = ExpectedStorage.SystemRequiredBytes,
                    ["deploymentScratchBytes"] = ExpectedStorage.DeploymentScratchBytes,
                    ["minimumLinuxDataBytes"] = ExpectedStorage.MinimumLinuxDataBytes,
                },
                ["artifacts"] = artifacts,
                ["deployment"] = new JsonObject
                {
                    ["kind"] = "edl-raw-v1",
                    ["commit"] = DeploymentCommit,
                    ["manifestDigest"] = ManifestDigest,
                    ["origin"] = RawFacts.Origin,
                    ["bootChecksum"] = BootChecksum,
                },
                ["bootRecipe"] = new JsonObject
                {
                    ["bootUuid"] = BootUuid.ToString("D"),
                    ["rootUuid"] = RootUuid.ToString("D"),
                    ["normalBootArgs"] = NormalBootArgs,
                    ["diagnosticBootArgs"] = DiagnosticBootArgs,
                    ["defaultEntry"] = "android",
                },
            };

            File.WriteAllText(
                Path.Combine(directory.Path, MetadataFileName), metadata.ToJsonString(WriteOptions));

            return new RawPackage(directory, metadata);
        }

        private static JsonObject RawFile(string role, string relativePath, byte[] bytes) => new()
        {
            ["role"] = role,
            ["file"] = relativePath,
            ["bytes"] = bytes.LongLength,
            ["sha256"] = Convert.ToHexString(SHA256.HashData(bytes)),
        };

        internal JsonObject ArtifactNode(string role) =>
            _metadata["artifacts"]!.AsArray()
                .Select(node => node!.AsObject())
                .Single(node => node["role"]!.GetValue<string>() == role);

        internal string ArtifactPath(string role)
        {
            var relativePath = ArtifactNode(role)["file"]!.GetValue<string>();
            return Path.Combine(_directory.Path, relativePath.Replace('/', Path.DirectorySeparatorChar));
        }

        internal FileFacts Artifact(string role)
        {
            var node = ArtifactNode(role);
            var relativePath = node["file"]!.GetValue<string>();
            var bytes = File.ReadAllBytes(ArtifactPath(role));
            return new FileFacts(
                relativePath, ArtifactPath(role), bytes.LongLength, Convert.ToHexString(SHA256.HashData(bytes)));
        }

        /// <summary>Writes replacement bytes and keeps the declaration truthful, so only the check under test fails.</summary>
        internal void RewriteArtifact(string role, byte[] bytes)
        {
            var node = ArtifactNode(role);
            var relativePath = node["file"]!.GetValue<string>();
            WriteFile(_directory.Path, relativePath, bytes);
            node["bytes"] = bytes.LongLength;
            node["sha256"] = Convert.ToHexString(SHA256.HashData(bytes));
            Save();
        }

        internal void EditManifest(Action<JsonObject> edit)
        {
            edit(_metadata);
            Save();
        }

        private void Save() =>
            File.WriteAllText(ManifestPath, _metadata.ToJsonString(WriteOptions));

        public void Dispose() => _directory.Dispose();
    }

    /// <summary>
    /// Synthetic schema-1 package: the legacy baseline route's own shape, so the direct entry can be shown
    /// to refuse it and the legacy capture can be shown to keep working unchanged.
    /// </summary>
    private sealed class LegacyPackage : IDisposable
    {
        private readonly TempPackageDirectory _directory;

        private LegacyPackage(TempPackageDirectory directory) => _directory = directory;

        internal string Directory => _directory.Path;

        internal static LegacyPackage Write()
        {
            var directory = new TempPackageDirectory();

            var payloads = new (string Role, string RelativePath, byte[] Bytes)[]
            {
                ("ostree-seed", "files/ostree-seed.bin", Payload(64, 11)),
                ("kernel", "files/kernel.bin", Payload(96, 23)),
                ("dtb", "files/dtb.bin", Payload(48, 37)),
                ("runtime", "files/runtime.bin", new byte[(int)RawFacts.RuntimeBytes]),
                ("initramfs", "files/initramfs.bin", Payload(40, 53)),
                ("extra", "extras/extra.bin", Payload(7, 67)),
            };

            var artifacts = new JsonArray();
            foreach (var (role, relativePath, bytes) in payloads)
            {
                WriteFile(directory.Path, relativePath, bytes);
                artifacts.Add(
                    new JsonObject
                    {
                        ["role"] = role,
                        ["file"] = relativePath,
                        ["bytes"] = bytes.LongLength,
                        ["sha256"] = Convert.ToHexString(SHA256.HashData(bytes)),
                    });
            }

            var metadata = new JsonObject
            {
                ["schemaVersion"] = 1,
                ["packageId"] = RawFacts.PackageId,
                ["version"] = RawFacts.PackageVersion,
                ["deviceModel"] = Model,
                ["testOnly"] = false,
                ["compatible"] = new JsonObject
                {
                    ["soc"] = "SM8750",
                    ["device"] = "elden",
                },
                ["artifacts"] = artifacts,
                ["deployment"] = new JsonObject
                {
                    ["kind"] = "ostree-offline-seed",
                    ["commit"] = DeploymentCommit,
                    ["manifestDigest"] = ManifestDigest,
                    ["origin"] = RawFacts.Origin,
                },
                ["storage"] = new JsonObject
                {
                    ["linuxBootBytes"] = ExpectedStorage.LinuxBootBytes,
                    ["systemRequiredBytes"] = ExpectedStorage.SystemRequiredBytes,
                    ["deploymentScratchBytes"] = ExpectedStorage.DeploymentScratchBytes,
                    ["minimumLinuxDataBytes"] = ExpectedStorage.MinimumLinuxDataBytes,
                },
                ["bootCompatibility"] = new JsonObject
                {
                    ["format"] = "android-boot-v4",
                    ["partitionBytes"] = 100_663_296L,
                    ["firmwareVersions"] = new JsonArray(JsonValue.Create(AndroidBuild)),
                },
                ["toolsCompatibility"] = new JsonObject
                {
                    ["installerProtocol"] = 1,
                    ["maintenanceProtocol"] = 1,
                },
                ["installTargets"] = new JsonArray(JsonValue.Create("internal")),
            };

            File.WriteAllText(
                Path.Combine(directory.Path, MetadataFileName), metadata.ToJsonString(WriteOptions));

            return new LegacyPackage(directory);
        }

        public void Dispose() => _directory.Dispose();
    }
}

/// <summary>
/// Shared synthetic inputs for the direct route. The 1 GiB boot image is compressed exactly once per test
/// class run; individual cases copy the small compressed file instead of rebuilding multi-GiB input.
/// </summary>
public sealed class EdlRawSharedInput : IDisposable
{
    private readonly TempPackageDirectory _directory;

    public EdlRawSharedInput()
    {
        _directory = new TempPackageDirectory();
        BootGzipPath = Path.Combine(_directory.Path, "linux-boot-raw.img.gz");

        var boot = SyntheticRawImages.WriteBootGzip(BootGzipPath, RawFacts.BootUuid);
        BootCompressedBytes = boot.CompressedBytes;
        BootCompressedSha256 = boot.CompressedSha256;
        BootExpandedSha256 = boot.ExpandedSha256;

        RootImage = SyntheticRawImages.CreateRootImage(RawFacts.RootUuid);
        RootExpandedSha256 = Convert.ToHexString(SHA256.HashData(RootImage));
        RootGzip = SyntheticRawImages.Gzip(RootImage);

        DtbNormal = SyntheticRawImages.CreateDtb(RawFacts.NormalBootArgs, "os");
        DtbDiagnostic = SyntheticRawImages.CreateDtb(RawFacts.DiagnosticBootArgs, "maintenance");
    }

    internal string BootGzipPath { get; }

    internal long BootCompressedBytes { get; }

    internal string BootCompressedSha256 { get; }

    internal string BootExpandedSha256 { get; }

    internal byte[] RootImage { get; }

    internal byte[] RootGzip { get; }

    internal string RootExpandedSha256 { get; }

    internal byte[] DtbNormal { get; }

    internal byte[] DtbDiagnostic { get; }

    public void Dispose() => _directory.Dispose();
}

/// <summary>
/// Literal facts of the approved G4 direct contract as they appear in the fixture. Nothing here is read
/// from a device, a real package or a backup.
/// </summary>
internal static class RawFacts
{
    internal const string Model = "TB322FC";

    internal const string Serial = "R58M12345ABC";

    internal const string AndroidBuild = "TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.259_ST_260611";

    internal const string BuildFingerprint = "Lenovo/elden_prc_wifi/elden:15/AP3A.240905.015/259:user/release-keys";

    internal const string SourceCommit = "244b74516d99d06cb0518609ce4b842ab278be8a";

    internal const string PackageId = "armadaos-freedom-edl-raw-example";

    internal const string PackageVersion = "1.0.0";

    internal const string Origin = "ostree-image-signed:docker://ghcr.io/mydanyi/armadaos-freedom:stable";

    internal const string DeploymentCommit =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    internal const string BootChecksum = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    internal const string ManifestDigest = "sha256:" + DeploymentCommit;

    internal const string EdlProfileId = "g4-9008-259";

    internal const string HardwareId = "0028D0E100400000";

    internal const string OstreeArgument =
        "/ostree/boot.0/default/" + BootChecksum + "/0";

    internal const long RuntimeBytes = 4L * 1024 * 1024;

    internal static readonly Guid BootUuid = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e");

    internal static readonly Guid RootUuid = Guid.Parse("7c9e6679-7425-40de-944b-e07fc1f90ae7");

    internal static readonly Guid OtherUuid = Guid.Parse("1b4e28ba-2fa1-11d2-883f-0016d3cca427");

    internal static readonly string NormalBootArgs =
        "root=UUID=" + RootUuid.ToString("D")
        + " boot=UUID=" + BootUuid.ToString("D")
        + " ostree=" + OstreeArgument
        + " console=ttyMSM0,115200n8";

    internal static readonly string DiagnosticBootArgs = NormalBootArgs + " rd.break=pre-mount";

    internal static readonly PackageStorage Storage =
        new(1L * TestSizes.GiB, 20L * TestSizes.GiB, 2L * TestSizes.GiB, 8L * TestSizes.GiB);
}

/// <summary>
/// Synthetic image and FDT builders. The ext4/Btrfs bytes carry only the metadata this route must check:
/// they describe no mountable filesystem, no OSTree deployment and no vendor image.
/// </summary>
internal static class SyntheticRawImages
{
    internal const long BootExpandedBytes = 1L * 1024 * 1024 * 1024;

    internal const int BtrfsSuperblockOffset = 65536;

    /// <summary>Seventeen 4096-byte sectors: exactly the space the synthetic primary superblock needs.</summary>
    internal const int RootImageBytes = 17 * 4096;

    internal const string BtrfsMagic = "_BHRfS_M";

    private const int ChunkBytes = 1024 * 1024;

    private const int FdtHeaderBytes = 40;

    private const int FdtReservationBytes = 16;

    private const int FdtBeginNode = 1;

    private const int FdtEndNode = 2;

    private const int FdtProp = 3;

    private const int FdtEnd = 9;

    internal readonly record struct BootGzipFacts(
        long CompressedBytes,
        string CompressedSha256,
        string ExpandedSha256);

    /// <summary>
    /// Streams the shared synthetic boot image through gzip. The 1 GiB expanded content never exists as a
    /// single array; the expanded digest is computed from the same buffers that are compressed.
    /// </summary>
    internal static BootGzipFacts WriteBootGzip(string path, Guid fsUuid)
    {
        var firstChunk = new byte[ChunkBytes];
        PatchExt4Superblock(firstChunk, fsUuid);
        var zeros = new byte[ChunkBytes];

        using var expandedHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        using (var gzip = new GZipStream(file, CompressionLevel.SmallestSize))
        {
            gzip.Write(firstChunk, 0, firstChunk.Length);
            expandedHash.AppendData(firstChunk);

            var written = (long)firstChunk.Length;
            while (written < BootExpandedBytes)
            {
                var take = (int)Math.Min(ChunkBytes, BootExpandedBytes - written);
                gzip.Write(zeros, 0, take);
                expandedHash.AppendData(zeros, 0, take);
                written += take;
            }
        }

        var compressed = File.ReadAllBytes(path);
        return new BootGzipFacts(
            compressed.LongLength,
            Convert.ToHexString(SHA256.HashData(compressed)),
            Convert.ToHexString(expandedHash.GetHashAndReset()));
    }

    /// <summary>
    /// Synthetic ext4 superblock at byte 1024: 262144 blocks of 4096 bytes is exactly 1 GiB, magic 0xEF53
    /// and the package UUID in standard UUID byte order.
    /// </summary>
    private static void PatchExt4Superblock(byte[] image, Guid fsUuid)
    {
        const int superblock = 1024;
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(superblock + 0x04), 262144);
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(superblock + 0x18), 2);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(superblock + 0x38), 0xEF53);
        fsUuid.TryWriteBytes(image.AsSpan(superblock + 0x68, 16), bigEndian: true, out _);
    }

    internal static byte[] CreateRootImage(
        Guid fsid, string magic = BtrfsMagic, long? totalBytes = null, int length = RootImageBytes)
    {
        if (magic.Length != 8)
        {
            throw new ArgumentException("A Btrfs magic is exactly 8 ASCII bytes.", nameof(magic));
        }

        var image = new byte[length];
        var superblock = image.AsSpan(BtrfsSuperblockOffset);

        BinaryPrimitives.WriteInt64LittleEndian(superblock[48..], BtrfsSuperblockOffset);
        BinaryPrimitives.WriteInt64LittleEndian(superblock[112..], totalBytes ?? length);
        BinaryPrimitives.WriteInt64LittleEndian(superblock[136..], 1);
        BinaryPrimitives.WriteInt32LittleEndian(superblock[144..], 4096);
        Encoding.ASCII.GetBytes(magic).CopyTo(superblock[64..]);
        fsid.TryWriteBytes(superblock.Slice(32, 16), bigEndian: true, out _);

        return image;
    }

    internal static byte[] Gzip(byte[] bytes)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            gzip.Write(bytes, 0, bytes.Length);
        }

        return output.ToArray();
    }

    /// <summary>
    /// Packed v17 FDT: root compatible pair, exact /chosen bootargs, boot stage, internal root medium and
    /// the single BE32 initrd entry index 5. No linux,initrd-start/end property is ever emitted.
    /// </summary>
    internal static byte[] CreateDtb(string bootArgs, string bootStage, string rootMedium = "internal")
    {
        var strings = new List<byte>();
        var nameOffsets = new Dictionary<string, int>(StringComparer.Ordinal);
        var structure = new List<byte>();

        int NameOffset(string name)
        {
            if (nameOffsets.TryGetValue(name, out var existing))
            {
                return existing;
            }

            var offset = strings.Count;
            strings.AddRange(Encoding.ASCII.GetBytes(name));
            strings.Add(0);
            nameOffsets.Add(name, offset);
            return offset;
        }

        void U32(int value)
        {
            structure.Add((byte)(value >> 24));
            structure.Add((byte)(value >> 16));
            structure.Add((byte)(value >> 8));
            structure.Add((byte)value);
        }

        void Pad()
        {
            while (structure.Count % 4 != 0)
            {
                structure.Add(0);
            }
        }

        void BeginNode(string name)
        {
            U32(FdtBeginNode);
            structure.AddRange(Encoding.ASCII.GetBytes(name));
            structure.Add(0);
            Pad();
        }

        void EndNode() => U32(FdtEndNode);

        void Property(string name, byte[] value)
        {
            U32(FdtProp);
            U32(value.Length);
            U32(NameOffset(name));
            structure.AddRange(value);
            Pad();
        }

        void StringProperty(string name, string value) =>
            Property(name, Encoding.ASCII.GetBytes(value + "\0"));

        BeginNode(string.Empty);
        StringProperty("compatible", "lenovo,elden\0qcom,sm8750");
        StringProperty("model", RawFacts.Model);

        BeginNode("chosen");
        StringProperty("bootargs", bootArgs);
        StringProperty("armada,boot-stage", bootStage);
        StringProperty("armada,root-medium", rootMedium);
        Property("kshim,initrd-entry", new byte[] { 0x00, 0x00, 0x00, 0x05 });
        EndNode();

        EndNode();
        U32(FdtEnd);

        var structOffset = FdtHeaderBytes + FdtReservationBytes;
        var stringsOffset = structOffset + structure.Count;
        var total = stringsOffset + strings.Count;
        var dtb = new byte[total];

        void Header(int offset, int value)
        {
            BinaryPrimitives.WriteInt32BigEndian(dtb.AsSpan(offset), value);
        }

        Header(0, unchecked((int)0xD00DFEED));
        Header(4, total);
        Header(8, structOffset);
        Header(12, stringsOffset);
        Header(16, FdtHeaderBytes);
        Header(20, 17);
        Header(24, 16);
        Header(28, 0);
        Header(32, strings.Count);
        Header(36, structure.Count);

        structure.CopyTo(dtb, structOffset);
        strings.CopyTo(dtb, stringsOffset);

        return dtb;
    }
}
