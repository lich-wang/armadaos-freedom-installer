using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Behaviour specifications for the INTERNAL <c>InternalInstallPackageSnapshot</c> (IBP001-L1).
/// <para>
/// The snapshot type is internal and no <c>InternalsVisibleTo</c> exists, so this file carries one narrow
/// reflection bridge: it resolves exactly <c>CaptureAsync</c>, <c>RevalidateAsync</c> and the six frozen
/// getters, unwraps <see cref="TargetInvocationException"/>, awaits the real returned <see cref="Task"/> and
/// only then reads <c>Result</c>. Nothing else is reflected.
/// </para>
/// <para>
/// Every fixture below is synthetic package data: a few small artefacts plus a zero-pattern 4 MiB runtime.
/// It is not firmware, not flashable and contains no vendor image, partition table, device output, backup
/// bytes or credential. All files live under <see cref="TestArtifactRoot.Resolve"/> so the remote run can
/// point <c>TEST_ARTIFACT_ROOT</c> at its own mount.
/// </para>
/// <para>
/// Every refusal test additionally rejects <see cref="NotImplementedException"/> as a valid decision. These
/// tests encode the behavioural contract and must not be weakened.
/// </para>
/// </summary>
public sealed class InternalInstallPackageSnapshotTests
{
    private const string Model = "TB322FC";
    private const string Serial = "R58M12345ABC";

    // The reviewed G4.259 build, written as a literal on purpose: MaintenanceProfiles.AndroidBuild must stay
    // exactly this string, and the observed DisplayId must match it character for character.
    private const string DisplayId = "TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.259_ST_260611";

    private const string BuildFingerprint = "Lenovo/TB322FC/TB322FC:15/AP3A.240905.015/259:user/release-keys";

    private const string Commit = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private const string Origin = "ostree-image-signed:docker://ghcr.io/mydanyi/armadaos-freedom:stable";

    private const string ManifestDigest = "sha256:" + Commit;

    private const long RuntimeBytes = 4 * 1024 * 1024;

    private const int ExpectedPayloadCount = 6;

    private const string SnapshotTypeName = "FreedomInstaller.Core.InternalInstallPackageSnapshot";

    private static readonly string[] DeclaredRoles =
    {
        "ostree-seed", "kernel", "dtb", "runtime", "initramfs", "extra",
    };

    private static readonly JsonSerializerOptions WriteOptions = new() { WriteIndented = true };

    private static readonly PackageStorage ExpectedStorage =
        new(1L * TestSizes.GiB, 20L * TestSizes.GiB, 2L * TestSizes.GiB, 8L * TestSizes.GiB);

    private static readonly Type SnapshotType =
        typeof(PackageReader).Assembly.GetType(SnapshotTypeName, throwOnError: true)!;

    private static readonly MethodInfo CaptureMethod =
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

    // ---------------------------------------------------------------- the complete snapshot

    [Fact]
    public async Task Capture_ValidProductionInternalPackage_ReturnsBoundSnapshot()
    {
        using var package = InternalPackage.Write();

        using var imported = await ImportAsync(package);
        Assert.True(imported.Validation.IsValid, string.Join("; ", imported.Validation.Reasons));

        var snapshot = await CaptureAsync(imported, Identity());
        try
        {
            // Protects: the snapshot reports the fingerprint of the exact bytes that were imported, not a
            // freshly re-derived value that could hide a manifest swap between import and capture.
            Assert.Equal(MaintenanceProfiles.AndroidBuild, DisplayId);
            Assert.Equal(imported.Validation.ManifestFingerprint, Get<string>(snapshot, "ManifestFingerprint"));
            Assert.Equal(ManifestFingerprint(package.ManifestPath), Get<string>(snapshot, "ManifestFingerprint"));

            // Protects: the declared storage is carried through unchanged.
            Assert.Equal(ExpectedStorage, Get<PackageStorage>(snapshot, "Storage"));

            // Protects: the seed is derived from the ostree-seed artefact plus the deployment block.
            var seed = Get<RamInstallSeed>(snapshot, "Seed");
            Assert.NotNull(seed);
            Assert.Equal(package.Files["ostree-seed"].Length, seed.Length);
            Assert.Equal(package.Files["ostree-seed"].Sha256.ToLowerInvariant(), seed.Sha256);
            Assert.Equal(Commit, seed.Commit);
            Assert.Equal(ManifestDigest, seed.ManifestDigest);
            Assert.Equal(Origin, seed.Origin);

            // Protects: all five observed firmware fields are preserved exactly; an Android report of Unknown
            // is allowed here because fastboot safety is decided by a higher layer, never by this snapshot.
            var firmware = Get<FirmwareSnapshot>(snapshot, "Firmware");
            Assert.NotNull(firmware);
            Assert.Equal(DisplayId, firmware.DisplayId);
            Assert.Equal(BuildFingerprint, firmware.BuildFingerprint);
            Assert.Equal("15", firmware.AndroidRelease);
            Assert.Equal("2026-06-01", firmware.SecurityPatch);
            Assert.Equal(BootloaderState.Unknown, firmware.AndroidReportedBootloaderState);

            // Protects: every declared role is present, including initramfs and the optional extra artefact,
            // each with its full absolute path, full length and full digest.
            var payloads = Get<IReadOnlyDictionary<string, VerifiedEdlFile>>(snapshot, "Payloads");
            Assert.NotNull(payloads);
            Assert.Equal(ExpectedPayloadCount, payloads.Count);
            Assert.Equal(package.Files.Count, payloads.Count);
            Assert.Equal(
                DeclaredRoles.OrderBy(role => role, StringComparer.Ordinal).ToArray(),
                payloads.Keys.OrderBy(role => role, StringComparer.Ordinal).ToArray());

            foreach (var pair in package.Files)
            {
                Assert.True(payloads.TryGetValue(pair.Key, out var found), "Missing payload role: " + pair.Key);
                var payload = found!;
                Assert.Equal(Path.GetFullPath(pair.Value.FullPath), Path.GetFullPath(payload.Path));
                Assert.Equal(pair.Value.Length, payload.Length);
                Assert.Equal(pair.Value.Sha256, payload.Sha256, ignoreCase: true);
            }

            // Protects: the payload view is immutable, not merely wrapped as read-only metadata.
            var mutable = Assert.IsAssignableFrom<IDictionary<string, VerifiedEdlFile>>(payloads);
            Assert.Throws<NotSupportedException>(
                () => mutable.Add("late", new VerifiedEdlFile("late.bin", 1, new string('0', 64))));
            Assert.Throws<NotSupportedException>(() => { mutable.Remove("kernel"); });

            // Protects: an independent ordinary reader still works while the snapshot is held, revalidation
            // succeeds, and disposing twice never closes a handle this snapshot does not own.
            using (var reader = new FileStream(
                package.ManifestPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                var raw = ReadFully(reader);
                Assert.Equal(
                    Get<string>(snapshot, "ManifestFingerprint"),
                    Convert.ToHexString(SHA256.HashData(raw)));

                await RevalidateAsync(snapshot);

                DisposeQuietly(snapshot);
                DisposeQuietly(snapshot);

                reader.Position = 0;
                Assert.True(reader.ReadByte() >= 0);
            }
        }
        finally
        {
            DisposeQuietly(snapshot);
        }
    }

    // ---------------------------------------------------------------- testOnly and install target

    [Fact]
    public async Task Capture_TestOnlyPackage_IsRejectedAndReaderRoleSetIsUnchanged()
    {
        using var package = InternalPackage.Write(testOnly: true);

        using var imported = await ImportAsync(package);

        // The generic reader stays structural: it accepts a testOnly package and reports the flag.
        Assert.True(imported.Validation.IsValid, string.Join("; ", imported.Validation.Reasons));
        Assert.True(imported.Validation.TestOnly);

        await AssertRefusedAsync(imported, Identity());

        // Protects: IBP001 did not widen PackageReader's required role set. initramfs is prepared-only and
        // stays optional for the generic reader, while a genuine contract role is still required.
        using (var withoutInitramfs = InternalPackage.Write(omitRoles: new[] { "initramfs" }))
        {
            var result = PackageReader.Validate(withoutInitramfs.Directory, Model, InstallationTarget.Internal);
            Assert.True(result.IsValid, string.Join("; ", result.Reasons));
        }

        using (var withoutRuntime = InternalPackage.Write(omitRoles: new[] { "runtime" }))
        {
            var result = PackageReader.Validate(withoutRuntime.Directory, Model, InstallationTarget.Internal);
            Assert.False(result.IsValid);
        }
    }

    [Fact]
    public async Task Capture_TfOnlyPackageIsRejected()
    {
        using var package = InternalPackage.Write(installTargets: new[] { "tf" });

        // The package is a valid package - for the TF target only. The snapshot is internal-only and must
        // re-check the declaration instead of trusting a validation result produced for another target.
        var tfValidation = PackageReader.Validate(package.Directory, Model, InstallationTarget.TfCard);
        Assert.True(tfValidation.IsValid, string.Join("; ", tfValidation.Reasons));

        using var imported = CreateImported(package.Directory, Model, tfValidation);

        await AssertRefusedAsync(imported, Identity());
    }

    // ---------------------------------------------------------------- stale trust after import

    [Fact]
    public async Task Capture_ManifestChangedAfterImport_IsRejectedEvenWhenPackageReaderAccepts()
    {
        using var package = InternalPackage.Write();

        using var imported = await ImportAsync(package);
        Assert.True(imported.Validation.IsValid, string.Join("; ", imported.Validation.Reasons));
        Assert.NotNull(imported.Validation.ManifestFingerprint);

        // A harmless, still-valid manifest rewrite (new version) changes the raw fingerprint. The reader
        // accepts the directory again, so only the snapshot's own original-fingerprint binding can catch it.
        RewriteManifest(package.ManifestPath, metadata => metadata["version"] = "1.0.1");

        var current = PackageReader.Validate(package.Directory, Model, InstallationTarget.Internal);
        Assert.True(current.IsValid, string.Join("; ", current.Reasons));
        Assert.NotEqual(imported.Validation.ManifestFingerprint, current.ManifestFingerprint);

        await AssertRefusedAsync(imported, Identity());
    }

    [Theory]
    [InlineData("ostree-seed")]
    [InlineData("initramfs")]
    [InlineData("extra")]
    public async Task Capture_SameLengthPayloadTamper_IsRejected(string role)
    {
        using var package = InternalPackage.Write();

        using var imported = await ImportAsync(package);
        Assert.True(imported.Validation.IsValid, string.Join("; ", imported.Validation.Reasons));

        var target = package.Files[role];
        FlipOneByte(target.FullPath);

        // Same length, different bytes: the reader notices the digest, but the snapshot must recheck the
        // complete digest itself instead of reusing the import-time verdict.
        Assert.Equal(target.Length, new FileInfo(target.FullPath).Length);
        Assert.False(PackageReader.Validate(package.Directory, Model, InstallationTarget.Internal).IsValid);

        await AssertRefusedAsync(imported, Identity());
    }

    // ---------------------------------------------------------------- device identity binding

    [Theory]
    [InlineData("TB323FU")]
    [InlineData("G5")]
    public async Task Capture_IdentityModelMismatch_IsRejected(string identityModel)
    {
        using var package = InternalPackage.Write();

        using var imported = await ImportAsync(package);

        await AssertRefusedAsync(imported, Identity(model: identityModel));
    }

    [Fact]
    public async Task Capture_ImportedPackageWithForeignDeviceModel_IsRejected()
    {
        using var package = InternalPackage.Write();

        var validation = PackageReader.Validate(package.Directory, Model, InstallationTarget.Internal);
        Assert.True(validation.IsValid, string.Join("; ", validation.Reasons));

        // The directory is a valid TB322FC package, but the imported selection claims another model. The
        // snapshot binds the package, the selection and the observed identity together.
        using var imported = CreateImported(package.Directory, "TB323FU", validation);

        await AssertRefusedAsync(imported, Identity());
    }

    // ---------------------------------------------------------------- observed firmware must be complete

    [Theory]
    [InlineData("display")]
    [InlineData("fingerprint")]
    [InlineData("release")]
    [InlineData("patch")]
    public async Task Capture_IncompleteObservedFirmware_IsRejected(string missing)
    {
        using var package = InternalPackage.Write();

        using var imported = await ImportAsync(package);
        Assert.True(imported.Validation.IsValid, string.Join("; ", imported.Validation.Reasons));

        var firmware = missing switch
        {
            "display" => Firmware(displayId: null),
            "fingerprint" => Firmware(fingerprint: "   "),
            "release" => Firmware(release: null),
            _ => Firmware(patch: " "),
        };

        // No synthesized values: an unobserved field can never be filled in from the manifest or the model.
        await AssertRefusedAsync(imported, Identity(firmware));
    }

    [Fact]
    public async Task Capture_MissingFirmwareSnapshot_IsRejected()
    {
        using var package = InternalPackage.Write();

        using var imported = await ImportAsync(package);

        var identity = new DeviceIdentity(Serial, Model, BootloaderState.Unknown) { Firmware = null };

        await AssertRefusedAsync(imported, identity);
    }

    // ---------------------------------------------------------------- exact build/profile binding

    [Theory]
    // Exact DisplayId and exact declared DisplayId: accepted.
    [InlineData(DisplayId, BuildFingerprint, DisplayId, true)]
    // Exact observed BuildFingerprint named by the manifest instead of the DisplayId: accepted.
    [InlineData(DisplayId, BuildFingerprint, BuildFingerprint, true)]
    // Another build: rejected even though the manifest names the reviewed build.
    [InlineData("TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.258_ST_260611", BuildFingerprint, DisplayId, false)]
    // A substring of the reviewed build is not the reviewed build.
    [InlineData("259", BuildFingerprint, DisplayId, false)]
    // A superstring in the manifest is not an exact match, and the fingerprint is not named either.
    [InlineData(DisplayId, BuildFingerprint, DisplayId + "-hotfix", false)]
    public async Task Capture_DisplayIdAndDeclaredFirmwareVersions_MustMatchExactly(
        string displayId,
        string buildFingerprint,
        string declaredFirmwareVersion,
        bool accepted)
    {
        using var package = InternalPackage.Write(firmwareVersions: new[] { declaredFirmwareVersion });

        using var imported = await ImportAsync(package);
        Assert.True(imported.Validation.IsValid, string.Join("; ", imported.Validation.Reasons));

        var identity = Identity(Firmware(displayId: displayId, fingerprint: buildFingerprint));

        if (!accepted)
        {
            await AssertRefusedAsync(imported, identity);
            return;
        }

        var snapshot = await CaptureAsync(imported, identity);
        try
        {
            Assert.Equal(DisplayId, Get<FirmwareSnapshot>(snapshot, "Firmware").DisplayId);
        }
        finally
        {
            DisposeQuietly(snapshot);
        }
    }

    // ---------------------------------------------------------------- prepared-only payload role

    [Fact]
    public async Task Capture_MissingPreparedInitramfs_IsRejectedEvenWhenPackageReaderAccepts()
    {
        using var package = InternalPackage.Write(omitRoles: new[] { "initramfs" });

        // The fixture's runtime is already the exact prepared runtime length.
        Assert.Equal(RuntimeBytes, package.Files["runtime"].Length);

        var validation = PackageReader.Validate(package.Directory, Model, InstallationTarget.Internal);
        Assert.True(validation.IsValid, string.Join("; ", validation.Reasons));

        using var imported = await ImportAsync(package);

        await AssertRefusedAsync(imported, Identity());
    }

    // ---------------------------------------------------------------- canonical binding

    [Theory]
    [InlineData("fingerprint")]
    [InlineData("lock-state")]
    [InlineData("patch")]
    public async Task Capture_BindingSha256BindsTheCompleteObservedFirmware(string change)
    {
        using var package = InternalPackage.Write();

        using var imported = await ImportAsync(package);
        Assert.True(imported.Validation.IsValid, string.Join("; ", imported.Validation.Reasons));

        var first = await CaptureAsync(imported, Identity());
        var binding = string.Empty;
        try
        {
            binding = Get<string>(first, "BindingSha256");
            Assert.Matches("^[0-9A-Fa-f]{64}$", binding);

            // Identical bytes and identical observed firmware must bind identically.
            var second = await CaptureAsync(imported, Identity());
            try
            {
                Assert.Equal(binding, Get<string>(second, "BindingSha256"), ignoreCase: true);
            }
            finally
            {
                DisposeQuietly(second);
            }
        }
        finally
        {
            DisposeQuietly(first);
        }

        // The manifest still names the known DisplayId, so the package stays acceptable; only the observed
        // firmware moved. A boolean "DisplayId is known" check would collide here - the full binding must not.
        var changed = change switch
        {
            "fingerprint" => Firmware(fingerprint: BuildFingerprint + "-r2"),
            "lock-state" => Firmware(state: BootloaderState.Locked),
            _ => Firmware(patch: "2026-07-01"),
        };

        var third = await CaptureAsync(imported, Identity(changed));
        try
        {
            Assert.False(string.Equals(binding, Get<string>(third, "BindingSha256"), StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            DisposeQuietly(third);
        }
    }

    // ---------------------------------------------------------------- leases, revalidation, ownership

    [Fact]
    public async Task Revalidate_And_Dispose_KeepOnlySnapshotOwnedLeases()
    {
        using var package = InternalPackage.Write();

        using var imported = await ImportAsync(package);
        Assert.True(imported.Validation.IsValid, string.Join("; ", imported.Validation.Reasons));

        var snapshot = await CaptureAsync(imported, Identity());
        var seedPath = package.Files["ostree-seed"].FullPath;

        try
        {
            // An ordinary independent reader is never excluded by the snapshot's leases.
            using (var reader = new FileStream(seedPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                Assert.True(reader.ReadByte() >= 0);
            }

            await RevalidateAsync(snapshot);

            if (OperatingSystem.IsWindows())
            {
                // Windows is the only OS with observable sharing denial: while the snapshot holds its leases
                // a writer/replacer and a delete of a payload must fail.
                AssertBlocked(
                    () =>
                    {
                        using var writer = new FileStream(
                            seedPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                    });
                AssertBlocked(() => File.Delete(seedPath));
            }
            else
            {
                // POSIX has no sharing denial, so the equivalent claim is that Revalidate re-reads the bytes
                // of the held leases rather than trusting the capture-time verdict.
                FlipOneByte(package.Files["extra"].FullPath);
                var tampered = await Record.ExceptionAsync(() => RevalidateAsync(snapshot));
                Assert.NotNull(tampered);
                Assert.IsNotType<ObjectDisposedException>(tampered);
            }

            DisposeQuietly(snapshot);
            DisposeQuietly(snapshot);

            var afterDispose = await Record.ExceptionAsync(() => RevalidateAsync(snapshot));
            Assert.IsType<ObjectDisposedException>(afterDispose);

            // Disposing the snapshot never disposes the caller's ImportedPackage or removes the legacy
            // package directory: only the read leases this snapshot created are released.
            Assert.True(Directory.Exists(imported.PackageDirectory));
            Assert.True(File.Exists(package.ManifestPath));

            if (OperatingSystem.IsWindows())
            {
                AssertCanWrite(seedPath);
                File.Delete(seedPath);
                Assert.False(File.Exists(seedPath));
            }
        }
        finally
        {
            DisposeQuietly(snapshot);
        }
    }

    [Fact]
    public async Task Capture_PreCancelled_IsRejectedWithoutResidue()
    {
        using var package = InternalPackage.Write();

        using var imported = await ImportAsync(package);
        Assert.True(imported.Validation.IsValid, string.Join("; ", imported.Validation.Reasons));

        var before = Tree(package.Directory);

        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        var cancellation = await Record.ExceptionAsync(
            () => CaptureAsync(imported, Identity(), cancelled.Token));

        Assert.IsAssignableFrom<OperationCanceledException>(cancellation);

        // No output directory, staging copy or partial artefact is created next to the package.
        Assert.Equal(before, Tree(package.Directory));

        // A refusal that happened after some payloads were opened must release every partial lease.
        FlipOneByte(package.Files["extra"].FullPath);
        await AssertRefusedAsync(imported, Identity());

        if (OperatingSystem.IsWindows())
        {
            AssertCanWrite(package.Files["ostree-seed"].FullPath);
            AssertCanWrite(package.Files["runtime"].FullPath);
        }
    }

    // ---------------------------------------------------------------- reflection bridge

    /// <summary>
    /// Invokes the frozen <c>CaptureAsync</c>. A synchronous throw is unwrapped; an asynchronous failure is
    /// observed by awaiting the returned task; the snapshot is read from <c>Result</c> only afterwards.
    /// </summary>
    private static async Task<object> CaptureAsync(
        ImportedPackage package,
        DeviceIdentity identity,
        CancellationToken cancellationToken = default)
    {
        object? task;
        try
        {
            task = CaptureMethod.Invoke(null, new object?[] { package, identity, cancellationToken });
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

    private static T Get<T>(object snapshot, string name)
    {
        var property = SnapshotType.GetProperty(
            name,
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("The frozen getter " + name + " is missing.");

        return (T)property.GetValue(snapshot)!;
    }

    private static void DisposeQuietly(object snapshot) => ((IDisposable)snapshot).Dispose();

    /// <summary>
    /// Asserts that a capture attempt failed for a real reason. <see cref="NotImplementedException"/> is the
    /// RED stub and is explicitly not a refusal, otherwise every negative test would pass for the wrong
    /// reason.
    /// </summary>
    private static async Task<Exception> AssertRefusedAsync(
        ImportedPackage package,
        DeviceIdentity identity,
        CancellationToken cancellationToken = default)
    {
        var error = await Record.ExceptionAsync(
            () => CaptureAsync(package, identity, cancellationToken));

        Assert.NotNull(error);
        Assert.False(
            error is NotImplementedException,
            "The snapshot factory is still the RED stub; a refusal must be a real decision, not "
            + "NotImplementedException.");
        Assert.IsNotType<OperationCanceledException>(error);

        return error!;
    }

    // ---------------------------------------------------------------- fixtures

    private static Task<ImportedPackage> ImportAsync(InternalPackage package) =>
        PackageImporter.ImportAsync(
            package.Directory,
            Model,
            InstallationTarget.Internal,
            TestArtifactRoot.Resolve());

    private static ImportedPackage CreateImported(
        string directory,
        string deviceModel,
        PackageValidationResult validation) =>
        (ImportedPackage)ImportedPackageConstructor.Invoke(
            new object?[] { directory, directory, deviceModel, validation, null, null });

    private static DeviceIdentity Identity(
        FirmwareSnapshot? firmware = null,
        string model = Model) =>
        new(Serial, model, BootloaderState.Unknown) { Firmware = firmware ?? Firmware() };

    private static FirmwareSnapshot Firmware(
        string? displayId = DisplayId,
        string? fingerprint = BuildFingerprint,
        string? release = "15",
        string? patch = "2026-06-01",
        BootloaderState state = BootloaderState.Unknown) =>
        new(displayId, fingerprint, release, patch, state);

    private static string ManifestFingerprint(string manifestPath) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(manifestPath)));

    private static void RewriteManifest(string manifestPath, Action<JsonObject> mutate)
    {
        var metadata = JsonNode.Parse(File.ReadAllText(manifestPath))!.AsObject();
        mutate(metadata);
        File.WriteAllText(manifestPath, metadata.ToJsonString(WriteOptions));
    }

    private static void FlipOneByte(string path)
    {
        var bytes = File.ReadAllBytes(path);
        Assert.NotEmpty(bytes);
        bytes[0] ^= 0xFF;
        File.WriteAllBytes(path, bytes);
    }

    private static byte[] ReadFully(FileStream stream)
    {
        var bytes = new byte[stream.Length];
        var offset = 0;
        while (offset < bytes.Length)
        {
            var read = stream.Read(bytes, offset, bytes.Length - offset);
            if (read <= 0)
            {
                throw new IOException("The package file ended before its declared length.");
            }

            offset += read;
        }

        return bytes;
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

    /// <summary>One written fixture artefact: declared relative name, absolute path, length and uppercase digest.</summary>
    private readonly record struct FileFacts(string RelativePath, string FullPath, long Length, string Sha256);

    /// <summary>
    /// Synthetic contract-v1 package for the internal target: production (testOnly false), internal
    /// installTargets, exact 4 MiB runtime, an initramfs artefact and one optional extra artefact.
    /// </summary>
    private sealed class InternalPackage : IDisposable
    {
        private static readonly byte[] SeedPayload = CreatePayload(64, 11);
        private static readonly byte[] KernelPayload = CreatePayload(96, 23);
        private static readonly byte[] DtbPayload = CreatePayload(48, 37);
        private static readonly byte[] RuntimePayload = CreatePayload((int)RuntimeBytes, 41);
        private static readonly byte[] InitramfsPayload = CreatePayload(40, 53);
        private static readonly byte[] ExtraPayload = CreatePayload(7, 67);

        private static readonly (string Role, string RelativePath, byte[] Bytes)[] DefaultArtifacts =
        {
            ("ostree-seed", "files/ostree-seed.bin", SeedPayload),
            ("kernel", "files/kernel.bin", KernelPayload),
            ("dtb", "files/dtb.bin", DtbPayload),
            ("runtime", "files/runtime.bin", RuntimePayload),
            ("initramfs", "files/initramfs.bin", InitramfsPayload),
            ("extra", "extras/extra.bin", ExtraPayload),
        };

        private readonly TempPackageDirectory _directory;

        private InternalPackage(TempPackageDirectory directory, Dictionary<string, FileFacts> files)
        {
            _directory = directory;
            Files = files;
        }

        internal string Directory => _directory.Path;

        internal string ManifestPath => Path.Combine(_directory.Path, "package.json");

        internal IReadOnlyDictionary<string, FileFacts> Files { get; }

        public void Dispose() => _directory.Dispose();

        internal static InternalPackage Write(
            bool testOnly = false,
            string[]? installTargets = null,
            string[]? firmwareVersions = null,
            string[]? omitRoles = null,
            string version = "1.0.0",
            Action<Dictionary<string, object?>>? mutate = null)
        {
            var directory = new TempPackageDirectory();
            var files = new Dictionary<string, FileFacts>(StringComparer.Ordinal);
            var artifacts = new List<object>();

            foreach (var (role, relativePath, bytes) in DefaultArtifacts)
            {
                if (omitRoles is not null && omitRoles.Contains(role, StringComparer.Ordinal))
                {
                    continue;
                }

                var fullPath = Path.Combine(
                    directory.Path,
                    relativePath.Replace('/', Path.DirectorySeparatorChar));

                var parent = Path.GetDirectoryName(fullPath);
                if (!string.IsNullOrEmpty(parent))
                {
                    System.IO.Directory.CreateDirectory(parent);
                }

                File.WriteAllBytes(fullPath, bytes);

                var sha256 = Convert.ToHexString(SHA256.HashData(bytes));
                files.Add(role, new FileFacts(relativePath, fullPath, bytes.LongLength, sha256));
                artifacts.Add(new Dictionary<string, object?>
                {
                    ["role"] = role,
                    ["file"] = relativePath,
                    ["bytes"] = bytes.LongLength,
                    ["sha256"] = sha256,
                });
            }

            var metadata = new Dictionary<string, object?>
            {
                ["schemaVersion"] = 1,
                ["packageId"] = "armadaos-freedom-internal-example",
                ["version"] = version,
                ["deviceModel"] = Model,
                ["testOnly"] = testOnly,
                ["compatible"] = new Dictionary<string, object?>
                {
                    ["soc"] = "SM8750",
                    ["device"] = "elden",
                },
                ["artifacts"] = artifacts.ToArray(),
                ["deployment"] = new Dictionary<string, object?>
                {
                    ["kind"] = "ostree-offline-seed",
                    ["commit"] = Commit,
                    ["manifestDigest"] = ManifestDigest,
                    ["origin"] = Origin,
                },
                ["storage"] = new Dictionary<string, object?>
                {
                    ["linuxBootBytes"] = ExpectedStorage.LinuxBootBytes,
                    ["systemRequiredBytes"] = ExpectedStorage.SystemRequiredBytes,
                    ["deploymentScratchBytes"] = ExpectedStorage.DeploymentScratchBytes,
                    ["minimumLinuxDataBytes"] = ExpectedStorage.MinimumLinuxDataBytes,
                },
                ["bootCompatibility"] = new Dictionary<string, object?>
                {
                    ["format"] = "android-boot-v4",
                    ["partitionBytes"] = 100_663_296L,
                    ["firmwareVersions"] = (firmwareVersions ?? new[] { DisplayId })
                        .Cast<object?>()
                        .ToArray(),
                },
                ["toolsCompatibility"] = new Dictionary<string, object?>
                {
                    ["installerProtocol"] = 1,
                    ["maintenanceProtocol"] = 1,
                },
                ["installTargets"] = (installTargets ?? new[] { "internal" })
                    .Cast<object?>()
                    .ToArray(),
            };

            mutate?.Invoke(metadata);

            File.WriteAllText(
                Path.Combine(directory.Path, "package.json"),
                JsonSerializer.Serialize(metadata, WriteOptions));

            return new InternalPackage(directory, files);
        }

        private static byte[] CreatePayload(int length, int salt)
        {
            var payload = new byte[length];
            for (var index = 0; index < payload.Length; index++)
            {
                payload[index] = (byte)((index * 31 + salt) & 0xFF);
            }

            return payload;
        }
    }
}
