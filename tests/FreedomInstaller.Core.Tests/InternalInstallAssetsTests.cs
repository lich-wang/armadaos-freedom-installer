using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Gate tests for <see cref="InternalInstallAssets"/>. The compiled install-asset pins are frozen, so the
/// only accepted answers are: refuse a claim, a bundle or held bytes that do not match a compiled pin with
/// the stable code <c>install-asset-pin-mismatch</c>, or cancel/null-reject before touching anything.
/// <para>
/// The negative tests never create a boot image or a support archive: every claimed path is a unique,
/// deliberately absent child of <see cref="TestArtifactRoot"/>, except the truncated case, which creates
/// one 1-byte file in its own unique directory and deletes only that directory again.
/// </para>
/// <para>
/// The single positive test reads the real frozen assets the manager provides through environment
/// variables. It never copies, moves or mutates them, never fakes a bundle payload, and its absence fails
/// with an explicit fixture-configuration error instead of skipping.
/// </para>
/// </summary>
public sealed class InternalInstallAssetsTests
{
    /// <summary>Stable refusal identity restated independently of production code.</summary>
    private const string PinMismatchCode = "install-asset-pin-mismatch";

    /// <summary>The compiled new maintenance boot pin, restated literally on purpose.</summary>
    private const long MaintenanceBootBytes = 100663296L;

    private const string MaintenanceBootSha256 =
        "14d306d9f85e980b38aa9453eff3ed3f708f3f516fd210ef0f98d77784bc9c7c";

    /// <summary>The compiled install-support archive pin, restated literally on purpose.</summary>
    private const long SupportArchiveBytes = 2883836L;

    private const string SupportArchiveSha256 =
        "ae2fdeeffb6e5e2488d54e7869ef3f68ddc9fdac57dbe398c07300e767d0d3d0";

    /// <summary>Syntactically valid 64-hex digest that no reviewed asset carries.</summary>
    private const string ForeignSha256 =
        "0000000000000000000000000000000000000000000000000000000000000000";

    /// <summary>Syntactically valid digest for the unused bootstrap/helper/avb metadata of the fake bundle.</summary>
    private const string FixtureSha256 =
        "7777777777777777777777777777777777777777777777777777777777777777";

    private const string BootPathVariable = "INTERNAL_INSTALL_MAINTENANCE_BOOT";

    private const string SupportPathVariable = "INTERNAL_INSTALL_SUPPORT_ARCHIVE";

    private const string ToolboxPathVariable = "INTERNAL_INSTALL_TOOLBOX";

    [Fact]
    public async Task LoadAsync_WithClaimsThatDoNotMatchTheCompiledPins_IsRefusedBeforeAnyBundleOrFileAccess()
    {
        // Syntactically valid claims that name the old boot digest and an unrelated support digest.
        var claims = Claims(
            MaintenanceBootBytes, MaintenanceProfiles.BootSha256,
            SupportArchiveBytes, new string('a', 64));
        var toolbox = new CountingToolboxBundle();

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => InternalInstallAssets.LoadAsync(claims.Boot, claims.Support, toolbox));

        Assert.IsNotType<NotImplementedException>(exception);
        Assert.Contains(PinMismatchCode, exception.Message, StringComparison.Ordinal);

        Assert.Equal(0, toolbox.GetAssetCalls);
        Assert.Equal(0, toolbox.OpenAssetCalls);
        Assert.False(File.Exists(claims.BootPath));
        Assert.False(File.Exists(claims.SupportPath));
    }

    [Fact]
    public async Task LoadAsync_WithOnlyTheNewBootPinWrong_IsRefusedBeforeAnyBundleOrFileAccess()
    {
        var claims = Claims(MaintenanceBootBytes, ForeignSha256, SupportArchiveBytes, SupportArchiveSha256);
        var toolbox = new CountingToolboxBundle();

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => InternalInstallAssets.LoadAsync(claims.Boot, claims.Support, toolbox));

        Assert.Contains(PinMismatchCode, exception.Message, StringComparison.Ordinal);
        Assert.Equal(0, toolbox.GetAssetCalls);
        Assert.Equal(0, toolbox.OpenAssetCalls);
        Assert.False(File.Exists(claims.BootPath));
        Assert.False(File.Exists(claims.SupportPath));
    }

    [Fact]
    public async Task LoadAsync_WithOnlyTheSupportPinWrong_IsRefusedBeforeAnyBundleOrFileAccess()
    {
        var claims = Claims(MaintenanceBootBytes, MaintenanceBootSha256, SupportArchiveBytes, ForeignSha256);
        var toolbox = new CountingToolboxBundle();

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => InternalInstallAssets.LoadAsync(claims.Boot, claims.Support, toolbox));

        Assert.Contains(PinMismatchCode, exception.Message, StringComparison.Ordinal);
        Assert.Equal(0, toolbox.GetAssetCalls);
        Assert.Equal(0, toolbox.OpenAssetCalls);
        Assert.False(File.Exists(claims.BootPath));
        Assert.False(File.Exists(claims.SupportPath));
    }

    [Fact]
    public async Task LoadAsync_WithAClaimDigestThatIsNotHex_IsRefusedBeforeAnyBundleOrFileAccess()
    {
        var claims = Claims(MaintenanceBootBytes, "zz", SupportArchiveBytes, SupportArchiveSha256);
        var toolbox = new CountingToolboxBundle();

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => InternalInstallAssets.LoadAsync(claims.Boot, claims.Support, toolbox));

        Assert.Contains(PinMismatchCode, exception.Message, StringComparison.Ordinal);
        Assert.Equal(0, toolbox.GetAssetCalls);
        Assert.Equal(0, toolbox.OpenAssetCalls);
        Assert.False(File.Exists(claims.BootPath));
        Assert.False(File.Exists(claims.SupportPath));
    }

    [Fact]
    public async Task LoadAsync_WithPreCancelledToken_CancelsBeforeAnyBundleOrFileAccess()
    {
        var claims = Claims();
        var toolbox = new CountingToolboxBundle();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        var exception = await Record.ExceptionAsync(
            () => InternalInstallAssets.LoadAsync(claims.Boot, claims.Support, toolbox, cancellation.Token));

        Assert.IsAssignableFrom<OperationCanceledException>(exception);
        Assert.IsNotType<NotImplementedException>(exception);
        Assert.Equal(0, toolbox.GetAssetCalls);
        Assert.Equal(0, toolbox.OpenAssetCalls);
        Assert.False(File.Exists(claims.BootPath));
        Assert.False(File.Exists(claims.SupportPath));
    }

    [Theory]
    [InlineData("maintenanceBoot")]
    [InlineData("supportArchive")]
    [InlineData("toolboxBundle")]
    public async Task LoadAsync_WithNullArgument_ThrowsArgumentNullExceptionBeforeAnyBundleOrFileAccess(
        string argument)
    {
        var claims = Claims();
        var toolbox = new CountingToolboxBundle();

        Func<Task<InternalInstallAssets>> load = argument switch
        {
            "maintenanceBoot" => () => InternalInstallAssets.LoadAsync(null!, claims.Support, toolbox),
            "supportArchive" => () => InternalInstallAssets.LoadAsync(claims.Boot, null!, toolbox),
            "toolboxBundle" => () => InternalInstallAssets.LoadAsync(claims.Boot, claims.Support, null!),
            _ => throw new ArgumentOutOfRangeException(nameof(argument), argument, "unknown argument"),
        };

        var exception = await Record.ExceptionAsync(load);

        Assert.IsType<ArgumentNullException>(exception);
        Assert.Equal(0, toolbox.GetAssetCalls);
        Assert.Equal(0, toolbox.OpenAssetCalls);
        Assert.False(File.Exists(claims.BootPath));
        Assert.False(File.Exists(claims.SupportPath));
    }

    [Fact]
    public async Task LoadAsync_WithCompiledClaimsButMissingFiles_IsRefusedOnTheActualFile()
    {
        var claims = Claims();
        var toolbox = new ValidMetadataBundle();

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => InternalInstallAssets.LoadAsync(claims.Boot, claims.Support, toolbox));

        Assert.Contains(PinMismatchCode, exception.Message, StringComparison.Ordinal);

        // The metadata is inspected first; a missing file can never open the toolbox payload.
        Assert.Equal(MaintenanceProfiles.RequiredRoles.Count, toolbox.GetAssetCalls);
        Assert.Equal(0, toolbox.OpenAssetCalls);
        Assert.False(File.Exists(claims.BootPath));
        Assert.False(File.Exists(claims.SupportPath));
    }

    [Fact]
    public async Task LoadAsync_WithCompiledClaimsButTruncatedFiles_IsRefusedOnTheActualFileLength()
    {
        // Correct claims alone must never satisfy the loader: the real files are one byte long.
        var root = Path.Combine(TestArtifactRoot.Resolve(), "ibp001-a2-" + Guid.NewGuid().ToString("N"));
        var bootPath = Path.Combine(root, "maintenance-boot.img");
        var supportPath = Path.Combine(root, "install-support.tar.gz");

        Directory.CreateDirectory(root);
        try
        {
            File.WriteAllBytes(bootPath, new byte[] { 0x00 });
            File.WriteAllBytes(supportPath, new byte[] { 0x00 });

            var claims = new ClaimsFixture(
                new VerifiedEdlFile(bootPath, MaintenanceBootBytes, MaintenanceBootSha256),
                new VerifiedEdlFile(supportPath, SupportArchiveBytes, SupportArchiveSha256),
                bootPath,
                supportPath);
            var toolbox = new ValidMetadataBundle();

            var exception = await Assert.ThrowsAsync<InvalidOperationException>(
                () => InternalInstallAssets.LoadAsync(claims.Boot, claims.Support, toolbox));

            Assert.Contains(PinMismatchCode, exception.Message, StringComparison.Ordinal);
            Assert.Equal(0, toolbox.OpenAssetCalls);
        }
        finally
        {
            TryDeleteDirectory(root);
        }
    }

    [Fact]
    public void Type_ExposesNoPublicConstructorNoSettersAndNoPinOverride()
    {
        var type = typeof(InternalInstallAssets);

        Assert.True(type.IsSealed);
        Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Single(type.GetConstructors(BindingFlags.NonPublic | BindingFlags.Instance));

        var instanceProperties = new[]
        {
            nameof(InternalInstallAssets.MaintenanceBoot),
            nameof(InternalInstallAssets.SupportArchive),
            nameof(InternalInstallAssets.ToolboxBundle),
            nameof(InternalInstallAssets.IsDisposed),
        };

        foreach (var name in instanceProperties)
        {
            var property = type.GetProperty(name, BindingFlags.Public | BindingFlags.Instance);
            Assert.NotNull(property);
            Assert.Empty(property!.GetIndexParameters());
            Assert.NotNull(property.GetMethod);
            Assert.False(property.CanWrite, $"{name} must not be settable from a caller.");
            Assert.Null(property.SetMethod);
        }

        // No public pin/Ready/trust switch may exist that a caller could use to bypass the compiled pin.
        var trustSurface = type
            .GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static)
            .Where(member => member.Name.Contains("Pin", StringComparison.OrdinalIgnoreCase)
                || member.Name.Contains("Ready", StringComparison.OrdinalIgnoreCase)
                || member.Name.Contains("Trust", StringComparison.OrdinalIgnoreCase))
            .ToArray();

        Assert.Empty(trustSurface);
    }

    /// <summary>
    /// The one real-asset integration fact. It needs the three manager-provided absolute paths, reads the
    /// real bytes through the public loader and then exercises the internal acquire/revalidate/dispose
    /// contract through a narrow reflection bridge: the real returned task is awaited and the real
    /// instance is read, never an uninitialized object, and no readiness flag is proven.
    /// </summary>
    [Fact]
    public async Task LoadAsync_WithTheRealFrozenAssets_AcquiresRevalidatesAndRefusesOnlyAfterDispose()
    {
        var bootPath = RequireAbsoluteEnvironmentPath(BootPathVariable);
        var supportPath = RequireAbsoluteEnvironmentPath(SupportPathVariable);
        var toolboxPath = RequireAbsoluteEnvironmentPath(ToolboxPathVariable);

        var claims = new ClaimsFixture(
            new VerifiedEdlFile(bootPath, MaintenanceBootBytes, MaintenanceBootSha256),
            new VerifiedEdlFile(supportPath, SupportArchiveBytes, SupportArchiveSha256),
            bootPath,
            supportPath);

        var bundle = new RealAssetToolboxBundle(toolboxPath);

        var assets = await InternalInstallAssets.LoadAsync(claims.Boot, claims.Support, bundle);

        Assert.False(assets.IsDisposed);
        Assert.Equal(MaintenanceBootBytes, assets.MaintenanceBoot.Length);
        Assert.Equal(MaintenanceBootSha256, assets.MaintenanceBoot.Sha256);
        Assert.Equal(SupportArchiveBytes, assets.SupportArchive.Length);
        Assert.Equal(SupportArchiveSha256, assets.SupportArchive.Sha256);

        var toolboxMetadata = assets.ToolboxBundle.GetAsset(MaintenanceProfiles.ToolboxRole);
        Assert.Equal(MaintenanceProfiles.ToolboxBytes, toolboxMetadata.Bytes);
        Assert.Equal(MaintenanceProfiles.ToolboxSha256, toolboxMetadata.Sha256);
        Assert.Equal(MaintenanceProfiles.KnownProfile, assets.ToolboxBundle.Profile);
        Assert.Equal(0, bundle.OldBootOpenCalls);

        // The held FileShare.Read leases deny writers on Windows; POSIX has no such promise.
        if (OperatingSystem.IsWindows())
        {
            AssertWriteIsDenied(bootPath);
            AssertWriteIsDenied(supportPath);
            AssertWriteIsDenied(toolboxPath);
        }

        var acquired = await AcquireAsync(assets);
        Assert.NotSame(assets, acquired);
        Assert.False(acquired.IsDisposed);

        // The original assets may be released; the acquired instance owns its own leases and toolbox view.
        assets.Dispose();
        Assert.True(assets.IsDisposed);

        await RevalidateAsync(acquired);

        using (var toolboxStream = acquired.ToolboxBundle.OpenAsset(MaintenanceProfiles.ToolboxRole))
        {
            Assert.True(toolboxStream.CanRead);
            Assert.True(toolboxStream.CanSeek);
            Assert.Equal(MaintenanceProfiles.ToolboxBytes, toolboxStream.Length);
        }

        Assert.Throws<MaintenanceException>(
            () =>
            {
                using var refused = acquired.ToolboxBundle.OpenAsset(MaintenanceProfiles.BootRole);
            });

        Assert.Equal(0, bundle.DisposeCalls);
        Assert.Equal(0, bundle.OldBootOpenCalls);
        Assert.True(File.Exists(bootPath));
        Assert.True(File.Exists(supportPath));
        Assert.True(File.Exists(toolboxPath));

        acquired.Dispose();
        acquired.Dispose();
        Assert.True(acquired.IsDisposed);

        var revalidateFailure = Record.Exception(
            () =>
            {
                Invoke(InternalMethod("RevalidateAsync"), acquired, CancellationToken.None);
            });
        Assert.IsType<ObjectDisposedException>(Unwrap(revalidateFailure));

        var acquireFailure = Record.Exception(
            () =>
            {
                Invoke(InternalMethod("AcquireAsync"), acquired, CancellationToken.None);
            });
        Assert.IsType<ObjectDisposedException>(Unwrap(acquireFailure));
    }

    // ---------------------------------------------------------------- fixtures

    /// <summary>
    /// Claim fixture with the exact compiled pins. The paths are unique, deliberately absent children of
    /// <see cref="TestArtifactRoot.Resolve"/>, so any file access on a refusal path is observable.
    /// </summary>
    private static ClaimsFixture Claims() =>
        Claims(MaintenanceBootBytes, MaintenanceBootSha256, SupportArchiveBytes, SupportArchiveSha256);

    private static ClaimsFixture Claims(long bootBytes, string bootSha256, long supportBytes, string supportSha256)
    {
        var root = Path.Combine(
            TestArtifactRoot.Resolve(), "ibp001-a2-" + Guid.NewGuid().ToString("N"));

        var bootPath = Path.Combine(root, "maintenance-boot.img");
        var supportPath = Path.Combine(root, "install-support.tar.gz");

        return new ClaimsFixture(
            new VerifiedEdlFile(bootPath, bootBytes, bootSha256),
            new VerifiedEdlFile(supportPath, supportBytes, supportSha256),
            bootPath,
            supportPath);
    }

    private sealed record ClaimsFixture(
        VerifiedEdlFile Boot,
        VerifiedEdlFile Support,
        string BootPath,
        string SupportPath);

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static string RequireAbsoluteEnvironmentPath(string name)
    {
        var value = Environment.GetEnvironmentVariable(name);

        if (string.IsNullOrWhiteSpace(value) || !Path.IsPathRooted(value))
        {
            // A missing fixture is a hard configuration failure, never a skip and never a silent pass.
            throw new InvalidOperationException(
                "Fixtures configuration error: the environment variable " + name
                + " must name an absolute path to the real frozen internal-install asset.");
        }

        return value;
    }

    private static void AssertWriteIsDenied(string path) =>
        Assert.Throws<IOException>(
            () =>
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
            });

    // ---------------------------------------------------------------- narrow reflection bridge

    private static MethodInfo InternalMethod(string name)
    {
        var method = typeof(InternalInstallAssets).GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic);

        return method
            ?? throw new InvalidOperationException($"InternalInstallAssets.{name} is missing from the contract.");
    }

    private static object? Invoke(MethodInfo method, object target, params object?[] arguments)
    {
        try
        {
            return method.Invoke(target, arguments);
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }
    }

    private static Exception Unwrap(Exception? exception) =>
        exception is TargetInvocationException { InnerException: not null } wrapped
            ? wrapped.InnerException!
            : exception ?? throw new InvalidOperationException("Expected an exception, none was thrown.");

    private static async Task<InternalInstallAssets> AcquireAsync(InternalInstallAssets assets)
    {
        var task = Invoke(InternalMethod("AcquireAsync"), assets, CancellationToken.None) as Task
            ?? throw new InvalidOperationException("AcquireAsync did not return a Task.");

        await task.ConfigureAwait(false);

        var result = task.GetType()
            .GetProperty("Result", BindingFlags.Public | BindingFlags.Instance)?
            .GetValue(task) as InternalInstallAssets;

        return result
            ?? throw new InvalidOperationException("AcquireAsync produced no InternalInstallAssets instance.");
    }

    private static async Task RevalidateAsync(InternalInstallAssets assets)
    {
        var task = Invoke(InternalMethod("RevalidateAsync"), assets, CancellationToken.None) as Task
            ?? throw new InvalidOperationException("RevalidateAsync did not return a Task.");

        await task.ConfigureAwait(false);
    }

    // ---------------------------------------------------------------- fake bundles

    /// <summary>
    /// A bundle that fails loudly if a refusal path reads it at all. Every accessor is counted.
    /// </summary>
    private sealed class CountingToolboxBundle : IMaintenanceBundle
    {
        internal int GetAssetCalls { get; private set; }

        internal int OpenAssetCalls { get; private set; }

        public MaintenanceProfile Profile => MaintenanceProfiles.KnownProfile;

        public MaintenanceAsset GetAsset(string role)
        {
            GetAssetCalls++;
            throw new InvalidOperationException("A refusal must not read the toolbox bundle.");
        }

        public Stream OpenAsset(string role)
        {
            OpenAssetCalls++;
            throw new InvalidOperationException("A refusal must not open the toolbox bundle.");
        }

        public void Dispose()
        {
        }
    }

    /// <summary>
    /// Syntactically valid metadata for all five reviewed roles, but no payload at all. The loader reaches
    /// the metadata before it opens a file, so this proves the file refusal itself.
    /// </summary>
    private sealed class ValidMetadataBundle : IMaintenanceBundle
    {
        internal int GetAssetCalls { get; private set; }

        internal int OpenAssetCalls { get; private set; }

        public MaintenanceProfile Profile => MaintenanceProfiles.KnownProfile;

        public MaintenanceAsset GetAsset(string role)
        {
            GetAssetCalls++;

            return role switch
            {
                MaintenanceProfiles.BootRole => new MaintenanceAsset(
                    role, "boot.img", MaintenanceProfiles.BootBytes, MaintenanceProfiles.BootSha256),
                MaintenanceProfiles.ToolboxRole => new MaintenanceAsset(
                    role, "installer-toolbox198.tar.gz",
                    MaintenanceProfiles.ToolboxBytes, MaintenanceProfiles.ToolboxSha256),
                MaintenanceProfiles.BootstrapRole => Fixture(role, "maintenance_bootstrap.sh"),
                MaintenanceProfiles.HelperRole => Fixture(role, "armada_uninstall.py"),
                MaintenanceProfiles.AvbRole => Fixture(role, "avb_stock.py"),
                _ => throw new MaintenanceException(
                    MaintenanceErrorCode.MissingAsset, $"Unknown role '{role}'."),
            };
        }

        public Stream OpenAsset(string role)
        {
            OpenAssetCalls++;
            throw new InvalidOperationException("A metadata-only fixture has no payload.");
        }

        public void Dispose()
        {
        }

        private static MaintenanceAsset Fixture(string role, string path) =>
            new(role, path, 1, FixtureSha256);
    }

    /// <summary>
    /// The real-asset bundle: exact reviewed profile and all five metadata records, but only the toolbox
    /// payload is actually openable. Every attempt to open the old boot role is recorded and refused, so
    /// the test can prove the loader never reads it.
    /// </summary>
    private sealed class RealAssetToolboxBundle : IMaintenanceBundle
    {
        private readonly string _toolboxPath;

        internal RealAssetToolboxBundle(string toolboxPath)
        {
            _toolboxPath = toolboxPath;
        }

        internal int DisposeCalls { get; private set; }

        internal int GetAssetCalls { get; private set; }

        internal int OpenAssetCalls { get; private set; }

        internal int OldBootOpenCalls { get; private set; }

        public MaintenanceProfile Profile => MaintenanceProfiles.KnownProfile;

        public MaintenanceAsset GetAsset(string role)
        {
            GetAssetCalls++;

            return role switch
            {
                MaintenanceProfiles.BootRole => new MaintenanceAsset(
                    role, "boot.img", MaintenanceProfiles.BootBytes, MaintenanceProfiles.BootSha256),
                MaintenanceProfiles.ToolboxRole => new MaintenanceAsset(
                    role, "installer-toolbox198.tar.gz",
                    MaintenanceProfiles.ToolboxBytes, MaintenanceProfiles.ToolboxSha256),
                MaintenanceProfiles.BootstrapRole => Fixture(role, "maintenance_bootstrap.sh"),
                MaintenanceProfiles.HelperRole => Fixture(role, "armada_uninstall.py"),
                MaintenanceProfiles.AvbRole => Fixture(role, "avb_stock.py"),
                _ => throw new MaintenanceException(
                    MaintenanceErrorCode.MissingAsset, $"Unknown role '{role}'."),
            };
        }

        public Stream OpenAsset(string role)
        {
            OpenAssetCalls++;

            if (!string.Equals(role, MaintenanceProfiles.ToolboxRole, StringComparison.Ordinal))
            {
                if (string.Equals(role, MaintenanceProfiles.BootRole, StringComparison.Ordinal))
                {
                    OldBootOpenCalls++;
                }

                throw new MaintenanceException(
                    MaintenanceErrorCode.MissingAsset, "Only the real toolbox payload is available.");
            }

            return new FileStream(_toolboxPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        }

        public void Dispose()
        {
            DisposeCalls++;
        }

        private static MaintenanceAsset Fixture(string role, string path) =>
            new(role, path, 1, FixtureSha256);
    }
}
