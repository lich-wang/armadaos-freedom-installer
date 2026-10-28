using System;
using System.IO;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Gate tests for <see cref="InternalInstallDirectAssets"/>. The type owns only a lease it acquired itself, so
/// the facts here are: an acquired lease survives the caller's loader, a child lease survives its parent's
/// dispose, revalidation reads the bytes currently on disk, and a refused load never takes ownership.
/// <para>
/// Every test copies the real pinned tools from <c>EDL_RAW_PACKER_PATH</c>/<c>EDL_RAW_UNPACKER_PATH</c> into a
/// unique unicode-and-spaces directory; a missing variable is a hard configuration failure, never a skip. Only
/// the copy is ever mutated, and nothing here executes a tool or reads tool contents into the test.
/// </para>
/// <para>
/// Internal <c>Tools</c>/<c>AcquireAsync</c>/<c>RevalidateAsync</c> members are reached through the same narrow
/// reflection bridge the existing tool tests use. The direct factory overload stays untested on purpose: its
/// body is a deliberate <see cref="NotImplementedException"/>.
/// </para>
/// </summary>
public sealed class InternalInstallDirectAssetsTests
{
    /// <summary>Stable refusal identity restated independently of production code.</summary>
    private const string PinMismatchCode = "edl-raw-boot-tool-pin-mismatch";

    /// <summary>Compiled packer pin, restated literally on purpose.</summary>
    private const long PackerBytes = 277460L;

    private const string PackerSha256 =
        "a2f03fc6b0e5d1b8defb60dd2a880bd5933c5133613778b17690172570ac20bb";

    /// <summary>Compiled unpacker pin, restated literally on purpose.</summary>
    private const long UnpackerBytes = 262703L;

    private const string UnpackerSha256 =
        "24d4788646282d23665b61b28460808480420a0a72e45afca6ab1a167b4b656f";

    private const string PackerPathVariable = "EDL_RAW_PACKER_PATH";

    private const string UnpackerPathVariable = "EDL_RAW_UNPACKER_PATH";

    [Fact]
    public async Task LoadAsync_OwnsAnIndependentLease_ThatOutlivesTheCallerLoaderAndItsOwnChildren()
    {
        var fixture = CreateCopies("da001-life");

        EdlRawBootTools? caller = null;
        InternalInstallDirectAssets? assets = null;
        InternalInstallDirectAssets? child = null;
        try
        {
            caller = await LoadToolsAsync(fixture.PackerCopy, fixture.UnpackerCopy);

            assets = await InternalInstallDirectAssets.LoadAsync(caller);
            Assert.False(assets.IsDisposed);

            var owned = Tools(assets);
            Assert.NotSame(caller, owned);
            Assert.False(owned.IsDisposed);

            if (OperatingSystem.IsWindows())
            {
                // The assets lease is a real read lease, so Windows refuses a concurrent writer.
                AssertWriteIsDenied(fixture.PackerCopy);
                AssertWriteIsDenied(fixture.UnpackerCopy);
            }

            // Independence in one direction: the caller's loader cannot take the assets lease away.
            caller.Dispose();
            Assert.True(caller.IsDisposed);
            await RevalidateAssetAsync(assets);

            // Independence in the other: a child acquired from the assets survives the assets' dispose.
            child = await AcquireAssetAsync(assets);
            Assert.NotSame(assets, child);
            Assert.False(child.IsDisposed);
            Assert.NotSame(owned, Tools(child));

            assets.Dispose();
            assets.Dispose();
            Assert.True(assets.IsDisposed);

            await RevalidateAssetAsync(child);

            Assert.Throws<ObjectDisposedException>(() => _ = Tools(assets));
            Assert.Throws<ObjectDisposedException>(
                () => Invoke(InternalMethod("AcquireAsync"), assets, CancellationToken.None));
            Assert.Throws<ObjectDisposedException>(
                () => Invoke(InternalMethod("RevalidateAsync"), assets, CancellationToken.None));

            child.Dispose();
            child.Dispose();
            Assert.True(child.IsDisposed);

            // Nothing here deletes an input: both copies and both provided originals are still present.
            Assert.True(File.Exists(fixture.PackerCopy));
            Assert.True(File.Exists(fixture.UnpackerCopy));
            Assert.True(File.Exists(fixture.PackerSource));
            Assert.True(File.Exists(fixture.UnpackerSource));
        }
        finally
        {
            child?.Dispose();
            assets?.Dispose();
            caller?.Dispose();
            TryDeleteDirectory(fixture.Root);
        }
    }

    [Fact]
    public async Task RevalidateAsync_ReadsTheCurrentBytes_OfTheLeaseItOwns()
    {
        var fixture = CreateCopies("da001-bytes");

        EdlRawBootTools? caller = null;
        InternalInstallDirectAssets? assets = null;
        try
        {
            caller = await LoadToolsAsync(fixture.PackerCopy, fixture.UnpackerCopy);
            assets = await InternalInstallDirectAssets.LoadAsync(caller);

            if (OperatingSystem.IsLinux())
            {
                // POSIX keeps the handle readable after an external write, so the changed byte is observable
                // and must make revalidation refuse instead of trusting the earlier read.
                TamperFirstByte(fixture.PackerCopy);

                var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
                    () => RevalidateAssetAsync(assets));

                Assert.Contains(PinMismatchCode, refusal.Message, StringComparison.Ordinal);
            }
            else if (OperatingSystem.IsWindows())
            {
                // Only Windows turns the held lease into a deny-write claim; the bytes cannot change under it.
                AssertWriteIsDenied(fixture.PackerCopy);
                AssertWriteIsDenied(fixture.UnpackerCopy);

                await RevalidateAssetAsync(assets);
            }
            else
            {
                await RevalidateAssetAsync(assets);
            }
        }
        finally
        {
            assets?.Dispose();
            caller?.Dispose();
            TryDeleteDirectory(fixture.Root);
        }
    }

    [Fact]
    public async Task LoadAsync_RefusesNullCancelledAndDisposedTools_WithoutTakingOverTheCallerLoader()
    {
        var fixture = CreateCopies("da001-guards");

        EdlRawBootTools? caller = null;
        try
        {
            caller = await LoadToolsAsync(fixture.PackerCopy, fixture.UnpackerCopy);

            await Assert.ThrowsAsync<ArgumentNullException>(
                async () => await InternalInstallDirectAssets.LoadAsync(null!).ConfigureAwait(false));

            using var cancelled = new CancellationTokenSource();
            cancelled.Cancel();

            await Assert.ThrowsAsync<OperationCanceledException>(
                async () => await InternalInstallDirectAssets
                    .LoadAsync(caller, cancelled.Token)
                    .ConfigureAwait(false));

            // A refused load leaves the caller exactly as it was: still open and still its own owner.
            Assert.False(caller.IsDisposed);
            await RevalidateToolsAsync(caller);

            caller.Dispose();
            Assert.True(caller.IsDisposed);

            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await InternalInstallDirectAssets.LoadAsync(caller).ConfigureAwait(false));
        }
        finally
        {
            caller?.Dispose();
            TryDeleteDirectory(fixture.Root);
        }
    }

    // ---------------------------------------------------------------- fixtures

    private static Fixture CreateCopies(string name)
    {
        var packerSource = RequireToolPath(PackerPathVariable);
        var unpackerSource = RequireToolPath(UnpackerPathVariable);

        var root = Path.Combine(
            TestArtifactRoot.Resolve(), name + "-中文 空格-" + Guid.NewGuid().ToString("N"));
        var packerCopy = Path.Combine(root, "packer copy.exe");
        var unpackerCopy = Path.Combine(root, "unpacker copy.exe");

        Directory.CreateDirectory(root);
        File.Copy(packerSource, packerCopy, overwrite: false);
        File.Copy(unpackerSource, unpackerCopy, overwrite: false);

        return new Fixture(root, packerCopy, unpackerCopy, packerSource, unpackerSource);
    }

    private static string RequireToolPath(string name)
    {
        var value = Environment.GetEnvironmentVariable(name);

        if (string.IsNullOrWhiteSpace(value) || !Path.IsPathRooted(value) || !File.Exists(value))
        {
            // A missing fixture is a hard configuration failure, never a skip and never a silent pass.
            throw new InvalidOperationException(
                "Fixtures configuration error: the environment variable " + name
                + " must name an absolute path to the real pinned EDL raw boot tool.");
        }

        return value;
    }

    private static Task<EdlRawBootTools> LoadToolsAsync(string packerPath, string unpackerPath) =>
        EdlRawBootTools.LoadAsync(
            new VerifiedEdlFile(packerPath, PackerBytes, PackerSha256),
            new VerifiedEdlFile(unpackerPath, UnpackerBytes, UnpackerSha256));

    private static void AssertWriteIsDenied(string path) =>
        Assert.Throws<IOException>(
            () =>
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
            });

    private static void TamperFirstByte(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);

        var original = stream.ReadByte();
        if (original < 0)
        {
            throw new InvalidOperationException("The copied tool is empty and cannot be tampered with.");
        }

        stream.Position = 0;
        stream.WriteByte((byte)(original ^ 0xFF));
        stream.Flush();
    }

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

    // ---------------------------------------------------------------- narrow reflection bridge

    private static MethodInfo InternalMethod(string name)
    {
        var method = typeof(InternalInstallDirectAssets)
            .GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic);

        return method
            ?? throw new InvalidOperationException($"InternalInstallDirectAssets.{name} is missing from the contract.");
    }

    private static EdlRawBootTools Tools(InternalInstallDirectAssets assets)
    {
        var property = typeof(InternalInstallDirectAssets)
            .GetProperty("Tools", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("InternalInstallDirectAssets.Tools is missing from the contract.");

        try
        {
            return property.GetValue(assets) as EdlRawBootTools
                ?? throw new InvalidOperationException("InternalInstallDirectAssets.Tools produced no tool set.");
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }
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

    private static async Task<InternalInstallDirectAssets> AcquireAssetAsync(
        InternalInstallDirectAssets assets)
    {
        var task = Invoke(InternalMethod("AcquireAsync"), assets, CancellationToken.None) as Task
            ?? throw new InvalidOperationException("AcquireAsync did not return a Task.");

        await task.ConfigureAwait(false);

        var result = task.GetType()
            .GetProperty("Result", BindingFlags.Public | BindingFlags.Instance)?
            .GetValue(task) as InternalInstallDirectAssets;

        return result
            ?? throw new InvalidOperationException("AcquireAsync produced no InternalInstallDirectAssets instance.");
    }

    private static Task RevalidateAssetAsync(InternalInstallDirectAssets assets) =>
        Invoke(InternalMethod("RevalidateAsync"), assets, CancellationToken.None) as Task
        ?? throw new InvalidOperationException("RevalidateAsync did not return a Task.");

    private static Task RevalidateToolsAsync(EdlRawBootTools tools)
    {
        var method = typeof(EdlRawBootTools).GetMethod(
            "RevalidateAsync", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("EdlRawBootTools.RevalidateAsync is missing from the contract.");

        return Invoke(method, tools, CancellationToken.None) as Task
            ?? throw new InvalidOperationException("RevalidateAsync did not return a Task.");
    }

    // ---------------------------------------------------------------- fixture shape

    private sealed class Fixture
    {
        public Fixture(
            string root,
            string packerCopy,
            string unpackerCopy,
            string packerSource,
            string unpackerSource)
        {
            Root = root;
            PackerCopy = packerCopy;
            UnpackerCopy = unpackerCopy;
            PackerSource = packerSource;
            UnpackerSource = unpackerSource;
        }

        public string Root { get; }

        public string PackerCopy { get; }

        public string UnpackerCopy { get; }

        public string PackerSource { get; }

        public string UnpackerSource { get; }
    }
}
