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
/// Gate tests for <see cref="EdlRawBootTools"/>. The compiled pins are frozen, so the only accepted
/// answers are: refuse a claim, a path or held bytes that do not match a compiled pin with the stable code
/// <c>edl-raw-boot-tool-pin-mismatch</c>, or cancel/null-reject before touching anything.
/// <para>
/// Negative tests never use the real tools: a claim that already fails is paired with absent paths, and a
/// right claim is paired with one tiny local file. The lifecycle test reads the real tools the manager
/// provides through environment variables, copies them into a unique unicode-and-spaces directory and
/// mutates only that copy. A missing environment variable is a hard configuration failure, never a skip.
/// </para>
/// <para>
/// Nothing here executes either tool. Internal <c>AcquireAsync</c>/<c>RevalidateAsync</c> are reached
/// through the existing narrow reflection bridge only.
/// </para>
/// </summary>
public sealed class EdlRawBootToolsTests
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

    private const string ForeignSha256 =
        "0000000000000000000000000000000000000000000000000000000000000000";

    private const string PackerPathVariable = "EDL_RAW_PACKER_PATH";

    private const string UnpackerPathVariable = "EDL_RAW_UNPACKER_PATH";

    [Fact]
    public async Task LoadAsync_WithAClaimThatDoesNotMatchTheCompiledPin_IsRefusedBeforeAnyFileAccess()
    {
        var root = Path.Combine(
            TestArtifactRoot.Resolve(), "bt001-claim-中文 空格-" + Guid.NewGuid().ToString("N"));
        var packerPath = Path.Combine(root, "packer.exe");
        var unpackerPath = Path.Combine(root, "unpacker.exe");

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => EdlRawBootTools.LoadAsync(
                new VerifiedEdlFile(packerPath, PackerBytes, ForeignSha256),
                new VerifiedEdlFile(unpackerPath, UnpackerBytes, UnpackerSha256)));

        Assert.Contains(PinMismatchCode, exception.Message, StringComparison.Ordinal);
        Assert.False(Directory.Exists(root));
    }

    [Fact]
    public async Task LoadAsync_WithTheRightClaimButWrongActualBytes_IsRefusedAndKeepsTheInput()
    {
        var root = Path.Combine(
            TestArtifactRoot.Resolve(), "bt001-bytes-中文 空格-" + Guid.NewGuid().ToString("N"));
        var packerPath = Path.Combine(root, "packer.exe");
        var unpackerPath = Path.Combine(root, "unpacker.exe");

        Directory.CreateDirectory(root);
        File.WriteAllBytes(packerPath, new byte[] { 0x4D });
        File.WriteAllBytes(unpackerPath, new byte[] { 0x5A });
        try
        {
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(
                () => EdlRawBootTools.LoadAsync(
                    new VerifiedEdlFile(packerPath, PackerBytes, PackerSha256),
                    new VerifiedEdlFile(unpackerPath, UnpackerBytes, UnpackerSha256)));

            Assert.Contains(PinMismatchCode, exception.Message, StringComparison.Ordinal);
            Assert.True(File.Exists(packerPath));
            Assert.True(File.Exists(unpackerPath));
        }
        finally
        {
            TryDeleteDirectory(root);
        }
    }

    [Fact]
    public async Task RealPins_LoadAcquireRevalidateAndDispose_AreIndependentAndPreserveEveryInput()
    {
        var packerSource = RequireToolPath(PackerPathVariable);
        var unpackerSource = RequireToolPath(UnpackerPathVariable);

        var root = Path.Combine(
            TestArtifactRoot.Resolve(), "bt001-life-中文 空格-" + Guid.NewGuid().ToString("N"));
        var packerCopy = Path.Combine(root, "packer copy.exe");
        var unpackerCopy = Path.Combine(root, "unpacker copy.exe");

        EdlRawBootTools? loaded = null;
        EdlRawBootTools? acquired = null;
        try
        {
            Directory.CreateDirectory(root);
            File.Copy(packerSource, packerCopy, overwrite: false);
            File.Copy(unpackerSource, unpackerCopy, overwrite: false);

            loaded = await EdlRawBootTools.LoadAsync(
                new VerifiedEdlFile(packerCopy, PackerBytes, PackerSha256),
                new VerifiedEdlFile(unpackerCopy, UnpackerBytes, UnpackerSha256));

            Assert.False(loaded.IsDisposed);
            Assert.Equal(Path.GetFullPath(packerCopy), loaded.Packer.Path);
            Assert.Equal(Path.GetFullPath(unpackerCopy), loaded.Unpacker.Path);
            Assert.Equal(PackerBytes, loaded.Packer.Length);
            Assert.Equal(UnpackerBytes, loaded.Unpacker.Length);
            Assert.Equal(PackerSha256, loaded.Packer.Sha256, StringComparer.Ordinal);
            Assert.Equal(UnpackerSha256, loaded.Unpacker.Sha256, StringComparer.Ordinal);

            if (OperatingSystem.IsWindows())
            {
                // Only Windows enforces FileShare.Read as a deny-write lease; no POSIX claim is made here.
                AssertWriteIsDenied(packerCopy);
                AssertWriteIsDenied(unpackerCopy);
            }

            acquired = await AcquireAsync(loaded);
            Assert.NotSame(loaded, acquired);
            Assert.False(acquired.IsDisposed);

            // The acquired instance owns its own leases, so releasing the original cannot affect it.
            loaded.Dispose();
            Assert.True(loaded.IsDisposed);

            await RevalidateAsync(acquired);

            Assert.True(File.Exists(packerCopy));
            Assert.True(File.Exists(unpackerCopy));
            Assert.True(File.Exists(packerSource));
            Assert.True(File.Exists(unpackerSource));

            if (OperatingSystem.IsLinux())
            {
                // On POSIX the read handle does not stop an external write, so the changed bytes are
                // observable and must make revalidation refuse.
                TamperFirstByte(packerCopy);

                var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
                    () => RevalidateAsync(acquired));
                Assert.Contains(PinMismatchCode, refusal.Message, StringComparison.Ordinal);
            }

            acquired.Dispose();
            acquired.Dispose();
            Assert.True(acquired.IsDisposed);

            Assert.Throws<ObjectDisposedException>(
                () =>
                {
                    Invoke(InternalMethod("RevalidateAsync"), acquired, CancellationToken.None);
                });
            Assert.Throws<ObjectDisposedException>(
                () =>
                {
                    Invoke(InternalMethod("AcquireAsync"), acquired, CancellationToken.None);
                });
        }
        finally
        {
            acquired?.Dispose();
            loaded?.Dispose();
            TryDeleteDirectory(root);
        }
    }

    [Fact]
    public void ApiShape_HasOnlyPrivateConstructors_AndNoSettablePinProperties()
    {
        var type = typeof(EdlRawBootTools);

        Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.NotEmpty(type.GetConstructors(BindingFlags.NonPublic | BindingFlags.Instance));

        foreach (var name in new[] { "Packer", "Unpacker", "IsDisposed" })
        {
            var property = type.GetProperty(name, BindingFlags.Public | BindingFlags.Instance)
                ?? throw new InvalidOperationException($"EdlRawBootTools.{name} is missing from the contract.");

            Assert.Null(property.SetMethod);
        }
    }

    // ---------------------------------------------------------------- fixtures

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
        var method = typeof(EdlRawBootTools).GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic);

        return method
            ?? throw new InvalidOperationException($"EdlRawBootTools.{name} is missing from the contract.");
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

    private static async Task<EdlRawBootTools> AcquireAsync(EdlRawBootTools tools)
    {
        var task = Invoke(InternalMethod("AcquireAsync"), tools, CancellationToken.None) as Task
            ?? throw new InvalidOperationException("AcquireAsync did not return a Task.");

        await task.ConfigureAwait(false);

        var result = task.GetType()
            .GetProperty("Result", BindingFlags.Public | BindingFlags.Instance)?
            .GetValue(task) as EdlRawBootTools;

        return result
            ?? throw new InvalidOperationException("AcquireAsync produced no EdlRawBootTools instance.");
    }

    private static async Task RevalidateAsync(EdlRawBootTools tools)
    {
        var task = Invoke(InternalMethod("RevalidateAsync"), tools, CancellationToken.None) as Task
            ?? throw new InvalidOperationException("RevalidateAsync did not return a Task.");

        await task.ConfigureAwait(false);
    }
}
