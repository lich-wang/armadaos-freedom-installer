// ES1: inactive-slot (factory-uninitialized B) proof specification.
// Reflection only: the production type is absent on the baseline, so this file compiles there and the
// assertions fail instead of breaking the build. Every synthetic file lives under the existing
// TestArtifactRoot workspace and no partition-sized array is ever allocated (the 96 MiB boot is a
// zero-filled sparse length, hashed by streaming).
using System;
using System.IO;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class EdlRawInactiveSlotBackupTests
{
    private const string ProfileId = "g5-9008-y7005";

    [Fact]
    public async Task VerifyAsync_ZeroInactiveTarget_ReportsSourceAAndTargetBAndDisposesCleanly()
    {
        using var workspace = new EdlRawBootBuilderTests.Workspace();
        InactiveSlotBackupFixture target = InactiveSlotBackupFixture.Create(workspace);

        string[] before = Snapshot(target.Five);
        long[] lengths = Lengths(target.Five);

        Type type = InactiveSlotBackupReflection.RequireType();
        MethodInfo verify = InactiveSlotBackupReflection.RequireVerifyAsync(type);

        object proof = await InactiveSlotBackupReflection.InvokeVerifyAsync(
            verify,
            ProfileId,
            "a",
            "b",
            target.Boot,
            target.VendorBoot,
            target.InitBoot,
            target.Abl,
            target.XblConfig);

        try
        {
            Assert.Equal("a", InactiveSlotBackupReflection.Read<string>(proof, "SourceSlot"));
            Assert.Equal("b", InactiveSlotBackupReflection.Read<string>(proof, "Slot"));
            Assert.False(InactiveSlotBackupReflection.Read<bool>(proof, "IsDisposed"));
            Assert.IsAssignableFrom<IDisposable>(proof);
        }
        finally
        {
            InactiveSlotBackupReflection.DisposeProof(proof);
        }

        Assert.True(InactiveSlotBackupReflection.Read<bool>(proof, "IsDisposed"));

        // The proof only holds read leases over its five inputs: disposing it keeps every original.
        AssertSameFiles(target.Five, before, lengths);
    }

    [Theory]
    [InlineData("g4-9008-259", "a", "b")]
    [InlineData("g5-9008-y7005", "b", "a")]
    public async Task VerifyAsync_KnownCompleteProfileOppositeSlotPair_IsAccepted(
        string profileId,
        string actualCurrentSlot,
        string targetSlot)
    {
        using var workspace = new EdlRawBootBuilderTests.Workspace();
        InactiveSlotBackupFixture target = InactiveSlotBackupFixture.Create(workspace);

        string[] before = Snapshot(target.Five);
        long[] lengths = Lengths(target.Five);
        MethodInfo verify = InactiveSlotBackupReflection.RequireVerifyAsync(
            InactiveSlotBackupReflection.RequireType());

        object proof = await InactiveSlotBackupReflection.InvokeVerifyAsync(
            verify,
            profileId,
            actualCurrentSlot,
            targetSlot,
            target.Boot,
            target.VendorBoot,
            target.InitBoot,
            target.Abl,
            target.XblConfig);

        using ((IDisposable)proof)
        {
            Assert.Equal(actualCurrentSlot, InactiveSlotBackupReflection.Read<string>(proof, "SourceSlot"));
            Assert.Equal(targetSlot, InactiveSlotBackupReflection.Read<string>(proof, "Slot"));
            Assert.Equal(
                profileId,
                InactiveSlotBackupReflection.Read<EdlDeviceProfile>(proof, "Profile").ProfileId);
            Assert.False(InactiveSlotBackupReflection.Read<bool>(proof, "IsDisposed"));
        }

        Assert.True(InactiveSlotBackupReflection.Read<bool>(proof, "IsDisposed"));
        AssertSameFiles(target.Five, before, lengths);
    }

    [Theory]
    [InlineData("g5-9008-y7006", "a", "b")]
    [InlineData("g5-9008-y7005", "b", "b")]
    [InlineData("g5-9008-y7005", "a", "a")]
    public async Task VerifyAsync_UnsupportedProfileOrSlotPair_IsRejected(
        string profileId,
        string actualCurrentSlot,
        string targetSlot)
    {
        using var workspace = new EdlRawBootBuilderTests.Workspace();
        InactiveSlotBackupFixture target = InactiveSlotBackupFixture.Create(workspace);
        MethodInfo verify = InactiveSlotBackupReflection.RequireVerifyAsync(
            InactiveSlotBackupReflection.RequireType());

        await AssertRejectedAsync(
            () => InactiveSlotBackupReflection.InvokeVerifyAsync(
                verify,
                profileId,
                actualCurrentSlot,
                targetSlot,
                target.Boot,
                target.VendorBoot,
                target.InitBoot,
                target.Abl,
                target.XblConfig));
    }

    /// <summary>
    /// A single non-zero byte outside the first 4 KiB must be found for every one of the five roles:
    /// a header-only probe is not a full streaming pass. The claim is rehashed first, so the only
    /// remaining reason to refuse is the non-zero content itself.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public async Task VerifyAsync_NonZeroByteBeyondFirstFourKiB_IsRejected(int roleIndex)
    {
        using var workspace = new EdlRawBootBuilderTests.Workspace();
        InactiveSlotBackupFixture target = InactiveSlotBackupFixture.Create(workspace);
        target.WriteByteAt(roleIndex, 4096 + 17, 0x01);

        MethodInfo verify = InactiveSlotBackupReflection.RequireVerifyAsync(
            InactiveSlotBackupReflection.RequireType());

        await AssertRejectedAsync(
            () => InactiveSlotBackupReflection.InvokeVerifyAsync(
                verify,
                ProfileId,
                "a",
                "b",
                target.Boot,
                target.VendorBoot,
                target.InitBoot,
                target.Abl,
                target.XblConfig));
    }

    [Fact]
    public async Task VerifyAsync_ClaimedLengthMismatch_IsRejected()
    {
        using var workspace = new EdlRawBootBuilderTests.Workspace();
        InactiveSlotBackupFixture target = InactiveSlotBackupFixture.Create(workspace);
        var mismatched = new VerifiedEdlFile(target.Boot.Path, target.Boot.Length - 1, target.Boot.Sha256);

        MethodInfo verify = InactiveSlotBackupReflection.RequireVerifyAsync(
            InactiveSlotBackupReflection.RequireType());

        await AssertRejectedAsync(
            () => InactiveSlotBackupReflection.InvokeVerifyAsync(
                verify,
                ProfileId,
                "a",
                "b",
                mismatched,
                target.VendorBoot,
                target.InitBoot,
                target.Abl,
                target.XblConfig));
    }

    [Fact]
    public async Task VerifyAsync_ClaimedHashMismatch_IsRejected()
    {
        using var workspace = new EdlRawBootBuilderTests.Workspace();
        InactiveSlotBackupFixture target = InactiveSlotBackupFixture.Create(workspace);
        var mismatched = new VerifiedEdlFile(target.Boot.Path, target.Boot.Length, new string('0', 64));

        MethodInfo verify = InactiveSlotBackupReflection.RequireVerifyAsync(
            InactiveSlotBackupReflection.RequireType());

        await AssertRejectedAsync(
            () => InactiveSlotBackupReflection.InvokeVerifyAsync(
                verify,
                ProfileId,
                "a",
                "b",
                mismatched,
                target.VendorBoot,
                target.InitBoot,
                target.Abl,
                target.XblConfig));
    }

    [Fact]
    public async Task VerifyAsync_ZeroLengthFile_IsRejected()
    {
        using var workspace = new EdlRawBootBuilderTests.Workspace();
        InactiveSlotBackupFixture target = InactiveSlotBackupFixture.Create(workspace);
        string emptyPath = Path.Combine(target.Root, "abl-empty.bin");
        File.WriteAllBytes(emptyPath, Array.Empty<byte>());
        var empty = new VerifiedEdlFile(emptyPath, 0, Sha256OfFile(emptyPath));

        MethodInfo verify = InactiveSlotBackupReflection.RequireVerifyAsync(
            InactiveSlotBackupReflection.RequireType());

        await AssertRejectedAsync(
            () => InactiveSlotBackupReflection.InvokeVerifyAsync(
                verify,
                ProfileId,
                "a",
                "b",
                target.Boot,
                target.VendorBoot,
                target.InitBoot,
                empty,
                target.XblConfig));
    }

    [Fact]
    public async Task VerifyAsync_PreCancelledToken_IsCancelled()
    {
        using var workspace = new EdlRawBootBuilderTests.Workspace();
        InactiveSlotBackupFixture target = InactiveSlotBackupFixture.Create(workspace);
        MethodInfo verify = InactiveSlotBackupReflection.RequireVerifyAsync(
            InactiveSlotBackupReflection.RequireType());

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => InactiveSlotBackupReflection.InvokeVerifyAsync(
                verify,
                ProfileId,
                "a",
                "b",
                target.Boot,
                target.VendorBoot,
                target.InitBoot,
                target.Abl,
                target.XblConfig,
                cancellation.Token));
    }

    /// <summary>
    /// A refusal is either a bad argument or bad data. Any other exception (including the missing-type
    /// failure) is not a rejection and fails the test.
    /// </summary>
    private static async Task AssertRejectedAsync(Func<Task<object>> action)
    {
        Exception? failure = null;
        try
        {
            _ = await action();
        }
        catch (Exception exception)
        {
            failure = exception;
        }

        Assert.True(failure is not null, "the inactive-slot proof was accepted");
        Assert.True(
            failure is ArgumentException or InvalidDataException,
            "unexpected refusal: " + failure);
    }

    internal static string[] Snapshot(VerifiedEdlFile[] files)
    {
        var hashes = new string[files.Length];
        for (int index = 0; index < files.Length; index++)
        {
            hashes[index] = files[index].Sha256;
        }

        return hashes;
    }

    private static long[] Lengths(VerifiedEdlFile[] files)
    {
        var lengths = new long[files.Length];
        for (int index = 0; index < files.Length; index++)
        {
            lengths[index] = files[index].Length;
        }

        return lengths;
    }

    private static void AssertSameFiles(VerifiedEdlFile[] files, string[] hashes, long[] lengths)
    {
        for (int index = 0; index < files.Length; index++)
        {
            Assert.True(File.Exists(files[index].Path), files[index].Path);
            Assert.Equal(lengths[index], new FileInfo(files[index].Path).Length);
            Assert.Equal(hashes[index], Sha256OfFile(files[index].Path));
        }
    }

    internal static string Sha256OfFile(string path)
    {
        using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.SequentialScan);
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[81920];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            hash.AppendData(buffer, 0, read);
        }

        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }
}

/// <summary>
/// Synthetic factory-uninitialized target slot: five positive-length files whose every byte is zero.
/// The boot file is a 96 MiB zero length (SetLength only, never a 96 MiB array); the other four stay
/// small so a single tampered byte can be placed beyond the first 4 KiB.
/// </summary>
internal sealed class InactiveSlotBackupFixture
{
    internal const long BootPartitionBytes = 100_663_296L;

    internal const long ZeroFileBytes = 8192L;

    private InactiveSlotBackupFixture(string root) => Root = root;

    internal string Root { get; }

    internal VerifiedEdlFile Boot { get; private set; } = null!;

    internal VerifiedEdlFile VendorBoot { get; private set; } = null!;

    internal VerifiedEdlFile InitBoot { get; private set; } = null!;

    internal VerifiedEdlFile Abl { get; private set; } = null!;

    internal VerifiedEdlFile XblConfig { get; private set; } = null!;

    internal VerifiedEdlFile[] Five => new[] { Boot, VendorBoot, InitBoot, Abl, XblConfig };

    internal static InactiveSlotBackupFixture Create(
        EdlRawBootBuilderTests.Workspace workspace,
        long bootLength = BootPartitionBytes)
    {
        string root = Path.Combine(workspace.Root, "inactive-target-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return new InactiveSlotBackupFixture(root)
        {
            Boot = CreateZeroFile(Path.Combine(root, "boot-b.img"), bootLength),
            VendorBoot = CreateZeroFile(Path.Combine(root, "vendor-b.img"), ZeroFileBytes),
            InitBoot = CreateZeroFile(Path.Combine(root, "init-b.img"), ZeroFileBytes),
            Abl = CreateZeroFile(Path.Combine(root, "abl-b.bin"), ZeroFileBytes),
            XblConfig = CreateZeroFile(Path.Combine(root, "xbl-b.bin"), ZeroFileBytes),
        };
    }

    /// <summary>
    /// Writes one non-zero byte and refreshes that role's claim, so only the non-zero content (not a
    /// stale hash) can be the reason a correct proof refuses it.
    /// </summary>
    internal void WriteByteAt(int roleIndex, long offset, byte value)
    {
        VerifiedEdlFile file = Five[roleIndex];
        using (var stream = new FileStream(file.Path, FileMode.Open, FileAccess.Write, FileShare.None))
        {
            stream.Position = offset;
            stream.WriteByte(value);
            stream.Flush(true);
        }

        SetRole(
            roleIndex,
            new VerifiedEdlFile(file.Path, new FileInfo(file.Path).Length,
                EdlRawInactiveSlotBackupTests.Sha256OfFile(file.Path)));
    }

    private void SetRole(int roleIndex, VerifiedEdlFile claim)
    {
        switch (roleIndex)
        {
            case 0:
                Boot = claim;
                break;
            case 1:
                VendorBoot = claim;
                break;
            case 2:
                InitBoot = claim;
                break;
            case 3:
                Abl = claim;
                break;
            case 4:
                XblConfig = claim;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(roleIndex));
        }
    }

    private static VerifiedEdlFile CreateZeroFile(string path, long length)
    {
        using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            stream.SetLength(length);
            stream.Flush(true);
        }

        return new VerifiedEdlFile(
            path,
            new FileInfo(path).Length,
            EdlRawInactiveSlotBackupTests.Sha256OfFile(path));
    }
}

/// <summary>Reflection bridge: no compile-time symbol of the planned inactive-slot API is used.</summary>
internal static class InactiveSlotBackupReflection
{
    internal const string TypeName = "FreedomInstaller.Core.EdlRawInactiveSlotBackup";

    internal static Type RequireType()
    {
        Type? type = typeof(EdlRawBootBuilder).Assembly.GetType(TypeName, throwOnError: false);
        Assert.True(type is not null, TypeName + " is not present in the production assembly");
        return type!;
    }

    internal static MethodInfo RequireVerifyAsync(Type type)
    {
        MethodInfo? method = type.GetMethod("VerifyAsync", BindingFlags.Public | BindingFlags.Static);
        Assert.True(method is not null, type.Name + ".VerifyAsync was not found");
        ParameterInfo[] parameters = method!.GetParameters();
        Assert.Equal(9, parameters.Length);
        Assert.Equal(typeof(string), parameters[0].ParameterType);
        Assert.Equal(typeof(string), parameters[1].ParameterType);
        Assert.Equal(typeof(string), parameters[2].ParameterType);
        for (int index = 3; index < 8; index++)
        {
            Assert.Equal(typeof(VerifiedEdlFile), parameters[index].ParameterType);
        }

        Assert.Equal(typeof(CancellationToken), parameters[8].ParameterType);
        Assert.True(parameters[8].IsOptional, "the cancellation token must be optional");
        Assert.Equal(typeof(Task<>).MakeGenericType(type), method.ReturnType);
        return method;
    }

    internal static async Task<object> InvokeVerifyAsync(
        MethodInfo method,
        string profileId,
        string actualCurrentSlot,
        string targetSlot,
        VerifiedEdlFile boot,
        VerifiedEdlFile vendorBoot,
        VerifiedEdlFile initBoot,
        VerifiedEdlFile abl,
        VerifiedEdlFile xblConfig,
        CancellationToken cancellationToken = default)
    {
        object? invocation;
        try
        {
            invocation = method.Invoke(
                null,
                new object?[]
                {
                    profileId, actualCurrentSlot, targetSlot,
                    boot, vendorBoot, initBoot, abl, xblConfig,
                    cancellationToken,
                });
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }

        Task task = (Task)(invocation ?? throw new InvalidOperationException("VerifyAsync returned null"));
        await task;
        PropertyInfo? result = task.GetType().GetProperty("Result");
        Assert.True(result is not null, "the awaited proof task carries no Result");
        return result!.GetValue(task)
            ?? throw new InvalidOperationException("VerifyAsync returned a null proof");
    }

    internal static T Read<T>(object instance, string name)
    {
        PropertyInfo? property = instance.GetType().GetProperty(
            name, BindingFlags.Public | BindingFlags.Instance);
        Assert.True(property is not null, instance.GetType().Name + "." + name + " was not found");
        object? value = property!.GetValue(instance);
        Assert.True(value is T, instance.GetType().Name + "." + name + " is not a " + typeof(T).Name);
        return (T)value!;
    }

    internal static void DisposeProof(object proof)
    {
        Assert.True(proof is IDisposable, proof.GetType().Name + " is not disposable");
        ((IDisposable)proof).Dispose();
    }
}
