using System;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Focused evidence-format and lease tests for the internal preparation context. Everything here is pure or
/// local: the BCB check and the unsigned JSON reader are driven through narrow reflection on their real
/// implementations, and the held-evidence helper is exercised against one small test-owned file. No context,
/// prepared instance, Sahara proof, device, command or backup is constructed.
/// </summary>
public sealed class InternalInstallContextEvidenceTests
{
    private static readonly Type ContextType =
        typeof(InternalInstallBackend).Assembly.GetType(
            "FreedomInstaller.Core.InternalInstallPreparationContext", throwOnError: true)!;

    private static readonly MethodInfo ValidateBcbMethod = ContextType.GetMethod(
        "ValidateNormalBootBcb", BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("The BCB allow-state check is missing.");

    private static readonly MethodInfo RequireUInt64Method = ContextType.GetMethod(
        "RequireUInt64", BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("The unsigned attribute reader is missing.");

    private static readonly MethodInfo HoldMethod = ContextType.GetMethod(
        "Hold", BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("The held-evidence helper is missing.");

    [Theory]
    [InlineData("empty")]
    [InlineData("bootonce")]
    [InlineData("unknown-command")]
    [InlineData("recovery")]
    [InlineData("padding")]
    [InlineData("truncated")]
    public void ValidateNormalBootBcb_AcceptsOnlyTheExactAllowStatesWithoutMutatingTheInput(string scenario)
    {
        byte[] bcb = BcbFixture(scenario);
        byte[] original = (byte[])bcb.Clone();

        bool accepted = scenario is "empty" or "bootonce";

        if (accepted)
        {
            InvokeBcb(bcb);
        }
        else
        {
            Assert.Throws<InvalidDataException>(() => InvokeBcb(bcb));
        }

        // Status, stage, reserved and every other non-control byte are never rewritten by the check.
        Assert.Equal(original, bcb);
    }

    [Theory]
    [InlineData("0", "0", true)]
    [InlineData("9223372036854775808", "9223372036854775808", true)]
    [InlineData("18446744073709551615", "18446744073709551615", true)]
    [InlineData("-1", null, false)]
    [InlineData("1.5", null, false)]
    [InlineData("18446744073709551616", null, false)]
    public void RequireUInt64_KeepsEveryBitAndRefusesEveryNonUnsignedInteger(
        string literal,
        string? expected,
        bool accepted)
    {
        using JsonDocument document = JsonDocument.Parse("{\"attributes\":" + literal + "}");
        JsonElement element = document.RootElement;

        if (!accepted)
        {
            Assert.Throws<InvalidDataException>(() => InvokeUInt64(element));
            return;
        }

        object? result = InvokeUInt64(element);

        ulong value = Assert.IsType<ulong>(result);
        Assert.Equal(ulong.Parse(expected!, CultureInfo.InvariantCulture), value);
    }

    [Fact]
    public void Hold_WithAPreCancelledToken_ClosesItsOwnReadLease()
    {
        string root = Path.Combine(
            TestArtifactRoot.Resolve(), "ibp001-p2f-hold-cancel-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);

        try
        {
            byte[] bytes = new byte[512];
            for (int index = 0; index < bytes.Length; index++)
            {
                bytes[index] = (byte)((index * 31) + 7);
            }

            string path = Path.Combine(root, "misc-prefix.bin");
            File.WriteAllBytes(path, bytes);
            string sha256 = Convert.ToHexString(SHA256.HashData(bytes));

            var evidence = new EdlReadEvidence(
                new EdlGeometry(0, 512, 1),
                0,
                1,
                path,
                bytes.Length,
                sha256,
                default!);

            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();

            Exception? failure = Record.Exception(
                () => InvokeHold("misc-prefix", path, bytes.Length, evidence, cancellation.Token));

            Assert.IsAssignableFrom<OperationCanceledException>(failure);

            // A leaked FileShare.Read lease would keep this exclusive reopen from succeeding.
            using (var exclusive = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                Assert.Equal(bytes.Length, exclusive.Length);
            }
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public void Hold_WithAWrongSha256_RefusesAndClosesItsLeaseOnEveryAttempt()
    {
        string root = Path.Combine(
            TestArtifactRoot.Resolve(), "ibp001-p2f-hold-mismatch-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);

        try
        {
            byte[] bytes = new byte[512];
            for (int index = 0; index < bytes.Length; index++)
            {
                bytes[index] = (byte)((index * 17) + 3);
            }

            string path = Path.Combine(root, "evidence.bin");
            File.WriteAllBytes(path, bytes);

            string wrongSha256 = new('0', 64);

            for (int attempt = 0; attempt < 2; attempt++)
            {
                var evidence = new EdlReadEvidence(
                    new EdlGeometry(0, 512, 1),
                    0,
                    1,
                    path,
                    bytes.Length,
                    wrongSha256,
                    default!);

                Exception? failure = Record.Exception(
                    () => InvokeHold("evidence", path, bytes.Length, evidence, CancellationToken.None));

                Assert.IsType<InvalidOperationException>(failure);

                using var exclusive = new FileStream(
                    path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                Assert.Equal(bytes.Length, exclusive.Length);
            }
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static byte[] BcbFixture(string scenario)
    {
        // Status [32:64) and reserved [832:2048) stay arbitrary: the contract only inspects command and recovery.
        byte[] bcb = new byte[2048];
        for (int index = 32; index < 64; index++)
        {
            bcb[index] = (byte)(0x5A + index);
        }

        for (int index = 832; index < bcb.Length; index++)
        {
            bcb[index] = (byte)(index * 7);
        }

        if (scenario == "truncated")
        {
            return bcb.AsSpan(0, 2047).ToArray();
        }

        if (scenario == "bootonce")
        {
            Encoding.ASCII.GetBytes("bootonce-bootloader").CopyTo(bcb, 0);
        }

        if (scenario == "unknown-command")
        {
            Encoding.ASCII.GetBytes("bootonce-recovery").CopyTo(bcb, 0);
        }

        if (scenario == "recovery")
        {
            bcb[64] = 0x01;
        }

        if (scenario == "padding")
        {
            Encoding.ASCII.GetBytes("bootonce-bootloader").CopyTo(bcb, 0);
            bcb[19] = (byte)'X';
        }

        return bcb;
    }

    private static void InvokeBcb(byte[] bcb)
    {
        try
        {
            ValidateBcbMethod.Invoke(null, new object?[] { bcb });
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }
    }

    private static object? InvokeUInt64(JsonElement element)
    {
        try
        {
            return RequireUInt64Method.Invoke(null, new object?[] { element, "attributes" });
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }
    }

    private static object? InvokeHold(
        string subject,
        string path,
        long expectedLength,
        EdlReadEvidence evidence,
        CancellationToken cancellationToken)
    {
        try
        {
            return HoldMethod.Invoke(
                null,
                new object?[] { subject, path, expectedLength, evidence, cancellationToken });
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }
    }
}
