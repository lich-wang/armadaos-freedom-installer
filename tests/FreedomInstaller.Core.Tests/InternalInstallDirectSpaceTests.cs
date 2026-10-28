using System;
using System.IO;
using System.Reflection;
using System.Runtime.ExceptionServices;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Policy tests for the direct execution free-space budget: the pure twelve-input arithmetic and the
/// required-versus-available refusal. The twelve arguments are fed in the production order (GPT capture,
/// boot_a capture, boot_b capture, misc capture, GPT write, board readback, Linux boot raw readback, Linux root
/// raw readback, candidate B, candidate A, fresh misc, overlay unit).
/// <para>
/// This is policy unit verification only: the expected totals are independent literals, not a mirror of the
/// implementation, and no file, device or free-space probe is touched. It says nothing about a whole flow or
/// about physical space, and it deliberately does not repeat the separate Windows UNC production-method probe.
/// </para>
/// <para>
/// The context and its static helpers are internal and there is no <c>InternalsVisibleTo</c>, so this file uses
/// the narrow reflection bridge of the existing EX001 tests: resolve the exact static method by signature,
/// invoke it and rethrow the original exception via <see cref="ExceptionDispatchInfo"/>.
/// </para>
/// </summary>
public sealed class InternalInstallDirectSpaceTests
{
    // Independent oracle: the twelve sample inputs sum to 18096 with the original capture and to 16176 without
    // it; the 1920 byte delta is exactly that one capture.
    private const long TotalWithCapture = 18096L;
    private const long TotalWithoutCapture = 16176L;
    private const long OriginalCaptureTotal = 1920L;

    private const long DummyRequiredBytes = 100L;

    [Fact]
    public void Default_twelve_argument_budget_counts_the_one_original_capture()
    {
        Assert.Equal(TotalWithCapture, Budget(SampleInputs));
    }

    [Fact]
    public void Explicit_capture_switch_reproduces_the_default_total()
    {
        Assert.Equal(TotalWithCapture, Budget(includeOriginalCapture: true, SampleInputs));
        Assert.Equal(TotalWithCapture, Budget());
    }

    [Fact]
    public void Omitting_the_original_capture_removes_exactly_that_capture()
    {
        long without = Budget(includeOriginalCapture: false, SampleInputs);

        Assert.Equal(TotalWithoutCapture, without);
        Assert.Equal(OriginalCaptureTotal, TotalWithCapture - without);
    }

    [Fact]
    public void Overflow_of_a_positive_sum_is_refused_in_both_capture_modes()
    {
        long[] captureOverflow = (long[])SampleInputs.Clone();
        captureOverflow[0] = long.MaxValue; // gpt capture
        captureOverflow[1] = 1;             // boot_a capture
        Assert.Throws<InvalidDataException>(() => Budget(captureOverflow));

        long[] readbackOverflow = new long[12];
        readbackOverflow[9] = long.MaxValue;  // candidate A readback
        readbackOverflow[10] = 1;             // fresh misc readback
        Assert.Throws<InvalidDataException>(() => Budget(includeOriginalCapture: false, readbackOverflow));
    }

    [Fact]
    public void Any_negative_input_is_refused_before_any_sum()
    {
        long[] negativeCapture = (long[])SampleInputs.Clone();
        negativeCapture[2] = -1; // boot_b capture
        Assert.Throws<InvalidDataException>(() => Budget(negativeCapture));

        long[] negativeReadback = (long[])SampleInputs.Clone();
        negativeReadback[11] = -1; // overlay unit
        Assert.Throws<InvalidDataException>(() => Budget(includeOriginalCapture: false, negativeReadback));
    }

    [Fact]
    public void Insufficient_free_space_is_refused_with_the_stable_token()
    {
        IOException error = Assert.Throws<IOException>(() => RequireSpace(DummyRequiredBytes, 99L));

        Assert.Contains("insufficient-direct-execution-space", error.Message);
    }

    [Fact]
    public void Unknown_free_space_is_the_same_refusal_never_an_unbounded_permission()
    {
        IOException error = Assert.Throws<IOException>(() => RequireSpace(DummyRequiredBytes, null));

        Assert.Contains("insufficient-direct-execution-space", error.Message);
    }

    [Fact]
    public void Exact_free_space_is_allowed_while_a_non_positive_requirement_is_refused()
    {
        RequireSpace(DummyRequiredBytes, DummyRequiredBytes);

        Assert.Throws<InvalidDataException>(() => RequireSpace(0L, DummyRequiredBytes));
    }

    private static readonly long[] SampleInputs =
    {
        128L,  // gptCaptureBytes
        256L,  // bootACaptureBytes
        512L,  // bootBCaptureBytes
        1024L, // miscCaptureBytes
        32L,   // gptWriteBytes
        2048L, // boardReadbackBytes
        4096L, // linuxBootRawReadbackBytes
        8192L, // linuxRootRawReadbackBytes
        512L,  // candidateBBytes
        256L,  // candidateABytes
        1024L, // freshMiscBytes
        8L,    // overlayUnitBytes
    };

    private static readonly Type ContextType =
        typeof(InternalInstallBackend).Assembly.GetType(
            "FreedomInstaller.Core.InternalInstallPreparationContext",
            throwOnError: true)!;

    private static readonly MethodInfo DefaultBudget = RequireStaticMethod(
        "ComputeDirectExecutionSpace",
        BudgetSignature(includeCaptureSwitch: false));

    private static readonly MethodInfo SwitchBudget = RequireStaticMethod(
        "ComputeDirectExecutionSpace",
        BudgetSignature(includeCaptureSwitch: true));

    private static readonly MethodInfo RequireSpaceMethod = RequireStaticMethod(
        "RequireDirectExecutionSpaceAvailable",
        new[] { typeof(long), typeof(long?) });

    private static MethodInfo RequireStaticMethod(string name, Type[] signature) =>
        ContextType.GetMethod(name, BindingFlags.Static | BindingFlags.NonPublic, null, signature, null)
        ?? throw new InvalidOperationException(
            "InternalInstallPreparationContext no longer declares the internal static " + name
            + " method with the expected signature.");

    private static Type[] BudgetSignature(bool includeCaptureSwitch)
    {
        Type[] signature = new Type[includeCaptureSwitch ? 13 : 12];
        int firstValue = includeCaptureSwitch ? 1 : 0;

        if (includeCaptureSwitch)
        {
            signature[0] = typeof(bool);
        }

        for (int index = firstValue; index < signature.Length; index++)
        {
            signature[index] = typeof(long);
        }

        return signature;
    }

    private static long Budget() => (long)Invoke(DefaultBudget, BoxArguments(SampleInputs))!;

    private static long Budget(long[] values) => (long)Invoke(DefaultBudget, BoxArguments(values))!;

    private static long Budget(bool includeOriginalCapture, long[] values) =>
        (long)Invoke(SwitchBudget, WithCaptureSwitch(includeOriginalCapture, values))!;

    private static void RequireSpace(long requiredBytes, long? availableBytes) =>
        Invoke(RequireSpaceMethod, new object?[] { requiredBytes, availableBytes });

    private static object?[] BoxArguments(long[] values)
    {
        object?[] arguments = new object?[values.Length];
        for (int index = 0; index < values.Length; index++)
        {
            arguments[index] = values[index];
        }

        return arguments;
    }

    private static object?[] WithCaptureSwitch(bool includeOriginalCapture, long[] values)
    {
        object?[] boxed = BoxArguments(values);
        object?[] arguments = new object?[boxed.Length + 1];
        arguments[0] = includeOriginalCapture;
        Array.Copy(boxed, 0, arguments, 1, boxed.Length);
        return arguments;
    }

    private static object? Invoke(MethodInfo method, object?[] arguments)
    {
        try
        {
            return method.Invoke(null, arguments);
        }
        catch (TargetInvocationException error) when (error.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(error.InnerException).Throw();
            throw;
        }
    }
}
