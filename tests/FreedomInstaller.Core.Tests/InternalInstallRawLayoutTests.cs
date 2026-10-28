using System;
using System.IO;
using System.Reflection;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Focused math tests for the pure raw-image upper bound. They call the internal static expression through
/// reflection, so no preparation context, package, backup, artifact or device is ever constructed here; the tests
/// prove the arithmetic and its refusals only.
/// </summary>
public sealed class InternalInstallRawLayoutTests
{
    private const long BaseLength = 36731392L;
    private const long BaseImageSize = 37355520L;
    private const long KernelLength = 78469632L;
    private const long KernelImageSize = 79364096L;
    private const long RuntimeLength = 4194304L;
    private const long DtbLength = 142132L;
    private const long InitramfsLength = 51282244L;
    private const long ReviewedUpperBound = 172917644L;
    private const long TwoMiB = 2L * 1024L * 1024L;
    private const long BranchLimit = 134217728L;

    private static readonly Type ContextType =
        typeof(InternalInstallBackend).Assembly.GetType(
            "FreedomInstaller.Core.InternalInstallPreparationContext", throwOnError: true)!;

    private static readonly MethodInfo ComputeMethod = ContextType.GetMethod(
        "ComputeRawUpperBound", BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("The raw layout expression is missing.");

    private static readonly MethodInfo FdtMethod = ContextType.GetMethod(
        "ComputeFdtUpperBound", BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("The rewritten FDT expression is missing.");

    [Fact]
    public void ReviewedProfile_ReturnsTheReviewedUpperBound()
    {
        Assert.Equal(ReviewedUpperBound, Compute(0UL, 0UL));
    }

    [Fact]
    public void ZeroTextOffsets_AreAcceptedWithoutInventingADefault()
    {
        // Both offsets stay exactly zero; no default text offset is substituted for either of them.
        long zero = Compute(0UL, 0UL);
        long explicitZero = Compute(0UL, 0UL, baseImageSize: BaseImageSize, kernelImageSize: KernelImageSize);

        Assert.Equal(ReviewedUpperBound, zero);
        Assert.Equal(zero, explicitZero);
    }

    [Fact]
    public void EqualLowTextOffsetBits_DoNotChangeTheBound()
    {
        long zero = Compute(0UL, 0UL);

        // A high, 2 MiB shifted pair has the same residue, so the same 2 MiB Linux grid is used.
        ulong high = 0x1_0000_0000UL;
        long shifted = Compute(high, unchecked(high + (ulong)TwoMiB));

        Assert.Equal(zero, shifted);
    }

    [Fact]
    public void VeryHighTextOffsets_WithTheReviewedResidue_AreAccepted()
    {
        ulong baseText = 0xFFFF_FFFF_FFFF_F000UL;
        ulong linuxText = unchecked(baseText + (ulong)TwoMiB);

        Assert.Equal(ReviewedUpperBound, Compute(baseText, linuxText));
    }

    [Fact]
    public void LargerBaseImageSize_MovesTheShimStartAndChangesTheBound()
    {
        long reviewed = Compute(0UL, 0UL);
        long larger = Compute(0UL, 0UL, baseImageSize: 40000000L);

        Assert.NotEqual(reviewed, larger);
        Assert.True(larger > reviewed, "A later shim start cannot reduce the packed upper bound.");
    }

    [Fact]
    public void BaseLengthAboveBaseImageSize_UsesTheBaseLengthForTheShim()
    {
        long reviewed = Compute(0UL, 0UL);
        long longerBase = Compute(0UL, 0UL, baseLength: 40000000L);

        Assert.NotEqual(reviewed, longerBase);
        Assert.True(longerBase > reviewed);
    }

    [Fact]
    public void ShimAtTheStrictBranchBoundary_IsRefused()
    {
        Exception failure = Refusal(0UL, 0UL, baseLength: BranchLimit, baseImageSize: 64L);

        Assert.IsType<InvalidDataException>(failure);
    }

    [Fact]
    public void ShimJustBelowTheStrictBranchBoundary_IsAccepted()
    {
        long bound = Compute(0UL, 0UL, baseLength: BranchLimit - 4L, baseImageSize: 64L);

        Assert.True(bound > 0);
    }

    [Fact]
    public void IncompatibleTextOffsetResidue_IsRefused()
    {
        Exception failure = Refusal(0UL, 0x1000UL);

        Assert.IsType<InvalidDataException>(failure);
    }

    [Theory]
    [InlineData("base-length")]
    [InlineData("base-image-size")]
    [InlineData("kernel-length")]
    [InlineData("kernel-image-size")]
    [InlineData("runtime")]
    [InlineData("dtb")]
    [InlineData("initramfs")]
    public void NonPositiveOrHeaderSizedInputs_AreRefused(string subject)
    {
        Exception failure = subject switch
        {
            "base-length" => Refusal(0UL, 0UL, baseLength: 0L),
            "base-image-size" => Refusal(0UL, 0UL, baseImageSize: 63L),
            "kernel-length" => Refusal(0UL, 0UL, kernelLength: 0L),
            "kernel-image-size" => Refusal(0UL, 0UL, kernelImageSize: 63L),
            "runtime" => Refusal(0UL, 0UL, runtimeLength: 0L),
            "dtb" => Refusal(0UL, 0UL, dtbLength: 0L),
            "initramfs" => Refusal(0UL, 0UL, initramfsLength: -1L),
            _ => throw new ArgumentOutOfRangeException(nameof(subject), subject, "unknown input"),
        };

        Assert.IsType<InvalidDataException>(failure);
    }

    [Fact]
    public void OverflowingInitramfs_IsRefused()
    {
        Exception failure = Refusal(0UL, 0UL, initramfsLength: long.MaxValue);

        Assert.IsType<InvalidDataException>(failure);
    }

    [Fact]
    public void KernelImageSizeAboveKernelLength_ExtendsTheLinuxReserve()
    {
        long byLength = Compute(0UL, 0UL, kernelImageSize: KernelLength);
        long byImageSize = Compute(0UL, 0UL, kernelImageSize: KernelImageSize);

        Assert.True(byImageSize > byLength);
    }

    [Fact]
    public void RewrittenFdtBounds_MatchTheReviewedOverheads()
    {
        Assert.Equal(142749L, Fdt(DtbLength, diagnostic: false));
        Assert.Equal(142777L, Fdt(DtbLength, diagnostic: true));
        Assert.Equal(28L, Fdt(DtbLength, diagnostic: true) - Fdt(DtbLength, diagnostic: false));
    }

    [Fact]
    public void RewrittenFdtBound_GrowsWithTheSourceBlob()
    {
        Assert.Equal(142749L + 4096L, Fdt(DtbLength + 4096L, diagnostic: false));
    }

    private static long Compute(
        ulong baseTextOffset,
        ulong linuxTextOffset,
        long baseLength = BaseLength,
        long baseImageSize = BaseImageSize,
        long kernelLength = KernelLength,
        long kernelImageSize = KernelImageSize,
        long runtimeLength = RuntimeLength,
        long dtbLength = DtbLength,
        long initramfsLength = InitramfsLength)
    {
        object? result = ComputeMethod.Invoke(
            null,
            new object[]
            {
                baseLength,
                baseImageSize,
                baseTextOffset,
                kernelLength,
                kernelImageSize,
                linuxTextOffset,
                runtimeLength,
                dtbLength,
                initramfsLength,
            });

        return Assert.IsType<long>(result);
    }

    private static long Fdt(long dtbLength, bool diagnostic) =>
        Assert.IsType<long>(FdtMethod.Invoke(null, new object[] { dtbLength, diagnostic }));

    private static Exception Refusal(
        ulong baseTextOffset,
        ulong linuxTextOffset,
        long baseLength = BaseLength,
        long baseImageSize = BaseImageSize,
        long kernelLength = KernelLength,
        long kernelImageSize = KernelImageSize,
        long runtimeLength = RuntimeLength,
        long dtbLength = DtbLength,
        long initramfsLength = InitramfsLength)
    {
        Exception? exception = Record.Exception(
            () => Compute(
                baseTextOffset,
                linuxTextOffset,
                baseLength,
                baseImageSize,
                kernelLength,
                kernelImageSize,
                runtimeLength,
                dtbLength,
                initramfsLength));

        Assert.NotNull(exception);
        TargetInvocationException invocation = Assert.IsType<TargetInvocationException>(exception);

        return invocation.InnerException
            ?? throw new InvalidOperationException("The reflected refusal carried no inner exception.");
    }
}
