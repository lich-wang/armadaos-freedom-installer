using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.ExceptionServices;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Gate tests for the internal <c>InternalInstallBackend.ExecutionRun</c> mutation-state holder. They pin the
/// only allowed transitions: Unknown until a real readback, no acknowledgement authority, no reset-driven boot
/// verification, no repeat finish and no Android downgrade.
/// <para>
/// The run type is internal and no <c>InternalsVisibleTo</c> exists, so this file carries one narrow reflection
/// bridge: it resolves the nested type, its frozen getters and its frozen methods, unwraps
/// <see cref="TargetInvocationException"/> and nothing else. Every transition below is the real production code;
/// no fake backend, transport, delegate or task framework is introduced, and no device is touched.
/// </para>
/// </summary>
public sealed class InternalInstallExecutionStateTests
{
    [Fact]
    public void New_run_starts_prepared_with_no_issued_mutation()
    {
        var run = new Run();

        Assert.Equal(InternalInstallStage.Prepared, run.Stage);
        Assert.Null(run.LastVerifiedStage);
        Assert.Equal(InternalInstallWriteState.NoneIssued, run.WriteState);
        Assert.False(run.AndroidDataMayBeErased);
        Assert.False(run.IsInterrupted);
        Assert.Empty(run.VerifiedSlots);
        Assert.Null(run.AndroidAcceptance);
    }

    [Fact]
    public void Start_stage_does_not_verify_and_is_refused_while_a_mutation_is_pending()
    {
        var run = new Run();

        run.StartStage(InternalInstallStage.Revalidating);
        Assert.Equal(InternalInstallStage.Revalidating, run.Stage);
        Assert.Null(run.LastVerifiedStage);
        Assert.Equal(InternalInstallWriteState.NoneIssued, run.WriteState);

        Assert.Throws<InvalidOperationException>(
            () => run.VerifyStage(InternalInstallStage.WritingGpt));
        Assert.Null(run.LastVerifiedStage);

        run.VerifyStage(InternalInstallStage.Revalidating);
        Assert.Equal(InternalInstallStage.Revalidating, run.LastVerifiedStage);

        run.BeginRawWrite(InternalInstallStage.WritingMaintenanceBoot, null, false);
        Assert.Throws<InvalidOperationException>(
            () => run.StartStage(InternalInstallStage.WritingGpt));
        Assert.Throws<InvalidOperationException>(
            () => run.VerifyStage(InternalInstallStage.WritingMaintenanceBoot));
        Assert.Equal(InternalInstallStage.WritingMaintenanceBoot, run.Stage);
        Assert.Equal(InternalInstallStage.Revalidating, run.LastVerifiedStage);
    }

    [Fact]
    public void Completed_is_never_a_stage_this_run_reaches()
    {
        var run = new Run();

        Assert.Throws<ArgumentOutOfRangeException>(
            () => run.StartStage(InternalInstallStage.Completed));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => run.VerifyStage(InternalInstallStage.Completed));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => run.BeginRawWrite(InternalInstallStage.Completed, null, false));
    }

    [Fact]
    public void Raw_write_stays_unknown_and_an_acknowledgement_has_no_completion_method()
    {
        var run = new Run();

        run.BeginRawWrite(InternalInstallStage.WritingMaintenanceBoot, null, mayEraseAndroid: true);

        Assert.Equal(InternalInstallWriteState.Unknown, run.WriteState);
        Assert.True(run.AndroidDataMayBeErased);
        Assert.Empty(run.VerifiedSlots);

        // An acknowledgement-only reset entry cannot clear a pending raw write: only a full matching readback
        // can resolve it, and the rejected call leaves the mutation Unknown.
        Assert.Throws<InvalidOperationException>(() => run.AcceptNormalReset());

        Assert.Equal(InternalInstallWriteState.Unknown, run.WriteState);
        Assert.Empty(run.VerifiedSlots);

        run.VerifyRawReadback(InternalInstallStage.WritingMaintenanceBoot, null);

        Assert.Equal(InternalInstallWriteState.AllVerified, run.WriteState);
        Assert.Equal(InternalInstallStage.WritingMaintenanceBoot, run.LastVerifiedStage);
        Assert.Empty(run.VerifiedSlots);
    }

    [Fact]
    public void Wrong_stage_does_not_clear_a_pending_raw_write()
    {
        var run = new Run();
        run.BeginRawWrite(InternalInstallStage.WritingBootA, "a", false);

        Assert.Throws<InvalidOperationException>(
            () => run.VerifyRawReadback(InternalInstallStage.WritingMaintenanceBoot, "a"));
        Assert.Equal(InternalInstallWriteState.Unknown, run.WriteState);
        Assert.Null(run.LastVerifiedStage);

        run.VerifyRawReadback(InternalInstallStage.WritingBootA, "a");

        Assert.Equal(InternalInstallWriteState.AllVerified, run.WriteState);
        Assert.Equal(new[] { "a" }, run.VerifiedSlots);
    }

    [Fact]
    public void Wrong_slot_does_not_clear_a_pending_boot_write()
    {
        var run = new Run();
        run.BeginRawWrite(InternalInstallStage.WritingBootB, "b", false);

        Assert.Throws<InvalidOperationException>(
            () => run.VerifyRawReadback(InternalInstallStage.WritingBootB, "a"));
        Assert.Throws<InvalidOperationException>(
            () => run.VerifyRawReadback(InternalInstallStage.WritingBootB, null));
        Assert.Equal(InternalInstallWriteState.Unknown, run.WriteState);
        Assert.Empty(run.VerifiedSlots);

        run.VerifyRawReadback(InternalInstallStage.WritingBootB, "b");

        Assert.Equal(new[] { "b" }, run.VerifiedSlots);
        Assert.Equal(InternalInstallStage.WritingBootB, run.LastVerifiedStage);
    }

    [Fact]
    public void Boot_write_requires_its_own_slot_and_no_mutation_is_staged_by_a_refusal()
    {
        var run = new Run();

        Assert.Throws<ArgumentException>(
            () => run.BeginRawWrite(InternalInstallStage.WritingBootA, "b", false));
        Assert.Throws<ArgumentException>(
            () => run.BeginRawWrite(InternalInstallStage.WritingBootB, null, false));
        Assert.Throws<ArgumentException>(
            () => run.BeginRawWrite(InternalInstallStage.WritingGpt, "c", false));
        Assert.Throws<ArgumentException>(
            () => run.BeginRawWrite(InternalInstallStage.Prepared, null, false));

        Assert.Equal(InternalInstallStage.Prepared, run.Stage);
        Assert.Equal(InternalInstallWriteState.NoneIssued, run.WriteState);

        run.BeginRawWrite(InternalInstallStage.WritingBootB, "b", false);
        run.VerifyRawReadback(InternalInstallStage.WritingBootB, "b");

        Assert.Equal(new[] { "b" }, run.VerifiedSlots);
    }

    [Fact]
    public void Interrupt_after_a_pending_mutation_poisons_the_run_and_keeps_prior_receipts()
    {
        var run = new Run();
        run.BeginRawWrite(InternalInstallStage.WritingBootB, "b", false);
        run.VerifyRawReadback(InternalInstallStage.WritingBootB, "b");
        Assert.Equal(new[] { "b" }, run.VerifiedSlots);

        run.BeginRawWrite(InternalInstallStage.WritingBootA, "a", false);
        run.Interrupt();

        Assert.True(run.IsInterrupted);
        Assert.Equal(InternalInstallWriteState.Unknown, run.WriteState);
        Assert.Equal(new[] { "b" }, run.VerifiedSlots);
        Assert.Equal(InternalInstallStage.WritingBootB, run.LastVerifiedStage);

        Assert.Throws<InvalidOperationException>(
            () => run.VerifyRawReadback(InternalInstallStage.WritingBootA, "a"));
        Assert.Throws<InvalidOperationException>(
            () => run.BeginRamMutation(InternalInstallStage.PreparingFilesystems, false));
        Assert.Throws<InvalidOperationException>(
            () => run.BeginNormalReset(InternalInstallStage.BootingAndroid));
        Assert.Throws<InvalidOperationException>(() => run.BeginFinish());
        Assert.Throws<InvalidOperationException>(
            () => run.StartStage(InternalInstallStage.WritingMisc));
        Assert.Throws<InvalidOperationException>(
            () => run.VerifyStage(InternalInstallStage.WritingBootB));

        // The poison does not rewrite the receipts it already recorded.
        Assert.Equal(new[] { "b" }, run.VerifiedSlots);
        Assert.Equal(InternalInstallWriteState.Unknown, run.WriteState);
    }

    [Fact]
    public void Interrupt_without_a_pending_mutation_preserves_the_known_state()
    {
        var run = new Run();
        run.BeginRawWrite(InternalInstallStage.WritingMaintenanceBoot, null, mayEraseAndroid: true);
        run.VerifyRawReadback(InternalInstallStage.WritingMaintenanceBoot, null);

        run.Interrupt();

        Assert.False(run.IsInterrupted);
        Assert.Equal(InternalInstallWriteState.AllVerified, run.WriteState);
        Assert.Equal(InternalInstallStage.WritingMaintenanceBoot, run.LastVerifiedStage);
        Assert.True(run.AndroidDataMayBeErased);
    }

    [Fact]
    public void Accepted_normal_reset_restores_all_verified_without_advancing_the_boot_identity()
    {
        var run = new Run();
        run.BeginRawWrite(InternalInstallStage.WritingMaintenanceBoot, null, mayEraseAndroid: true);
        run.VerifyRawReadback(InternalInstallStage.WritingMaintenanceBoot, null);
        Assert.Equal(InternalInstallStage.WritingMaintenanceBoot, run.LastVerifiedStage);

        run.BeginNormalReset(InternalInstallStage.BootingAndroid);
        Assert.Equal(InternalInstallWriteState.Unknown, run.WriteState);
        Assert.Equal(InternalInstallStage.BootingAndroid, run.Stage);

        run.AcceptNormalReset();

        Assert.Equal(InternalInstallWriteState.AllVerified, run.WriteState);
        Assert.Equal(InternalInstallStage.WritingMaintenanceBoot, run.LastVerifiedStage);
        Assert.Equal(InternalInstallStage.BootingAndroid, run.Stage);
        Assert.Empty(run.VerifiedSlots);
    }

    [Fact]
    public void Requested_or_lost_finish_acknowledgement_stays_unknown_until_fresh_edl_proof()
    {
        var run = new Run();
        run.BeginFinish();

        Assert.Equal(InternalInstallStage.ReturningEdl, run.Stage);
        Assert.Equal(InternalInstallWriteState.Unknown, run.WriteState);
        Assert.Null(run.LastVerifiedStage);

        run.FinishMayHaveReset();

        Assert.Equal(InternalInstallWriteState.Unknown, run.WriteState);
        Assert.Null(run.LastVerifiedStage);
        Assert.Empty(run.VerifiedSlots);

        // The pending finish rejects a second begin; only the fresh Sahara + full post proof resolves it.
        Assert.Throws<InvalidOperationException>(() => run.BeginFinish());

        run.VerifyFreshEdlTransition();

        Assert.Equal(InternalInstallWriteState.AllVerified, run.WriteState);
        Assert.Equal(InternalInstallStage.ReturningEdl, run.LastVerifiedStage);
        Assert.Throws<InvalidOperationException>(() => run.BeginFinish());

        // A later stage transition must not re-authorize a second finish: the flag is sticky, not stage-derived.
        run.StartStage(InternalInstallStage.WritingBootB);
        Assert.Equal(InternalInstallStage.WritingBootB, run.Stage);
        Assert.Throws<InvalidOperationException>(() => run.BeginFinish());
        Assert.Equal(InternalInstallStage.WritingBootB, run.Stage);
    }

    [Fact]
    public void Restart2_returned_is_a_known_failure_not_stage_proof()
    {
        var run = new Run();
        run.StartStage(InternalInstallStage.Revalidating);
        run.VerifyStage(InternalInstallStage.Revalidating);

        run.BeginFinish();
        run.FinishReturned();

        Assert.Equal(InternalInstallWriteState.AllVerified, run.WriteState);
        Assert.Equal(InternalInstallStage.Revalidating, run.LastVerifiedStage);
        Assert.Equal(InternalInstallStage.ReturningEdl, run.Stage);

        Assert.Throws<InvalidOperationException>(() => run.BeginFinish());
    }

    [Fact]
    public void Ram_mutation_stays_unknown_until_the_job_itself_verified()
    {
        var run = new Run();
        run.BeginRamMutation(InternalInstallStage.ReceivingSeed, mayEraseAndroid: true);

        Assert.Equal(InternalInstallWriteState.Unknown, run.WriteState);
        Assert.True(run.AndroidDataMayBeErased);
        Assert.Empty(run.VerifiedSlots);

        Assert.Throws<InvalidOperationException>(
            () => run.VerifyRamJob(InternalInstallStage.Deploying));
        Assert.Equal(InternalInstallWriteState.Unknown, run.WriteState);

        run.VerifyRamJob(InternalInstallStage.ReceivingSeed);

        Assert.Equal(InternalInstallWriteState.AllVerified, run.WriteState);
        Assert.Equal(InternalInstallStage.ReceivingSeed, run.LastVerifiedStage);
        Assert.Empty(run.VerifiedSlots);
    }

    [Theory]
    [InlineData(InternalInstallStage.PreparingFilesystems)]
    [InlineData(InternalInstallStage.ReceivingSeed)]
    [InlineData(InternalInstallStage.Deploying)]
    public void Ram_wait_cancel_or_timeout_poisons_the_fixed_stage(InternalInstallStage stage)
    {
        var run = new Run();
        run.BeginRamMutation(stage, mayEraseAndroid: false);

        Assert.Equal(InternalInstallWriteState.Unknown, run.WriteState);
        Assert.Equal(stage, run.Stage);
        Assert.Null(run.LastVerifiedStage);

        // Interrupt represents the caller's wait cancellation or timeout: the job outcome is unknown.
        run.Interrupt();

        Assert.True(run.IsInterrupted);
        Assert.Equal(InternalInstallWriteState.Unknown, run.WriteState);
        Assert.Equal(stage, run.Stage);
        Assert.Null(run.LastVerifiedStage);

        // An unknown job is never promoted, and no new mutation or stage proof is accepted.
        Assert.Throws<InvalidOperationException>(() => run.VerifyRamJob(stage));
        Assert.Throws<InvalidOperationException>(
            () => run.BeginRamMutation(InternalInstallStage.Deploying, false));

        Assert.Equal(InternalInstallWriteState.Unknown, run.WriteState);
        Assert.Null(run.LastVerifiedStage);
    }

    [Fact]
    public void Verified_android_is_cached_and_later_nonverified_or_absent_results_are_ignored()
    {
        var run = new Run();
        var verified = Acceptance(InternalAndroidAcceptanceState.Verified);

        run.RememberAndroidAcceptance(verified);
        Assert.Same(verified, run.AndroidAcceptance);

        run.RememberAndroidAcceptance(Acceptance(InternalAndroidAcceptanceState.AwaitingUsbAuthorization));
        run.RememberAndroidAcceptance(Acceptance(InternalAndroidAcceptanceState.Rejected));
        run.RememberAndroidAcceptance(null);

        Assert.Same(verified, run.AndroidAcceptance);

        // A non-verified result is never cached, even before any verified one was seen.
        var freshRun = new Run();
        freshRun.RememberAndroidAcceptance(
            Acceptance(InternalAndroidAcceptanceState.AwaitingAndroidInitialization));
        Assert.Null(freshRun.AndroidAcceptance);
    }

    private static InternalAndroidAcceptanceResult Acceptance(InternalAndroidAcceptanceState state)
    {
        var constructor = typeof(InternalAndroidAcceptanceResult).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            new[]
            {
                typeof(InternalAndroidAcceptanceState),
                typeof(string),
                typeof(AndroidMaintenanceIdentity),
                typeof(long?),
                typeof(long?),
                typeof(bool),
            },
            modifiers: null)
            ?? throw new InvalidOperationException(
                "InternalAndroidAcceptanceResult no longer exposes the internal constructor this fixture drives.");

        return (InternalAndroidAcceptanceResult)constructor.Invoke(new object?[]
        {
            state,
            state.ToString(),
            null,
            null,
            null,
            false,
        });
    }

    /// <summary>
    /// The narrow bridge to the internal nested run type: resolve the frozen getter or method by name, invoke
    /// it on the real instance and surface the production exception instead of a reflection wrapper.
    /// </summary>
    private sealed class Run
    {
        private static readonly Type RunType =
            typeof(InternalInstallBackend).GetNestedType("ExecutionRun", BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "InternalInstallBackend no longer declares the nested ExecutionRun type.");

        private readonly object _instance =
            Activator.CreateInstance(RunType, nonPublic: true)
            ?? throw new InvalidOperationException("ExecutionRun has no parameterless constructor.");

        /// <summary>Every declared instance method name, for the no-acknowledgement surface assertion.</summary>
        public static IReadOnlyList<string> MethodNames { get; } = RunType
            .GetMethods(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)
            .Where(method => !method.IsSpecialName)
            .Select(method => method.Name)
            .ToArray();

        public InternalInstallStage Stage => (InternalInstallStage)Read(nameof(Stage))!;

        public InternalInstallStage? LastVerifiedStage =>
            (InternalInstallStage?)Read(nameof(LastVerifiedStage));

        public InternalInstallWriteState WriteState =>
            (InternalInstallWriteState)Read(nameof(WriteState))!;

        public bool AndroidDataMayBeErased => (bool)Read(nameof(AndroidDataMayBeErased))!;

        public bool IsInterrupted => (bool)Read(nameof(IsInterrupted))!;

        public IReadOnlyList<string> VerifiedSlots =>
            (IReadOnlyList<string>)Read(nameof(VerifiedSlots))!;

        public InternalAndroidAcceptanceResult? AndroidAcceptance =>
            (InternalAndroidAcceptanceResult?)Read(nameof(AndroidAcceptance));

        public void StartStage(InternalInstallStage stage) => Invoke(nameof(StartStage), stage);

        public void VerifyStage(InternalInstallStage stage) => Invoke(nameof(VerifyStage), stage);

        public void BeginRawWrite(InternalInstallStage stage, string? slot, bool mayEraseAndroid) =>
            Invoke(nameof(BeginRawWrite), stage, slot, mayEraseAndroid);

        public void VerifyRawReadback(InternalInstallStage stage, string? slot) =>
            Invoke(nameof(VerifyRawReadback), stage, slot);

        public void BeginRamMutation(InternalInstallStage stage, bool mayEraseAndroid) =>
            Invoke(nameof(BeginRamMutation), stage, mayEraseAndroid);

        public void VerifyRamJob(InternalInstallStage stage) => Invoke(nameof(VerifyRamJob), stage);

        public void BeginNormalReset(InternalInstallStage stage) =>
            Invoke(nameof(BeginNormalReset), stage);

        public void AcceptNormalReset() => Invoke(nameof(AcceptNormalReset));

        public void BeginFinish() => Invoke(nameof(BeginFinish));

        public void FinishReturned() => Invoke(nameof(FinishReturned));

        public void FinishMayHaveReset() => Invoke(nameof(FinishMayHaveReset));

        public void VerifyFreshEdlTransition() => Invoke(nameof(VerifyFreshEdlTransition));

        public void Interrupt() => Invoke(nameof(Interrupt));

        public void RememberAndroidAcceptance(InternalAndroidAcceptanceResult? result) =>
            Invoke(nameof(RememberAndroidAcceptance), result);

        private object? Read(string name)
        {
            var property = RunType.GetProperty(name, BindingFlags.Instance | BindingFlags.NonPublic)
                ?? throw new InvalidOperationException(
                    "ExecutionRun no longer declares the " + name + " getter this fixture drives.");

            return property.GetValue(_instance);
        }

        private object? Invoke(string name, params object?[] arguments)
        {
            var method = RunType.GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)
                ?? throw new InvalidOperationException(
                    "ExecutionRun no longer declares the " + name + " method this fixture drives.");

            try
            {
                return method.Invoke(_instance, arguments);
            }
            catch (TargetInvocationException error) when (error.InnerException is not null)
            {
                ExceptionDispatchInfo.Capture(error.InnerException).Throw();
                throw;
            }
        }
    }
}
