using System;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Threading;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Guard-semantics tests for the cheap admission of <c>ExecuteAsync</c>. They drive the real production static
/// guard through one narrow reflection bridge and touch nothing else: no backend instance, no process, no file
/// and no device. The actual write sequence is not exercised here.
/// </summary>
public sealed class InternalInstallExecutionAdmissionTests
{
    private const string Confirmation =
        "9F1C0B7D2A4E63584B0D9C1E7A2F3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C";

    [Fact]
    public void Matching_confirmation_without_the_erase_flag_is_rejected()
    {
        Assert.Throws<ArgumentException>(
            () => Guard.Invoke(Confirmation, Confirmation, userdataEraseConfirmed: false));
    }

    [Fact]
    public void A_different_confirmation_id_is_rejected()
    {
        Assert.Throws<ArgumentException>(
            () => Guard.Invoke(Confirmation, Confirmation.ToLowerInvariant(), userdataEraseConfirmed: true));
    }

    [Fact]
    public void A_pre_cancelled_token_is_rejected_before_the_confirmation_is_accepted()
    {
        using var source = new CancellationTokenSource();
        source.Cancel();

        Assert.Throws<OperationCanceledException>(
            () => Guard.Invoke(
                Confirmation, Confirmation, userdataEraseConfirmed: true, cancellationToken: source.Token));
    }

    [Fact]
    public void The_exact_confirmation_and_erase_flag_are_accepted()
    {
        Guard.Invoke(Confirmation, Confirmation, userdataEraseConfirmed: true);
    }

    /// <summary>
    /// Resolves only the production static guard, invokes it and surfaces the production exception instead of
    /// a reflection wrapper.
    /// </summary>
    private static class Guard
    {
        private static readonly MethodInfo Method = typeof(InternalInstallBackend).GetMethod(
            "ValidateExecutionConfirmation",
            BindingFlags.Static | BindingFlags.NonPublic,
            binder: null,
            new[] { typeof(string), typeof(string), typeof(bool), typeof(CancellationToken) },
            modifiers: null)
            ?? throw new InvalidOperationException(
                "InternalInstallBackend no longer declares the static ValidateExecutionConfirmation guard.");

        internal static void Invoke(
            string expected,
            string? supplied,
            bool userdataEraseConfirmed,
            CancellationToken cancellationToken = default)
        {
            try
            {
                _ = Method.Invoke(null, new object?[] { expected, supplied, userdataEraseConfirmed, cancellationToken });
            }
            catch (TargetInvocationException error) when (error.InnerException is not null)
            {
                ExceptionDispatchInfo.Capture(error.InnerException).Throw();
                throw;
            }
        }
    }
}
