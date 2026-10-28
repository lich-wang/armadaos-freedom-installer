using System.Diagnostics;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Behaviour tests for <see cref="ProcessRunner"/> against the real POSIX shell and sleep binary.
/// <para>
/// They start <c>/bin/sh</c> and <c>/bin/sleep</c> only: no adb, no fastboot and no device is involved, and
/// no process other than the one a single run started is ever touched. The background child used by the
/// regression test ends on its own, so nothing on the host is killed.
/// </para>
/// <para>
/// Because the tests depend on POSIX binaries they are executed only in the remote Linux container
/// (Linux Docker) and fail loudly instead of silently passing anywhere else.
/// </para>
/// </summary>
public sealed class ProcessRunnerTests
{
    private const string Shell = "/bin/sh";
    private const string SleepBinary = "/bin/sleep";

    /// <summary>Upper bound used where the run itself is expected to finish immediately.</summary>
    private static readonly TimeSpan GenerousTimeout = TimeSpan.FromSeconds(10);

    public ProcessRunnerTests()
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new InvalidOperationException(
                "ProcessRunnerTests run /bin/sh and /bin/sleep and are only allowed inside the Linux test "
                + "container (Linux Docker), never on the Windows host.");
        }
    }

    private static ProcessRunner NewRunner() => new();

    private static ProcessCommand Command(string executable, TimeSpan timeout, params string[] arguments) =>
        new(executable, arguments, timeout);

    // ---------- 1 ----------

    [Fact]
    public async Task RunAsync_ExitZero_CapturesBothStreamsCompletely()
    {
        var command = Command(
            Shell,
            GenerousTimeout,
            "-c",
            "printf 'stdout-first\nstdout-second'; printf 'stderr-first\nstderr-second' >&2");

        var result = await NewRunner().RunAsync(command);

        Assert.Equal(0, result.ExitCode);
        Assert.Equal("stdout-first\nstdout-second", result.StandardOutput);
        Assert.Equal("stderr-first\nstderr-second", result.StandardError);
    }

    // ---------- 2 ----------

    [Fact]
    public async Task RunAsync_PassesEachArgumentAsItsOwnArgvEntry_WithoutShellConcatenation()
    {
        // Every payload below would change meaning if the arguments were joined into a shell command line:
        // the space would split, and "(...)", "*" and ";" would be expanded or start a second command.
        var payloads = new[]
        {
            "first",
            "a b",
            "$(touch should-not-exist)",
            "*",
            "; printf injected",
            "quote\"and'single",
        };

        var arguments = new List<string> { "-c", "printf '%s|' \"$@\"", "sh" };
        arguments.AddRange(payloads);

        var result = await NewRunner().RunAsync(Command(Shell, GenerousTimeout, arguments.ToArray()));

        Assert.Equal(0, result.ExitCode);
        Assert.Equal(string.Concat(payloads.Select(payload => payload + "|")), result.StandardOutput);
        Assert.Equal(string.Empty, result.StandardError);
    }

    // ---------- 3 ----------

    [Fact]
    public async Task RunAsync_NonZeroExit_IsANormalResult_ThatKeepsStandardError()
    {
        var result = await NewRunner().RunAsync(
            Command(Shell, GenerousTimeout, "-c", "printf 'fatal: device offline' >&2; exit 7"));

        Assert.Equal(7, result.ExitCode);
        Assert.Equal("fatal: device offline", result.StandardError);
    }

    // ---------- 4 ----------

    [Fact]
    public async Task RunAsync_MissingExecutable_ThrowsIOException()
    {
        var command = Command("/nonexistent/freedom-installer-missing-binary", GenerousTimeout);

        await Assert.ThrowsAsync<IOException>(() => NewRunner().RunAsync(command));
    }

    // ---------- 5 ----------

    [Fact]
    public async Task RunAsync_PrecancelledToken_ThrowsOperationCanceled_WithoutStartingAnything()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var stopwatch = Stopwatch.StartNew();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => NewRunner().RunAsync(Command(Shell, GenerousTimeout, "-c", "printf 'should-not-run'"), cts.Token));
        stopwatch.Stop();

        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(1), $"precancel returned after {stopwatch.Elapsed}.");
    }

    // ---------- 6 ----------

    [Fact]
    public async Task RunAsync_RunningProcess_ExceedingCommandTimeout_ThrowsTimeoutException()
    {
        var stopwatch = Stopwatch.StartNew();
        var exception = await Assert.ThrowsAsync<TimeoutException>(
            () => NewRunner().RunAsync(Command(SleepBinary, TimeSpan.FromMilliseconds(100), "5")));
        stopwatch.Stop();

        Assert.False(string.IsNullOrWhiteSpace(exception.Message));
        Assert.True(
            stopwatch.Elapsed < TimeSpan.FromSeconds(4),
            $"the run must stop at its own timeout, not after the 5 second sleep; it took {stopwatch.Elapsed}.");
    }

    // ---------- 7 ----------

    [Fact]
    public async Task RunAsync_CallerCancellation_ThrowsOperationCanceled_NotTimeout()
    {
        using var cts = new CancellationTokenSource();
        var run = NewRunner().RunAsync(Command(SleepBinary, TimeSpan.FromSeconds(30), "5"), cts.Token);

        await Task.Delay(TimeSpan.FromMilliseconds(150));
        cts.Cancel();

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
        Assert.Equal(cts.Token, exception.CancellationToken);
    }

    // ---------- 8 ----------

    /// <summary>
    /// Regression: the shell reports a result and exits 0 at once, but the background child it started still
    /// holds the stderr pipe open. A run that returns here would hand back a truncated success, so the whole
    /// capture must stay bounded by the command timeout and surface as a timeout instead.
    /// </summary>
    [Fact]
    public async Task RunAsync_ParentExitsZeroWhileChildHoldsPipeOpen_ThrowsTimeoutException()
    {
        // stdout closes with the parent, stderr stays open because the background child inherits it.
        const string script = "printf 'unlocked: yes'; /bin/sleep 2 >/dev/null &";

        var stopwatch = Stopwatch.StartNew();
        await Assert.ThrowsAsync<TimeoutException>(
            () => NewRunner().RunAsync(Command(Shell, TimeSpan.FromMilliseconds(100), "-c", script)));
        stopwatch.Stop();

        // The background child sleeps 2 seconds and then ends on its own; nothing here kills it or any
        // other process, so the answer has to be bounded by the command timeout alone.
        Assert.True(
            stopwatch.Elapsed < TimeSpan.FromSeconds(1.5),
            $"the run must fail at its own 100 ms timeout instead of waiting for the child; it took {stopwatch.Elapsed}.");
    }
}
