using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Behaviour specifications for live output: <see cref="ProcessCommand.OutputReceived"/> must deliver every
/// complete frame of the real <c>/bin/sh</c> child while it still runs, thread-safely for both streams, and
/// must not change the raw <see cref="ProcessResult"/> capture.
/// <para>
/// Only <c>/bin/sh</c> and <c>/bin/sleep</c> are started: no adb, no fastboot, no device, and only the process
/// a single run started is touched. As with the other runner tests they are allowed only inside the remote
/// Linux container (Linux Docker) and fail loudly elsewhere instead of skipping.
/// </para>
/// </summary>
public sealed class ProcessRunnerStreamingTests
{
    private const string Shell = "/bin/sh";
    private const string SleepBinary = "/bin/sleep";

    /// <summary>Upper bound used where a run may legitimately finish on its own.</summary>
    private static readonly TimeSpan GenerousTimeout = TimeSpan.FromSeconds(10);

    /// <summary>How long a test waits for one live frame before declaring the callback missing.</summary>
    private static readonly TimeSpan EventWait = TimeSpan.FromSeconds(2);

    public ProcessRunnerStreamingTests()
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new InvalidOperationException(
                "ProcessRunnerStreamingTests run /bin/sh and /bin/sleep and are only allowed inside the Linux "
                + "test container (Linux Docker), never on the Windows host.");
        }
    }

    private static ProcessRunner NewRunner() => new();

    private static ProcessCommand Streaming(
        TimeSpan timeout,
        string script,
        Action<ProcessOutputLine>? outputReceived) =>
        new(Shell, new[] { "-c", script }, timeout) { OutputReceived = outputReceived };

    private static TaskCompletionSource<ProcessOutputLine> NewSignal() =>
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Byte-exact reconstruction of one stream from the frames the observer saw.</summary>
    private static string Reconstruct(
        ConcurrentQueue<ProcessOutputLine> lines,
        ProcessOutputStream stream) =>
        string.Concat(
            lines.Where(line => line.Stream == stream).Select(line => line.Text + line.Terminator));

    /// <summary>Frames with real text, i.e. ignoring any empty CR/LF frame an ordinary consumer may skip.</summary>
    private static ProcessOutputLine[] Frames(
        ConcurrentQueue<ProcessOutputLine> lines,
        ProcessOutputStream stream) =>
        lines.Where(line => line.Stream == stream && line.Text.Length > 0).ToArray();

    /// <summary>
    /// Cleanup-only wait for a run the test has already cancelled or stopped asserting on. Every failure is
    /// expected here; the test's own assertions have already decided the outcome.
    /// </summary>
    private static async Task ObserveRunEndAsync(Task run)
    {
        try
        {
            await run.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Cancelled, timed out or faulted: the run has ended either way.
        }
    }

    // ---------- 1 ----------

    /// <summary>
    /// The callback has to fire while the child is alive: a runner that captures with ReadToEnd only can never
    /// produce this event before the 5 second sleep ends.
    /// </summary>
    [Fact]
    public async Task OutputReceived_DeliversCompleteStdoutFrame_BeforeTheProcessExits()
    {
        using var cts = new CancellationTokenSource();
        var firstFrame = NewSignal();
        var observed = new ConcurrentQueue<ProcessOutputLine>();

        var command = Streaming(
            TimeSpan.FromSeconds(30),
            "printf 'ready\\n'; exec " + SleepBinary + " 5",
            line =>
            {
                observed.Enqueue(line);
                if (line.Stream == ProcessOutputStream.Stdout)
                {
                    firstFrame.TrySetResult(line);
                }
            });

        var run = NewRunner().RunAsync(command, cts.Token);
        try
        {
            var frame = await firstFrame.Task.WaitAsync(EventWait);

            Assert.Equal(ProcessOutputStream.Stdout, frame.Stream);
            Assert.Equal("ready", frame.Text);
            Assert.Equal("\n", frame.Terminator);

            // The shell replaced itself with a 5 second sleep, so a frame arriving now proves the observer ran
            // before the process ended rather than on a post-exit buffer.
            Assert.False(run.IsCompleted, "输出回调必须早于进程退出到达，而不是进程结束后一次性补发。");
        }
        finally
        {
            cts.Cancel();
            await ObserveRunEndAsync(run);
        }
    }

    // ---------- 2 ----------

    /// <summary>
    /// A carriage-return progress frame split across writes, a CRLF split between two writes (the CR must be
    /// held until the next character decides it) and an unterminated tail: concatenating Text and Terminator
    /// must give back the exact original text of each stream, while the raw result keeps its own copy.
    /// </summary>
    [Fact]
    public async Task OutputReceived_SplitCrAndCrLf_ReconstructsEachStreamExactly_AndLeavesRawResultIntact()
    {
        const string script =
            "printf 'alpha\\r'; " + SleepBinary + " 0.05; "
            + "printf 'beta\\r'; " + SleepBinary + " 0.05; "
            + "printf '\\n'; " + SleepBinary + " 0.05; "
            + "printf 'tail-without-newline'; " + SleepBinary + " 0.05; "
            + "printf 'warn\\r' >&2; " + SleepBinary + " 0.05; "
            + "printf 'ing\\n' >&2; " + SleepBinary + " 0.05; "
            + "printf 'stderr-tail' >&2";

        var observed = new ConcurrentQueue<ProcessOutputLine>();

        var result = await NewRunner().RunAsync(
            Streaming(GenerousTimeout, script, observed.Enqueue));

        // The result is the original capture, byte for byte: not trimmed, not normalised, not rebuilt.
        Assert.Equal(0, result.ExitCode);
        Assert.Equal("alpha\rbeta\r\ntail-without-newline", result.StandardOutput);
        Assert.Equal("warn\ring\nstderr-tail", result.StandardError);

        // Thread-safe pumps may interleave, so per stream order is what has to hold.
        Assert.Equal(result.StandardOutput, Reconstruct(observed, ProcessOutputStream.Stdout));
        Assert.Equal(result.StandardError, Reconstruct(observed, ProcessOutputStream.Stderr));

        var stdoutFrames = Frames(observed, ProcessOutputStream.Stdout);
        Assert.Equal(
            new[] { "alpha", "beta", "tail-without-newline" },
            stdoutFrames.Select(line => line.Text).ToArray());
        Assert.Equal("\r", stdoutFrames[0].Terminator);
        Assert.Equal("\r\n", stdoutFrames[1].Terminator);
        Assert.Equal(string.Empty, stdoutFrames[2].Terminator);

        var stderrFrames = Frames(observed, ProcessOutputStream.Stderr);
        Assert.Equal(
            new[] { "warn", "ing", "stderr-tail" },
            stderrFrames.Select(line => line.Text).ToArray());
        Assert.Equal("\r", stderrFrames[0].Terminator);
        Assert.Equal("\n", stderrFrames[1].Terminator);
        Assert.Equal(string.Empty, stderrFrames[2].Terminator);
    }

    // ---------- 3 ----------

    /// <summary>
    /// Both streams end without a newline and the child exits normally: the last frame of each stream must be
    /// delivered with an empty Terminator, and the raw result must still own the same exact text.
    /// </summary>
    [Fact]
    public async Task OutputReceived_UnterminatedEofTails_AreDeliveredWithEmptyTerminator_OnBothStreams()
    {
        const string script =
            "printf 'out-complete\\n'; printf 'out-tail'; "
            + "printf 'err-complete\\n' >&2; printf 'err-tail' >&2";

        var observed = new ConcurrentQueue<ProcessOutputLine>();

        var result = await NewRunner().RunAsync(
            Streaming(GenerousTimeout, script, observed.Enqueue));

        Assert.Equal(0, result.ExitCode);
        Assert.Equal("out-complete\nout-tail", result.StandardOutput);
        Assert.Equal("err-complete\nerr-tail", result.StandardError);

        Assert.Equal(result.StandardOutput, Reconstruct(observed, ProcessOutputStream.Stdout));
        Assert.Equal(result.StandardError, Reconstruct(observed, ProcessOutputStream.Stderr));

        Assert.Collection(
            Frames(observed, ProcessOutputStream.Stdout),
            line =>
            {
                Assert.Equal("out-complete", line.Text);
                Assert.Equal("\n", line.Terminator);
            },
            line =>
            {
                Assert.Equal("out-tail", line.Text);
                Assert.Equal(string.Empty, line.Terminator);
            });

        Assert.Collection(
            Frames(observed, ProcessOutputStream.Stderr),
            line =>
            {
                Assert.Equal("err-complete", line.Text);
                Assert.Equal("\n", line.Terminator);
            },
            line =>
            {
                Assert.Equal("err-tail", line.Text);
                Assert.Equal(string.Empty, line.Terminator);
            });
    }

    // ---------- 4 ----------

    /// <summary>
    /// Caller cancellation after a real frame arrives must keep the already observed output, surface
    /// OperationCanceledException with the caller's own token (never a timeout), and stop the callbacks.
    /// </summary>
    [Fact]
    public async Task RunAsync_CancelledAfterObservedFrame_KeepsObservedOutput_AndSurfacesCallerToken()
    {
        using var cts = new CancellationTokenSource();
        var firstFrame = NewSignal();
        var observed = new ConcurrentQueue<ProcessOutputLine>();

        var command = Streaming(
            TimeSpan.FromSeconds(30),
            "printf 'line-one\\n'; printf 'frag'; exec " + SleepBinary + " 5",
            line =>
            {
                observed.Enqueue(line);
                if (line.Text == "line-one")
                {
                    firstFrame.TrySetResult(line);
                }
            });

        var run = NewRunner().RunAsync(command, cts.Token);
        try
        {
            await firstFrame.Task.WaitAsync(EventWait);

            cts.Cancel();

            var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
            Assert.Equal(cts.Token, exception.CancellationToken);

            var countAtTerminal = observed.Count;
            Assert.Contains(
                observed,
                line => line.Stream == ProcessOutputStream.Stdout
                    && line.Text == "line-one"
                    && line.Terminator == "\n");

            // Only complete frames are ever handed out; a partial read is not a frame.
            Assert.All(
                observed,
                line => Assert.True(
                    line.Text == "line-one" || line.Text == "frag",
                    $"unexpected frame text '{line.Text}'."));

            await Task.Delay(TimeSpan.FromMilliseconds(100));
            Assert.Equal(countAtTerminal, observed.Count);
        }
        finally
        {
            cts.Cancel();
            await ObserveRunEndAsync(run);
        }
    }

    // ---------- 5 ----------

    /// <summary>
    /// The command timeout still throws TimeoutException, but a frame the child wrote before it must already
    /// have reached the observer and no later callback may arrive; no truncated ProcessResult is invented.
    /// </summary>
    [Fact]
    public async Task RunAsync_TimedOutAfterObservedFrame_StillThrowsTimeout_AndKeepsObservedOutput()
    {
        var observed = new ConcurrentQueue<ProcessOutputLine>();

        var command = Streaming(
            TimeSpan.FromMilliseconds(400),
            "printf 'frame-before-timeout\\n'; exec " + SleepBinary + " 5",
            observed.Enqueue);

        var run = NewRunner().RunAsync(command);
        try
        {
            var exception = await Assert.ThrowsAsync<TimeoutException>(() => run);
            Assert.False(string.IsNullOrWhiteSpace(exception.Message));

            Assert.Contains(
                observed,
                line => line.Stream == ProcessOutputStream.Stdout
                    && line.Text == "frame-before-timeout"
                    && line.Terminator == "\n");

            var countAtTerminal = observed.Count;
            await Task.Delay(TimeSpan.FromMilliseconds(100));
            Assert.Equal(countAtTerminal, observed.Count);
        }
        finally
        {
            await ObserveRunEndAsync(run);
        }
    }

    // ---------- 6 ----------

    /// <summary>
    /// A throwing observer is a caller bug, not a successful and not a timed-out run: the run stops only its
    /// own child, returns long before the 5 second sleep ends and rethrows that same exception.
    /// </summary>
    [Fact]
    public async Task RunAsync_ObserverThrows_StopsOwnProcess_AndRethrowsThatException()
    {
        var fault = new InvalidOperationException("观察者故意失败");
        var calls = 0;

        var command = Streaming(
            TimeSpan.FromSeconds(2),
            "printf 'fault-frame\\n'; exec " + SleepBinary + " 5",
            _ =>
            {
                Interlocked.Increment(ref calls);
                throw fault;
            });

        var stopwatch = Stopwatch.StartNew();
        var exception = await Record.ExceptionAsync(() => NewRunner().RunAsync(command));
        stopwatch.Stop();

        Assert.NotNull(exception);
        Assert.IsType<InvalidOperationException>(exception);
        Assert.Equal(fault.Message, exception!.Message);

        Assert.True(
            stopwatch.Elapsed < TimeSpan.FromSeconds(3),
            $"a throwing observer must end the run promptly instead of waiting for the 5 second sleep; it took {stopwatch.Elapsed}.");

        var countAtTerminal = Volatile.Read(ref calls);
        await Task.Delay(TimeSpan.FromMilliseconds(100));
        Assert.Equal(countAtTerminal, Volatile.Read(ref calls));
    }
}
