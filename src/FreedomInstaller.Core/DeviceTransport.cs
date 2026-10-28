using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.ExceptionServices;
using System.Text;

namespace FreedomInstaller.Core;

/// <summary>Which of the two piped streams one <see cref="ProcessOutputLine"/> was read from.</summary>
public enum ProcessOutputStream
{
    Stdout,
    Stderr,
}

/// <summary>
/// One complete frame of live process output, observed before the process reported its exit code.
/// <para>
/// <see cref="Text"/> never contains the delimiter. <see cref="Terminator"/> is the delimiter that actually
/// ended the frame — <c>"\r"</c>, <c>"\n"</c> or <c>"\r\n"</c> — and <see cref="string.Empty"/> for a final
/// frame that ended at end of stream without one. Concatenating <see cref="Text"/> and
/// <see cref="Terminator"/> in delivery order therefore reproduces that stream byte for byte as decoded;
/// this live view is never the source of <see cref="ProcessResult"/>, whose text stays the original capture.
/// </para>
/// </summary>
public sealed record ProcessOutputLine(ProcessOutputStream Stream, string Text, string Terminator);

/// <summary>
/// One external command, expressed as an executable plus an already separated argument vector.
/// <para>
/// The arguments are separated here and must stay separated: no layer below this record may re-join
/// them into a command line, re-quote them or hand them to a shell. A serial such as
/// <c>-s all</c> therefore cannot turn into an option or a second command.
/// </para>
/// <para>
/// <see cref="Timeout"/> is always finite and positive. A device query that hangs must fail with a
/// readable error instead of blocking the installer forever.
/// </para>
/// </summary>
public sealed record ProcessCommand(string Executable, IReadOnlyList<string> Arguments, TimeSpan Timeout)
{
    /// <summary>
    /// Optional per-process working directory. Null or empty keeps the directory the installer inherited;
    /// a non-empty value is copied to <see cref="ProcessStartInfo.WorkingDirectory"/> of the new process
    /// only, so <see cref="Environment.CurrentDirectory"/> of this process is never changed.
    /// </summary>
    public string? WorkingDirectory { get; init; }

    /// <summary>
    /// Optional live observer for this one command's output. When set, every complete frame read from
    /// <see cref="ProcessOutputStream.Stdout"/> or <see cref="ProcessOutputStream.Stderr"/> is handed to it
    /// while the process is still running, without waiting for the exit code.
    /// <para>
    /// Frames of the same stream are delivered in write order; the two streams are pumped independently and
    /// may therefore interleave. The observer must not block the pump for long, and a throwing observer stops
    /// only the process this run started, with its exception surfacing to the caller unchanged. Null keeps
    /// the previous behaviour: capture both streams to the end and return them in <see cref="ProcessResult"/>.
    /// </para>
    /// </summary>
    public Action<ProcessOutputLine>? OutputReceived { get; init; }
}

/// <summary>
/// Complete outcome of one external command: the exit code plus both streams, captured to the end before
/// the result is returned. A non-zero exit code is a normal result; turning it into an error is the
/// caller's decision, so the caller can still read the output of a failed query.
/// </summary>
public sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError);

/// <summary>
/// The only boundary through which the installer may start an external program.
/// <see cref="DeviceTransport"/> depends on this interface instead of starting processes itself, so tests
/// substitute a fake and never launch a real adb or fastboot binary.
/// </summary>
public interface ICommandRunner
{
    /// <summary>
    /// Runs <paramref name="command"/> exactly once and returns its exit code and both streams.
    /// <para>
    /// Implementations must: pass <see cref="ProcessCommand.Arguments"/> as a real argv vector without
    /// shell concatenation; capture standard output and standard error to completion before returning;
    /// stop the process when <see cref="ProcessCommand.Timeout"/> elapses and surface
    /// <see cref="TimeoutException"/>; stop the process when <paramref name="cancellationToken"/> is
    /// cancelled and surface <see cref="OperationCanceledException"/>; and terminate only the process they
    /// started. An executable that cannot be started surfaces <see cref="IOException"/> or
    /// <see cref="InvalidOperationException"/> with a readable diagnostic.
    /// </para>
    /// </summary>
    Task<ProcessResult> RunAsync(ProcessCommand command, CancellationToken cancellationToken = default);
}

/// <summary>
/// Default <see cref="ICommandRunner"/>: starts one real process with an argv vector and captures both
/// streams, the exit code and a finite timeout.
/// <para>
/// One run owns exactly one process. On timeout or cancellation only that process is killed; no process is
/// ever looked up by name, so an adb server or a device session started elsewhere stays untouched.
/// </para>
/// </summary>
public sealed class ProcessRunner : ICommandRunner
{
    /// <summary>
    /// Largest delay the cancellation timer accepts. A longer but still finite request is clamped to this
    /// value instead of being rejected, so the timer can never become infinite.
    /// </summary>
    private static readonly TimeSpan MaxTimerDelay = TimeSpan.FromMilliseconds(int.MaxValue);

    /// <summary>
    /// Upper bound for the cleanup read of a run that was already stopped by its timeout or by the caller.
    /// It is not part of the successful path: there both streams are awaited strictly under the command
    /// timeout alone, so no grace period can turn an incomplete capture into a result.
    /// </summary>
    private static readonly TimeSpan CleanupDrainLimit = TimeSpan.FromMilliseconds(250);

    /// <summary>
    /// Size of the per-stream read buffer used when live output is observed. It is deliberately small so a
    /// frame reaches the observer as soon as the child writes it, and it is only ever a read buffer: the
    /// delimiter that ends a frame is decided by the characters, never by where a read happened to stop.
    /// </summary>
    private const int StreamReadBufferSize = 256;

    /// <inheritdoc />
    public async Task<ProcessResult> RunAsync(ProcessCommand command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        // An infinite or negative timeout would silently disable the only protection against a hanging query.
        if (command.Timeout <= TimeSpan.Zero || command.Timeout == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentException(
                $"命令 {command.Executable} 的超时必须是一个有限的正值，当前为 {command.Timeout}；不接受无限或非正超时。",
                nameof(command));
        }

        if (command.Arguments is null)
        {
            throw new ArgumentException($"命令 {command.Executable} 缺少参数向量。", nameof(command));
        }

        // A call that arrives already cancelled must not launch anything at all.
        cancellationToken.ThrowIfCancellationRequested();

        var startInfo = new ProcessStartInfo
        {
            FileName = command.Executable,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        // Every argument goes in as its own argv entry: nothing is joined, quoted or handed to a shell, so a
        // value such as "-s all" can never turn into a second option or a second command.
        foreach (var argument in command.Arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        // Applied to this one new ProcessStartInfo only: the installer's own current directory is never
        // changed, and an empty value simply keeps the inherited directory.
        if (!string.IsNullOrEmpty(command.WorkingDirectory))
        {
            startInfo.WorkingDirectory = command.WorkingDirectory;
        }

        using var process = new Process { StartInfo = startInfo };

        try
        {
            if (!process.Start())
            {
                throw new IOException($"无法启动可执行文件 {command.Executable}：操作系统没有返回进程句柄。");
            }
        }
        catch (Win32Exception exception)
        {
            // The readable form of "binary missing, not executable or not permitted".
            throw new IOException($"无法启动可执行文件 {command.Executable}：{exception.Message}", exception);
        }
        catch (InvalidOperationException exception)
        {
            throw new InvalidOperationException(
                $"无法启动可执行文件 {command.Executable}：{exception.Message}",
                exception);
        }

        using var timeoutOrCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutOrCancellation.CancelAfter(
            command.Timeout > MaxTimerDelay ? MaxTimerDelay : command.Timeout);

        var token = timeoutOrCancellation.Token;

        // With an observer set the same two pipes are read in small chunks while the process runs, so every
        // complete frame is delivered before the exit code exists. Without one the whole-stream capture below
        // stays exactly as it was.
        if (command.OutputReceived is not null)
        {
            return await RunWithOutputEventsAsync(process, command, command.OutputReceived, token, cancellationToken)
                .ConfigureAwait(false);
        }

        // Both streams are drained concurrently while the process runs, so a chatty child cannot fill one
        // pipe and deadlock the wait below.
        var standardOutputTask = process.StandardOutput.ReadToEndAsync(token);
        var standardErrorTask = process.StandardError.ReadToEndAsync(token);

        string standardOutput;
        string standardError;
        try
        {
            // Exit and both stream reads are awaited strictly together: the run is only a success once the
            // process ended *and* both pipes are closed. A child that keeps a pipe open therefore surfaces as
            // a timeout instead of a truncated "successful" capture, and the single linked token bounds the
            // whole group, so the command timeout covers the reads too. A read failure on the normal path is
            // not swallowed but propagates to the caller.
            await Task.WhenAll(process.WaitForExitAsync(token), standardOutputTask, standardErrorTask)
                .ConfigureAwait(false);

            standardOutput = await standardOutputTask.ConfigureAwait(false);
            standardError = await standardErrorTask.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Only the process this run started is stopped, and only while it is still running.
            StopOwnProcess(process);

            // Cleanup only: the reads were cancelled with the same token, and a broken read here must never
            // replace the timeout or cancellation the caller has to see.
            await Task.WhenAll(
                    BestEffortDrainAsync(standardOutputTask),
                    BestEffortDrainAsync(standardErrorTask))
                .ConfigureAwait(false);

            if (cancellationToken.IsCancellationRequested)
            {
                // The caller cancelled: that is not a timeout, so the two must stay distinguishable.
                throw new OperationCanceledException(
                    $"命令 {command.Executable} 已被取消，已终止本次启动的进程。",
                    cancellationToken);
            }

            throw new TimeoutException(
                $"命令 {command.Executable} 在 {command.Timeout.TotalSeconds:0.###} 秒内没有结束，已终止本次启动的进程。");
        }

        return new ProcessResult(process.ExitCode, standardOutput, standardError);
    }

    /// <summary>
    /// Cleanup-only read of one stream after the run was stopped. The wait stays bounded so cleanup cannot
    /// become a new hang, and every failure is expected here and discarded.
    /// </summary>
    private static async Task BestEffortDrainAsync(Task<string> readTask)
    {
        try
        {
            await readTask.WaitAsync(CleanupDrainLimit).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is OperationCanceledException
            or TimeoutException
            or IOException
            or ObjectDisposedException)
        {
            // Nothing more can be read: the process is gone or its pipe was closed under us.
        }
    }

    /// <summary>
    /// One run with live output: both pipes are pumped concurrently in small chunks, every complete frame is
    /// handed to the observer while the process is still alive, and the raw text is captured independently
    /// from those same chunks so <see cref="ProcessResult"/> never depends on what the observer saw.
    /// <para>
    /// Exit and both end-of-stream reads are still one group under the command timeout, so a child that keeps
    /// a pipe open stays a timeout. An observer or read failure stops only this run's process and cancels the
    /// sibling pump at once, and that first failure is then rethrown unchanged instead of being replaced by a
    /// timeout after the process had to be killed.
    /// </para>
    /// </summary>
    private static async Task<ProcessResult> RunWithOutputEventsAsync(
        Process process,
        ProcessCommand command,
        Action<ProcessOutputLine> outputReceived,
        CancellationToken runToken,
        CancellationToken callerToken)
    {
        // A child token of the run token: cancelling it on a pump failure stops the sibling pump and the exit
        // wait, while caller cancellation and the command timeout keep flowing in from the run token.
        using var pumpCancellation = CancellationTokenSource.CreateLinkedTokenSource(runToken);

        var standardOutput = new StringBuilder();
        var standardError = new StringBuilder();

        var standardOutputPump = PumpStreamAsync(
            process,
            process.StandardOutput,
            ProcessOutputStream.Stdout,
            outputReceived,
            standardOutput,
            pumpCancellation,
            runToken);
        var standardErrorPump = PumpStreamAsync(
            process,
            process.StandardError,
            ProcessOutputStream.Stderr,
            outputReceived,
            standardError,
            pumpCancellation,
            runToken);

        try
        {
            await Task.WhenAll(
                    process.WaitForExitAsync(pumpCancellation.Token),
                    standardOutputPump,
                    standardErrorPump)
                .ConfigureAwait(false);
        }
        catch (Exception failure)
        {
            // Read before this method cancels anything itself, so a caller cancellation stays distinguishable
            // from a timeout and from an observer that threw.
            var runWasCancelled = runToken.IsCancellationRequested;
            var callerCancelled = callerToken.IsCancellationRequested;

            // Only the process this run started is stopped, and only while it is still running.
            CancelQuietly(pumpCancellation);
            StopOwnProcess(process);

            // Bounded cleanup: the pipes close with the process, and a stuck pump must not delay the failure
            // that is about to be rethrown. No callback is started from here.
            await StopPumpsQuietlyAsync(standardOutputPump, standardErrorPump).ConfigureAwait(false);

            var pumpFailure = FirstPumpFailure(standardOutputPump, standardErrorPump);

            // An observer exception, or a stream that failed to read, is rethrown unchanged. It is never
            // reported as a timeout or as a caller cancellation, both of which only describe the run token.
            if (pumpFailure is not null && !(pumpFailure is OperationCanceledException && runWasCancelled))
            {
                Rethrow(pumpFailure);
            }

            if (callerCancelled)
            {
                // The caller cancelled: that is not a timeout, so the two must stay distinguishable.
                throw new OperationCanceledException(
                    $"命令 {command.Executable} 已被取消，已终止本次启动的进程。",
                    callerToken);
            }

            if (runWasCancelled)
            {
                throw new TimeoutException(
                    $"命令 {command.Executable} 在 {command.Timeout.TotalSeconds:0.###} 秒内没有结束，已终止本次启动的进程。");
            }

            throw;
        }

        // Both pumps ended before this point, so no observer can be called after the run returns.
        return new ProcessResult(process.ExitCode, standardOutput.ToString(), standardError.ToString());
    }

    /// <summary>
    /// Reads one stream in small chunks until end of stream, capturing the decoded chunk verbatim and cutting
    /// it into frames. <see cref="ProcessOutputLine.Text"/> excludes the delimiter and
    /// <see cref="ProcessOutputLine.Terminator"/> keeps the real one; a carriage return that ends a chunk is
    /// held until the next character of the same stream decides between CR and CRLF, and a final frame without
    /// a delimiter gets an empty terminator. Frames are delivered in this stream's order only.
    /// </summary>
    private static async Task PumpStreamAsync(
        Process process,
        StreamReader reader,
        ProcessOutputStream stream,
        Action<ProcessOutputLine> outputReceived,
        StringBuilder raw,
        CancellationTokenSource pumpCancellation,
        CancellationToken runToken)
    {
        var token = pumpCancellation.Token;
        var buffer = new char[StreamReadBufferSize];
        var pendingText = new StringBuilder();
        var pendingCarriageReturn = false;

        try
        {
            while (true)
            {
                var read = await reader.ReadAsync(buffer.AsMemory(), token).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                // The chunk exactly as it was decoded, independent of any frame that is cut out of it.
                raw.Append(buffer, 0, read);

                for (var index = 0; index < read; index++)
                {
                    var character = buffer[index];

                    if (pendingCarriageReturn)
                    {
                        pendingCarriageReturn = false;

                        if (character == '\n')
                        {
                            DeliverFrame(stream, pendingText, "\r\n", outputReceived);
                            continue;
                        }

                        DeliverFrame(stream, pendingText, "\r", outputReceived);
                    }

                    if (character == '\r')
                    {
                        pendingCarriageReturn = true;
                    }
                    else if (character == '\n')
                    {
                        DeliverFrame(stream, pendingText, "\n", outputReceived);
                    }
                    else
                    {
                        pendingText.Append(character);
                    }
                }
            }

            // End of stream is part of the protected region: a throwing observer here has to take the same
            // immediate own-process stop as one that throws mid-stream, not wait for the command timeout.
            FlushPendingFragment(stream, pendingText, pendingCarriageReturn, outputReceived);
        }
        catch (OperationCanceledException)
        {
            // The run token was cancelled (caller or timeout), or the sibling pump already failed. Only an
            // externally cancelled run publishes its already observed fragment; a sibling cancellation caused
            // by another observer failure must not produce extra callbacks.
            if (runToken.IsCancellationRequested)
            {
                try
                {
                    // Last observed text of this stream, with no invented unread bytes: a held CR is its own
                    // terminator, remaining text is the final frame at the stop with an empty terminator.
                    FlushPendingFragment(stream, pendingText, pendingCarriageReturn, outputReceived);
                }
                catch
                {
                    // The tail callback failed too: stop this run's own process and the sibling pump through
                    // the existing path, then surface that callback exception unchanged. No retry.
                    StopOwnProcess(process);
                    CancelQuietly(pumpCancellation);
                    throw;
                }
            }

            CancelQuietly(pumpCancellation);
            throw;
        }
        catch
        {
            // A throwing observer or a broken pipe ends this pump now: only this run's own process is stopped,
            // which closes both pipes so the sibling pump cannot keep waiting for the command timeout, and the
            // sibling pump is cancelled at the same time. The failure is rethrown unchanged.
            StopOwnProcess(process);
            CancelQuietly(pumpCancellation);
            throw;
        }
    }

    /// <summary>
    /// Publishes whatever this stream has already observed but not yet delivered: a held carriage return as a
    /// frame of its own and remaining text as a final frame with an empty terminator. Used both at normal end
    /// of stream and once at a stopped run, so a stopped run's observer still sees the last real fragment.
    /// </summary>
    private static void FlushPendingFragment(
        ProcessOutputStream stream,
        StringBuilder text,
        bool pendingCarriageReturn,
        Action<ProcessOutputLine> outputReceived)
    {
        if (pendingCarriageReturn)
        {
            DeliverFrame(stream, text, "\r", outputReceived);
        }

        if (text.Length > 0)
        {
            DeliverFrame(stream, text, string.Empty, outputReceived);
        }
    }

    /// <summary>
    /// Hands one complete frame to the observer. The frame is built before the buffer is cleared, so the
    /// observer always sees the text that belongs to its own terminator.
    /// </summary>
    private static void DeliverFrame(
        ProcessOutputStream stream,
        StringBuilder text,
        string terminator,
        Action<ProcessOutputLine> outputReceived)
    {
        var line = new ProcessOutputLine(stream, text.ToString(), terminator);
        text.Clear();
        outputReceived(line);
    }

    /// <summary>
    /// The failure a pump actually ended with, or null while it is still running or succeeded. A genuine
    /// observer or stream failure always outranks the cancellation it caused in the sibling pump, so the
    /// original exception is never replaced by the token cancellation that follows from it.
    /// </summary>
    private static Exception? FirstPumpFailure(Task first, Task second)
    {
        var firstFailure = first.IsFaulted ? first.Exception!.InnerExceptions[0] : null;
        var secondFailure = second.IsFaulted ? second.Exception!.InnerExceptions[0] : null;

        if (firstFailure is not null && firstFailure is not OperationCanceledException)
        {
            return firstFailure;
        }

        if (secondFailure is not null && secondFailure is not OperationCanceledException)
        {
            return secondFailure;
        }

        return firstFailure ?? secondFailure;
    }

    /// <summary>
    /// Cleanup-only wait for both pumps of a failed run: the wait stays bounded, and every failure here has
    /// already been captured for the caller and is discarded instead of replacing it.
    /// </summary>
    private static async Task StopPumpsQuietlyAsync(params Task[] pumps)
    {
        try
        {
            await Task.WhenAll(pumps).WaitAsync(CleanupDrainLimit).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // The process is gone and its pipes are closed; the captured failure is rethrown by the caller.
        }
    }

    /// <summary>
    /// Cancels the run's own pump token without letting a cancellation callback turn into a new failure that
    /// would hide the one being handled.
    /// </summary>
    private static void CancelQuietly(CancellationTokenSource cancellation)
    {
        try
        {
            cancellation.Cancel();
        }
        catch (Exception exception) when (exception is AggregateException or ObjectDisposedException)
        {
            // A callback on the token failed or the source is already gone: the token is cancelled either way.
        }
    }

    /// <summary>Rethrows an already captured exception with its original stack instead of wrapping it.</summary>
    [DoesNotReturn]
    private static void Rethrow(Exception failure) => ExceptionDispatchInfo.Capture(failure).Throw();

    /// <summary>
    /// Terminates only the process this call started, and only while it is still running. No process is ever
    /// looked up by name or enumerated, so an unrelated adb server, device session or fastboot client is
    /// never stopped by this installer.
    /// </summary>
    private static void StopOwnProcess(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: false);
            }
        }
        catch (InvalidOperationException)
        {
            // Exited between the check and the kill.
        }
        catch (Win32Exception)
        {
            // Already gone or not permitted: there is nothing left to stop, and guessing is not allowed.
        }
        catch (NotSupportedException)
        {
            // The platform refused the kill; the process is left alone rather than replaced by a name lookup.
        }
    }
}

/// <summary>
/// Query-only transport for one already known device serial: it lists adb devices, reads the adb identity
/// and verifies the fastboot lock state.
/// <para>
/// Scope: read only. This class contains no reboot, unlock, flash, format or erase operation, so no write
/// path is reachable through the transport, and <see cref="CheckFastbootAsync"/> explicitly does not
/// reboot the device when it is done.
/// </para>
/// <para>
/// Every external command goes through <see cref="ICommandRunner"/>. The exact command lines are part of
/// this contract, so an implementation may not add, drop or reorder arguments.
/// </para>
/// </summary>
public sealed class DeviceTransport
{
    /// <summary>adb executable used for <c>devices -l</c> and <c>shell getprop</c>.</summary>
    public string AdbPath { get; }

    /// <summary>fastboot executable used for <c>getvar unlocked</c> and the <c>oem device-info</c> fallback.</summary>
    public string FastbootPath { get; }

    /// <summary>Process boundary. Tests pass a fake, so no real binary is started.</summary>
    internal ICommandRunner Runner { get; }

    /// <summary>
    /// The fixed, finite timeout every device query carries. A hung adb or fastboot session must fail with a
    /// readable error instead of blocking the installer forever.
    /// </summary>
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Creates the transport. The two binary paths and the runner are required; an empty path would make
    /// every later query fail with an unrelated error, so it is rejected here.
    /// </summary>
    public DeviceTransport(string adbPath, string fastbootPath, ICommandRunner runner)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(adbPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(fastbootPath);
        ArgumentNullException.ThrowIfNull(runner);

        AdbPath = adbPath;
        FastbootPath = fastbootPath;
        Runner = runner;
    }

    /// <summary>
    /// Lists the devices adb currently sees, by running exactly <c>[adbPath, "devices", "-l"]</c>.
    /// <para>
    /// Output is parsed with <see cref="DeviceProbe.ParseAdbDevices"/>: the "List of devices attached"
    /// header, blank lines and daemon chatter are skipped, "device" maps to
    /// <see cref="ConnectionState.Authorized"/>, "unauthorized" to
    /// <see cref="ConnectionState.Unauthorized"/> and every other state to
    /// <see cref="ConnectionState.Offline"/>, so unauthorized stays distinguishable from offline.
    /// </para>
    /// <para>
    /// A non-zero exit code throws <see cref="InvalidOperationException"/> whose message names the adb
    /// executable, the exit code and the captured adb error text, so the user sees a readable diagnostic
    /// instead of an empty list. Cancellation surfaces as <see cref="OperationCanceledException"/>.
    /// </para>
    /// </summary>
    public async Task<IReadOnlyList<ConnectedDevice>> ListDevicesAsync(CancellationToken cancellationToken = default)
    {
        var result = await Runner
            .RunAsync(new ProcessCommand(AdbPath, new[] { "devices", "-l" }, QueryTimeout), cancellationToken)
            .ConfigureAwait(false);

        if (result.ExitCode != 0)
        {
            // A failed listing must never look like "zero devices attached".
            throw new InvalidOperationException(
                $"adb 设备列表读取失败（{AdbPath} devices -l，退出码 {result.ExitCode}）：{DescribeDiagnostic(result)}");
        }

        return DeviceProbe.ParseAdbDevices(result.StandardOutput);
    }

    /// <summary>
    /// Reads the adb identity of <paramref name="serial"/> by running exactly
    /// <c>[adbPath, "-s", serial, "shell", "getprop"]</c>.
    /// <para>
    /// A blank or empty serial is rejected with <see cref="ArgumentException"/> before any process starts,
    /// because an empty <c>-s</c> value would target whatever adb happens to pick.
    /// </para>
    /// <para>
    /// The model must be exactly one of the supported models, as decided by
    /// <see cref="DeviceProbe.IdentifyModel"/>. A missing model, an unsupported model and two contradictory
    /// model properties all throw <see cref="InvalidOperationException"/>; a non-zero adb exit code throws
    /// the same type with the captured diagnostic.
    /// </para>
    /// <para>
    /// The same getprop dump that named the model also fills
    /// <see cref="DeviceIdentity.Firmware"/> through <see cref="FirmwareProbe.Parse"/>, so the build identity
    /// and the Android-reported lock state come from one query instead of a second one.
    /// </para>
    /// <para>
    /// The returned <see cref="DeviceIdentity.BootloaderState"/> is always
    /// <see cref="BootloaderState.Unknown"/>: getprop runs inside Android and says nothing about whether
    /// fastboot will accept writes, so it is not final verification. Only <see cref="CheckFastbootAsync"/>
    /// may report <see cref="BootloaderState.Locked"/> or <see cref="BootloaderState.Unlocked"/>, and the
    /// readiness gate therefore cannot be satisfied by adb properties alone. In particular,
    /// <see cref="FirmwareSnapshot.AndroidReportedBootloaderState"/> saying "unlocked" changes nothing here.
    /// </para>
    /// </summary>
    public async Task<DeviceIdentity> ReadAdbIdentityAsync(string serial, CancellationToken cancellationToken = default)
    {
        // Rejected before any process exists: an empty -s value would target whichever device adb picks.
        ArgumentException.ThrowIfNullOrWhiteSpace(serial);

        var result = await Runner
            .RunAsync(
                new ProcessCommand(AdbPath, new[] { "-s", serial, "shell", "getprop" }, QueryTimeout),
                cancellationToken)
            .ConfigureAwait(false);

        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"读取设备 {serial} 的 adb 属性失败（{AdbPath}，退出码 {result.ExitCode}）：{DescribeDiagnostic(result)}");
        }

        var model = DeviceProbe.IdentifyModel(result.StandardOutput);
        if (model is null)
        {
            // Missing model, unsupported model and two contradictory model properties all land here.
            throw new InvalidOperationException(
                $"无法从设备 {serial} 的 getprop 输出确认受支持的型号（只接受 TB322FC / TB323FU），拒绝继续。");
        }

        // getprop runs inside Android, so it says nothing about fastboot accepting writes: always Unknown.
        // The firmware snapshot comes from this very dump; a second query would be an unrelated command.
        return new DeviceIdentity(serial, model, BootloaderState.Unknown)
        {
            Firmware = FirmwareProbe.Parse(result.StandardOutput),
        };
    }

    /// <summary>
    /// Verifies the bootloader lock state of <paramref name="identity"/> in fastboot mode.
    /// <para>
    /// Primary query is exactly <c>[fastbootPath, "-s", identity.Serial, "getvar", "unlocked"]</c>. Its
    /// standard output and standard error are combined and parsed with
    /// <see cref="DeviceProbe.ParseBootloaderState"/> only when the exit code is 0, so a conflicting pair of
    /// reports yields <see cref="BootloaderState.Unknown"/> instead of an optimistic "unlocked".
    /// </para>
    /// <para>
    /// When the primary query exits non-zero (this bootloader does not know the variable), one fallback
    /// query <c>[fastbootPath, "-s", identity.Serial, "oem", "device-info"]</c> is issued and parsed the same
    /// way. A non-zero exit is not a failure by itself: it is simply no evidence.
    /// </para>
    /// <para>
    /// If neither query produced a parseable report with exit code 0, the result is
    /// <see cref="BootloaderState.Unknown"/> and no exception is thrown, because an unsupported query is an
    /// expected property of some bootloaders. Output printed by a failing query is never trusted, so a
    /// non-zero exit that still prints "unlocked: yes" cannot unlock the gate. A null identity throws
    /// <see cref="ArgumentNullException"/> and a blank serial <see cref="ArgumentException"/>.
    /// </para>
    /// <para>
    /// The returned identity keeps the caller's <see cref="DeviceIdentity.Serial"/> and
    /// <see cref="DeviceIdentity.Model"/> unchanged: fastboot chatter can never rewrite the confirmed
    /// identity, and a product value that does not match the confirmed model is ignored rather than adopted.
    /// The caller's <see cref="DeviceIdentity.Firmware"/> snapshot is preserved unchanged on every result,
    /// including the Unknown one, because the record-with update below replaces only the lock state. The
    /// device is left in fastboot; this method never reboots it.
    /// </para>
    /// </summary>
    public async Task<DeviceIdentity> CheckFastbootAsync(DeviceIdentity identity, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(identity);

        // Only an already confirmed identity may be queried: a blank serial would let fastboot pick a device,
        // and an unsupported model means the identity was never confirmed in the first place.
        if (string.IsNullOrWhiteSpace(identity.Serial))
        {
            throw new ArgumentException("已确认的设备身份缺少序列号，无法定向查询引导状态。", nameof(identity));
        }

        if (!DeviceProbe.IsSupportedModel(identity.Model))
        {
            throw new ArgumentException(
                $"已确认的设备身份型号「{identity.Model}」不在支持列表（TB322FC / TB323FU）内，拒绝查询引导状态。",
                nameof(identity));
        }

        var serial = identity.Serial;

        var primary = await Runner
            .RunAsync(
                new ProcessCommand(FastbootPath, new[] { "-s", serial, "getvar", "unlocked" }, QueryTimeout),
                cancellationToken)
            .ConfigureAwait(false);

        BootloaderState state;
        if (primary.ExitCode == 0)
        {
            // Only an exit-0 report is evidence, so output printed by a failing query can never unlock.
            state = CombineAndParse(primary);
        }
        else
        {
            // This bootloader does not know the variable: exactly one fallback query, parsed the same way.
            var fallback = await Runner
                .RunAsync(
                    new ProcessCommand(FastbootPath, new[] { "-s", serial, "oem", "device-info" }, QueryTimeout),
                    cancellationToken)
                .ConfigureAwait(false);

            state = fallback.ExitCode == 0 ? CombineAndParse(fallback) : BootloaderState.Unknown;
        }

        // Only the lock state may change: fastboot chatter never rewrites the confirmed serial or model, the
        // firmware snapshot rides along unchanged through the record-with copy, and the device is left in
        // fastboot because nothing here reboots it.
        return identity with { BootloaderState = state };
    }

    /// <summary>
    /// fastboot prints its reports to either stream depending on version, so both are combined before
    /// parsing; <see cref="DeviceProbe.ParseBootloaderState"/> reports Unknown when the two contradict.
    /// </summary>
    private static BootloaderState CombineAndParse(ProcessResult result) =>
        DeviceProbe.ParseBootloaderState($"{result.StandardOutput}\n{result.StandardError}");

    /// <summary>The captured error text if there is any, otherwise whatever the tool printed.</summary>
    private static string DescribeDiagnostic(ProcessResult result)
    {
        var error = result.StandardError.Trim();
        if (error.Length > 0)
        {
            return error;
        }

        var output = result.StandardOutput.Trim();
        return output.Length > 0 ? output : "（命令没有输出任何诊断信息）";
    }
}
