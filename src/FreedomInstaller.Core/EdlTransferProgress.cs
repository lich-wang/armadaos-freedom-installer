using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace FreedomInstaller.Core;

/// <summary>Direction of the validated request being executed; only native frames that match that direction
/// are observed and a frame naming the other direction is ignored.</summary>
public enum EdlTransferDirection
{
    Write,
    Read,
}

/// <summary>
/// Phase of one operation at the moment a progress report is made: the input file is being verified, the
/// native transfer is running, or the captured output is being checked.
/// </summary>
public enum EdlTransferPhase
{
    CheckingInput,
    Transferring,
    CheckingOutput,
}

/// <summary>
/// One approximate, display-only progress observation of a read or write.
/// <para>
/// While <see cref="Phase"/> is <see cref="EdlTransferPhase.Transferring"/>, <see cref="CompletedBytes"/> is
/// derived from the rounded native MiB counter the tool prints (native current MiB multiplied by 1 048 576),
/// so it is an approximation suitable for a progress bar or log only and never a measured byte count.
/// <see cref="EdlTransferPhase.CheckingInput"/> and <see cref="EdlTransferPhase.CheckingOutput"/> reports are
/// the start and end markers of the existing validation itself, not native estimates.
/// </para>
/// <para>
/// <see cref="TotalBytes"/> is the trusted, already validated actual range of the request, never the
/// rounded denominator or the percentage printed in the same native frame. A reported total therefore does
/// not change because the tool rounded 0.99 MiB, 99.99 MiB or 32768.00 MiB.
/// </para>
/// <para>
/// Reaching 100 % is not a final ACK, not a readback and not a SHA-256 proof: success still requires the
/// separately validated command evidence, and any verification this type might seem to imply does not
/// exist here.
/// </para>
/// </summary>
public sealed record EdlTransferProgress(
    EdlTransferDirection Direction,
    EdlTransferPhase Phase,
    long CompletedBytes,
    long TotalBytes);

/// <summary>
/// Operation-scoped observation of exactly one read or write: it renders the native progress frames to an
/// optional caller observer and mirrors every raw stdout/stderr frame into the optional prefixed logs.
/// <para>
/// The observer is display-only. A throwing <see cref="IProgress{T}"/> never fails the device operation,
/// while a failing log write is a real failure and is surfaced to the caller. The only native grammar
/// understood here is the tool's own <c>Writing: 50.0% (0.50 / 99.99 MiB)</c> /
/// <c>Reading:25.0% (0,25 / 99,99 MiB)</c> shape: the percentage and denominator are ignored, and a
/// malformed, opposite-direction or backwards frame changes no reported value.
/// </para>
/// </summary>
internal sealed class EdlOperationObservation : IDisposable
{
    private const long Mebibyte = 1024L * 1024L;

    /// <summary>Shortest delay between two delivered native frames; phase boundaries bypass it.</summary>
    private const int ReportIntervalMilliseconds = 200;

    private static readonly Regex NativeFrame = new(
        @"^\s*(?<direction>Writing|Reading)\s*:\s*(?<percent>[0-9]+(?:[.,][0-9]+)?)\s*%\s*\(\s*" +
        @"(?<current>[0-9]+(?:[.,][0-9]+)?)\s*/\s*(?<total>[0-9]+(?:[.,][0-9]+)?)\s*MiB\s*\)",
        RegexOptions.CultureInvariant);

    private readonly object _gate = new();
    private readonly EdlTransferDirection _direction;
    private readonly long _trustedTotal;
    private readonly IProgress<EdlTransferProgress>? _progress;
    private readonly Stopwatch _clock = Stopwatch.StartNew();

    private StreamWriter? _stdoutLog;
    private StreamWriter? _stderrLog;
    private FileStream? _stdoutStream;
    private FileStream? _stderrStream;
    private Timer? _flushTimer;

    private long _stdoutObservedChars;
    private long _stderrObservedChars;
    private long _lastSeenNativeBytes;
    private long _lastDeliveredBytes;
    private long _lastDeliveredMilliseconds;
    private bool _deliveredNativeFrame;
    private bool _flushedFirstFrame;
    private bool _disposed;
    private Exception? _pendingLogFailure;

    private EdlOperationObservation(
        EdlTransferDirection direction,
        long trustedTotal,
        IProgress<EdlTransferProgress>? progress,
        string? logPrefix)
    {
        _direction = direction;
        _trustedTotal = trustedTotal < 0 ? 0 : trustedTotal;
        _progress = progress;

        if (logPrefix is null)
        {
            return;
        }

        if (!Path.IsPathFullyQualified(logPrefix))
        {
            throw new ArgumentException("A log prefix must be an absolute path.", nameof(logPrefix));
        }

        string? parent = Path.GetDirectoryName(logPrefix);
        if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent))
        {
            throw new IOException(
                $"The log prefix '{logPrefix}' requires an existing explicit parent directory.");
        }

        try
        {
            _stdoutStream = OpenLog(logPrefix + ".stdout.log");
            _stdoutLog = CreateWriter(_stdoutStream);
            _stderrStream = OpenLog(logPrefix + ".stderr.log");
            _stderrLog = CreateWriter(_stderrStream);
        }
        catch
        {
            CloseOwnedStreams();
            throw;
        }

        // Owned, bounded flush so a quiet child still shows its last frame within roughly one interval.
        _flushTimer = new Timer(
            OnFlushTimer,
            null,
            ReportIntervalMilliseconds,
            ReportIntervalMilliseconds);
    }

    /// <summary>
    /// Creates the observation only when there is something to observe; a call without a caller observer and
    /// without a log prefix allocates nothing.
    /// </summary>
    public static EdlOperationObservation? Start(
        EdlTransferDirection direction,
        long trustedTotal,
        IProgress<EdlTransferProgress>? progress,
        string? logPrefix) =>
        progress is null && logPrefix is null
            ? null
            : new EdlOperationObservation(direction, trustedTotal, progress, logPrefix);

    /// <summary>
    /// Live frame callback. Every frame is appended to the logs verbatim, whatever it contains; only a
    /// well-formed stdout frame of the expected direction can become a reported transfer count.
    /// </summary>
    public void Observe(ProcessOutputLine line)
    {
        if (line is null)
        {
            return;
        }

        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            AppendRawFrame(line);

            // The first frame is written through immediately; later frames are buffered and flushed by the
            // bounded timer, Complete or Dispose.
            if (!_flushedFirstFrame)
            {
                _flushedFirstFrame = true;
                _stdoutLog?.Flush();
                _stderrLog?.Flush();
            }

            ThrowPendingLogFailure();

            if (line.Stream != ProcessOutputStream.Stdout)
            {
                return;
            }

            if (!TryReadNativeCounter(line.Text, out long completedBytes))
            {
                return;
            }

            if (completedBytes < _lastSeenNativeBytes)
            {
                return;
            }

            _lastSeenNativeBytes = completedBytes;

            if (_deliveredNativeFrame && completedBytes <= _lastDeliveredBytes)
            {
                return;
            }

            // The first native frame is delivered immediately, even right after a phase boundary reported
            // zero; a new frame that reaches the trusted total is delivered even inside the interval.
            bool first = !_deliveredNativeFrame;
            bool final = completedBytes == _trustedTotal;
            long elapsed = _clock.ElapsedMilliseconds;
            if (!first && !final && elapsed - _lastDeliveredMilliseconds < ReportIntervalMilliseconds)
            {
                return;
            }

            _deliveredNativeFrame = true;
            _lastDeliveredBytes = completedBytes;
            _lastDeliveredMilliseconds = elapsed;
            Report(EdlTransferPhase.Transferring, completedBytes);
        }
    }

    /// <summary>
    /// Reports a phase boundary. Boundaries are never rate limited and always carry a trusted value: zero at
    /// the start of an actual validation and the trusted total at its end.
    /// </summary>
    public void ReportPhase(EdlTransferPhase phase, long completedBytes)
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            long completed = completedBytes < 0 ? 0 : completedBytes;
            if (completed > _trustedTotal)
            {
                completed = _trustedTotal;
            }

            if (phase == EdlTransferPhase.Transferring)
            {
                _lastDeliveredBytes = completed;
                _lastDeliveredMilliseconds = _clock.ElapsedMilliseconds;
            }

            Report(phase, completed);
        }
    }

    /// <summary>
    /// Completes the logs from the captured result: everything already delivered live is never repeated and
    /// the remaining suffix of each stream is appended exactly once. A run without live frames therefore
    /// stores the complete result. The result handed to the validators is never modified.
    /// </summary>
    public void Complete(ProcessResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            AppendRemainder(_stdoutLog, result.StandardOutput, _stdoutObservedChars);
            _stdoutObservedChars = result.StandardOutput.Length > _stdoutObservedChars
                ? result.StandardOutput.Length
                : _stdoutObservedChars;

            AppendRemainder(_stderrLog, result.StandardError, _stderrObservedChars);
            _stderrObservedChars = result.StandardError.Length > _stderrObservedChars
                ? result.StandardError.Length
                : _stderrObservedChars;

            _stdoutLog?.Flush();
            _stderrLog?.Flush();
            ThrowPendingLogFailure();
        }
    }

    /// <summary>Best effort: never throws, so it cannot mask a timeout, cancellation or unknown outcome.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;

            try
            {
                _flushTimer?.Dispose();
            }
            catch
            {
                // Cleanup only.
            }

            _flushTimer = null;

            FlushQuietly(_stdoutLog);
            FlushQuietly(_stderrLog);
            CloseQuietly(_stdoutLog, _stdoutStream);
            CloseQuietly(_stderrLog, _stderrStream);

            _stdoutLog = null;
            _stderrLog = null;
            _stdoutStream = null;
            _stderrStream = null;
        }
    }

    private void OnFlushTimer(object? state)
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            try
            {
                _stdoutLog?.Flush();
                _stderrLog?.Flush();
            }
            catch (Exception exception)
            {
                // Never thrown on the timer thread: recorded and surfaced by Observe/Complete.
                _pendingLogFailure ??= exception;
            }
        }
    }

    private void AppendRawFrame(ProcessOutputLine line)
    {
        bool stdout = line.Stream == ProcessOutputStream.Stdout;
        StreamWriter? writer = stdout ? _stdoutLog : _stderrLog;
        if (writer is null)
        {
            return;
        }

        writer.Write(line.Text);
        writer.Write(line.Terminator);

        if (stdout)
        {
            _stdoutObservedChars += line.Text.Length + line.Terminator.Length;
        }
        else
        {
            _stderrObservedChars += line.Text.Length + line.Terminator.Length;
        }
    }

    private static void AppendRemainder(StreamWriter? writer, string captured, long observedChars)
    {
        if (writer is null || captured.Length <= observedChars)
        {
            return;
        }

        writer.Write(captured.AsSpan((int)observedChars));
    }

    private bool TryReadNativeCounter(string text, out long completedBytes)
    {
        completedBytes = 0;

        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        Match match = NativeFrame.Match(text);
        if (!match.Success)
        {
            return false;
        }

        string expected = _direction == EdlTransferDirection.Write ? "Writing" : "Reading";
        if (!string.Equals(match.Groups["direction"].Value, expected, StringComparison.Ordinal))
        {
            return false;
        }

        if (!TryParseMebibytes(match.Groups["current"].Value, out decimal current))
        {
            return false;
        }

        // Checked before any cast: a huge native counter is clamped against the trusted total and can never
        // overflow into a wrapped or negative value, and it is never derived from the printed percentage.
        if (current > (decimal)long.MaxValue / Mebibyte)
        {
            completedBytes = _trustedTotal;
            return true;
        }

        decimal bytes = current * Mebibyte;
        if (bytes <= 0m)
        {
            completedBytes = 0;
        }
        else if (bytes >= _trustedTotal)
        {
            completedBytes = _trustedTotal;
        }
        else
        {
            completedBytes = (long)bytes;
        }

        return true;
    }

    private static bool TryParseMebibytes(string value, out decimal mebibytes) =>
        decimal.TryParse(
            value.Replace(',', '.'),
            NumberStyles.AllowDecimalPoint,
            CultureInfo.InvariantCulture,
            out mebibytes);

    private void Report(EdlTransferPhase phase, long completedBytes)
    {
        if (_progress is null)
        {
            return;
        }

        try
        {
            _progress.Report(new EdlTransferProgress(_direction, phase, completedBytes, _trustedTotal));
        }
        catch (Exception)
        {
            // The observer is display-only: it can never fail the device operation.
        }
    }

    private void ThrowPendingLogFailure()
    {
        if (_pendingLogFailure is null)
        {
            return;
        }

        throw new IOException("The EDL transfer log could not be written.", _pendingLogFailure);
    }

    private static FileStream OpenLog(string path) =>
        new(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);

    private static StreamWriter CreateWriter(FileStream stream) =>
        new(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), 4096, leaveOpen: true);

    private void CloseOwnedStreams()
    {
        CloseQuietly(_stdoutLog, _stdoutStream);
        CloseQuietly(_stderrLog, _stderrStream);
        _stdoutLog = null;
        _stderrLog = null;
        _stdoutStream = null;
        _stderrStream = null;
    }

    private static void FlushQuietly(StreamWriter? writer)
    {
        try
        {
            writer?.Flush();
        }
        catch
        {
            // Cleanup only.
        }
    }

    private static void CloseQuietly(StreamWriter? writer, FileStream? stream)
    {
        try
        {
            writer?.Dispose();
        }
        catch
        {
            // Cleanup only.
        }

        try
        {
            stream?.Dispose();
        }
        catch
        {
            // Cleanup only.
        }
    }
}
