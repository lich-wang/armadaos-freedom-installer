using System;
using System.Diagnostics;
using System.IO;
using System.IO.Ports;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// Maintenance console for a caller-selected Windows COM port.
/// <para>
/// Uses <see cref="SerialPort"/> with fixed settings (115200 baud, XOnXOff handshake, 16 MiB read
/// buffer, UTF-8 without BOM, LF newline). The port is created and opened only inside
/// <see cref="OpenAsync"/> for the explicit port name given to the constructor; nothing is
/// enumerated, scanned or retried, and no control lines, logins or reboots are performed.
/// </para>
/// <para>
/// Requests are serialised, written as a base64 heredoc that is decoded by <c>busybox base64 -d</c>
/// and executed by <c>busybox sh</c>, and a per-request random start marker precedes the decoded
/// script so terminal echo of the encoded request can never satisfy the caller's expected marker.
/// A marker only matches as a whole output line. Raw TX/RX is never logged and never embedded in
/// exceptions.
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsMaintenanceConsole : IMaintenanceConsole, IAsyncDisposable
{
    private const int SerialBaudRate = 115200;
    private const int SerialReadBufferSize = 16 * 1024 * 1024;
    private const int SerialReadPollMilliseconds = 150;
    private const int SerialWriteTimeoutMilliseconds = 5000;
    private const int ReadChunkBytes = 8192;
    private const int Base64LineLength = 76;
    private const int MaxCapturedCharacters = 16 * 1024 * 1024;

    private const string TimeoutMessage =
        "The device did not emit the expected marker within the requested timeout.";

    private const string TransportFailureMessage =
        "The serial transport failed while communicating with the device.";

    /// <summary>Anchored with \A and \z so trailing newlines or surrounding whitespace can never match.</summary>
    private static readonly Regex PortNamePattern = new(
        @"\ACOM[1-9][0-9]*\z",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly UTF8Encoding Utf8NoBom = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: false);

    /// <summary>
    /// Serialises open/command requests. Intentionally never disposed: disposal would fault any
    /// waiter still queued on it, and an undisposed <see cref="SemaphoreSlim"/> holds no handles.
    /// </summary>
    private readonly SemaphoreSlim _gate = new(1, 1);

    private SerialPort? _port;
    private bool _disposed;

    /// <summary>
    /// Creates the console for an explicitly selected port. Only validates and canonicalises the
    /// name; no serial port is created, opened or scanned here.
    /// </summary>
    /// <param name="portName">A COM port name in the form COM1, COM11, com11, ...</param>
    /// <exception cref="ArgumentException">
    /// <paramref name="portName"/> is null, empty, whitespace-padded, a non-COM name (LPT1), a path,
    /// contains control characters/newlines, or does not match COM[1-9][0-9]*.
    /// </exception>
    public WindowsMaintenanceConsole(string portName)
    {
        if (portName is null)
        {
            throw new ArgumentNullException(nameof(portName));
        }

        if (!PortNamePattern.IsMatch(portName))
        {
            throw new ArgumentException(
                "Port name must be an explicit COM port name such as COM1 or COM11.",
                nameof(portName));
        }

        PortName = portName.ToUpperInvariant();
    }

    /// <summary>Canonical upper-case COM port name (for example COM11).</summary>
    public string PortName { get; }

    /// <summary>True only while the owned serial port is open.</summary>
    public bool IsOpen { get; private set; }

    /// <summary>
    /// Opens the serial transport for <see cref="PortName"/>. The blocking open runs off the caller's
    /// thread; a failed or cancelled open only ever cleans up the port created here.
    /// </summary>
    public async Task OpenAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();

            if (IsOpen)
            {
                return;
            }

            // DtrEnable/RtsEnable stay at their defaults (false): no control-line actions.
            SerialPort port = new(PortName, SerialBaudRate, Parity.None, 8, StopBits.One)
            {
                Handshake = Handshake.XOnXOff,
                ReadBufferSize = SerialReadBufferSize,
                Encoding = Utf8NoBom,
                NewLine = "\n",
                ReadTimeout = SerialReadPollMilliseconds,
                WriteTimeout = SerialWriteTimeoutMilliseconds,
            };

            try
            {
                await Task.Run(() => port.Open()).ConfigureAwait(false);
            }
            catch
            {
                ReleasePort(port);
                throw;
            }

            if (Volatile.Read(ref _disposed) || cancellationToken.IsCancellationRequested)
            {
                ReleasePort(port);
                cancellationToken.ThrowIfCancellationRequested();
                throw new ObjectDisposedException(nameof(WindowsMaintenanceConsole));
            }

            _port = port;
            IsOpen = true;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Runs a trusted fixed script and returns the device output through and including the expected
    /// marker line. The marker must appear as a whole output line and be preceded by this request's
    /// start marker; it is never synthesised on failure.
    /// </summary>
    public async Task<string> RunCommandAsync(
        string script,
        string expectedMarker,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (!IsOpen)
        {
            throw new InvalidOperationException("The maintenance console must be open before running commands.");
        }

        if (script is null)
        {
            throw new ArgumentNullException(nameof(script));
        }

        if (string.IsNullOrWhiteSpace(script))
        {
            throw new ArgumentException("The script must not be blank.", nameof(script));
        }

        if (expectedMarker is null)
        {
            throw new ArgumentNullException(nameof(expectedMarker));
        }

        if (string.IsNullOrWhiteSpace(expectedMarker)
            || expectedMarker.Contains('\r')
            || expectedMarker.Contains('\n'))
        {
            throw new ArgumentException(
                "The expected marker must be a single non-blank line.",
                nameof(expectedMarker));
        }

        if (timeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(timeout),
                timeout,
                "The timeout must be a positive finite duration.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (Volatile.Read(ref _disposed))
            {
                throw new ObjectDisposedException(nameof(WindowsMaintenanceConsole));
            }

            if (!IsOpen || _port is not { } port)
            {
                throw new InvalidOperationException(
                    "The maintenance console must be open before running commands.");
            }

            string startMarker = CreateRandomToken("MBSTART_");
            string request = BuildRequest(script, startMarker);

            return await Task
                .Run(
                    () => ExecuteCommand(port, request, startMarker, expectedMarker, timeout, cancellationToken),
                    CancellationToken.None)
                .ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Releases the owned transport. Safe to call more than once and before the console was ever
    /// opened; a concurrent open or command completes or aborts before the port is closed.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        Volatile.Write(ref _disposed, true);

        SerialPort? owned;
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            owned = _port;
            _port = null;
            IsOpen = false;
        }
        finally
        {
            _gate.Release();
        }

        if (owned is not null)
        {
            ReleasePort(owned);
        }
    }

    /// <summary>
    /// Writes the request and polls for complete lines until the expected marker line arrives.
    /// Runs synchronously inside <see cref="Task.Run(Action)"/>; <see cref="SerialPort.ReadTimeout"/>
    /// provides the wait between polls.
    /// </summary>
    private string ExecuteCommand(
        SerialPort port,
        string request,
        string startMarker,
        string expectedMarker,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        // Cancellation or disposal between gate hand-off and here must not send a request at all.
        cancellationToken.ThrowIfCancellationRequested();

        if (Volatile.Read(ref _disposed))
        {
            throw new ObjectDisposedException(nameof(WindowsMaintenanceConsole));
        }

        byte[] payload = Utf8NoBom.GetBytes(request);

        // Started before the write so the read deadline also covers the write duration.
        Stopwatch elapsed = Stopwatch.StartNew();
        try
        {
            port.Write(payload, 0, payload.Length);
        }
        catch (TimeoutException)
        {
            throw new TimeoutException(TimeoutMessage);
        }
        catch (Exception exception) when (IsTransportFailure(exception))
        {
            throw new IOException(TransportFailureMessage);
        }

        Decoder decoder = Utf8NoBom.GetDecoder();
        byte[] chunk = new byte[ReadChunkBytes];
        char[] characters = new char[Utf8NoBom.GetMaxCharCount(ReadChunkBytes)];
        var line = new StringBuilder(256);
        var output = new StringBuilder();
        bool started = false;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (Volatile.Read(ref _disposed))
            {
                throw new ObjectDisposedException(nameof(WindowsMaintenanceConsole));
            }

            if (elapsed.Elapsed >= timeout)
            {
                throw new TimeoutException(TimeoutMessage);
            }

            int read;
            try
            {
                read = port.Read(chunk, 0, chunk.Length);
            }
            catch (TimeoutException)
            {
                continue;
            }
            catch (Exception exception) when (IsTransportFailure(exception))
            {
                throw new IOException(TransportFailureMessage);
            }

            if (read <= 0)
            {
                continue;
            }

            int produced = decoder.GetChars(chunk, 0, read, characters, 0);
            for (int index = 0; index < produced; index++)
            {
                char current = characters[index];

                if (current == '\n')
                {
                    string text = line.ToString();
                    line.Clear();

                    if (!started)
                    {
                        // Terminal echo, banners and prompts before real execution are ignored.
                        started = text == startMarker;
                        continue;
                    }

                    if (text == expectedMarker)
                    {
                        // The contract is the transcript through and including the marker line, so the
                        // marker is appended as its own LF-terminated line before returning.
                        if (output.Length > 0)
                        {
                            output.Append('\n');
                        }

                        output.Append(expectedMarker).Append('\n');
                        return output.ToString();
                    }

                    if (output.Length > 0)
                    {
                        output.Append('\n');
                    }

                    output.Append(text);

                    if (output.Length > MaxCapturedCharacters)
                    {
                        throw new InvalidDataException(
                            "The device produced more output than the maintenance console captures.");
                    }

                    continue;
                }

                if (current != '\r')
                {
                    line.Append(current);

                    if (line.Length > MaxCapturedCharacters)
                    {
                        throw new InvalidDataException(
                            "The device produced a line longer than the maintenance console captures.");
                    }
                }
            }
        }
    }

    /// <summary>
    /// Builds the single base64 heredoc request: 76-character lines keep every physical line well
    /// below the Linux tty canonical limit, and the random delimiter cannot occur in base64 data.
    /// </summary>
    private static string BuildRequest(string script, string startMarker)
    {
        string decodedScript = "printf '%s\\n' '" + startMarker + "'\n" + script;
        if (!decodedScript.EndsWith('\n'))
        {
            decodedScript += "\n";
        }

        string encoded = Convert.ToBase64String(Utf8NoBom.GetBytes(decodedScript));
        string delimiter = CreateRandomToken("MB004_");

        var builder = new StringBuilder(encoded.Length + (encoded.Length / Base64LineLength) + 128);
        builder.Append("busybox base64 -d <<'").Append(delimiter).Append("' | busybox sh\n");

        for (int offset = 0; offset < encoded.Length; offset += Base64LineLength)
        {
            builder
                .Append(encoded, offset, Math.Min(Base64LineLength, encoded.Length - offset))
                .Append('\n');
        }

        builder.Append(delimiter).Append('\n');
        return builder.ToString();
    }

    private static string CreateRandomToken(string prefix) =>
        prefix + Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

    private static bool IsTransportFailure(Exception exception) =>
        exception is IOException or InvalidOperationException or UnauthorizedAccessException;

    /// <summary>Closes and disposes only a port created by this instance.</summary>
    private static void ReleasePort(SerialPort port)
    {
        try
        {
            port.Dispose();
        }
        catch (IOException)
        {
        }
        catch (InvalidOperationException)
        {
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}
