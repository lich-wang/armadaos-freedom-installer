using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace FreedomInstaller.Core;

public sealed record OfflineUpdateSshOptions(
    string Host,
    int Port,
    string UserName,
    string IdentityFile,
    string KnownHostsFile,
    string? SshExecutable = null,
    string? BindAddress = null);

public sealed class OfflineUpdateSshConnection : IOfflineUpdateConnection
{
    private const int DiagnosticsLimit = 8192;
    private const string RootRemoteCommand = "/usr/bin/python3 -I /usr/libexec/armada/armada-offline-update";
    private const string NonRootRemoteCommand = "/usr/bin/sudo -n -- " + RootRemoteCommand;
    private static readonly TimeSpan GracefulExitWait = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan KillExitWait = TimeSpan.FromSeconds(5);

    private readonly Process _process;
    private readonly OfflineUpdateRpcClient _rpc;
    private readonly CancellationTokenSource _drainCts = new();
    private readonly Task _drainTask;
    private readonly object _diagnosticsLock = new();
    private readonly StringBuilder _diagnosticsTail = new();
    private readonly object _cleanupLock = new();
    private Task? _cleanupTask;

    private OfflineUpdateSshConnection(Process process, OfflineUpdateRpcClient rpc)
    {
        _process = process;
        _rpc = rpc;
        _drainTask = DrainStderrAsync(process, _drainCts.Token, this);
    }

    public OfflineUpdateRpcClient Rpc => _rpc;
    public JsonElement DeviceInfo { get; private set; }

    public string Diagnostics
    {
        get
        {
            lock (_diagnosticsLock)
            {
                return _diagnosticsTail.ToString();
            }
        }
    }

    public static async Task<OfflineUpdateSshConnection> ConnectAsync(
        OfflineUpdateSshOptions options,
        TimeSpan? requestTimeout = null,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        token.ThrowIfCancellationRequested();

        if (requestTimeout is { } t)
        {
            if (t <= TimeSpan.Zero || t == Timeout.InfiniteTimeSpan ||
                t > TimeSpan.FromMilliseconds(uint.MaxValue - 1))
            {
                throw new ArgumentOutOfRangeException(nameof(requestTimeout),
                    "Request timeout must be a positive finite duration supported by CancellationTokenSource.");
            }
        }

        var psi = CreateStartInfo(options);

        var process = new Process { StartInfo = psi };
        var started = false;
        try
        {
            started = process.Start();
            if (!started)
                throw new IOException("Failed to start the OpenSSH client process.");
        }
        catch (Exception ex)
        {
            try
            {
                if (started)
                    await StopAndDisposeProcessAsync(process, isStarted: true).ConfigureAwait(false);
                else
                    process.Dispose();
            }
            catch (Exception cleanupEx)
            {
                throw new IOException(BuildTroubleshootingMessage(new AggregateException(ex, cleanupEx), string.Empty), new AggregateException(ex, cleanupEx));
            }
            throw new IOException("Failed to start the OpenSSH client process. " + ex.Message, ex);
        }

        OfflineUpdateSshConnection? connection = null;
        try
        {
            var rpc = new OfflineUpdateRpcClient(
                process.StandardInput.BaseStream,
                process.StandardOutput.BaseStream,
                requestTimeout,
                leaveOpen: true);
            connection = new OfflineUpdateSshConnection(process, rpc);

            var info = await connection._rpc.GetInfoAsync(token).ConfigureAwait(false);
            connection.DeviceInfo = info.Clone();
            return connection;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            if (connection is not null)
                await connection.DisposeAsync().ConfigureAwait(false);
            else
                await StopAndDisposeProcessAsync(process, isStarted: true).ConfigureAwait(false);
            throw;
        }
        catch (Exception ex)
        {
            Exception? cleanupError = null;
            var tail = string.Empty;
            try
            {
                if (connection is not null)
                    await connection.DisposeAsync().ConfigureAwait(false);
                else
                    await StopAndDisposeProcessAsync(process, isStarted: true).ConfigureAwait(false);
            }
            catch (Exception cEx)
            {
                cleanupError = cEx;
            }
            finally
            {
                if (connection is not null)
                    tail = connection.Diagnostics;
            }

            var finalEx = cleanupError is null ? ex : new AggregateException(ex, cleanupError);
            throw new IOException(BuildTroubleshootingMessage(finalEx, tail), finalEx);
        }
    }

    private static string BuildTroubleshootingMessage(Exception ex, string diagnostics)
    {
        var sb = new StringBuilder();
        sb.Append("Failed to establish the offline update SSH connection: ").Append(ex.Message).AppendLine();
        sb.AppendLine("Troubleshooting:");
        sb.AppendLine("- Verify the host key is already enrolled in the configured known-hosts file; unknown hosts are never accepted automatically.");
        sb.AppendLine("- Verify the identity file is authorized for this user on the device (public key authentication only on this transport).");
        sb.AppendLine("- For non-root users, the remote command uses 'sudo -n' and requires an existing explicit noninteractive sudo authorization on the device.");
        sb.AppendLine("- Verify the fixed offline updater entry (/usr/libexec/armada/armada-offline-update) is present on the device and the protocol version is supported. If it is missing, deploy the offline update components on the tablet first; this connection cannot install them.");
        if (diagnostics.Length > 0)
        {
            sb.AppendLine("OpenSSH diagnostics:").Append(diagnostics);
        }
        return sb.ToString();
    }

    internal static ProcessStartInfo CreateStartInfo(OfflineUpdateSshOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var userName = ValidateUserName(options.UserName);
        var host = ValidateHost(options.Host);
        if (options.Port is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(options), "Port must be between 1 and 65535.");

        var identityPath = ValidateOpenSshPath(options.IdentityFile, nameof(options.IdentityFile));
        var knownHostsPath = ValidateOpenSshPath(options.KnownHostsFile, nameof(options.KnownHostsFile));
        var executable = ResolveExecutable(options.SshExecutable);
        var bindAddress = ValidateBindAddress(options.BindAddress);

        var psi = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(identityPath) ?? ".",
        };

        psi.Environment["SSH_ASKPASS_REQUIRE"] = "never";
        psi.Environment.Remove("SSH_ASKPASS");

        if (bindAddress is not null)
        {
            psi.ArgumentList.Add("-b");
            psi.ArgumentList.Add(bindAddress);
        }

        foreach (var arg in new[]
        {
            "-F", "none",
            "-T", "-a", "-x",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", $"UserKnownHostsFile=\"{EncodeKnownHostsPath(knownHostsPath)}\"",
            "-o", "GlobalKnownHostsFile=none",
            "-o", "UpdateHostKeys=no",
            "-o", "VerifyHostKeyDNS=no",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "PreferredAuthentications=publickey",
            "-o", "IdentitiesOnly=yes",
            "-o", "IdentityAgent=none",
            "-o", "ClearAllForwardings=yes",
            "-o", "ControlMaster=no",
            "-o", "ControlPath=none",
            "-o", "ConnectTimeout=20",
            "-o", "ConnectionAttempts=1",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=2",
            "-i", identityPath,
            "-p", options.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "-l", userName,
            host,
            userName == "root" ? RootRemoteCommand : NonRootRemoteCommand,
        })
        {
            psi.ArgumentList.Add(arg);
        }

        return psi;
    }

    internal static string? ValidateBindAddress(string? bindAddress)
    {
        if (bindAddress is null)
            return null;
        if (bindAddress.IndexOfAny(new[] { ' ', '\t', '\r', '\n' }) >= 0 ||
            !IPAddress.TryParse(bindAddress, out var ip) ||
            ip.AddressFamily != AddressFamily.InterNetwork ||
            !string.Equals(ip.ToString(), bindAddress, StringComparison.Ordinal) ||
            ip.Equals(IPAddress.Any) ||
            ip.Equals(IPAddress.Broadcast) ||
            IPAddress.IsLoopback(ip) ||
            ip.GetAddressBytes()[0] is >= 224 and <= 255)
        {
            throw new ArgumentException(
                "BindAddress must be a canonical IPv4 unicast address in the offline-update USB range 172.16.42.2-172.16.42.254.",
                nameof(bindAddress));
        }
        var bytes = ip.GetAddressBytes();
        if (bytes[0] != 172 || bytes[1] != 16 || bytes[2] != 42 || bytes[3] is < 2 or > 254)
        {
            throw new ArgumentException(
                "BindAddress is restricted to the offline-update USB private subnet range 172.16.42.2-172.16.42.254.",
                nameof(bindAddress));
        }
        return bindAddress;
    }

    private static string ResolveExecutable(string? sshExecutable)
    {
        if (sshExecutable is null)
        {
            if (OperatingSystem.IsMacOS())
            {
                // macOS ships OpenSSH in the sealed system volume.
                const string macPath = "/usr/bin/ssh";
                if (!File.Exists(macPath))
                    throw new IOException($"The macOS OpenSSH client was not found at the expected location ('{macPath}'); supply SshExecutable.");
                return macPath;
            }
            if (!OperatingSystem.IsWindows())
                throw new IOException("No default OpenSSH executable is available on this platform; supply SshExecutable explicitly.");
            var path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "OpenSSH", "ssh.exe");
            if (!File.Exists(path))
                throw new IOException($"The Windows OpenSSH client was not found at the expected location ('{path}'); install the OpenSSH client or supply SshExecutable.");
            return path;
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(sshExecutable);
        if (sshExecutable.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0)
            throw new ArgumentException("SshExecutable must not contain newline or null characters.", nameof(sshExecutable));
        if (!Path.IsPathFullyQualified(sshExecutable))
            throw new ArgumentException("SshExecutable must be a fully qualified path.", nameof(sshExecutable));
        var fullPath = Path.GetFullPath(sshExecutable);
        if (!File.Exists(fullPath) || Directory.Exists(fullPath))
            throw new ArgumentException("SshExecutable must point to an existing file.", nameof(sshExecutable));
        return fullPath;
    }

    internal static string ValidateHost(string host)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        if (host.IndexOfAny(new[] { ' ', '\t', '@', '/', '\n', '\r', '\0', '\'', '\"', '%', '[', ']' }) >= 0 ||
            host.StartsWith('-') ||
            host.Contains("://", StringComparison.Ordinal))
            throw new ArgumentException("Host must be a plain IP address or DNS name without options, whitespace, URI syntax, or shell metacharacters.", nameof(host));

        if (IPAddress.TryParse(host, out var address))
            return address.ToString();

        if (host.Length is < 1 or > 253)
            throw new ArgumentException("Host is not a valid IP address or DNS name.", nameof(host));
        var labels = host.Split('.');
        foreach (var label in labels)
        {
            if (label.Length is < 1 or > 63 || label.StartsWith('-') || label.EndsWith('-') ||
                !label.All(c => c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '-'))
            {
                throw new ArgumentException("Host is not a valid IP address or DNS name.", nameof(host));
            }
        }
        return host.ToLowerInvariant();
    }

    internal static string ValidateUserName(string userName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userName);
        if (!System.Text.RegularExpressions.Regex.IsMatch(userName, @"\A[a-z_][a-z0-9_.-]{0,63}\z"))
            throw new ArgumentException("UserName must match [a-z_][a-z0-9_.-]{0,63}.", nameof(userName));
        return userName;
    }

    private static string ValidateOpenSshPath(string path, string paramName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (path.IndexOfAny(new[] { '\r', '\n', '\0', '\"' }) >= 0 ||
            path.Contains("%", StringComparison.Ordinal) || path.Contains("${", StringComparison.Ordinal))
        {
            throw new ArgumentException($"{paramName} contains characters rejected to prevent OpenSSH configuration token expansion.", paramName);
        }
        if (!Path.IsPathFullyQualified(path))
            throw new ArgumentException($"{paramName} must be a fully qualified path.", paramName);
        var fullPath = Path.GetFullPath(path);
        if (fullPath.IndexOfAny(new[] { '\r', '\n', '\0', '\"' }) >= 0 ||
            fullPath.Contains("%", StringComparison.Ordinal) || fullPath.Contains("${", StringComparison.Ordinal))
        {
            throw new ArgumentException($"{paramName} contains characters rejected to prevent OpenSSH configuration token expansion.", paramName);
        }
        if (!File.Exists(fullPath) || Directory.Exists(fullPath))
            throw new ArgumentException($"{paramName} must point to an existing file.", paramName);
        return fullPath;
    }

    /// <summary>
    /// The known-hosts path as a quoted <c>-o</c> value. OpenSSH splits option values itself and treats a
    /// backslash before a quote, a space or another backslash as an escape. On Windows a backslash is a separator,
    /// so it becomes '/'; elsewhere it is part of a file name, so it is doubled and OpenSSH reads the same file the
    /// caller validated. Quotes are already rejected by <see cref="ValidateOpenSshPath"/>.
    /// </summary>
    internal static string EncodeKnownHostsPath(string path) =>
        OperatingSystem.IsWindows() ? path.Replace('\\', '/') : path.Replace("\\", "\\\\", StringComparison.Ordinal);

    private static async Task DrainStderrAsync(Process process, CancellationToken cancellationToken, OfflineUpdateSshConnection owner)
    {
        var buffer = new char[1024];
        while (true)
        {
            int read;
            try
            {
                read = await process.StandardError.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (cancellationToken.IsCancellationRequested && ex is OperationCanceledException or ObjectDisposedException or IOException)
            {
                break;
            }

            if (read == 0)
                break;

            lock (owner._diagnosticsLock)
            {
                owner._diagnosticsTail.Append(buffer, 0, read);
                if (owner._diagnosticsTail.Length > DiagnosticsLimit)
                    owner._diagnosticsTail.Remove(0, owner._diagnosticsTail.Length - DiagnosticsLimit);
            }
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (_cleanupLock)
        {
            _cleanupTask ??= CleanupAsync();
            return new ValueTask(_cleanupTask);
        }
    }

    private async Task CleanupAsync()
    {
        List<Exception>? errors = null;
        try
        {
            try
            {
                await _rpc.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                (errors ??= new()).Add(ex);
            }

            try
            {
                await StopProcessCoreAsync(_process, isStarted: true).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                (errors ??= new()).Add(ex);
            }

            try
            {
                using var drainTimeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(1));
                try
                {
                    await _drainTask.WaitAsync(drainTimeoutCts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (drainTimeoutCts.IsCancellationRequested)
                {
                }
            }
            catch (Exception ex)
            {
                (errors ??= new()).Add(ex);
            }

            await _drainCts.CancelAsync().ConfigureAwait(false);
            try
            {
                _process.StandardError.Close();
            }
            catch (Exception ex) when (ex is ObjectDisposedException or InvalidOperationException or IOException)
            {
            }

            try
            {
                await _drainTask.ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                (errors ??= new()).Add(ex);
            }
        }
        finally
        {
            _drainCts.Dispose();
            try { _process.StandardOutput.Close(); } catch { }
            try { _process.StandardError.Close(); } catch { }
            _process.Dispose();
        }

        if (errors is { Count: 1 })
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(errors[0]).Throw();
        if (errors is { Count: > 1 })
            throw new AggregateException("One or more errors occurred while cleaning up the offline update SSH connection.", errors);
    }

    private static async Task StopAndDisposeProcessAsync(Process process, bool isStarted)
    {
        try
        {
            await StopProcessCoreAsync(process, isStarted).ConfigureAwait(false);
        }
        finally
        {
            if (isStarted)
            {
                try { process.StandardOutput.Close(); } catch { }
                try { process.StandardError.Close(); } catch { }
            }
            process.Dispose();
        }
    }

    private static async Task StopProcessCoreAsync(Process process, bool isStarted)
    {
        if (!isStarted)
            return;

        List<Exception>? errors = null;
        try
        {
            process.StandardInput.Close();
        }
        catch (Exception ex) when (ex is ObjectDisposedException or InvalidOperationException or IOException)
        {
        }
        catch (Exception ex)
        {
            (errors ??= new()).Add(ex);
        }

        var exited = await WaitForExitBoundedAsync(process, GracefulExitWait).ConfigureAwait(false);
        if (!exited)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException) when (HasProcessExitedSafe(process))
            {
                exited = true;
            }
            catch (Exception ex)
            {
                if (!HasProcessExitedSafe(process))
                    (errors ??= new()).Add(ex);
                else
                    exited = true;
            }

            if (!exited)
            {
                exited = await WaitForExitBoundedAsync(process, KillExitWait).ConfigureAwait(false);
            }
        }

        if (!exited && !HasProcessExitedSafe(process))
        {
            (errors ??= new()).Add(new IOException("The owned OpenSSH client process did not terminate within the allowed cleanup timeout."));
        }

        if (errors is { Count: 1 })
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(errors[0]).Throw();
        if (errors is { Count: > 1 })
            throw new AggregateException(errors);
    }

    private static async Task<bool> WaitForExitBoundedAsync(Process process, TimeSpan timeout)
    {
        if (HasProcessExitedSafe(process))
            return true;
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            await process.WaitForExitAsync(cts.Token).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            return HasProcessExitedSafe(process);
        }
    }

    private static bool HasProcessExitedSafe(Process process)
    {
        try
        {
            return process.HasExited;
        }
        catch (InvalidOperationException)
        {
            return true;
        }
    }
}
