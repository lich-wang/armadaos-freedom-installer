using System.Diagnostics;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Text.Json;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class OfflineUpdateSshConnectionTests : IDisposable
{
    private readonly string _directory;
    private readonly string _identity;
    private readonly string _knownHosts;
    private readonly string _dummyExecutable;
    private readonly string? _script;

    public OfflineUpdateSshConnectionTests()
    {
        var root = Environment.GetEnvironmentVariable("TEST_ARTIFACT_ROOT");
        if (string.IsNullOrWhiteSpace(root))
            throw new InvalidOperationException("TEST_ARTIFACT_ROOT must be set.");
        _directory = Path.Combine(root, $"U323 {Guid.NewGuid():N} café's fixture");
        Directory.CreateDirectory(_directory);
        _identity = Path.Combine(_directory, "identity fixture.txt");
        _knownHosts = Path.Combine(_directory, "known hosts fixture.txt");
        _dummyExecutable = Path.Combine(_directory, "dummy ssh.exe");
        File.WriteAllText(_identity, "harmless identity fixture text\n", new UTF8Encoding(false));
        File.WriteAllText(_knownHosts, "harmless known-hosts fixture text\n", new UTF8Encoding(false));
        File.WriteAllText(_dummyExecutable, "not an executable; validation fixture only\n", new UTF8Encoding(false));
        if (OperatingSystem.IsLinux() && File.Exists("/usr/bin/python3"))
        {
            _script = Path.Combine(_directory, "fake ssh fixture.py");
            File.WriteAllText(_script, Script, new UTF8Encoding(false));
            File.SetUnixFileMode(_script, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    private OfflineUpdateSshOptions Options(string host = "device.example", string user = "root", string? executable = null) =>
        new(host, 2222, user, _identity, _knownHosts, executable ?? _dummyExecutable);

    private OfflineUpdateSshOptions FakeOptions(string host) => Options(host, executable: _script);

    private static ProcessStartInfo StartInfo(OfflineUpdateSshOptions options)
    {
        try
        {
            var method = typeof(OfflineUpdateSshConnection).GetMethod(
                "CreateStartInfo", BindingFlags.NonPublic | BindingFlags.Static);
            Assert.NotNull(method);
            return Assert.IsType<ProcessStartInfo>(method.Invoke(null, new object[] { options }));
        }
        catch (TargetInvocationException ex) when (ex.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
            throw;
        }
    }

    [Theory]
    [InlineData("root", "/usr/bin/python3 -I /usr/libexec/armada/armada-offline-update")]
    [InlineData("other-user", "/usr/bin/sudo -n -- /usr/bin/python3 -I /usr/libexec/armada/armada-offline-update")]
    public void StartInfo_UsesSafeFixedCommand(string user, string command)
    {
        var psi = StartInfo(Options(user: user));
        var args = psi.ArgumentList;
        Assert.Equal(command, args[^1]);
        Assert.Contains("device.example", args);
        Assert.Equal("-F", args[0]);
        Assert.Equal("none", args[1]);
        Assert.Contains("BatchMode=yes", args);
        Assert.Contains("StrictHostKeyChecking=yes", args);
        Assert.Contains("ClearAllForwardings=yes", args);
        Assert.DoesNotContain(args, a => a.Contains("StrictHostKeyChecking=no", StringComparison.Ordinal));
        Assert.DoesNotContain(args, a => a.Contains("UserKnownHostsFile=/dev/null", StringComparison.Ordinal));
        Assert.DoesNotContain(args, a => a.Contains("Forward", StringComparison.Ordinal) && a.Contains("yes", StringComparison.Ordinal) && a != "ClearAllForwardings=yes");
        var keyIndex = args.IndexOf("-i");
        Assert.True(keyIndex >= 0);
        Assert.Equal(_identity, args[keyIndex + 1]);
        Assert.DoesNotContain(args, a => a.Contains("harmless identity", StringComparison.Ordinal));
    }

    [Fact]
    public void StartInfo_BindAddressPrecedesDestinationAndPreservesSafety()
    {
        var psi = StartInfo(Options() with { BindAddress = "172.16.42.2" });
        var args = psi.ArgumentList;
        var bind = args.IndexOf("-b");
        Assert.True(bind >= 0);
        Assert.Equal("172.16.42.2", args[bind + 1]);
        Assert.True(bind + 1 < args.IndexOf("device.example"));
        Assert.Equal("/usr/bin/python3 -I /usr/libexec/armada/armada-offline-update", args[^1]);
        Assert.Contains("StrictHostKeyChecking=yes", args);
    }

    [Fact]
    public void StartInfo_WithoutBindAddressHasNoBindOption()
    {
        var args = StartInfo(Options()).ArgumentList;
        Assert.Equal("-F", args[0]);
        Assert.DoesNotContain("-b", args);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("192.168.1.2")]
    [InlineData("172.16.42.2 -oProxyCommand=x")]
    [InlineData("172.16.42.2\n")]
    public void StartInfo_RejectsInvalidBindAddress(string bindAddress)
    {
        Assert.Throws<ArgumentException>(() => StartInfo(Options() with { BindAddress = bindAddress }));
    }

    [Fact]
    public void StartInfo_AcceptsLiteralIPv6AndQuotedSpecialPaths()
    {
        var psi = StartInfo(Options("2001:0db8:0:0:0:0:0:1"));
        Assert.Contains("2001:db8::1", psi.ArgumentList);
        var option = Assert.Single(psi.ArgumentList, a => a.StartsWith("UserKnownHostsFile=", StringComparison.Ordinal));
        Assert.Equal($"UserKnownHostsFile=\"{OfflineUpdateSshConnection.EncodeKnownHostsPath(_knownHosts)}\"", option);
        Assert.Equal(_directory, psi.WorkingDirectory);
    }

    [Fact]
    public void StartInfo_KeepsALiteralBackslashInAUnixKnownHostsFileName()
    {
        if (OperatingSystem.IsWindows())
        {
            Assert.Equal("C:/Users/a/known_hosts", OfflineUpdateSshConnection.EncodeKnownHostsPath(@"C:\Users\a\known_hosts"));
            return;
        }

        // On macOS and Linux "tablet\lab" is one file name: OpenSSH must read that file, not "tablet/lab".
        var knownHosts = Path.Combine(_directory, @"tablet\lab");
        File.WriteAllText(knownHosts, "harmless known-hosts fixture text\n", new UTF8Encoding(false));
        var psi = StartInfo(Options() with { KnownHostsFile = knownHosts });

        var option = Assert.Single(psi.ArgumentList, a => a.StartsWith("UserKnownHostsFile=", StringComparison.Ordinal));
        Assert.Equal($"UserKnownHostsFile=\"{knownHosts.Replace(@"\", @"\\", StringComparison.Ordinal)}\"", option);
        Assert.DoesNotContain("tablet/lab", option, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65536)]
    public void StartInfo_RejectsInvalidPort(int port)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => StartInfo(Options() with { Port = port }));
    }

    [Theory]
    [InlineData("-oProxyCommand=x")]
    [InlineData("host/path")]
    [InlineData("user@host")]
    [InlineData("host name")]
    [InlineData("https://host")]
    [InlineData("host'x")]
    [InlineData("[2001:db8::1]")]
    [InlineData("host%token")]
    public void StartInfo_RejectsUnsafeHosts(string host)
    {
        Assert.Throws<ArgumentException>(() => StartInfo(Options(host)));
    }

    [Fact]
    public void StartInfo_RejectsInvalidUserAndPaths()
    {
        Assert.Throws<ArgumentException>(() => StartInfo(Options(user: "root\n")));
        Assert.Throws<ArgumentException>(() => StartInfo(Options() with { IdentityFile = "relative-key" }));
        Assert.Throws<ArgumentException>(() => StartInfo(Options() with { KnownHostsFile = Path.Combine(_directory, "missing") }));
        Assert.Throws<ArgumentException>(() => StartInfo(Options() with { IdentityFile = _directory }));
        Assert.Throws<ArgumentException>(() => StartInfo(Options() with { KnownHostsFile = _knownHosts + "%d" }));
        Assert.Throws<ArgumentException>(() => StartInfo(Options() with { IdentityFile = _identity + "${TOKEN}" }));
        Assert.Throws<ArgumentException>(() => StartInfo(Options(executable: "relative-ssh")));
        Assert.Throws<ArgumentException>(() => StartInfo(Options(executable: Path.Combine(_directory, "absent-ssh"))));
    }

    [LinuxFact]
    public async Task ValidationAndPrecancellation_DoNotSpawn()
    {
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            OfflineUpdateSshConnection.ConnectAsync(FakeOptions("stall"), TimeSpan.Zero));
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            OfflineUpdateSshConnection.ConnectAsync(FakeOptions("stall"), token: cts.Token));
        Assert.False(File.Exists(PidPath));
    }

    [LinuxFact]
    public async Task Success_ProbesInfoAndSupportsStatusThenCleanExit()
    {
        var connection = await OfflineUpdateSshConnection.ConnectAsync(FakeOptions("success"));
        try
        {
            Assert.Equal("TB323FU", connection.DeviceInfo.GetProperty("model").GetString());
            await connection.Rpc.GetStatusAsync("0123456789abcdef0123456789abcdef");
        }
        finally
        {
            await connection.DisposeAsync();
        }
        await AssertOwnedProcessExited();
        var methods = await WaitForMethods(2);
        Assert.Equal(new[] { "info", "status" }, methods);
        Assert.DoesNotContain(methods, m => m.Contains("transfer", StringComparison.OrdinalIgnoreCase) || m.Contains("reboot", StringComparison.OrdinalIgnoreCase));
        using var argv = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(_directory, "argv.json")));
        var args = argv.RootElement.EnumerateArray().Select(a => a.GetString()).ToArray();
        Assert.Equal("/usr/bin/python3 -I /usr/libexec/armada/armada-offline-update", args[^1]);
        Assert.Contains("success", args);
        var keyIndex = Array.IndexOf(args, "-i");
        Assert.True(keyIndex >= 0);
        Assert.Equal(_identity, args[keyIndex + 1]);
        Assert.Equal(1, File.ReadAllLines(StartsPath).Length);
    }

    [LinuxFact]
    public async Task KnownHostFailure_HasDiagnosticsAndOneExitedProcess()
    {
        var ex = await Assert.ThrowsAsync<IOException>(() =>
            OfflineUpdateSshConnection.ConnectAsync(FakeOptions("error")));
        Assert.Contains("known host fixture failure", ex.Message, StringComparison.Ordinal);
        Assert.Contains("host key", ex.Message, StringComparison.OrdinalIgnoreCase);
        await AssertOwnedProcessExited();
        Assert.False(File.Exists(MethodsPath));
    }

    [LinuxFact]
    public async Task BrokenFrame_FailsWithoutRetryAndProcessExits()
    {
        var ex = await Assert.ThrowsAsync<IOException>(() =>
            OfflineUpdateSshConnection.ConnectAsync(FakeOptions("broken")));
        Assert.Contains("offline update SSH", ex.Message, StringComparison.OrdinalIgnoreCase);
        await AssertOwnedProcessExited();
        var methods = await WaitForMethods(1);
        Assert.Equal("info", Assert.Single(methods));
        Assert.Equal(1, File.ReadAllLines(StartsPath).Length);
    }

    [LinuxFact]
    public async Task Stall_RequestTimeoutAndExplicitCancelCleanUpProcess()
    {
        var timeout = await Assert.ThrowsAsync<IOException>(() =>
            OfflineUpdateSshConnection.ConnectAsync(FakeOptions("stall"), TimeSpan.FromSeconds(1)));
        Assert.Contains("offline update SSH", timeout.Message, StringComparison.OrdinalIgnoreCase);
        await AssertOwnedProcessExited();
        File.Delete(PidPath);
        File.Delete(MethodsPath);

        using var cts = new CancellationTokenSource();
        var pending = OfflineUpdateSshConnection.ConnectAsync(FakeOptions("stall"), token: cts.Token);
        await WaitForFile(PidPath);
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
        await AssertOwnedProcessExited();
    }

    [LinuxFact]
    public async Task LargeStderr_IsBoundedAndDoesNotDeadlockConnect()
    {
        var connection = await OfflineUpdateSshConnection.ConnectAsync(FakeOptions("stderr"));
        try
        {
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
            while (!connection.Diagnostics.Contains("TAILMARKER", StringComparison.Ordinal))
            {
                if (DateTime.UtcNow >= deadline)
                    Assert.Fail("Timed out waiting for TAILMARKER in diagnostics.");
                await Task.Delay(50);
            }
            Assert.True(connection.Diagnostics.Length <= 8192);
            Assert.DoesNotContain("STARTMARKER", connection.Diagnostics, StringComparison.Ordinal);
        }
        finally
        {
            await connection.DisposeAsync();
        }
        await AssertOwnedProcessExited();
    }

    [Fact]
    public async Task MissingExecutable_ConnectRejectedWithoutProcessStart()
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            OfflineUpdateSshConnection.ConnectAsync(Options(executable: Path.Combine(_directory, "absent-ssh"))));
        Assert.False(File.Exists(PidPath));
        Assert.False(File.Exists(StartsPath));
    }

    [LinuxFact]
    public async Task StubbornProcess_ConcurrentDisposalKillsAndRpcRejects()
    {
        var connection = await OfflineUpdateSshConnection.ConnectAsync(FakeOptions("stubborn"));
        try
        {
            var disposals = Enumerable.Range(0, 4).Select(_ => connection.DisposeAsync().AsTask()).ToArray();
            await Task.WhenAll(disposals).WaitAsync(TimeSpan.FromSeconds(12));
            await AssertOwnedProcessExited();
            await Assert.ThrowsAsync<ObjectDisposedException>(() => connection.Rpc.GetInfoAsync());
        }
        finally
        {
            await connection.DisposeAsync();
        }
    }

    private string PidPath => Path.Combine(_directory, "pid.txt");
    private string StartsPath => Path.Combine(_directory, "starts.log");

    private bool OwnsPid(int pid)
    {
        if (_script is null || !File.Exists($"/proc/{pid}/cmdline"))
            return false;

        try
        {
            return File.ReadAllText($"/proc/{pid}/cmdline")
                .Split('\0', StringSplitOptions.RemoveEmptyEntries)
                .Contains(_script);
        }
        catch (IOException)
        {
            return false;
        }
    }
    private string MethodsPath => Path.Combine(_directory, "methods.log");

    private static async Task WaitForFile(string path)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (!File.Exists(path) || new FileInfo(path).Length == 0)
        {
            if (DateTime.UtcNow >= deadline)
                Assert.Fail($"Timed out waiting for {path}");
            await Task.Delay(50);
        }
    }

    private async Task<string[]> WaitForMethods(int count)
    {
        await WaitForFile(MethodsPath);
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (true)
        {
            var lines = File.ReadAllLines(MethodsPath);
            if (lines.Length >= count)
                return lines;
            if (DateTime.UtcNow >= deadline)
                Assert.Fail($"Timed out waiting for {count} RPC requests.");
            await Task.Delay(50);
        }
    }

    private async Task AssertOwnedProcessExited()
    {
        await WaitForFile(PidPath);
        var pid = int.Parse(File.ReadAllText(PidPath).Trim());
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                using var process = Process.GetProcessById(pid);
                if (process.HasExited)
                    return;
            }
            catch (ArgumentException)
            {
                return;
            }
            await Task.Delay(50);
        }
        Assert.Fail($"Fixture-owned fake SSH process {pid} is still running.");
    }

    public void Dispose()
    {
        if (!File.Exists(PidPath))
        {
            Directory.Delete(_directory, recursive: true);
            return;
        }

        if (!int.TryParse(File.ReadAllText(PidPath), out var pid))
            throw new IOException($"Malformed PID file: {PidPath}");

        try
        {
            using var process = Process.GetProcessById(pid);
            if (!process.HasExited)
            {
                if (!OwnsPid(pid))
                    throw new IOException($"Cleanup refused: PID {pid} is not the fixture child.");

                process.Kill(entireProcessTree: true);
            }

            process.WaitForExit(5000);
            if (!process.HasExited)
                throw new IOException($"Cleanup failed: fixture child PID {pid} is still running.");
        }
        catch (ArgumentException)
        {
            // The process has already exited.
        }

        Directory.Delete(_directory, recursive: true);
    }

    private const string Script = @"#!/usr/bin/python3
import json, os, sys, time
cwd = os.getcwd()
with open(os.path.join(cwd, 'argv.json'), 'w', encoding='utf-8') as f:
    json.dump(sys.argv[1:], f)
with open(os.path.join(cwd, 'pid.txt'), 'w', encoding='utf-8') as f:
    f.write(str(os.getpid()))
with open(os.path.join(cwd, 'starts.log'), 'a', encoding='utf-8') as f:
    f.write(str(os.getpid()) + '\n')
mode = sys.argv[-2]
if mode == 'error':
    sys.stderr.write('known host fixture failure: Host key verification failed.\n')
    sys.stderr.flush()
    sys.exit(255)
if mode == 'stderr':
    sys.stderr.write('STARTMARKER' + ('x' * 1100000) + 'TAILMARKER\n')
    sys.stderr.flush()
methods = open(os.path.join(cwd, 'methods.log'), 'a', encoding='utf-8')
while True:
    line = sys.stdin.buffer.readline()
    if not line:
        break
    try:
        request = json.loads(line)
        method = request['method']
        methods.write(method + '\n')
        methods.flush()
    except Exception:
        sys.exit(2)
    if mode == 'stall':
        time.sleep(60)
        sys.exit(0)
    if mode == 'broken':
        sys.stdout.buffer.write(b'not-a-protocol-frame\n')
        sys.stdout.buffer.flush()
        sys.exit(0)
    if method == 'info':
        result = {'schemaVersion': 1, 'updaterVersion': '0.8.0', 'model': 'TB323FU', 'recoveryGuid': '01234567-89ab-cdef-0123-456789abcdef', 'receivedMethod': method}
    else:
        result = {'receivedMethod': method, 'sessionId': '0123456789abcdef0123456789abcdef'}
    response = {'protocolVersion': 1, 'id': request['id'], 'ok': True, 'result': result}
    sys.stdout.buffer.write((json.dumps(response, separators=(',', ':')) + '\n').encode('utf-8'))
    sys.stdout.buffer.flush()
if mode == 'stubborn':
    time.sleep(60)
";
}

internal sealed class LinuxFactAttribute : FactAttribute
{
    public LinuxFactAttribute()
    {
        if (!OperatingSystem.IsLinux() || !File.Exists("/usr/bin/python3"))
            Skip = "Requires Linux and /usr/bin/python3.";
    }
}
