using System;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// 同窗口的「准备环境」控制器：只读自检 + 显式安装随附高通驱动，并维护重启门禁。
/// 安装的 UAC / pnputil 进程完全归 <see cref="WindowsDriverInstaller"/> 所有，这里从不启动或结束它。
/// 重启标记只写在本程序缓存目录的一个文件里，不碰注册表、系统设置或用户偏好。
/// </summary>
public partial class MainWindow
{
    private const string PendingRebootMarkerFileName = "qualcomm-driver-pending-reboot.txt";
    private const string BootIdentityScript =
        "$ErrorActionPreference='Stop'; (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('O')";

    private bool _showingEnvironment = true;
    private bool _environmentDriverInstalling;
    private bool _environmentCheckCompleted;
    private bool _environmentSystemSupported;
    private bool _environmentToolsReady;
    private bool _environmentBootVerified;
    private bool _environmentStateUnknown;
    private bool _environmentPendingReboot;

    /// <summary>最近一次确认过的启动标识；读取失败时保留旧值，不无根据清空内存门禁。</summary>
    private string? _environmentBootIdentity;
    private string? _environmentPendingBootId;
    private WindowsDriverCheckResult? _environmentDriverResult;

    /// <summary>环境页自己的检查 / 安装日志，保留消息而不是渲染后的文字。</summary>
    private UiMessage? _environmentLogRoot;

    /// <summary>自检完全成功、系统受支持、工具与真实驱动都就绪、启动标识已确认且没有门禁。</summary>
    private bool EnvironmentIsReady =>
        EnvironmentPlatformReady && _environmentDriverResult is { IsReady: true };

    /// <summary>与驱动是否就绪无关的平台前置条件：安装按钮也只在此基础上开放。</summary>
    private bool EnvironmentPlatformReady =>
        _environmentCheckCompleted && _environmentSystemSupported && _environmentToolsReady
        && _transport is not null && _environmentBootVerified && _environmentBootIdentity is not null
        && !_environmentPendingReboot && !_environmentStateUnknown;

    private bool EnvironmentDriverMissing =>
        string.Equals(_environmentDriverResult?.State.ToString(), "Missing", StringComparison.Ordinal);

    // ---------- 启动与入口 ----------

    internal Task InitializeEnvironmentAsync() =>
        _closed ? Task.CompletedTask : RunEnvironmentCheckAsync();

    /// <summary>普通自检入口：只有它占用 <see cref="RunBusyAsync"/> 的忙碌状态。</summary>
    private async Task RunEnvironmentCheckAsync()
    {
        if (!_ready || _closed || _environmentDriverInstalling) return;
        await RunBusyAsync(async token =>
        {
            try { await CheckEnvironmentCoreAsync(token); }
            catch (OperationCanceledException) { MarkEnvironmentCheckFailed(); throw; }
            catch (Exception) { MarkEnvironmentCheckFailed(); }
        });
    }

    private async void OnEnvironmentCheck(object sender, RoutedEventArgs e)
    {
        if (_ready && !_busy && !_environmentDriverInstalling) await RunEnvironmentCheckAsync();
    }

    private async void OnShowEnvironment(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy || _environmentDriverInstalling || !_showingHome || _showingSupport) return;

        // 受保护卸载、受保护 TF 现场、真实 9008 会话与尚未完成 / 未核实的内部安装都不切换视图；
        // 已完成的安装事务不是活动现场。
        if (HasProtectedUninstallState || ProtectedModernTfInstallState || HasInternalInstallLiveEdlState
            || (HasInternalInstallExecutionStarted && !IsCompletedInternalInstallExecution)
            || HasPendingTfTabletRecovery || HasGlobalRecoveryProtectedState) return;

        _showingEnvironment = true;
        _showingGlobalRecovery = false;
        ApplyFunctionView();
        RefreshEnvironmentActions();
        // 进入页面即做一次只读复核；不改变已选功能，也不重置向导输入。
        await RunEnvironmentCheckAsync();
    }

    private async void OnEnvironmentContinue(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy || _environmentDriverInstalling
            || !_showingEnvironment || _showingSupport || !EnvironmentIsReady) return;
        _showingEnvironment = false;

        // 平板恢复现场仍待处理：先打开恢复页并刷新动作，不走 --tf-reader 入口，也不进首页。
        if (HasPendingTfTabletRecovery)
        {
            ForceOpenTfTabletRecoveryPage();
            RefreshActions();
            return;
        }

        // 带 --tf-reader 启动时，在进入首页前先接管入口（提升重启或直接进入读卡器模式）。
        if (await TryOpenRequestedTfReaderStartupAsync())
        {
            return;
        }

        // 环境完成后的可选页只有备份视图：不展示任何恢复控件，也可以直接跳过进入首页。
        ShowGlobalRecoveryPage(GlobalRecoveryMode.Backup, GlobalRecoveryOrigin.Onboarding);
        // 准备页曾把首页卡片设为禁用；离开准备页后必须立刻按就绪状态重新计算。
        RefreshActions();
    }

    /// <summary>安装等待期间拒绝关闭，但不结束安装器；其余情况保持正常关闭。</summary>
    private void OnEnvironmentClosing(object? sender, CancelEventArgs e)
    {
        if (!_environmentDriverInstalling) return;
        e.Cancel = true;
        SetText(EnvironmentStatusText, "Dynamic.Environment.WaitForInstall");
    }

    // ---------- 只读自检 ----------

    /// <summary>安装流程已持有 <c>_busy</c> 时也会直接调用，所以这里不碰忙碌状态、不创建取消源。</summary>
    private async Task CheckEnvironmentCoreAsync(CancellationToken cancellationToken)
    {
        _environmentCheckCompleted = false;
        _environmentSystemSupported = false;
        _environmentToolsReady = false;
        _environmentBootVerified = false;
        _environmentStateUnknown = false;
        _environmentDriverResult = null;
        ReportEnvironment(M("Dynamic.Environment.Checking"));

        // 1. 原生系统：64 位且不低于 Windows 10。
        _environmentSystemSupported = RuntimeInformation.OSArchitecture == Architecture.X64
            && OperatingSystem.IsWindowsVersionAtLeast(10);
        SetText(EnvironmentSystemStatusText, _environmentSystemSupported
            ? "Dynamic.Environment.SystemReady"
            : "Dynamic.Environment.SystemUnsupported");

        // 2. 随附工具：复用现有解包入口，它只解包，不执行设备命令。
        var bundledToolsPrepared = await InitializeBundledToolsAsync();
        if (_closed) return;
        cancellationToken.ThrowIfCancellationRequested();
        _environmentToolsReady = bundledToolsPrepared && _transport is not null;
        SetText(EnvironmentToolsStatusText, _environmentToolsReady
            ? "Dynamic.Environment.ToolsReady"
            : "Dynamic.Environment.ToolsFailed");

        // 3. 启动标识：读取失败时保留上一次确认过的值，并明确标为未核实。
        var bootIdentity = await ReadBootIdentityAsync(cancellationToken);
        if (_closed) return;
        cancellationToken.ThrowIfCancellationRequested();
        if (bootIdentity is null) _environmentStateUnknown = true;
        else
        {
            _environmentBootIdentity = bootIdentity;
            _environmentBootVerified = true;
            EvaluatePendingRebootMarker(bootIdentity);
        }

        // 4. 真实驱动状态：同步 Inspect 放到线程池，结论只信 IsReady。
        WindowsDriverCheckResult? result = null;
        try { result = await Task.Run(() => new WindowsQualcommDriver().Inspect(), cancellationToken); }
        catch (OperationCanceledException) { throw; }
        catch (Exception) { _environmentStateUnknown = true; }

        if (_closed) return;
        cancellationToken.ThrowIfCancellationRequested();
        _environmentDriverResult = result;
        RenderDriverState(result);
        _environmentCheckCompleted = _environmentSystemSupported && _environmentToolsReady
            && _environmentBootVerified && result is not null && !_environmentStateUnknown;
        RenderEnvironmentStatus();
        RefreshEnvironmentActions();
    }

    private void RenderDriverState(WindowsDriverCheckResult? result)
    {
        if (result is null)
        {
            SetText(EnvironmentDriverStatusText, "Dynamic.Environment.DriverState.Unknown");
            SetText(EnvironmentDriverVersionText, "Dynamic.Environment.VersionUnknown");
            return;
        }

        SetText(EnvironmentDriverStatusText, DriverStateKey(result.State.ToString()));
        var version = result.DriverVersion?.ToString();
        SetText(EnvironmentDriverVersionText, string.IsNullOrWhiteSpace(version)
            ? M("Dynamic.Environment.VersionUnknown")
            : M("Dynamic.Environment.DriverVersion", version));

        // 原生 Detail 只是可选说明，追加为日志；绝不覆盖已有历史。
        if (!string.IsNullOrWhiteSpace(result.Detail))
            AppendEnvironmentLog(M("Dynamic.Environment.DriverDetail", result.Detail));
    }

    private void RenderEnvironmentStatus()
    {
        var key =
            !_environmentSystemSupported ? "Dynamic.Environment.SystemUnsupported"
            : !_environmentBootVerified ? "Dynamic.Environment.BootUnknown"
            : _environmentStateUnknown ? "Dynamic.Environment.CheckFailed"
            : _environmentPendingReboot ? "Dynamic.Environment.PendingReboot"
            : EnvironmentIsReady ? "Dynamic.Environment.Ready"
            : EnvironmentDriverMissing ? "Dynamic.Environment.NeedDriver"
            : "Dynamic.Environment.NotReady";
        ReportEnvironment(M(key));
    }

    /// <summary>Core 稳定给出枚举名；只对固定已知名字拼接键名，其余归为 Unknown。</summary>
    private static string DriverStateKey(string? stateName) =>
        stateName is "Missing" or "Prepared" or "Connected" or "Problem" or "Unsupported"
            ? "Dynamic.Environment.DriverState." + stateName
            : "Dynamic.Environment.DriverState.Unknown";

    private void MarkEnvironmentCheckFailed()
    {
        _environmentCheckCompleted = false;
        _environmentDriverResult = null;
        if (_closed) return;
        // 清零后不能继续显示上一次的 Ready / 版本结论。
        RenderDriverState(null);
        ReportEnvironment(M("Dynamic.Environment.CheckFailed"));
        RefreshEnvironmentActions();
    }

    // ---------- 启动标识与重启标记 ----------

    /// <summary>固定 argv 的只读 PowerShell 查询；退出码 0 且输出可往返解析才算成功。</summary>
    private async Task<string?> ReadBootIdentityAsync(CancellationToken cancellationToken)
    {
        try
        {
            var command = new ProcessCommand(
                Path.Combine(System.Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
                new[] { "-NoProfile", "-NonInteractive", "-Command", BootIdentityScript },
                TimeSpan.FromSeconds(15));
            var result = await _runner.RunAsync(command, cancellationToken);
            return result.ExitCode == 0 && TryNormalizeBootIdentity(result.StandardOutput, out var canonical)
                ? canonical
                : null;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception) { return null; }
    }

    private static bool TryNormalizeBootIdentity(string? raw, out string canonical)
    {
        canonical = string.Empty;
        if (string.IsNullOrWhiteSpace(raw)
            || !DateTimeOffset.TryParseExact(
                raw.Trim(), "O", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var value))
            return false;

        canonical = value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
        return true;
    }

    /// <summary>
    /// 缺失标记视为没有门禁；其他读取失败或内容不可解析一律未知并阻断。
    /// 只有当前启动确实不同的过期标记才删除，删除失败同样保持阻断。
    /// </summary>
    private void EvaluatePendingRebootMarker(string bootIdentity)
    {
        string content;
        try { content = File.ReadAllText(PendingRebootMarkerPath()); }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        { KeepPendingRebootWithoutMarker(bootIdentity); return; }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException)
        { _environmentStateUnknown = true; return; }

        if (!TryNormalizeBootIdentity(content, out var markerIdentity))
        { _environmentStateUnknown = true; return; }

        if (string.Equals(markerIdentity, bootIdentity, StringComparison.Ordinal))
        { _environmentPendingReboot = true; _environmentPendingBootId = bootIdentity; return; }

        try
        {
            File.Delete(PendingRebootMarkerPath());
            _environmentPendingReboot = false;
            _environmentPendingBootId = null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException)
        { _environmentStateUnknown = true; }
    }

    /// <summary>同一启动周期里标记意外缺失时，保留已经知道的待重启结论。</summary>
    private void KeepPendingRebootWithoutMarker(string bootIdentity)
    {
        if (!_environmentPendingReboot) return;
        if (_environmentPendingBootId is null
            || string.Equals(_environmentPendingBootId, bootIdentity, StringComparison.Ordinal)) return;
        _environmentPendingReboot = false;
        _environmentPendingBootId = null;
    }

    private static string PendingRebootMarkerPath() =>
        Path.Combine(BundledTools.GetCacheRoot(), PendingRebootMarkerFileName);

    /// <summary>写入当前启动标识；写入失败意味着不能调用安装器。</summary>
    private bool TryWritePendingRebootMarker(string bootIdentity)
    {
        try
        {
            var root = BundledTools.GetCacheRoot();
            Directory.CreateDirectory(root);
            File.WriteAllText(
                Path.Combine(root, PendingRebootMarkerFileName), bootIdentity,
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
            or NotSupportedException or ArgumentException)
        { return false; }
    }

    /// <summary>只在明确「无需重启」或明确取消的结果上清除；失败记为未知并保持阻断。</summary>
    private bool ClearPendingRebootMarker()
    {
        try { File.Delete(PendingRebootMarkerPath()); return true; }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        { return true; }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException)
        { _environmentStateUnknown = true; return false; }
    }

    /// <summary>清除成功才释放内存门禁；失败时保持 pending + Unknown。</summary>
    private bool TryClearPendingRebootGate()
    {
        if (!ClearPendingRebootMarker()) return false;
        _environmentPendingReboot = false;
        _environmentPendingBootId = null;
        return true;
    }

    // ---------- 显式安装 ----------

    private async void OnEnvironmentInstall(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy || _environmentDriverInstalling || !CanInstallDriverNow()) return;

        _environmentDriverInstalling = true;
        _busy = true;
        RefreshActions();
        RefreshEnvironmentActions();

        try
        {
            ReportEnvironment(M("Dynamic.Environment.Installing"));

            QualcommDriverFiles files;
            try { files = BundledQualcommDriver.EnsureAvailable(); }
            catch (Exception)
            {
                // 真实解包与哈希校验失败：不进入 UAC。
                _environmentCheckCompleted = false;
                ReportEnvironment(M("Dynamic.Environment.InstallFailed"));
                return;
            }

            var bootIdentity = _environmentBootIdentity;
            if (bootIdentity is null || !TryWritePendingRebootMarker(bootIdentity))
            {
                // 缓存写入失败时绝不进入 UAC。
                _environmentCheckCompleted = false;
                _environmentStateUnknown = true;
                ReportEnvironment(M("Dynamic.Environment.MarkerFailed"));
                return;
            }

            _environmentPendingReboot = true;
            _environmentPendingBootId = bootIdentity;

            DriverInstallResult installResult;
            try
            {
                // 不传取消令牌、不接管进程：UAC 与 pnputil 的生命周期都属于安装器。
                installResult = await WindowsDriverInstaller.InstallAsync(files);
            }
            catch (Exception)
            {
                // 未知失败保留标记，保持未就绪，不宣称成功也不自动重启。
                _environmentCheckCompleted = false;
                ReportEnvironment(M("Dynamic.Environment.InstallFailed"));
                return;
            }

            await ApplyInstallOutcomeAsync(installResult);
        }
        finally
        {
            _environmentDriverInstalling = false;
            _busy = false;
            if (!_closed) { RefreshActions(); RefreshEnvironmentActions(); }
        }
    }

    private async Task ApplyInstallOutcomeAsync(DriverInstallResult installResult)
    {
        switch (installResult.Outcome.ToString())
        {
            case "Completed":
                // 明确的非重启结果才清标记，然后用一次全新自检确认，绝不只信退出码 0。
                TryClearPendingRebootGate();
                _environmentCheckCompleted = false;
                ReportEnvironment(M("Dynamic.Environment.InstallCompleted"));
                try { await CheckEnvironmentCoreAsync(CancellationToken.None); }
                catch (OperationCanceledException) { MarkEnvironmentCheckFailed(); }
                catch (Exception) { MarkEnvironmentCheckFailed(); }
                return;

            case "Cancelled":
                // 明确取消且标记清理成功：保留已核实的系统 / 工具 / 启动与当前 Missing 结论，
                // 直接允许重试；不自动重开 UAC，也不宣称就绪或成功。
                if (!TryClearPendingRebootGate()) _environmentCheckCompleted = false;
                ReportEnvironment(M("Dynamic.Environment.Cancelled"));
                return;

            case "Failed":
                TryClearPendingRebootGate();
                _environmentCheckCompleted = false;
                ReportEnvironment(M("Dynamic.Environment.InstallFailed"));
                if (installResult.ExitCode is int exitCode)
                    AppendEnvironmentLog(M("Dynamic.Environment.InstallerExit", exitCode));
                return;

            case "RebootRequired":
                // 3010：保留预先写入的标记与内存门禁，只提示用户手动重启 Windows。
                _environmentCheckCompleted = false;
                _environmentPendingReboot = true;
                _environmentPendingBootId = _environmentBootIdentity;
                ReportEnvironment(M("Dynamic.Environment.PendingReboot"));
                return;

            default:
                // 结果未知：保留标记与未就绪状态，不自动重启、不重试。
                _environmentCheckCompleted = false;
                ReportEnvironment(M("Dynamic.Environment.InstallFailed"));
                return;
        }
    }

    private bool CanInstallDriverNow() => EnvironmentPlatformReady && EnvironmentDriverMissing;

    // ---------- 可用性与日志 ----------

    private void RefreshEnvironmentActions()
    {
        if (_closed) return;
        var idle = !_busy && !_environmentDriverInstalling;
        EnvironmentCheckButton.IsEnabled = idle;
        EnvironmentInstallDriverButton.Visibility =
            EnvironmentDriverMissing ? Visibility.Visible : Visibility.Collapsed;
        EnvironmentInstallDriverButton.IsEnabled =
            idle && EnvironmentDriverMissing && EnvironmentPlatformReady;
        EnvironmentContinueButton.IsEnabled = idle && EnvironmentIsReady;
        // 受保护 TF 现场存在时不允许经环境页「返回首页」丢掉已知状态。
        HomeEnvironmentButton.IsEnabled = idle && !ProtectedModernTfInstallState && !HasPendingTfTabletRecovery;
    }

    /// <summary>状态行与页面日志永远同时更新，检查 / 安装结论不会只留在其中一个。</summary>
    private void ReportEnvironment(UiMessage message)
    {
        if (_closed) return;
        SetText(EnvironmentStatusText, message);
        AppendEnvironmentLog(message);
    }

    private void AppendEnvironmentLog(UiMessage message)
    {
        var timestamp = DateTime.Now.ToString("HH:mm:ss", CultureInfo.InvariantCulture);
        var line = M("Dynamic.Environment.LogLine", timestamp, message);
        _environmentLogRoot = _environmentLogRoot is null ? line : LogJoin(_environmentLogRoot, line);
        if (!_closed) SetText(EnvironmentDetailsText, _environmentLogRoot);
        AppendLocalizedLog(message);
    }

    /// <summary>把新旧两行合并成同一条可重新渲染的消息，切换语言时整段历史一起更新。</summary>
    private static UiMessage LogJoin(UiMessage older, UiMessage newer) =>
        new("Dynamic.Environment.LogJoin", older, newer);
}
