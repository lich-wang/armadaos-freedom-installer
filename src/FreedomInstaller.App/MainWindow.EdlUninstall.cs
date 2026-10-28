using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// 卸载流程的 9008 只读准备与执行（N8A/N8B）：加载真实 EDL 工具链、读取设备分区并生成只读还原方案；
/// 用户在一次确认为「是」后交给真实工作流，成功后只发送一次重置，再由真实安卓读数做验收。
/// <para>
/// 本文件不传入任何模拟输入、不创建 HTTP/RAM 事务。失败与结果未知都不会自动重试、不会重建事务，
/// 也不会用任何界面状态代替设备的真实读数。
/// </para>
/// </summary>
public partial class MainWindow
{
    /// <summary>进入 9008 前的安卓电量采样；不得当作 9008 状态下的实时读数。</summary>
    private sealed record EdlPowerSample(int? Percentage, bool? ExternalPower, DateTimeOffset CapturedAt);

    private EdlToolchain? _uninstallEdlTools;

    private EdlClient? _uninstallEdlClient;

    private EdlUninstallBackend? _uninstallEdlBackend;

    private bool _uninstallEdlResetAttempted;

    private EdlPowerSample? _uninstallEdlPower;

    /// <summary>EDL 工具链 ZIP 的固定嵌入资源名；构建期未提供时该资源不存在。</summary>
    private const string EdlToolsArchiveResource = "FreedomInstaller.EdlTools.zip";

    /// <summary>只释放当前已准备的后端；工具链与入口结果由调用方按安全边界另行释放。</summary>
    private void ClearPreparedEdlUninstallState()
    {
        var backend = _uninstallEdlBackend;
        _uninstallEdlBackend = null;
        if (backend is null)
        {
            return;
        }

        try
        {
            backend.Dispose();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    /// <summary>
    /// 释放后端与暂存工具链，并丢弃客户端引用；不删除用户文件、备份或工作目录，
    /// 也不处置调用方传入的 runner/端点发现对象。只在既有保护闸门允许时调用。
    /// </summary>
    private void DisposeEdlUninstallState()
    {
        ClearPreparedEdlUninstallState();

        var tools = _uninstallEdlTools;
        var client = _uninstallEdlClient;
        _uninstallEdlTools = null;
        _uninstallEdlClient = null;

        // EdlClient 不拥有工具链，也没有可释放资源；两个引用都为空时无需再处理。
        if (tools is null && client is null)
        {
            return;
        }

        if (tools is null)
        {
            return;
        }

        try
        {
            tools.Dispose();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    // ---------- 进入前电量采样 ----------

    /// <summary>
    /// 只读一次 <c>dumpsys battery</c>，记录进入 9008 之前的安卓电量与外部供电状态。
    /// 读不到或解析失败一律记为未知；调用方取消照常向外传播。
    /// </summary>
    private async Task CaptureEdlPowerAsync(string adbPath, string serial, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(adbPath) || string.IsNullOrWhiteSpace(serial))
        {
            _uninstallEdlPower = new EdlPowerSample(null, null, default);
            return;
        }

        try
        {
            var command = new ProcessCommand(
                adbPath,
                new[] { "-s", serial, "shell", "dumpsys", "battery" },
                TimeSpan.FromSeconds(10));
            var result = await _runner.RunAsync(command, token);

            _uninstallEdlPower = result.ExitCode == 0
                ? ParseEdlPower(result.StandardOutput)
                : new EdlPowerSample(null, null, default);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            // 超时、启动失败或输出不可用都只表示「没有采样」，绝不推测电量。
            _uninstallEdlPower = new EdlPowerSample(null, null, default);
        }
    }

    /// <summary>只解析 dumpsys 的 level/scale 与三个 powered 键；其余行一律忽略。</summary>
    private static EdlPowerSample ParseEdlPower(string output)
    {
        int? level = null;
        int? scale = null;
        bool? ac = null;
        bool? usb = null;
        bool? wireless = null;

        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            var separator = line.IndexOf(':');
            if (separator <= 0)
            {
                continue;
            }

            var key = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();

            switch (key)
            {
                case "level":
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedLevel))
                    {
                        level = parsedLevel;
                    }

                    break;
                case "scale":
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedScale))
                    {
                        scale = parsedScale;
                    }

                    break;
                case "AC powered":
                    ac = ParseDumpsysBool(value);
                    break;
                case "USB powered":
                    usb = ParseDumpsysBool(value);
                    break;
                case "Wireless powered":
                    wireless = ParseDumpsysBool(value);
                    break;
            }
        }

        int? percentage = null;
        if (level is int levelValue
            && scale is int scaleValue
            && scaleValue > 0
            && levelValue >= 0
            && levelValue <= scaleValue)
        {
            percentage = (int)Math.Round(levelValue * 100.0 / scaleValue, MidpointRounding.AwayFromZero);
        }

        bool? external = null;
        if (ac == true || usb == true || wireless == true)
        {
            external = true;
        }
        else if (ac == false && usb == false && wireless == false)
        {
            external = false;
        }

        return new EdlPowerSample(percentage, external, DateTimeOffset.UtcNow);
    }

    private static bool? ParseDumpsysBool(string value) => bool.TryParse(value, out var parsed)
        ? parsed
        : null;

    /// <summary>把采样渲染成完整一行；没有真实采样时明确说明未知。</summary>
    private UiMessage PowerMessage()
    {
        var sample = _uninstallEdlPower;
        if (sample is null)
        {
            return M("Dynamic.UninstallFlow.EdlRestore.PowerUnknown");
        }

        var percent = sample.Percentage is int value
            ? string.Format(CultureInfo.CurrentCulture, "{0}%", value)
            : T("Dynamic.UninstallFlow.EdlRestore.PowerPercentUnknown");

        var external = sample.ExternalPower switch
        {
            true => T("Dynamic.UninstallFlow.Common.Yes"),
            false => T("Dynamic.UninstallFlow.Common.No"),
            _ => T("Dynamic.UninstallFlow.EdlRestore.PowerExternalUnknown"),
        };

        var time = sample.CapturedAt == default
            ? T("Dynamic.UninstallFlow.EdlRestore.PowerTimeUnknown")
            : sample.CapturedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.CurrentCulture);

        return M(
            "Dynamic.UninstallFlow.EdlRestore.PowerSample",
            percent,
            external,
            time);
    }

    // ---------- 只读准备 ----------

    /// <summary>
    /// 在真实 9008 连接之后生成只读还原方案：加载工具链、让后端读取设备并保存宿主机备份，
    /// 全程不写入设备。已有真实 Sahara 证明时保留同一套工具链与客户端；其余失败对象在等待调用
    /// 返回后按所有权释放，保留原入口结果并允许安全重试。
    /// </summary>
    private async Task PrepareEdlUninstallAsync()
    {
        var entry = _uninstallEdlResult;
        if (!_ready
            || _busy
            || HasProtectedUninstallState
            || CurrentModeTag() != "uninstall"
            || entry is null)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(_uninstallWorkRoot))
        {
            SetText(UninstallInputNoteText, "Dynamic.UninstallFlow.Input.NeedWorkRoot");
            return;
        }

        if (!AllUninstallGptAssetsExist())
        {
            SetText(
                UninstallInputNoteText,
                "Dynamic.UninstallFlow.EdlRestore.NeedGptFiles",
                MissingUninstallGptAssets());
            return;
        }

        var legacyPath = (InstallationRecordBox.Text ?? string.Empty).Trim();
        if (legacyPath.Length > 0 && _installationRecord is null)
        {
            SetText(UninstallInputNoteText, "Dynamic.UninstallFlow.Input.NeedLegacyRecord");
            return;
        }

        var binding = entry;
        var workRoot = _uninstallWorkRoot!;
        var paths = UninstallGptPaths();
        var selectedRecord = legacyPath.Length > 0 ? _installationRecord : null;

        await RunBusyAsync(async token =>
        {
            InvalidateUninstallPreparedPlan();

            // 已有工具链与客户端转入本地变量：本次操作期间由这里持有，字段先清空，
            // 因此窗口在只读准备期间关闭时不会释放仍在使用的工具链。
            var tools = _uninstallEdlTools;
            var client = _uninstallEdlClient;
            _uninstallEdlTools = null;
            _uninstallEdlClient = null;
            _uninstallEdlResetAttempted = false;

            var inspecting = M("Dynamic.UninstallFlow.EdlRestore.PrepareInspecting");
            SetEdlUninstallStatus(inspecting, false);
            SetText(ProgressStatusText, inspecting);

            Stream? archive = null;
            EdlUninstallBackend? backend = null;
            var committed = false;

            // 只有成对的工具链与客户端才能复用；残缺的一对在设备操作开始前本地释放。
            if (tools is null || client is null)
            {
                if (tools is not null)
                {
                    try
                    {
                        tools.Dispose();
                    }
                    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                    {
                    }
                }

                tools = null;
                client = null;
            }

            try
            {
                if (tools is null || client is null)
                {
                    archive = Assembly.GetExecutingAssembly()
                        .GetManifestResourceStream(EdlToolsArchiveResource);
                    if (archive is null)
                    {
                        throw new InvalidOperationException(
                            T("Dynamic.UninstallFlow.EdlRestore.MissingPackage"));
                    }

                    SetText(ProgressStatusText, "Dynamic.UninstallFlow.EdlRestore.PrepareToolchain");
                    tools = await EdlToolchain.LoadAsync(archive, workRoot, token);

                    SetText(ProgressStatusText, "Dynamic.UninstallFlow.EdlRestore.PrepareValidating");
                    client = new EdlClient(
                        tools,
                        binding,
                        _runner,
                        new WindowsEdlEndpointDiscovery());
                }

                var assets = new UninstallGptAssets(paths[0], paths[1]);

                backend = await EdlUninstallBackend.CreatePreparedAsync(
                    client!,
                    tools!,
                    binding,
                    assets,
                    workRoot,
                    _runner,
                    token);

                if (selectedRecord is not null)
                {
                    RequireSameLegacyRecord(selectedRecord, backend.Inputs.Record);
                }

                // 准备可能耗时较长：在提交任何字段前最后确认一次未被取消、窗口仍然打开。
                token.ThrowIfCancellationRequested();
                if (_closed)
                {
                    return;
                }

                _uninstallEdlTools = tools;
                _uninstallEdlClient = client;
                _uninstallEdlBackend = backend;
                _uninstallInputs = backend.Inputs;
                _restorePlan = backend.Inputs.Plan;
                _uninstallPhase = UninstallUiPhase.Prepared;
                _uninstallAttempted = false;
                _uninstallWritesStarted = false;
                committed = true;

                var ready = M(
                    "Dynamic.UninstallFlow.EdlRestore.PrepareReady",
                    backend.PlanFingerprint,
                    backend.BackupDirectory);
                SetEdlUninstallStatus(ready, false);
                SetText(ProgressStatusText, ready);
                SetText(UninstallTransactionStatusText, ready);
                SetText(ConnectionStatusText, "Dynamic.UninstallFlow.EdlRestore.ConnectionPrepared");
                SetText(UninstallInputNoteText, "Dynamic.UninstallFlow.EdlRestore.PrepareReadyNote");
                SetText(
                    UninstallPlanStatusText,
                    "Dynamic.UninstallFlow.EdlRestore.PlanStatus",
                    backend.PlanFingerprint,
                    M(PhaseKey(_uninstallPhase)));
                AppendLocalizedLog(ready);
                UpdateUninstallPanel();
            }
            catch (OperationCanceledException)
            {
                // 只读准备被取消：可能已经完成设备读取与宿主机备份，不作「设备未切换模式」的断言。
                if (committed)
                {
                    throw;
                }

                _uninstallPhase = UninstallUiPhase.Failed;
                _uninstallAttempted = false;
                _uninstallWritesStarted = false;
                var cancelled = M("Dynamic.UninstallFlow.EdlRestore.Cancelled");
                SetEdlUninstallStatus(cancelled, false);
                SetText(ProgressStatusText, cancelled);
                AppendLocalizedLog(cancelled);
                throw;
            }
            catch (Exception exception)
            {
                if (committed)
                {
                    // 方案已经提交，后续界面刷新出错不能把已准备状态改写成失败。
                    throw;
                }

                _uninstallPhase = UninstallUiPhase.Failed;
                _uninstallAttempted = false;
                _uninstallWritesStarted = false;
                _restorePlan = null;
                var failure = M(
                    "Dynamic.UninstallFlow.EdlRestore.PrepareFailed",
                    exception.Message);
                ApplyEdlUninstallOutcome(failure, false);
                AppendLocalizedLog(failure);
            }
            finally
            {
                archive?.Dispose();

                if (!committed)
                {
                    // 只释放本次新建的后端（它只拥有自己的只读锁）；工具链与客户端按真实证明保留。
                    try
                    {
                        backend?.Dispose();
                    }
                    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                    {
                    }

                    var retained = !_closed
                        && client is not null
                        && tools is not null
                        && client.HasInitialSaharaProof;

                    if (retained)
                    {
                        _uninstallEdlTools = tools;
                        _uninstallEdlClient = client;
                        SetText(
                            UninstallInputNoteText,
                            "Dynamic.UninstallFlow.EdlRestore.ConnectionRetained");
                    }
                    else
                    {
                        // 关闭或没有真实 Sahara 证明：等待调用已经返回，这里才本地释放工具链。
                        try
                        {
                            tools?.Dispose();
                        }
                        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                        {
                        }
                    }
                }
            }
        });

        RefreshUninstallActions();
        RefreshUninstallEdlActions();
        UpdateSummary();
    }

    // ---------- 状态辅助 ----------

    /// <summary>
    /// 9008 流程的唯一状态写入点：同一条消息同时进入卡片状态字段、状态行与日志，
    /// 因此 GetUninstallEdlMessage / 引导路线不会残留上一次的「只读准备」文案。
    /// </summary>
    private void SetEdlUninstallStatus(UiMessage message, bool log)
    {
        _uninstallEdlStatus = message;
        if (_ready)
        {
            SetText(UninstallEdlStatusText, message);
        }

        if (log)
        {
            AppendLocalizedLog(message);
        }
    }

    /// <summary>同时把同一条真实结果写进进度行与设备操作状态卡；不做另一套措辞。</summary>
    private void ApplyEdlUninstallOutcome(UiMessage message, bool log)
    {
        SetEdlUninstallStatus(message, log);
        if (_ready)
        {
            SetText(ProgressStatusText, message);
            SetText(UninstallTransactionStatusText, message);
            if (_uninstallEdlBackend is not null)
            {
                // 方案卡的状态行同样按当前阶段重画，避免页面停留在「只读准备完成」。
                TryRenderEdlUninstallPanel();
            }
        }
    }

    // ---------- 执行（一次确认，一次重置） ----------

    /// <summary>
    /// 执行已准备的 9008 卸载：只在这里弹一次确认，随后交给真实工作流；
    /// 成功且停在等待清除数据时只发送一次重置命令，绝不自动重试或新建事务。
    /// </summary>
    private async Task ExecuteEdlUninstallAsync()
    {
        var backend = _uninstallEdlBackend;
        var inputs = _uninstallInputs;
        var client = _uninstallEdlClient;
        var entry = _uninstallEdlResult;

        if (!_ready
            || _busy
            || CurrentModeTag() != "uninstall"
            || _uninstallPhase != UninstallUiPhase.Prepared
            || _uninstallAttempted
            || RiskCheck.IsChecked != true
            || backend is null
            || inputs is null
            || client is null
            || entry is null
            || !ReferenceEquals(backend.Inputs, inputs)
            || !ReferenceEquals(client.Binding, entry))
        {
            return;
        }

        // 入口证据必须仍然是本次已准备方案的设备；任何一项不一致都不执行。
        var entryIdentity = entry.AndroidIdentity?.Identity;
        if (entryIdentity is null || !entryIdentity.Equals(inputs.Identity))
        {
            return;
        }

        var power = PowerMessage();
        var answer = MessageBox.Show(
            this,
            T(
                "Dynamic.UninstallFlow.EdlRestore.Confirm.Body",
                inputs.Identity.Model,
                inputs.Identity.Serial,
                inputs.CurrentTable.DeviceId ?? UnknownValue,
                FormatBytesOrPlaceholder(CurrentUserdataBytes(inputs)),
                FormatBytes(inputs.Plan.RestoredAndroidBytes),
                DeletedPartitionExtents(inputs),
                T(
                    "Dynamic.UninstallFlow.Plan.Range",
                    inputs.Plan.UserdataStartSector,
                    inputs.Plan.UserdataEndSectorExclusive - 1),
                backend.BackupDirectory,
                T(power.Key, power.Arguments)),
            T("Dynamic.UninstallFlow.EdlRestore.Confirm.Title"),
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);

        if (answer != MessageBoxResult.Yes)
        {
            return;
        }

        // 先落盘「已尝试」与执行中，再进入忙状态；默认「否」时以上字段一个都不改。
        _uninstallAttempted = true;
        _uninstallWritesStarted = false;
        _uninstallPhase = UninstallUiPhase.Running;

        var starting = M("Dynamic.UninstallFlow.EdlRestore.Run.Starting");
        ApplyEdlUninstallOutcome(starting, true);
        RefreshUninstallEdlActions();

        await RunBusyAsync(async token =>
        {
            var progress = new Progress<UninstallStage>(stage =>
            {
                // 进度只写文案和「已有写入」标记；阶段与成功状态绝不从这里改变。
                // 只有真正改动设备的三个阶段才置位，不再用旧阶段的数值顺序推断。
                if (EdlStageWritesData(stage))
                {
                    _uninstallWritesStarted = true;
                }

                // 阶段已经离开执行中（成功、未知或失败）后，迟到的进度回调不能再覆盖终态文案。
                if (_uninstallPhase != UninstallUiPhase.Running)
                {
                    return;
                }

                var text = M("Dynamic.UninstallFlow.Run.Progress", M(EdlUninstallStageKey(stage)));
                SetText(ProgressStatusText, text);
                SetText(UninstallTransactionStatusText, text);
            });

            UninstallResult result;
            try
            {
                var request = new UserdataUninstallRequest(
                    backend.Snapshot,
                    backend.PlanFingerprint,
                    string.Empty,
                    true);
                request = request with { ConfirmationId = UninstallWorkflow.ConfirmationFor(request) };
                result = await UninstallWorkflow.RunAsync(request, backend, progress, token);
            }
            catch (OperationCanceledException)
            {
                // 工作流一旦被调用，回调未送达并不代表没有写入；保留全部对象并按「未知」处理。
                _uninstallPhase = UninstallUiPhase.Uncertain;
                ApplyEdlUninstallOutcome(
                    M(
                        "Dynamic.UninstallFlow.EdlRestore.Run.UncertainCancelled",
                        backend.BackupDirectory),
                    true);
                return;
            }
            catch (Exception exception)
            {
                _uninstallPhase = UninstallUiPhase.Uncertain;
                ApplyEdlUninstallOutcome(
                    M(
                        "Dynamic.UninstallFlow.EdlRestore.Run.Uncertain",
                        exception.Message,
                        backend.BackupDirectory),
                    true);
                return;
            }

            if (result.Success && result.Stage == UninstallStage.AwaitingFactoryReset)
            {
                // 保持「执行中」直到重置流程结束：关闭钩子只在执行中时拒绝关闭，
                // 若提前改为等待清除数据，可能在客户端重置进程仍在运行时释放工具链。
                // 只在这个确切成功分支里发送一次重置；发送前先置位，失败也不会第二次发送。
                UiMessage message;
                if (!_uninstallEdlResetAttempted)
                {
                    _uninstallEdlResetAttempted = true;
                    try
                    {
                        var reset = await client.ResetAsync(token);
                        if (reset.CommandAccepted)
                        {
                            message = M("Dynamic.UninstallFlow.EdlRestore.Run.ResetSent");
                            SetText(ConnectionStatusText, "Dynamic.UninstallFlow.EdlRestore.WaitingAndroid");
                        }
                        else
                        {
                            message = M(
                                "Dynamic.UninstallFlow.EdlRestore.Run.ResetUnconfirmed",
                                UnknownValue);
                            SetText(ConnectionStatusText, "Dynamic.UninstallFlow.EdlRestore.ResetUnknownConnection");
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        message = M(
                            "Dynamic.UninstallFlow.EdlRestore.Run.ResetUnconfirmed",
                            T("Dynamic.UninstallFlow.EdlRestore.Run.Cancelled"));
                        SetText(ConnectionStatusText, "Dynamic.UninstallFlow.EdlRestore.ResetUnknownConnection");
                    }
                    catch (Exception exception)
                    {
                        message = M(
                            "Dynamic.UninstallFlow.EdlRestore.Run.ResetUnconfirmed",
                            exception.Message);
                        SetText(ConnectionStatusText, "Dynamic.UninstallFlow.EdlRestore.ResetUnknownConnection");
                    }
                }
                else
                {
                    message = M("Dynamic.UninstallFlow.EdlRestore.Run.ResetAlreadyAttempted");
                }

                _uninstallPhase = UninstallUiPhase.AwaitingFactoryReset;
                ApplyEdlUninstallOutcome(message, true);
                return;
            }

            var error = string.IsNullOrWhiteSpace(result.Error) ? UnknownValue : result.Error;
            var wrote = _uninstallWritesStarted
                || result.DataMayBeErased
                || EdlStageWritesData(result.Stage);
            var stageText = M(EdlUninstallStageKey(result.Stage));

            if (wrote)
            {
                _uninstallPhase = UninstallUiPhase.Uncertain;
                ApplyEdlUninstallOutcome(
                    M(
                        "Dynamic.UninstallFlow.EdlRestore.Run.FailedAfterWrite",
                        stageText,
                        error,
                        backend.BackupDirectory),
                    true);
                return;
            }

            // 写入开始前停止：明确说明没有开始写入，但仍保留已准备好的后端与输入，不就地重跑。
            _uninstallPhase = UninstallUiPhase.Failed;
            ApplyEdlUninstallOutcome(
                M("Dynamic.UninstallFlow.EdlRestore.Run.FailedBeforeWrite", stageText, error),
                true);
        });

        RefreshUninstallEdlActions();
        UpdateSummary();
    }

    // ---------- 阶段文案 ----------

    /// <summary>
    /// 9008 进度与失败阶段的文案：只把两个含义变化的阶段映射到 EDL 专用键，
    /// 其余阶段沿用既有 <see cref="StageKey"/>。RAM 事务的 <c>StageKey</c> 保持不变。
    /// </summary>
    private static string EdlUninstallStageKey(UninstallStage stage) => stage switch
    {
        UninstallStage.ValidateRestoreInputs => "Dynamic.UninstallFlow.EdlRestore.Stage.ValidateGptInputs",
        UninstallStage.BackupCurrentBoot => "Dynamic.UninstallFlow.EdlRestore.Stage.BackupCurrentLayout",
        _ => StageKey(stage),
    };

    /// <summary>只有这三个阶段会改动设备；写入标记只按它们置位，不看旧阶段的数值顺序。</summary>
    private static bool EdlStageWritesData(UninstallStage stage) => stage
        is UninstallStage.ReclaimAndroidSpace
        or UninstallStage.InitializeAndroid
        or UninstallStage.AwaitingFactoryReset;

    // ---------- 安卓只读验收 ----------

    /// <summary>
    /// 使用真实 9008 入口证据与只读 adb 探针做一次验收；允许用户稍后再次点击，
    /// 但从这里绝不重启、写入或再次发送重置命令。
    /// </summary>
    private async Task VerifyEdlUninstallAndroidAsync()
    {
        var inputs = _uninstallInputs;
        var entry = _uninstallEdlResult;
        var transport = _transport;

        if (!_ready
            || _busy
            || _uninstallEdlBackend is null
            || _uninstallPhase != UninstallUiPhase.AwaitingFactoryReset
            || inputs is null
            || entry is null
            || transport is null)
        {
            return;
        }

        var adbPath = transport.AdbPath;

        await RunBusyAsync(async token =>
        {
            var probing = M("Dynamic.UninstallFlow.EdlVerify.Probing");
            ApplyEdlUninstallOutcome(probing, false);

            try
            {
                var probe = new AdbAndroidUninstallAcceptanceProbe(_runner, adbPath);
                var result = await AndroidUninstallAcceptance.VerifyEdlAsync(inputs, entry, probe, token);

                if (result.Accepted)
                {
                    long? measuredBytes = null;
                    string? acceptedKey = null;
                    if (result.DataFilesystemBytes is long filesystemBytes && filesystemBytes > 0)
                    {
                        measuredBytes = filesystemBytes;
                        acceptedKey = result.FilesystemOnlyEvidence
                            ? "Dynamic.UninstallFlow.Verify.AcceptedFilesystemOnly"
                            : "Dynamic.UninstallFlow.Verify.AcceptedFilesystem";
                    }
                    else if (!result.FilesystemOnlyEvidence
                        && result.UserdataPartitionBytes is long rawBytes
                        && rawBytes > 0)
                    {
                        measuredBytes = rawBytes;
                        acceptedKey = "Dynamic.UninstallFlow.Verify.Accepted";
                    }

                    if (measuredBytes is long bytes && acceptedKey is not null)
                    {
                        _uninstallPhase = UninstallUiPhase.Accepted;
                        var accepted = M(acceptedKey, FormatBytes(bytes));
                        ApplyEdlUninstallOutcome(accepted, true);
                        SetText(ConnectionStatusText, "Dynamic.UninstallFlow.EdlRestore.ConnectionVerified");
                        return;
                    }
                }

                _uninstallPhase = UninstallUiPhase.AwaitingFactoryReset;
                var detail = result.Accepted
                    ? T("Dynamic.UninstallFlow.Verify.NoBytes")
                    : result.Message;
                var pending = M("Dynamic.UninstallFlow.EdlVerify.Pending", detail);
                ApplyEdlUninstallOutcome(pending, true);
            }
            catch (OperationCanceledException)
            {
                // 取消按调用方语义向外传播；不声称设备未发生任何变化。
                throw;
            }
            catch (Exception exception)
            {
                _uninstallPhase = UninstallUiPhase.AwaitingFactoryReset;
                ApplyEdlUninstallOutcome(
                    M("Dynamic.UninstallFlow.EdlVerify.Failed", exception.Message),
                    true);
            }
        });

        RefreshUninstallEdlActions();
        UpdateSummary();
    }

    // ---------- 只读渲染 ----------

    /// <summary>EDL 只读方案存在时优先渲染它；返回 false 表示交回旧的 RAM 事务渲染。</summary>
    private bool TryRenderEdlUninstallPanel()
    {
        if (_uninstallEdlBackend is null)
        {
            return false;
        }

        var inputs = _uninstallEdlBackend.Inputs;
        _restorePlan = inputs.Plan;

        RenderDeviceStrip();
        RestoredCapacityText.Text = FormatBytes(inputs.Plan.RestoredAndroidBytes);
        SetText(
            RemovedRangeText,
            "Dynamic.UninstallFlow.Plan.RemovedRange",
            DeletedPartitionExtents(inputs),
            inputs.Plan.UserdataStartSector,
            inputs.Plan.UserdataEndSectorExclusive - 1,
            FormatBytesOrPlaceholder(CurrentUserdataBytes(inputs)));
        SetText(
            UninstallPlanStatusText,
            "Dynamic.UninstallFlow.EdlRestore.PlanStatus",
            _uninstallEdlBackend.PlanFingerprint,
            M(PhaseKey(_uninstallPhase)));
        return true;
    }

    /// <summary>EDL 只读方案的摘要使用后端返回的真实输入、指纹与备份目录。</summary>
    private bool TryRenderEdlUninstallSummary()
    {
        if (_uninstallEdlBackend is null)
        {
            return false;
        }

        var backend = _uninstallEdlBackend;
        var inputs = backend.Inputs;
        SetText(
            SummaryText,
            "Dynamic.UninstallFlow.EdlRestore.Summary",
            ModeMessage("uninstall"),
            $"{inputs.Identity.Model} · {inputs.Identity.Serial}",
            inputs.CurrentTable.DeviceId ?? UnknownValue,
            FormatBytesOrPlaceholder(CurrentUserdataBytes(inputs)),
            FormatBytes(inputs.Plan.RestoredAndroidBytes),
            DeletedPartitionExtents(inputs),
            T(
                "Dynamic.UninstallFlow.Plan.Range",
                inputs.Plan.UserdataStartSector,
                inputs.Plan.UserdataEndSectorExclusive - 1),
            backend.BackupDirectory,
            M(EdlSummaryPhaseKey(_uninstallPhase)),
            PowerMessage());
        return true;
    }

    /// <summary>
    /// 9008 摘要的阶段文案：只描述真实写入与安卓验收，不沿用 HTTP 事务的「只能查询」或手动 Recovery 话术。
    /// </summary>
    private static string EdlSummaryPhaseKey(UninstallUiPhase phase) => phase switch
    {
        UninstallUiPhase.Prepared => "Dynamic.UninstallFlow.EdlRestore.Phase.Prepared",
        UninstallUiPhase.Running => "Dynamic.UninstallFlow.EdlRestore.Phase.Running",
        UninstallUiPhase.Uncertain => "Dynamic.UninstallFlow.EdlRestore.Phase.Uncertain",
        UninstallUiPhase.Failed => "Dynamic.UninstallFlow.EdlRestore.Phase.Failed",
        UninstallUiPhase.AwaitingFactoryReset => "Dynamic.UninstallFlow.EdlRestore.Phase.AwaitingFactoryReset",
        UninstallUiPhase.Accepted => "Dynamic.UninstallFlow.EdlRestore.Phase.Accepted",
        _ => "Dynamic.UninstallFlow.EdlRestore.Phase.Idle",
    };
}
