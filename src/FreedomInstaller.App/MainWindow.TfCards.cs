using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// 「安装到 TF 卡」的卡片发现与容量估算。
/// <para>
/// 两条读取路线都由 Core 决定：平板内（通过维护助手只读查询）与电脑读卡器（主机侧只读查询）。
/// 本文件只做三件事：发起一次只读查询、把真实报告里的卡片填进列表、按所选卡片与已校验的安装包
/// 用 <see cref="TfCardSupport.Plan"/> 算出容量。任何一条路线都不在这里写设备、不格式化卡片、
/// 不调用 adb server 管理命令，也不自动挑第一张卡或自动开始查询。
/// </para>
/// <para>
/// 面向用户的文字一律先登记消息（<c>Dynamic.*</c> 键 + 参数）再渲染，所以切换语言只会按原消息重写，
/// 不会把读取方式、目标卡、容量计划或风险勾选清掉。
/// </para>
/// </summary>
public partial class MainWindow
{
    /// <summary>当前选择的读取方式，默认「TF 卡在平板里」。</summary>
    private TfCardSource _tfSource = TfCardSource.Tablet;

    /// <summary>上一次查询真实返回的候选卡片；换方式或换设备时按需清空。</summary>
    private IReadOnlyList<TfCardCandidate> _tfCards = Array.Empty<TfCardCandidate>();

    /// <summary>用户在列表里手动选中的目标卡；<c>null</c> 表示尚未选择（从不自动选中）。</summary>
    private TfCardCandidate? _tfCard;

    /// <summary>所选卡片 + 已校验安装包算出的容量计划；缺输入或算不出来时为 <c>null</c>。</summary>
    private TfSpacePlan? _tfPlan;

    /// <summary>卡片状态行当前的消息（键 + 参数），切换语言时按它重新渲染。</summary>
    private UiMessage? _tfStatus;

    /// <summary>容量计划行当前的消息，同上。</summary>
    private UiMessage? _tfPlanNote;

    // ---------- 读取方式 ----------

    /// <summary>
    /// 切换读取方式。取消选中、界面未就绪或忙碌时一律忽略；真正的切换会清掉上一路读到的卡片，
    /// 但不会自动发起查询（读取仍然只能由用户点「读取 TF 卡」触发）。
    /// </summary>
    private async void OnTfSourceChanged(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy || _suppressTfSourceForElevation)
        {
            return;
        }

        if (sender is not RadioButton radio || radio.IsChecked != true)
        {
            return;
        }

        // TF 受保护状态或仍持有 TF 会话：拒绝切换读取方式，恢复原单选。
        if (ProtectedModernTfInstallState || HasAnyPreparedModernTfInstall)
        {
            RestoreTfSourceChoiceAfterElevation();
            return;
        }

        var source = ReferenceEquals(radio, TfSourceReaderRadio) ? TfCardSource.Reader : TfCardSource.Tablet;

        // 非管理员选择读卡器：先恢复原来的单选，再走同 EXE 的 UAC 提起重启；不做任何其它事。
        if (source == TfCardSource.Reader && !IsActualWindowsAdmin())
        {
            RestoreTfSourceChoiceAfterElevation();
            await TryRelaunchForTfReaderAsync();
            return;
        }

        if (source == _tfSource)
        {
            RenderTfTexts();
            return;
        }

        // TF 卡安装模式下换读取方式：先作废 TF 输入；失败则恢复旧单选并原样返回。
        if (IsModernTfInstallMode)
        {
            if (!await BeginModernTfInputChangeAsync(clearPackage: false))
            {
                RestoreTfSourceChoiceAfterElevation();
                return;
            }
        }

        _tfSource = source;
        RenderTfTabletHostDriverStatus();

        // 两种来源的卡片列表绝不混用：换来源时把上一路读到的卡片、目标卡、计划与风险同意一起清掉。
        ResetTfSelection(clearInventory: true);
        UpdateTfCapacity();
        UpdateSummary();
        RefreshActions();
        AppendLocalizedLog(M("Dynamic.Log.TfSourceChanged", M(TfSourceLabelKey(_tfSource))));
    }

    /// <summary>用户在列表里选择目标卡：只认列表项里真实携带的候选对象，没有任何回退默认值。</summary>
    private async void OnTfCardChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_ready)
        {
            return;
        }

        // 现代平板模式：手动选卡只更新本地目标与容量视图，不作废真实待处理的恢复现场。
        if (IsModernTfTabletMode)
        {
            if (_busy)
            {
                return;
            }

            _tfCard = TfCardsCombo.SelectedItem is ComboBoxItem tabletItem
                && tabletItem.Tag is TfCardCandidate tabletCard
                    ? tabletCard
                    : null;
            _tfPlan = null;
            TfTabletRiskCheck.IsChecked = false;
            UpdateTfCapacity();
            RefreshTfTabletActions();
            return;
        }

        // TF 卡安装下忙碌 / 受保护 / 仍持有会话：直接忽略本次选择变化。
        if (IsModernTfInstallMode && (_busy || ProtectedModernTfInstallState || HasAnyPreparedModernTfInstall))
        {
            return;
        }

        // TF 卡安装下换目标卡等于换写入位置：先作废 TF 输入，失败则不提交新选择。
        if (IsModernTfInstallMode && !await BeginModernTfInputChangeAsync(clearPackage: false))
        {
            return;
        }

        _tfCard = TfCardsCombo.SelectedItem is ComboBoxItem item && item.Tag is TfCardCandidate card
            ? card
            : null;
        _tfPlan = null;

        // 换目标卡等于换写入位置：上一次的风险同意必须重新勾选。
        RiskCheck.IsChecked = false;

        ClearTfFields();
        UpdateTfCapacity();
        UpdateSummary();
        RefreshActions();

        var selected = _tfCard;
        if (selected is not null)
        {
            AppendLocalizedLog(M("Dynamic.Log.TfCardSelected", selected.DisplayName, FormatBytes(selected.SizeBytes)));
        }
    }

    // ---------- 读取卡片 ----------

    /// <summary>
    /// 「读取 TF 卡」：一次只读查询。平板内的查询需要已确认的设备身份；电脑读卡器只查主机上的卡片，
    /// 因此在没有平板身份时也能读取。查询开始前先让旧列表与旧计划失效，失败时也不会留下旧结论。
    /// </summary>
    private async void OnReadTfCards(object sender, RoutedEventArgs e)
    {
        if (_busy)
        {
            return;
        }

        // 现代平板模式：卡片发现由平板控制器自己的只读入口完成，绝不进入旧 ADB 查询。
        if (IsModernTfTabletMode)
        {
            await DiscoverTfTabletCardsAsync();
            return;
        }

        // TF 受保护状态或仍持有会话：拒绝发起新的只读查询。
        if (ProtectedModernTfInstallState || HasAnyPreparedModernTfInstall)
        {
            return;
        }

        var source = _tfSource;
        var adbPath = _transport?.AdbPath;
        var serial = _identity?.Serial;

        if (source == TfCardSource.Tablet && (adbPath is null || serial is null))
        {
            // 平板内读取依赖维护环境里的读卡能力，当前尚未开放：直说，并指向读卡器这条路线。
            SetTfStatus(M("Dynamic.Tf.Status.TabletUnavailable"));
            SetText(ProgressStatusText, "Dynamic.Progress.TfCardsFailed");
            AppendLocalizedLog(M("Dynamic.Log.TfQueryFailed", T("Dynamic.Tf.Status.TabletUnavailable")));
            return;
        }

        await RunBusyAsync(async token =>
        {
            // 重新查询之前先作废旧结果：列表、目标卡、计划与字段一律回到未知。
            _tfCards = Array.Empty<TfCardCandidate>();
            TfCardsCombo.Items.Clear();
            TfCardsCombo.SelectedIndex = -1;
            _tfCard = null;
            _tfPlan = null;
            ClearTfFields();
            SetTfStatus(M("Dynamic.Tf.Status.Reading"));
            SetText(ProgressStatusText, "Dynamic.Progress.ReadingTfCards");
            AppendLocalizedLog(M("Dynamic.Log.ReadingTfCards", M(TfSourceLabelKey(source))));

            try
            {
                var command = source == TfCardSource.Tablet
                    ? TfCardDiscovery.BuildTabletCommand(adbPath!, serial!)
                    : TfCardDiscovery.BuildReaderCommand();

                var result = await _runner.RunAsync(command, token);
                if (result.ExitCode != 0)
                {
                    // 平板内读取失败最常见的原因就是维护环境的读卡能力不可用，这时给出可执行的下一步。
                    SetTfStatus(source == TfCardSource.Tablet
                        ? M("Dynamic.Tf.Status.TabletUnavailable")
                        : M("Dynamic.Tf.Status.Failed"));
                    SetText(ProgressStatusText, "Dynamic.Progress.TfCardsFailed");
                    AppendLocalizedLog(M("Dynamic.Log.TfQueryExitCode", result.ExitCode));
                    UpdateTfCapacity();
                    return;
                }

                var cards = TfCardSupport.ParseCandidates(result.StandardOutput, source);
                _tfCards = cards;

                foreach (var candidate in cards)
                {
                    TfCardsCombo.Items.Add(new ComboBoxItem
                    {
                        Content = $"{candidate.DisplayName} · {FormatBytes(candidate.SizeBytes)} · {candidate.Path}",
                        Tag = candidate,
                    });
                }

                if (cards.Count == 0)
                {
                    SetTfStatus(M("Dynamic.Tf.Status.Empty"));
                    SetText(ProgressStatusText, "Dynamic.Progress.TfCardsRead");
                    AppendLocalizedLog(M("Dynamic.Log.TfCardsEmpty"));
                }
                else
                {
                    SetTfStatus(M("Dynamic.Tf.Status.Found", cards.Count));
                    SetText(ProgressStatusText, "Dynamic.Progress.TfCardsRead");
                    AppendLocalizedLog(M("Dynamic.Log.TfCardsFound", cards.Count));
                }

                // 永不自动选中第一张卡：容量计划只在用户明确选了目标卡之后才出现。
                UpdateTfCapacity();
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception exception) when (exception is IOException
                or InvalidOperationException
                or ArgumentException
                or JsonException
                or TimeoutException)
            {
                _tfCards = Array.Empty<TfCardCandidate>();
                TfCardsCombo.Items.Clear();
                TfCardsCombo.SelectedIndex = -1;
                _tfCard = null;
                _tfPlan = null;
                ClearTfFields();
                SetTfStatus(M("Dynamic.Tf.Status.Failed"));
                SetText(ProgressStatusText, "Dynamic.Progress.TfCardsFailed");
                AppendLocalizedLog(M("Dynamic.Log.TfQueryFailed", exception.Message));
                UpdateTfCapacity();
            }
        });
    }

    // ---------- 容量 ----------

    /// <summary>
    /// 按「已选目标卡 + 已校验安装包」重算 TF 容量。选中卡片后总容量一律显示读卡报告里的实际值；
    /// 缺安装包时其余三项显示「—」并说明缺什么，只有两者都真实存在时才调用 <see cref="TfCardSupport.Plan"/>，
    /// 内部安装的 <see cref="PartitionPlanner"/> 与 userdata 数字在这里完全不会出现。
    /// </summary>
    private void UpdateTfCapacity()
    {
        _tfPlan = null;
        ClearTfFields();

        var card = _tfCard;
        var storage = _package?.Storage;

        if (card is null)
        {
            SetTfPlanNote(M("Dynamic.Tf.Plan.NoCard"));
            return;
        }

        // 卡片选中后，总容量是读卡报告里的真实数字：不需要安装包就先照实显示。
        TfTotalText.Text = FormatBytes(card.SizeBytes);

        if (storage is null)
        {
            SetTfPlanNote(M("Dynamic.Tf.Plan.NoPackage"));
            return;
        }

        TfSpacePlan plan;
        try
        {
            plan = TfCardSupport.Plan(card, storage);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            SetTfPlanNote(M("Dynamic.Tf.Plan.Failed"));
            AppendLocalizedLog(M("Dynamic.Log.TfPlanFailed", exception.Message));
            return;
        }

        _tfPlan = plan;

        // 总容量保持读卡报告里的实际卡片容量，计划只补 boot / root / data 三项。
        TfTotalText.Text = FormatBytes(card.SizeBytes);
        TfBootText.Text = FormatBytes(plan.LinuxBootBytes);
        TfRootText.Text = FormatBytes(plan.LinuxRootBytes);
        TfDataText.Text = FormatBytes(plan.EstimatedLinuxDataBytes);
        SetTfPlanNote(M("Dynamic.Tf.Plan.Ready"));
    }

    /// <summary>摘要里的 TF 分支：读取方式、真实选中的卡片与容量计划，绝不写内部规划数字。</summary>
    private void RenderTfSummary(UiMessage modeMessage, string device, object bootloader, object package)
    {
        var card = _tfCard;
        var plan = _tfPlan;

        SetText(
            SummaryText,
            "Dynamic.Summary.InstallTf",
            modeMessage,
            M(TfSourceLabelKey(_tfSource)),
            device,
            bootloader,
            card is null ? M("Dynamic.Summary.NotSelected") : card.DisplayName,
            card is null ? UnknownValue : card.Path,
            card is null ? UnknownValue : FormatBytes(card.SizeBytes),
            plan is null ? UnknownValue : FormatBytes(plan.LinuxRootBytes),
            plan is null ? UnknownValue : FormatBytes(plan.EstimatedLinuxDataBytes),
            package);
    }

    // ---------- 可用性 ----------

    /// <summary>
    /// 卡片侧的可用性：忙碌时读取方式、读取按钮与列表一律禁用；
    /// 读取按钮在「电脑读卡器」下始终可用（与平板无关），在「平板内」下需要工具目录与已确认身份。
    /// </summary>
    private void RefreshTfActions()
    {
        // 现代 TF 流程优先：动作可用性完全由 TF 控制器刷新重算，绝不走旧版重新启用。
        if (IsModernTfInstallMode)
        {
            RefreshModernTfInstallActions();
            return;
        }

        TfSourceTabletRadio.IsEnabled = !_busy;
        TfSourceReaderRadio.IsEnabled = !_busy;
        ReadTfCardsButton.IsEnabled = !_busy
            && (_tfSource == TfCardSource.Reader || (_transport is not null && _identity is not null));
        TfCardsCombo.IsEnabled = !_busy && _tfCards.Count > 0;
        RenderTfTabletHostDriverStatus();
    }

    // ---------- 状态与渲染 ----------

    /// <summary>
    /// 清掉上一轮卡片结论：目标卡、计划与四个容量字段回到未知。
    /// 候选列表由调用方决定是否一起清空（电脑读卡器读到的列表与设备无关）。
    /// </summary>
    private void ResetTfSelection(bool clearInventory)
    {
        _tfCard = null;
        _tfPlan = null;

        if (clearInventory)
        {
            _tfCards = Array.Empty<TfCardCandidate>();
            TfCardsCombo.Items.Clear();
            TfCardsCombo.SelectedIndex = -1;
        }

        ClearTfFields();
        SetTfStatus(M("Dynamic.Tf.StatusInitial"));
        SetTfPlanNote(M("Dynamic.Tf.Plan.Idle"));

        // 换设备 / 换功能 / 换卡片都等于换了写入位置：风险同意必须由用户重新勾选。
        RiskCheck.IsChecked = false;
        RenderTfTexts();
    }

    private void ClearTfFields()
    {
        TfTotalText.Text = UnknownValue;
        TfBootText.Text = UnknownValue;
        TfRootText.Text = UnknownValue;
        TfDataText.Text = UnknownValue;
    }

    private void SetTfStatus(UiMessage message)
    {
        _tfStatus = message;
        SetText(TfStatusText, message);
    }

    private void SetTfPlanNote(UiMessage message)
    {
        _tfPlanNote = message;
        SetText(TfPlanStatusText, message);
    }

    /// <summary>
    /// 按当前读取方式与已登记消息重写说明、状态与计划行；只改文字，
    /// 不动读取方式、目标卡、容量计划、风险勾选与页面位置。
    /// </summary>
    private void RenderTfTexts()
    {
        SetText(TfSourceHintText, TfSourceHintKey(_tfSource));
        SetText(TfStatusText, _tfStatus ?? M("Dynamic.Tf.StatusInitial"));
        SetText(TfPlanStatusText, _tfPlanNote ?? M("Dynamic.Tf.Plan.Idle"));
        RenderTfTabletHostDriverStatus();
    }

    private static string TfSourceHintKey(TfCardSource source) =>
        source == TfCardSource.Reader ? "Dynamic.Tf.Hint.Reader" : "Dynamic.Tf.Hint.Tablet";

    private static string TfSourceLabelKey(TfCardSource source) =>
        source == TfCardSource.Reader ? "Dynamic.Tf.Source.Reader" : "Dynamic.Tf.Source.Tablet";
}
