using System;
using System.Globalization;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// 「安装到内部存储」第 3 步（分配空间）：真实导入一个系统包，用真实备份里的 LUN0 原始分区表计算
/// 可分配范围，滑条只做纯算术规划；点「下一步」时才真正调用 Core 的
/// <see cref="InternalInstallArtifacts.PrepareAsync"/> 生成一次主机侧方案对象。
/// <para>
/// 本文件只保存工厂实际返回的对象：<see cref="ImportedPackage"/>、<see cref="InternalAllocationPlan"/>
/// 和 <see cref="InternalArtifactSet"/>。没有伪造的校验结果、没有默认型号、没有容量回退值，也没有
/// 任何构造成功证据的入口。滑条移动只重算规划并作废旧的确认对象，绝不重复写 2 GiB 或重新哈希备份。
/// </para>
/// <para>
/// 下一步只有真实准备工厂成功返回后才打开确认页；安装执行由独立的执行入口处理，按钮按真实准备结果与风险确认启用，结果只来自后端快照与实际验收。
/// </para>
/// </summary>
public partial class MainWindow
{
    /// <summary>系统包导入目录名；只在用户显式选择的备份父目录下创建，没有临时目录回退。</summary>
    private const string InternalPackageImportsDirectoryName = ".armada-package-imports";

    /// <summary>
    /// 「安装到内部存储」唯一接受的部署类型。Core 只对结构完整、schema 2 的直装包给出这个值；
    /// schema 1 种子包与所有无效结果都是 null。
    /// </summary>
    private const string DirectPackageDeploymentKind = "edl-raw-v1";

    /// <summary>最近一次真实导入的系统包；null 表示没有可供第 3 步使用的有效校验结果。</summary>
    private ImportedPackage? _internalInstallPackage;

    /// <summary>当前滑条位置对应的真实规划；null 表示还不能分配。</summary>
    private InternalAllocationPlan? _internalInstallAllocation;

    /// <summary>唯一一次主机侧准备返回的方案对象；只有它非空才允许进入确认页。</summary>
    private InternalArtifactSet? _internalInstallArtifacts;

    /// <summary>程序化写入滑条范围 / 数值时抑制 ValueChanged，避免重复规划。</summary>
    private bool _suppressInternalInstallCapacitySync;

    /// <summary>当前导入来源路径；用于区分「同一路径重新校验」与「路径已改动」。</summary>
    private string? _internalInstallImportedSourcePath;

    /// <summary>当前选择的整 GiB 值；只保存实际写在滑条上的整数，不重复换算物理字节。</summary>
    private long _internalInstallAndroidGiB;

    // ---------- 门槛 ----------

    /// <summary>
    /// 真实有效的系统包：导入成功、校验通过、带有真实容量声明，并且确实是直装包
    /// （<c>DeploymentKind</c> 精确等于 <c>edl-raw-v1</c>）。旧 schema 1 种子包不满足最后一条。
    /// </summary>
    private bool HasValidInternalInstallPackage =>
        _internalInstallPackage is
        {
            Validation.IsValid: true,
            Validation.Storage: not null,
            Validation.DeploymentKind: var deploymentKind,
        }
        && string.Equals(deploymentKind, DirectPackageDeploymentKind, StringComparison.Ordinal);

    /// <summary>第 3 步所需要的输入：备份、检查结论与有效系统包；不包含滑条规划。</summary>
    private bool HasInternalInstallCapacityInputs =>
        IsInternalInstallMode
        && HasCheckedInternalInstallDevice
        && _internalInstallBackup is not null
        && HasValidInternalInstallPackage;

    /// <summary>
    /// 允许点「下一步」去准备主机方案的全部条件：容量规划已算出，并且当前 9008 会话仍然真实持有。
    /// 没有安卓路线回退，也不凭文件存在推断。
    /// </summary>
    private bool HasInternalInstallAllocationInputs =>
        HasInternalInstallCapacityInputs
        && _internalInstallAllocation is not null
        && _internalInstallAndroidGiB > 0
        && _internalInstallEdlClient is not null
        && _internalInstallEdlEntry is not null;

    // ---------- 第 3 步入口 ----------

    /// <summary>
    /// 「浏览…」：只选择实际存在的文件；旧版安装包目录仍可直接粘贴到路径框。
    /// 选中后立即走同一条导入入口一次，取消对话框不改变任何状态。
    /// </summary>
    private async void OnBrowseInternalInstallPackage(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy || _internalInstallOperationActive || !IsInternalInstallMode)
        {
            return;
        }

        if (_internalInstallBackup is null || !HasCheckedInternalInstallDevice)
        {
            SetInternalInstallCapacityPackageStatus(
                _internalInstallBackup is null
                    ? M("Dynamic.InternalInstall.Capacity.StatusNeedBackup")
                    : M("Dynamic.InternalInstall.Capacity.StatusNeedCheck"));
            return;
        }

        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = T("Dynamic.Dialog.SelectPackageFile"),
            Filter = T("Dynamic.Dialog.PackageFileFilter"),
            CheckFileExists = true,
            Multiselect = false,
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        var file = (dialog.FileName ?? string.Empty).Trim();
        if (file.Length == 0 || !File.Exists(file))
        {
            SetInternalInstallCapacityPackageStatus(
                M("Dynamic.InternalInstall.Capacity.StatusMissing", file));
            return;
        }

        // 程序化写入路径不属于用户改动：抑制一次 TextChanged，导入入口自己负责作废旧结果。
        _suppressInternalInstallCapacitySync = true;
        try
        {
            InternalInstallPackageBox.Text = file;
        }
        finally
        {
            _suppressInternalInstallCapacitySync = false;
        }

        await BeginInternalInstallPackageImportAsync();
    }

    /// <summary>「校验安装包」：只做真实导入；所有读取与哈希都在 Core 的后台任务里完成。</summary>
    private async void OnValidateInternalInstallPackage(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy || _internalInstallOperationActive || !IsInternalInstallMode)
        {
            return;
        }

        if (_internalInstallBackup is null || !HasCheckedInternalInstallDevice)
        {
            SetInternalInstallCapacityPackageStatus(
                _internalInstallBackup is null
                    ? M("Dynamic.InternalInstall.Capacity.StatusNeedBackup")
                    : M("Dynamic.InternalInstall.Capacity.StatusNeedCheck"));
            return;
        }

        await BeginInternalInstallPackageImportAsync();
    }

    /// <summary>
    /// 路径框改动：只有文本真的不同于上一次导入来源时才作废旧结果。
    /// 旧系统包、旧规划、旧确认对象与摘要一起失效，但电脑备份、9008 会话与工具链都不动。
    /// </summary>
    private void OnInternalInstallPackagePathChanged(object sender, TextChangedEventArgs e)
    {
        if (!_ready
            || _busy
            || _internalInstallOperationActive
            || _suppressInternalInstallCapacitySync
            || !IsInternalInstallMode)
        {
            return;
        }

        var text = (InternalInstallPackageBox.Text ?? string.Empty).Trim();
        if (string.Equals(text, _internalInstallImportedSourcePath, StringComparison.Ordinal))
        {
            return;
        }

        InvalidateInternalInstallAllocation(clearPackage: true);
        SetInternalInstallCapacityPackageStatus(
            text.Length == 0
                ? M("Dynamic.InternalInstall.Capacity.StatusNeedPath")
                : M("Dynamic.InternalInstall.Capacity.PackageChanged"));
        RefreshInternalInstallActions();
    }

    /// <summary>
    /// 一次真实导入：检查输入、创建显式导入目录、调用 Core，并且只登记实际返回的对象。
    /// 全程处于 <see cref="_internalInstallOperationActive"/> 保护下，关闭 / 退出闸门因此继续有效。
    /// </summary>
    private async Task BeginInternalInstallPackageImportAsync()
    {
        _internalInstallOperationActive = true;
        try
        {
            await RunBusyAsync(ImportInternalInstallPackageAsync);
        }
        finally
        {
            _internalInstallOperationActive = false;
            if (_ready)
            {
                RefreshActions();
            }
        }
    }

    /// <summary>
    /// 导入的实际流程。型号只取已确认的检查结果，并要求与真实备份记录的型号一致；
    /// 不解析文件名，也没有默认型号。
    /// </summary>
    private async Task ImportInternalInstallPackageAsync(CancellationToken token)
    {
        try
        {
            var source = (InternalInstallPackageBox.Text ?? string.Empty).Trim();
            if (source.Length == 0)
            {
                SetInternalInstallCapacityPackageStatus(M("Dynamic.InternalInstall.Capacity.StatusNeedPath"));
                return;
            }

            var backup = _internalInstallBackup;
            var android = _internalInstallDeviceCheck?.Android;
            if (backup is null || android is null || !HasCheckedInternalInstallDevice)
            {
                SetInternalInstallCapacityPackageStatus(M("Dynamic.InternalInstall.Capacity.StatusNeedCheck"));
                return;
            }

            if (!Directory.Exists(source) && !File.Exists(source))
            {
                SetInternalInstallCapacityPackageStatus(
                    M("Dynamic.InternalInstall.Capacity.StatusMissing", source));
                InvalidateInternalInstallAllocation(clearPackage: true);
                return;
            }

            var model = android.Identity.Model;
            if (string.IsNullOrWhiteSpace(model)
                || !string.Equals(model, backup.Model, StringComparison.OrdinalIgnoreCase))
            {
                SetInternalInstallCapacityPackageStatus(
                    M("Dynamic.InternalInstall.Capacity.StatusModelMismatch"));
                InvalidateInternalInstallAllocation(clearPackage: true);
                return;
            }

            var parent = _internalInstallBackupParent;
            if (string.IsNullOrWhiteSpace(parent) || !Directory.Exists(parent))
            {
                SetInternalInstallCapacityPackageStatus(
                    M("Dynamic.InternalInstall.Capacity.StatusNeedBackupParent"));
                return;
            }

            // 本方法只在显式「浏览 / 校验」之后调用：同一路径也可能被原地替换，因此每次都必须真实导入一次。
            // 用户此前选定的整 GiB 在作废旧规划前先记下，只有真实导入成功后才恢复。
            var priorAndroidGiB = _internalInstallAndroidGiB;

            InvalidateInternalInstallAllocation(clearPackage: true);
            SetInternalInstallCapacityPackageStatus(M("Dynamic.InternalInstall.Capacity.Importing"));

            var workRoot = Path.Combine(parent, InternalPackageImportsDirectoryName);
            try
            {
                Directory.CreateDirectory(workRoot);
            }
            catch (Exception exception) when (exception is IOException
                or UnauthorizedAccessException
                or NotSupportedException
                or ArgumentException)
            {
                SetInternalInstallCapacityPackageStatus(
                    M("Dynamic.InternalInstall.Capacity.StatusWorkRootFailed", exception.Message));
                return;
            }

            SetInternalInstallConfirmProgressIndeterminate(true);
            var imported = await PackageImporter.ImportAsync(
                source,
                model,
                CurrentInstallTarget(),
                workRoot,
                token);

            if (_closeRequested || _closed)
            {
                imported.Dispose();
                return;
            }

            // 只有这里才登记实际返回的对象；校验失败也保留结果，以便界面显示真实原因。
            _internalInstallPackage = imported;
            _internalInstallImportedSourcePath = source;
            RenderInternalInstallPackageValidation(imported);

            if (!HasValidInternalInstallPackage)
            {
                InvalidateInternalInstallAllocation(clearPackage: false);
                return;
            }

            // 真实导入成功后才恢复用户此前的合法选择；范围校验照常决定保留还是退回提案。
            _internalInstallAndroidGiB = priorAndroidGiB;
            EnsureInternalInstallCapacityRange();
        }
        catch (OperationCanceledException)
        {
            SetInternalInstallCapacityPackageStatus(M("Dynamic.InternalInstall.Capacity.ImportCancelled"));
            throw;
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or InvalidDataException
            or NotSupportedException
            or ArgumentException
            or InvalidOperationException)
        {
            InvalidateInternalInstallAllocation(clearPackage: false);
            SetInternalInstallCapacityPackageStatus(
                M("Dynamic.InternalInstall.Capacity.ImportFailed", exception.Message));
        }
        catch (Exception exception)
        {
            // 其余失败同样如实显示；不保留「正在导入」的旧文字，也不伪造成功。
            InvalidateInternalInstallAllocation(clearPackage: false);
            SetInternalInstallCapacityPackageStatus(
                M("Dynamic.InternalInstall.Capacity.ImportFailed", exception.Message));
        }
        finally
        {
            SetInternalInstallConfirmProgressIndeterminate(false);
        }
    }

    /// <summary>实际校验字段：型号、包 ID、版本、清单指纹与拒绝原因都来自 Core 返回值。</summary>
    private void RenderInternalInstallPackageValidation(ImportedPackage imported)
    {
        if (!_ready)
        {
            return;
        }

        var validation = imported.Validation;
        if (!validation.IsValid)
        {
            var reasons = string.Join(T("Dynamic.Package.ReasonSeparator"), validation.Reasons);
            SetInternalInstallCapacityPackageStatus(
                M("Dynamic.InternalInstall.Capacity.Invalid", reasons));
            return;
        }

        if (validation.Storage is null)
        {
            SetInternalInstallCapacityPackageStatus(
                M("Dynamic.InternalInstall.Capacity.Invalid",
                    M("Dynamic.InternalInstall.Capacity.StorageMissing")));
            return;
        }

        if (!string.Equals(validation.DeploymentKind, DirectPackageDeploymentKind, StringComparison.Ordinal))
        {
            // 包本身通过了校验，只是不是本模式需要的直装包：如实说明要哪种包，不称它损坏，也不改写校验结论。
            SetInternalInstallCapacityPackageStatus(
                M("Dynamic.InternalInstall.Capacity.RequiresDirectPackage"));
            return;
        }

        if (validation.TestOnly)
        {
            // 测试包只能看容量：这里如实标注，不改成正式包，也不解锁任何执行路径。
            SetInternalInstallCapacityPackageStatus(
                M(
                    "Dynamic.InternalInstall.Capacity.TestOnly",
                    imported.DeviceModel,
                    validation.PackageId,
                    validation.Version,
                    validation.ManifestFingerprint));
        }
        else
        {
            SetInternalInstallCapacityPackageStatus(
                M(
                    "Dynamic.InternalInstall.Capacity.Valid",
                    imported.DeviceModel,
                    validation.PackageId,
                    validation.Version,
                    validation.ManifestFingerprint));
        }
    }

    // ---------- 范围与规划 ----------

    /// <summary>
    /// 用真实备份的 LUN0 原始表与真实包容量声明取可选范围。失败就显示 Core 的实际诊断并禁用滑条，
    /// 不退回 16 GiB，也不拼一个「好看」的范围。
    /// </summary>
    private bool EnsureInternalInstallCapacityRange()
    {
        if (!_ready)
        {
            return false;
        }

        var backup = _internalInstallBackup;
        var storage = _internalInstallPackage?.Validation.Storage;
        if (backup is null || storage is null)
        {
            return false;
        }

        var table = backup.Tables[0];
        AndroidAllocationRange range;
        try
        {
            range = InternalPartitionPlanner.GetAndroidRange(table, storage);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            DisableInternalInstallCapacitySlider(
                M("Dynamic.InternalInstall.Capacity.RangeFailed", exception.Message));
            return false;
        }

        var previous = _internalInstallAndroidGiB;
        var proposal = InternalInstallDefaultAndroidGiB(table, range);

        // 同一路径重新校验时保留用户已经选过的合法值；只有超出新范围才退回提案。
        var chosen = previous >= range.MinimumGiB && previous <= range.MaximumGiB
            ? previous
            : proposal;

        _suppressInternalInstallCapacitySync = true;
        try
        {
            InternalInstallCapacitySlider.Minimum = range.MinimumGiB;
            InternalInstallCapacitySlider.Maximum = range.MaximumGiB;
            InternalInstallCapacitySlider.TickFrequency = 1;
            InternalInstallCapacitySlider.IsSnapToTickEnabled = true;
            InternalInstallCapacitySlider.Value = chosen;
        }
        finally
        {
            _suppressInternalInstallCapacitySync = false;
        }

        return ApplyInternalInstallCapacityPlan(chosen);
    }

    /// <summary>默认提案是原始 userdata 整 GiB 的一半，再夹到真实范围内；不读取当前安卓已用空间。</summary>
    private static long InternalInstallDefaultAndroidGiB(GptTable table, AndroidAllocationRange range)
    {
        long userdataBytes = 0;
        foreach (var partition in table.Partitions)
        {
            if (string.Equals(partition.Name, "userdata", StringComparison.OrdinalIgnoreCase))
            {
                userdataBytes = partition.SectorCount * (long)table.SectorSize;
                break;
            }
        }

        var wholeGiB = userdataBytes / Gibibyte;
        var proposal = wholeGiB / 2;
        if (proposal < range.MinimumGiB)
        {
            return range.MinimumGiB;
        }

        return proposal > range.MaximumGiB ? range.MaximumGiB : proposal;
    }

    /// <summary>滑条移动：只重算规划并作废旧方案对象；不写文件、不哈希、不重建 GPT。</summary>
    private void OnInternalInstallCapacityChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (!_ready
            || _busy
            || _internalInstallOperationActive
            || _suppressInternalInstallCapacitySync
            || !IsInternalInstallMode)
        {
            return;
        }

        if (!HasInternalInstallCapacityInputs || _internalInstallBackup is null)
        {
            return;
        }

        var value = (long)Math.Round(e.NewValue, MidpointRounding.AwayFromZero);
        if (value == _internalInstallAndroidGiB && _internalInstallAllocation is not null)
        {
            return;
        }

        InvalidateInternalInstallAllocation(clearPackage: false);
        ApplyInternalInstallCapacityPlan(value);
        RefreshInternalInstallActions();
    }

    /// <summary>
    /// 调用实际 Planner 得到当前选择；显示的三个数字都来自它，固定 2 GiB 尾部由静态标签说明。
    /// </summary>
    private bool ApplyInternalInstallCapacityPlan(long androidGiB)
    {
        var backup = _internalInstallBackup;
        var storage = _internalInstallPackage?.Validation.Storage;
        if (backup is null || storage is null)
        {
            return false;
        }

        try
        {
            var plan = InternalPartitionPlanner.Plan(backup.Tables[0], androidGiB, storage);
            long totalBytes;
            try
            {
                totalBytes = checked(plan.OriginalUserdata.SectorCount * (long)plan.SectorSize);
            }
            catch (OverflowException)
            {
                totalBytes = 0;
            }

            _internalInstallAllocation = plan;
            _internalInstallAndroidGiB = androidGiB;

            if (!_ready)
            {
                return true;
            }

            SetText(
                InternalInstallCapacityTotalText,
                "Dynamic.RawValue",
                totalBytes > 0 ? FormatBytes(totalBytes) : UnknownValue);
            SetText(InternalInstallCapacityAndroidText, "Dynamic.RawValue", FormatBytes(plan.AndroidBytes));
            SetText(InternalInstallCapacityLinuxText, "Dynamic.RawValue", FormatBytes(plan.LinuxBytes));
            SetInternalInstallCapacityStatus(
                M(
                    "Dynamic.InternalInstall.Capacity.PlanReady",
                    (long)InternalInstallCapacitySlider.Minimum,
                    (long)InternalInstallCapacitySlider.Maximum,
                    FormatBytes(plan.LinuxBootBytes)));
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException
            or InvalidOperationException
            or OverflowException)
        {
            _internalInstallAllocation = null;
            _internalInstallAndroidGiB = 0;
            if (_ready)
            {
                SetText(InternalInstallCapacityTotalText, "Dynamic.RawValue", UnknownValue);
                SetText(InternalInstallCapacityAndroidText, "Dynamic.RawValue", UnknownValue);
                SetText(InternalInstallCapacityLinuxText, "Dynamic.RawValue", UnknownValue);
                SetInternalInstallCapacityStatus(
                    M("Dynamic.InternalInstall.Capacity.PlanFailed", exception.Message));
            }

            return false;
        }
    }

    private void DisableInternalInstallCapacitySlider(UiMessage diagnostic)
    {
        _internalInstallAllocation = null;
        _internalInstallAndroidGiB = 0;

        if (!_ready)
        {
            return;
        }

        _suppressInternalInstallCapacitySync = true;
        try
        {
            InternalInstallCapacitySlider.IsEnabled = false;
            InternalInstallCapacitySlider.Minimum = 16;
            InternalInstallCapacitySlider.Maximum = 16;
            InternalInstallCapacitySlider.Value = 16;
        }
        finally
        {
            _suppressInternalInstallCapacitySync = false;
        }

        SetText(InternalInstallCapacityTotalText, "Dynamic.RawValue", UnknownValue);
        SetText(InternalInstallCapacityAndroidText, "Dynamic.RawValue", UnknownValue);
        SetText(InternalInstallCapacityLinuxText, "Dynamic.RawValue", UnknownValue);
        SetInternalInstallCapacityStatus(diagnostic);
    }

    // ---------- 第 3 步 → 确认页 ----------

    /// <summary>
    /// 「下一步」从第 3 步进入主机侧准备：只有这里才调用一次真实的 PrepareAsync。
    /// 成功后才导航；导航必须发生在忙碌状态复位之后，否则会被导航闸门拒绝。
    /// </summary>
    private async Task PrepareInternalInstallConfirmationAsync()
    {
        if (!_ready || _busy || _internalInstallOperationActive || !IsInternalInstallMode)
        {
            return;
        }

        if (_internalInstallStep != 2)
        {
            return;
        }

        var backup = _internalInstallBackup;
        var package = _internalInstallPackage;
        var storage = package?.Validation.Storage;
        var parent = _internalInstallBackupParent;

        if (!HasInternalInstallAllocationInputs
            || backup is null
            || package is null
            || storage is null
            || _internalInstallAllocation is null
            || _internalInstallAndroidGiB <= 0)
        {
            SetInternalInstallConfirmStatus(M("Dynamic.InternalInstall.Prepared.NeedInputs"));
            return;
        }

        if (string.IsNullOrWhiteSpace(parent) || !Directory.Exists(parent))
        {
            SetInternalInstallConfirmStatus(M("Dynamic.InternalInstall.Prepared.NeedParent"));
            return;
        }

        var parentPath = parent!;
        var androidGiB = _internalInstallAndroidGiB;
        var allocation = _internalInstallAllocation!;

        // 只有真实后端和与当前分配一致的方案同时存在，才直接打开确认页。
        if (_internalInstallBackend is not null
            && _internalInstallArtifacts is not null
            && _internalInstallArtifacts.Allocation.AndroidBytes == allocation.AndroidBytes)
        {
            NavigateInternalInstallStep(3);
            return;
        }

        var rendered = false;

        SetInternalInstallConfirmProgressIndeterminate(true);
        SetInternalInstallConfirmStatus(M("Dynamic.InternalInstall.Prepared.Preparing"));

        _internalInstallOperationActive = true;
        try
        {
            await RunBusyAsync(async token =>
            {
                try
                {
                    var artifacts = _internalInstallArtifacts;
                    if (artifacts is null
                        || artifacts.Allocation.AndroidBytes != allocation.AndroidBytes)
                    {
                        // 旧方案与旧后端都不再匹配当前分配：先释放，再只生成一次真实方案。
                        ReleaseInternalInstallArtifacts();
                        artifacts = null;

                        // 上面的释放会复位进度条；本次准备仍在进行，重新打开忙碌指示。
                        SetInternalInstallConfirmProgressIndeterminate(true);
                        SetInternalInstallConfirmStatus(
                            M("Dynamic.InternalInstall.Prepared.PreparingArtifacts"));
                        var preparedArtifacts = await InternalInstallArtifacts.PrepareAsync(
                            backup,
                            androidGiB,
                            storage,
                            parentPath,
                            token);

                        if (_closeRequested || _closed)
                        {
                            preparedArtifacts.Dispose();
                            return;
                        }

                        _internalInstallArtifacts = preparedArtifacts;
                        artifacts = preparedArtifacts;
                    }

                    if (artifacts is null)
                    {
                        return;
                    }

                    // 保留已匹配的真实方案，只在只读工厂上重试；失败时不重新生成 2 GiB。
                    SetInternalInstallConfirmStatus(
                        M("Dynamic.InternalInstall.Prepared.LoadingComponents"));
                    var backend = await PrepareInternalInstallBackendAsync(parentPath, token);

                    if (_closeRequested || _closed)
                    {
                        return;
                    }

                    RenderInternalInstallPreparedSummary(artifacts, backend.Prepared);
                    rendered = true;
                }
                catch (OperationCanceledException)
                {
                    SetInternalInstallConfirmStatus(M("Dynamic.InternalInstall.Prepared.Cancelled"));
                    throw;
                }
                catch (InvalidOperationException exception) when (exception.Message.StartsWith(
                    "requires-complete-backup-with-efisp:",
                    StringComparison.Ordinal))
                {
                    // 只有后端明确报告备份缺少含 efisp 的完整启动恢复资料时才换成专用提示。
                    SetInternalInstallConfirmStatus(
                        M("Dynamic.InternalInstall.Prepared.CompleteBackupWithEfispRequired"));
                }
                catch (InvalidOperationException exception) when (exception.Message.StartsWith(
                    "gbl-boot-chain-key-mismatch:",
                    StringComparison.Ordinal))
                {
                    // 只有后端明确报告签名链不匹配时才换成专用提示；其余异常保留原始消息。
                    SetInternalInstallConfirmStatus(
                        M("Dynamic.InternalInstall.Prepared.GblBootChainKeyMismatch"));
                }
                catch (InvalidOperationException exception) when (exception.Message.StartsWith(
                    "gbl-runtime-region-unknown:",
                    StringComparison.Ordinal))
                {
                    // 只有后端明确报告地区无法确认或两槽冲突时才换成专用提示，绝不按语言猜地区。
                    SetInternalInstallConfirmStatus(
                        M("Dynamic.InternalInstall.Prepared.GblRuntimeRegionUnknown"));
                }
                catch (InvalidOperationException exception) when (exception.Message.StartsWith(
                    "requires-compatible-bootloader:",
                    StringComparison.Ordinal))
                {
                    // 只有后端明确要求匹配的引导加载器时才换成兼容性提示；其余异常保留原始消息。
                    SetInternalInstallConfirmStatus(
                        M("Dynamic.InternalInstall.Prepared.CompatibilityRequired"));
                }
                catch (Exception exception) when (exception is IOException
                    or UnauthorizedAccessException
                    or InvalidDataException
                    or NotSupportedException
                    or ArgumentException
                    or InvalidOperationException
                    or NotImplementedException
                    or MaintenanceException)
                {
                    SetInternalInstallConfirmStatus(
                        M("Dynamic.InternalInstall.Prepared.Failed", exception.Message));
                }
                finally
                {
                    SetInternalInstallConfirmProgressIndeterminate(false);
                }
            });
        }
        finally
        {
            _internalInstallOperationActive = false;
        }

        // 只有真实工厂返回后端、摘要已按后端字段渲染，且仍停在第 3 步时才导航。
        if (rendered
            && _internalInstallBackend is not null
            && _internalInstallArtifacts is not null
            && _internalInstallStep == 2
            && !_busy)
        {
            NavigateInternalInstallStep(3);
        }
        else if (_ready)
        {
            RefreshInternalInstallActions();
        }
    }

    /// <summary>确认页摘要只使用真实后端与方案对象的实际字段，不声称任何写入已完成。</summary>
    private void RenderInternalInstallPreparedSummary(
        InternalArtifactSet set,
        InternalInstallPrepared prepared)
    {
        if (!_ready)
        {
            return;
        }

        var backup = _internalInstallBackup;
        var validation = _internalInstallPackage?.Validation;

        // 型号与版本仍由工厂绑定的备份 / 系统包给出；其余字段取后端已经验证过的值。
        var model = backup?.Model ?? UnknownValue;
        var serial = prepared.AndroidSerial;
        var build = prepared.AndroidBuild;
        object bootloader = prepared.FastbootLockState switch
        {
            BootloaderState.Locked => M("Dynamic.BootState.Locked"),
            BootloaderState.Unlocked => M("Dynamic.BootState.Unlocked"),
            _ => M("Dynamic.BootState.Unknown"),
        };

        var androidBytes = checked(prepared.AndroidGiB * Gibibyte);
        var linuxBytes = checked(prepared.LinuxRootBytes + set.Allocation.LinuxBootBytes);

        // 卡片只放真实读到 / 已校验的值；哈希、计划与工程路径仍只出现在下方的校验详情里。
        SetText(InternalInstallConfirmDeviceModelText, "Dynamic.InternalInstall.Confirm.Value", model);
        SetText(InternalInstallConfirmDeviceSerialText, "Dynamic.InternalInstall.Confirm.Value", serial);
        SetText(InternalInstallConfirmDeviceFirmwareText, "Dynamic.InternalInstall.Confirm.Value", build);
        SetText(InternalInstallConfirmDeviceBootloaderText, "Dynamic.InternalInstall.Confirm.Value", bootloader);
        SetText(
            InternalInstallConfirmPackageVersionText,
            "Dynamic.InternalInstall.Confirm.Value",
            validation?.Version ?? UnknownValue);
        SetText(
            InternalInstallConfirmPackageIdText,
            "Dynamic.InternalInstall.Confirm.Value",
            validation?.PackageId ?? UnknownValue);
        SetText(
            InternalInstallConfirmAndroidText,
            "Dynamic.InternalInstall.Confirm.Value",
            FormatBytes(androidBytes));
        SetText(
            InternalInstallConfirmLinuxText,
            "Dynamic.InternalInstall.Confirm.Value",
            FormatBytes(linuxBytes));
        SetText(
            InternalInstallConfirmRecoveryText,
            "Dynamic.InternalInstall.Confirm.Value",
            FormatBytes(prepared.BoardBackupBytes));
        SetText(
            InternalInstallConfirmBackupPathText,
            "Dynamic.InternalInstall.Confirm.Value",
            prepared.BackupDirectory);
        SetText(
            InternalInstallConfirmPowerText,
            "Dynamic.InternalInstall.Confirm.PowerRecord",
            InternalInstallPowerMessage());

        // 后端给出的非启动安卓槽是事实：按槽位稳定排序后逐条成句，语言切换时随整段重渲染。
        var inactiveAvbFacts = prepared.AvbSlots.Values
            .Where(facts => facts.NonbootableSystem)
            .OrderBy(facts => facts.Slot, StringComparer.Ordinal)
            .ToArray();
        UiMessage? inactiveSystemWarning = null;
        foreach (var facts in inactiveAvbFacts)
        {
            var factWarning = M(
                "Dynamic.InternalInstall.Prepared.InactiveSystemUnavailable",
                facts.Slot.ToUpperInvariant(),
                facts.SourceSlot.ToUpperInvariant());
            inactiveSystemWarning = inactiveSystemWarning is null
                ? factWarning
                : M(
                    "Dynamic.InternalInstall.Execution.WithFailureDetails",
                    inactiveSystemWarning,
                    factWarning);
        }

        // 只有原始备份与后端材料都真实给出 A/B 两槽时才提写入计划。
        var bootBackedUp = backup is not null
            && backup.Files is not null
            && backup.Files.ContainsKey("boot_a")
            && backup.Files.ContainsKey("boot_b")
            && prepared.SlotMaterials.ContainsKey("a")
            && prepared.SlotMaterials.ContainsKey("b");
        var bootBackupMessage = M(
            bootBackedUp
                ? "Dynamic.InternalInstall.Confirm.BootBackedUp"
                : "Dynamic.InternalInstall.Confirm.BootPending");
        SetText(
            InternalInstallConfirmBootBackupText,
            inactiveSystemWarning is null
                ? bootBackupMessage
                : M(
                    "Dynamic.InternalInstall.Execution.WithFailureDetails",
                    bootBackupMessage,
                    inactiveSystemWarning));

        // 新的后端就是新的确认：旧勾选不沿用。它只是知情确认，随时可再取消。
        InternalInstallVerificationDetails.IsExpanded = false;
        InternalInstallEraseRiskCheck.IsChecked = false;
        InternalInstallEraseRiskCheck.IsEnabled = backup is not null && validation is { IsValid: true };

        // {14} 只描述压缩恢复资料（含格式头）的实际占用，按当前区域格式化为 MiB；
        // {15} 是板端恢复镜像的固定容量，两者不能混为一谈。
        var recoveryImageUsedMiB = (set.SummaryUsedBytes / 1024d / 1024d)
            .ToString("0.0", System.Globalization.CultureInfo.CurrentCulture) + " MiB";

        var preparedSummaryMessage = M(
            "Dynamic.InternalInstall.Prepared.Summary",
            model,
            serial,
            build,
            bootloader,
            InternalInstallPowerMessage(),
            prepared.BackupDirectory,
            prepared.BackupManifestSha256,
            validation?.PackageId ?? UnknownValue,
            validation?.Version ?? UnknownValue,
            prepared.PackageFingerprint,
            FormatBytes(androidBytes),
            FormatBytes(linuxBytes),
            FormatBytes(set.Allocation.LinuxBootBytes),
            FormatBytes(prepared.BoardBackupBytes),
            recoveryImageUsedMiB,
            FormatBytes(set.BoardSummary.Length),
            prepared.ArtifactPlanSha256,
            set.DirectoryPath);

        // 免解锁安装才追加一行短安装方式：它只是保留下来的嵌套消息，随整段一起重渲染。
        if (prepared.BootTrustMode == InternalInstallBootTrustMode.GblPreserveOem)
        {
            preparedSummaryMessage = M(
                "Dynamic.InternalInstall.Execution.WithFailureDetails",
                preparedSummaryMessage,
                M("Dynamic.InternalInstall.Prepared.GblInstallMode"));
        }

        // 主摘要的 18 个参数保持原样，事实告警只作为第二段追加在它后面。
        SetText(
            InternalInstallSummaryText,
            inactiveSystemWarning is null
                ? preparedSummaryMessage
                : M(
                    "Dynamic.InternalInstall.Execution.WithFailureDetails",
                    preparedSummaryMessage,
                    inactiveSystemWarning));

        // 指纹、证据目录与材料目录只写进本地化日志，不进入面向用户的工程卡片。
        // 直装路径只记录真实共有的字段：原始工具、候选等哈希留在 Core 证据里，不在这里另造字段。
        AppendLocalizedLog(
            M(
                "Dynamic.InternalInstall.Prepared.RecoveryImageLog",
                recoveryImageUsedMiB,
                FormatBytes(set.BoardSummary.Length)));

        AppendLocalizedLog(
            M(
                "Dynamic.InternalInstall.Prepared.DirectEvidenceLog",
                prepared.ConfirmationId,
                prepared.ArtifactPlanSha256,
                prepared.BackupManifestSha256,
                prepared.PackageFingerprint,
                prepared.PackageBindingSha256,
                prepared.EvidenceDirectory,
                _internalInstallAssetsDirectory ?? UnknownValue));

        SetInternalInstallConfirmStatus(M("Dynamic.InternalInstall.Prepared.StatusReady"));
    }

    /// <summary>摘要里的电源字段仍然只描述那一次安卓采样，不推断 9008 下的实时状态。</summary>
    private UiMessage InternalInstallPowerMessage()
    {
        var sample = _internalInstallPower;
        if (sample is null)
        {
            return M("Dynamic.InternalInstall.Power.Unknown");
        }

        object percent = sample.Percentage is int value
            ? string.Format(CultureInfo.CurrentCulture, "{0}%", value)
            : M("Dynamic.InternalInstall.Power.PercentUnknown");
        object external = sample.ExternalPower switch
        {
            true => M("Dynamic.UninstallFlow.Common.Yes"),
            false => M("Dynamic.UninstallFlow.Common.No"),
            _ => M("Dynamic.InternalInstall.Power.ExternalUnknown"),
        };
        object time = sample.CapturedAt == default
            ? M("Dynamic.InternalInstall.Power.TimeUnknown")
            : sample.CapturedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.CurrentCulture);

        return M("Dynamic.InternalInstall.Power.Sample", percent, external, time);
    }

    // ---------- 失效与生命周期 ----------

    /// <summary>
    /// 只释放方案对象自己的只读锁：生成的方案文件与备份都保留，绝不删除用户文件。
    /// </summary>
    private void ReleaseInternalInstallArtifacts()
    {
        // 后端 / 资产 / 维护包先按固定顺序释放，方案对象自己的锁最后释放。
        try
        {
            ReleaseInternalInstallPreparedBackend();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            AppendLocalizedLog(
                M("Dynamic.InternalInstall.Prepared.ReleaseFailed", exception.Message));
        }

        var artifacts = _internalInstallArtifacts;
        _internalInstallArtifacts = null;
        if (artifacts is not null)
        {
            try
            {
                artifacts.Dispose();
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                AppendLocalizedLog(
                    M("Dynamic.InternalInstall.Capacity.ArtifactCleanupFailed", exception.Message));
            }
        }

        if (!_ready)
        {
            return;
        }

        // 两根进度条一起复位：都是同一次准备的实际状态，不留下「仍在准备」的残影。
        SetInternalInstallConfirmProgressIndeterminate(false);
        SetText(
            InternalInstallSummaryText,
            "Static.InternalInstall.Confirm.SummaryInitial");
        SetText(
            InternalInstallConfirmStatusText,
            "Static.InternalInstall.Confirm.StatusWaiting");
        ResetInternalInstallConfirmationCards();
    }

    /// <summary>
    /// 方案对象失效后确认页卡片回到中性值：只改可见文字与勾选状态，
    /// 不动任何数据文件、备份、9008 会话或导航门槛。
    /// </summary>
    private void ResetInternalInstallConfirmationCards()
    {
        SetText(InternalInstallConfirmDeviceModelText, "Dynamic.InternalInstall.Confirm.Value", UnknownValue);
        SetText(InternalInstallConfirmDeviceSerialText, "Dynamic.InternalInstall.Confirm.Value", UnknownValue);
        SetText(InternalInstallConfirmDeviceFirmwareText, "Dynamic.InternalInstall.Confirm.Value", UnknownValue);
        SetText(InternalInstallConfirmDeviceBootloaderText, "Dynamic.InternalInstall.Confirm.Value", UnknownValue);
        SetText(InternalInstallConfirmPackageVersionText, "Dynamic.InternalInstall.Confirm.Value", UnknownValue);
        SetText(InternalInstallConfirmPackageIdText, "Dynamic.InternalInstall.Confirm.Value", UnknownValue);
        SetText(InternalInstallConfirmAndroidText, "Dynamic.InternalInstall.Confirm.Value", UnknownValue);
        SetText(InternalInstallConfirmLinuxText, "Dynamic.InternalInstall.Confirm.Value", UnknownValue);
        SetText(InternalInstallConfirmRecoveryText, "Dynamic.InternalInstall.Confirm.Value", UnknownValue);
        SetText(InternalInstallConfirmBackupPathText, "Dynamic.InternalInstall.Confirm.Value", UnknownValue);
        SetText(InternalInstallConfirmPowerText, "Dynamic.InternalInstall.Confirm.Value", UnknownValue);
        SetText(
            InternalInstallConfirmBootBackupText,
            "Dynamic.InternalInstall.Confirm.BootPending");

        InternalInstallVerificationDetails.IsExpanded = false;
        InternalInstallEraseRiskCheck.IsChecked = false;
        InternalInstallEraseRiskCheck.IsEnabled = false;
    }

    /// <summary>
    /// 作废容量规划与（可选的）系统包。clearPackage 为 true 时连解包目录一起释放；
    /// 备份、9008 会话、工具链与用户原始文件都不在这里处理。
    /// </summary>
    private void InvalidateInternalInstallAllocation(bool clearPackage)
    {
        ReleaseInternalInstallArtifacts();
        _internalInstallAllocation = null;
        _internalInstallAndroidGiB = 0;

        if (clearPackage)
        {
            ReleaseInternalInstallPackage();
            if (_ready)
            {
                _suppressInternalInstallCapacitySync = true;
                try
                {
                    InternalInstallCapacitySlider.IsEnabled = false;
                }
                finally
                {
                    _suppressInternalInstallCapacitySync = false;
                }
            }
        }

        if (!_ready)
        {
            return;
        }

        SetText(InternalInstallCapacityTotalText, "Dynamic.RawValue", UnknownValue);
        SetText(InternalInstallCapacityAndroidText, "Dynamic.RawValue", UnknownValue);
        SetText(InternalInstallCapacityLinuxText, "Dynamic.RawValue", UnknownValue);
        SetInternalInstallCapacityStatus(M("Dynamic.InternalInstall.Capacity.StatusWaiting"));
    }

    /// <summary>释放系统包实例拥有的解包目录；调用方选择的原始目录 / 归档永远不归本实例所有。</summary>
    private void ReleaseInternalInstallPackage()
    {
        var package = _internalInstallPackage;
        _internalInstallPackage = null;
        _internalInstallImportedSourcePath = null;

        if (package is null)
        {
            return;
        }

        try
        {
            package.Dispose();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // 清理失败必须可见：记录实际异常，绝不写成「已清理」。
            AppendLocalizedLog(
                M("Dynamic.InternalInstall.Capacity.PackageCleanupFailed", exception.Message));
        }
    }

    // ---------- 视图 ----------

    /// <summary>
    /// 第 3 步控件的最终可用性：空闲、真实检查通过且备份对象仍在时才允许编辑路径；
    /// 滑条只在实际规划存在且系统包有效时可用。不改当前页，也不调用 RefreshActions。
    /// </summary>
    private void RefreshInternalInstallCapacityActions()
    {
        if (!_ready || !IsInternalInstallMode)
        {
            return;
        }

        var editable = !_busy
            && !_internalInstallOperationActive
            && HasCheckedInternalInstallDevice
            && _internalInstallBackup is not null;

        InternalInstallPackageBox.IsEnabled = editable;
        InternalInstallPackageBrowseButton.IsEnabled = editable;
        InternalInstallPackageValidateButton.IsEnabled = editable
            && !string.IsNullOrWhiteSpace(InternalInstallPackageBox.Text);

        InternalInstallCapacitySlider.IsEnabled = editable
            && HasValidInternalInstallPackage
            && _internalInstallAllocation is not null;
    }

    private void SetInternalInstallCapacityPackageStatus(UiMessage message)
    {
        if (!_ready)
        {
            return;
        }

        SetText(InternalInstallPackageStatusText, message);
    }

    private void SetInternalInstallCapacityStatus(UiMessage message)
    {
        if (!_ready)
        {
            return;
        }

        SetText(InternalInstallCapacityStatusText, message);
    }

    private void SetInternalInstallConfirmStatus(UiMessage message)
    {
        if (!_ready)
        {
            return;
        }

        SetText(InternalInstallConfirmStatusText, message);

        // 准备发生在本步骤可见的第 3 步（index 2）：同一份状态必须同时出现在用户看得见的容量页。
        if (_internalInstallStep == 2)
        {
            SetInternalInstallCapacityStatus(message);
        }
    }

    private void SetInternalInstallConfirmProgressIndeterminate(bool running)
    {
        if (!_ready)
        {
            return;
        }

        InternalInstallConfirmProgressBar.IsIndeterminate = running;
        InternalInstallConfirmProgressBar.Visibility =
            running ? Visibility.Visible : Visibility.Collapsed;

        InternalInstallCapacityPreparationProgressBar.IsIndeterminate = running;
        InternalInstallCapacityPreparationProgressBar.Visibility =
            running ? Visibility.Visible : Visibility.Collapsed;
    }
}
