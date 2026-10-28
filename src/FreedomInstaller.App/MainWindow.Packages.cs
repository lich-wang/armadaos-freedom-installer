using System;
using System.ComponentModel;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// 统一安装包（单个压缩归档：bundle.json + models/TB322FC/… 与 models/TB323FU/…）的选择与准备。
/// <para>
/// 归档格式与型号子树的解析全部由 Core 的 <see cref="PackageImporter"/> 在后台完成；本文件只负责
/// 取「已确认设备身份里的实际型号」与当前安装目标，调用导入 API，并把结果登记成可重新渲染的本地化文案。
/// 这里不做文件名推断、不提供默认型号，也没有未知型号的回退。
/// </para>
/// <para>
/// 导入结果（<see cref="ImportedPackage"/>）只保留到下一次失效或窗口关闭：它可能拥有一个解包目录，
/// 因此每次失效都走同一个释放入口，绝不泄漏；调用方选择的原始归档 / 目录永远不归本实例所有。
/// </para>
/// </summary>
public partial class MainWindow
{
    /// <summary>界面测试通过该变量把解包根目录指到 NAS；没有设置时使用程序自己的缓存目录。</summary>
    private const string PackageWorkRootVariable = "FREEDOM_PACKAGE_WORK_ROOT";

    private const string PackageImportsDirectoryName = "PackageImports";

    /// <summary>当前已准备好的安装包；<c>null</c> 表示没有可复用的结果。</summary>
    private ImportedPackage? _importedPackage;

    /// <summary>正在进行的导入任务，只用于关闭窗口时等待它释放自己拥有的解包目录。</summary>
    private Task? _importTask;

    private bool _closeRequested;

    private bool _closed;

    // ---------- 中央导入流程 ----------

    /// <summary>
    /// 唯一导入入口：浏览、手动校验、身份确认与切换功能都走这里。
    /// 调用方必须已经在 <see cref="RunBusyAsync"/> 里，或自己保证不在 <c>_busy</c> 中重复进入。
    /// 本方法只负责登记整段导入任务：关闭窗口时要等的不只是 Core 读取，还有结果的释放。
    /// </summary>
    private async Task ImportSelectedPackageAsync(CancellationToken token)
    {
        var coreTask = ImportSelectedPackageCoreAsync(token);
        _importTask = coreTask;

        try
        {
            await coreTask;
        }
        finally
        {
            if (ReferenceEquals(_importTask, coreTask))
            {
                _importTask = null;
            }
        }
    }

    /// <summary>
    /// 导入的实际流程：取输入、释放上一次结果、调用 Core，并在关闭已请求时释放本次结果。
    /// 所有开销大的读取与校验都在 Core 的 <see cref="PackageImporter.ImportAsync"/> 里完成，界面线程不被阻塞。
    /// </summary>
    private async Task ImportSelectedPackageCoreAsync(CancellationToken token)
    {
        var source = (PackagePathBox.Text ?? string.Empty).Trim();
        if (source.Length == 0)
        {
            SetText(PackageStatusText, "Dynamic.Package.StatusNeedsFolder");
            return;
        }

        // 新格式是压缩归档文件，旧格式是安装包目录：两者都交给 Core 判断，这里只要求路径真实存在。
        if (!Directory.Exists(source) && !File.Exists(source))
        {
            SetText(PackageStatusText, "Dynamic.Package.StatusFolderMissing", source);
            return;
        }

        // 型号只能来自已确认的设备身份：不读文件名、不用默认型号，也没有未知型号的回退。
        var model = _identity?.Model;
        if (string.IsNullOrWhiteSpace(model))
        {
            SetText(PackageStatusText, "Dynamic.Package.StatusNeedsModel");
            return;
        }

        var knownModel = model!;

        // 新导入开始前先释放上一次的准备结果：同一个实例绝不并行持有两份解包目录。
        if (!ReleasePreparedPackage())
        {
            AppendLocalizedLog(M("Dynamic.Log.PackageCleanupBlocked"));
            return;
        }

        _plan = null;
        _capacityInitialized = false;

        // 新的安装包还没有通过校验：上一次的风险同意不能沿用到这次导入。
        RiskCheck.IsChecked = false;

        var target = CurrentInstallTarget();
        var workRoot = ResolvePackageWorkRoot();

        SetText(ProgressStatusText, "Dynamic.Progress.ImportingPackage");
        AppendLocalizedLog(M("Dynamic.Log.ImportingPackage", source, knownModel));

        // Core 要求传入的解包根目录已经存在：来源与身份检查已在上方通过，这里才创建。
        Directory.CreateDirectory(workRoot);

        var prepared = await PackageImporter.ImportAsync(source, knownModel, target, workRoot, token);

        // 窗口已在关闭：不保留这次结果，只释放它可能拥有的解包目录（原始目录不归本实例所有）。
        if (_closeRequested || _closed)
        {
            prepared.Dispose();
            return;
        }

        _importedPackage = prepared;
        _package = prepared.Validation;

        var validation = prepared.Validation;
        if (!validation.IsValid)
        {
            var reasons = string.Join(T("Dynamic.Package.ReasonSeparator"), validation.Reasons);
            SetText(PackageStatusText, "Dynamic.Package.StatusRejectedForModel", knownModel, reasons);
            AppendLocalizedLog(M("Dynamic.Log.PackageRejectedForModel", knownModel));
            SetText(ProgressStatusText, "Dynamic.Package.StatusRejectedShort");
        }
        else if (validation.TestOnly)
        {
            SetText(
                PackageStatusText,
                "Dynamic.Package.StatusTestOnlyForModel",
                knownModel,
                validation.PackageId,
                validation.Version);
            AppendLocalizedLog(
                M("Dynamic.Log.PackageTestOnlyForModel", knownModel, validation.PackageId, validation.Version));
            SetText(ProgressStatusText, "Dynamic.Progress.PackageValidated");
        }
        else
        {
            SetText(
                PackageStatusText,
                "Dynamic.Package.StatusValidForModel",
                knownModel,
                validation.PackageId,
                validation.Version);
            AppendLocalizedLog(
                M("Dynamic.Log.PackageValidForModel", knownModel, validation.PackageId, validation.Version));
            SetText(ProgressStatusText, "Dynamic.Progress.PackageValidated");
        }

        UpdateCapacityPanel();
        UpdateSummary();
    }

    // ---------- 路径与可用输入 ----------

    /// <summary>路径框改动时让上一次的准备结果失效，并释放它拥有的解包目录。</summary>
    private void InvalidatePreparedPackage(string statusKey)
    {
        var released = ReleasePreparedPackage();
        _plan = null;
        _capacityInitialized = false;

        if (released)
        {
            SetText(PackageStatusText, statusKey);
        }

        // 安装包变了，依赖它的容量计划与风险同意都必须重新确认。
        RiskCheck.IsChecked = false;

        UpdateCapacityPanel();
        UpdateSummary();
        RefreshActions();
    }

    /// <summary>设备身份失效时丢弃上一台设备 / 上一次型号的准备结果，但不改动安装包路径本身。</summary>
    private void ResetPreparedPackageForIdentityFailure()
    {
        var released = ReleasePreparedPackage();
        _plan = null;
        _capacityInitialized = false;

        if (released)
        {
            SetText(PackageStatusText, "Dynamic.Package.StatusNotValidated");
        }

        RiskCheck.IsChecked = false;
    }

    /// <summary>当前操作对应的安装目标：只有 TF 卡安装才要求安装包声明 TF。</summary>
    private InstallationTarget CurrentInstallTarget() =>
        CurrentModeTag() == "install-tf" ? InstallationTarget.TfCard : InstallationTarget.Internal;

    /// <summary>是否已经具备自动导入的三个输入：安装模式、已确认的实际型号、安装包路径。</summary>
    private bool HasImportInputs() =>
        IsInstallOperation(CurrentModeTag())
        && !string.IsNullOrWhiteSpace(_identity?.Model)
        && !string.IsNullOrWhiteSpace(PackagePathBox.Text);

    /// <summary>
    /// 解包根目录：界面测试用 FREEDOM_PACKAGE_WORK_ROOT 指向 NAS；否则用程序自己的缓存目录。
    /// 这里只负责算出路径，不创建目录 —— 目录由界面导入流程在来源与身份检查通过之后、
    /// 调用 Core 导入之前创建。
    /// </summary>
    private static string ResolvePackageWorkRoot()
    {
        var configured = Environment.GetEnvironmentVariable(PackageWorkRootVariable);
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return Path.GetFullPath(configured.Trim());
        }

        return Path.Combine(BundledTools.GetCacheRoot(), PackageImportsDirectoryName);
    }

    // ---------- 释放 ----------

    /// <summary>
    /// 释放当前准备结果及其拥有的解包目录。返回 <see langword="false"/> 表示清理失败，
    /// 调用方不能把它当成「已清理」继续往下走，也不能用成功状态覆盖这条失败说明。
    /// </summary>
    private bool ReleasePreparedPackage()
    {
        var prepared = _importedPackage;
        _importedPackage = null;
        _package = null;

        if (prepared is null)
        {
            return true;
        }

        try
        {
            prepared.Dispose();
            return true;
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or InvalidOperationException)
        {
            SetText(PackageStatusText, "Dynamic.Package.StatusCleanupFailed", exception.Message);
            AppendLocalizedLog(M("Dynamic.Log.PackageCleanupFailed", exception.Message));
            return false;
        }
    }

    /// <summary>窗口关闭时释放本次导入拥有的目录；已没有可呈现失败的位置，但绝不当成成功保留。</summary>
    private void DisposePreparedPackageOnClose()
    {
        var prepared = _importedPackage;
        _importedPackage = null;
        _package = null;

        if (prepared is null)
        {
            return;
        }

        try
        {
            prepared.Dispose();
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or InvalidOperationException)
        {
            // 窗口已关闭：不阻止退出，也不留下任何「已清理」的状态。
        }
    }

    // ---------- 关闭窗口 ----------

    /// <summary>
    /// 导入仍在进行时先取消并通过现有 CTS 让 Core 结束任务，等它释放自己拥有的解包目录后再真正关闭。
    /// 其他设备查询的关闭策略保持不变。
    /// </summary>
    protected override void OnClosing(CancelEventArgs e)
    {
        var importTask = _importTask;
        if (importTask is { IsCompleted: false })
        {
            _closeRequested = true;
            e.Cancel = true;
            _cts?.Cancel();
            _ = CloseAfterImportAsync(importTask);
            return;
        }

        base.OnClosing(e);
    }

    private async Task CloseAfterImportAsync(Task importTask)
    {
        try
        {
            await importTask;
        }
        catch (OperationCanceledException)
        {
            // 关闭流程主动取消：没有结果需要保留。
        }
        catch (Exception)
        {
            // 导入失败已经由 RunBusyAsync 写进状态与日志；关闭流程只等它结束。
        }

        if (!_closeRequested || _closed)
        {
            return;
        }

        _closeRequested = false;
        Close();
    }
}
