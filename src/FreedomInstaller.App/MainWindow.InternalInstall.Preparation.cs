using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// 「安装到内部存储」的主机侧准备：把程序集内置的两个 EDL 原始引导工具解到用户选定备份父目录下的
/// 独立子目录，再交给 Core 的 <see cref="EdlRawBootTools"/> / <see cref="InternalInstallDirectAssets"/>
/// 按编译期引脚复核并持有独立只读租约。
/// <para>
/// 这里只保存真实工厂返回的 <see cref="InternalInstallBackend"/> 以及它需要的工具租约；没有任何
/// 预备就绪标记、占位对象或写死结论。整个准备过程不做设备写入、不进入 9008、不删除用户文件。
/// </para>
/// <para>
/// 释放顺序固定为：后端 → 直装工具集 → 本机工具。只有在各自 Dispose 成功后才清空字段，
/// 客户端、工具链、备份、系统包与方案对象都不在这里释放或删除。
/// </para>
/// </summary>
public partial class MainWindow
{
    /// <summary>EDL 原始引导打包工具的逻辑资源名；构建只按属性嵌入，运行时只按这个名字读取。</summary>
    private const string InternalEdlRawPackerResource = "FreedomInstaller.EdlRawPacker.exe";

    /// <summary>EDL 原始引导解包工具的逻辑资源名；同样只按固定名字读取。</summary>
    private const string InternalEdlRawUnpackerResource = "FreedomInstaller.EdlRawUnpacker.exe";

    /// <summary>内置安装组件解出目录名；只在用户显式选择的备份父目录下创建。</summary>
    private const string InternalInstallAssetsDirectoryName = ".armada-install-assets";

    /// <summary>有界拷贝 / 哈希缓冲：1 MiB，避免把上百 MiB 的镜像整体读进内存。</summary>
    private const int InternalInstallCopyBufferBytes = 1024 * 1024;

    /// <summary>真实工厂返回的后端；null 表示当前分配还没有可确认的安装上下文。</summary>
    private InternalInstallBackend? _internalInstallBackend;

    /// <summary>Core 复核过编译期引脚并持有独立只读租约的直装工具集。</summary>
    private InternalInstallDirectAssets? _internalInstallAssets;

    /// <summary>解出的两个本机工具及其只读租约；直装工具集释放后才轮到它。</summary>
    private EdlRawBootTools? _internalInstallNativeTools;

    /// <summary>实际解出内置组件的目录，仅用于诊断日志，不参与任何门槛判断。</summary>
    private string? _internalInstallAssetsDirectory;

    /// <summary>
    /// 准备并调用真实工厂。所有输入都必须是已经存在的真实对象：同一台设备的检查结果、同一个
    /// 9008 客户端、真实备份、有效系统包与真实方案对象。
    /// </summary>
    /// <exception cref="InvalidOperationException">任何真实输入缺失。</exception>
    /// <exception cref="OperationCanceledException">准备被取消，或窗口在保存后端前关闭。</exception>
    private async Task<InternalInstallBackend> PrepareInternalInstallBackendAsync(
        string evidenceParent,
        CancellationToken cancellationToken)
    {
        var check = _internalInstallDeviceCheck;
        var client = _internalInstallEdlClient;
        var entry = _internalInstallEdlEntry;
        var backup = _internalInstallBackup;
        var package = _internalInstallPackage;
        var artifacts = _internalInstallArtifacts;
        var transport = _transport;

        if (check is null
            || client is null
            || entry is null
            || backup is null
            || package is null
            || artifacts is null
            || transport is null
            || string.IsNullOrWhiteSpace(transport.AdbPath)
            || !HasCheckedInternalInstallDevice)
        {
            throw new InvalidOperationException(T("Dynamic.InternalInstall.Prepared.NeedInputs"));
        }

        await EnsureInternalInstallAssetsAsync(evidenceParent, backup, cancellationToken);

        var assets = _internalInstallAssets
            ?? throw new InvalidOperationException(T("Dynamic.InternalInstall.Prepared.AssetsMissing"));

        // 同一个初始客户端只用于只读证据；EdlEntry 在这里只是服务的引用，不调用 EnterAsync。
        var discovery = new WindowsEdlEndpointDiscovery();
        var services = new InternalInstallServices(
            new EdlEntry(transport.AdbPath, _runner, discovery),
            _runner,
            discovery,
            transport.AdbPath);

        if (_ready)
        {
            SetInternalInstallConfirmStatus(M("Dynamic.InternalInstall.Prepared.CheckingFactory"));
        }

        var backend = await InternalInstallBackend.CreatePreparedAsync(
            check,
            client,
            backup,
            artifacts,
            package,
            assets,
            services,
            evidenceParent,
            cancellationToken);

        if (_closeRequested || _closed)
        {
            // 窗口已经关闭：只释放刚返回的后端自己的租约，不碰调用方的任何对象。
            backend.Dispose();
            throw new OperationCanceledException();
        }

        _internalInstallBackend = backend;
        // 新后端就是新的安装前复核起点：旧的界面失败原因与上一次关闭批准都不再适用。
        _internalInstallExecutionError = null;
        _internalInstallPostWriteCloseApproved = false;
        return backend;
    }

    /// <summary>
    /// 只在真实备份与检查都成立时解出两个内置本机工具。已经成功加载的工具会在同一次方案的只读工厂
    /// 重试中复用，不重复拷贝或哈希；失败时只释放尚未保存的工具集与工具，解出的材料文件保留在用户目录供诊断。
    /// </summary>
    private async Task EnsureInternalInstallAssetsAsync(
        string evidenceParent,
        InternalBackupSet backup,
        CancellationToken cancellationToken)
    {
        if (_internalInstallAssets is not null && _internalInstallNativeTools is not null)
        {
            return;
        }

        var materialDirectory = Path.Combine(
            evidenceParent,
            InternalInstallAssetsDirectoryName,
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(materialDirectory);

        var packerPath = Path.Combine(materialDirectory, "MultiBootKernelPatcher.exe");
        var unpackerPath = Path.Combine(materialDirectory, "UnpackTool.exe");

        EdlRawBootTools? pendingTools = null;
        InternalInstallDirectAssets? pendingAssets = null;
        try
        {
            var packerClaim = await ExtractInternalInstallResourceAsync(
                InternalEdlRawPackerResource,
                packerPath,
                cancellationToken);
            var unpackerClaim = await ExtractInternalInstallResourceAsync(
                InternalEdlRawUnpackerResource,
                unpackerPath,
                cancellationToken);

            // 解出的只是调用方声明；Core 用自己的编译期引脚独立复核，再以只读租约打开真实文件。
            pendingTools = await EdlRawBootTools.LoadAsync(
                packerClaim,
                unpackerClaim,
                cancellationToken);

            // 直装工具集在这份工具上再取一份独立租约；它从不接管、也不释放上面的工具。
            pendingAssets = await InternalInstallDirectAssets.LoadAsync(
                pendingTools,
                cancellationToken);

            if (_closeRequested || _closed)
            {
                throw new OperationCanceledException();
            }

            _internalInstallNativeTools = pendingTools;
            pendingTools = null;
            _internalInstallAssets = pendingAssets;
            pendingAssets = null;
            _internalInstallAssetsDirectory = materialDirectory;

            AppendLocalizedLog(
                M("Dynamic.InternalInstall.Prepared.MaterialsReady", materialDirectory));
        }
        catch
        {
            // 顺序与持有顺序相反；已解出的材料文件留在显式父目录下，不递归删除。
            pendingAssets?.Dispose();
            pendingTools?.Dispose();
            throw;
        }
    }

    /// <summary>
    /// 有界地拷贝一个内置资源到显式文件，再重新打开同一文件计算实际长度与 SHA-256。
    /// 返回的只是调用方声明，Core 会用自己的编译期引脚独立复核。
    /// </summary>
    private async Task<VerifiedEdlFile> ExtractInternalInstallResourceAsync(
        string logicalName,
        string destinationPath,
        CancellationToken cancellationToken)
    {
        using var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream(logicalName)
            ?? throw new InvalidOperationException(
                T("Dynamic.InternalInstall.Prepared.ComponentsMissing", logicalName));

        await using (var destination = new FileStream(
            destinationPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            InternalInstallCopyBufferBytes,
            FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            await resource.CopyToAsync(destination, InternalInstallCopyBufferBytes, cancellationToken)
                .ConfigureAwait(false);
        }

        await using var verify = new FileStream(
            destinationPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            InternalInstallCopyBufferBytes,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        var length = verify.Length;
        var sha256 = await SHA256.HashDataAsync(verify, cancellationToken).ConfigureAwait(false);
        return new VerifiedEdlFile(destinationPath, length, Convert.ToHexStringLower(sha256));
    }

    /// <summary>
    /// 释放本工单持有的后端、直装工具集与本机工具：后端必须最先释放，本机工具最后释放。
    /// 只有各自 Dispose 成功后才清空对应字段，异常不被吞掉，避免活动租约被悄悄丢掉。
    /// </summary>
    private void ReleaseInternalInstallPreparedBackend()
    {
        var backend = _internalInstallBackend;
        if (backend is not null)
        {
            // 真实执行/复查仍在进行，或已经真正开始写入但未到真实终态且没有关闭批准：
            // 在任何字段、资产或文件被清掉之前显式抛错，调用方链条不会带着半清状态继续。
            if (!CanReleaseInternalInstallBackend(backend))
            {
                throw new InvalidOperationException(
                    T("Dynamic.InternalInstall.Execution.ReleaseBlocked"));
            }

            backend.Dispose();
            _internalInstallBackend = null;

            // 只有真正释放成功之后才允许下一次执行；方法失败或异常都不会重置这个标志。
            _internalInstallExecuteAttempted = false;
            _internalInstallAttemptedBackend = null;
            _internalInstallExecutionError = null;
        }

        // 直装工具集持有从本机工具派生出来的独立租约，必须先于本机工具释放。
        var assets = _internalInstallAssets;
        if (assets is not null)
        {
            assets.Dispose();
            _internalInstallAssets = null;
        }

        var tools = _internalInstallNativeTools;
        if (tools is not null)
        {
            tools.Dispose();
            _internalInstallNativeTools = null;
        }

        _internalInstallAssetsDirectory = null;
    }
}
