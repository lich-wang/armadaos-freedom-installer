using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Controls;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// 共享「默认非内部安装 ADB → 9008」管线：维护 / 卸载模式第 0 步的默认检查只读取真实安卓
/// 身份与 SoC 序列号（绝不经 Fastboot 往返），备份阶段自动进入 9008。
/// 这里只保存真实读取到的对象，绝不伪造 Ready、检查结果或锁态证据。
/// </summary>
public partial class MainWindow
{
    /// <summary>最近一次真实读取的安卓维护身份；null 表示没有可用事实，绝不是任何就绪证明。</summary>
    private AndroidMaintenanceIdentity? _sharedAdbAndroid;

    /// <summary>非内部安装的共享模式：维护、卸载与 TF 卡安装共用同一套默认检查与备份管线。</summary>
    private bool IsSharedNonInternalDeviceMode =>
        IsBootMaintenanceMode || IsModernUserdataUninstallMode || IsModernTfInstallMode;

    /// <summary>真实对象且完整：型号、序列号、完整固件 display id 与 SoC 序列号都不为空。</summary>
    private static bool IsSharedAndroidIdentityComplete(AndroidMaintenanceIdentity? android)
    {
        if (android is null)
        {
            return false;
        }

        var identity = android.Identity;
        return identity is not null
            && !string.IsNullOrWhiteSpace(identity.Model)
            && !string.IsNullOrWhiteSpace(identity.Serial)
            && !string.IsNullOrWhiteSpace(identity.Firmware?.DisplayId)
            && !string.IsNullOrWhiteSpace(android.SocSerial);
    }

    /// <summary>
    /// 共享安卓备份证明：仅表示「当前选中的真实 adb 设备身份已完整读取」，绝不表示
    /// BL 锁态已核实或备份已就绪；已勾选 9008 路线时由历史身份证明接管。
    /// </summary>
    private bool HasSharedAndroidBackupProof =>
        IsSharedNonInternalDeviceMode
        && !_bootMaintenanceAlreadyEdl
        && IsSharedAndroidIdentityComplete(_sharedAdbAndroid)
        && string.Equals(
            _sharedAdbAndroid!.Identity!.Serial,
            SelectedInternalInstallDevice()?.Serial,
            StringComparison.Ordinal);

    /// <summary>
    /// 备份前置门槛：完整维护证明，或（非内部模式）共享安卓身份读取事实。
    /// 这只是进入备份页 / 选目录的事实门槛，不是准备或执行就绪。
    /// </summary>
    private bool HasBootMaintenanceBackupPrerequisite =>
        HasBootMaintenanceDeviceProof || HasSharedAndroidBackupProof;

    /// <summary>
    /// 备份使用的真实安卓对象：完整检查存在时用检查返回的完整对象；否则仅当非内部模式
    /// 下共享读取事实完整时使用它。绝不从路径或勾选状态合成对象。
    /// </summary>
    private AndroidMaintenanceIdentity? CurrentAndroidForBackup
    {
        get
        {
            if (HasCheckedInternalInstallDevice)
            {
                return _internalInstallDeviceCheck!.Android;
            }

            return IsSharedNonInternalDeviceMode
                && IsSharedAndroidIdentityComplete(_sharedAdbAndroid)
                ? _sharedAdbAndroid
                : null;
        }
    }

    /// <summary>清掉共享安卓身份读取事实；由检查作废 / 换设备 / 不一致时调用。</summary>
    private void ClearSharedAndroidIdentity()
    {
        _sharedAdbAndroid = null;
    }

    // ---------- 共享默认检查 ----------

    /// <summary>
    /// 非内部模式的默认检查：只读一次真实身份与 SoC 序列号，按实际型号核对可信配置
    /// 完整且支持这台平板后，才提交读取事实并采样电量。绝不发 Fastboot 命令，
    /// 也绝不声称已核实 Bootloader 锁态。异常向上传播给既有失败处理。
    /// </summary>
    private async Task CheckSharedAndroidTargetAsync(string serial, CancellationToken token)
    {
        var transport = _transport;
        if (transport is null || _runner is null)
        {
            SetInternalInstallCheckStatus(M("Dynamic.InternalInstall.Check.ToolsRequired"));
            return;
        }

        // 每次都是一次全新读取：先作废上一轮事实，失败时自然回到「无证明」。
        _sharedAdbAndroid = null;

        SetInternalInstallCheckProgress(M("Dynamic.InternalInstall.Check.Progress.ReadingAndroid"));

        var identity = await transport.ReadAdbIdentityAsync(serial, token);
        var maintenance = new MaintenanceEntry(
            transport.AdbPath,
            transport.FastbootPath,
            _runner);
        var android = await maintenance.ReadAndroidAsync(identity, token);

        var profile = EdlDeviceProfiles.FindByModel(android.Identity?.Model);
        if (android.Identity is null
            || profile is null
            || !profile.IsComplete
            || !profile.SupportsIdentity(android.Identity)
            || string.IsNullOrWhiteSpace(profile.ArchiveLogicalName))
        {
            SetInternalInstallCheckStatus(
                M(
                    "Dynamic.InternalInstall.Backup.ProfileUnavailable",
                    Placeholder(android.Identity?.Model),
                    Placeholder(android.Identity?.Firmware?.DisplayId)));
            return;
        }

        // 与完整检查同源：只在确认回到安卓后只读采样一次电量；读不到保持未知。
        _internalInstallPower = await CaptureInternalInstallPowerAsync(
            transport.AdbPath,
            serial,
            token);
        RenderInternalInstallPower();

        _sharedAdbAndroid = android;
        RenderSharedDeviceIdentity(android);
        SetInternalInstallCheckStatus(M("Dynamic.Shared.IdentityReadStatus"));
        RefreshInternalInstallActions();
    }

    /// <summary>共享读取事实的字段渲染：型号 / 序列号 / 固件来自返回值，锁态明确写未知。</summary>
    private void RenderSharedDeviceIdentity(AndroidMaintenanceIdentity android)
    {
        if (!_ready)
        {
            return;
        }

        var identity = android.Identity;
        SetText(InternalInstallModelText, "Dynamic.RawValue", Placeholder(identity?.Model));
        SetText(InternalInstallSerialText, "Dynamic.RawValue", Placeholder(identity?.Serial));
        SetText(InternalInstallFirmwareText, "Dynamic.RawValue", Placeholder(identity?.Firmware?.DisplayId));
        SetText(InternalInstallBootloaderText, BootStateKey(BootloaderState.Unknown));
    }

    // ---------- 共享控件刷新 ----------

    /// <summary>
    /// 高级 Fastboot 核验按钮只在完全空闲、无保护状态、没有活跃 9008 现场且有传输工具时可用；
    /// 由两种模式的渲染 / 动作刷新与检查按钮渲染共同调用。
    /// </summary>
    private void RefreshSharedAdvancedCheckAvailability()
    {
        if (!_ready || SharedFastbootCheckButton is null)
        {
            return;
        }

        var idle = !_busy
            && !_internalInstallOperationActive
            && !_bootMaintenanceOperationActive
            && !_userdataUninstallOperationActive
            && !_tfInstallOperationActive;
        var protectedState =
            (IsBootMaintenanceMode && ProtectedBootMaintenanceState)
            || (IsModernUserdataUninstallMode && ProtectedModernUserdataUninstallState)
            || (IsModernTfInstallMode && ProtectedModernTfInstallState);

        SetContent(SharedFastbootCheckButton, "Dynamic.Shared.AdvancedCheckButton");
        SharedFastbootCheckButton.IsEnabled = idle
            && !protectedState
            && !HasInternalInstallLiveEdlState
            && !_bootMaintenanceAlreadyEdl
            && _transport is not null;
    }

    /// <summary>
    /// 第 0 步说明文字：非内部模式显示共享读取说明；内部安装恢复原有静态资源。
    /// 走 SetText 机制，语言切换后按新语言重绘。
    /// </summary>
    private void RenderSharedDeviceEntryLead()
    {
        if (!_ready || SharedDeviceCheckLead is null)
        {
            return;
        }

        if (IsSharedNonInternalDeviceMode)
        {
            SetText(SharedDeviceCheckLead, "Dynamic.Shared.DeviceCheckLead");
        }
        else
        {
            SetText(SharedDeviceCheckLead, "Static.InternalInstall.Check.Lead");
        }
    }
}
