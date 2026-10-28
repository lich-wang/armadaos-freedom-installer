using System;
using System.Collections.Generic;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// 引导兼容性：固件、Android 上报与免解锁候选路线的只读渲染。
/// <para>
/// 本文件不做任何判定：路线状态由 Core 的 <see cref="BootRouteAssessment.Evaluate"/> 决定，
/// 这里只把结果按当前语言写成文案。固件显示 ID、构建指纹、Android 版本、安全补丁与
/// Android 自身上报的 BL 状态全部来自设备身份（getprop），一个字节都不会被写回设备。
/// </para>
/// <para>
/// Android 上报始终标成「仅供参考」：它不是 Fastboot 的结论，所以本文件绝不会因为
/// 这个字段把设备当成已确认解锁，也不会替用户决定解锁或写入。
/// </para>
/// <para>
/// 连接页的固件行与路线提示、确认页的小面板都由 <see cref="RenderBootRoute"/> 写入，
/// 因此「身份读取成功 / 失败 / 清除设备 / Fastboot 查询前后 / 切换语言 / 启动」看到的永远是同一份状态，
/// 换设备后不会残留上一台设备的结论。
/// </para>
/// </summary>
public partial class MainWindow
{
    /// <summary>
    /// 引导兼容性唯一的渲染入口。调用点：构造函数、身份读取失败、<see cref="UpdateSummary"/>
    /// （覆盖身份读取成功、Fastboot 查询前后、语言切换、清除设备与初始化）。
    /// </summary>
    private void RenderBootRoute()
    {
        var firmware = _identity?.Firmware;

        var firmwareValue = DescribeFirmware(firmware);
        var androidValue = DescribeAndroidVersion(firmware);
        var androidReportValue = DescribeAndroidBootReport(firmware);

        // 连接页：三行真实值。以「Dynamic.RawValue」登记，切换语言后按原消息重写。
        SetText(FirmwareText, "Dynamic.RawValue", firmwareValue);
        SetText(AndroidVersionText, "Dynamic.RawValue", androidValue);
        SetText(AndroidBootReportText, "Dynamic.RawValue", androidReportValue);

        // 路线判定完全来自 Core；这里只按状态选文案，不参与判断。
        var status = BootRouteAssessment.Evaluate(_identity);
        var uninstall = CurrentModeTag() == "uninstall";

        // 卸载模式：连接页直接给出 9008（EDL）入口状态与下一步，不再要求手动进入 Fastboot
        // 或启动临时 RAM。仅覆盖文案，Core 判定与固件 / Android 上报保持原样。
        UiMessage statusMessage = uninstall
            ? M("Dynamic.UninstallFlow.Edl.Title")
            : M(BootRouteStatusKey(status));
        UiMessage nextMessage = uninstall
            ? GetUninstallEdlMessage()
            : M(BootRouteNextStepKey(status));

        SetText(BootRouteStatusText, statusMessage);
        SetText(BootRouteNextStepText, nextMessage);

        // 连接页的通用身份提示按模式改写：只处理已知的身份/维护状态提示与 9008 入口提示，
        // 失败与其他诊断文案保持原样；切换模式或语言后由本入口重新刷新。
        if (_identity is not null
            && _localizedProperties.TryGetValue((DeviceHintText, "Text"), out var hint)
            && (hint.Message.Key is "Dynamic.DeviceHint.IdentityConfirmed"
                    or "Dynamic.DeviceHint.UninstallIdentityConfirmed"
                    or "Dynamic.UninstallFlow.Maintenance.StatusConnected"
                    or "Dynamic.UninstallFlow.Maintenance.StatusBootingDone"
                    or "Dynamic.UninstallFlow.Verify.Accepted"
                    or "Dynamic.UninstallFlow.Verify.AcceptedFilesystem"
                    or "Dynamic.UninstallFlow.Verify.AcceptedFilesystemOnly"
                || hint.Message.Key.StartsWith("Dynamic.UninstallFlow.Edl.", StringComparison.Ordinal)
                || hint.Message.Key.StartsWith("Dynamic.UninstallFlow.EdlRestore.", StringComparison.Ordinal)
                || hint.Message.Key.StartsWith("Dynamic.UninstallFlow.EdlVerify.", StringComparison.Ordinal)))
        {
            SetText(
                DeviceHintText,
                uninstall ? GetUninstallEdlMessage() : M("Dynamic.DeviceHint.IdentityConfirmed"));
        }

        // 确认页的小面板：所有模式共用同一份数据，不进入任何 SummaryText 的格式约定。
        SetText(
            ConfirmBootRouteSourceText,
            _identity is null ? "Dynamic.Confirm.BootRoute.SourceMissing" : "Dynamic.Confirm.BootRoute.SourceDevice");
        SetText(ConfirmFirmwareText, "Dynamic.Confirm.BootRoute.Firmware", firmwareValue);
        SetText(ConfirmAndroidText, "Dynamic.Confirm.BootRoute.Android", androidValue);
        SetText(ConfirmAndroidBootReportText, "Dynamic.Confirm.BootRoute.AndroidReport", androidReportValue);
        SetText(ConfirmBootRouteStatusText, statusMessage);
        SetText(ConfirmBootRouteNextStepText, nextMessage);
    }

    /// <summary>固件显示：优先设备上报的显示 ID，缺失时退回构建指纹；两者都没有才显示占位符。</summary>
    private static string DescribeFirmware(FirmwareSnapshot? firmware)
    {
        var displayId = firmware?.DisplayId;
        if (!string.IsNullOrWhiteSpace(displayId))
        {
            return displayId!.Trim();
        }

        var fingerprint = firmware?.BuildFingerprint;
        return string.IsNullOrWhiteSpace(fingerprint) ? UnknownValue : fingerprint!.Trim();
    }

    /// <summary>
    /// Android 版本行：只拼接设备真实上报的字段，缺哪个就不写哪个，两个都缺才显示占位符。
    /// 分隔符与标签都取当前语言，所以切换语言后由 <see cref="RenderBootRoute"/> 重算即可。
    /// </summary>
    private string DescribeAndroidVersion(FirmwareSnapshot? firmware)
    {
        var parts = new List<string>(2);

        var release = firmware?.AndroidRelease;
        if (!string.IsNullOrWhiteSpace(release))
        {
            parts.Add(T("Dynamic.Firmware.ReleaseFormat", release!.Trim()));
        }

        var patch = firmware?.SecurityPatch;
        if (!string.IsNullOrWhiteSpace(patch))
        {
            parts.Add(T("Dynamic.Firmware.PatchFormat", patch!.Trim()));
        }

        return parts.Count == 0 ? UnknownValue : string.Join(T("Dynamic.Firmware.Separator"), parts);
    }

    /// <summary>
    /// Android 上报的 BL 状态。快照字段是 <see cref="BootloaderState"/> 枚举，不是 getprop 原文：
    /// 已锁定 / 已解锁各有固定文案，其余取值（含未知）统一写成「未上报」，
    /// 任何情况都不升级成「已通过 Fastboot 确认」。
    /// </summary>
    private string DescribeAndroidBootReport(FirmwareSnapshot? firmware)
    {
        return firmware?.AndroidReportedBootloaderState switch
        {
            BootloaderState.Locked => T("Dynamic.Firmware.AndroidReport.Locked"),
            BootloaderState.Unlocked => T("Dynamic.Firmware.AndroidReport.Unlocked"),
            _ => T("Dynamic.Firmware.AndroidReport.Missing"),
        };
    }

    /// <summary>路线状态的标题文案。七种状态都有独立文案，未知取值退回「待读取设备」。</summary>
    private static string BootRouteStatusKey(BootRouteStatus status) => status switch
    {
        BootRouteStatus.UnsupportedModel => "Dynamic.BootRoute.Status.UnsupportedModel",
        BootRouteStatus.PendingLockState => "Dynamic.BootRoute.Status.PendingLockState",
        BootRouteStatus.FastbootConfirmationRequired => "Dynamic.BootRoute.Status.FastbootConfirmationRequired",
        BootRouteStatus.UnlockedRoute => "Dynamic.BootRoute.Status.UnlockedRoute",
        BootRouteStatus.LockedEdlCandidate => "Dynamic.BootRoute.Status.LockedEdlCandidate",
        BootRouteStatus.LockedRouteUnsupported => "Dynamic.BootRoute.Status.LockedRouteUnsupported",
        _ => "Dynamic.BootRoute.Status.PendingDevice",
    };

    /// <summary>与状态文案配套的简短下一步；同样是纯文案，不含任何写入动作。</summary>
    private static string BootRouteNextStepKey(BootRouteStatus status) => status switch
    {
        BootRouteStatus.UnsupportedModel => "Dynamic.BootRoute.Next.UnsupportedModel",
        BootRouteStatus.PendingLockState => "Dynamic.BootRoute.Next.PendingLockState",
        BootRouteStatus.FastbootConfirmationRequired => "Dynamic.BootRoute.Next.FastbootConfirmationRequired",
        BootRouteStatus.UnlockedRoute => "Dynamic.BootRoute.Next.UnlockedRoute",
        BootRouteStatus.LockedEdlCandidate => "Dynamic.BootRoute.Next.LockedEdlCandidate",
        BootRouteStatus.LockedRouteUnsupported => "Dynamic.BootRoute.Next.LockedRouteUnsupported",
        _ => "Dynamic.BootRoute.Next.PendingDevice",
    };
}
