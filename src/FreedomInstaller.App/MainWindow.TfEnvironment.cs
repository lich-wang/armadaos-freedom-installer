using System;
using System.IO;
using Microsoft.Win32;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

/// <summary>
/// 「安装到 TF 卡」的主机环境只读事实：这里只检查本机是否存在平板路线所需的
/// USB 网络驱动文件（UsbNcm.sys）——先看传统的 System32\drivers 文件，缺失时
/// 仅只读 UsbNcm 服务注册的 ImagePath（典型指向 DriverStore 的系统注册路径）再核对
/// 文件是否存在。不做进程/网络/驱动扫描，不安装/启动/启用/修改任何驱动，不写注册表。
/// 文件存在仅代表主机具备该驱动的可用性事实，绝不代表驱动已在内存就绪或 USB 网络
/// 连接已经可用；真正的连接核对由进入维护环境之后的控制器完成。本文件只负责在
/// 用户选择平板路线之前给出可行动的提示。
/// </summary>
public partial class MainWindow
{
    /// <summary>主机上是否存在平板 TF 路线所需的 USB 网络驱动文件（只读检查：传统 drivers 文件，或 UsbNcm 服务注册的 DriverStore/系统路径）。</summary>
    private bool HasTfTabletHostNetworkDriver()
    {
        // 事实一：传统路径 System32\drivers\UsbNcm.sys（部分 Win11 实机缺这个文件）。
        string legacyPath = Path.Combine(Environment.SystemDirectory, "drivers", "UsbNcm.sys");
        if (File.Exists(legacyPath))
        {
            return true;
        }

        // 事实二：只读 UsbNcm 服务注册的 ImagePath（典型指向
        // DriverStore\FileRepository\usbncm.inf_amd64_*\UsbNcm.sys）。仅此一处注册表读取，
        // 不枚举其他驱动服务、不查 INF、不写任何值；任何异常都按“不可用”返回而非崩溃。
        try
        {
            string rawValue;
            using (RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            using (RegistryKey serviceKey = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\UsbNcm"))
            {
                if (serviceKey == null)
                {
                    return false;
                }

                // 原样读取 REG_EXPAND_SZ（不做任意环境变量展开）；非字符串或空值视为不可用。
                rawValue = serviceKey.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
            }

            if (string.IsNullOrWhiteSpace(rawValue))
            {
                return false;
            }

            rawValue = rawValue.Trim();
            if (rawValue.Length >= 2 && rawValue[0] == '"' && rawValue[rawValue.Length - 1] == '"')
            {
                rawValue = rawValue.Substring(1, rawValue.Length - 2).Trim();
            }

            if (rawValue.Length == 0)
            {
                return false;
            }

            // Windows 根目录从本机实际的系统目录上一级推导（不硬编码盘符，不信任环境变量）。
            string systemDirectory = Path.GetFullPath(Environment.SystemDirectory);
            string windowsRoot = Path.GetFullPath(Path.Combine(systemDirectory, ".."));

            string candidate;
            if (rawValue.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase) ||
                rawValue.StartsWith("/SystemRoot/", StringComparison.OrdinalIgnoreCase))
            {
                // 内核式根前缀 \SystemRoot\（允许 / 分隔）映射到实际 Windows 根目录。
                candidate = Path.Combine(windowsRoot, rawValue.Substring(@"\SystemRoot\".Length));
            }
            else if (rawValue.StartsWith(@"%SystemRoot%\", StringComparison.OrdinalIgnoreCase) ||
                     rawValue.StartsWith("%SystemRoot%/", StringComparison.OrdinalIgnoreCase))
            {
                // 根令牌 %SystemRoot%\ 同样只映射到实际 Windows 根目录（依旧不做其他变量展开）。
                candidate = Path.Combine(windowsRoot, rawValue.Substring(@"%SystemRoot%\".Length));
            }
            else if (Path.IsPathFullyQualified(rawValue))
            {
                // 标准的完全限定绝对路径直接采用。
                candidate = rawValue;
            }
            else
            {
                // 其余格式（相对路径、设备路径等）一律视为不可用。
                return false;
            }

            if (!Path.IsPathFullyQualified(candidate))
            {
                return false;
            }

            // 先归一化再比对：包含 ..\ 的逃逸写法会在归一化后被下方的包含性检查拒绝。
            candidate = Path.GetFullPath(candidate);

            // 候选必须位于本机真实 System32 目录之下；前缀末尾带分隔符保证边界
            // （避免 System32Other 这类同前缀目录被误判成 System32 本身）。
            string systemPrefix = systemDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                + Path.DirectorySeparatorChar;
            if (!candidate.StartsWith(systemPrefix, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            // 基名必须恰好是 UsbNcm.sys（忽略大小写），且文件真实存在。
            if (!string.Equals(Path.GetFileName(candidate), "UsbNcm.sys", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            // 文件存在只是主机可用性事实，绝不代表驱动已在内存就绪或 USB 网络已连接。
            return File.Exists(candidate);
        }
        catch (Exception)
        {
            // 注册表/路径/文件访问的任何异常都按“不可用”返回，不让 GUI 崩溃。
            return false;
        }
    }

    /// <summary>
    /// 平板路线写入前的主机驱动文件门槛：文件存在即放行（只返回事实，不等于维护环境已就绪）；
    /// 缺失时登记本地化消息、写状态与日志并返回 false，任何临时启动写入都不应开始。
    /// 由现代平板 TF 控制器在写入临时引导之前实际调用，缺失时任何临时启动写入都不开始。
    /// </summary>
    private bool EnsureTfTabletHostNetworkDriverAvailable()
    {
        if (HasTfTabletHostNetworkDriver())
        {
            return true;
        }

        SetTfStatus(M("Dynamic.Tf.HostNetworkDriverRequired"));
        SetText(TfTabletHostDriverStatusText, "Dynamic.Tf.HostNetworkDriverRequired");
        AppendLocalizedLog(M("Dynamic.Tf.HostNetworkDriverRequired"));
        return false;
    }

    /// <summary>
    /// 只读渲染：仅在当前读取方式为「平板内」时显示主机驱动文件事实；
    /// 读卡器路线与此无关，说明行清空。只改文字，不影响选择、卡片与状态。
    /// </summary>
    private void RenderTfTabletHostDriverStatus()
    {
        if (_tfSource == TfCardSource.Tablet)
        {
            SetText(
                TfTabletHostDriverStatusText,
                HasTfTabletHostNetworkDriver()
                    ? "Dynamic.Tf.HostNetworkDriverAvailable"
                    : "Dynamic.Tf.HostNetworkDriverRequired");
        }
        else
        {
            // 走资源注册清空：语言切换时本地化注册表不会把平板状态重放进读卡器路线。
            SetText(TfTabletHostDriverStatusText, "Dynamic.RawValue", string.Empty);
        }
    }
}
