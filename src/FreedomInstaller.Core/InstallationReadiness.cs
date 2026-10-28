namespace FreedomInstaller.Core;

/// <summary>
/// Single gate in front of any write. Every input is already-verified state; this type only decides
/// whether the installer may proceed and why it may not.
/// </summary>
public static class InstallationReadiness
{
    /// <summary>
    /// Evaluates the installation gate.
    /// <para>
    /// Ready only when: a device identity is present, its bootloader is exactly
    /// <see cref="BootloaderState.Unlocked"/>, the A/B boot backup is verified, a valid package with storage
    /// is present, maintenance state is validated and an allocation plan exists.
    /// </para>
    /// <para>
    /// The bootloader check is an allow-list: only <see cref="BootloaderState.Unlocked"/> passes. Every other
    /// value blocks the gate, including the undefined enum values an unvalidated cast can produce, so an
    /// unconfirmed state can never be read as "not locked, therefore fine".
    /// </para>
    /// <para>
    /// A missing package is never ready, even when every other input is true: without a package there is
    /// nothing that could be written. Whenever <see cref="Readiness.IsReady"/> is false the reason list
    /// is non-empty and names each blocker; when it is true the list is empty.
    /// </para>
    /// <para>
    /// This gate is advisory only. It never touches a device and it does not enable any write path:
    /// write execution stays unimplemented until a real package contract and real maintenance
    /// integration exist.
    /// </para>
    /// </summary>
    public static Readiness Evaluate(
        DeviceIdentity? identity,
        bool backupsVerified,
        PackageValidationResult? package,
        bool maintenanceValidated,
        AllocationPlan? plan)
    {
        var reasons = new List<string>();

        // ---- device identity ------------------------------------------------------------
        if (identity is null)
        {
            reasons.Add("缺少设备身份：没有确认过的序列号、型号与引导状态，拒绝继续。");
        }
        else
        {
            if (string.IsNullOrWhiteSpace(identity.Serial))
            {
                reasons.Add("设备序列号缺失，无法确认目标设备。");
            }

            if (!DeviceProbe.IsSupportedModel(identity.Model))
            {
                reasons.Add($"设备型号 {Describe(identity.Model)} 不在支持列表（TB322FC / TB323FU）内。");
            }

            switch (identity.BootloaderState)
            {
                case BootloaderState.Unlocked:
                    // The only state that opens the gate.
                    break;
                case BootloaderState.Locked:
                    // A locked unit is not told to just unlock: a lock is one of the two supported
                    // generations' normal state, so the reason has to name the evidence a locked route
                    // would need. The gate itself is not loosened by this wording.
                    reasons.Add("引导加载程序仍处于锁定状态：锁定机型只能走一条经过验证、兼容且无需解锁的路线；当前执行适配器只支持已确认解锁的设备，因此本次安装无法继续。");
                    break;
                default:
                    // Unknown and every undefined enum value: unconfirmed never means "not locked".
                    reasons.Add("引导加载程序的解锁状态未知，未确认 device unlocked 前不允许写入。");
                    break;
            }
        }

        // ---- verified A/B boot backup ---------------------------------------------------
        if (!backupsVerified)
        {
            // This installer backs up the A/B boot partitions only; it never touches or restores userdata, so
            // the reason must not promise a userdata rollback that does not exist.
            reasons.Add("A/B boot 备份尚未完成或校验未通过：请先完成 A/B boot 备份并通过校验。本工具不备份用户数据，userdata 一旦清空无法通过本工具恢复。");
        }

        // ---- package --------------------------------------------------------------------
        if (package is null)
        {
            reasons.Add("缺少安装包校验结果：没有任何镜像可以被写入。");
        }
        else
        {
            if (!package.IsValid)
            {
                reasons.Add($"安装包校验未通过{DescribeReasons(package.Reasons)}。");
            }

            if (package.Storage is null)
            {
                reasons.Add("安装包未提供可信的存储容量声明，无法确认目标空间足够。");
            }
        }

        // ---- maintenance ----------------------------------------------------------------
        if (!maintenanceValidated)
        {
            reasons.Add("维护模式（maintenance）尚未验证，设备未处于可安全写入的状态。");
        }

        // ---- plan -----------------------------------------------------------------------
        if (plan is null)
        {
            reasons.Add("缺少分区规划结果，无法确定 userdata 的切分范围。");
        }

        return reasons.Count == 0
            ? new Readiness(true, Array.Empty<string>())
            : new Readiness(false, reasons);
    }

    private static string Describe(string? model) =>
        string.IsNullOrWhiteSpace(model) ? "（空）" : model.Trim();

    private static string DescribeReasons(IReadOnlyList<string>? packageReasons)
    {
        if (packageReasons is null || packageReasons.Count == 0)
        {
            return string.Empty;
        }

        var details = packageReasons.Where(reason => !string.IsNullOrWhiteSpace(reason)).ToArray();
        return details.Length == 0 ? string.Empty : "：" + string.Join("；", details);
    }
}
