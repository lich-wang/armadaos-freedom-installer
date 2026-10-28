namespace FreedomInstaller.Core;

/// <summary>
/// Turns the device's existing userdata extent plus the requested Android share into absolute
/// sector boundaries. Pure arithmetic: no disk access, no device command, no float.
/// </summary>
public static class PartitionPlanner
{
    private const long KiB = 1024L;
    private const long MiB = 1024L * KiB;
    private const long GiB = 1024L * MiB;

    /// <summary>
    /// Smallest Linux root the device side accepts (KshimPlan requires root &gt;= 32 GiB). It is a hard
    /// floor: a package that declares less can only raise the requirement, never lower it, and both
    /// <see cref="Plan"/> and <see cref="GetAndroidRange"/> use this single rule.
    /// </summary>
    private const long MinimumLinuxRootBytes = 32L * GiB;

    private const string UserdataName = "userdata";

    /// <summary>
    /// Plans the userdata split.
    /// <para>
    /// Layout rules: exactly one partition named "userdata" (case-insensitive) must exist, and it must be the
    /// physically last partition: every other extent must end at or before the userdata start. The GPT dump
    /// may be ordered by partition number instead of by physical position, so list order is deliberately
    /// ignored; the input list is never sorted, reordered or otherwise mutated. A structural violation throws
    /// <see cref="InvalidOperationException"/>, and so does a sector size that is not a power of two dividing
    /// 1 MiB (only 512 and 4096 are expected in practice).
    /// </para>
    /// <para>
    /// Size rules: <paramref name="androidGiB"/> must be positive and not below
    /// <paramref name="androidMinimumGiB"/>; Linux boot, system image and minimum Linux data from
    /// <paramref name="storage"/> must be positive and the deployment scratch may be zero; Linux boot
    /// must be 1 MiB aligned and the userdata start must be 1 MiB aligned, because a layout that cannot
    /// be respected as reported is rejected instead of being silently rearranged; the Linux root must
    /// still host the system image, the deployment scratch and the minimum Linux data, and must never be
    /// smaller than the 32 GiB the device itself demands, so the effective minimum root is
    /// <c>max(32 GiB, system + scratch + minimum data)</c>. A size violation, including arithmetic
    /// overflow, throws <see cref="ArgumentException"/>. <paramref name="androidMinimumGiB"/> may still
    /// be zero for callers that have no confirmed model minimum; <see cref="GetAndroidRange"/> is the
    /// entry point that refuses an unknown lower bound.
    /// </para>
    /// <para>
    /// Result: <c>AndroidBytes = androidGiB * 1 GiB</c>, <c>LinuxBytes = userdataBytes - AndroidBytes</c>,
    /// <c>LinuxBootBytes</c> from the package, <c>LinuxRootBytes = LinuxBytes - LinuxBootBytes</c>,
    /// <c>EstimatedLinuxDataBytes = LinuxRootBytes - SystemRequiredBytes</c> (deployment scratch is
    /// transient and released after deployment). Sector fields are absolute and derived from the
    /// userdata start sector, so <c>EndSectorExclusive</c> is always the end of the userdata extent
    /// and earlier partitions stay untouched.
    /// </para>
    /// </summary>
    public static AllocationPlan Plan(
        DiskLayout layout,
        long androidGiB,
        long androidMinimumGiB,
        PackageStorage storage)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(storage);

        var sectorSize = RequireSectorSize(layout.SectorSize);

        var partitions = layout.Partitions;
        if (partitions is null)
        {
            throw new InvalidOperationException("分区表为空，设备没有报告任何分区，无法规划 userdata 切分。");
        }

        RequireAndroidShare(androidGiB, androidMinimumGiB);
        RequireStorage(storage);

        // ---- structural validation of the reported layout --------------------------------

        DiskPartition? userdata = null;
        var seenNumbers = new HashSet<long>();

        for (var index = 0; index < partitions.Count; index++)
        {
            var partition = partitions[index];
            if (partition is null)
            {
                throw new InvalidOperationException($"分区表第 {index} 项为 null，无法信任该分区表。");
            }

            if (partition.SectorCount <= 0)
            {
                throw new InvalidOperationException($"分区 {Describe(partition)} 的扇区数量必须为正数。");
            }

            if (partition.StartSector < 0)
            {
                throw new InvalidOperationException($"分区 {Describe(partition)} 的起始扇区不能为负数。");
            }

            if (partition.StartSector > long.MaxValue - partition.SectorCount)
            {
                throw new ArgumentException(
                    $"分区 {Describe(partition)} 的扇区范围超出 64 位可表示范围。",
                    nameof(layout));
            }

            if (!seenNumbers.Add(partition.Number))
            {
                throw new InvalidOperationException($"分区号 {partition.Number} 在分区表中重复出现，拒绝猜测目标分区。");
            }

            if (string.Equals(partition.Name?.Trim(), UserdataName, StringComparison.OrdinalIgnoreCase))
            {
                if (userdata is not null)
                {
                    throw new InvalidOperationException("分区表中出现多个 userdata 分区，拒绝在其中挑选一个。");
                }

                userdata = partition;
            }
        }

        if (userdata is null)
        {
            throw new InvalidOperationException("分区表中没有 userdata 分区，无法切分。");
        }

        // userdata must be the physically last extent. The GPT dump can be ordered by partition number
        // instead of by position, so list order proves nothing and is never used here; the input list is
        // also never sorted or otherwise mutated.
        foreach (var partition in partitions)
        {
            if (ReferenceEquals(partition, userdata))
            {
                continue;
            }

            // Both extents were checked for overflow above, so this sum is representable.
            if (partition.StartSector + partition.SectorCount > userdata.StartSector)
            {
                throw new InvalidOperationException(
                    $"分区 {Describe(partition)} 的物理范围位于 userdata（起始扇区 {userdata.StartSector}）之后，拒绝通过移动后续分区来腾出空间。");
            }
        }

        for (var first = 0; first < partitions.Count; first++)
        {
            for (var second = first + 1; second < partitions.Count; second++)
            {
                if (Overlaps(partitions[first], partitions[second]))
                {
                    throw new InvalidOperationException(
                        $"分区 {Describe(partitions[first])} 与 {Describe(partitions[second])} 的扇区范围重叠，分区表不可信。");
                }
            }
        }

        // ---- size arithmetic (checked, integer only) ------------------------------------

        long userdataBytes;
        try
        {
            userdataBytes = checked(userdata.SectorCount * sectorSize);
        }
        catch (OverflowException exception)
        {
            throw new ArgumentException(
                "userdata 的扇区数量换算成字节时溢出 64 位范围，拒绝规划。",
                nameof(layout),
                exception);
        }

        long androidBytes;
        try
        {
            androidBytes = checked(androidGiB * GiB);
        }
        catch (OverflowException exception)
        {
            throw new ArgumentException(
                $"要为 Android 保留 {androidGiB} GiB，换算成字节时溢出 64 位范围。",
                nameof(androidGiB),
                exception);
        }

        long userdataStartBytes;
        try
        {
            userdataStartBytes = checked(userdata.StartSector * sectorSize);
        }
        catch (OverflowException exception)
        {
            throw new ArgumentException(
                "userdata 的起始扇区换算成字节时溢出 64 位范围，拒绝规划。",
                nameof(layout),
                exception);
        }

        if (userdataStartBytes % MiB != 0)
        {
            throw new ArgumentException(
                "userdata 的起始位置没有按 1 MiB 对齐，拒绝在未对齐的布局上规划。",
                nameof(layout));
        }

        var linuxBytes = userdataBytes - androidBytes;
        if (linuxBytes <= 0)
        {
            throw new ArgumentException(
                $"Android 需要 {androidGiB} GiB，但 userdata 总共只有 {userdataBytes / GiB} GiB，Linux 侧没有剩余空间。",
                nameof(androidGiB));
        }

        var linuxBootBytes = storage.LinuxBootBytes;
        var linuxRootBytes = linuxBytes - linuxBootBytes;

        // Shared with GetAndroidRange: the device floor of 32 GiB wins over a smaller package demand.
        var requiredRootBytes = MinimumRootBytes(storage);

        if (linuxRootBytes < requiredRootBytes)
        {
            throw new ArgumentException(
                $"Linux root 只剩 {linuxRootBytes / MiB} MiB，低于系统镜像、部署 scratch、最小数据与设备端 32 GiB 下限合成的 {requiredRootBytes / MiB} MiB。",
                nameof(androidGiB));
        }

        var estimatedLinuxDataBytes = linuxRootBytes - storage.SystemRequiredBytes;

        // ---- absolute sector boundaries -------------------------------------------------

        var androidSectorCount = androidBytes / sectorSize;
        var linuxBootSectorCount = linuxBootBytes / sectorSize;
        var linuxRootSectorCount = linuxRootBytes / sectorSize;

        long linuxBootStartSector;
        long linuxRootStartSector;
        long endSectorExclusive;
        try
        {
            linuxBootStartSector = checked(userdata.StartSector + androidSectorCount);
            linuxRootStartSector = checked(linuxBootStartSector + linuxBootSectorCount);
            endSectorExclusive = checked(userdata.StartSector + userdata.SectorCount);
        }
        catch (OverflowException exception)
        {
            throw new ArgumentException(
                "计算绝对扇区边界时溢出 64 位范围，拒绝规划。",
                nameof(layout),
                exception);
        }

        var boundariesConsistent = false;
        try
        {
            boundariesConsistent = linuxRootBytes % sectorSize == 0
                && checked(linuxRootStartSector + linuxRootSectorCount) == endSectorExclusive;
        }
        catch (OverflowException)
        {
            boundariesConsistent = false;
        }

        if (!boundariesConsistent)
        {
            throw new InvalidOperationException("推导出的扇区边界与 userdata 末端不一致，拒绝输出不可信的分区表。");
        }

        return new AllocationPlan(
            AndroidBytes: androidBytes,
            LinuxBytes: linuxBytes,
            LinuxBootBytes: linuxBootBytes,
            LinuxRootBytes: linuxRootBytes,
            EstimatedLinuxDataBytes: estimatedLinuxDataBytes,
            UserdataStartSector: userdata.StartSector,
            AndroidSectorCount: androidSectorCount,
            LinuxBootStartSector: linuxBootStartSector,
            LinuxRootStartSector: linuxRootStartSector,
            EndSectorExclusive: endSectorExclusive);
    }

    /// <summary>
    /// Reports the inclusive GiB interval the Android share may take on <paramref name="layout"/>.
    /// <para>
    /// <paramref name="androidMinimumGiB"/> is the model's confirmed minimum and must be positive: an
    /// unknown or unconfirmed lower bound is refused instead of being treated as a valid model minimum.
    /// The reported minimum is <c>max(1, androidMinimumGiB)</c>, i.e. the confirmed minimum itself.
    /// </para>
    /// <para>
    /// The maximum is <c>(userdataBytes - linuxBootBytes - minimumRootBytes) / 1 GiB</c> in integer
    /// arithmetic, so the upper bound is the largest whole GiB that still leaves the Linux root at
    /// <c>max(32 GiB, system + scratch + minimum data)</c>. The userdata extent is taken from
    /// <see cref="Plan"/> instead of being re-derived, so no structural, sector size, alignment or
    /// overflow rule is duplicated here: <see cref="Plan"/> validates the layout first, and the computed
    /// maximum is validated again by <see cref="Plan"/> before it is reported. A table that cannot be
    /// trusted keeps throwing <see cref="InvalidOperationException"/>; an extent that cannot host the
    /// confirmed minimum, an invalid size or an overflow throws <see cref="ArgumentException"/>.
    /// </para>
    /// </summary>
    public static AndroidAllocationRange GetAndroidRange(
        DiskLayout layout,
        long androidMinimumGiB,
        PackageStorage storage)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(storage);

        if (androidMinimumGiB <= 0)
        {
            throw new ArgumentException(
                "机型给出的 Android 最小容量必须是正整数 GiB；未确认或未知的下限不能当作有效下限。",
                nameof(androidMinimumGiB));
        }

        // The lower bound doubles as the layout check: Plan rejects an untrustworthy table, an
        // unsupported sector size, a too small userdata extent and every arithmetic overflow.
        var minimumPlan = Plan(layout, androidMinimumGiB, androidMinimumGiB, storage);

        long userdataBytes;
        try
        {
            userdataBytes = checked(minimumPlan.AndroidBytes + minimumPlan.LinuxBytes);
        }
        catch (OverflowException exception)
        {
            throw new ArgumentException(
                "userdata 容量在合成 Android 与 Linux 两侧时溢出 64 位范围，拒绝给出范围。",
                nameof(layout),
                exception);
        }

        var minimumRootBytes = MinimumRootBytes(storage);

        long maximumGiB;
        try
        {
            maximumGiB = checked(userdataBytes - minimumPlan.LinuxBootBytes - minimumRootBytes) / GiB;
        }
        catch (OverflowException exception)
        {
            throw new ArgumentException(
                "计算 Android 容量上限时溢出 64 位范围，拒绝给出范围。",
                nameof(layout),
                exception);
        }

        if (maximumGiB < androidMinimumGiB)
        {
            throw new ArgumentException(
                $"userdata 只有 {userdataBytes / GiB} GiB，装不下机型最小 {androidMinimumGiB} GiB 的 Android 与 {minimumRootBytes / GiB} GiB 的 Linux root。",
                nameof(androidMinimumGiB));
        }

        // The upper bound must survive the same planner, so the range never advertises a share Plan rejects.
        _ = Plan(layout, maximumGiB, androidMinimumGiB, storage);

        return new AndroidAllocationRange(androidMinimumGiB, maximumGiB);
    }

    private static int RequireSectorSize(int sectorSize)
    {
        var isPowerOfTwo = sectorSize > 0 && (sectorSize & (sectorSize - 1)) == 0;
        if (!isPowerOfTwo || MiB % sectorSize != 0)
        {
            throw new InvalidOperationException(
                $"分区表报告的扇区大小 {sectorSize} 无效：只接受 1 MiB 的 2 的幂次约数（如 512 或 4096）。");
        }

        return sectorSize;
    }

    private static void RequireAndroidShare(long androidGiB, long androidMinimumGiB)
    {
        if (androidGiB <= 0)
        {
            throw new ArgumentException("要留给 Android 的容量必须是正整数 GiB。", nameof(androidGiB));
        }

        if (androidMinimumGiB < 0)
        {
            throw new ArgumentException("Android 的最小容量不能是负数。", nameof(androidMinimumGiB));
        }

        if (androidGiB < androidMinimumGiB)
        {
            throw new ArgumentException(
                $"要留给 Android 的 {androidGiB} GiB 低于允许的最小值 {androidMinimumGiB} GiB。",
                nameof(androidGiB));
        }

        if (androidGiB > long.MaxValue / GiB)
        {
            throw new ArgumentException(
                $"要留给 Android 的 {androidGiB} GiB 换算成字节会溢出 64 位范围。",
                nameof(androidGiB));
        }
    }

    private static void RequireStorage(PackageStorage storage)
    {
        if (storage.LinuxBootBytes <= 0)
        {
            throw new ArgumentException("安装包声明的 Linux boot 大小必须为正数。", nameof(storage));
        }

        if (storage.SystemRequiredBytes <= 0)
        {
            throw new ArgumentException("安装包声明的 system 镜像容量必须为正数。", nameof(storage));
        }

        if (storage.DeploymentScratchBytes < 0)
        {
            throw new ArgumentException("安装包声明的部署 scratch 容量不能为负数。", nameof(storage));
        }

        if (storage.MinimumLinuxDataBytes <= 0)
        {
            throw new ArgumentException("安装包声明的最小 Linux 数据容量必须为正数。", nameof(storage));
        }

        // Linux root 必须从 1 MiB 边界开始，因此 boot 也必须是 1 MiB 的整数倍。
        if (storage.LinuxBootBytes % MiB != 0)
        {
            throw new ArgumentException("安装包声明的 Linux boot 大小必须按 1 MiB 对齐。", nameof(storage));
        }

        try
        {
            _ = checked(storage.SystemRequiredBytes + storage.DeploymentScratchBytes + storage.MinimumLinuxDataBytes);
        }
        catch (OverflowException exception)
        {
            throw new ArgumentException("安装包声明的容量需求相加时溢出 64 位范围。", nameof(storage), exception);
        }
    }

    /// <summary>
    /// The one minimum-root rule shared by <see cref="Plan"/> and <see cref="GetAndroidRange"/>:
    /// <c>max(32 GiB, system + deployment scratch + minimum Linux data)</c>, with the sum checked.
    /// </summary>
    private static long MinimumRootBytes(PackageStorage storage)
    {
        long declaredBytes;
        try
        {
            declaredBytes = checked(
                storage.SystemRequiredBytes + storage.DeploymentScratchBytes + storage.MinimumLinuxDataBytes);
        }
        catch (OverflowException exception)
        {
            throw new ArgumentException("安装包声明的容量需求相加时溢出 64 位范围。", nameof(storage), exception);
        }

        return Math.Max(MinimumLinuxRootBytes, declaredBytes);
    }

    private static bool Overlaps(DiskPartition left, DiskPartition right)
    {
        // Both extents were checked for overflow above, so the ends are representable.
        var leftEnd = left.StartSector + left.SectorCount;
        var rightEnd = right.StartSector + right.SectorCount;
        return left.StartSector < rightEnd && right.StartSector < leftEnd;
    }

    private static string Describe(DiskPartition partition) => $"#{partition.Number} \"{partition.Name}\"";
}

/// <summary>
/// Inclusive GiB bounds for the Android share of a userdata extent, produced by
/// <see cref="PartitionPlanner.GetAndroidRange"/>. <see cref="MinimumGiB"/> is the confirmed model
/// minimum and <see cref="MaximumGiB"/> the largest share whose Linux side still hosts boot plus the
/// minimum root; both ends are shares <see cref="PartitionPlanner.Plan"/> accepts.
/// </summary>
public sealed record AndroidAllocationRange(long MinimumGiB, long MaximumGiB);
