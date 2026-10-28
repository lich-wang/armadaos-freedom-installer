using System;
using System.Collections.Generic;

namespace FreedomInstaller.Core;

/// <summary>
/// The installation record the uninstall path is allowed to trust. It names, by PARTUUID, the exact
/// three partitions the installer created (<c>userdata</c> plus <c>ARMADA_BOOT</c> and
/// <c>ARMADA_ROOT</c>) and records where the original Android userdata ended before it was split.
/// Records for the modern layout additionally name, by PARTUUID, the retained <c>ARMADA_BACKUP</c>
/// partition (see <see cref="BoardBackupPartUuid"/>).
/// <para>
/// Ownership is proven by PARTUUID, never by a partition's name alone: a partition that merely looks
/// like <c>ARMADA_BOOT</c> but carries a different PARTUUID is not taken to belong to this install.
/// </para>
/// </summary>
public sealed record LinuxInstallationLayout(
    string DeviceId,
    string UserdataPartUuid,
    string LinuxBootPartUuid,
    string LinuxRootPartUuid,
    long OriginalUserdataEndSector)
{
    /// <summary>
    /// The optional board backup partition (<c>ARMADA_BACKUP</c>), named by PARTUUID. <c>null</c> means the
    /// legacy layout without a backup; a non-null value must be a well-formed, non-empty GUID distinct from
    /// the three positional ones. When present, the backup is validated (label, type, exact 2 GiB size and
    /// geometry) and preserved: the restored userdata ends at its start, and it is never reclaimed.
    /// </summary>
    public string? BoardBackupPartUuid { get; init; }
}

/// <summary>
/// Result of <see cref="UninstallPlanner.Plan"/>. The Android userdata extent is restored to
/// [<see cref="UserdataStartSector"/>, <see cref="UserdataEndSectorExclusive"/>): the reclaimed Linux
/// boot and root partitions, plus the original sub-MiB padding - and, when a board backup is retained,
/// stopping exactly at the backup's start so the backup survives untouched. <see cref="RemovedPartitionNumbers"/>
/// are the GPT numbers of the partitions to drop; every other partition is left where it is.
/// </summary>
public sealed record AndroidRestorePlan(
    long UserdataStartSector,
    long UserdataEndSectorExclusive,
    long RestoredAndroidBytes,
    IReadOnlyList<long> RemovedPartitionNumbers);

/// <summary>
/// Decides which partitions may be reclaimed to restore Android, given the live partition table and the
/// installation record. The contract (frozen; pinned by tests/FreedomInstaller.Core.Tests/UninstallPlannerTests.cs):
/// <list type="bullet">
/// <item>Only the two partitions immediately following the recorded <c>userdata</c> - exactly
/// <c>ARMADA_BOOT</c> (1 GiB) and <c>ARMADA_ROOT</c> (&gt;= 32 GiB) - are reclaimed.</item>
/// <item>The three labels must correspond strictly to the recorded PARTUUIDs; every recorded UUID must
/// be well formed and the three must be distinct.</item>
/// <item>The reported partition table must be uniquely the three partitions on 512 or 4096 byte sectors
/// and on the same device, ordered <c>userdata</c>, <c>ARMADA_BOOT</c>, <c>ARMADA_ROOT</c> with no overlap,
/// overflow or unknown trailing partition. The factory userdata start need not be 1 MiB aligned; the only
/// permitted gap is the sub-MiB padding between userdata's end and the first 1 MiB boundary, where
/// <c>ARMADA_BOOT</c> must begin.</item>
/// <item><c>ARMADA_ROOT</c> must start exactly where <c>ARMADA_BOOT</c> ends. When the record names no
/// board backup (legacy layout), <c>ARMADA_ROOT</c>'s end must equal the recorded
/// <see cref="LinuxInstallationLayout.OriginalUserdataEndSector"/>; when it does, the retained
/// <c>ARMADA_BACKUP</c> (found only by that PARTUUID, labelled exactly, Linux filesystem type, exactly
/// 2 GiB) must start exactly at <c>ARMADA_ROOT</c>'s end and end at the recorded original end. In both
/// cases the restored userdata tail ends at <c>ARMADA_ROOT</c>'s end and the backup is never reclaimed.</item>
/// </list>
/// A table or record that cannot be trusted is rejected rather than guessed; the inputs are never mutated.
/// The check is pure: no device access, no IO. A business rejection surfaces as
/// <see cref="ArgumentException"/> or <see cref="InvalidOperationException"/> only - an overflow is caught
/// and re-reported as an <see cref="ArgumentException"/>, so it can never masquerade as an untrusted table
/// or leak out as a raw <see cref="OverflowException"/>.
/// </summary>
public static class UninstallPlanner
{
    private const long KiB = 1024L;
    private const long MiB = 1024L * KiB;
    private const long GiB = 1024L * MiB;

    /// <summary>The only sector sizes the device layout may report.</summary>
    private const int SectorSize512 = 512;
    private const int SectorSize4096 = 4096;

    /// <summary><c>ARMADA_BOOT</c> is exactly 1 GiB; a different size is not the partition this record owns.</summary>
    private const long LinuxBootBytes = 1L * GiB;

    /// <summary><c>ARMADA_BACKUP</c> is exactly 2 GiB; a different size is not the partition this record owns.</summary>
    private const long LinuxBackupBytes = 2L * GiB;

    /// <summary>The floor the device side demands for the Linux root (same value as the install planner).</summary>
    private const long MinimumLinuxRootBytes = 32L * GiB;

    private const string UserdataName = "userdata";
    private const string LinuxBootName = "ARMADA_BOOT";
    private const string LinuxRootName = "ARMADA_ROOT";
    private const string LinuxBackupName = "ARMADA_BACKUP";

    /// <summary>GPT type GUID of a Linux filesystem data partition.</summary>
    private static readonly Guid LinuxFilesystemTypeGuid =
        new("0FC63DAF-8483-4772-8E79-3D69D8477DE4");

    public static AndroidRestorePlan Plan(DiskLayout layout, LinuxInstallationLayout installation)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(installation);

        var sectorSize = RequireSectorSize(layout.SectorSize);

        // Same device, proven by id: a record that belongs to another disk says nothing about this table.
        if (string.IsNullOrWhiteSpace(layout.DeviceId))
        {
            throw new ArgumentException("分区表没有报告设备标识，无法确认这些分区属于同一台设备。", nameof(layout));
        }

        if (!string.Equals(layout.DeviceId, installation.DeviceId, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"安装记录属于设备 {DescribeValue(installation.DeviceId)}，而分区表来自 {DescribeValue(layout.DeviceId)}，拒绝在另一台设备上回收分区。",
                nameof(installation));
        }

        // The record itself must name three well-formed, distinct PARTUUIDs before the table is consulted.
        var userdataUuid = RequirePartUuid(installation.UserdataPartUuid, nameof(installation));
        var bootUuid = RequirePartUuid(installation.LinuxBootPartUuid, nameof(installation));
        var rootUuid = RequirePartUuid(installation.LinuxRootPartUuid, nameof(installation));

        if (userdataUuid == bootUuid || userdataUuid == rootUuid || bootUuid == rootUuid)
        {
            throw new ArgumentException(
                "安装记录中的三个 PARTUUID 必须互不相同，否则无法确定每个分区的归属。",
                nameof(installation));
        }

        // The optional board backup must itself be a well-formed GUID, distinct from the three positional
        // ones; null means the legacy layout without a retained backup.
        Guid? backupUuid = null;
        var backupUuidRaw = installation.BoardBackupPartUuid;
        if (backupUuidRaw is not null)
        {
            if (!Guid.TryParse(backupUuidRaw.Trim(), out var parsedBackupUuid) || parsedBackupUuid == Guid.Empty)
            {
                throw new ArgumentException(
                    "安装记录的 ARMADA_BACKUP PARTUUID 不是有效的非空 GUID。",
                    nameof(installation));
            }

            if (parsedBackupUuid == userdataUuid || parsedBackupUuid == bootUuid || parsedBackupUuid == rootUuid)
            {
                throw new ArgumentException(
                    "安装记录的 ARMADA_BACKUP PARTUUID 不得与 userdata、ARMADA_BOOT 或 ARMADA_ROOT 相同。",
                    nameof(installation));
            }

            backupUuid = parsedBackupUuid;
        }

        if (installation.OriginalUserdataEndSector <= 0)
        {
            throw new ArgumentException(
                "安装记录的原 Android userdata 末端必须是一个正数扇区。",
                nameof(installation));
        }

        var partitions = layout.Partitions;
        if (partitions is null)
        {
            throw new InvalidOperationException("分区表为空，设备没有报告任何分区，无法规划回收。");
        }

        // ---- structural validation of the reported table --------------------------------

        DiskPartition? userdata = null;
        DiskPartition? boot = null;
        DiskPartition? root = null;
        DiskPartition? backup = null;

        var seenNumbers = new HashSet<long>();
        var seenUuids = new HashSet<string>(StringComparer.Ordinal);

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
                throw new InvalidOperationException(
                    $"分区号 {partition.Number} 在分区表中重复出现，拒绝猜测目标分区。");
            }

            var rawUuid = (partition.PartUuid ?? string.Empty).Trim();
            if (rawUuid.Length > 0 && !seenUuids.Add(rawUuid.ToUpperInvariant()))
            {
                throw new InvalidOperationException(
                    $"PARTUUID {partition.PartUuid} 在分区表中重复出现，分区归属不确定。");
            }

            if (rawUuid.Length == 0 || !Guid.TryParse(rawUuid, out var uuid))
            {
                // An unreadable PARTUUID can never prove ownership; it simply matches nothing.
                continue;
            }

            if (uuid == userdataUuid)
            {
                userdata = Claim(partition, userdata, UserdataName);
            }
            else if (uuid == bootUuid)
            {
                boot = Claim(partition, boot, LinuxBootName);
            }
            else if (uuid == rootUuid)
            {
                root = Claim(partition, root, LinuxRootName);
            }
            else if (backupUuid is not null && uuid == backupUuid.Value)
            {
                backup = Claim(partition, backup, LinuxBackupName);
            }
        }

        if (userdata is null)
        {
            throw new InvalidOperationException(
                $"分区表中找不到 PARTUUID {installation.UserdataPartUuid} 的 userdata 分区，安装记录与分区表不匹配。");
        }

        if (boot is null)
        {
            throw new InvalidOperationException(
                $"分区表中找不到 PARTUUID {installation.LinuxBootPartUuid} 的 {LinuxBootName} 分区，安装记录与分区表不匹配。");
        }

        if (root is null)
        {
            throw new InvalidOperationException(
                $"分区表中找不到 PARTUUID {installation.LinuxRootPartUuid} 的 {LinuxRootName} 分区，安装记录与分区表不匹配。");
        }

        if (backupUuid is not null && backup is null)
        {
            throw new InvalidOperationException(
                $"分区表中找不到 PARTUUID {installation.BoardBackupPartUuid} 的 {LinuxBackupName} 分区，安装记录与分区表不匹配。");
        }

        // Ownership is by PARTUUID, so the label has to match as well - strictly, not case-insensitively.
        RequireLabel(userdata, UserdataName);
        RequireLabel(boot, LinuxBootName);
        RequireLabel(root, LinuxRootName);

        RequireLinuxType(boot);
        RequireLinuxType(root);

        // A modern record names a backup, so its partition must be present and named exactly too. The
        // backup is retained - never reclaimed - so its geometry is validated against the record here.
        if (backupUuid is not null)
        {
            RequireLabel(backup!, LinuxBackupName);
            RequireLinuxType(backup!);

            var backupBytes = SectorsToBytes(backup!, sectorSize, nameof(layout));
            if (backupBytes != LinuxBackupBytes)
            {
                throw new ArgumentException(
                    $"{LinuxBackupName} 必须恰好是 2 GiB，实际为 {backupBytes} 字节，与安装记录不符。",
                    nameof(layout));
            }

            var backupEnd = backup!.StartSector + backup.SectorCount;
            if (backupEnd != installation.OriginalUserdataEndSector)
            {
                throw new ArgumentException(
                    $"{LinuxBackupName} 的末端 {backupEnd} 与安装记录的原 userdata 末端 {installation.OriginalUserdataEndSector} 不一致。",
                    nameof(installation));
            }
        }

        // ---- sizes, alignment and geometry ----------------------------------------------

        var bootBytes = SectorsToBytes(boot, sectorSize, nameof(layout));
        if (bootBytes != LinuxBootBytes)
        {
            throw new ArgumentException(
                $"{LinuxBootName} 必须恰好是 1 GiB，实际为 {bootBytes} 字节，与安装记录不符。",
                nameof(layout));
        }

        var rootBytes = SectorsToBytes(root, sectorSize, nameof(layout));
        if (rootBytes < MinimumLinuxRootBytes)
        {
            throw new ArgumentException(
                $"{LinuxRootName} 只有 {rootBytes} 字节，低于 32 GiB 下限，不是安装时创建的 Linux root。",
                nameof(layout));
        }

        // The Android userdata extent this record restores must itself be a whole number of GiB: the
        // install side only ever shortens the factory tail by whole GiB, so a length that is not a whole
        // GiB cannot be the extent this record owns. The start may still be unaligned. (Overflow-safe,
        // unlike a raw multiply.)
        var userdataBytes = SectorsToBytes(userdata, sectorSize, nameof(layout));
        if (userdataBytes <= 0 || userdataBytes % GiB != 0)
        {
            throw new ArgumentException(
                $"userdata 的长度 {userdataBytes} 字节不是 GiB 的整数倍，与安装时创建的布局不符，拒绝回收。",
                nameof(layout));
        }

        // The factory partitioner can start userdata mid-MiB, so its start is deliberately not required to
        // be 1 MiB aligned. The byte conversion is still checked: an unrepresentable start is an overflow,
        // not evidence that the table is untrusted.
        try
        {
            _ = checked(userdata.StartSector * (long)sectorSize);
        }
        catch (OverflowException exception)
        {
            throw new ArgumentException(
                "userdata 的起始扇区换算成字节时溢出 64 位范围，拒绝规划。",
                nameof(layout),
                exception);
        }

        // 1 MiB expressed in whole sectors: 2048 at 512 bytes, 256 at 4096 bytes.
        var alignmentSectors = MiB / sectorSize;

        // Every extent was checked for negative starts and overflow above, so these sums are representable.
        var userdataEnd = userdata.StartSector + userdata.SectorCount;
        var bootEnd = boot.StartSector + boot.SectorCount;
        var rootEnd = root.StartSector + root.SectorCount;

        // Factory origin: the installer split the Android tail at a 1 MiB boundary, so ARMADA_BOOT starts at
        // the first MiB boundary at or after userdata's end. Whatever sub-MiB remainder userdata leaves
        // (88 sectors on 4096-byte media) is padding, and ARMADA_ROOT absorbs it by keeping its end pinned
        // to the recorded original end. A boot start anywhere else is a different, untrusted layout.
        var expectedBootStart = AlignUp(userdataEnd, alignmentSectors, nameof(layout));
        if (boot.StartSector != expectedBootStart)
        {
            throw new InvalidOperationException(
                $"{LinuxBootName}（起始扇区 {boot.StartSector}）没有从 userdata 结束扇区 {userdataEnd} 之后的第一个 1 MiB 边界 {expectedBootStart} 开始，拒绝在未对齐的 Linux 尾部布局上回收。");
        }

        if (bootEnd != root.StartSector)
        {
            throw new InvalidOperationException(
                $"{LinuxRootName}（起始扇区 {root.StartSector}）没有紧接在 {LinuxBootName} 的结束扇区 {bootEnd} 之后，拒绝在不连续的布局上回收。");
        }

        // The tail may be longer than boot+root in the modern layout: the original userdata end may sit
        // beyond root's end because the exact-2-GiB ARMADA_BACKUP occupies that remainder and is retained.
        // Legacy layouts (no backup) keep the original pin of root's end to the recorded original end.
        if (backupUuid is null)
        {
            if (rootEnd != installation.OriginalUserdataEndSector)
            {
                throw new ArgumentException(
                    $"{LinuxRootName} 的末端 {rootEnd} 与安装记录的原 userdata 末端 {installation.OriginalUserdataEndSector} 不一致。",
                    nameof(installation));
            }
        }
        else
        {
            var backupStart = backup!.StartSector;
            if (rootEnd != backupStart)
            {
                throw new InvalidOperationException(
                    $"{LinuxBackupName}（起始扇区 {backupStart}）没有紧接在 {LinuxRootName} 的结束扇区 {rootEnd} 之后，拒绝在不连续的布局上回收。");
            }
        }

        for (var first = 0; first < partitions.Count; first++)
        {
            var left = partitions[first];
            if (left is null)
            {
                continue;
            }

            for (var second = first + 1; second < partitions.Count; second++)
            {
                var right = partitions[second];
                if (right is null)
                {
                    continue;
                }

                if (Overlaps(left, right))
                {
                    throw new InvalidOperationException(
                        $"分区 {Describe(left)} 与 {Describe(right)} 的扇区范围重叠，分区表不可信。");
                }
            }
        }

        // Nothing may sit after userdata: the tail is the sub-MiB padding plus boot + root (plus the
        // retained ARMADA_BACKUP when the record names one); every other partition precedes userdata.
        // Only the record's own backup is exempt - any other unowned partition after userdata is refused.
        foreach (var partition in partitions)
        {
            if (partition is null
                || ReferenceEquals(partition, userdata)
                || ReferenceEquals(partition, boot)
                || ReferenceEquals(partition, root)
                || (backupUuid is not null && ReferenceEquals(partition, backup)))
            {
                continue;
            }

            if (partition.StartSector + partition.SectorCount > userdata.StartSector)
            {
                throw new InvalidOperationException(
                    $"分区 {Describe(partition)} 位于 userdata（起始扇区 {userdata.StartSector}）之后，归属未确认，拒绝回收。");
            }
        }

        // ---- restored extent ------------------------------------------------------------

        long restoredBytes;
        try
        {
            restoredBytes = checked((rootEnd - userdata.StartSector) * sectorSize);
        }
        catch (OverflowException exception)
        {
            throw new ArgumentException(
                "要恢复的 userdata 区段换算成字节时溢出 64 位范围，拒绝规划。",
                nameof(layout),
                exception);
        }

        if (restoredBytes <= 0)
        {
            throw new InvalidOperationException("要恢复的 userdata 区段不是正长度，分区表不可信。");
        }

        // Only boot and root are ever reclaimed; the retained ARMADA_BACKUP (when present) stays put and
        // the restored userdata tail stops exactly at its start.
        return new AndroidRestorePlan(
            userdata.StartSector,
            rootEnd,
            restoredBytes,
            new[] { boot.Number, root.Number });
    }

    private static int RequireSectorSize(int sectorSize)
    {
        if (sectorSize != SectorSize512 && sectorSize != SectorSize4096)
        {
            throw new InvalidOperationException(
                $"分区表报告的扇区大小 {sectorSize} 无效：只接受 512 或 4096 字节。");
        }

        return sectorSize;
    }

    private static Guid RequirePartUuid(string? value, string parameter)
    {
        if (string.IsNullOrWhiteSpace(value)
            || !Guid.TryParse(value.Trim(), out var parsed)
            || parsed == Guid.Empty)
        {
            throw new ArgumentException(
                $"安装记录中的 PARTUUID {DescribeValue(value)} 不是合法的 GUID，无法据此确认分区归属。",
                parameter);
        }

        return parsed;
    }

    /// <summary>Two partitions may not claim the same recorded PARTUUID: the owner would be ambiguous.</summary>
    private static DiskPartition Claim(DiskPartition partition, DiskPartition? existing, string expectedName)
    {
        if (existing is not null)
        {
            throw new InvalidOperationException(
                $"分区表中出现多个 PARTUUID 相同的 {expectedName} 候选（{Describe(existing)} 与 {Describe(partition)}），拒绝在其中挑选一个。");
        }

        return partition;
    }

    private static void RequireLabel(DiskPartition partition, string expectedName)
    {
        if (!string.Equals(partition.Name, expectedName, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"PARTUUID {partition.PartUuid} 对应的分区标签是 {DescribeValue(partition.Name)}，不是期望的 {expectedName}，拒绝按名字推断归属。");
        }
    }

    private static void RequireLinuxType(DiskPartition partition)
    {
        var typeGuid = partition.TypeGuid;
        if (string.IsNullOrWhiteSpace(typeGuid)
            || !Guid.TryParse(typeGuid.Trim(), out var type)
            || type != LinuxFilesystemTypeGuid)
        {
            throw new InvalidOperationException(
                $"分区 {Describe(partition)} 的类型不是 Linux 文件系统类型，拒绝回收。");
        }
    }

    private static long SectorsToBytes(DiskPartition partition, int sectorSize, string parameter)
    {
        try
        {
            return checked(partition.SectorCount * sectorSize);
        }
        catch (OverflowException exception)
        {
            throw new ArgumentException(
                $"分区 {Describe(partition)} 的扇区数量换算成字节时溢出 64 位范围。",
                parameter,
                exception);
        }
    }

    /// <summary>
    /// Rounds a sector position up to the next <paramref name="alignment"/> boundary without evaluating
    /// <c>position + alignment - 1</c>, which can overflow for a position near <see cref="long.MaxValue"/>.
    /// The caller has already proven the position non-negative. An unrepresentable result is reported as
    /// <see cref="ArgumentException"/>, like every other overflow in this planner.
    /// </summary>
    private static long AlignUp(long position, long alignment, string parameter)
    {
        var remainder = position % alignment;
        if (remainder == 0)
        {
            return position;
        }

        var padding = alignment - remainder;
        if (position > long.MaxValue - padding)
        {
            throw new ArgumentException(
                "userdata 的结束位置按 1 MiB 对齐时溢出 64 位范围，拒绝规划。",
                parameter);
        }

        return position + padding;
    }

    private static bool Overlaps(DiskPartition left, DiskPartition right)
    {
        // Both extents were checked for overflow above, so the ends are representable.
        var leftEnd = left.StartSector + left.SectorCount;
        var rightEnd = right.StartSector + right.SectorCount;
        return left.StartSector < rightEnd && right.StartSector < leftEnd;
    }

    private static string Describe(DiskPartition partition) => $"#{partition.Number} \"{partition.Name}\"";

    private static string DescribeValue(string? value) => string.IsNullOrWhiteSpace(value) ? "（空）" : value.Trim();
}
