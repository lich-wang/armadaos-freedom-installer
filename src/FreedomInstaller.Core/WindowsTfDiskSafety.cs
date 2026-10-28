using System;
using System.Collections.Generic;

namespace FreedomInstaller.Core;

/// <summary>
/// Pure safety policy for the Windows raw TF card target. The same checks the live
/// <see cref="WindowsTfCardWriteTarget"/> must pass before any native IO are exposed here so they can be
/// exercised by real offline tests: exact candidate selection from a fresh reader inventory, rejection of
/// disks that hold protected local paths, and checked sector-aligned range arithmetic.
/// <para>
/// No IO and no Windows call happens in this type. A disk-interface path accepted here is still subject to
/// the native whole-disk checks (device number, geometry, volume extents) inside the target before a single
/// byte is touched.
/// </para>
/// </summary>
public static class WindowsTfDiskSafety
{
    private const int MinLogicalSectorSize = 512;

    private const int MaxLogicalSectorSize = 4096;

    private const string ReaderKeyPrefix = "reader:";

    /// <summary>
    /// Selects the one fresh reader candidate that exactly matches the expected card identity: same
    /// source-prefixed key, same device-interface path, same size and same logical sector size.
    /// <para>
    /// The expected candidate itself must be eligible (a <c>reader:</c> key, a real Windows whole-disk
    /// device namespace path, 512/4096 sectors, positive aligned capacity, exact SD/MMC/USB bus, non-blank
    /// identity, not read-only/system/offline); the matched fresh candidate is re-checked the same way.
    /// A missing match, an ambiguous duplicate and a foreign-source key all refuse instead of being
    /// substituted, so a card that was unplugged or swapped after confirmation can never be written.
    /// </para>
    /// <para>
    /// The fresh list is the product of <see cref="TfCardSupport.ParseCandidates"/> over the live reader
    /// report; that parser remains the only JSON authority and no second parser is introduced here.
    /// </para>
    /// </summary>
    public static TfCardCandidate Select(TfCardCandidate expected, IReadOnlyList<TfCardCandidate> fresh)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(fresh);

        RequireEligibleReaderCandidate(expected, nameof(expected));

        TfCardCandidate? match = null;
        var matchCount = 0;

        foreach (var candidate in fresh)
        {
            if (candidate is null)
            {
                continue;
            }

            if (!string.Equals(candidate.Key, expected.Key, StringComparison.Ordinal)
                || !string.Equals(candidate.Path, expected.Path, StringComparison.Ordinal)
                || candidate.SizeBytes != expected.SizeBytes
                || candidate.LogicalSectorSize != expected.LogicalSectorSize)
            {
                continue;
            }

            matchCount++;
            if (matchCount == 1)
            {
                RequireEligibleReaderCandidate(candidate, nameof(fresh));
                match = candidate;
            }
        }

        if (matchCount == 0)
        {
            throw new InvalidOperationException(
                $"新的读取器清单中没有与期望身份完全一致的 TF 卡（{expected.Key}，{expected.Path}，{expected.SizeBytes} 字节 / {expected.LogicalSectorSize} 字节扇区）。卡片可能已被拔出或更换，拒绝继续。");
        }

        if (matchCount > 1)
        {
            throw new InvalidOperationException(
                $"新的读取器清单中出现了 {matchCount} 个与期望身份一致的 TF 卡，无法唯一定位目标，拒绝继续。");
        }

        return match!;
    }

    /// <summary>
    /// Rejects a selected disk number that is negative or invalid, and rejects a selected disk that hosts
    /// any protected source/work/backup/executable path (reported through its mapped disk number).
    /// A negative number inside the protected collection is an invalid number, not a comparison value.
    /// </summary>
    public static void RequireUnprotectedDisk(int diskNumber, IReadOnlyCollection<int> protectedDiskNumbers)
    {
        ArgumentNullException.ThrowIfNull(protectedDiskNumbers);

        if (diskNumber < 0)
        {
            throw new ArgumentException(
                $"选中的磁盘编号 {diskNumber} 不是有效的本机磁盘编号，拒绝继续。",
                nameof(diskNumber));
        }

        foreach (var protectedNumber in protectedDiskNumbers)
        {
            if (protectedNumber < 0)
            {
                throw new ArgumentException(
                    $"受保护的磁盘编号 {protectedNumber} 不是有效的本机磁盘编号，拒绝继续。",
                    nameof(protectedDiskNumbers));
            }

            if (protectedNumber == diskNumber)
            {
                throw new InvalidOperationException(
                    $"选中的磁盘 {diskNumber} 上存在受保护的包/工作/备份/可执行文件路径，拒绝作为写入目标。");
            }
        }
    }

    /// <summary>
    /// Checked arithmetic gate for one whole-disk range: the count must be a positive multiple of the
    /// sector size, the offset must be a non-negative multiple of the sector size, the sum must not
    /// overflow the 64-bit range and the end must not pass the disk capacity. Every violation — including
    /// overflow — surfaces as <see cref="ArgumentException"/>; no value is rounded or clamped.
    /// </summary>
    public static void RequireAlignedRange(long diskBytes, int logicalSectorSize, long offset, int count)
    {
        if (diskBytes <= 0)
        {
            throw new ArgumentException($"磁盘容量 {diskBytes} 不是正数，拒绝按该容量计算范围。", nameof(diskBytes));
        }

        if (logicalSectorSize != MinLogicalSectorSize && logicalSectorSize != MaxLogicalSectorSize)
        {
            throw new ArgumentException(
                $"扇区大小 {logicalSectorSize} 不是 512 或 4096，拒绝按该扇区计算范围。",
                nameof(logicalSectorSize));
        }

        if (count <= 0)
        {
            throw new ArgumentException($"范围长度 {count} 必须是正的整数个扇区。", nameof(count));
        }

        if (offset < 0)
        {
            throw new ArgumentException($"范围偏移 {offset} 不能为负。", nameof(offset));
        }

        if (offset % logicalSectorSize != 0)
        {
            throw new ArgumentException(
                $"范围偏移 {offset} 没有按 {logicalSectorSize} 字节扇区对齐，拒绝该范围。",
                nameof(offset));
        }

        if (count % logicalSectorSize != 0)
        {
            throw new ArgumentException(
                $"范围长度 {count} 没有按 {logicalSectorSize} 字节扇区对齐，拒绝该范围。",
                nameof(count));
        }

        long end;
        try
        {
            end = checked(offset + count);
        }
        catch (OverflowException exception)
        {
            throw new ArgumentException(
                $"范围 [{offset}, +{count}] 溢出 64 位范围，拒绝该范围。",
                nameof(offset),
                exception);
        }

        if (end > diskBytes)
        {
            throw new ArgumentException(
                $"范围 [{offset}, {end}] 超出磁盘容量 {diskBytes} 字节，拒绝该范围。",
                nameof(offset));
        }
    }

    /// <summary>
    /// One candidate of the reader inventory must be a whole-disk device. Only two canonical shapes are
    /// accepted: the device namespace path <c>\\.\PhysicalDrive</c> followed by a nonnegative ASCII decimal
    /// disk number, or a <c>\\?\</c> disk-interface object path (for example the <c>\\?\USBSTOR#...</c>
    /// path reported by <c>Get-Disk.Path</c>) ending exactly, case-insensitively, with the Microsoft
    /// GUID_DEVINTERFACE_DISK suffix <c>#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}</c>. Volume device paths
    /// (<c>\\.\C:</c>), extended drive/file paths (<c>\\?\C:\...</c>), ordinary and extended UNC paths, other
    /// device interfaces and arbitrary device paths are refused. The native whole-disk proof still happens
    /// in the target before any byte is written.
    /// </summary>
    private static bool IsWindowsDeviceInterfacePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        if (path.StartsWith(@"\\.\", StringComparison.Ordinal))
        {
            return IsCanonicalPhysicalDrivePath(path[4..]);
        }

        if (path.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            var rest = path[4..];
            return rest.Length > 0
                && !IsUncRoot(rest)
                && !rest.Contains(':')
                && rest.EndsWith(DiskInterfaceGuidSuffix, StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    private const string DiskInterfaceGuidSuffix = "#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";

    private static bool IsCanonicalPhysicalDrivePath(string rest)
    {
        const string prefix = "PhysicalDrive";

        if (rest.Length <= prefix.Length || !rest.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var digits = rest[prefix.Length..];
        foreach (var character in digits)
        {
            if (character is < '0' or > '9')
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsUncRoot(string rest) =>
        rest.StartsWith("UNC\\", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Full eligibility of one reader candidate for a raw write target. Mirrors the reader parser's own
    /// filters (the parser already drops such entries) and is re-applied here so a hand-built or stale
    /// candidate can never pass. Unsafe state refuses with <see cref="InvalidOperationException"/>;
    /// malformed identity, geometry, bus or path refuses with <see cref="ArgumentException"/>.
    /// </summary>
    private static void RequireEligibleReaderCandidate(TfCardCandidate candidate, string paramName)
    {
        if (string.IsNullOrWhiteSpace(candidate.Key)
            || !candidate.Key.StartsWith(ReaderKeyPrefix, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"候选卡片标识「{candidate.Key}」为空或缺少 reader: 前缀，拒绝混入非读取器来源的卡片。",
                paramName);
        }

        if (string.IsNullOrWhiteSpace(candidate.Path))
        {
            throw new ArgumentException($"候选卡片 {candidate.Key} 的设备路径为空，拒绝空白身份。", paramName);
        }

        if (string.IsNullOrWhiteSpace(candidate.DisplayName))
        {
            throw new ArgumentException($"候选卡片 {candidate.Key} 的显示名为空，拒绝空白身份。", paramName);
        }

        if (candidate.LogicalSectorSize != MinLogicalSectorSize
            && candidate.LogicalSectorSize != MaxLogicalSectorSize)
        {
            throw new ArgumentException(
                $"候选卡片 {candidate.Key} 的扇区大小 {candidate.LogicalSectorSize} 不是 512 或 4096。",
                paramName);
        }

        if (candidate.SizeBytes <= 0)
        {
            throw new ArgumentException($"候选卡片 {candidate.Key} 的容量 {candidate.SizeBytes} 不是正数。", paramName);
        }

        if (candidate.SizeBytes % candidate.LogicalSectorSize != 0)
        {
            throw new ArgumentException(
                $"候选卡片 {candidate.Key} 的容量 {candidate.SizeBytes} 没有按 {candidate.LogicalSectorSize} 字节扇区对齐。",
                paramName);
        }

        // Exact bus match on the raw evidence string: the reader script reports Get-Disk BusType verbatim,
        // so only the exact tokens SD / MMC / USB are acceptable (case-insensitive, no trimming, no prefix).
        var bus = candidate.MediumEvidence;
        if (string.IsNullOrEmpty(bus)
            || (!string.Equals(bus, "SD", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(bus, "MMC", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(bus, "USB", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(
                $"候选卡片 {candidate.Key} 的总线类型「{candidate.MediumEvidence}」不是确切的 SD、MMC 或 USB，拒绝当作读取器 TF 卡。",
                paramName);
        }

        if (candidate.ReadOnly)
        {
            throw new InvalidOperationException($"候选卡片 {candidate.Key} 被报告为只读，不能作为安装目标。");
        }

        if (candidate.IsSystemDisk)
        {
            throw new InvalidOperationException($"候选卡片 {candidate.Key} 被报告为系统盘，不能作为安装目标。");
        }

        if (candidate.IsOffline)
        {
            throw new InvalidOperationException($"候选卡片 {candidate.Key} 被报告为离线，无法确认其容量。");
        }

        if (!IsWindowsDeviceInterfacePath(candidate.Path))
        {
            throw new ArgumentException(
                $"候选卡片 {candidate.Key} 的路径「{candidate.Path}」不是 Windows 整盘设备命名空间路径（\\\\?\\ 或 \\\\.\\ 对象路径），拒绝当作写入目标。",
                paramName);
        }
    }
}
