namespace FreedomInstaller.Core;

/// <summary>
/// Plans the internal partition layout that follows a partition-table rewrite: the Android userdata window
/// carved out of the original userdata partition, the Linux boot and root extents behind it and the reserved
/// backup tail. Pure arithmetic over an immutable table snapshot; it never touches a device, never generates
/// GPT entries and never creates UUIDs.
/// </summary>
public static class InternalPartitionPlanner
{
    private const long GiB = 1L << 30;
    private const long MiB = 1L << 20;
    private const long MinimumAndroidGiB = 16;
    private const long MinimumLinuxBytes = 64L * GiB;
    private const long MinimumRootBytes = 32L * GiB;
    // Reserved recovery tail behind the Linux root extent; independent of the package's boot requirement.
    private const long BackupTailBytes = 2L * GiB;
    private const string UserdataName = "userdata";

    /// <summary>
    /// Plans the internal layout for <paramref name="androidGiB"/> whole GiB of Android userdata on top of
    /// <paramref name="original"/>.
    /// </summary>
    /// <param name="original">Read-only snapshot of the original GPT; its userdata entry is preserved verbatim.</param>
    /// <param name="androidGiB">Whole GiB handed to Android; at least 16.</param>
    /// <param name="storage">Storage the installation package requires.</param>
    /// <returns>
    /// The planned extents. All sector values are absolute sectors of <see cref="GptTable.SectorSize"/>; every
    /// <c>*EndSectorExclusive</c> value is half-open, i.e. one sector past the last sector the extent occupies.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="original"/> or <paramref name="storage"/> is null.</exception>
    /// <exception cref="InvalidOperationException">
    /// The snapshot is structurally unusable: an unsupported sector size, an invalid disk length or usable
    /// window, a null or duplicate partition number, a partition that starts before its usable window or ends
    /// past it, overlapping partitions, or a table without exactly one userdata entry.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// A size or arithmetic bound cannot be satisfied: invalid package storage, Android below 16 GiB, an
    /// overflowing sector or byte value, a non-positive extent, or a layout that misses the Linux minima.
    /// </exception>
    public static InternalAllocationPlan Plan(GptTable original, long androidGiB, PackageStorage storage)
        => BuildPlan(original, androidGiB, storage);

    /// <summary>
    /// Returns the inclusive whole-GiB Android range that <see cref="Plan"/> accepts for
    /// <paramref name="original"/> and <paramref name="storage"/>: the smallest choice is 16 GiB and the
    /// largest is the biggest whole GiB that still satisfies the same acceptance rules.
    /// </summary>
    /// <param name="original">Read-only snapshot of the original GPT.</param>
    /// <param name="storage">Storage the installation package requires.</param>
    /// <returns>The inclusive <see cref="AndroidAllocationRange"/> of accepted Android sizes.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="original"/> or <paramref name="storage"/> is null.</exception>
    /// <exception cref="InvalidOperationException">The snapshot is structurally unusable, exactly as for <see cref="Plan"/>.</exception>
    /// <exception cref="ArgumentException">
    /// The package storage or the minimum Android size is invalid, an arithmetic bound overflows, or the
    /// userdata window cannot hold the minimum Android size next to the Linux requirement.
    /// </exception>
    public static AndroidAllocationRange GetAndroidRange(GptTable original, PackageStorage storage)
    {
        ArgumentNullException.ThrowIfNull(original);
        ArgumentNullException.ThrowIfNull(storage);

        InternalAllocationPlan minimum = BuildPlan(original, MinimumAndroidGiB, storage);
        ValidatePackageStorage(storage, out long bootBytes, out _, out long requiredRootBytes);

        long requiredLinuxBytes;
        try
        {
            requiredLinuxBytes = Math.Max(MinimumLinuxBytes, checked(bootBytes + requiredRootBytes));
        }
        catch (OverflowException ex)
        {
            throw new ArgumentException("The package's Linux requirement overflows in bytes.", nameof(storage), ex);
        }

        // Whole GiB is a whole MiB, so every accepted Android choice leaves the boot alignment gap where the
        // minimum plan found it and shrinks Linux by exactly the added Android bytes.
        long alignedBaseSector = minimum.LinuxBootStartSector - minimum.AndroidSectorCount;
        long availableBytes;
        try
        {
            availableBytes = checked((minimum.BackupStartSector - alignedBaseSector) * minimum.SectorSize);
        }
        catch (OverflowException ex)
        {
            throw new ArgumentException("The usable userdata window overflows in bytes.", nameof(original), ex);
        }

        if (availableBytes < requiredLinuxBytes)
        {
            throw new ArgumentException(
                "The userdata window cannot hold the minimum Android size next to the Linux requirement.",
                nameof(storage));
        }

        long maximumGiB = (availableBytes - requiredLinuxBytes) / GiB;
        if (maximumGiB < MinimumAndroidGiB)
        {
            throw new ArgumentException("Not even the minimum Android size fits beside the Linux requirement.", nameof(storage));
        }

        // Both inclusive endpoints must be accepted by Plan itself.
        BuildPlan(original, maximumGiB, storage);

        return new AndroidAllocationRange(MinimumAndroidGiB, maximumGiB);
    }

    private static InternalAllocationPlan BuildPlan(GptTable original, long androidGiB, PackageStorage storage)
    {
        ArgumentNullException.ThrowIfNull(original);
        ArgumentNullException.ThrowIfNull(storage);

        int sectorSize = original.SectorSize;
        if (sectorSize != 512 && sectorSize != 4096)
        {
            throw new InvalidOperationException(
                $"Sector size {sectorSize} is unsupported; only 512 and 4096 bytes are planned for.");
        }

        if (original.DiskBytes <= 0 || original.DiskBytes % sectorSize != 0)
        {
            throw new InvalidOperationException(
                $"Disk length {original.DiskBytes} is not a positive whole number of {sectorSize}-byte sectors.");
        }

        long diskSectors = original.DiskBytes / sectorSize;
        long firstUsable = original.FirstUsableSector;
        long lastUsable = original.LastUsableSector;
        if (firstUsable < 2 || firstUsable > lastUsable || lastUsable >= diskSectors - 1)
        {
            throw new InvalidOperationException(
                "The usable window is invalid or reaches into the reserved backup header.");
        }

        ValidatePartitions(original.Partitions, sectorSize, firstUsable, lastUsable);
        GptPartition userdata = FindUserdata(original.Partitions);

        ValidatePackageStorage(storage, out long bootBytes, out long systemBytes, out long requiredRootBytes);

        if (androidGiB < MinimumAndroidGiB)
        {
            throw new ArgumentException(
                $"Android must receive at least {MinimumAndroidGiB} GiB, not {androidGiB}.", nameof(androidGiB));
        }

        long androidBytes;
        try
        {
            androidBytes = checked(androidGiB * GiB);
        }
        catch (OverflowException ex)
        {
            throw new ArgumentException($"Android size {androidGiB} GiB overflows in bytes.", nameof(androidGiB), ex);
        }

        long alignmentSectors = MiB / sectorSize;
        long originalStart = userdata.StartSector;
        long originalEnd = userdata.StartSector + userdata.SectorCount; // validated representable

        // The backup tail sits at the last whole MiB boundary of the original userdata window; the slack
        // beyond it is reported as tail loss instead of being handed to any extent.
        long backupEndSector = originalEnd / alignmentSectors * alignmentSectors;
        long backupSectorCount = BackupTailBytes / sectorSize;
        long backupStartSector = backupEndSector - backupSectorCount;

        long androidSectorCount = androidBytes / sectorSize;
        long linuxBootSectorCount = bootBytes / sectorSize;
        long androidEndSector;
        long bootStartSector;
        long rootStartSector;
        long rootSectorCount;
        try
        {
            androidEndSector = checked(originalStart + androidSectorCount);
            bootStartSector = checked(CeilToAlignment(androidEndSector, alignmentSectors));
            rootStartSector = checked(bootStartSector + linuxBootSectorCount);
            rootSectorCount = backupStartSector - rootStartSector;
        }
        catch (OverflowException ex)
        {
            throw new ArgumentException("The planned extents overflow the sector space.", nameof(androidGiB), ex);
        }

        if (rootSectorCount <= 0)
        {
            throw new ArgumentException("The package leaves no room for the Linux root extent.", nameof(storage));
        }

        long alignmentGapSectors = bootStartSector - androidEndSector;
        long tailSectors = originalEnd - backupEndSector;
        if (alignmentGapSectors < 0 || tailSectors < 0 || bootStartSector < originalStart || backupEndSector > originalEnd)
        {
            throw new ArgumentException("The planned extents leave the original userdata window.", nameof(storage));
        }

        long linuxBootBytes = bootBytes;
        long linuxBytes;
        long linuxRootBytes;
        long alignmentLossBytes;
        try
        {
            linuxRootBytes = checked(rootSectorCount * sectorSize);
            linuxBytes = checked((backupStartSector - bootStartSector) * sectorSize);
            alignmentLossBytes = checked((alignmentGapSectors + tailSectors) * sectorSize);
        }
        catch (OverflowException ex)
        {
            throw new ArgumentException("The planned extents overflow their byte representation.", nameof(storage), ex);
        }

        long requiredLinuxBytes;
        try
        {
            requiredLinuxBytes = Math.Max(MinimumLinuxBytes, checked(bootBytes + requiredRootBytes));
        }
        catch (OverflowException ex)
        {
            throw new ArgumentException("The package's Linux requirement overflows in bytes.", nameof(storage), ex);
        }

        if (linuxBytes < MinimumLinuxBytes || linuxBytes < requiredLinuxBytes || linuxRootBytes < requiredRootBytes)
        {
            throw new ArgumentException(
                $"The plan leaves {linuxBytes} Linux bytes and {linuxRootBytes} root bytes, "
                + $"below the required {requiredLinuxBytes} and {requiredRootBytes} bytes.",
                nameof(storage));
        }

        return new InternalAllocationPlan(
            userdata,
            sectorSize,
            originalEnd,
            androidBytes,
            androidSectorCount,
            androidEndSector,
            linuxBytes,
            linuxBootBytes,
            linuxRootBytes,
            linuxRootBytes - systemBytes,
            bootStartSector,
            linuxBootSectorCount,
            rootStartSector,
            rootSectorCount,
            BackupTailBytes,
            backupStartSector,
            backupSectorCount,
            backupEndSector,
            alignmentGapSectors,
            tailSectors,
            alignmentLossBytes);
    }

    private static void ValidatePartitions(
        IReadOnlyList<GptPartition> partitions,
        int sectorSize,
        long firstUsable,
        long lastUsable)
    {
        var numbers = new HashSet<int>();
        var ranges = new List<(long Start, long End)>(partitions.Count);

        foreach (GptPartition partition in partitions)
        {
            if (partition is null)
            {
                throw new InvalidOperationException("The partition table contains a null entry.");
            }

            if (partition.Number <= 0 || !numbers.Add(partition.Number))
            {
                throw new InvalidOperationException(
                    $"Partition number {partition.Number} is not positive and unique.");
            }

            if (partition.StartSector < 0 || partition.SectorCount <= 0)
            {
                throw new InvalidOperationException(
                    $"Partition {partition.Number} has a negative start sector or a non-positive sector count.");
            }

            long end;
            try
            {
                // Arithmetic representability is decided before the usable-window check, so a malformed
                // window never hides an overflow.
                end = checked(partition.StartSector + partition.SectorCount);
                _ = checked(partition.StartSector * sectorSize);
                _ = checked(partition.SectorCount * sectorSize);
                _ = checked(end * sectorSize);
            }
            catch (OverflowException ex)
            {
                throw new ArgumentException(
                    $"Partition {partition.Number} does not fit in the sector or byte space.", ex);
            }

            if (partition.StartSector < firstUsable || end > lastUsable + 1)
            {
                throw new InvalidOperationException(
                    $"Partition {partition.Number} lies outside the usable window.");
            }

            ranges.Add((partition.StartSector, end));
        }

        // Local copy only: the table snapshot and its entry order are never mutated.
        ranges.Sort(static (left, right) => left.Start.CompareTo(right.Start));
        for (int index = 1; index < ranges.Count; index++)
        {
            if (ranges[index].Start < ranges[index - 1].End)
            {
                throw new InvalidOperationException("Two partitions of the table overlap.");
            }
        }
    }

    private static GptPartition FindUserdata(IReadOnlyList<GptPartition> partitions)
    {
        GptPartition? userdata = null;
        foreach (GptPartition partition in partitions)
        {
            if (!string.Equals(partition.Name.Trim(), UserdataName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (userdata is not null)
            {
                throw new InvalidOperationException("The table names more than one userdata partition.");
            }

            userdata = partition;
        }

        return userdata ?? throw new InvalidOperationException("The table has no userdata partition.");
    }

    private static void ValidatePackageStorage(
        PackageStorage storage,
        out long bootBytes,
        out long systemBytes,
        out long requiredRootBytes)
    {
        bootBytes = storage.LinuxBootBytes;
        systemBytes = storage.SystemRequiredBytes;
        long scratchBytes = storage.DeploymentScratchBytes;
        long minimumDataBytes = storage.MinimumLinuxDataBytes;

        if (bootBytes <= 0 || bootBytes % MiB != 0)
        {
            throw new ArgumentException("Package boot bytes must be positive and a whole MiB.", nameof(storage));
        }

        if (systemBytes <= 0)
        {
            throw new ArgumentException("Package system bytes must be positive.", nameof(storage));
        }

        if (scratchBytes < 0)
        {
            throw new ArgumentException("Package scratch bytes cannot be negative.", nameof(storage));
        }

        if (minimumDataBytes <= 0)
        {
            throw new ArgumentException("Package minimum data bytes must be positive.", nameof(storage));
        }

        long declaredBytes;
        try
        {
            declaredBytes = checked(systemBytes + scratchBytes + minimumDataBytes);
        }
        catch (OverflowException ex)
        {
            throw new ArgumentException(
                "The package's system, scratch and minimum data bytes overflow when summed.", nameof(storage), ex);
        }

        requiredRootBytes = Math.Max(MinimumRootBytes, declaredBytes);
    }

    private static long CeilToAlignment(long sectors, long alignmentSectors)
    {
        long remainder = sectors % alignmentSectors;
        return remainder == 0 ? sectors : sectors + (alignmentSectors - remainder);
    }
}

/// <summary>
/// Result of <see cref="InternalPartitionPlanner.Plan"/>. All sector values are absolute sectors of
/// <see cref="SectorSize"/>. Every <c>*EndSectorExclusive</c> member is half-open: it is one sector past the
/// last sector of its extent, so <c>StartSector + SectorCount == EndSectorExclusive</c> and no extent ever
/// contains its own end sector. <see cref="LinuxBytes"/> covers the Linux boot and root extents only - it
/// excludes the reserved <see cref="BackupBytes"/> tail as well as every alignment gap and tail slack, whose
/// combined cost is reported by <see cref="AlignmentLossBytes"/> instead.
/// </summary>
/// <param name="OriginalUserdata">
/// The untouched original userdata entry: same instance, number, name, type GUID, partition UUID, attributes
/// and start sector, even when that start is not 1 MiB aligned.
/// </param>
/// <param name="SectorSize">Sector size of the source table, 512 or 4096.</param>
/// <param name="OriginalUserdataEndSectorExclusive">Half-open end of the whole original userdata partition.</param>
/// <param name="AndroidBytes">Bytes handed to Android; exactly <c>androidGiB * 1 GiB</c>.</param>
/// <param name="AndroidSectorCount">Sectors the Android userdata window spans.</param>
/// <param name="AndroidEndSectorExclusive">Half-open end of the Android window.</param>
/// <param name="LinuxBytes">Bytes of the Linux boot and root extents together, excluding backup and gaps.</param>
/// <param name="LinuxBootBytes">Bytes of the Linux boot extent.</param>
/// <param name="LinuxRootBytes">Bytes of the Linux root extent.</param>
/// <param name="EstimatedLinuxDataBytes">Usable data bytes left on root after the package's system requirement is placed.</param>
/// <param name="LinuxBootStartSector">First sector of the Linux boot extent.</param>
/// <param name="LinuxBootSectorCount">Sectors the Linux boot extent spans.</param>
/// <param name="LinuxRootStartSector">First sector of the Linux root extent.</param>
/// <param name="LinuxRootSectorCount">Sectors the Linux root extent spans; it ends at <see cref="BackupStartSector"/>.</param>
/// <param name="BackupBytes">Reserved backup tail in bytes; always 2 GiB, independent of the package boot size.</param>
/// <param name="BackupStartSector">First sector of the reserved backup tail.</param>
/// <param name="BackupSectorCount">Sectors the backup tail spans.</param>
/// <param name="BackupEndSectorExclusive">
/// Half-open end of the backup tail; it is 1 MiB aligned and at or before the original userdata end.
/// </param>
/// <param name="AlignmentGapSectors">Sectors lost to the aligned start of the Linux boot extent.</param>
/// <param name="TailUnallocatedSectors">Sectors left between the backup end and the original userdata end.</param>
/// <param name="AlignmentLossBytes">
/// <c>(AlignmentGapSectors + TailUnallocatedSectors) * SectorSize</c>; loss is neither Android, Linux nor
/// backup usable space.
/// </param>
public sealed record InternalAllocationPlan(
    GptPartition OriginalUserdata,
    int SectorSize,
    long OriginalUserdataEndSectorExclusive,
    long AndroidBytes,
    long AndroidSectorCount,
    long AndroidEndSectorExclusive,
    long LinuxBytes,
    long LinuxBootBytes,
    long LinuxRootBytes,
    long EstimatedLinuxDataBytes,
    long LinuxBootStartSector,
    long LinuxBootSectorCount,
    long LinuxRootStartSector,
    long LinuxRootSectorCount,
    long BackupBytes,
    long BackupStartSector,
    long BackupSectorCount,
    long BackupEndSectorExclusive,
    long AlignmentGapSectors,
    long TailUnallocatedSectors,
    long AlignmentLossBytes);
