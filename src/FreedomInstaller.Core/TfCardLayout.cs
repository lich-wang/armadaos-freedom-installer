using System;
using System.Buffers.Binary;
using System.Text;

namespace FreedomInstaller.Core;

/// <summary>
/// Immutable result of <see cref="TfCardLayout.Create"/>: the fixed TF-card partition geometry together
/// with the identities to stamp into the GPT. Every value is final once created; nothing is editable.
/// </summary>
public sealed class TfCardLayoutPlan
{
    internal TfCardLayoutPlan(
        long cardBytes,
        int logicalSectorSize,
        long totalSectors,
        long bootStartSector,
        long bootSectorCount,
        long rootStartSector,
        long rootSectorCount,
        Guid diskGuid,
        Guid bootGuid,
        Guid rootGuid)
    {
        CardBytes = cardBytes;
        LogicalSectorSize = logicalSectorSize;
        TotalSectors = totalSectors;
        BootStartSector = bootStartSector;
        BootSectorCount = bootSectorCount;
        RootStartSector = rootStartSector;
        RootSectorCount = rootSectorCount;
        DiskGuid = diskGuid;
        BootGuid = bootGuid;
        RootGuid = rootGuid;
    }

    public long CardBytes { get; }

    public int LogicalSectorSize { get; }

    public long TotalSectors { get; }

    public long BootStartSector { get; }

    public long BootSectorCount { get; }

    public long RootStartSector { get; }

    public long RootSectorCount { get; }

    public Guid DiskGuid { get; }

    public Guid BootGuid { get; }

    public Guid RootGuid { get; }
}

/// <summary>
/// The small byte fragments that carry the whole protective MBR + GPT of a planned card: where each
/// fragment starts on the disk and its bytes. No fragment ever spans the partitions themselves.
/// </summary>
public sealed class TfGptWriteSet
{
    internal TfGptWriteSet(long backupOffsetBytes, byte[] primaryBytes, byte[] backupBytes)
    {
        BackupOffsetBytes = backupOffsetBytes;
        PrimaryBytes = primaryBytes;
        BackupBytes = backupBytes;
    }

    /// <summary>The primary fragment always starts at byte 0 of the card.</summary>
    public long PrimaryOffsetBytes => 0;

    public byte[] PrimaryBytes { get; }

    public long BackupOffsetBytes { get; }

    public byte[] BackupBytes { get; }
}

/// <summary>
/// Pure, in-memory layout and serialization of the TF-card GPT used by the Linux install: one boot and one
/// root partition on a protective-MBR disk, serialized as primary and backup GPT fragments. No device,
/// file, shell or native API is touched.
/// </summary>
public static class TfCardLayout
{
    private const int SectorSize512 = 512;
    private const int SectorSize4096 = 4096;
    private const long MiB = 1024L * 1024;
    private const long FirstUsableSector512 = 34;
    private const long FirstUsableSector4096 = 6;
    private const int HeaderBytes = 92;
    private const int EntryCount = 128;
    private const int EntrySize = 128;

    private static readonly Guid LinuxFileSystemGuid = new("0fc63daf-8483-4772-8e79-3d69d8477de4");

    public static TfCardLayoutPlan Create(
        long cardBytes,
        int logicalSectorSize,
        long linuxBootImageBytes,
        long linuxRootImageBytes,
        long minimumLinuxRootBytes,
        Guid diskGuid,
        Guid bootGuid,
        Guid rootGuid)
    {
        if (logicalSectorSize != SectorSize512 && logicalSectorSize != SectorSize4096)
        {
            throw new ArgumentException(
                "The logical sector size must be 512 or 4096 bytes.", nameof(logicalSectorSize));
        }

        RequirePositiveAndAligned(cardBytes, logicalSectorSize, nameof(cardBytes));
        RequirePositiveAndAligned(linuxBootImageBytes, logicalSectorSize, nameof(linuxBootImageBytes));
        RequirePositiveAndAligned(linuxRootImageBytes, logicalSectorSize, nameof(linuxRootImageBytes));

        if (minimumLinuxRootBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(minimumLinuxRootBytes));
        }

        if (diskGuid == Guid.Empty)
        {
            throw new ArgumentException("The disk GUID must not be zero.", nameof(diskGuid));
        }

        if (bootGuid == Guid.Empty)
        {
            throw new ArgumentException("The boot partition GUID must not be zero.", nameof(bootGuid));
        }

        if (rootGuid == Guid.Empty)
        {
            throw new ArgumentException("The root partition GUID must not be zero.", nameof(rootGuid));
        }

        if (bootGuid == rootGuid)
        {
            throw new ArgumentException(
                "The boot and root partitions must carry different GUIDs.", nameof(rootGuid));
        }

        checked
        {
            var firstUsable = logicalSectorSize == SectorSize512 ? FirstUsableSector512 : FirstUsableSector4096;
            var totalSectors = cardBytes / logicalSectorSize;
            var lastUsable = totalSectors - firstUsable;

            // The boot partition starts at 1 MiB; the root partition starts at the next 1 MiB boundary
            // after the boot image and runs to the end of the usable range.
            var bootStart = MiB / logicalSectorSize;
            var rootStart = AlignUp(MiB + linuxBootImageBytes, MiB) / logicalSectorSize;

            if (rootStart > lastUsable)
            {
                throw new ArgumentException(
                    "The card is too small to hold the boot image and a root partition.", nameof(cardBytes));
            }

            var rootSectorCapacity = lastUsable - rootStart + 1;
            var rootRequiredSectors =
                (Math.Max(linuxRootImageBytes, minimumLinuxRootBytes) + logicalSectorSize - 1) / logicalSectorSize;

            if (rootSectorCapacity < rootRequiredSectors)
            {
                throw new ArgumentException(
                    "The card cannot offer the required root partition size after the GPT and boot overhead.",
                    nameof(minimumLinuxRootBytes));
            }

            return new TfCardLayoutPlan(
                cardBytes,
                logicalSectorSize,
                totalSectors,
                bootStart,
                rootStart - bootStart,
                rootStart,
                rootSectorCapacity,
                diskGuid,
                bootGuid,
                rootGuid);
        }
    }

    public static TfGptWriteSet SerializeGpt(TfCardLayoutPlan plan)
    {
        if (plan is null)
        {
            throw new ArgumentNullException(nameof(plan));
        }

        var sectorSize = plan.LogicalSectorSize;
        var totalSectors = plan.TotalSectors;
        var lastLba = totalSectors - 1;
        var firstUsable = sectorSize == SectorSize512 ? FirstUsableSector512 : FirstUsableSector4096;
        var lastUsable = totalSectors - firstUsable;
        var arrayBytes = EntryCount * EntrySize;
        var arraySectors = arrayBytes / sectorSize;

        var entries = BuildEntries(plan);
        var arrayCrc = Crc32(entries);

        // Primary fragment: protective MBR at LBA 0, header at LBA 1, entry array from LBA 2.
        var primary = new byte[(2 + arraySectors) * sectorSize];
        WriteProtectiveMbr(primary, plan.TotalSectors);
        WriteGptHeader(
            primary.AsSpan(sectorSize, sectorSize),
            currentLba: 1,
            backupLba: lastLba,
            firstUsable,
            lastUsable,
            plan.DiskGuid,
            entryArrayLba: 2,
            arrayCrc);
        entries.CopyTo(primary.AsSpan(2 * sectorSize, arrayBytes));

        // Backup fragment: entry array immediately before the header in the last sector of the disk.
        var backup = new byte[(1 + arraySectors) * sectorSize];
        entries.CopyTo(backup.AsSpan(0, arrayBytes));
        WriteGptHeader(
            backup.AsSpan(arraySectors * sectorSize, sectorSize),
            currentLba: lastLba,
            backupLba: 1,
            firstUsable,
            lastUsable,
            plan.DiskGuid,
            entryArrayLba: lastLba - arraySectors,
            arrayCrc);

        var backupOffset = (totalSectors - (1 + arraySectors)) * sectorSize;
        return new TfGptWriteSet(backupOffset, primary, backup);
    }

    private static void RequirePositiveAndAligned(long value, int sectorSize, string paramName)
    {
        if (value <= 0)
        {
            throw new ArgumentOutOfRangeException(paramName);
        }

        if (value % sectorSize != 0)
        {
            throw new ArgumentException(
                "The value must be a positive multiple of the logical sector size.", paramName);
        }
    }

    private static long AlignUp(long value, long alignment) => checked((value + alignment - 1) / alignment * alignment);

    private static byte[] BuildEntries(TfCardLayoutPlan plan)
    {
        var entries = new byte[EntryCount * EntrySize];

        WriteEntry(
            entries.AsSpan(0, EntrySize),
            plan.BootGuid,
            "ARMADA_TF_BOOT",
            plan.BootStartSector,
            plan.BootStartSector + plan.BootSectorCount - 1);

        WriteEntry(
            entries.AsSpan(EntrySize, EntrySize),
            plan.RootGuid,
            "ARMADA_TF_ROOT",
            plan.RootStartSector,
            plan.RootStartSector + plan.RootSectorCount - 1);

        return entries;
    }

    private static void WriteEntry(
        Span<byte> entry, Guid partitionGuid, string name, long startSector, long endSector)
    {
        LinuxFileSystemGuid.TryWriteBytes(entry[0..16]);
        partitionGuid.TryWriteBytes(entry[16..32]);
        BinaryPrimitives.WriteUInt64LittleEndian(entry[32..], (ulong)startSector);
        BinaryPrimitives.WriteUInt64LittleEndian(entry[40..], (ulong)endSector);

        // Attributes stay zero and all remaining entry bytes stay zero except the UTF-16LE name.
        Encoding.Unicode.GetBytes(name, entry[56..88]);
    }

    private static void WriteGptHeader(
        Span<byte> sector,
        long currentLba,
        long backupLba,
        long firstUsable,
        long lastUsable,
        Guid diskGuid,
        long entryArrayLba,
        uint entryArrayCrc)
    {
        Span<byte> header = stackalloc byte[HeaderBytes];

        // "EFI PART"
        header[0] = 0x45;
        header[1] = 0x46;
        header[2] = 0x49;
        header[3] = 0x20;
        header[4] = 0x50;
        header[5] = 0x41;
        header[6] = 0x52;
        header[7] = 0x54;

        BinaryPrimitives.WriteUInt32LittleEndian(header[8..], 0x0001_0000); // revision 1.0
        BinaryPrimitives.WriteUInt32LittleEndian(header[12..], HeaderBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(header[16..], 0); // header CRC32, filled in below
        BinaryPrimitives.WriteUInt32LittleEndian(header[20..], 0); // reserved

        BinaryPrimitives.WriteUInt64LittleEndian(header[24..], (ulong)currentLba);
        BinaryPrimitives.WriteUInt64LittleEndian(header[32..], (ulong)backupLba);
        BinaryPrimitives.WriteUInt64LittleEndian(header[40..], (ulong)firstUsable);
        BinaryPrimitives.WriteUInt64LittleEndian(header[48..], (ulong)lastUsable);

        diskGuid.TryWriteBytes(header[56..72]);

        BinaryPrimitives.WriteUInt64LittleEndian(header[72..], (ulong)entryArrayLba);
        BinaryPrimitives.WriteUInt32LittleEndian(header[80..], EntryCount);
        BinaryPrimitives.WriteUInt32LittleEndian(header[84..], EntrySize);
        BinaryPrimitives.WriteUInt32LittleEndian(header[88..], entryArrayCrc);

        BinaryPrimitives.WriteUInt32LittleEndian(header[16..], Crc32(header));
        header.CopyTo(sector);
    }

    private static void WriteProtectiveMbr(Span<byte> lba0, long totalSectors)
    {
        var entry = lba0.Slice(446, 16);
        entry[4] = 0xEE; // protective MBR partition type

        // UEFI convention (matching util-linux gpt.c gpt_write_pmbr): the protective entry covers the
        // whole disk minus the MBR itself, counted in logical sectors of this disk, capped at the
        // 32-bit field maximum. CHS addressing is not used: start CHS is (0, 2, 0) and end CHS is the
        // (0xFF, 0xFF, 0xFF) "not applicable" tuple.
        var coverBlocks = totalSectors - 1;
        if (coverBlocks > uint.MaxValue)
        {
            coverBlocks = uint.MaxValue;
        }

        entry[1] = 0x00;
        entry[2] = 0x02;
        entry[3] = 0x00;
        entry[5] = 0xFF;
        entry[6] = 0xFF;
        entry[7] = 0xFF;

        BinaryPrimitives.WriteUInt32LittleEndian(entry[8..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(entry[12..], (uint)coverBlocks);

        lba0[510] = 0x55;
        lba0[511] = 0xAA;
    }

    private static uint Crc32(ReadOnlySpan<byte> data)
    {
        var crc = 0xFFFF_FFFFu;
        foreach (var byteValue in data)
        {
            crc ^= byteValue;
            for (var bit = 0; bit < 8; bit++)
            {
                var mask = (crc & 1) != 0 ? 0xEDB8_8320u : 0u;
                crc = (crc >> 1) ^ mask;
            }
        }

        return ~crc;
    }
}
