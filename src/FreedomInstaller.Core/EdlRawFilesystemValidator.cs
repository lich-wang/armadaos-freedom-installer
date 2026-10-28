using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;

namespace FreedomInstaller.Core;

/// <summary>
/// Validates an already-read ext4 or Btrfs primary superblock against the declared expanded
/// image: magic, layout fields and the RFC 4122 filesystem UUID checks, shared by the
/// expanded-package verification path.
/// </summary>
internal static class EdlRawFilesystemValidator
{
    private const long Ext4SuperblockOffset = 1024L;

    private const int Ext4SuperblockBytes = 0x158;

    private const int Ext4MagicOffset = 0x38;

    private const int Ext4BlocksLowOffset = 0x04;

    private const int Ext4LogBlockSizeOffset = 0x18;

    private const int Ext4FeatureIncompatOffset = 0x60;

    private const int Ext4BlocksHighOffset = 0x150;

    private const int Ext4UuidOffset = 0x68;

    private const ushort Ext4Magic = 0xEF53;

    private const uint Ext4Incompat64Bit = 0x80;

    private const uint Ext4MaxLogBlockSize = 6;

    private const long BtrfsSuperblockOffset = 65536L;

    private const int BtrfsSuperblockBytes = 148;

    private const int BtrfsFsidOffset = 32;

    private const int BtrfsBytenrOffset = 48;

    private const int BtrfsMagicOffset = 64;

    private const int BtrfsMagicLength = 8;

    private const int BtrfsTotalBytesOffset = 112;

    private const int BtrfsDevicesOffset = 136;

    private const int BtrfsSectorSizeOffset = 144;

    /// <summary>Exactly the eight ASCII bytes a primary Btrfs superblock carries at +64.</summary>
    private static readonly byte[] BtrfsSuperblockMagic = Encoding.ASCII.GetBytes("_BHRfS_M");

    /// <summary>
    /// Validates the actual ext4 primary superblock: magic, block count (with the high word only
    /// when the 64bit incompat feature is really set), block size, total filesystem bytes and the
    /// package UUID in RFC 4122 network order.
    /// </summary>
    internal static void ValidateExt4(
        ReadOnlySpan<byte> superblock,
        long actualImageBytes,
        EdlRawImage image,
        Guid expectedUuid)
    {
        if (actualImageBytes < Ext4SuperblockOffset + Ext4SuperblockBytes
            || superblock.Length < Ext4SuperblockBytes)
        {
            throw new InvalidDataException(
                $"The expanded image '{image.Artifact.Role}' is too short to carry an ext4 superblock.");
        }

        if (BinaryPrimitives.ReadUInt16LittleEndian(superblock.Slice(Ext4MagicOffset)) != Ext4Magic)
        {
            throw new InvalidDataException(
                $"The expanded image '{image.Artifact.Role}' does not carry the ext4 magic 0xEF53 at 1024+0x38.");
        }

        ulong blocks = BinaryPrimitives.ReadUInt32LittleEndian(superblock.Slice(Ext4BlocksLowOffset));
        var logBlockSize = BinaryPrimitives.ReadUInt32LittleEndian(
            superblock.Slice(Ext4LogBlockSizeOffset));
        var incompat = BinaryPrimitives.ReadUInt32LittleEndian(
            superblock.Slice(Ext4FeatureIncompatOffset));

        if ((incompat & Ext4Incompat64Bit) != 0)
        {
            blocks |= (ulong)BinaryPrimitives.ReadUInt32LittleEndian(
                superblock.Slice(Ext4BlocksHighOffset)) << 32;
        }

        if (blocks == 0)
        {
            throw new InvalidDataException(
                $"The expanded image '{image.Artifact.Role}' declares an empty ext4 filesystem.");
        }

        if (logBlockSize > Ext4MaxLogBlockSize)
        {
            throw new InvalidDataException(
                $"The expanded image '{image.Artifact.Role}' declares an impossible ext4 log block size.");
        }

        ulong filesystemBytes;
        try
        {
            filesystemBytes = checked(blocks * (1024UL << (int)logBlockSize));
        }
        catch (OverflowException)
        {
            throw new InvalidDataException(
                $"The expanded image '{image.Artifact.Role}' declares an impossible ext4 size.");
        }

        if (filesystemBytes != (ulong)image.ExpandedBytes || filesystemBytes != (ulong)actualImageBytes)
        {
            throw new InvalidDataException(
                $"The actual ext4 size of '{image.Artifact.Role}' does not match its declared expanded length.");
        }

        var uuid = new Guid(superblock.Slice(Ext4UuidOffset, 16), bigEndian: true);
        if (uuid != image.FsUuid || uuid != expectedUuid)
        {
            throw new InvalidDataException(
                $"The actual ext4 UUID of '{image.Artifact.Role}' does not match the declared filesystem UUID.");
        }
    }

    /// <summary>
    /// Validates the actual Btrfs primary superblock: magic, FSID, bytenr, total bytes, the
    /// single-device count and the declared sector size.
    /// </summary>
    internal static void ValidateBtrfs(
        ReadOnlySpan<byte> superblock,
        long actualImageBytes,
        EdlRawImage image,
        Guid expectedUuid)
    {
        if (actualImageBytes < BtrfsSuperblockOffset + BtrfsSuperblockBytes
            || superblock.Length < BtrfsSuperblockBytes)
        {
            throw new InvalidDataException(
                $"The expanded image '{image.Artifact.Role}' is too short to carry a Btrfs superblock.");
        }

        if (!superblock.Slice(BtrfsMagicOffset, BtrfsMagicLength).SequenceEqual(BtrfsSuperblockMagic))
        {
            throw new InvalidDataException(
                $"The expanded image '{image.Artifact.Role}' does not carry the Btrfs magic at 65536+64.");
        }

        var fsid = new Guid(superblock.Slice(BtrfsFsidOffset, 16), bigEndian: true);
        if (fsid != image.FsUuid || fsid != expectedUuid)
        {
            throw new InvalidDataException(
                $"The actual Btrfs FSID of '{image.Artifact.Role}' does not match the declared filesystem UUID.");
        }

        if (BinaryPrimitives.ReadInt64LittleEndian(superblock.Slice(BtrfsBytenrOffset)) != BtrfsSuperblockOffset)
        {
            throw new InvalidDataException(
                $"The actual Btrfs bytenr of '{image.Artifact.Role}' is not 65536.");
        }

        if (BinaryPrimitives.ReadInt64LittleEndian(superblock.Slice(BtrfsTotalBytesOffset)) != actualImageBytes)
        {
            throw new InvalidDataException(
                $"The actual Btrfs total_bytes of '{image.Artifact.Role}' does not match the expanded length.");
        }

        if (BinaryPrimitives.ReadInt64LittleEndian(superblock.Slice(BtrfsDevicesOffset)) != 1L)
        {
            throw new InvalidDataException(
                $"The actual Btrfs superblock of '{image.Artifact.Role}' is not a single-device filesystem.");
        }

        var sectorSize = BinaryPrimitives.ReadInt32LittleEndian(
            superblock.Slice(BtrfsSectorSizeOffset));
        if (sectorSize != image.SectorSize)
        {
            throw new InvalidDataException(
                $"The actual Btrfs sector size of '{image.Artifact.Role}' does not match the declared "
                + $"{image.SectorSize} bytes.");
        }
    }
}
