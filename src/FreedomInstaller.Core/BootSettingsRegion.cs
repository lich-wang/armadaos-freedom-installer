using System.Buffers.Binary;

namespace FreedomInstaller.Core;

/// <summary>The explicit mutable tail of a v3 ARMADA_BACKUP image.
/// UUID bytes are RFC 4122 order, matching kShimC after GPT UUID conversion.
/// Recovery validates the immutable descriptor and reserved bytes. Both settings
/// slots remain independent of recovery validation, including interrupted writes.</summary>
internal static class BootSettingsRegion
{
    internal const int Bytes = 65536;
    internal const int SlotBytes = 4096;
    internal const long Offset = (2L << 30) - Bytes;
    internal const string Format = "armada-gzip-ustar-v3";
    internal static uint BoardId(string model) => model switch
    {
        "TB322FC" => 1,
        "TB323FU" => 2,
        _ => throw new InvalidDataException("No launcher settings profile for this model.")
    };

    internal static byte[] CreateDescriptor(Guid partition, Guid installation, string model, long payloadEnd)
    {
        if (partition == Guid.Empty || installation == Guid.Empty || payloadEnd < 65536 || payloadEnd > Offset)
            throw new InvalidDataException("Launcher settings overlap the archive or have no installation identity.");
        uint board = BoardId(model);
        var d = new byte[SlotBytes];
        "KSCFGV3\0"u8.CopyTo(d);
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(8), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(12), SlotBytes);
        BinaryPrimitives.WriteInt64LittleEndian(d.AsSpan(16), 2L << 30);
        BinaryPrimitives.WriteInt64LittleEndian(d.AsSpan(24), payloadEnd);
        BinaryPrimitives.WriteInt64LittleEndian(d.AsSpan(32), Offset);
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(40), Bytes);
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(44), SlotBytes);
        partition.ToByteArray(bigEndian: true).CopyTo(d, 48);
        installation.ToByteArray(bigEndian: true).CopyTo(d, 64);
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(80), SlotBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(84), 2 * SlotBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(88), board);
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(4092),
            InternalInstallArtifacts.Crc32(d.AsSpan(0, 4092)));
        return d;
    }

    internal static void VerifyRegion(byte[] region, Guid partition, Guid installation, string model, long payloadEnd)
    {
        if (region.Length != Bytes ||
            !region.AsSpan(0, SlotBytes).SequenceEqual(CreateDescriptor(partition, installation, model, payloadEnd)))
            throw new InvalidDataException("The launcher settings descriptor does not match this archive.");
        foreach (byte value in region.AsSpan(3 * SlotBytes))
            if (value != 0)
                throw new InvalidDataException("The reserved launcher settings tail is not zero filled.");
    }
}
