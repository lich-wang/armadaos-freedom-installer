using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;

namespace FreedomInstaller.Core;

/// <summary>
/// One used GPT entry, already decoded out of its on-disk form: GUIDs are canonical strings, sector values
/// are absolute sectors in the table's own sector size and <see cref="Attributes"/> is the raw 64-bit
/// attribute word. The instance is a read-only snapshot; nothing here can be edited after the parse.
/// </summary>
public sealed class GptPartition
{
    internal GptPartition(
        int number,
        string name,
        string typeGuid,
        string partUuid,
        long startSector,
        long sectorCount,
        ulong attributes)
    {
        Number = number;
        Name = name;
        TypeGuid = typeGuid;
        PartUuid = partUuid;
        StartSector = startSector;
        SectorCount = sectorCount;
        Attributes = attributes;
    }

    /// <summary>1-based GPT entry number, i.e. the slot index in the entry array plus one.</summary>
    public int Number { get; }

    /// <summary>Partition name decoded from the UTF-16LE name field; empty when the entry carries no name.</summary>
    public string Name { get; }

    /// <summary>Type GUID of the entry in canonical form.</summary>
    public string TypeGuid { get; }

    /// <summary>
    /// Unique partition GUID of the entry - the value the installer records as PARTUUID - in canonical form.
    /// Ownership of a partition is decided by this value, never by <see cref="Name"/> alone.
    /// </summary>
    public string PartUuid { get; }

    /// <summary>Absolute first sector of the partition.</summary>
    public long StartSector { get; }

    /// <summary>Number of sectors the partition spans; its last sector is StartSector + SectorCount - 1.</summary>
    public long SectorCount { get; }

    /// <summary>Raw GPT attribute word of the entry, exactly as stored.</summary>
    public ulong Attributes { get; }
}

/// <summary>
/// Read-only snapshot of one whole GPT: disk identity, usable window, the used entries and a fingerprint of
/// the bytes this table was decoded from. <see cref="DeviceId"/> is null for a table that came from a raw
/// original dump, because those bytes name no device node; a table reported by the live disk carries the
/// device node the reporter used.
/// </summary>
public sealed class GptTable
{
    internal GptTable(
        string? deviceId,
        int sectorSize,
        long diskBytes,
        string diskGuid,
        long firstUsableSector,
        long lastUsableSector,
        IReadOnlyList<GptPartition> partitions,
        string sourceFingerprint)
    {
        DeviceId = deviceId;
        SectorSize = sectorSize;
        DiskBytes = diskBytes;
        DiskGuid = diskGuid;
        FirstUsableSector = firstUsableSector;
        LastUsableSector = lastUsableSector;
        Partitions = new ReadOnlyCollection<GptPartition>(
            new List<GptPartition>(partitions ?? throw new ArgumentNullException(nameof(partitions))));
        SourceFingerprint = sourceFingerprint;
    }

    /// <summary>Device node this table was reported for, or null when it was decoded from a raw original dump.</summary>
    public string? DeviceId { get; }

    /// <summary>Sector size the table was decoded with. Only 512 and 4096 are ever accepted.</summary>
    public int SectorSize { get; }

    /// <summary>Size of the whole disk in bytes; every sector value above belongs to this disk.</summary>
    public long DiskBytes { get; }

    /// <summary>Disk GUID of the GPT header in canonical form.</summary>
    public string DiskGuid { get; }

    /// <summary>First LBA a partition may start at, as declared by the header.</summary>
    public long FirstUsableSector { get; }

    /// <summary>Last LBA a partition may end at, as declared by the header.</summary>
    public long LastUsableSector { get; }

    /// <summary>Used entries only, in table order. Entries whose type GUID is zero are not reported.</summary>
    public IReadOnlyList<GptPartition> Partitions { get; }

    /// <summary>
    /// Opaque SHA-256 fingerprint of the validated source bytes together with the sector size and disk
    /// dimensions. Two tables that were decoded from different bytes - or from the same bytes at a different
    /// sector size - carry different fingerprints; the exact input to the hash is an implementation detail.
    /// </summary>
    public string SourceFingerprint { get; }
}

/// <summary>
/// Rebuilds the original Android partition table from raw GPT bytes captured before the Linux install.
/// <para>
/// <paramref name="primaryFragment"/> starts at LBA 0 and <paramref name="backupFragment"/> ends at
/// <c>diskBytes</c>, so the backup header lives at <c>(diskBytes - backupFragment.Length) / sectorSize</c>
/// plus <c>lastLba</c> - the fragments are not both anchored at LBA 1. Both fragments are parsed in full and
/// must agree; a table that cannot be proven consistent is rejected, never repaired.
/// </para>
/// <para>
/// Rejection rules: malformed or untrustworthy bytes surface as <see cref="InvalidDataException"/>;
/// invalid caller input (null fragments, a sector size other than 512/4096, a fragment or disk length that is
/// not sector aligned) surfaces as <see cref="ArgumentException"/>. Limits: each fragment is at most 16 MiB
/// and the declared entry array at most 4 MiB, so no declared length can drive an unbounded allocation.
/// </para>
/// </summary>
public static class OriginalGptImporter
{
    private const int SignatureBytes = 8;
    private const int MinimumHeaderSize = 92;
    private const int HeaderSizeFieldOffset = 12;
    private const int HeaderCrcFieldOffset = 16;
    private const int ReservedFieldOffset = 20;
    private const int CurrentLbaOffset = 24;
    private const int AlternateLbaOffset = 32;
    private const int FirstUsableOffset = 40;
    private const int LastUsableOffset = 48;
    private const int DiskGuidOffset = 56;
    private const int EntryArrayLbaOffset = 72;
    private const int EntryCountOffset = 80;
    private const int EntrySizeFieldOffset = 84;
    private const int EntryArrayCrcOffset = 88;

    private const int EntrySize = 128;
    private const int TypeGuidOffset = 0;
    private const int PartUuidOffset = 16;
    private const int EntryStartOffset = 32;
    private const int EntryEndOffset = 40;
    private const int EntryAttributesOffset = 48;
    private const int EntryNameOffset = 56;
    private const int NameFieldBytes = 72;

    private const int MaximumFragmentBytes = 16 * 1024 * 1024;
    private const int MaximumEntryArrayBytes = 4 * 1024 * 1024;
    private const uint SupportedRevision = 0x0001_0000u;

    private static readonly byte[] HeaderSignature =
    {
        (byte)'E', (byte)'F', (byte)'I', (byte)' ', (byte)'P', (byte)'A', (byte)'R', (byte)'T',
    };

    /// <summary>
    /// Decodes the GPT whose primary fragment starts at LBA 0 and whose backup fragment ends at
    /// <paramref name="diskBytes"/>. The returned table has a null <see cref="GptTable.DeviceId"/>: raw
    /// original bytes identify no device node, and identity is never guessed from a dump path.
    /// </summary>
    /// <exception cref="ArgumentNullException">One of the fragments is null.</exception>
    /// <exception cref="ArgumentException">
    /// The sector size is not 512 or 4096, the disk length is not a positive sector multiple large enough for
    /// two headers, or a fragment is empty, not sector aligned, larger than 16 MiB or larger than the disk.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// The bytes are not a coherent GPT: bad signature or revision, failed header or entry array checksum, a
    /// header that is not where it claims to be, an entry array outside the reserved area or the fragment, or
    /// primary and backup that describe different tables.
    /// </exception>
    public static GptTable Parse(byte[] primaryFragment, byte[] backupFragment, int sectorSize, long diskBytes)
    {
        if (primaryFragment is null)
        {
            throw new ArgumentNullException(nameof(primaryFragment));
        }

        if (backupFragment is null)
        {
            throw new ArgumentNullException(nameof(backupFragment));
        }

        if (sectorSize != 512 && sectorSize != 4096)
        {
            throw new ArgumentException("The GPT sector size must be 512 or 4096 bytes.", nameof(sectorSize));
        }

        if (diskBytes <= 0 || diskBytes % sectorSize != 0)
        {
            throw new ArgumentException(
                "The disk length must be a positive multiple of the sector size.", nameof(diskBytes));
        }

        RequireFragment(primaryFragment, nameof(primaryFragment), sectorSize, diskBytes);
        RequireFragment(backupFragment, nameof(backupFragment), sectorSize, diskBytes);

        var totalSectors = diskBytes / sectorSize;
        if (totalSectors < 4)
        {
            throw new ArgumentException(
                "The disk length must leave room for a primary and a backup GPT header.", nameof(diskBytes));
        }

        var lastLba = totalSectors - 1;

        // The primary fragment starts at LBA 0, so its header is LBA 1. The backup fragment ends at the last
        // LBA, so its origin - and therefore its header offset - follows from its own length.
        const long primaryOriginLba = 0L;
        var primaryHeaderOffset = checked((int)((1L - primaryOriginLba) * sectorSize));

        var backupOriginLba = totalSectors - (backupFragment.Length / sectorSize);
        var backupHeaderOffset = checked((int)((lastLba - backupOriginLba) * sectorSize));

        var primary = ReadHeader(primaryFragment, primaryHeaderOffset, sectorSize, totalSectors, 1L, lastLba);
        var backup = ReadHeader(backupFragment, backupHeaderOffset, sectorSize, totalSectors, lastLba, 1L);

        RequireSameTable(primary, backup);

        var arraySectors = (primary.EntryArrayBytes + sectorSize - 1) / sectorSize;

        // Every structure has to sit in the reserved area: the primary array between the header and the first
        // usable sector, the backup array between the last usable sector and the backup header.
        if (primary.EntryArrayLba < 2
            || primary.EntryArrayLba > primary.FirstUsableSector - arraySectors)
        {
            throw new InvalidDataException(
                "The primary GPT entry array is not inside the reserved area before the usable range.");
        }

        if (backup.EntryArrayLba <= backup.LastUsableSector
            || backup.EntryArrayLba > lastLba - arraySectors)
        {
            throw new InvalidDataException(
                "The backup GPT entry array is not inside the reserved area after the usable range.");
        }

        var primaryArrayOffset = LocateEntryArray(
            primary.EntryArrayLba, primaryOriginLba, primaryFragment.Length, sectorSize, primary.EntryArrayBytes);

        var backupArrayOffset = LocateEntryArray(
            backup.EntryArrayLba, backupOriginLba, backupFragment.Length, sectorSize, backup.EntryArrayBytes);

        var primaryArray = primaryFragment.AsSpan(primaryArrayOffset, primary.EntryArrayBytes);
        var backupArray = backupFragment.AsSpan(backupArrayOffset, backup.EntryArrayBytes);

        // Each half is checked on its own over exactly the declared entry bytes, never over sector padding.
        if (Crc32(primaryArray) != primary.EntryArrayCrc)
        {
            throw new InvalidDataException("The primary GPT entry array checksum does not match its bytes.");
        }

        if (Crc32(backupArray) != backup.EntryArrayCrc)
        {
            throw new InvalidDataException("The backup GPT entry array checksum does not match its bytes.");
        }

        if (!primaryArray.SequenceEqual(backupArray))
        {
            throw new InvalidDataException("The primary and backup GPT entry arrays are not identical.");
        }

        var partitions = DecodeEntries(
            primaryArray, primary.EntryCount, primary.FirstUsableSector, primary.LastUsableSector);

        return new GptTable(
            deviceId: null,
            sectorSize,
            diskBytes,
            FormatGuid(primary.DiskGuid),
            primary.FirstUsableSector,
            primary.LastUsableSector,
            partitions,
            ComputeSourceFingerprint(primaryFragment, backupFragment, sectorSize, diskBytes));
    }

    private static void RequireFragment(byte[] fragment, string parameterName, int sectorSize, long diskBytes)
    {
        if (fragment.Length <= 0 || fragment.Length % sectorSize != 0)
        {
            throw new ArgumentException(
                "A GPT fragment must be a positive multiple of the sector size.", parameterName);
        }

        if (fragment.Length > MaximumFragmentBytes)
        {
            throw new ArgumentException("A GPT fragment must be at most 16 MiB.", parameterName);
        }

        if (fragment.Length > diskBytes)
        {
            throw new ArgumentException("A GPT fragment cannot be larger than the disk.", parameterName);
        }
    }

    private static GptHeader ReadHeader(
        byte[] fragment,
        int headerOffset,
        int sectorSize,
        long totalSectors,
        long expectedCurrentLba,
        long expectedAlternateLba)
    {
        // One whole present sector is required, so no read below can leave the fragment.
        if (headerOffset < 0 || headerOffset > fragment.Length - sectorSize)
        {
            throw new InvalidDataException(
                "The fragment does not contain a full GPT header sector at its expected location.");
        }

        var sector = fragment.AsSpan(headerOffset, sectorSize);

        if (!sector.Slice(0, SignatureBytes).SequenceEqual(HeaderSignature))
        {
            throw new InvalidDataException("The GPT header signature is missing.");
        }

        var revision = BinaryPrimitives.ReadUInt32LittleEndian(sector.Slice(8, 4));
        if (revision != SupportedRevision)
        {
            throw new InvalidDataException("The GPT header revision is not 1.0.");
        }

        var headerSize = BinaryPrimitives.ReadUInt32LittleEndian(sector.Slice(HeaderSizeFieldOffset, 4));
        if (headerSize < MinimumHeaderSize || headerSize > (uint)sectorSize)
        {
            throw new InvalidDataException("The GPT header size is outside the supported range.");
        }

        if (BinaryPrimitives.ReadUInt32LittleEndian(sector.Slice(ReservedFieldOffset, 4)) != 0u)
        {
            throw new InvalidDataException("The reserved GPT header field is not zero.");
        }

        var storedCrc = BinaryPrimitives.ReadUInt32LittleEndian(sector.Slice(HeaderCrcFieldOffset, 4));
        var crcCovered = sector.Slice(0, (int)headerSize).ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(crcCovered.AsSpan(HeaderCrcFieldOffset, 4), 0u);
        if (Crc32(crcCovered) != storedCrc)
        {
            throw new InvalidDataException("The GPT header checksum does not match the header bytes.");
        }

        var currentLba = ReadSectorField(sector, CurrentLbaOffset, "current", totalSectors);
        var alternateLba = ReadSectorField(sector, AlternateLbaOffset, "alternate", totalSectors);
        var firstUsableSector = ReadSectorField(sector, FirstUsableOffset, "first usable", totalSectors);
        var lastUsableSector = ReadSectorField(sector, LastUsableOffset, "last usable", totalSectors);

        if (currentLba != expectedCurrentLba)
        {
            throw new InvalidDataException("The GPT header is not at the LBA it declares.");
        }

        if (alternateLba != expectedAlternateLba)
        {
            throw new InvalidDataException("The GPT header does not point at the peer header location.");
        }

        // The usable range has to be strictly between the two header sectors: LBA 1 and the last LBA.
        if (firstUsableSector <= 1
            || lastUsableSector >= totalSectors - 1
            || firstUsableSector > lastUsableSector)
        {
            throw new InvalidDataException(
                "The declared usable range is not inside the disk between the primary and backup headers.");
        }

        var diskGuid = new Guid(sector.Slice(DiskGuidOffset, 16).ToArray());
        if (diskGuid == Guid.Empty)
        {
            throw new InvalidDataException("The GPT header carries a zero disk GUID.");
        }

        var entryArrayLba = ReadSectorField(sector, EntryArrayLbaOffset, "entry array", totalSectors);
        var entryCount = BinaryPrimitives.ReadUInt32LittleEndian(sector.Slice(EntryCountOffset, 4));
        var entrySize = BinaryPrimitives.ReadUInt32LittleEndian(sector.Slice(EntrySizeFieldOffset, 4));
        var entryArrayCrc = BinaryPrimitives.ReadUInt32LittleEndian(sector.Slice(EntryArrayCrcOffset, 4));

        if (entrySize != (uint)EntrySize)
        {
            throw new InvalidDataException("Only 128 byte GPT entries are supported.");
        }

        if (entryCount == 0)
        {
            throw new InvalidDataException("The GPT header declares no partition entries.");
        }

        // The declared length is checked against the cap before anything is allocated or indexed with it.
        var declaredArrayBytes = (ulong)entryCount * entrySize;
        if (declaredArrayBytes > MaximumEntryArrayBytes)
        {
            throw new InvalidDataException("The declared partition entry array exceeds 4 MiB.");
        }

        return new GptHeader(
            diskGuid,
            firstUsableSector,
            lastUsableSector,
            entryArrayLba,
            (int)entryCount,
            (int)entrySize,
            (int)headerSize,
            revision,
            (int)declaredArrayBytes,
            entryArrayCrc);
    }

    private static long ReadSectorField(
        ReadOnlySpan<byte> header, int offset, string field, long totalSectors)
    {
        // LBA fields are unsigned on disk and are rejected before any narrowing conversion.
        var raw = BinaryPrimitives.ReadUInt64LittleEndian(header.Slice(offset, 8));
        if (raw > long.MaxValue || raw >= (ulong)totalSectors)
        {
            throw new InvalidDataException($"The GPT header declares a {field} LBA outside the disk.");
        }

        return (long)raw;
    }

    private static void RequireSameTable(GptHeader primary, GptHeader backup)
    {
        if (primary.DiskGuid != backup.DiskGuid)
        {
            throw new InvalidDataException("The primary and backup GPT headers name different disks.");
        }

        if (primary.FirstUsableSector != backup.FirstUsableSector
            || primary.LastUsableSector != backup.LastUsableSector)
        {
            throw new InvalidDataException("The primary and backup GPT headers declare different usable ranges.");
        }

        if (primary.EntryCount != backup.EntryCount || primary.EntrySize != backup.EntrySize)
        {
            throw new InvalidDataException(
                "The primary and backup GPT headers declare different partition entry arrays.");
        }

        if (primary.HeaderSize != backup.HeaderSize || primary.Revision != backup.Revision)
        {
            throw new InvalidDataException("The primary and backup GPT headers have different layout versions.");
        }
    }

    private static int LocateEntryArray(
        long entryArrayLba, long originLba, int fragmentLength, int sectorSize, int entryArrayBytes)
    {
        var sectorOffset = entryArrayLba - originLba;
        var byteOffset = sectorOffset * (long)sectorSize;

        // The whole declared array has to be present in this fragment, not just its first sector.
        if (sectorOffset < 0
            || byteOffset > fragmentLength
            || entryArrayBytes > fragmentLength - byteOffset)
        {
            throw new InvalidDataException(
                "The declared partition entry array is not fully present in its fragment.");
        }

        return (int)byteOffset;
    }

    private static IReadOnlyList<GptPartition> DecodeEntries(
        ReadOnlySpan<byte> entryArray, int entryCount, long firstUsableSector, long lastUsableSector)
    {
        var partitions = new List<GptPartition>();
        var used = new List<(long Start, long End)>();
        var seenPartUuids = new HashSet<Guid>();

        for (var index = 0; index < entryCount; index++)
        {
            var entry = entryArray.Slice(index * EntrySize, EntrySize);

            var typeGuid = new Guid(entry.Slice(TypeGuidOffset, 16).ToArray());

            // A zero type GUID marks an unused slot; nothing else in such an entry is meaningful.
            if (typeGuid == Guid.Empty)
            {
                continue;
            }

            var partUuid = new Guid(entry.Slice(PartUuidOffset, 16).ToArray());
            if (partUuid == Guid.Empty)
            {
                throw new InvalidDataException($"The used GPT entry {index + 1} has a zero partition GUID.");
            }

            if (!seenPartUuids.Add(partUuid))
            {
                throw new InvalidDataException($"GPT entry {index + 1} repeats a partition GUID.");
            }

            var startSector = BinaryPrimitives.ReadUInt64LittleEndian(entry.Slice(EntryStartOffset, 8));
            var endInclusive = BinaryPrimitives.ReadUInt64LittleEndian(entry.Slice(EntryEndOffset, 8));
            if (startSector > long.MaxValue || endInclusive > long.MaxValue)
            {
                throw new InvalidDataException($"GPT entry {index + 1} has sector values that are not representable.");
            }

            var start = (long)startSector;
            var end = (long)endInclusive;
            if (start > end || start < firstUsableSector || end > lastUsableSector)
            {
                throw new InvalidDataException($"GPT entry {index + 1} lies outside the declared usable range.");
            }

            var sectorCount = end - start + 1;
            var attributes = BinaryPrimitives.ReadUInt64LittleEndian(entry.Slice(EntryAttributesOffset, 8));

            partitions.Add(new GptPartition(
                index + 1,
                DecodeName(entry),
                FormatGuid(typeGuid),
                FormatGuid(partUuid),
                start,
                sectorCount,
                attributes));

            used.Add((start, end));
        }

        used.Sort((left, right) => left.Start.CompareTo(right.Start));
        for (var index = 1; index < used.Count; index++)
        {
            if (used[index].Start <= used[index - 1].End)
            {
                throw new InvalidDataException("Two used GPT entries claim overlapping sectors.");
            }
        }

        return partitions;
    }

    private static string DecodeName(ReadOnlySpan<byte> entry)
    {
        var nameField = entry.Slice(EntryNameOffset, NameFieldBytes);
        var characters = new char[NameFieldBytes / 2];
        var length = 0;

        for (var index = 0; index < characters.Length; index++)
        {
            var codeUnit = BinaryPrimitives.ReadUInt16LittleEndian(nameField.Slice(index * 2, 2));
            if (codeUnit == 0)
            {
                break;
            }

            characters[length++] = (char)codeUnit;
        }

        // Only the NUL terminator ends the name; trailing spaces are part of it and are kept.
        return new string(characters, 0, length);
    }

    private static string FormatGuid(Guid value) => value.ToString("D").ToUpperInvariant();

    private static string ComputeSourceFingerprint(
        byte[] primaryFragment, byte[] backupFragment, int sectorSize, long diskBytes)
    {
        // The fixed prefix frames the hash: sector size, disk length and both fragment lengths are length
        // delimited, so no pair of fragments can be re-read as the concatenation of another pair.
        var prefix = new byte[4 + 8 + 4 + 4];
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(0, 4), sectorSize);
        BinaryPrimitives.WriteInt64LittleEndian(prefix.AsSpan(4, 8), diskBytes);
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(12, 4), primaryFragment.Length);
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(16, 4), backupFragment.Length);

        using var sha256 = SHA256.Create();
        sha256.TransformBlock(prefix, 0, prefix.Length, null, 0);
        sha256.TransformBlock(primaryFragment, 0, primaryFragment.Length, null, 0);
        sha256.TransformBlock(backupFragment, 0, backupFragment.Length, null, 0);
        sha256.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

        return BitConverter.ToString(sha256.Hash!).Replace("-", string.Empty);
    }

    /// <summary>CRC32 with the reflected IEEE polynomial 0xEDB88320, as the GPT specification requires.</summary>
    private static uint Crc32(ReadOnlySpan<byte> data)
    {
        var crc = 0xFFFF_FFFFu;

        foreach (var value in data)
        {
            crc ^= value;
            for (var bit = 0; bit < 8; bit++)
            {
                crc = (crc & 1u) != 0u ? (crc >> 1) ^ 0xEDB8_8320u : crc >> 1;
            }
        }

        return ~crc;
    }

    /// <summary>The fields of one validated header sector; the LBA pair is checked while reading.</summary>
    private readonly struct GptHeader
    {
        internal GptHeader(
            Guid diskGuid,
            long firstUsableSector,
            long lastUsableSector,
            long entryArrayLba,
            int entryCount,
            int entrySize,
            int headerSize,
            uint revision,
            int entryArrayBytes,
            uint entryArrayCrc)
        {
            DiskGuid = diskGuid;
            FirstUsableSector = firstUsableSector;
            LastUsableSector = lastUsableSector;
            EntryArrayLba = entryArrayLba;
            EntryCount = entryCount;
            EntrySize = entrySize;
            HeaderSize = headerSize;
            Revision = revision;
            EntryArrayBytes = entryArrayBytes;
            EntryArrayCrc = entryArrayCrc;
        }

        internal Guid DiskGuid { get; }

        internal long FirstUsableSector { get; }

        internal long LastUsableSector { get; }

        internal long EntryArrayLba { get; }

        internal int EntryCount { get; }

        internal int EntrySize { get; }

        internal int HeaderSize { get; }

        internal uint Revision { get; }

        internal int EntryArrayBytes { get; }

        internal uint EntryArrayCrc { get; }
    }
}
