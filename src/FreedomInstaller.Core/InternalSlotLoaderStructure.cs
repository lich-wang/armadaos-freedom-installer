using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using SharpCompress.Compressors.LZMA;

namespace FreedomInstaller.Core;

internal static partial class InternalSlotLoaderStructure
{
    private const long ContainerKernelWindowBytes = 0x10000000L;

    private const uint ContainerElfMagic = 0x464C457F;
    private const int ContainerElf32HeaderSize = 52;
    private const int ContainerElf32ProgramSize = 32;
    private const int ContainerElf64HeaderSize = 64;
    private const int ContainerElf64ProgramSize = 56;
    private const int ContainerProgramOffset32 = 4;
    private const int ContainerProgramFileSize32 = 16;
    private const int ContainerProgramTypeLoad = 1;

    private const int ContainerFvSignatureOffset = 0x28;
    private const int ContainerFvLengthOffset = 0x20;
    private const int ContainerFvHeaderLengthOffset = 0x30;
    private const int ContainerFvMinHeaderLength = 56;
    private const int ContainerFfsHeaderSize = 24;
    private const int ContainerFfsAlignment = 8;
    private const byte ContainerFfsTypeRaw = 0x01;
    private const byte ContainerFfsTypePad = 0xF0;
    private const int ContainerAlignment4 = 4;
    private const byte ContainerSectionGuidDefined = 0x02;
    private const int ContainerGuidSectionHeaderSize = 24;
    private const int ContainerLzmaAloneHeaderSize = 13;
    private const int ContainerLzmaPropertySize = 5;
    private const int ContainerMaxDecodedSize = 4 * 1024 * 1024;
    private const int ContainerDecodeChunkSize = 64 * 1024;

    private static readonly byte[] ContainerLzmaSectionGuid =
    {
        0x98, 0x58, 0x4E, 0xEE, 0x14, 0x39, 0x59, 0x42, 0x9D, 0x6E, 0xDC, 0x7B, 0xD7, 0x94, 0x03, 0xCF
    };

    private const uint ContainerFdtMagic = 0xD00DFEED;
    private const int ContainerFdtHeaderSize = 40;
    private const uint ContainerFdtVersion = 17;
    private const uint ContainerFdtTokenBeginNode = 1;
    private const uint ContainerFdtTokenEndNode = 2;
    private const uint ContainerFdtTokenProperty = 3;
    private const uint ContainerFdtTokenNop = 4;
    private const uint ContainerFdtTokenEnd = 9;
    private const int ContainerFdtReservationEntrySize = 16;
    private const int ContainerMaxNameLength = 4096;
    private const string ContainerKernelNodePath = "/soc/memorymap/memory@A8000000";
    private const string ContainerLabelProperty = "mem-label";
    private const string ContainerDeviceTypeProperty = "device_type";
    private const string ContainerRegProperty = "reg";
    private const string ContainerKernelLabel = "Kernel\0";
    private const string ContainerMemoryDeviceType = "memory\0";
    private const ulong ContainerKernelBase = 0xA8000000UL;
    private const ulong ContainerKernelSize = 0x10000000UL;
    private const string ContainerGen5NodePath = "/soc/memorymap/memory@C7800000";
    private const ulong ContainerGen5Base = 0xC7800000UL;

    internal static bool TryDecodeContainers(
        byte[] abl,
        byte[] xbl,
        CancellationToken token,
        out byte[] pe,
        out long windowBytes)
    {
        pe = Array.Empty<byte>();
        windowBytes = 0;

        if (abl == null || xbl == null)
        {
            return false;
        }

        token.ThrowIfCancellationRequested();

        if (!ContainerTryDecodeBoundedImage(abl, token, out byte[] image))
        {
            return false;
        }

        if (!ContainerTryMatchKernelRegion(xbl, token))
        {
            return false;
        }

        pe = image;
        windowBytes = ContainerKernelWindowBytes;
        return true;
    }

    private static bool ContainerTryDecodeBoundedImage(byte[] abl, CancellationToken token, out byte[] image)
    {
        image = Array.Empty<byte>();

        if (abl.Length < ContainerElf32HeaderSize)
        {
            return false;
        }

        if (BinaryPrimitives.ReadUInt32LittleEndian(abl.AsSpan(0)) != ContainerElfMagic)
        {
            return false;
        }

        if (abl[4] != 1 || abl[5] != 1 || abl[6] != 1)
        {
            return false;
        }

        if (BinaryPrimitives.ReadUInt16LittleEndian(abl.AsSpan(16)) != 2)
        {
            return false;
        }

        if (BinaryPrimitives.ReadUInt16LittleEndian(abl.AsSpan(18)) != 40)
        {
            return false;
        }

        if (BinaryPrimitives.ReadUInt32LittleEndian(abl.AsSpan(20)) != 1)
        {
            return false;
        }

        if (BinaryPrimitives.ReadUInt16LittleEndian(abl.AsSpan(40)) != ContainerElf32HeaderSize)
        {
            return false;
        }

        if (BinaryPrimitives.ReadUInt16LittleEndian(abl.AsSpan(42)) != ContainerElf32ProgramSize)
        {
            return false;
        }

        long tableOffset = BinaryPrimitives.ReadUInt32LittleEndian(abl.AsSpan(28));
        int tableCount = BinaryPrimitives.ReadUInt16LittleEndian(abl.AsSpan(44));
        if (tableCount == 0 || tableOffset < ContainerElf32HeaderSize)
        {
            return false;
        }

        if (tableOffset + (long)tableCount * ContainerElf32ProgramSize > abl.Length)
        {
            return false;
        }

        var children = new List<ContainerLzmaChild>();

        for (int i = 0; i < tableCount; i++)
        {
            token.ThrowIfCancellationRequested();

            int program = (int)(tableOffset + (long)i * ContainerElf32ProgramSize);
            if (BinaryPrimitives.ReadUInt32LittleEndian(abl.AsSpan(program)) != ContainerProgramTypeLoad)
            {
                continue;
            }

            long fileOffset = BinaryPrimitives.ReadUInt32LittleEndian(abl.AsSpan(program + ContainerProgramOffset32));
            long fileSize = BinaryPrimitives.ReadUInt32LittleEndian(abl.AsSpan(program + ContainerProgramFileSize32));
            long memorySize = BinaryPrimitives.ReadUInt32LittleEndian(abl.AsSpan(program + 20));
            if (fileSize <= 0 || memorySize < fileSize)
            {
                return false;
            }

            if (fileOffset > abl.Length || fileSize > abl.Length - fileOffset)
            {
                return false;
            }

            if (!ContainerTryCollectVolume(abl, (int)fileOffset, (int)fileSize, token, children))
            {
                return false;
            }

            if (children.Count > 1)
            {
                return false;
            }
        }

        if (children.Count != 1)
        {
            return false;
        }

        return ContainerTryDecodeChild(abl, children[0], token, out image);
    }

    private static bool ContainerTryCollectVolume(
        byte[] blob,
        int loadOffset,
        int loadLength,
        CancellationToken token,
        List<ContainerLzmaChild> children)
    {
        if (loadLength < ContainerFvSignatureOffset + 4)
        {
            return true;
        }

        if (blob[loadOffset + ContainerFvSignatureOffset] != (byte)'_' ||
            blob[loadOffset + ContainerFvSignatureOffset + 1] != (byte)'F' ||
            blob[loadOffset + ContainerFvSignatureOffset + 2] != (byte)'V' ||
            blob[loadOffset + ContainerFvSignatureOffset + 3] != (byte)'H')
        {
            return true;
        }

        if (loadLength < ContainerFvMinHeaderLength)
        {
            return false;
        }

        long volumeLength = (long)BinaryPrimitives.ReadUInt64LittleEndian(
            blob.AsSpan(loadOffset + ContainerFvLengthOffset));
        if (volumeLength <= 0 || volumeLength > loadLength)
        {
            return false;
        }

        int headerLength = BinaryPrimitives.ReadUInt16LittleEndian(
            blob.AsSpan(loadOffset + ContainerFvHeaderLengthOffset));
        if (headerLength < ContainerFvMinHeaderLength || (headerLength & 1) != 0 || headerLength > volumeLength)
        {
            return false;
        }

        if (!ContainerIsChecksumValid(blob, loadOffset, headerLength))
        {
            return false;
        }

        long volumeEnd = loadOffset + volumeLength;
        long position = loadOffset + headerLength;

        while (position + ContainerFfsHeaderSize <= volumeEnd)
        {
            token.ThrowIfCancellationRequested();

            if (ContainerIsErasedRange(blob, position, position + ContainerFfsHeaderSize, token))
            {
                return ContainerIsErasedRange(blob, position, volumeEnd, token);
            }

            if ((blob[(int)position + 19] & 0x01) != 0)
            {
                return false;
            }

            if (blob[(int)position + 18] == 0xFF)
            {
                return false;
            }

            long fileSize = ContainerReadUInt24(blob, (int)position + 20);
            if (fileSize < ContainerFfsHeaderSize || position + fileSize > volumeEnd)
            {
                return false;
            }

            byte fileType = blob[(int)position + 18];
            if (fileType != ContainerFfsTypeRaw && fileType != ContainerFfsTypePad)
            {
                if (!ContainerTryCollectSections(blob, position + ContainerFfsHeaderSize, position + fileSize, token, children))
                {
                    return false;
                }
            }

            position = ContainerAlign(position + fileSize, ContainerFfsAlignment);
            if (position > volumeEnd)
            {
                position = volumeEnd;
            }
        }

        return ContainerIsErasedRange(blob, position, volumeEnd, token);
    }

    private static bool ContainerTryCollectSections(
        byte[] blob,
        long start,
        long end,
        CancellationToken token,
        List<ContainerLzmaChild> children)
    {
        long position = start;

        while (position + 4 <= end)
        {
            token.ThrowIfCancellationRequested();

            long sectionSize = ContainerReadUInt24(blob, (int)position);
            if (sectionSize < 4 || position + sectionSize > end)
            {
                return false;
            }

            if (blob[(int)position + 3] == ContainerSectionGuidDefined)
            {
                if (!ContainerTryCollectLzmaSection(blob, position, sectionSize, children))
                {
                    return false;
                }

                if (children.Count > 1)
                {
                    return false;
                }
            }

            position = ContainerAlign(position + sectionSize, ContainerAlignment4);
        }

        return true;
    }

    private static bool ContainerTryCollectLzmaSection(
        byte[] blob,
        long sectionOffset,
        long sectionSize,
        List<ContainerLzmaChild> children)
    {
        if (sectionSize < ContainerGuidSectionHeaderSize)
        {
            return false;
        }

        for (int i = 0; i < ContainerLzmaSectionGuid.Length; i++)
        {
            if (blob[(int)sectionOffset + 4 + i] != ContainerLzmaSectionGuid[i])
            {
                return true;
            }
        }

        int dataOffset = BinaryPrimitives.ReadUInt16LittleEndian(blob.AsSpan((int)sectionOffset + 20));
        if (dataOffset < ContainerGuidSectionHeaderSize || dataOffset > sectionSize)
        {
            return false;
        }

        long payloadOffset = sectionOffset + dataOffset;
        long payloadLength = sectionSize - dataOffset;
        if (payloadLength < ContainerLzmaAloneHeaderSize)
        {
            return false;
        }

        long declared = (long)BinaryPrimitives.ReadUInt64LittleEndian(blob.AsSpan((int)payloadOffset + ContainerLzmaPropertySize));
        if (declared <= 0 || declared > ContainerMaxDecodedSize)
        {
            return false;
        }

        children.Add(new ContainerLzmaChild(
            (int)payloadOffset + ContainerLzmaAloneHeaderSize,
            (int)(payloadLength - ContainerLzmaAloneHeaderSize),
            (int)declared));
        return true;
    }

    private static bool ContainerTryDecodeChild(byte[] abl, ContainerLzmaChild child, CancellationToken token, out byte[] image)
    {
        image = Array.Empty<byte>();

        if (child.DeclaredSize <= 0 || child.DeclaredSize > ContainerMaxDecodedSize)
        {
            return false;
        }

        if (child.DataOffset < 0 || child.DataLength < 0)
        {
            return false;
        }

        if ((long)child.DataOffset + child.DataLength > abl.Length)
        {
            return false;
        }

        var properties = new byte[ContainerLzmaPropertySize];
        Buffer.BlockCopy(abl, child.DataOffset - ContainerLzmaAloneHeaderSize, properties, 0, ContainerLzmaPropertySize);

        byte[] decoded = new byte[child.DeclaredSize];

        try
        {
            using var input = new MemoryStream(abl, child.DataOffset, child.DataLength, writable: false);
            using LzmaStream stream = LzmaStream.Create(
                properties,
                input,
                child.DataLength,
                child.DeclaredSize,
                leaveOpen: true);

            int total = 0;
            while (total < child.DeclaredSize)
            {
                token.ThrowIfCancellationRequested();

                int chunk = Math.Min(ContainerDecodeChunkSize, child.DeclaredSize - total);
                int read = stream.Read(decoded, total, chunk);
                if (read <= 0)
                {
                    return false;
                }

                total += read;
            }

            if (stream.Read(decoded, 0, 1) != 0)
            {
                return false;
            }
        }
        catch (InvalidDataException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (OverflowException)
        {
            return false;
        }
        catch (IndexOutOfRangeException)
        {
            return false;
        }

        return ContainerTryExtractImage(decoded, token, out image);
    }

    private static bool ContainerTryExtractImage(byte[] buffer, CancellationToken token, out byte[] image)
    {
        image = Array.Empty<byte>();
        int found = -1;

        for (int i = 0; i + 0x40 <= buffer.Length; i++)
        {
            token.ThrowIfCancellationRequested();

            if (buffer[i] != (byte)'M' || buffer[i + 1] != (byte)'Z')
            {
                continue;
            }

            if (!ContainerIsCompleteArm64Image(buffer.AsSpan(i)))
            {
                continue;
            }

            if (found >= 0)
            {
                return false;
            }

            found = i;
        }

        if (found < 0)
        {
            return false;
        }

        image = new byte[buffer.Length - found];
        Buffer.BlockCopy(buffer, found, image, 0, image.Length);
        return true;
    }

    private static bool ContainerIsCompleteArm64Image(ReadOnlySpan<byte> candidate)
    {
        if (candidate.Length < 0x40)
        {
            return false;
        }

        long peOffset = BinaryPrimitives.ReadUInt32LittleEndian(candidate.Slice(0x3C));
        if (peOffset < 0x40 || peOffset + 24 > candidate.Length)
        {
            return false;
        }

        int pe = (int)peOffset;
        if (BinaryPrimitives.ReadUInt32LittleEndian(candidate.Slice(pe)) != 0x00004550)
        {
            return false;
        }

        int file = pe + 4;
        if (BinaryPrimitives.ReadUInt16LittleEndian(candidate.Slice(file)) != 0xAA64)
        {
            return false;
        }

        int sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(candidate.Slice(file + 2));
        int optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(candidate.Slice(file + 16));
        if (sectionCount == 0 || sectionCount > 96)
        {
            return false;
        }

        int optional = file + 20;
        if (optionalSize < 112 || (long)optional + optionalSize > candidate.Length)
        {
            return false;
        }

        if (BinaryPrimitives.ReadUInt16LittleEndian(candidate.Slice(optional)) != 0x020B)
        {
            return false;
        }

        long entryRva = BinaryPrimitives.ReadUInt32LittleEndian(candidate.Slice(optional + 16));
        long imageSize = BinaryPrimitives.ReadUInt32LittleEndian(candidate.Slice(optional + 56));
        long headersSize = BinaryPrimitives.ReadUInt32LittleEndian(candidate.Slice(optional + 60));
        if (entryRva == 0 || imageSize == 0)
        {
            return false;
        }

        long table = (long)optional + optionalSize;
        long tableEnd = table + (long)sectionCount * 40;
        if (tableEnd > headersSize || headersSize > candidate.Length || headersSize > imageSize)
        {
            return false;
        }

        var rawStarts = new List<long>();
        var rawEnds = new List<long>();
        var virtualStarts = new List<long>();
        var virtualEnds = new List<long>();
        int entryMatches = 0;

        for (int i = 0; i < sectionCount; i++)
        {
            int section = (int)(table + (long)i * 40);
            long virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(candidate.Slice(section + 8));
            long virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(candidate.Slice(section + 12));
            long rawSize = BinaryPrimitives.ReadUInt32LittleEndian(candidate.Slice(section + 16));
            long rawPointer = BinaryPrimitives.ReadUInt32LittleEndian(candidate.Slice(section + 20));
            uint flags = BinaryPrimitives.ReadUInt32LittleEndian(candidate.Slice(section + 36));

            if (rawSize > 0)
            {
                if (rawPointer < headersSize || rawPointer + rawSize > candidate.Length)
                {
                    return false;
                }

                for (int j = 0; j < rawStarts.Count; j++)
                {
                    if (ContainerRangesOverlap(rawPointer, rawPointer + rawSize, rawStarts[j], rawEnds[j]))
                    {
                        return false;
                    }
                }

                rawStarts.Add(rawPointer);
                rawEnds.Add(rawPointer + rawSize);
            }
            else if (rawPointer > candidate.Length)
            {
                return false;
            }

            long extent = virtualSize > rawSize ? virtualSize : rawSize;
            if (extent == 0)
            {
                continue;
            }

            if (virtualAddress < headersSize || virtualAddress + extent > imageSize)
            {
                return false;
            }

            for (int j = 0; j < virtualStarts.Count; j++)
            {
                if (ContainerRangesOverlap(virtualAddress, virtualAddress + extent, virtualStarts[j], virtualEnds[j]))
                {
                    return false;
                }
            }

            virtualStarts.Add(virtualAddress);
            virtualEnds.Add(virtualAddress + extent);

            if ((flags & 0x20000000u) != 0 &&
                entryRva >= virtualAddress &&
                entryRva - virtualAddress < rawSize)
            {
                entryMatches++;
            }
        }

        return entryMatches == 1;
    }

    private static bool ContainerTryMatchKernelRegion(byte[] xbl, CancellationToken token)
    {
        if (xbl.Length < ContainerElf64HeaderSize)
        {
            return false;
        }

        if (BinaryPrimitives.ReadUInt32LittleEndian(xbl.AsSpan(0)) != ContainerElfMagic)
        {
            return false;
        }

        if (xbl[4] != 2 || xbl[5] != 1 || xbl[6] != 1)
        {
            return false;
        }

        if (BinaryPrimitives.ReadUInt32LittleEndian(xbl.AsSpan(20)) != 1)
        {
            return false;
        }

        if (BinaryPrimitives.ReadUInt16LittleEndian(xbl.AsSpan(52)) != ContainerElf64HeaderSize)
        {
            return false;
        }

        if (BinaryPrimitives.ReadUInt16LittleEndian(xbl.AsSpan(54)) != ContainerElf64ProgramSize)
        {
            return false;
        }

        ulong tableOffset = BinaryPrimitives.ReadUInt64LittleEndian(xbl.AsSpan(32));
        int tableCount = BinaryPrimitives.ReadUInt16LittleEndian(xbl.AsSpan(56));
        if (tableCount == 0 || tableOffset < ContainerElf64HeaderSize || tableOffset > (ulong)xbl.Length)
        {
            return false;
        }

        ulong tableBytes = (ulong)tableCount * ContainerElf64ProgramSize;
        if (tableBytes > (ulong)xbl.Length - tableOffset)
        {
            return false;
        }

        int kernelNodes = 0;

        for (int i = 0; i < tableCount; i++)
        {
            token.ThrowIfCancellationRequested();

            int program = (int)(tableOffset + (ulong)i * ContainerElf64ProgramSize);
            if (BinaryPrimitives.ReadUInt32LittleEndian(xbl.AsSpan(program)) != ContainerProgramTypeLoad)
            {
                continue;
            }

            ulong fileOffset = BinaryPrimitives.ReadUInt64LittleEndian(xbl.AsSpan(program + 8));
            ulong fileSize = BinaryPrimitives.ReadUInt64LittleEndian(xbl.AsSpan(program + 32));
            ulong memorySize = BinaryPrimitives.ReadUInt64LittleEndian(xbl.AsSpan(program + 40));
            if (fileSize == 0 || memorySize < fileSize)
            {
                return false;
            }

            if (fileOffset > (ulong)xbl.Length || fileSize > (ulong)xbl.Length - fileOffset)
            {
                return false;
            }

            if (fileSize < 4)
            {
                continue;
            }

            if (BinaryPrimitives.ReadUInt32BigEndian(xbl.AsSpan((int)fileOffset)) != ContainerFdtMagic)
            {
                continue;
            }

            if (!ContainerTryParseFdt(xbl, (int)fileOffset, (int)fileSize, token, ref kernelNodes))
            {
                return false;
            }

            if (kernelNodes > 1)
            {
                return false;
            }
        }

        return kernelNodes == 1;
    }

    private static bool ContainerTryParseFdt(
        byte[] blob,
        int start,
        int limit,
        CancellationToken token,
        ref int kernelNodes)
    {
        if (limit < ContainerFdtHeaderSize)
        {
            return false;
        }

        if (BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(start)) != ContainerFdtMagic)
        {
            return false;
        }

        long totalSize = BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(start + 4));
        if (totalSize < ContainerFdtHeaderSize || totalSize > limit)
        {
            return false;
        }

        if (BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(start + 20)) != ContainerFdtVersion)
        {
            return false;
        }

        if (BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(start + 24)) > ContainerFdtVersion)
        {
            return false;
        }

        long structOffset = BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(start + 8));
        long stringsOffset = BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(start + 12));
        long reservationOffset = BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(start + 16));
        long stringsSize = BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(start + 32));
        long structSize = BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(start + 36));

        if ((structOffset & 3) != 0 || (structSize & 3) != 0 || (reservationOffset & 7) != 0)
        {
            return false;
        }

        if (structOffset < ContainerFdtHeaderSize || stringsOffset < ContainerFdtHeaderSize || reservationOffset < ContainerFdtHeaderSize)
        {
            return false;
        }

        long structEnd = structOffset + structSize;
        long stringsEnd = stringsOffset + stringsSize;
        if (structEnd > totalSize || stringsEnd > totalSize)
        {
            return false;
        }

        if (ContainerRangesOverlap(structOffset, structEnd, stringsOffset, stringsEnd))
        {
            return false;
        }

        long reservationEnd = -1;
        for (long position = reservationOffset; ; position += ContainerFdtReservationEntrySize)
        {
            token.ThrowIfCancellationRequested();

            if (position + ContainerFdtReservationEntrySize > totalSize)
            {
                return false;
            }

            ulong address = BinaryPrimitives.ReadUInt64BigEndian(blob.AsSpan(start + (int)position));
            ulong size = BinaryPrimitives.ReadUInt64BigEndian(blob.AsSpan(start + (int)position + 8));
            if (address == 0 && size == 0)
            {
                reservationEnd = position + ContainerFdtReservationEntrySize;
                break;
            }
        }

        if (ContainerRangesOverlap(reservationOffset, reservationEnd, structOffset, structEnd) ||
            ContainerRangesOverlap(reservationOffset, reservationEnd, stringsOffset, stringsEnd))
        {
            return false;
        }

        return ContainerTryParseFdtStructure(
            blob,
            start,
            structOffset,
            structEnd,
            stringsOffset,
            stringsSize,
            stringsEnd,
            token,
            ref kernelNodes);
    }

    private static bool ContainerTryParseFdtStructure(
        byte[] blob,
        int start,
        long structOffset,
        long structEnd,
        long stringsOffset,
        long stringsSize,
        long stringsEnd,
        CancellationToken token,
        ref int kernelNodes)
    {
        var frames = new List<ContainerFdtFrame>();
        var names = new List<string>();
        bool rootSeen = false;
        bool rootClosed = false;
        bool endSeen = false;
        long position = structOffset;

        while (!endSeen)
        {
            token.ThrowIfCancellationRequested();

            if (position + 4 > structEnd)
            {
                return false;
            }

            uint value = BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(start + (int)position));
            position += 4;

            if (value == ContainerFdtTokenBeginNode)
            {
                if (!ContainerTryReadStructuredName(blob, start, ref position, structEnd, out string name))
                {
                    return false;
                }

                position = ContainerAlign(position, ContainerAlignment4);
                if (position > structEnd)
                {
                    return false;
                }

                if (frames.Count == 0)
                {
                    if (rootSeen || rootClosed || name.Length != 0)
                    {
                        return false;
                    }

                    rootSeen = true;
                }
                else
                {
                    if (name.Length == 0 || name.IndexOf('/') >= 0)
                    {
                        return false;
                    }

                    if (!frames[frames.Count - 1].AddChild(name))
                    {
                        return false;
                    }
                }

                frames.Add(new ContainerFdtFrame());
                names.Add(name);
                continue;
            }

            if (value == ContainerFdtTokenEndNode)
            {
                if (frames.Count == 0)
                {
                    return false;
                }

                ContainerFdtFrame frame = frames[frames.Count - 1];
                if (frame.LabelKernel)
                {
                    string frameNodePath = ContainerBuildNodePath(names);
                    ulong expectedBase;
                    if (string.Equals(frameNodePath, ContainerKernelNodePath, StringComparison.Ordinal))
                    {
                        expectedBase = ContainerKernelBase;
                    }
                    else if (string.Equals(frameNodePath, ContainerGen5NodePath, StringComparison.Ordinal))
                    {
                        expectedBase = ContainerGen5Base;
                    }
                    else
                    {
                        return false;
                    }

                    if (!frame.DeviceTypeMemory ||
                        !frame.RegKernel ||
                        frame.ActualRegBase != expectedBase)
                    {
                        return false;
                    }

                    kernelNodes++;
                    if (kernelNodes > 1)
                    {
                        return false;
                    }
                }

                frames.RemoveAt(frames.Count - 1);
                names.RemoveAt(names.Count - 1);
                if (frames.Count == 0)
                {
                    rootClosed = true;
                }

                continue;
            }

            if (value == ContainerFdtTokenProperty)
            {
                if (frames.Count == 0 || position + 8 > structEnd)
                {
                    return false;
                }

                ContainerFdtFrame frame = frames[frames.Count - 1];
                if (frame.ChildSeen)
                {
                    return false;
                }

                long valueLength = BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(start + (int)position));
                long nameOffset = BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(start + (int)position + 4));
                position += 8;

                if (nameOffset >= stringsSize)
                {
                    return false;
                }

                if (!ContainerTryReadStringsName(blob, start, stringsOffset, stringsSize, stringsEnd, nameOffset, out string propertyName))
                {
                    return false;
                }

                if (!frame.AddProperty(propertyName))
                {
                    return false;
                }

                if (valueLength > structEnd - position)
                {
                    return false;
                }

                long dataStart = position;
                position += valueLength;
                position = ContainerAlign(position, ContainerAlignment4);
                if (position > structEnd)
                {
                    return false;
                }

                ContainerInspectProperty(blob, start + (int)dataStart, (int)valueLength, propertyName, frame);
                continue;
            }

            if (value == ContainerFdtTokenNop)
            {
                continue;
            }

            if (value == ContainerFdtTokenEnd)
            {
                if (frames.Count != 0 || !rootClosed)
                {
                    return false;
                }

                endSeen = true;
                continue;
            }

            return false;
        }

        for (long i = position; i < structEnd; i++)
        {
            if (blob[start + (int)i] != 0)
            {
                return false;
            }
        }

        return rootSeen;
    }

    private static void ContainerInspectProperty(byte[] blob, int offset, int length, string name, ContainerFdtFrame frame)
    {
        if (string.Equals(name, ContainerLabelProperty, StringComparison.Ordinal))
        {
            frame.LabelKernel = ContainerEqualsAscii(blob, offset, length, ContainerKernelLabel);
            return;
        }

        if (string.Equals(name, ContainerDeviceTypeProperty, StringComparison.Ordinal))
        {
            frame.DeviceTypeMemory = ContainerEqualsAscii(blob, offset, length, ContainerMemoryDeviceType);
            return;
        }

        if (string.Equals(name, ContainerRegProperty, StringComparison.Ordinal))
        {
            if (length != 16)
            {
                frame.RegKernel = false;
                return;
            }

            frame.ActualRegBase = BinaryPrimitives.ReadUInt64BigEndian(blob.AsSpan(offset));
            frame.RegKernel =
                BinaryPrimitives.ReadUInt64BigEndian(blob.AsSpan(offset + 8)) == ContainerKernelSize;
        }
    }

    private static string ContainerBuildNodePath(List<string> names)
    {
        var builder = new StringBuilder();
        for (int i = 1; i < names.Count; i++)
        {
            builder.Append('/');
            builder.Append(names[i]);
        }

        return builder.ToString();
    }

    private static bool ContainerTryReadStructuredName(byte[] blob, int start, ref long position, long end, out string value)
    {
        value = string.Empty;

        long limit = position + ContainerMaxNameLength;
        if (limit > end)
        {
            limit = end;
        }

        long cursor = position;
        while (cursor < limit && blob[start + (int)cursor] != 0)
        {
            cursor++;
        }

        if (cursor >= limit)
        {
            return false;
        }

        value = Encoding.ASCII.GetString(blob, start + (int)position, (int)(cursor - position));
        position = cursor + 1;
        return true;
    }

    private static bool ContainerTryReadStringsName(
        byte[] blob,
        int start,
        long stringsOffset,
        long stringsSize,
        long stringsEnd,
        long nameOffset,
        out string value)
    {
        value = string.Empty;

        long begin = stringsOffset + nameOffset;
        if (begin >= stringsEnd || nameOffset >= stringsSize)
        {
            return false;
        }

        long cursor = begin;
        while (cursor < stringsEnd && blob[start + (int)cursor] != 0)
        {
            cursor++;
        }

        if (cursor >= stringsEnd || cursor == begin)
        {
            return false;
        }

        value = Encoding.ASCII.GetString(blob, start + (int)begin, (int)(cursor - begin));
        return true;
    }

    private static bool ContainerEqualsAscii(byte[] blob, int offset, int length, string text)
    {
        if (length != text.Length || offset < 0 || offset + length > blob.Length)
        {
            return false;
        }

        for (int i = 0; i < length; i++)
        {
            if (blob[offset + i] != (byte)text[i])
            {
                return false;
            }
        }

        return true;
    }

    private static bool ContainerIsChecksumValid(byte[] blob, int offset, int headerLength)
    {
        uint sum = 0;
        for (int i = 0; i < headerLength; i += 2)
        {
            sum = (sum + BinaryPrimitives.ReadUInt16LittleEndian(blob.AsSpan(offset + i))) & 0xFFFFu;
        }

        return sum == 0;
    }

    private static long ContainerReadUInt24(byte[] blob, int offset)
    {
        return blob[offset] | ((long)blob[offset + 1] << 8) | ((long)blob[offset + 2] << 16);
    }

    private static long ContainerAlign(long value, int alignment)
    {
        return (value + alignment - 1) & ~(long)(alignment - 1);
    }

    private static bool ContainerRangesOverlap(long firstStart, long firstEnd, long secondStart, long secondEnd)
    {
        return firstStart < secondEnd && secondStart < firstEnd;
    }

    private static bool ContainerIsErasedRange(byte[] blob, long start, long end, CancellationToken token)
    {
        if (start < 0 || end < start || end > blob.Length)
        {
            return false;
        }

        for (long i = start; i < end; i++)
        {
            token.ThrowIfCancellationRequested();

            if (blob[(int)i] != 0xFF)
            {
                return false;
            }
        }

        return true;
    }

    private sealed class ContainerLzmaChild
    {
        internal ContainerLzmaChild(int dataOffset, int dataLength, int declaredSize)
        {
            DataOffset = dataOffset;
            DataLength = dataLength;
            DeclaredSize = declaredSize;
        }

        internal int DataOffset { get; }

        internal int DataLength { get; }

        internal int DeclaredSize { get; }
    }

    private sealed class ContainerFdtFrame
    {
        private List<string>? properties;
        private List<string>? children;

        internal bool ChildSeen { get; private set; }

        internal bool LabelKernel { get; set; }

        internal bool DeviceTypeMemory { get; set; }

        internal bool RegKernel { get; set; }

        internal ulong ActualRegBase { get; set; }

        internal bool AddChild(string name)
        {
            if (children == null)
            {
                children = new List<string>();
            }

            if (children.Contains(name))
            {
                return false;
            }

            children.Add(name);
            ChildSeen = true;
            return true;
        }

        internal bool AddProperty(string name)
        {
            if (properties == null)
            {
                properties = new List<string>();
            }

            if (properties.Contains(name))
            {
                return false;
            }

            properties.Add(name);
            return true;
        }
    }
}
