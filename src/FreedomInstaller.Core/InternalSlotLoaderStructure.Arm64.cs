using System;
using System.Collections.Generic;
using System.Threading;

namespace FreedomInstaller.Core;

// Private Arm64 PE32+ view for the slot loader. Every member/type/constant is
// prefixed Arm64 so later tickets can append public Matches/TryRecognize
// members to this same file without collisions.
internal static partial class InternalSlotLoaderStructure
{
    private const ushort Arm64Machine = 0xAA64;
    private const ushort Arm64Pe32PlusMagic = 0x20B;
    private const uint Arm64PeSignature = 0x00004550u;
    private const uint Arm64SectionExecuteFlag = 0x20000000u;
    private const int Arm64DosHeaderSize = 64;
    private const int Arm64FileHeaderSize = 24;
    private const int Arm64OptionalHeaderMinimum = 112;
    private const int Arm64SectionHeaderSize = 40;
    private const int Arm64SectionLimit = 96;
    private const long Arm64PageSize = 0x1000L;
    private const long Arm64PageMask = ~0xFFFL;

    private enum Arm64BranchKind
    {
        B = 0,
        Bl = 1,
        CbzW = 2,
        CbzX = 3,
        BCond = 4,
    }

    private readonly struct Arm64Section
    {
        internal Arm64Section(long arm64VirtualStart, long arm64VirtualEnd, long arm64RawStart, long arm64RawEnd, bool arm64Executable)
        {
            Arm64VirtualStart = arm64VirtualStart;
            Arm64VirtualEnd = arm64VirtualEnd;
            Arm64RawStart = arm64RawStart;
            Arm64RawEnd = arm64RawEnd;
            Arm64Executable = arm64Executable;
        }

        internal long Arm64VirtualStart { get; }

        internal long Arm64VirtualEnd { get; }

        internal long Arm64RawStart { get; }

        // End (exclusive) of the RVA window that is backed by section raw data.
        internal long Arm64RawEnd { get; }

        internal bool Arm64Executable { get; }
    }

    private readonly struct Arm64CodeRange
    {
        internal Arm64CodeRange(long arm64RvaStart, long arm64RvaEnd)
        {
            Arm64RvaStart = arm64RvaStart;
            Arm64RvaEnd = arm64RvaEnd;
        }

        internal long Arm64RvaStart { get; }

        internal long Arm64RvaEnd { get; }
    }

    private sealed class Arm64PeView
    {
        private readonly byte[] Arm64Data;
        private readonly Arm64Section[] Arm64SectionList;
        private readonly Arm64CodeRange[] Arm64CodeRangeList;

        internal Arm64PeView(byte[] arm64Data, Arm64Section[] arm64Sections, Arm64CodeRange[] arm64CodeRanges)
        {
            Arm64Data = arm64Data;
            Arm64SectionList = arm64Sections;
            Arm64CodeRangeList = arm64CodeRanges;
        }

        internal byte[] Arm64Bytes
        {
            get { return Arm64Data; }
        }

        internal IReadOnlyList<Arm64CodeRange> Arm64CodeRanges
        {
            get { return Arm64CodeRangeList; }
        }

        // Maps an RVA window onto a file offset. Only raw-backed bytes resolve;
        // zero-fill/BSS tails never do. No RVA==file-offset assumption.
        internal bool Arm64TryMapRva(long arm64Rva, int arm64Count, bool arm64RequireExecutable, out int arm64Offset)
        {
            arm64Offset = 0;
            if (arm64Count < 0)
            {
                return false;
            }

            if (arm64Rva < 0L)
            {
                return false;
            }

            long arm64End = arm64Rva + (long)arm64Count;
            if (arm64End < arm64Rva)
            {
                return false;
            }

            Arm64Section[] arm64Sections = Arm64SectionList;
            for (int i = 0; i < arm64Sections.Length; i++)
            {
                Arm64Section arm64Section = arm64Sections[i];
                if (arm64RequireExecutable && !arm64Section.Arm64Executable)
                {
                    continue;
                }

                if (arm64Rva < arm64Section.Arm64VirtualStart || arm64End > arm64Section.Arm64RawEnd)
                {
                    continue;
                }

                long arm64FileOffset = arm64Section.Arm64RawStart + (arm64Rva - arm64Section.Arm64VirtualStart);
                if (arm64FileOffset < 0L || arm64FileOffset > (long)int.MaxValue)
                {
                    return false;
                }

                arm64Offset = (int)arm64FileOffset;
                return true;
            }

            return false;
        }
    }

    private static bool Arm64TryOpenPe(byte[] pe, CancellationToken token, out Arm64PeView view)
    {
        view = null!;
        if (pe == null)
        {
            return false;
        }

        long arm64FileLength = pe.Length;
        if (arm64FileLength < Arm64DosHeaderSize)
        {
            return false;
        }

        if (pe[0] != (byte)'M' || pe[1] != (byte)'Z')
        {
            return false;
        }

        token.ThrowIfCancellationRequested();

        if (!Arm64TryReadUInt32(pe, 0x3CL, out uint arm64RawLfanew))
        {
            return false;
        }

        long arm64Lfanew = arm64RawLfanew;
        if (arm64Lfanew < Arm64DosHeaderSize || arm64Lfanew + Arm64FileHeaderSize > arm64FileLength)
        {
            return false;
        }

        if (!Arm64TryReadUInt32(pe, arm64Lfanew, out uint arm64Signature))
        {
            return false;
        }

        if (arm64Signature != Arm64PeSignature)
        {
            return false;
        }

        if (!Arm64TryReadUInt16(pe, arm64Lfanew + 4L, out ushort arm64MachineValue))
        {
            return false;
        }

        if (arm64MachineValue != Arm64Machine)
        {
            return false;
        }

        if (!Arm64TryReadUInt16(pe, arm64Lfanew + 6L, out ushort arm64SectionCount))
        {
            return false;
        }

        if (arm64SectionCount == 0 || arm64SectionCount > Arm64SectionLimit)
        {
            return false;
        }

        if (!Arm64TryReadUInt16(pe, arm64Lfanew + 20L, out ushort arm64OptionalSize))
        {
            return false;
        }

        if (arm64OptionalSize < Arm64OptionalHeaderMinimum)
        {
            return false;
        }

        long arm64OptionalOffset = arm64Lfanew + Arm64FileHeaderSize;
        if (arm64OptionalOffset + (long)arm64OptionalSize > arm64FileLength)
        {
            return false;
        }

        if (!Arm64TryReadUInt16(pe, arm64OptionalOffset, out ushort arm64Magic))
        {
            return false;
        }

        if (arm64Magic != Arm64Pe32PlusMagic)
        {
            return false;
        }

        if (!Arm64TryReadUInt32(pe, arm64OptionalOffset + 16L, out uint arm64RawEntry))
        {
            return false;
        }

        if (!Arm64TryReadUInt32(pe, arm64OptionalOffset + 56L, out uint arm64RawImageSize))
        {
            return false;
        }

        if (!Arm64TryReadUInt32(pe, arm64OptionalOffset + 60L, out uint arm64RawHeadersSize))
        {
            return false;
        }

        long arm64ImageSize = arm64RawImageSize;
        long arm64HeadersSize = arm64RawHeadersSize;
        if (arm64ImageSize <= 0L || arm64HeadersSize <= 0L)
        {
            return false;
        }

        if (arm64HeadersSize > arm64FileLength || arm64HeadersSize > arm64ImageSize)
        {
            return false;
        }

        long arm64SectionTable = arm64OptionalOffset + (long)arm64OptionalSize;
        long arm64SectionTableEnd = arm64SectionTable + (long)arm64SectionCount * Arm64SectionHeaderSize;
        if (arm64SectionTableEnd > arm64HeadersSize || arm64SectionTableEnd > arm64FileLength)
        {
            return false;
        }

        Arm64Section[] arm64Sections = new Arm64Section[arm64SectionCount];
        for (int i = 0; i < arm64SectionCount; i++)
        {
            token.ThrowIfCancellationRequested();

            long arm64HeaderOffset = arm64SectionTable + (long)i * Arm64SectionHeaderSize;
            if (!Arm64TryReadUInt32(pe, arm64HeaderOffset + 8L, out uint arm64RawVirtualSize))
            {
                return false;
            }

            if (!Arm64TryReadUInt32(pe, arm64HeaderOffset + 12L, out uint arm64RawVirtualAddress))
            {
                return false;
            }

            if (!Arm64TryReadUInt32(pe, arm64HeaderOffset + 16L, out uint arm64RawSectionSize))
            {
                return false;
            }

            if (!Arm64TryReadUInt32(pe, arm64HeaderOffset + 20L, out uint arm64RawSectionPointer))
            {
                return false;
            }

            if (!Arm64TryReadUInt32(pe, arm64HeaderOffset + 36L, out uint arm64RawCharacteristics))
            {
                return false;
            }

            long arm64VirtualStart = arm64RawVirtualAddress;
            long arm64RawSize = arm64RawSectionSize;
            long arm64VirtualExtent = Math.Max((long)arm64RawVirtualSize, arm64RawSize);
            if (arm64VirtualStart + arm64VirtualExtent > arm64ImageSize)
            {
                return false;
            }

            long arm64RawStart = 0L;
            long arm64RawVisible = 0L;
            if (arm64RawSize > 0L)
            {
                if ((long)arm64RawSectionPointer < arm64HeadersSize)
                {
                    return false;
                }

                long arm64RawFileEnd = (long)arm64RawSectionPointer + arm64RawSize;
                if (arm64RawFileEnd > arm64FileLength)
                {
                    return false;
                }

                arm64RawStart = arm64RawSectionPointer;
                arm64RawVisible = arm64RawVirtualSize == 0u
                    ? arm64RawSize
                    : Math.Min(arm64RawSize, (long)arm64RawVirtualSize);
            }

            arm64Sections[i] = new Arm64Section(
                arm64VirtualStart,
                arm64VirtualStart + arm64VirtualExtent,
                arm64RawStart,
                arm64VirtualStart + arm64RawVisible,
                (arm64RawCharacteristics & Arm64SectionExecuteFlag) != 0u);
        }

        for (int i = 0; i < arm64Sections.Length; i++)
        {
            token.ThrowIfCancellationRequested();

            for (int j = i + 1; j < arm64Sections.Length; j++)
            {
                Arm64Section arm64First = arm64Sections[i];
                Arm64Section arm64Second = arm64Sections[j];

                if (Arm64RangesOverlap(
                    arm64First.Arm64VirtualStart,
                    arm64First.Arm64VirtualEnd,
                    arm64Second.Arm64VirtualStart,
                    arm64Second.Arm64VirtualEnd))
                {
                    return false;
                }

                long arm64FirstRawSize = arm64First.Arm64RawEnd - arm64First.Arm64VirtualStart;
                long arm64SecondRawSize = arm64Second.Arm64RawEnd - arm64Second.Arm64VirtualStart;
                if (arm64FirstRawSize > 0L
                    && arm64SecondRawSize > 0L
                    && Arm64RangesOverlap(
                        arm64First.Arm64RawStart,
                        arm64First.Arm64RawStart + arm64FirstRawSize,
                        arm64Second.Arm64RawStart,
                        arm64Second.Arm64RawStart + arm64SecondRawSize))
                {
                    return false;
                }
            }
        }

        long arm64Entry = arm64RawEntry;
        bool arm64EntryBacked = false;
        for (int i = 0; i < arm64Sections.Length; i++)
        {
            Arm64Section arm64Section = arm64Sections[i];
            if (!arm64Section.Arm64Executable)
            {
                continue;
            }

            if (arm64Entry < arm64Section.Arm64VirtualStart || arm64Entry + 4L > arm64Section.Arm64RawEnd)
            {
                continue;
            }

            arm64EntryBacked = true;
            break;
        }

        if (!arm64EntryBacked)
        {
            return false;
        }

        int arm64CodeCount = 0;
        for (int i = 0; i < arm64Sections.Length; i++)
        {
            if (arm64Sections[i].Arm64Executable && arm64Sections[i].Arm64RawEnd > arm64Sections[i].Arm64VirtualStart)
            {
                arm64CodeCount++;
            }
        }

        Arm64CodeRange[] arm64CodeRanges = new Arm64CodeRange[arm64CodeCount];
        int arm64CodeIndex = 0;
        for (int i = 0; i < arm64Sections.Length; i++)
        {
            Arm64Section arm64Section = arm64Sections[i];
            if (!arm64Section.Arm64Executable || arm64Section.Arm64RawEnd <= arm64Section.Arm64VirtualStart)
            {
                continue;
            }

            arm64CodeRanges[arm64CodeIndex] = new Arm64CodeRange(arm64Section.Arm64VirtualStart, arm64Section.Arm64RawEnd);
            arm64CodeIndex++;
        }

        view = new Arm64PeView(pe, arm64Sections, arm64CodeRanges);
        return true;
    }

    private static bool Arm64RangesOverlap(long arm64StartA, long arm64EndA, long arm64StartB, long arm64EndB)
    {
        return arm64StartA < arm64EndB && arm64StartB < arm64EndA;
    }

    private static bool Arm64TryReadUInt16(byte[] arm64Data, long arm64Offset, out ushort arm64Value)
    {
        arm64Value = 0;
        if (arm64Data == null || arm64Offset < 0L)
        {
            return false;
        }

        if (arm64Offset + 2L > arm64Data.Length)
        {
            return false;
        }

        int arm64Index = (int)arm64Offset;
        arm64Value = (ushort)(arm64Data[arm64Index] | (arm64Data[arm64Index + 1] << 8));
        return true;
    }

    private static bool Arm64TryReadUInt32(byte[] arm64Data, long arm64Offset, out uint arm64Value)
    {
        arm64Value = 0u;
        if (arm64Data == null || arm64Offset < 0L)
        {
            return false;
        }

        if (arm64Offset + 4L > arm64Data.Length)
        {
            return false;
        }

        int arm64Index = (int)arm64Offset;
        arm64Value = (uint)(arm64Data[arm64Index]
            | (arm64Data[arm64Index + 1] << 8)
            | (arm64Data[arm64Index + 2] << 16)
            | (arm64Data[arm64Index + 3] << 24));
        return true;
    }

    private static bool Arm64TryReadWord(Arm64PeView view, long rva, out uint word)
    {
        word = 0u;
        if ((rva & 3L) != 0L)
        {
            return false;
        }

        if (!view.Arm64TryMapRva(rva, 4, true, out int arm64Offset))
        {
            return false;
        }

        byte[] arm64Data = view.Arm64Bytes;
        word = (uint)(arm64Data[arm64Offset]
            | (arm64Data[arm64Offset + 1] << 8)
            | (arm64Data[arm64Offset + 2] << 16)
            | (arm64Data[arm64Offset + 3] << 24));
        return true;
    }

    private static bool Arm64Words(Arm64PeView view, long rva, params uint[] expected)
    {
        if (expected == null)
        {
            return false;
        }

        for (int i = 0; i < expected.Length; i++)
        {
            if (!Arm64TryReadWord(view, rva + (long)i * 4L, out uint arm64Word))
            {
                return false;
            }

            if (arm64Word != expected[i])
            {
                return false;
            }
        }

        return true;
    }

    private static bool Arm64TryAdrp(Arm64PeView view, long at, int rd, out long page)
    {
        page = 0L;
        if (rd < 0 || rd > 30)
        {
            return false;
        }

        if (!Arm64TryReadWord(view, at, out uint arm64Word))
        {
            return false;
        }

        if ((arm64Word & 0x9F000000u) != 0x90000000u)
        {
            return false;
        }

        if ((int)(arm64Word & 0x1Fu) != rd)
        {
            return false;
        }

        long arm64Immlo = (long)((arm64Word >> 29) & 0x3u);
        long arm64Immhi = (long)((arm64Word >> 5) & 0x7FFFFu);
        long arm64Imm = (arm64Immhi << 2) | arm64Immlo;
        if ((arm64Imm & 0x100000L) != 0L)
        {
            arm64Imm -= 0x200000L;
        }

        page = (at & Arm64PageMask) + arm64Imm * Arm64PageSize;
        return true;
    }

    private static bool Arm64TryAddImm(Arm64PeView view, long at, int rd, int rn, out long imm)
    {
        imm = 0L;
        // rd never encodes SP here. rn == 31 is the frame/output SP base that the
        // supported 64-bit ADD immediate form uses for needed stack arguments.
        if (rd < 0 || rd > 30 || rn < 0 || rn > 31)
        {
            return false;
        }

        if (!Arm64TryReadWord(view, at, out uint arm64Word))
        {
            return false;
        }

        if ((arm64Word & 0xFF800000u) != 0x91000000u)
        {
            return false;
        }

        if ((int)(arm64Word & 0x1Fu) != rd)
        {
            return false;
        }

        if ((int)((arm64Word >> 5) & 0x1Fu) != rn)
        {
            return false;
        }

        long arm64Imm12 = (long)((arm64Word >> 10) & 0xFFFu);
        imm = ((arm64Word >> 22) & 0x1u) != 0u ? arm64Imm12 << 12 : arm64Imm12;
        return true;
    }

    private static bool Arm64TryAddress(Arm64PeView view, long adrpAt, long addAt, int reg, out long rva)
    {
        rva = 0L;
        if (reg < 0 || reg > 30)
        {
            return false;
        }

        if (!Arm64TryAdrp(view, adrpAt, reg, out long arm64Page))
        {
            return false;
        }

        if (!Arm64TryAddImm(view, addAt, reg, reg, out long arm64Imm))
        {
            return false;
        }

        long arm64Address = arm64Page + arm64Imm;
        if (!view.Arm64TryMapRva(arm64Address, 1, false, out _))
        {
            return false;
        }

        rva = arm64Address;
        return true;
    }

    private static bool Arm64TryBranch(Arm64PeView view, long at, Arm64BranchKind kind, int operand, out long target)
    {
        target = 0L;
        if (!Arm64TryReadWord(view, at, out uint arm64Word))
        {
            return false;
        }

        switch (kind)
        {
            case Arm64BranchKind.B:
            case Arm64BranchKind.Bl:
            {
                uint arm64Expected = kind == Arm64BranchKind.Bl ? 0x94000000u : 0x14000000u;
                if ((arm64Word & 0xFC000000u) != arm64Expected)
                {
                    return false;
                }

                long arm64Imm26 = (long)(arm64Word & 0x03FFFFFFu);
                if ((arm64Imm26 & 0x02000000L) != 0L)
                {
                    arm64Imm26 -= 0x04000000L;
                }

                target = at + arm64Imm26 * 4L;
                break;
            }

            case Arm64BranchKind.CbzW:
            case Arm64BranchKind.CbzX:
            {
                uint arm64Expected = kind == Arm64BranchKind.CbzX ? 0xB4000000u : 0x34000000u;
                if ((arm64Word & 0xFF000000u) != arm64Expected)
                {
                    return false;
                }

                if (operand < 0 || operand > 31)
                {
                    return false;
                }

                if ((int)(arm64Word & 0x1Fu) != operand)
                {
                    return false;
                }

                long arm64Imm19 = (long)((arm64Word >> 5) & 0x7FFFFu);
                if ((arm64Imm19 & 0x40000L) != 0L)
                {
                    arm64Imm19 -= 0x80000L;
                }

                target = at + arm64Imm19 * 4L;
                break;
            }

            case Arm64BranchKind.BCond:
            {
                if ((arm64Word & 0xFF000010u) != 0x54000000u)
                {
                    return false;
                }

                if (operand < 0 || operand > 15)
                {
                    return false;
                }

                if ((int)(arm64Word & 0x0Fu) != operand)
                {
                    return false;
                }

                long arm64Imm19 = (long)((arm64Word >> 5) & 0x7FFFFu);
                if ((arm64Imm19 & 0x40000L) != 0L)
                {
                    arm64Imm19 -= 0x80000L;
                }

                target = at + arm64Imm19 * 4L;
                break;
            }

            default:
                return false;
        }

        return view.Arm64TryMapRva(target, 4, true, out _);
    }

    private static bool Arm64Utf16(Arm64PeView view, long rva, string text)
    {
        if (text == null)
        {
            return false;
        }

        byte[] arm64Data = view.Arm64Bytes;
        for (int i = 0; i < text.Length; i++)
        {
            if (!view.Arm64TryMapRva(rva + (long)i * 2L, 2, false, out int arm64Offset))
            {
                return false;
            }

            char arm64Char = text[i];
            if (arm64Data[arm64Offset] != (byte)(arm64Char & 0xFF) || arm64Data[arm64Offset + 1] != (byte)((arm64Char >> 8) & 0xFF))
            {
                return false;
            }
        }

        if (!view.Arm64TryMapRva(rva + (long)text.Length * 2L, 2, false, out int arm64Terminator))
        {
            return false;
        }

        return arm64Data[arm64Terminator] == 0 && arm64Data[arm64Terminator + 1] == 0;
    }

    private static bool Arm64BytesAt(Arm64PeView view, long rva, byte[] expected)
    {
        if (expected == null)
        {
            return false;
        }

        if (!view.Arm64TryMapRva(rva, expected.Length, false, out int arm64Offset))
        {
            return false;
        }

        byte[] arm64Data = view.Arm64Bytes;
        for (int i = 0; i < expected.Length; i++)
        {
            if (arm64Data[arm64Offset + i] != expected[i])
            {
                return false;
            }
        }

        return true;
    }

    private const int Arm64CondNe = 1;
    private const int Arm64CondLo = 3;
    private const int Arm64CondLs = 9;
    private const string Arm64PrefixGuid = "882f8c2b-9646-435f-8de5-f208ff80c1bd";
    private const string Arm64PrefixKernelBase = "KernelBaseAddr";
    private const string Arm64PrefixKernelSize = "KernelSize";

    // Narrow ADRP+ADD pair where the destination register is read from the
    // ADRP itself; the ADD must reuse that register as both source and target.
    private static bool Arm64TryAddressPair(Arm64PeView view, long adrpAt, long addAt, out long rva)
    {
        rva = 0L;
        if (!Arm64TryReadWord(view, adrpAt, out uint arm64Word))
        {
            return false;
        }

        if ((arm64Word & 0x9F000000u) != 0x90000000u)
        {
            return false;
        }

        int arm64Reg = (int)(arm64Word & 0x1Fu);
        if (arm64Reg > 30)
        {
            return false;
        }

        if (!Arm64TryAdrp(view, adrpAt, arm64Reg, out long arm64Page))
        {
            return false;
        }

        if (!Arm64TryAddImm(view, addAt, arm64Reg, arm64Reg, out long arm64Imm))
        {
            return false;
        }

        long arm64Address = arm64Page + arm64Imm;
        if (!view.Arm64TryMapRva(arm64Address, 1, false, out _))
        {
            return false;
        }

        rva = arm64Address;
        return true;
    }

    // Bounded prefix/input/math chain anchored at p. Populates m only after
    // the gzip caller, detector, cookie, q/u flow, math and header all agree.
    private static bool Arm64Prefix(Arm64PeView view, long p, out long m)
    {
        m = 0L;
        if (view == null)
        {
            return false;
        }

        if (!Arm64PrefixFrame(view, p))
        {
            return false;
        }

        if (!Arm64PrefixCaller(view, p, out long arm64Q))
        {
            return false;
        }

        if (!Arm64PrefixFlow(view, p, arm64Q, out long arm64M))
        {
            return false;
        }

        if (!Arm64PrefixMath(view, arm64M))
        {
            return false;
        }

        if (!Arm64PrefixHeader(view, arm64Q))
        {
            return false;
        }

        if (!Arm64PrefixGzipCaller(view, p))
        {
            return false;
        }

        m = arm64M;
        return true;
    }

    // Same-function frame: fixed prologue seven words, x29=sp+0x78 at +0x20,
    // and a dynamic ADRP x8 at +0x1c.
    private static bool Arm64PrefixFrame(Arm64PeView view, long p)
    {
        long arm64Prologue = p - 0x800L;
        if (!Arm64Words(
            view,
            arm64Prologue,
            0xa9ba7bfdu,
            0xa9016ffcu,
            0xa90267fau,
            0xa9035ff8u,
            0xa90457f6u,
            0xa9054ff4u,
            0xd10b83ffu))
        {
            return false;
        }

        if (!Arm64Words(view, arm64Prologue + 0x20L, 0x9101e3fdu))
        {
            return false;
        }

        return Arm64TryAdrp(view, arm64Prologue + 0x1cL, 8, out _);
    }

    private static bool Arm64PrefixCaller(Arm64PeView view, long p, out long q)
    {
        q = 0L;

        // Runtime global page in x27 (preceding) with its ADD at p+0x0c.
        if (!Arm64TryAdrp(view, p - 0x0cL, 27, out long arm64GlobalPage))
        {
            return false;
        }

        if (!Arm64TryAddImm(view, p + 0x0cL, 27, 27, out long arm64GlobalImm))
        {
            return false;
        }

        long arm64Global = arm64GlobalPage + arm64GlobalImm;
        if (!view.Arm64TryMapRva(arm64Global, 8, false, out _))
        {
            return false;
        }

        // p is the ADRP of the KernelBaseAddr literal; KernelSize is the
        // p+0x20/p+0x24 pair. GetVariable takes the name in x0, so both pairs
        // are fixed to rd=x0/rn=x0 rather than an inferred register.
        if (!Arm64TryAddress(view, p, p + 0x04L, 0, out long arm64KernelBase))
        {
            return false;
        }

        if (!Arm64Utf16(view, arm64KernelBase, Arm64PrefixKernelBase))
        {
            return false;
        }

        if (!Arm64TryAddress(view, p + 0x20L, p + 0x24L, 0, out long arm64KernelSize))
        {
            return false;
        }

        if (!Arm64Utf16(view, arm64KernelSize, Arm64PrefixKernelSize))
        {
            return false;
        }

        if (!Arm64Words(view, p - 0x08L, 0x5280011au))
        {
            return false;
        }

        if (!Arm64Words(view, p + 0x08L, 0x910623e3u))
        {
            return false;
        }

        if (!Arm64Words(view, p + 0x10L, 0x9109e3e4u))
        {
            return false;
        }

        if (!Arm64Words(view, p + 0x18L, 0xf9400368u))
        {
            return false;
        }

        if (!Arm64Words(view, p + 0x1cL, 0xaa0003fbu))
        {
            return false;
        }

        if (!Arm64Words(view, p + 0x28L, 0x910623e3u))
        {
            return false;
        }

        if (!Arm64Words(view, p + 0x2cL, 0x910a03e4u))
        {
            return false;
        }

        if (!Arm64Words(view, p + 0x34L, 0xaa000368u))
        {
            return false;
        }

        // Fixed GUID page in x20 precedes p; the helper at p+0x14 supplies the
        // dynamic ADD x20,x20 at helper+0x10.
        if (!Arm64TryAdrp(view, p - 0x04L, 20, out long arm64GuidPage))
        {
            return false;
        }

        if (!Arm64TryBranch(view, p + 0x14L, Arm64BranchKind.Bl, 0, out long arm64FirstHelper))
        {
            return false;
        }

        if (!Arm64Words(view, arm64FirstHelper, 0xf9008bbau, 0xaa1f03e2u, 0xf9400368u, 0xf9402508u))
        {
            return false;
        }

        if (!Arm64TryAddImm(view, arm64FirstHelper + 0x10L, 20, 20, out long arm64GuidImm))
        {
            return false;
        }

        if (!Arm64Words(view, arm64FirstHelper + 0x14L, 0xaa1403e1u, 0xd61f0100u))
        {
            return false;
        }

        // x1 is EFI_GUID* (16-byte EFI_GUID field layout), not a UTF16 text pointer.
        if (!Arm64BytesAt(
            view,
            arm64GuidPage + arm64GuidImm,
            new Guid(Arm64PrefixGuid).ToByteArray()))
        {
            return false;
        }

        if (!Arm64TryBranch(view, p + 0x30L, Arm64BranchKind.Bl, 0, out long arm64SecondHelper))
        {
            return false;
        }

        if (!Arm64Words(view, arm64SecondHelper, 0xaa1403e1u, 0xaa1f03e2u, 0xf9402508u, 0xf9008bbau, 0xd61f0100u))
        {
            return false;
        }

        if (!Arm64TryBranch(view, p + 0x38L, Arm64BranchKind.CbzX, 8, out q))
        {
            return false;
        }

        return q == p + 0xd4L;
    }

    // q -> m success flow, the non-gzip u block, and the exact q-relative
    // branch targets. u ends where m begins; h is numerically after p.
    private static bool Arm64PrefixFlow(Arm64PeView view, long p, long q, out long m)
    {
        m = 0L;
        if (q != p + 0xd4L)
        {
            return false;
        }

        long arm64ExpectedM = q + 0x178L;
        long arm64U = arm64ExpectedM - 0x1cL;

        if (!Arm64Words(view, q, 0xf94103a8u, 0x394543e9u, 0xf9005fe8u))
        {
            return false;
        }

        if (!Arm64TryBranch(view, q + 0x0cL, Arm64BranchKind.CbzW, 9, out long arm64QSkip))
        {
            return false;
        }

        if (arm64QSkip != q + 0x18L)
        {
            return false;
        }

        if (!Arm64Words(view, q + 0x10L, 0x91402109u))
        {
            return false;
        }

        if (!Arm64TryBranch(view, q + 0x14L, Arm64BranchKind.B, 0, out long arm64QFirstJoin))
        {
            return false;
        }

        if (arm64QFirstJoin != arm64ExpectedM)
        {
            return false;
        }

        if (!Arm64Words(view, q + 0x18L, 0x39454be9u))
        {
            return false;
        }

        if (!Arm64TryBranch(view, q + 0x1cL, Arm64BranchKind.CbzW, 9, out long arm64NonGzip))
        {
            return false;
        }

        if (arm64NonGzip != arm64U)
        {
            return false;
        }

        if (!Arm64Words(view, q + 0x20L, 0x91420109u))
        {
            return false;
        }

        if (!Arm64TryBranch(view, q + 0x24L, Arm64BranchKind.B, 0, out long arm64QSecondJoin))
        {
            return false;
        }

        if (arm64QSecondJoin != arm64ExpectedM)
        {
            return false;
        }

        if (!Arm64Words(view, arm64U, 0xf94043e9u, 0xb940fbeau, 0x8b0a0129u))
        {
            return false;
        }

        if (!Arm64Words(view, arm64U + 0x0cL, 0xf940092au))
        {
            return false;
        }

        if (!Arm64TryBranch(view, arm64U + 0x10L, Arm64BranchKind.CbzX, 10, out long arm64UBack))
        {
            return false;
        }

        if (arm64UBack != q + 0x20L)
        {
            return false;
        }

        if (!Arm64Words(view, arm64U + 0x14L, 0xf9400529u, 0x8b080129u))
        {
            return false;
        }

        m = arm64ExpectedM;
        return true;
    }

    // m first three words, the seventeen-word page/2MiB math, then B.LS to
    // m+0xd4 rejecting L<=D outside the admitted flow.
    private static bool Arm64PrefixMath(Arm64PeView view, long m)
    {
        if (!Arm64Words(view, m, 0xf94107aau, 0x8b080148u, 0xa90ba3e9u))
        {
            return false;
        }

        if (!Arm64Words(
            view,
            m + 0x0cL,
            0xb94123e8u,
            0xb94127e9u,
            0xb94107eau,
            0xb940fbebu,
            0x0b080148u,
            0x0b0b0129u,
            0x4b0b03eau,
            0x0b090108u,
            0x51000508u,
            0x0a0a0108u,
            0xa94ba7eau,
            0x0b0b0108u,
            0xcb080128u,
            0x11480169u,
            0xcb090109u,
            0xeb0a013fu,
            0xa90ca7e8u))
        {
            return false;
        }

        if (!Arm64TryBranch(view, m + 0x50L, Arm64BranchKind.BCond, Arm64CondLs, out long arm64Reject))
        {
            return false;
        }

        return arm64Reject == m + 0xd4L;
    }

    // h = q+0x28: fixed source words plus the two real helper calls.
    private static bool Arm64PrefixHeader(Arm64PeView view, long q)
    {
        long arm64H = q + 0x28L;
        if (!Arm64Words(view, arm64H, 0xf9407ba8u, 0xf94107a9u, 0xa90aa7e8u, 0x3840cd09u))
        {
            return false;
        }

        if (!Arm64TryBranch(view, arm64H + 0x10L, Arm64BranchKind.Bl, 0, out long arm64Init))
        {
            return false;
        }

        if (!Arm64Words(view, arm64H + 0x14L, 0xf9407fa9u))
        {
            return false;
        }

        if (!Arm64TryBranch(view, arm64H + 0x18L, Arm64BranchKind.Bl, 0, out long arm64Tail))
        {
            return false;
        }

        if (!Arm64Words(
            view,
            arm64H + 0x1cL,
            0xb948412bu,
            0x2a080148u,
            0xb948352au,
            0xb90107e8u,
            0xb9401928u,
            0xb90123e8u,
            0xb9400d28u,
            0xb9484d29u,
            0xb90117eau,
            0xb9011bebu,
            0xb900fbe8u))
        {
            return false;
        }

        if (!Arm64Words(
            view,
            arm64Init,
            0x3940050au,
            0x39400d0bu,
            0x39400908u,
            0x2a0a2129u,
            0x53103d08u,
            0x2a0b6108u,
            0x2a090108u,
            0xd65f03c0u))
        {
            return false;
        }

        return Arm64Words(
            view,
            arm64Tail,
            0xf9408baau,
            0xb90127e8u,
            0xaa1403e8u,
            0xa909abe9u,
            0x38408d0bu,
            0x39400d0cu,
            0x39400908u,
            0x3940268au,
            0x53103d08u,
            0x2a0a216au,
            0x2a0c6108u,
            0x2a0a0108u,
            0xb900ffe8u,
            0x3840ce88u,
            0x3940068au,
            0x39400a8cu,
            0x39400e8bu,
            0x2a0a2108u,
            0x53103d8au,
            0x2a0b614au,
            0xd65f03c0u);
    }

    // Input setup before p-0x64 BL, the gzip Boolean sink at sp+0x152, the
    // fixed caller branch edges, and the detector/cookie return chain.
    private static bool Arm64PrefixGzipCaller(Arm64PeView view, long p)
    {
        if (!Arm64Words(view, p - 0x78L, 0xf94043e8u, 0x295f07e9u, 0x390543ffu, 0x8b090114u, 0xaa1403e0u))
        {
            return false;
        }

        if (!Arm64TryBranch(view, p - 0x64L, Arm64BranchKind.Bl, 0, out long arm64Detector))
        {
            return false;
        }

        if (!Arm64TryBranch(view, p - 0x54L, Arm64BranchKind.CbzW, 0, out long arm64Zero))
        {
            return false;
        }

        if (arm64Zero != p - 0x44L)
        {
            return false;
        }

        if (!Arm64Words(view, p - 0x50L, 0x52800028u))
        {
            return false;
        }

        if (!Arm64Words(view, p - 0x4cL, 0x39054be8u))
        {
            return false;
        }

        if (!Arm64TryBranch(view, p - 0x48L, Arm64BranchKind.B, 0, out long arm64GzipJoin))
        {
            return false;
        }

        if (arm64GzipJoin != p - 0x0cL)
        {
            return false;
        }

        return Arm64PrefixDetector(view, arm64Detector);
    }

    private static bool Arm64PrefixDetector(Arm64PeView view, long d)
    {
        if (!Arm64Words(view, d, 0xd10083ffu, 0xf9000bfeu))
        {
            return false;
        }

        if (!Arm64TryAdrp(view, d + 0x08L, 9, out long arm64CookiePage))
        {
            return false;
        }

        if (!Arm64Words(view, d + 0x0cL, 0xaa0003e8u, 0x2a1f03e0u))
        {
            return false;
        }

        if (!Arm64TryAddImm(view, d + 0x14L, 9, 9, out long arm64CookieImm))
        {
            return false;
        }

        if (!Arm64Words(view, d + 0x18L, 0xf9400129u, 0xf90007e9u))
        {
            return false;
        }

        long arm64Cookie = arm64CookiePage + arm64CookieImm;
        if (!view.Arm64TryMapRva(arm64Cookie, 8, false, out _))
        {
            return false;
        }

        if (!Arm64TryBranch(view, d + 0x20L, Arm64BranchKind.CbzX, 8, out long arm64FailA))
        {
            return false;
        }

        if (arm64FailA != d + 0x58L)
        {
            return false;
        }

        if (!Arm64Words(view, d + 0x24L, 0x7100283fu))
        {
            return false;
        }

        if (!Arm64TryBranch(view, d + 0x28L, Arm64BranchKind.BCond, Arm64CondLo, out long arm64FailB))
        {
            return false;
        }

        if (arm64FailB != d + 0x58L)
        {
            return false;
        }

        if (!Arm64Words(view, d + 0x2cL, 0x39400109u))
        {
            return false;
        }

        if (!Arm64Words(view, d + 0x30L, 0x71007d3fu))
        {
            return false;
        }

        if (!Arm64TryBranch(view, d + 0x34L, Arm64BranchKind.BCond, Arm64CondNe, out long arm64FailC))
        {
            return false;
        }

        if (arm64FailC != d + 0x54L)
        {
            return false;
        }

        if (!Arm64Words(view, d + 0x38L, 0x39400509u))
        {
            return false;
        }

        if (!Arm64Words(view, d + 0x3cL, 0x71022d3fu))
        {
            return false;
        }

        if (!Arm64TryBranch(view, d + 0x40L, Arm64BranchKind.BCond, Arm64CondNe, out long arm64FailD))
        {
            return false;
        }

        if (arm64FailD != d + 0x54L)
        {
            return false;
        }

        if (!Arm64Words(view, d + 0x44L, 0x39400908u, 0x7100211fu, 0x1a9f17e0u))
        {
            return false;
        }

        if (!Arm64TryBranch(view, d + 0x50L, Arm64BranchKind.B, 0, out long arm64ReturnFalse))
        {
            return false;
        }

        if (arm64ReturnFalse != d + 0x58L)
        {
            return false;
        }

        if (!Arm64Words(view, d + 0x54L, 0x2a1f03e0u))
        {
            return false;
        }

        if (!Arm64TryAdrp(view, d + 0x58L, 9, out long arm64CookiePage2))
        {
            return false;
        }

        if (!Arm64TryBranch(view, d + 0x5cL, Arm64BranchKind.Bl, 0, out long arm64CookieCheck))
        {
            return false;
        }

        if (!Arm64TryBranch(view, d + 0x60L, Arm64BranchKind.BCond, Arm64CondNe, out long arm64StackFail))
        {
            return false;
        }

        if (arm64StackFail != d + 0x70L)
        {
            return false;
        }

        if (!Arm64Words(view, d + 0x64L, 0xf9400bfeu, 0x910083ffu, 0xd65f03c0u))
        {
            return false;
        }

        if (!Arm64Words(view, arm64CookieCheck, 0xf94007e8u))
        {
            return false;
        }

        if (!Arm64TryAddImm(view, arm64CookieCheck + 0x04L, 9, 9, out long arm64CookieImm2))
        {
            return false;
        }

        if (!Arm64Words(view, arm64CookieCheck + 0x08L, 0xf9400129u, 0xeb08013fu, 0xd65f03c0u))
        {
            return false;
        }

        return arm64CookiePage2 + arm64CookieImm2 == arm64Cookie;
    }

    // Declared XBL container window for the recognized family.
    private const long Arm64RecognizedWindow = 268435456L;

    private static bool Arm64InCodeRange(Arm64PeView view, long rva, int count)
    {
        if (view == null || count <= 0 || (rva & 3L) != 0L)
        {
            return false;
        }

        long arm64End = rva + (long)count;
        if (arm64End < rva)
        {
            return false;
        }

        IReadOnlyList<Arm64CodeRange> arm64Ranges = view.Arm64CodeRanges;
        for (int i = 0; i < arm64Ranges.Count; i++)
        {
            Arm64CodeRange arm64Range = arm64Ranges[i];
            if (rva >= arm64Range.Arm64RvaStart && arm64End <= arm64Range.Arm64RvaEnd)
            {
                return true;
            }
        }

        return false;
    }

    // Two 64-bit LDR words read the same [sp+imm] slot; the destination
    // register is deliberately not part of the comparison.
    private static bool Arm64SameLdrXSlot(uint arm64Left, uint arm64Right)
    {
        if ((arm64Left & 0xFFC00000u) != 0xF9400000u || (arm64Right & 0xFFC00000u) != 0xF9400000u)
        {
            return false;
        }

        if ((int)((arm64Left >> 5) & 0x1Fu) != 31 || (int)((arm64Right >> 5) & 0x1Fu) != 31)
        {
            return false;
        }

        return ((arm64Left >> 10) & 0xFFFu) == ((arm64Right >> 10) & 0xFFFu);
    }

    // Finite check of the zlib wrapper prefix ahead of the capacity comparison.
    // Every instruction z+0x00..z+0x34 is verified, so an unrecognised word is
    // rejected instead of being assumed harmless. w20 is initialised from w1
    // here, while the compressed length (w3) and the x2 argument stay intact.
    private static bool Arm64DecompressPrefix(Arm64PeView view, long z)
    {
        if (!Arm64Words(
            view,
            z,
            0xd10183ffu,
            0xf9000bfeu,
            0xa90267fau,
            0xa9035ff8u,
            0xa90457f6u,
            0xa9054ff4u))
        {
            return false;
        }

        // ADRP x8 at z+0x18 and ADD x8, x8 at z+0x1c must agree on one mapped
        // eight-byte raw value; no absolute production RVA is embedded here.
        if (!Arm64TryAddress(view, z + 0x18L, z + 0x1cL, 8, out long arm64Arguments))
        {
            return false;
        }

        if (!view.Arm64TryMapRva(arm64Arguments, 8, false, out _))
        {
            return false;
        }

        if (!Arm64Words(view, z + 0x20L, 0xf9400108u, 0xf90007e8u))
        {
            return false;
        }

        // A zero compressed length skips the zlib call entirely.
        if (!Arm64TryBranch(view, z + 0x28L, Arm64BranchKind.CbzX, 0, out long arm64EmptyLength))
        {
            return false;
        }

        if (arm64EmptyLength != z + 0xfcL)
        {
            return false;
        }

        if (!Arm64Words(view, z + 0x2cL, 0x2a0103f4u, 0x7100283au))
        {
            return false;
        }

        // The capacity guard is reached only after w20 has been set from w1.
        if (!Arm64TryBranch(view, z + 0x34L, Arm64BranchKind.BCond, Arm64CondLs, out long arm64TooLarge))
        {
            return false;
        }

        return arm64TooLarge == z + 0xfcL;
    }

    // Outbound gzip/frame chain anchored at m: L-D over32bit rejection, the
    // t argument setup, z capacity link, and the a image_size comparison.
    private static bool Arm64Output(Arm64PeView view, long m)
    {
        if (view == null)
        {
            return false;
        }

        long g = m + 0x144L;
        long t = g + 0x128L;
        long a = m + 0x380L;

        // Preceding x26 global page with its ADD at g+0x14, then the two
        // fixed spill words that keep the gzip path from reordering.
        if (!Arm64TryAddress(view, g - 0x04L, g + 0x14L, 26, out long arm64X26Global))
        {
            return false;
        }

        if (!view.Arm64TryMapRva(arm64X26Global, 8, false, out _))
        {
            return false;
        }

        if (!Arm64Words(view, g + 0x18L, 0xb9018bffu, 0xa9002928u))
        {
            return false;
        }

        if (!Arm64Words(view, g, 0xf9405fe8u, 0xf94067eau))
        {
            return false;
        }

        // Cookie/flag page in x9: ADRP at g+0x08, dynamic ADD at g+0x0c.
        if (!Arm64TryAddress(view, g + 0x08L, g + 0x0cL, 9, out long arm64GzipGlobal))
        {
            return false;
        }

        if (!view.Arm64TryMapRva(arm64GzipGlobal, 8, false, out _))
        {
            return false;
        }

        if (!Arm64Words(view, g + 0x10L, 0x39454bebu))
        {
            return false;
        }

        if (!Arm64TryBranch(view, g + 0x20L, Arm64BranchKind.CbzW, 11, out long arm64NonGzip))
        {
            return false;
        }

        if (arm64NonGzip != g + 0x60L)
        {
            return false;
        }

        if (!Arm64Words(view, g + 0x24L, 0xf9406be9u, 0xcb080134u, 0xd360fe88u))
        {
            return false;
        }

        if (!Arm64TryBranch(view, g + 0x30L, Arm64BranchKind.CbzX, 8, out long arm64Success))
        {
            return false;
        }

        if (arm64Success != t)
        {
            return false;
        }

        if (!Arm64TryBranch(view, t, Arm64BranchKind.Bl, 0, out long arm64THelper))
        {
            return false;
        }

        if (!Arm64InCodeRange(view, arm64THelper, 4))
        {
            return false;
        }

        if (!Arm64Words(
            view,
            t + 0x04L,
            0xf94043e8u,
            0x9101e3eau,
            0x295f07e9u,
            0xaa0003fbu,
            0x91026144u))
        {
            return false;
        }

        if (!Arm64TryReadWord(view, g, out uint arm64DWord))
        {
            return false;
        }

        if (!Arm64TryReadWord(view, t + 0x18L, out uint arm64TArgWord))
        {
            return false;
        }

        // x2 must carry the same stack value as the D load in g.
        if (!Arm64SameLdrXSlot(arm64DWord, arm64TArgWord))
        {
            return false;
        }

        // SameLdrXSlot deliberately ignores Rt, so the zlib output length must
        // additionally land in x2 rather than in any other general register.
        if ((int)(arm64TArgWord & 0x1Fu) != 2)
        {
            return false;
        }

        if (!Arm64Words(view, t + 0x1cL, 0x910623e5u, 0x2a1403e3u, 0x8b090100u))
        {
            return false;
        }

        if (!Arm64TryBranch(view, t + 0x28L, Arm64BranchKind.Bl, 0, out long z))
        {
            return false;
        }

        if (!Arm64InCodeRange(view, z, 0x7c))
        {
            return false;
        }

        if (!Arm64DecompressPrefix(view, z))
        {
            return false;
        }

        if (!Arm64Words(view, z + 0x38L, 0x2a0303f8u, 0x6b14007fu))
        {
            return false;
        }

        if (!Arm64TryBranch(view, z + 0x40L, Arm64BranchKind.BCond, Arm64CondLs, out long arm64CapacityReject))
        {
            return false;
        }

        if (arm64CapacityReject != z + 0x144L)
        {
            return false;
        }

        if (!Arm64Words(
            view,
            z + 0x44L,
            0xaa0003f7u,
            0x52800e00u,
            0xaa0503f5u,
            0xaa0403f6u,
            0xaa0203f9u))
        {
            return false;
        }

        if (!Arm64TryBranch(view, z + 0x58L, Arm64BranchKind.Bl, 0, out long arm64Allocator))
        {
            return false;
        }

        if (!Arm64InCodeRange(view, arm64Allocator, 4))
        {
            return false;
        }

        if (!Arm64TryBranch(view, z + 0x5cL, Arm64BranchKind.CbzX, 0, out long arm64AllocFail))
        {
            return false;
        }

        if (arm64AllocFail != z + 0x198L)
        {
            return false;
        }

        if (!Arm64TryAddress(view, z + 0x60L, z + 0x64L, 8, out long arm64OutGlobal))
        {
            return false;
        }

        if (!view.Arm64TryMapRva(arm64OutGlobal, 8, false, out _))
        {
            return false;
        }

        if (!Arm64TryAddress(view, z + 0x68L, z + 0x6cL, 9, out long arm64AvailGlobal))
        {
            return false;
        }

        if (!view.Arm64TryMapRva(arm64AvailGlobal, 8, false, out _))
        {
            return false;
        }

        // next_out and avail_out both hang off the allocator result in x0.
        if (!Arm64Words(view, z + 0x70L, 0xf9000c19u, 0xaa0003f3u, 0xb9002018u))
        {
            return false;
        }

        if (!Arm64Words(view, a - 0x0cL, 0xb9403a88u, 0x6b1b011fu))
        {
            return false;
        }

        if (!Arm64TryBranch(view, a - 0x04L, Arm64BranchKind.BCond, Arm64CondNe, out long arm64OtherFormat))
        {
            return false;
        }

        if (arm64OtherFormat != a + 0x44L)
        {
            return false;
        }

        if (!Arm64Words(view, a, 0xf9406be8u, 0xf9405fe9u, 0xf9400a8au))
        {
            return false;
        }

        if (!Arm64TryReadWord(view, a + 0x00L, out uint arm64LWord))
        {
            return false;
        }

        if (!Arm64TryReadWord(view, a + 0x04L, out uint arm64AArgWord))
        {
            return false;
        }

        if (!Arm64TryReadWord(view, a + 0x08L, out uint arm64SizeWord))
        {
            return false;
        }

        // Same L and D slots as the outbound path, so the compared L-D is the
        // same value handed to the decompressor.
        if (!Arm64SameLdrXSlot(arm64LWord, 0xf9406be9u))
        {
            return false;
        }

        if (!Arm64SameLdrXSlot(arm64AArgWord, arm64TArgWord))
        {
            return false;
        }

        // image_size field at +0x10 read through the same x20 base.
        if ((arm64SizeWord & 0xFFC00000u) != 0xF9400000u)
        {
            return false;
        }

        if ((int)((arm64SizeWord >> 5) & 0x1Fu) != 20)
        {
            return false;
        }

        if ((int)((arm64SizeWord >> 10) & 0xFFFu) != 2)
        {
            return false;
        }

        if (!Arm64Words(view, a + 0x0cL, 0xcb090108u, 0xeb08015fu))
        {
            return false;
        }

        if (!Arm64TryBranch(view, a + 0x14L, Arm64BranchKind.BCond, Arm64CondLs, out long arm64Allow))
        {
            return false;
        }

        if (arm64Allow != a + 0x4cL)
        {
            return false;
        }

        if (!Arm64TryBranch(view, a + 0x40L, Arm64BranchKind.B, 0, out long arm64Excess))
        {
            return false;
        }

        return arm64Excess == m + 0x104L;
    }

    // Scans executable aligned RVAs for the ADRP x0 / ADD x0,x0 name anchor and
    // requires exactly one complete linked prefix+output chain. Ambiguous or
    // partial matches are rejected; cancellation propagates.
    internal static bool MatchesArm64Pe(byte[] pe, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        if (!Arm64TryOpenPe(pe, token, out Arm64PeView view))
        {
            return false;
        }

        if (view == null)
        {
            return false;
        }

        IReadOnlyList<Arm64CodeRange> arm64Ranges = view.Arm64CodeRanges;
        long arm64Hit = -1L;
        for (int i = 0; i < arm64Ranges.Count; i++)
        {
            long arm64Start = arm64Ranges[i].Arm64RvaStart;
            long arm64End = arm64Ranges[i].Arm64RvaEnd;
            if ((arm64Start & 3L) != 0L)
            {
                arm64Start = (arm64Start + 3L) & ~3L;
            }

            for (long arm64At = arm64Start; arm64At + 8L <= arm64End; arm64At += 4L)
            {
                token.ThrowIfCancellationRequested();

                if (!Arm64TryReadWord(view, arm64At, out uint arm64AnchorWord))
                {
                    continue;
                }

                if ((arm64AnchorWord & 0x9F00001Fu) != 0x90000000u)
                {
                    continue;
                }

                if (!Arm64TryReadWord(view, arm64At + 4L, out uint arm64AddWord))
                {
                    continue;
                }

                if ((arm64AddWord & 0xFF8003FFu) != 0x91000000u)
                {
                    continue;
                }

                if (!Arm64TryAddress(view, arm64At, arm64At + 4L, 0, out long arm64Base))
                {
                    continue;
                }

                if (!Arm64Utf16(view, arm64Base, Arm64PrefixKernelBase))
                {
                    continue;
                }

                bool arm64OldChain =
                    Arm64Prefix(view, arm64At, out long arm64M) && Arm64Output(view, arm64M);
                if (!arm64OldChain && !Arm64Gen5Matches(view, arm64At))
                {
                    continue;
                }

                if (arm64Hit >= 0L && arm64Hit != arm64At)
                {
                    return false;
                }

                arm64Hit = arm64At;
            }
        }

        return arm64Hit >= 0L;
    }

    internal static bool TryRecognize(byte[] abl, byte[] xbl, CancellationToken token, out string evidence)
    {
        evidence = "unrecognized";
        token.ThrowIfCancellationRequested();

        if (!TryDecodeContainers(abl, xbl, token, out byte[] arm64Pe, out long arm64Window))
        {
            return false;
        }

        if (arm64Window != Arm64RecognizedWindow || arm64Pe == null || arm64Pe.Length == 0)
        {
            return false;
        }

        if (!MatchesArm64Pe(arm64Pe, token))
        {
            return false;
        }

        evidence = "conditional-normal GetVariable success; static same-slot XBL region match; runtime GetVariable results and physical capacity unverified";
        return true;
    }
}
