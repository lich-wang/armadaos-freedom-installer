using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace FreedomInstaller.Core;

public enum EdlRawDtbKind
{
    Normal,
    Diagnostic
}

public sealed class EdlRawDtbEvidence
{
    internal EdlRawDtbEvidence(
        EdlRawDtbKind kind,
        string deviceModel,
        long length,
        string sha256,
        IReadOnlyList<string> compatible,
        string bootArgs,
        string bootStage,
        string rootMedium,
        uint initrdEntryIndex)
    {
        string[] compatibleCopy = new string[compatible.Count];
        for (int i = 0; i < compatibleCopy.Length; i++)
        {
            compatibleCopy[i] = compatible[i];
        }

        Kind = kind;
        DeviceModel = deviceModel;
        Length = length;
        Sha256 = sha256;
        Compatible = Array.AsReadOnly(compatibleCopy);
        BootArgs = bootArgs;
        BootStage = bootStage;
        RootMedium = rootMedium;
        InitrdEntryIndex = initrdEntryIndex;
    }

    public EdlRawDtbKind Kind { get; }

    public string DeviceModel { get; }

    public long Length { get; }

    public string Sha256 { get; }

    public IReadOnlyList<string> Compatible { get; }

    public string BootArgs { get; }

    public string BootStage { get; }

    public string RootMedium { get; }

    public uint InitrdEntryIndex { get; }
}

public static class EdlRawDtbValidator
{
    private const uint FdtMagic = 0xD00DFEED;
    private const uint TokenBeginNode = 1;
    private const uint TokenEndNode = 2;
    private const uint TokenProperty = 3;
    private const uint TokenNop = 4;
    private const uint TokenEnd = 9;

    private const int HeaderSize = 40;
    private const int ReservationEntrySize = 16;
    private const int MaxExpectedBootArgsBytes = 4096;
    private const int MaxStringBytes = 4096;

    private const uint SupportedVersion = 17;
    private const uint MaxLastCompatibleVersion = 17;
    private const uint ExpectedInitrdEntryIndex = 5;

    private const string ModelG4 = "TB322FC";
    private const string ModelG5 = "TB323FU";
    private const string G4DeviceToken = "lenovo,elden";
    private const string G4SocToken = "qcom,sm8750";
    private const string G5DeviceToken = "lenovo,baldur";
    private const string G5SocToken = "qcom,kaanapali";

    private const string NormalStage = "os";
    private const string DiagnosticStage = "maintenance";
    private const string InternalMedium = "internal";
    private const string TfMedium = "tf";

    private const string CompatibleProperty = "compatible";
    private const string ChosenNode = "chosen";
    private const string BootArgsProperty = "bootargs";
    private const string BootStageProperty = "armada,boot-stage";
    private const string RootMediumProperty = "armada,root-medium";
    private const string InitrdEntryProperty = "kshim,initrd-entry";
    private const string InitrdStartProperty = "linux,initrd-start";
    private const string InitrdEndProperty = "linux,initrd-end";

    private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

    public static EdlRawDtbEvidence Validate(
        ReadOnlySpan<byte> dtb,
        string expectedBootArgs,
        EdlRawDtbKind kind,
        string expectedModel)
    {
        return ValidateCore(dtb, expectedBootArgs, kind, expectedModel, InternalMedium);
    }

    public static EdlRawDtbEvidence ValidateTf(
        ReadOnlySpan<byte> dtb,
        string expectedBootArgs,
        EdlRawDtbKind kind,
        string expectedModel)
    {
        return ValidateCore(dtb, expectedBootArgs, kind, expectedModel, TfMedium);
    }

    internal static EdlRawDtbEvidence ValidateTfPacked(
        ReadOnlySpan<byte> dtb,
        string expectedBootArgs,
        EdlRawDtbKind kind,
        string expectedModel,
        uint expectedInitrdIndex)
    {
        if (expectedInitrdIndex == 0)
        {
            throw new ArgumentException("Expected initrd entry index must not be zero.", nameof(expectedInitrdIndex));
        }

        return ValidateCore(dtb, expectedBootArgs, kind, expectedModel, TfMedium, expectedInitrdIndex);
    }

    internal static byte[] RelocateTfInitrdEntry(
        ReadOnlySpan<byte> dtb,
        string expectedBootArgs,
        EdlRawDtbKind kind,
        string expectedModel,
        uint newInitrdIndex)
    {
        if (newInitrdIndex == 0)
        {
            throw new ArgumentException("New initrd entry index must not be zero.", nameof(newInitrdIndex));
        }

        _ = ValidateTf(dtb, expectedBootArgs, kind, expectedModel);

        Facts facts = Parse(dtb);
        PropertySlice slice = facts.InitrdEntry;
        if (!slice.Present || slice.Length != 4)
        {
            throw Malformed(InitrdEntryProperty + " must contain exactly one cell.");
        }

        byte[] relocated = dtb.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(relocated.AsSpan(slice.Offset, 4), newInitrdIndex);

        _ = ValidateTfPacked(relocated, expectedBootArgs, kind, expectedModel, newInitrdIndex);
        return relocated;
    }

    internal static (string RootMedium, string BootArgs, uint InitrdEntryIndex) ReadInstalledRoute(
        ReadOnlySpan<byte> dtb,
        string expectedModel)
    {
        Facts facts;
        try
        {
            facts = Parse(dtb);
        }
        catch (OverflowException)
        {
            throw Malformed("numeric overflow while decoding header or structure block.");
        }
        catch (ArgumentOutOfRangeException)
        {
            throw Malformed("structure bounds escaped the input buffer.");
        }
        catch (DecoderFallbackException)
        {
            throw Malformed("device tree text is not valid UTF-8.");
        }

        if (!facts.RootSeen)
        {
            throw Malformed("missing root node.");
        }

        if (!facts.ChosenSeen)
        {
            throw Malformed("missing /chosen node.");
        }

        string rootMedium = ReadSingleNulString(dtb, facts.RootMedium, RootMediumProperty);
        bool isInternal = string.Equals(rootMedium, InternalMedium, StringComparison.Ordinal);
        bool isTf = string.Equals(rootMedium, TfMedium, StringComparison.Ordinal);
        if (!isInternal && !isTf)
        {
            throw Malformed(RootMediumProperty + " must be " + InternalMedium + " or " + TfMedium + ".");
        }

        string bootArgs = ReadSingleNulString(dtb, facts.BootArgs, BootArgsProperty);
        if (bootArgs.Length == 0)
        {
            throw Malformed(BootArgsProperty + " must not be empty.");
        }

        string bootStage = ReadSingleNulString(dtb, facts.BootStage, BootStageProperty);
        bool isOs = string.Equals(bootStage, NormalStage, StringComparison.Ordinal);
        bool isMaintenance = string.Equals(bootStage, DiagnosticStage, StringComparison.Ordinal);
        if (!isOs && !isMaintenance)
        {
            throw Malformed(BootStageProperty + " must be " + NormalStage + " or " + DiagnosticStage + ".");
        }

        if (!facts.InitrdEntry.Present)
        {
            throw Malformed("missing /chosen " + InitrdEntryProperty + " property.");
        }

        if (facts.InitrdEntry.Length != 4)
        {
            throw Malformed(InitrdEntryProperty + " must contain exactly one cell.");
        }

        uint initrdEntryIndex = BinaryPrimitives.ReadUInt32BigEndian(dtb.Slice(facts.InitrdEntry.Offset, 4));
        if (initrdEntryIndex == 0)
        {
            throw Malformed(InitrdEntryProperty + " must not be zero.");
        }

        EdlRawDtbKind kind = isOs ? EdlRawDtbKind.Normal : EdlRawDtbKind.Diagnostic;
        ValidateCore(dtb, bootArgs, kind, expectedModel, rootMedium, initrdEntryIndex);

        return (rootMedium, bootArgs, initrdEntryIndex);
    }

    private static EdlRawDtbEvidence ValidateCore(
        ReadOnlySpan<byte> dtb,
        string expectedBootArgs,
        EdlRawDtbKind kind,
        string expectedModel,
        string expectedRootMedium,
        uint expectedInitrdIndex = ExpectedInitrdEntryIndex)
    {
        if (kind != EdlRawDtbKind.Normal && kind != EdlRawDtbKind.Diagnostic)
        {
            throw new ArgumentException("Unsupported DTB kind.", nameof(kind));
        }

        if (expectedModel is null)
        {
            throw new ArgumentException("Expected model is required.", nameof(expectedModel));
        }

        bool isG4 = string.Equals(expectedModel, ModelG4, StringComparison.Ordinal);
        bool isG5 = string.Equals(expectedModel, ModelG5, StringComparison.Ordinal);
        if (!isG4 && !isG5)
        {
            throw new ArgumentException("Expected model must be exactly TB322FC or TB323FU.", nameof(expectedModel));
        }

        ValidateExpectedBootArgs(expectedBootArgs);

        string requiredDevice = isG4 ? G4DeviceToken : G5DeviceToken;
        string requiredSoc = isG4 ? G4SocToken : G5SocToken;
        string foreignDevice = isG4 ? G5DeviceToken : G4DeviceToken;
        string foreignSoc = isG4 ? G5SocToken : G4SocToken;

        Facts facts;
        try
        {
            facts = Parse(dtb);
        }
        catch (OverflowException)
        {
            throw Malformed("numeric overflow while decoding header or structure block.");
        }
        catch (ArgumentOutOfRangeException)
        {
            throw Malformed("structure bounds escaped the input buffer.");
        }
        catch (DecoderFallbackException)
        {
            throw Malformed("device tree text is not valid UTF-8.");
        }

        if (!facts.RootSeen)
        {
            throw Malformed("missing root node.");
        }

        if (!facts.ChosenSeen)
        {
            throw Malformed("missing /chosen node.");
        }

        string[] compatible = ReadCompatibleList(dtb, facts.Compatible, requiredDevice, requiredSoc, foreignDevice, foreignSoc);
        string bootArgs = ReadBootArgs(dtb, facts.BootArgs, expectedBootArgs);
        string bootStage = ReadSingleNulString(dtb, facts.BootStage, BootStageProperty);
        string expectedStage = kind == EdlRawDtbKind.Normal ? NormalStage : DiagnosticStage;
        if (!string.Equals(bootStage, expectedStage, StringComparison.Ordinal))
        {
            throw Malformed(BootStageProperty + " does not match the requested kind.");
        }

        string rootMedium = ReadSingleNulString(dtb, facts.RootMedium, RootMediumProperty);
        if (!string.Equals(rootMedium, expectedRootMedium, StringComparison.Ordinal))
        {
            throw Malformed(RootMediumProperty + " must be " + expectedRootMedium + ".");
        }

        uint initrdEntryIndex = ReadInitrdEntryIndex(dtb, facts.InitrdEntry, expectedInitrdIndex);

        byte[] hash = SHA256.HashData(dtb);
        string sha256 = Convert.ToHexString(hash).ToLowerInvariant();

        return new EdlRawDtbEvidence(
            kind,
            expectedModel,
            dtb.Length,
            sha256,
            compatible,
            bootArgs,
            bootStage,
            rootMedium,
            initrdEntryIndex);
    }

    private static void ValidateExpectedBootArgs(string expectedBootArgs)
    {
        if (expectedBootArgs is null)
        {
            throw new ArgumentException("Expected boot arguments are required.", nameof(expectedBootArgs));
        }

        if (expectedBootArgs.Length == 0)
        {
            throw new ArgumentException("Expected boot arguments must not be empty.", nameof(expectedBootArgs));
        }

        for (int i = 0; i < expectedBootArgs.Length; i++)
        {
            char current = expectedBootArgs[i];
            if (current == '\0' || current == '\r' || current == '\n')
            {
                throw new ArgumentException(
                    "Expected boot arguments must be a single line without NUL characters.",
                    nameof(expectedBootArgs));
            }
        }

        byte[] encoded;
        try
        {
            encoded = StrictUtf8.GetBytes(expectedBootArgs);
        }
        catch (EncoderFallbackException)
        {
            throw new ArgumentException("Expected boot arguments must be valid UTF-8.", nameof(expectedBootArgs));
        }

        if (encoded.Length > MaxExpectedBootArgsBytes)
        {
            throw new ArgumentException(
                "Expected boot arguments exceed the " + MaxExpectedBootArgsBytes + " byte limit.",
                nameof(expectedBootArgs));
        }
    }

    private static Facts Parse(ReadOnlySpan<byte> dtb)
    {
        int length = dtb.Length;
        if (length < HeaderSize)
        {
            throw Malformed("device tree header is truncated.");
        }

        if (ReadUInt32BigEndian(dtb, 0) != FdtMagic)
        {
            throw Malformed("bad header magic.");
        }

        long totalSize = ReadUInt32BigEndian(dtb, 4);
        if (totalSize != length)
        {
            throw Malformed("header total size does not match the input length.");
        }

        uint version = ReadUInt32BigEndian(dtb, 20);
        if (version != SupportedVersion)
        {
            throw Malformed("unsupported device tree version.");
        }

        uint lastCompatibleVersion = ReadUInt32BigEndian(dtb, 24);
        if (lastCompatibleVersion > MaxLastCompatibleVersion)
        {
            throw Malformed("unsupported last compatible version.");
        }

        long structOffset = ReadUInt32BigEndian(dtb, 8);
        long stringsOffset = ReadUInt32BigEndian(dtb, 12);
        long reserveOffset = ReadUInt32BigEndian(dtb, 16);
        long stringsSize = ReadUInt32BigEndian(dtb, 32);
        long structSize = ReadUInt32BigEndian(dtb, 36);

        if ((structOffset & 3) != 0 || (structSize & 3) != 0)
        {
            throw Malformed("structure block offset or size is not 4 byte aligned.");
        }

        if ((reserveOffset & 7) != 0)
        {
            throw Malformed("reservation block offset is not 8 byte aligned.");
        }

        if (structOffset < HeaderSize || stringsOffset < HeaderSize || reserveOffset < HeaderSize)
        {
            throw Malformed("a block starts inside the device tree header.");
        }

        long structEnd = structOffset + structSize;
        long stringsEnd = stringsOffset + stringsSize;
        if (structEnd > length || stringsEnd > length)
        {
            throw Malformed("a block extends past the end of the input.");
        }

        if (Overlaps(structOffset, structEnd, stringsOffset, stringsEnd))
        {
            throw Malformed("structure and strings blocks overlap.");
        }

        long reserveEnd = FindReservationEnd(dtb, reserveOffset);
        if (Overlaps(reserveOffset, reserveEnd, structOffset, structEnd) ||
            Overlaps(reserveOffset, reserveEnd, stringsOffset, stringsEnd))
        {
            throw Malformed("reservation block overlaps another block.");
        }

        return ParseStructure(dtb, structOffset, structEnd, stringsOffset, stringsSize, stringsEnd);
    }

    private static long FindReservationEnd(ReadOnlySpan<byte> dtb, long reserveOffset)
    {
        long limit = dtb.Length;
        for (long position = reserveOffset; ; position += ReservationEntrySize)
        {
            if (position > limit - ReservationEntrySize)
            {
                throw Malformed("reservation block is not terminated inside the input.");
            }

            ulong address = BinaryPrimitives.ReadUInt64BigEndian(dtb.Slice((int)position, 8));
            ulong size = BinaryPrimitives.ReadUInt64BigEndian(dtb.Slice((int)position + 8, 8));
            if (address == 0 && size == 0)
            {
                return position + ReservationEntrySize;
            }
        }
    }

    private static Facts ParseStructure(
        ReadOnlySpan<byte> dtb,
        long structOffset,
        long structEnd,
        long stringsOffset,
        long stringsSize,
        long stringsEnd)
    {
        var facts = new Facts();
        var frames = new List<Frame>();
        Frame chosenFrame = null;
        bool rootClosed = false;
        bool endSeen = false;
        long position = structOffset;

        while (!endSeen)
        {
            if (position + 4 > structEnd)
            {
                throw Malformed("structure block ended before the END token.");
            }

            uint token = ReadUInt32BigEndian(dtb, (int)position);
            position += 4;

            if (token == TokenBeginNode)
            {
                string name = ReadNodeName(dtb, ref position, structEnd);
                AlignToFour(ref position, structEnd);

                if (frames.Count == 0)
                {
                    if (rootClosed || facts.RootSeen)
                    {
                        throw Malformed("second root node in the structure block.");
                    }

                    if (name.Length != 0)
                    {
                        throw Malformed("root node name must be empty.");
                    }

                    facts.RootSeen = true;
                    frames.Add(new Frame());
                }
                else
                {
                    if (name.Length == 0)
                    {
                        throw Malformed("non-root node name must not be empty.");
                    }

                    if (name.IndexOf('/') >= 0)
                    {
                        throw Malformed("node name must not contain a path separator.");
                    }

                    Frame parent = frames[frames.Count - 1];
                    if (!parent.AddChild(name))
                    {
                        throw Malformed("duplicate child node name.");
                    }

                    var frame = new Frame();
                    frames.Add(frame);

                    if (frames.Count == 2 && string.Equals(name, ChosenNode, StringComparison.Ordinal))
                    {
                        facts.ChosenSeen = true;
                        chosenFrame = frame;
                    }
                }

                continue;
            }

            if (token == TokenEndNode)
            {
                if (frames.Count == 0)
                {
                    throw Malformed("END_NODE token without an open node.");
                }

                frames.RemoveAt(frames.Count - 1);
                if (frames.Count == 0)
                {
                    rootClosed = true;
                }

                continue;
            }

            if (token == TokenProperty)
            {
                if (frames.Count == 0)
                {
                    throw Malformed("property outside of any node.");
                }

                if (position + 8 > structEnd)
                {
                    throw Malformed("property header is truncated.");
                }

                long valueLength = ReadUInt32BigEndian(dtb, (int)position);
                long nameOffset = ReadUInt32BigEndian(dtb, (int)position + 4);
                position += 8;

                string propertyName = ReadPropertyName(dtb, stringsOffset, stringsSize, stringsEnd, nameOffset);
                if (valueLength > structEnd - position)
                {
                    throw Malformed("property value extends past the structure block.");
                }

                long dataStart = position;
                position = dataStart + valueLength;
                AlignToFour(ref position, structEnd);

                Frame frame = frames[frames.Count - 1];
                if (!frame.AddProperty(propertyName))
                {
                    throw Malformed("duplicate property name in a node.");
                }

                if (frames.Count == 1)
                {
                    if (string.Equals(propertyName, CompatibleProperty, StringComparison.Ordinal))
                    {
                        facts.Compatible = new PropertySlice((int)dataStart, (int)valueLength);
                    }
                }
                else if (ReferenceEquals(frame, chosenFrame))
                {
                    switch (propertyName)
                    {
                        case BootArgsProperty:
                            facts.BootArgs = new PropertySlice((int)dataStart, (int)valueLength);
                            break;
                        case BootStageProperty:
                            facts.BootStage = new PropertySlice((int)dataStart, (int)valueLength);
                            break;
                        case RootMediumProperty:
                            facts.RootMedium = new PropertySlice((int)dataStart, (int)valueLength);
                            break;
                        case InitrdEntryProperty:
                            facts.InitrdEntry = new PropertySlice((int)dataStart, (int)valueLength);
                            break;
                        case InitrdStartProperty:
                            throw Malformed("stale " + InitrdStartProperty + " is present.");
                        case InitrdEndProperty:
                            throw Malformed("stale " + InitrdEndProperty + " is present.");
                    }
                }

                continue;
            }

            if (token == TokenNop)
            {
                continue;
            }

            if (token == TokenEnd)
            {
                if (frames.Count != 0 || !rootClosed)
                {
                    throw Malformed("END token with unbalanced nodes.");
                }

                endSeen = true;
                continue;
            }

            throw Malformed("unknown structure block token.");
        }

        for (long i = position; i < structEnd; i++)
        {
            if (dtb[(int)i] != 0)
            {
                throw Malformed("non-zero data after the END token.");
            }
        }

        if (!facts.RootSeen)
        {
            throw Malformed("missing root node.");
        }

        return facts;
    }

    private static string[] ReadCompatibleList(
        ReadOnlySpan<byte> dtb,
        PropertySlice slice,
        string requiredDevice,
        string requiredSoc,
        string foreignDevice,
        string foreignSoc)
    {
        if (!slice.Present)
        {
            throw Malformed("missing root " + CompatibleProperty + " property.");
        }

        ReadOnlySpan<byte> data = dtb.Slice(slice.Offset, slice.Length);
        if (data.Length == 0 || data[data.Length - 1] != 0)
        {
            throw Malformed(CompatibleProperty + " is not NUL terminated.");
        }

        var items = new List<string>();
        int itemStart = 0;
        int deviceCount = 0;
        int socCount = 0;

        for (int i = 0; i < data.Length; i++)
        {
            if (data[i] != 0)
            {
                continue;
            }

            if (i == itemStart)
            {
                throw Malformed(CompatibleProperty + " contains an empty item.");
            }

            string item = DecodeStrictUtf8(data.Slice(itemStart, i - itemStart), CompatibleProperty);
            if (string.Equals(item, foreignDevice, StringComparison.Ordinal) ||
                string.Equals(item, foreignSoc, StringComparison.Ordinal))
            {
                throw Malformed(CompatibleProperty + " contains a token from another model family.");
            }

            if (string.Equals(item, requiredDevice, StringComparison.Ordinal))
            {
                deviceCount++;
            }
            else if (string.Equals(item, requiredSoc, StringComparison.Ordinal))
            {
                socCount++;
            }

            items.Add(item);
            itemStart = i + 1;
        }

        if (deviceCount != 1 || socCount != 1)
        {
            throw Malformed(CompatibleProperty + " does not contain the required model pair exactly once.");
        }

        return items.ToArray();
    }

    private static string ReadBootArgs(ReadOnlySpan<byte> dtb, PropertySlice slice, string expectedBootArgs)
    {
        if (!slice.Present)
        {
            throw Malformed("missing /chosen " + BootArgsProperty + " property.");
        }

        ReadOnlySpan<byte> data = dtb.Slice(slice.Offset, slice.Length);
        int terminator = data.IndexOf((byte)0);
        if (terminator < 0)
        {
            throw Malformed(BootArgsProperty + " is not NUL terminated.");
        }

        if (terminator != data.Length - 1)
        {
            throw Malformed(BootArgsProperty + " has interior NUL bytes or trailing data.");
        }

        string bootArgs = DecodeStrictUtf8(data.Slice(0, terminator), BootArgsProperty);
        if (!string.Equals(bootArgs, expectedBootArgs, StringComparison.Ordinal))
        {
            throw Malformed(BootArgsProperty + " does not match the expected value.");
        }

        return bootArgs;
    }

    private static string ReadSingleNulString(ReadOnlySpan<byte> dtb, PropertySlice slice, string propertyName)
    {
        if (!slice.Present)
        {
            throw Malformed("missing /chosen " + propertyName + " property.");
        }

        ReadOnlySpan<byte> data = dtb.Slice(slice.Offset, slice.Length);
        int terminator = data.IndexOf((byte)0);
        if (terminator < 0)
        {
            throw Malformed(propertyName + " is not NUL terminated.");
        }

        if (terminator != data.Length - 1)
        {
            throw Malformed(propertyName + " has interior NUL bytes or trailing data.");
        }

        return DecodeStrictUtf8(data.Slice(0, terminator), propertyName);
    }

    private static uint ReadInitrdEntryIndex(ReadOnlySpan<byte> dtb, PropertySlice slice, uint expectedIndex = ExpectedInitrdEntryIndex)
    {
        if (!slice.Present)
        {
            throw Malformed("missing /chosen " + InitrdEntryProperty + " property.");
        }

        if (slice.Length != 4)
        {
            throw Malformed(InitrdEntryProperty + " must contain exactly one cell.");
        }

        uint value = BinaryPrimitives.ReadUInt32BigEndian(dtb.Slice(slice.Offset, 4));
        if (value != expectedIndex)
        {
            throw Malformed(InitrdEntryProperty + " must reference the protocol 1 initramfs entry.");
        }

        return value;
    }

    private static string ReadNodeName(ReadOnlySpan<byte> dtb, ref long position, long limit)
    {
        long start = position;
        long scan = start;
        while (scan < limit && dtb[(int)scan] != 0)
        {
            scan++;
            if (scan - start > MaxStringBytes)
            {
                throw Malformed("node name is too long.");
            }
        }

        if (scan >= limit)
        {
            throw Malformed("node name is not NUL terminated.");
        }

        string name = DecodeStrictUtf8(dtb.Slice((int)start, (int)(scan - start)), "node name");
        position = scan + 1;
        return name;
    }

    private static string ReadPropertyName(
        ReadOnlySpan<byte> dtb,
        long stringsOffset,
        long stringsSize,
        long stringsEnd,
        long nameOffset)
    {
        if (nameOffset >= stringsSize)
        {
            throw Malformed("property name offset is outside the strings block.");
        }

        long start = stringsOffset + nameOffset;
        long scan = start;
        while (scan < stringsEnd && dtb[(int)scan] != 0)
        {
            scan++;
            if (scan - start > MaxStringBytes)
            {
                throw Malformed("property name is too long.");
            }
        }

        if (scan >= stringsEnd)
        {
            throw Malformed("property name is not NUL terminated inside the strings block.");
        }

        if (scan == start)
        {
            throw Malformed("property name must not be empty.");
        }

        return DecodeStrictUtf8(dtb.Slice((int)start, (int)(scan - start)), "property name");
    }

    private static void AlignToFour(ref long position, long limit)
    {
        position = (position + 3) & ~3L;
        if (position > limit)
        {
            throw Malformed("structure block padding extends past the block end.");
        }
    }

    private static uint ReadUInt32BigEndian(ReadOnlySpan<byte> data, int offset)
    {
        return BinaryPrimitives.ReadUInt32BigEndian(data.Slice(offset, 4));
    }

    private static string DecodeStrictUtf8(ReadOnlySpan<byte> data, string what)
    {
        try
        {
            return StrictUtf8.GetString(data);
        }
        catch (DecoderFallbackException)
        {
            throw Malformed(what + " is not valid UTF-8.");
        }
    }

    private static bool Overlaps(long firstStart, long firstEnd, long secondStart, long secondEnd)
    {
        return firstStart < secondEnd && secondStart < firstEnd;
    }

    private static InvalidDataException Malformed(string reason)
    {
        return new InvalidDataException("Malformed device tree: " + reason);
    }

    private readonly struct PropertySlice
    {
        public PropertySlice(int offset, int length)
        {
            Offset = offset;
            Length = length;
            Present = true;
        }

        public int Offset { get; }

        public int Length { get; }

        public bool Present { get; }
    }

    private struct Facts
    {
        public bool RootSeen;
        public bool ChosenSeen;
        public PropertySlice Compatible;
        public PropertySlice BootArgs;
        public PropertySlice BootStage;
        public PropertySlice RootMedium;
        public PropertySlice InitrdEntry;
    }

    private sealed class Frame
    {
        private HashSet<string> _properties;
        private HashSet<string> _children;

        public bool AddProperty(string name)
        {
            if (_properties == null)
            {
                _properties = new HashSet<string>(StringComparer.Ordinal);
            }

            return _properties.Add(name);
        }

        public bool AddChild(string name)
        {
            if (_children == null)
            {
                _children = new HashSet<string>(StringComparer.Ordinal);
            }

            return _children.Add(name);
        }
    }
}
