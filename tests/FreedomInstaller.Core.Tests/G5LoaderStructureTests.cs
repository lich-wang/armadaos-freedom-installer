using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Discovery-level gate for the Gen5 loader-structure regressions below. They are meaningless without the
/// two real Gen5 loader captures (no loader bytes are committed), so xunit must report them as skipped
/// while the directory is not mounted. The decision is taken at discovery time from the environment; once
/// the variable is set a missing file or an unusable capture fails the run instead of skipping it. The
/// release run always sets the variable, so a published run contains no skips.
/// </summary>
public sealed class G5LoaderFixtureFactAttribute : FactAttribute
{
    public G5LoaderFixtureFactAttribute()
    {
        Skip = G5LoaderStructureTests.UnmountedSkipReason(
            G5LoaderStructureTests.FixtureRootVariable,
            G5LoaderStructureTests.AblName,
            G5LoaderStructureTests.XblConfigName);
    }
}

/// <summary>Theory form of <see cref="G5LoaderFixtureFactAttribute"/>: the same discovery-time gate, applied
/// to every inline data row of a public-capture theory.</summary>
public sealed class G5LoaderFixtureTheoryAttribute : TheoryAttribute
{
    public G5LoaderFixtureTheoryAttribute()
    {
        Skip = G5LoaderStructureTests.UnmountedSkipReason(
            G5LoaderStructureTests.FixtureRootVariable,
            G5LoaderStructureTests.AblName,
            G5LoaderStructureTests.XblConfigName);
    }
}

/// <summary>
/// Discovery-level gate for the owner-approved actual Gen5 capture pair, and for nothing else: it reads only
/// <c>G5_ACTUAL_LOADER_FIXTURE_ROOT</c>, independently of the public capture root. An unset variable skips;
/// a set variable with a missing or altered capture fails, because a run that claims to mount the private
/// pair must actually see it.
/// </summary>
public sealed class G5ActualLoaderFixtureFactAttribute : FactAttribute
{
    public G5ActualLoaderFixtureFactAttribute()
    {
        Skip = G5LoaderStructureTests.UnmountedSkipReason(
            G5LoaderStructureTests.ActualFixtureRootVariable,
            G5LoaderStructureTests.ActualAblName,
            G5LoaderStructureTests.ActualXblConfigName);
    }
}

/// <summary>
/// Boundary evidence for the Gen5 ABL chain: the ABL container decode, the strict ARM64 PE matcher, and the
/// container pair decoder/recognizer are asked directly about the mounted Gen5 captures rather than through
/// the Gen4 slot pipeline. The captures themselves are never committed; instead this file carries their
/// reviewed lengths and SHA-256 digests as constants, so every read is refused — before any production
/// method sees the bytes — unless it is byte-for-byte the reviewed capture. Those digests are public
/// expectations, not values read back from the reader, and nothing here asks the production code to
/// stringify its own source.
///
/// The Gen5 reader currently rejects the C780 Kernel-region layout, so the pair facts are expected to stay
/// red until the Kernel-region reader accepts that layout; the ABL-only facts keep the reviewed ARM64
/// capacity chain observable either way.
/// </summary>
public sealed class G5LoaderStructureTests
{
    /// <summary>Directory holding the two mounted public Gen5 loader captures.</summary>
    public const string FixtureRootVariable = "G5_LOADER_FIXTURE_ROOT";

    public const string AblName = "abl.elf";
    public const string XblConfigName = "xbl_config.elf";

    /// <summary>
    /// Directory holding the two owner-approved private Gen5 captures. They are mounted read-only by the
    /// release run, never committed, and never copied out of this process.
    /// </summary>
    public const string ActualFixtureRootVariable = "G5_ACTUAL_LOADER_FIXTURE_ROOT";

    public const string ActualAblName = "abl_a.bin";
    public const string ActualXblConfigName = "xbl_config_a.bin";

    // Reviewed capture identities. These are the claims the fixture must satisfy before any production
    // method sees the bytes; they are not derived from the reader and are independent of its results.
    private const int ExpectedAblLength = 270136;
    private const string ExpectedAblSha256 =
        "A7B278E11E6C7AA2A930C69E0811F3C0C3DADFE066F5753A7C975B4BACF991BA";

    private const int ExpectedXblLength = 381708;
    private const string ExpectedXblSha256 =
        "737E87430B19A0D83D885DE207584A77711B5F26F1852FFD381DAEEE2A8893F9";

    private const int ExpectedActualAblLength = 1048576;
    private const string ExpectedActualAblSha256 =
        "382A34D8E460FA98BF210B7E36731BD3CFB2B97AA0E6582AD000EA9FB340AF52";

    private const int ExpectedActualXblLength = 471040;
    private const string ExpectedActualXblSha256 =
        "C391D93F8C65BBAB2E91ED5981910BD133313F33146CA30A864B865CFB46CEF9";

    // The reviewed Gen5 Kernel-region window is 256 MiB. It is an independent expectation here: the test
    // does not read it back from the production constant or from the decoded FDT.
    private const long ExpectedKernelRegionWindowBytes = 268435456;

    // Independent layout metadata for the pinned public captures. These offsets and values come from the
    // loader analysis and from the ELF/PE headers it records, not from any production reader, so a test that
    // patches them is provably patching the reviewed bytes and not whatever the reader happens to look at.
    private const int XblRegOffset = 0x2A128;
    private const int XblRegLength = 16;
    private const int XblNodeOffset = 0x2A0F8;
    private const uint PinnedRegBase = 0xC7800000;
    private const uint PinnedRegSize = 0x10000000;
    private const string PinnedNodeText = "memory@C7800000";

    private const uint PeTextOffset = 0x1000;
    private const uint PeTextSize = 0x62000;
    private const uint PeDataOffset = 0x63000;
    private const uint PeDataSize = 0x42000;

    private const uint KernelBaseNameOffset = 0x5813A;
    private const uint KernelSizeNameOffset = 0x58190;
    private const uint KernelBaseLoadOffset = 0xB420;
    private const uint KernelSizeLoadOffset = 0xB454;
    private const uint RelocatedKernelBaseOffset = 0xA4000;
    private const uint RelocatedKernelSizeOffset = 0xA4040;

    /// <summary>
    /// Gen5 ABL must decode to a PE image that the existing strict ARM64 capacity matcher accepts. When
    /// this fails the reviewed strict GetVariable/gzip ARM64 proof cannot be reused for Gen5, and that is
    /// itself the finding: the message says which of the two stages broke so the report is actionable.
    /// </summary>
    [G5LoaderFixtureFact]
    public void Gen5AblMatchesReviewedArm64CapacityChain()
    {
        byte[] abl = LoadAbl();

        byte[] image = DecodeBoundedImage(abl);
        Assert.True(
            image.Length >= 2 && image[0] == (byte)'M' && image[1] == (byte)'Z',
            "ContainerTryDecodeBoundedImage reported success for the Gen5 ABL but the decoded image is "
                + "not an MZ executable (length " + image.Length + ").");

        bool matched = MatchArm64Pe(image);
        Assert.True(
            matched,
            "The decoded Gen5 ABL (" + image.Length + " bytes) does not satisfy MatchesArm64Pe, so the "
                + "existing strict GetVariable/gzip ARM64 capacity chain cannot be reused for Gen5.");
    }

    /// <summary>
    /// The Gen5 pair must decode through the container reader to the reviewed 256 MiB Kernel-region window
    /// and a PE image. Expected red while the C780 FDT node is rejected.
    /// </summary>
    [G5LoaderFixtureFact]
    public void Gen5KernelRegionDecodesReviewedWindow()
    {
        byte[] abl = LoadAbl();
        byte[] xbl = LoadXblConfig();

        (bool decoded, byte[] pe, long windowBytes) = TryDecodeContainersPair(abl, xbl);
        Assert.True(
            decoded,
            "TryDecodeContainers must accept the mounted Gen5 loader pair ("
                + AblName + ", " + XblConfigName + "); the current reader rejects the C780 FDT node.");

        Assert.Equal(ExpectedKernelRegionWindowBytes, windowBytes);
        Assert.True(
            pe.Length >= 2 && pe[0] == (byte)'M' && pe[1] == (byte)'Z',
            "TryDecodeContainers reported success for the Gen5 pair but produced a "
                + pe.Length + "-byte image that is not an MZ executable.");
    }

    /// <summary>
    /// The Gen5 pair must also be recognized, with evidence that describes the capacity as conditional and
    /// static. The evidence is prose, not a proof: this fact never claims the capacity was exercised at
    /// runtime on hardware. Expected red while the C780 FDT node is rejected.
    /// </summary>
    [G5LoaderFixtureFact]
    public void Gen5PairRecognizesCapacity()
    {
        byte[] abl = LoadAbl();
        byte[] xbl = LoadXblConfig();

        (bool recognized, string evidence) = TryRecognizePair(abl, xbl);
        Assert.True(
            recognized,
            "TryRecognize must accept the mounted Gen5 loader pair ("
                + AblName + ", " + XblConfigName + "); the current reader rejects the C780 FDT node.");

        Assert.False(
            string.IsNullOrWhiteSpace(evidence),
            "TryRecognize accepted the Gen5 pair without producing capacity evidence.");
        Assert.Contains("conditional", evidence, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("static", evidence, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The owner-approved actual Gen5 capture pair, mounted read-only for the release run. The two files are
    /// verified by length and SHA-256 before any production method is allowed to see them, and they are only
    /// ever held in memory here: this fact never writes, prints or persists the bytes. The same pair must
    /// decode to the reviewed 256 MiB window, produce an MZ image that the strict ARM64 matcher accepts, and
    /// be recognized.
    /// </summary>
    [G5ActualLoaderFixtureFact]
    public void ActualGen5PairDecodesRecognizesAndMatchesArm64()
    {
        byte[] abl = ReadVerifiedFixture(
            ActualFixtureRootVariable, ActualAblName, ExpectedActualAblLength, ExpectedActualAblSha256);
        byte[] xbl = ReadVerifiedFixture(
            ActualFixtureRootVariable,
            ActualXblConfigName,
            ExpectedActualXblLength,
            ExpectedActualXblSha256);

        (bool decoded, byte[] pe, long windowBytes) = TryDecodeContainersPair(abl, xbl);
        Assert.True(
            decoded,
            "TryDecodeContainers must accept the actual Gen5 loader pair ("
                + ActualAblName + ", " + ActualXblConfigName + ").");
        Assert.True(
            windowBytes == ExpectedKernelRegionWindowBytes,
            "the actual Gen5 pair decoded a " + windowBytes + "-byte Kernel region, but the reviewed window "
                + "is " + ExpectedKernelRegionWindowBytes + " bytes.");
        Assert.True(
            pe.Length >= 2 && pe[0] == (byte)'M' && pe[1] == (byte)'Z',
            "TryDecodeContainers reported success for the actual Gen5 pair but produced a " + pe.Length
                + "-byte image that is not an MZ executable.");
        Assert.True(
            MatchArm64Pe(pe),
            "the actual Gen5 pair decoded to a " + pe.Length
                + "-byte PE image that does not satisfy MatchesArm64Pe.");

        var (recognized, _) = TryRecognizePair(abl, xbl);
        Assert.True(
            recognized,
            "TryRecognize must accept the actual Gen5 loader pair ("
                + ActualAblName + ", " + ActualXblConfigName + ").");
    }

    /// <summary>
    /// The Kernel-region reader must be bound to the exact (reg base, FDT node address, reg size) tuple, not
    /// to a disjunction of independent signals. Each case changes exactly one of the three reviewed fields
    /// and leaves the other two pinned, so a reader that is satisfied by any one of them — or by any two —
    /// would still accept a case and fail here. A rejection must hold for both the decoder and the
    /// recognizer.
    /// </summary>
    [G5LoaderFixtureTheory]
    [InlineData("only the reg base moves", 0xA8000000L, 0x10000000L, "memory@C7800000")]
    [InlineData("only the FDT node moves", 0xC7800000L, 0x10000000L, "memory@A8000000")]
    [InlineData("only the reg size shrinks", 0xC7800000L, 0x0FFFF000L, "memory@C7800000")]
    public void Gen5XblKernelRegionMutationBreaksPair(
        string mutation, long regBase, long regSize, string nodeText)
    {
        byte[] original = LoadXblConfig();

        AssertSingleOccurrence(
            original, BigEndianReg(PinnedRegBase, PinnedRegSize), XblRegOffset, "the Kernel reg property");
        AssertSingleOccurrence(
            original, AsciiZ(PinnedNodeText), XblNodeOffset, "the Kernel FDT node name");
        Assert.Equal((ulong)PinnedRegBase, ReadUInt64BigEndian(original, XblRegOffset));
        Assert.Equal((ulong)PinnedRegSize, ReadUInt64BigEndian(original, XblRegOffset + 8));

        int deviations = 0;
        if ((uint)regBase != PinnedRegBase)
        {
            deviations++;
        }

        if ((uint)regSize != PinnedRegSize)
        {
            deviations++;
        }

        if (!string.Equals(nodeText, PinnedNodeText, StringComparison.Ordinal))
        {
            deviations++;
        }

        Assert.True(
            deviations == 1,
            mutation + " must change exactly one reviewed Kernel-region field, but it changes " + deviations
                + "; the sibling fields have to stay pinned for the case to isolate anything.");
        Assert.True(
            nodeText.Length == PinnedNodeText.Length,
            mutation + " must keep the FDT node name at its reviewed byte length, otherwise the case would "
                + "move surrounding bytes instead of just the address.");

        byte[] mutated = (byte[])original.Clone();
        WriteUInt64BigEndian(mutated, XblRegOffset, (uint)regBase);
        WriteUInt64BigEndian(mutated, XblRegOffset + 8, (uint)regSize);
        byte[] node = AsciiZ(nodeText);
        Array.Copy(node, 0, mutated, XblNodeOffset, node.Length);

        byte[] abl = LoadAbl();
        var (decoded, _, _) = TryDecodeContainersPair(abl, mutated);
        Assert.False(
            decoded,
            mutation + " must make TryDecodeContainers reject the pair; accepting it would mean the "
                + "Kernel-region lookup is satisfied without the exact base/address/size tuple.");

        var (recognized, _) = TryRecognizePair(abl, mutated);
        Assert.False(
            recognized,
            mutation + " must make TryRecognize reject the pair; accepting it would mean the capacity is "
                + "recognized from a looser signal than the exact base/address/size tuple.");
    }

    /// <summary>
    /// The strict ARM64 matcher must survive on the reviewed instruction path only: each case rewrites one
    /// 32-bit word that the loader analysis identified as load-bearing, and the matcher has to reject the
    /// result. RVAs and file offsets coincide in the raw-backed .text section (offset 0x1000, size 0x62000),
    /// so the addresses below are directly patchable in the decoded image.
    /// </summary>
    [G5LoaderFixtureTheory]
    [InlineData("the first actual GetVariable BLR is removed", 0xB444L, 0xD63F0100L, 0xD503201FL)]
    [InlineData("the dual-success CBZ is inverted", 0xB47CL, 0xB4000348L, 0xB5000348L)]
    [InlineData("the page-alignment arithmetic is broken", 0xB644L, 0x4B0D03EBL, 0xD503201FL)]
    [InlineData("the avail_out producer reads the wrong room register", 0xB870L, 0xB9002019L, 0xB9002018L)]
    [InlineData("the inline inflate consumer reads field 24 instead of 20", 0xB9A8L, 0xB940212CL, 0xB940252CL)]
    [InlineData("the vendor ramdisk source offset is changed", 0xB53CL, 0xB9401928L, 0xB9401528L)]
    [InlineData("the description stream pointer is clobbered after the internal allocation", 0xB8ACL, 0xAA0003F9L, 0xAA0003FAL)]
    public void Gen5AblCriticalPeMutationBreaksArm64Match(
        string mutation, long offset, long original, long mutatedWord)
    {
        byte[] abl = LoadAbl();
        byte[] pe = DecodeBoundedImage(abl);

        uint at = (uint)offset;
        AssertInSection(PeTextOffset, PeTextSize, at, 4, ".text");
        Assert.Equal((uint)original, ReadUInt32Le(pe, at));
        Assert.True(
            (uint)original != (uint)mutatedWord,
            mutation + " is not a mutation: the replacement word equals the reviewed original.");

        byte[] mutated = (byte[])pe.Clone();
        WriteUInt32Le(mutated, at, (uint)mutatedWord);
        Assert.Equal((uint)mutatedWord, ReadUInt32Le(mutated, at));

        Assert.False(
            MatchArm64Pe(mutated),
            "MatchesArm64Pe still accepts the decoded Gen5 ABL after " + mutation + " (offset 0x"
                + Convert.ToString(at, 16) + "), so that word is not part of the reviewed ARM64 proof.");
    }

    /// <summary>
    /// Positive control for the mutations above: the two reviewed name literals are moved from .text to the
    /// end of .data and the x0 loads that reference them are retargeted with an independently written ARM64
    /// encoder. The matcher must still accept the image, which is only possible if it follows the decoded
    /// instructions rather than whitelisting the original code bytes, hashes or string positions. No ELF is
    /// repacked and no mutated firmware is run: the proof is entirely inside the decoded PE.
    /// </summary>
    [G5LoaderFixtureFact]
    public void Gen5AblNameRelocationKeepsArm64Match()
    {
        byte[] abl = LoadAbl();
        byte[] pe = DecodeBoundedImage(abl);
        Assert.True(
            pe.Length >= 2 && pe[0] == (byte)'M' && pe[1] == (byte)'Z',
            "the Gen5 ABL did not decode to an MZ executable (length " + pe.Length + ").");

        AssertInSection(PeTextOffset, PeTextSize, KernelBaseNameOffset, 2, ".text");
        AssertInSection(PeTextOffset, PeTextSize, KernelSizeNameOffset, 2, ".text");
        AssertInSection(PeTextOffset, PeTextSize, KernelBaseLoadOffset, 8, ".text");
        AssertInSection(PeTextOffset, PeTextSize, KernelSizeLoadOffset, 8, ".text");
        AssertInSection(PeDataOffset, PeDataSize, RelocatedKernelBaseOffset, 4, ".data");
        AssertInSection(PeDataOffset, PeDataSize, RelocatedKernelSizeOffset, 4, ".data");

        byte[] baseName = ReadUtf16Z(pe, KernelBaseNameOffset, PeTextOffset + PeTextSize);
        byte[] sizeName = ReadUtf16Z(pe, KernelSizeNameOffset, PeTextOffset + PeTextSize);
        AssertPrintableUtf16(baseName, "the Kernel patch-base name");
        AssertPrintableUtf16(sizeName, "the Kernel size name");
        Assert.True(
            KernelBaseNameOffset + baseName.Length <= KernelSizeNameOffset,
            "the two reviewed name literals overlap in .text, so erasing the first would destroy the second.");
        Assert.True(
            RelocatedKernelBaseOffset + baseName.Length <= RelocatedKernelSizeOffset,
            "the relocated names would overlap at .data 0x"
                + Convert.ToString(RelocatedKernelBaseOffset, 16) + "/0x"
                + Convert.ToString(RelocatedKernelSizeOffset, 16) + ".");
        Assert.True(
            RelocatedKernelSizeOffset + sizeName.Length <= PeDataOffset + PeDataSize,
            "the relocated size name does not fit at the end of the raw-backed .data window.");

        // Decode both load pairs before touching anything: this proves the reviewed offsets really address
        // these literals, so the patch below retargets those exact references and nothing else.
        AssertLoadsAddress(pe, KernelBaseLoadOffset, KernelBaseNameOffset);
        AssertLoadsAddress(pe, KernelSizeLoadOffset, KernelSizeNameOffset);

        byte[] relocated = (byte[])pe.Clone();
        Array.Clear(relocated, (int)KernelBaseNameOffset, baseName.Length);
        Array.Clear(relocated, (int)KernelSizeNameOffset, sizeName.Length);
        Array.Copy(baseName, 0, relocated, (int)RelocatedKernelBaseOffset, baseName.Length);
        Array.Copy(sizeName, 0, relocated, (int)RelocatedKernelSizeOffset, sizeName.Length);

        WriteUInt32Le(
            relocated, KernelBaseLoadOffset, EncodeAdrp(KernelBaseLoadOffset, RelocatedKernelBaseOffset, 0));
        WriteUInt32Le(
            relocated, KernelBaseLoadOffset + 4u, EncodeAddImm(RelocatedKernelBaseOffset & 0xFFFu));
        WriteUInt32Le(
            relocated, KernelSizeLoadOffset, EncodeAdrp(KernelSizeLoadOffset, RelocatedKernelSizeOffset, 0));
        WriteUInt32Le(
            relocated, KernelSizeLoadOffset + 4u, EncodeAddImm(RelocatedKernelSizeOffset & 0xFFFu));

        AssertLoadsAddress(relocated, KernelBaseLoadOffset, RelocatedKernelBaseOffset);
        AssertLoadsAddress(relocated, KernelSizeLoadOffset, RelocatedKernelSizeOffset);

        Assert.True(
            MatchArm64Pe(relocated),
            "MatchesArm64Pe rejects the decoded Gen5 ABL after both name literals were moved to .data 0x"
                + Convert.ToString(RelocatedKernelBaseOffset, 16) + "/0x"
                + Convert.ToString(RelocatedKernelSizeOffset, 16)
                + " and their x0 loads were retargeted, so the matcher still depends on the original string "
                + "or code positions rather than on the decoded instruction stream.");
    }

    // ------------------------------------------------------------- fixture claims

    /// <summary>
    /// The single discovery-time decision shared by every gated attribute: only an unset variable may skip,
    /// and the reason names the exact captures the run would have needed.
    /// </summary>
    internal static string? UnmountedSkipReason(string rootVariable, params string[] fileNames)
    {
        if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(rootVariable)))
        {
            return null;
        }

        return rootVariable + " is not set, so the external Gen5 loader captures ("
            + string.Join(", ", fileNames) + ") are not mounted for this run.";
    }

    private static byte[] LoadAbl() =>
        ReadVerifiedFixture(
            FixtureRootVariable, AblName, ExpectedAblLength, ExpectedAblSha256);

    private static byte[] LoadXblConfig() =>
        ReadVerifiedFixture(
            FixtureRootVariable, XblConfigName, ExpectedXblLength, ExpectedXblSha256);

    /// <summary>
    /// Reads a mounted capture and refuses it unless it is byte-for-byte the reviewed capture. A set
    /// fixture root with a missing or altered file fails: only an unset root skips, and that decision was
    /// already taken at discovery. The root variable is explicit so the public and the owner-approved
    /// captures share this verification instead of duplicating it.
    /// </summary>
    private static byte[] ReadVerifiedFixture(
        string rootVariable, string fileName, int expectedLength, string expectedSha256)
    {
        byte[] bytes = File.ReadAllBytes(RequireMountedFixture(rootVariable, fileName));
        Assert.True(
            bytes.Length == expectedLength,
            "the mounted Gen5 capture " + fileName + " is " + bytes.Length
                + " bytes, but the reviewed capture is " + expectedLength + " bytes.");
        Assert.Equal(expectedSha256, Sha256Hex(bytes));
        return bytes;
    }

    private static string RequireMountedFixture(string rootVariable, string fileName)
    {
        string? root = Environment.GetEnvironmentVariable(rootVariable);
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new InvalidOperationException(
                rootVariable + " is not set, so the Gen5 capture " + fileName
                    + " is not mounted; this test should have been skipped at discovery.");
        }

        string path = Path.Combine(root, fileName);
        if (!File.Exists(path))
        {
            throw new FileNotFoundException(
                "the external Gen5 loader capture is missing from " + rootVariable + ": " + fileName,
                path);
        }

        return path;
    }

    private static string Sha256Hex(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes));

    // ------------------------------------------------------------- PE byte access

    /// <summary>
    /// Refuses an offset that would be patched outside the raw-backed section the analysis recorded. RVAs
    /// equal file offsets in these sections, which is why the metadata above may be used directly.
    /// </summary>
    private static void AssertInSection(
        uint sectionStart, uint sectionSize, uint offset, int length, string sectionName)
    {
        Assert.True(
            offset >= sectionStart && (ulong)offset + (ulong)length <= (ulong)sectionStart + sectionSize,
            "the reviewed " + sectionName + " offset 0x" + Convert.ToString(offset, 16) + " (length "
                + length + ") is outside the raw-backed " + sectionName + " window starting at 0x"
                + Convert.ToString(sectionStart, 16) + " with size 0x"
                + Convert.ToString(sectionSize, 16) + ".");
    }

    private static uint ReadUInt32Le(byte[] image, uint offset)
    {
        int at = (int)offset;
        return (uint)(image[at] | (image[at + 1] << 8) | (image[at + 2] << 16) | (image[at + 3] << 24));
    }

    private static void WriteUInt32Le(byte[] image, uint offset, uint value)
    {
        int at = (int)offset;
        image[at] = (byte)value;
        image[at + 1] = (byte)(value >> 8);
        image[at + 2] = (byte)(value >> 16);
        image[at + 3] = (byte)(value >> 24);
    }

    private static ulong ReadUInt64BigEndian(byte[] image, int offset)
    {
        ulong value = 0;
        for (int i = 0; i < 8; i++)
        {
            value = (value << 8) | image[offset + i];
        }

        return value;
    }

    private static void WriteUInt64BigEndian(byte[] image, int offset, ulong value)
    {
        for (int i = 7; i >= 0; i--)
        {
            image[offset + i] = (byte)value;
            value >>= 8;
        }
    }

    private static byte[] BigEndianReg(uint baseAddress, uint size)
    {
        byte[] bytes = new byte[XblRegLength];
        WriteUInt64BigEndian(bytes, 0, baseAddress);
        WriteUInt64BigEndian(bytes, 8, size);
        return bytes;
    }

    private static byte[] AsciiZ(string text)
    {
        byte[] bytes = new byte[text.Length + 1];
        for (int i = 0; i < text.Length; i++)
        {
            bytes[i] = (byte)text[i];
        }

        return bytes;
    }

    /// <summary>
    /// Requires the pinned byte pattern to exist exactly once, at the reviewed offset, so a mutation at that
    /// offset provably edits the only copy of the value the reader could be looking at.
    /// </summary>
    private static void AssertSingleOccurrence(
        byte[] haystack, byte[] needle, int expectedOffset, string what)
    {
        int first = -1;
        int count = 0;
        for (int i = 0; i + needle.Length <= haystack.Length; i++)
        {
            if (haystack.AsSpan(i, needle.Length).SequenceEqual(needle))
            {
                count++;
                if (first < 0)
                {
                    first = i;
                }
            }
        }

        Assert.True(
            count == 1,
            "the public XBL capture must contain " + what + " exactly once, but it appears " + count
                + " times.");
        Assert.Equal(expectedOffset, first);
    }

    /// <summary>
    /// Reads one UTF-16LE, NUL-terminated literal and returns its bytes including the terminator.
    /// </summary>
    private static byte[] ReadUtf16Z(byte[] image, uint offset, uint limit)
    {
        int start = (int)offset;
        int end = start;
        while (end + 1 < limit)
        {
            if (image[end] == 0 && image[end + 1] == 0)
            {
                end += 2;
                break;
            }

            end += 2;
        }

        Assert.True(
            end - start >= 2 && image[end - 2] == 0 && image[end - 1] == 0,
            "the reviewed name at offset 0x" + Convert.ToString(offset, 16)
                + " is not a NUL-terminated UTF-16 literal inside the raw-backed window.");
        byte[] text = new byte[end - start];
        Array.Copy(image, start, text, 0, text.Length);
        return text;
    }

    private static void AssertPrintableUtf16(byte[] text, string what)
    {
        Assert.True(
            text.Length > 2,
            what + " must not be empty (" + text.Length + " bytes including the terminator).");
        Assert.Equal(0, (int)text[text.Length - 2]);
        Assert.Equal(0, (int)text[text.Length - 1]);

        for (int i = 0; i + 1 < text.Length - 2; i += 2)
        {
            char c = (char)(text[i] | (text[i + 1] << 8));
            Assert.True(
                c >= 0x20 && c < 0x7F,
                what + " must be printable ASCII, but byte pair " + (i / 2) + " is U+"
                    + Convert.ToString((int)c, 16) + ".");
        }
    }

    // ------------------------------------------------------------- ARM64 encoder/decoder

    /// <summary>
    /// Standard ARM64 ADRP encoder, written here from the architecture encoding and deliberately not shared
    /// with the production reader: sf=1, immlo in bits 30..29, immhi in bits 23..5, Rd in bits 4..0.
    /// </summary>
    private static uint EncodeAdrp(uint pc, uint target, int reg)
    {
        if ((pc & 0x3u) != 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(pc), "the ADRP site must be a 4-byte aligned instruction.");
        }

        if (reg < 0 || reg > 31)
        {
            throw new ArgumentOutOfRangeException(nameof(reg), "ADRP Rd must be x0..x31.");
        }

        long deltaPages =
            ((long)(target & 0xFFFFF000u) - (long)(pc & 0xFFFFF000u)) >> 12;
        if (deltaPages < -(1L << 20) || deltaPages > (1L << 20) - 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(target), "the ADRP page delta does not fit in 21 signed bits.");
        }

        uint immlo = (uint)(deltaPages & 0x3L);
        uint immhi = (uint)((deltaPages >> 2) & 0x7FFFFL);
        return 0x90000000u | (immlo << 29) | (immhi << 5) | (uint)reg;
    }

    /// <summary>Standard ARM64 <c>ADD x0, x0, #imm12</c>: opcode 0x91000000, Rd=Rn=0.</summary>
    private static uint EncodeAddImm(uint offsetInPage)
    {
        if (offsetInPage > 0xFFFu)
        {
            throw new ArgumentOutOfRangeException(
                nameof(offsetInPage), "the ADD immediate must fit in 12 bits.");
        }

        return 0x91000000u | (offsetInPage << 10);
    }

    private static uint AdrpTargetPage(uint pc, uint insn)
    {
        Assert.Equal(0x90000000u, insn & 0x9F000000u);
        long immlo = (insn >> 29) & 0x3u;
        long immhi = (insn >> 5) & 0x7FFFFu;
        long pages = (immhi << 2) | immlo;
        if ((pages & (1L << 20)) != 0)
        {
            pages -= 1L << 21;
        }

        return (uint)((long)(pc & 0xFFFFF000u) + (pages << 12));
    }

    /// <summary>
    /// Requires the two instructions at <paramref name="loadOffset"/> to materialize exactly
    /// <paramref name="expectedAddress"/> in x0, using only the architectural encoding.
    /// </summary>
    private static void AssertLoadsAddress(byte[] image, uint loadOffset, uint expectedAddress)
    {
        uint adrp = ReadUInt32Le(image, loadOffset);
        Assert.Equal(0x90000000u, adrp & 0x9F000000u);
        Assert.Equal(0, (int)(adrp & 0x1Fu));

        uint add = ReadUInt32Le(image, loadOffset + 4u);
        Assert.Equal(0x91000000u, add & 0xFFC00000u);
        Assert.Equal(0, (int)(add & 0x1Fu));
        Assert.Equal(0, (int)((add >> 5) & 0x1Fu));

        uint target = AdrpTargetPage(loadOffset, adrp) | ((add >> 10) & 0xFFFu);
        Assert.True(
            target == expectedAddress,
            "the x0 load at 0x" + Convert.ToString(loadOffset, 16)
                + " materializes 0x" + Convert.ToString(target, 16) + ", not the reviewed name at 0x"
                + Convert.ToString(expectedAddress, 16) + ".");
    }

    // ------------------------------------------------------------- reflection bridges

    /// <summary>
    /// One reflection bridge to the private bounded-image decode. Each lookup names the exact parameter
    /// types so an unrelated overload can never be selected by accident.
    /// </summary>
    private static byte[] DecodeBoundedImage(byte[] abl)
    {
        MethodInfo? decode = LoaderType().GetMethod(
            "ContainerTryDecodeBoundedImage",
            BindingFlags.NonPublic | BindingFlags.Static,
            binder: null,
            types: new[]
            {
                typeof(byte[]),
                typeof(CancellationToken),
                typeof(byte[]).MakeByRefType(),
            },
            modifiers: null);
        Assert.NotNull(decode);

        object?[] arguments = { abl, CancellationToken.None, null };
        object? decoded = decode!.Invoke(null, arguments);
        Assert.True(
            decoded is bool success && success,
            "ContainerTryDecodeBoundedImage must decode the Gen5 ABL (" + abl.Length + " bytes).");
        return (byte[])arguments[2]!;
    }

    private static bool MatchArm64Pe(byte[] pe)
    {
        MethodInfo? match = LoaderType().GetMethod(
            "MatchesArm64Pe",
            BindingFlags.NonPublic | BindingFlags.Static,
            binder: null,
            types: new[] { typeof(byte[]), typeof(CancellationToken) },
            modifiers: null);
        Assert.NotNull(match);

        object? result = match!.Invoke(null, new object?[] { pe, CancellationToken.None });
        return result is bool matched && matched;
    }

    private static (bool Decoded, byte[] Pe, long WindowBytes) TryDecodeContainersPair(
        byte[] abl, byte[] xbl)
    {
        MethodInfo? decode = LoaderType().GetMethod(
            "TryDecodeContainers",
            BindingFlags.NonPublic | BindingFlags.Static,
            binder: null,
            types: new[]
            {
                typeof(byte[]),
                typeof(byte[]),
                typeof(CancellationToken),
                typeof(byte[]).MakeByRefType(),
                typeof(long).MakeByRefType(),
            },
            modifiers: null);
        Assert.NotNull(decode);

        object?[] arguments = { abl, xbl, CancellationToken.None, null, 0L };
        object? decoded = decode!.Invoke(null, arguments);
        bool success = decoded is bool value && value;
        return (success, (byte[])arguments[3]!, (long)arguments[4]!);
    }

    private static (bool Recognized, string Evidence) TryRecognizePair(byte[] abl, byte[] xbl)
    {
        MethodInfo? recognize = LoaderType().GetMethod(
            "TryRecognize",
            BindingFlags.NonPublic | BindingFlags.Static,
            binder: null,
            types: new[]
            {
                typeof(byte[]),
                typeof(byte[]),
                typeof(CancellationToken),
                typeof(string).MakeByRefType(),
            },
            modifiers: null);
        Assert.NotNull(recognize);

        object?[] arguments = { abl, xbl, CancellationToken.None, null };
        object? recognized = recognize!.Invoke(null, arguments);
        bool success = recognized is bool value && value;
        return (success, arguments[3] as string ?? string.Empty);
    }

    private static Type LoaderType() =>
        typeof(InternalSlotMaterialReader).Assembly.GetType(
            "FreedomInstaller.Core.InternalSlotLoaderStructure", throwOnError: true)!;
}
