using System;
using System.Buffers.Binary;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Discovery-level gate for the loader-structure regressions below. They are meaningless without the four
/// real loader captures (no loader bytes are committed), so xunit must report them as skipped while the
/// directory is not mounted. The decision is taken at discovery time from the environment; once the
/// variable is set a missing file or an unusable capture fails the run instead of skipping it.
/// </summary>
public sealed class Lb01LoaderFixtureFactAttribute : FactAttribute
{
    public Lb01LoaderFixtureFactAttribute()
    {
        if (string.IsNullOrWhiteSpace(
                Environment.GetEnvironmentVariable(
                    InternalSlotLoaderStructureTests.FixtureRootVariable)))
        {
            Skip = InternalSlotLoaderStructureTests.FixtureRootVariable
                + " is not set, so the external loader captures ("
                + InternalSlotLoaderStructureTests.AblAName + ", "
                + InternalSlotLoaderStructureTests.AblBName + ", "
                + InternalSlotLoaderStructureTests.XblConfigAName + ", "
                + InternalSlotLoaderStructureTests.XblConfigBName
                + ") are not mounted for this run.";
        }
    }
}

/// <summary>
/// Regression over the real per-slot loader files (<c>abl_a.img</c>, <c>abl_b.img</c>,
/// <c>xbl_config_a.img</c>, <c>xbl_config_b.img</c>), mounted out of tree by the release run. Every test
/// claims the capture bytes as they are read at runtime — no capture hash or loader byte is embedded here —
/// and pairs them with tiny synthetic Android v4 boot/vendor/init material whose header sizes are backed by
/// the full padding/data length so the reader's existing range checks actually run. All synthetic
/// material lives in an explicitly configured test work root.
/// </summary>
public sealed class InternalSlotLoaderStructureTests
{
    /// <summary>Directory holding the four mounted loader captures.</summary>
    public const string FixtureRootVariable = "LB01_LOADER_FIXTURE_ROOT";

    public const string AblAName = "abl_a.img";
    public const string AblBName = "abl_b.img";
    public const string XblConfigAName = "xbl_config_a.img";
    public const string XblConfigBName = "xbl_config_b.img";

    private const string ExpectedProfile = "tb322fc-abl-kernel-region-derived";
    private const long ExpectedASlotBudget = 254787584;
    private const long ExpectedBSlotBudget = 254783488;
    private const long ConservativeFallbackBudget = 134217728;

    // Same-slot values are independent constants: they are not derived from one another here.
    private const long ASlotVendorRamdiskSize = 8556941;
    private const long BSlotVendorRamdiskSize = 8560566;
    private const long InitRamdiskSize = 2457778;

    // Independent fixture mutation point: the valid Kernel reg property (16 big-endian bytes) inside the
    // real XBL. The size cell is the uint64 at +8. This is a property of the fixture, not a production
    // constant, and nothing below asks the reader to know this offset.
    private const int XblKernelRegionCellOffset = 0x1F664;
    private const ulong XblKernelRegionSize = 0x10000000;
    private const ulong XblKernelRegionShrunkSize = 0x0FFFF000;

    // Independent fixture RVAs: p anchors the same-function prefix chain, z the detector helper.
    // Neither value is a production constant; the tests map them through the PE section table.
    private const long PrefixAnchorRva = 0x7498;
    private const long DetectorAnchorRva = 0x3F9B4;
    private const uint Arm64Nop = 0xD503201F;

    private const string UnmutatedMatchMessage =
        "the unmodified A-slot capture must match the reviewed structure before any mutation.";

    private const int Page = 4096;
    private const int BootHeaderSize = 1584;
    private const int VendorHeaderSize = 2128;
    private const uint AndroidBootVersion = 4;
    private const uint VendorBootVersion = 4;

    private static readonly byte[] Arm64Magic = { (byte)'A', (byte)'R', (byte)'M', 0x64 };

    // ------------------------------------------------------------------ tests

    [Lb01LoaderFixtureFact]
    public async Task ASlotLoaderStructureBudgetMatchesReviewedProfile()
    {
        using TestWorkspace work = new TestWorkspace();

        VerifiedEdlFile abl = ClaimMountedFixture(AblAName);
        VerifiedEdlFile xblConfig = ClaimMountedFixture(XblConfigAName);
        SlotMaterialInputs synthetic = WriteSyntheticSlotInputs(
            work, "a", ASlotVendorRamdiskSize);

        InternalSlotMaterial material = await InternalSlotMaterialReader.AnalyzeAsync(
            "a", synthetic.Boot, synthetic.Vendor, synthetic.Init, abl, xblConfig);

        InternalSlotLoaderBudget budget = material.LoaderBudget;
        Assert.True(
            budget.KnownLoaderMatch,
            "A-slot ABL/xbl_config must match the reviewed loader structure. Evidence: "
                + budget.Evidence);
        Assert.Equal(ExpectedProfile, budget.Profile);
        Assert.Equal(ExpectedASlotBudget, budget.MaxRawBytes);
        AssertEvidenceKeepsRuntimeUnverified(budget);

        Assert.Equal(abl.Sha256, material.SourceSha256["abl"]);
        Assert.Equal(xblConfig.Sha256, material.SourceSha256["xbl_config"]);
        Assert.Equal(0L, material.BootRamdiskSize);
        Assert.Equal(ASlotVendorRamdiskSize, material.VendorRamdiskSize);
        Assert.Equal(InitRamdiskSize, material.InitRamdiskSize);
    }

    [Lb01LoaderFixtureFact]
    public async Task BSlotLoaderStructureBudgetMatchesReviewedProfile()
    {
        using TestWorkspace work = new TestWorkspace();

        VerifiedEdlFile abl = ClaimMountedFixture(AblBName);
        VerifiedEdlFile xblConfig = ClaimMountedFixture(XblConfigBName);
        SlotMaterialInputs synthetic = WriteSyntheticSlotInputs(
            work, "b", BSlotVendorRamdiskSize);

        InternalSlotMaterial material = await InternalSlotMaterialReader.AnalyzeAsync(
            "b", synthetic.Boot, synthetic.Vendor, synthetic.Init, abl, xblConfig);

        InternalSlotLoaderBudget budget = material.LoaderBudget;
        Assert.True(
            budget.KnownLoaderMatch,
            "B-slot ABL/xbl_config must match the reviewed loader structure. Evidence: "
                + budget.Evidence);
        Assert.Equal(ExpectedProfile, budget.Profile);
        Assert.Equal(ExpectedBSlotBudget, budget.MaxRawBytes);
        AssertEvidenceKeepsRuntimeUnverified(budget);

        Assert.Equal(abl.Sha256, material.SourceSha256["abl"]);
        Assert.Equal(xblConfig.Sha256, material.SourceSha256["xbl_config"]);
        Assert.Equal(0L, material.BootRamdiskSize);
        Assert.Equal(BSlotVendorRamdiskSize, material.VendorRamdiskSize);
        Assert.Equal(InitRamdiskSize, material.InitRamdiskSize);
    }

    [Lb01LoaderFixtureFact]
    public async Task ASlotAblPaddingByteChangeKeepsTheStructuralBudget()
    {
        using TestWorkspace work = new TestWorkspace();

        byte[] original = File.ReadAllBytes(RequireMountedFixture(AblAName));
        byte[] mutated = (byte[])original.Clone();

        // One byte inside the outer ABL's last 256-byte padding; the ELF LOAD/FV bytes stay untouched.
        int paddingIndex = mutated.Length - 1;
        mutated[paddingIndex] ^= 0xFF;

        string originalSha = Sha256Hex(original);
        string mutatedSha = Sha256Hex(mutated);
        Assert.NotEqual(originalSha, mutatedSha);
        Assert.Equal(1, CountDifferences(original, mutated));

        VerifiedEdlFile abl = work.Claim(mutated, "abl_a_padding_changed.img");
        Assert.Equal(mutatedSha, abl.Sha256);
        VerifiedEdlFile xblConfig = ClaimMountedFixture(XblConfigAName);
        SlotMaterialInputs synthetic = WriteSyntheticSlotInputs(
            work, "a", ASlotVendorRamdiskSize);

        InternalSlotMaterial material = await InternalSlotMaterialReader.AnalyzeAsync(
            "a", synthetic.Boot, synthetic.Vendor, synthetic.Init, abl, xblConfig);

        InternalSlotLoaderBudget budget = material.LoaderBudget;
        Assert.True(
            budget.KnownLoaderMatch,
            "A padding-only ABL change must keep the structurally derived loader match. Evidence: "
                + budget.Evidence);
        Assert.Equal(ExpectedProfile, budget.Profile);
        Assert.Equal(ExpectedASlotBudget, budget.MaxRawBytes);
        Assert.Equal(mutatedSha, material.SourceSha256["abl"]);
        Assert.NotEqual(originalSha, material.SourceSha256["abl"]);
    }

    [Lb01LoaderFixtureFact]
    public async Task ASlotXblKernelRegionShrinkFallsBackToConservativeBudget()
    {
        using TestWorkspace work = new TestWorkspace();

        VerifiedEdlFile abl = ClaimMountedFixture(AblAName);
        byte[] xblBytes = File.ReadAllBytes(RequireMountedFixture(XblConfigAName));
        Assert.True(
            xblBytes.LongLength >= XblKernelRegionCellOffset + 16,
            "the mounted XBL is shorter than the independent Kernel reg mutation point");

        Span<byte> cell = xblBytes.AsSpan(XblKernelRegionCellOffset, 16);
        ulong originalSize = BinaryPrimitives.ReadUInt64BigEndian(cell.Slice(8, 8));
        Assert.Equal(XblKernelRegionSize, originalSize);

        BinaryPrimitives.WriteUInt64BigEndian(cell.Slice(8, 8), XblKernelRegionShrunkSize);
        Assert.Equal(
            XblKernelRegionShrunkSize,
            BinaryPrimitives.ReadUInt64BigEndian(cell.Slice(8, 8)));

        VerifiedEdlFile xblConfig = work.Claim(
            xblBytes, "xbl_config_a_kernel_region_shrunk.img");
        SlotMaterialInputs synthetic = WriteSyntheticSlotInputs(
            work, "a", ASlotVendorRamdiskSize);

        InternalSlotMaterial material = await InternalSlotMaterialReader.AnalyzeAsync(
            "a", synthetic.Boot, synthetic.Vendor, synthetic.Init, abl, xblConfig);

        InternalSlotLoaderBudget budget = material.LoaderBudget;
        Assert.False(
            budget.KnownLoaderMatch,
            "a shrunk Kernel node region must not keep the larger structural match. Evidence: "
                + budget.Evidence);
        Assert.Equal(ConservativeFallbackBudget, budget.MaxRawBytes);
        Assert.Equal(xblConfig.Sha256, material.SourceSha256["xbl_config"]);
    }

    [Lb01LoaderFixtureFact]
    public void ASlotContainersDecodeSupportedPeAndRegion()
    {
        (byte[] pe, long windowBytes) = DecodeMountedContainers(AblAName, XblConfigAName);

        Assert.Equal(268435456L, windowBytes);
        Assert.True(pe.Length >= 64, "the decoded supported PE is shorter than a DOS header");
        Assert.Equal((byte)'M', pe[0]);
        Assert.Equal((byte)'Z', pe[1]);

        // e_lfanew is read from this returned PE, so a prefixed child cannot borrow another offset base.
        int eLfanew = BinaryPrimitives.ReadInt32LittleEndian(pe.AsSpan(0x3C, 4));
        Assert.True(
            eLfanew > 0 && eLfanew <= pe.Length - 24,
            "the decoded PE e_lfanew must stay inside this returned PE: " + eLfanew);
        Assert.Equal(0x00004550u, BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(eLfanew, 4)));
        Assert.Equal(
            (ushort)0xAA64,
            BinaryPrimitives.ReadUInt16LittleEndian(pe.AsSpan(eLfanew + 4, 2)));
    }

    [Lb01LoaderFixtureFact]
    public void BSlotContainersDecodeSupportedPeAndRegion()
    {
        (byte[] pe, long windowBytes) = DecodeMountedContainers(AblBName, XblConfigBName);

        Assert.Equal(268435456L, windowBytes);
        Assert.True(pe.Length >= 64, "the decoded supported PE is shorter than a DOS header");
        Assert.Equal((byte)'M', pe[0]);
        Assert.Equal((byte)'Z', pe[1]);

        // e_lfanew is read from this returned PE, so a prefixed child cannot borrow another offset base.
        int eLfanew = BinaryPrimitives.ReadInt32LittleEndian(pe.AsSpan(0x3C, 4));
        Assert.True(
            eLfanew > 0 && eLfanew <= pe.Length - 24,
            "the decoded PE e_lfanew must stay inside this returned PE: " + eLfanew);
        Assert.Equal(0x00004550u, BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(eLfanew, 4)));
        Assert.Equal(
            (ushort)0xAA64,
            BinaryPrimitives.ReadUInt16LittleEndian(pe.AsSpan(eLfanew + 4, 2)));
    }

    // ------------------------------------------------- loader fixture mutations

    // Every negative below refuses to run on an already-broken expectation: the unmodified decoded
    // A-slot PE must match first, so none of these can pass vacuously.

    [Lb01LoaderFixtureFact]
    public void ASlotFirstGetVariableCallReplacementIsRejected()
    {
        (byte[] pe, _) = DecodeMountedContainers(AblAName, XblConfigAName);
        Assert.True(MatchDecodedPe(pe), UnmutatedMatchMessage);

        int call = MapRvaThroughPeSections(pe, PrefixAnchorRva + 0x14L, 4);
        uint original = BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(call, 4));
        Assert.Equal(0x94000000u, original & 0xFC000000u);

        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(call, 4), Arm64Nop);

        Assert.False(
            MatchDecodedPe(pe),
            "a NOP over the first GetVariable call must not keep the reviewed structure.");
    }

    [Lb01LoaderFixtureFact]
    public void ASlotDualStatusBranchInversionIsRejected()
    {
        (byte[] pe, _) = DecodeMountedContainers(AblAName, XblConfigAName);
        Assert.True(MatchDecodedPe(pe), UnmutatedMatchMessage);

        int branch = MapRvaThroughPeSections(pe, PrefixAnchorRva + 0x38L, 4);
        uint original = BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(branch, 4));
        Assert.Equal(0xB4000000u, original & 0xFF000000u);
        Assert.Equal(8u, original & 0x1Fu);

        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(branch, 4), original ^ 0x01000000u);
        Assert.Equal(
            0xB5000000u,
            BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(branch, 4)) & 0xFF000000u);

        Assert.False(
            MatchDecodedPe(pe),
            "inverting the dual-status CBZ into a CBNZ must not keep the reviewed structure.");
    }

    [Lb01LoaderFixtureFact]
    public void ASlotAvailOutStoreReplacementIsRejected()
    {
        (byte[] pe, _) = DecodeMountedContainers(AblAName, XblConfigAName);
        Assert.True(MatchDecodedPe(pe), UnmutatedMatchMessage);

        int store = MapRvaThroughPeSections(pe, DetectorAnchorRva + 0x78L, 4);
        uint original = BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(store, 4));

        // STR (immediate, unsigned offset): the reviewed word writes avail_out in either width.
        Assert.Equal(0x39000000u, original & 0x3B400000u);

        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(store, 4), Arm64Nop);

        Assert.False(
            MatchDecodedPe(pe),
            "a NOP over the avail_out store must not keep the reviewed structure.");
    }

    [Lb01LoaderFixtureFact]
    public void ASlotZlibOutputLengthRegisterReplacementIsRejected()
    {
        (byte[] pe, _) = DecodeMountedContainers(AblAName, XblConfigAName);
        Assert.True(MatchDecodedPe(pe), UnmutatedMatchMessage);

        // t+0x18 loads the zlib output length from the spilled slot into x2.
        int argument = MapRvaThroughPeSections(pe, 0x7968L, 4);
        uint original = BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(argument, 4));
        Assert.Equal(0xf9405fe2u, original);

        BinaryPrimitives.WriteUInt32LittleEndian(
            pe.AsSpan(argument, 4), (original & 0xFFFFFFE0u) | 7u);

        Assert.False(
            MatchDecodedPe(pe),
            "loading that slot into x7 instead of x2 must not keep the reviewed structure.");
    }

    [Lb01LoaderFixtureFact]
    public void ASlotRelocatedVariableNamesKeepTheStructuralMatch()
    {
        (byte[] pe, _) = DecodeMountedContainers(AblAName, XblConfigAName);
        Assert.True(MatchDecodedPe(pe), UnmutatedMatchMessage);

        int baseAdrp = MapRvaThroughPeSections(pe, PrefixAnchorRva, 8);
        int sizeAdrp = MapRvaThroughPeSections(pe, PrefixAnchorRva + 0x20L, 8);

        long oldBase = DecodeAddressPair(pe, PrefixAnchorRva, PrefixAnchorRva + 0x04L);
        long oldSize = DecodeAddressPair(pe, PrefixAnchorRva + 0x20L, PrefixAnchorRva + 0x24L);
        Assert.True(
            Arm64Utf16At(pe, oldBase, "KernelBaseAddr"),
            "the A-slot PE must first carry the KernelBaseAddr literal at its original address.");
        Assert.True(
            Arm64Utf16At(pe, oldSize, "KernelSize"),
            "the A-slot PE must first carry the KernelSize literal at its original address.");

        (long spanRva, int spanOffset) = FindZeroDataSpan(
            pe, 96, oldBase, 30, oldSize, 22);
        long newBase = spanRva;
        long newSize = spanRva + 48;

        WriteUtf16(pe, spanOffset, "KernelBaseAddr");
        WriteUtf16(pe, spanOffset + 48, "KernelSize");

        RetargetAddressPair(pe, baseAdrp, PrefixAnchorRva, newBase);
        RetargetAddressPair(pe, sizeAdrp, PrefixAnchorRva + 0x20L, newSize);

        Assert.Equal(newBase, DecodeAddressPair(pe, PrefixAnchorRva, PrefixAnchorRva + 0x04L));
        Assert.Equal(newSize, DecodeAddressPair(pe, PrefixAnchorRva + 0x20L, PrefixAnchorRva + 0x24L));

        EraseUtf16(pe, oldBase, "KernelBaseAddr");
        EraseUtf16(pe, oldSize, "KernelSize");

        Assert.True(
            MatchDecodedPe(pe),
            "relocating the two UTF16 variable-name literals must keep the structural match.");
    }

    [Lb01LoaderFixtureFact]
    public async Task ASlotDuplicateFdtXblFallsBackToTheConservativeBudget()
    {
        using TestWorkspace work = new TestWorkspace();

        VerifiedEdlFile abl = ClaimMountedFixture(AblAName);
        SlotMaterialInputs synthetic = WriteSyntheticSlotInputs(
            work, "a", ASlotVendorRamdiskSize);

        InternalSlotMaterial matched = await InternalSlotMaterialReader.AnalyzeAsync(
            "a", synthetic.Boot, synthetic.Vendor, synthetic.Init,
            abl, ClaimMountedFixture(XblConfigAName));
        Assert.True(
            matched.LoaderBudget.KnownLoaderMatch,
            "the unmodified A-slot pair must match before its FDT is duplicated. Evidence: "
                + matched.LoaderBudget.Evidence);

        byte[] xblBytes = File.ReadAllBytes(RequireMountedFixture(XblConfigAName));
        (int fdtOffset, int fdtSize) = FindFdtLoadPayload(xblBytes);
        byte[] fdt = new ReadOnlySpan<byte>(xblBytes, fdtOffset, fdtSize).ToArray();
        byte[] duplicated = BuildDuplicateFdtXbl(fdt);

        byte[] ablBytes = File.ReadAllBytes(RequireMountedFixture(AblAName));
        Assert.True(
            TryDecodeContainersFor(ablBytes, xblBytes),
            "the unmodified A-slot pair must decode before the duplicate-FDT image is judged.");
        Assert.False(
            TryDecodeContainersFor(ablBytes, duplicated),
            "two LOAD segments that both start with the same complete FDT must not decode.");

        VerifiedEdlFile claimed = work.Claim(duplicated, "xbl_config_a_duplicate_fdt.img");
        InternalSlotMaterial fallback = await InternalSlotMaterialReader.AnalyzeAsync(
            "a", synthetic.Boot, synthetic.Vendor, synthetic.Init, abl, claimed);

        Assert.False(fallback.LoaderBudget.KnownLoaderMatch);
        Assert.Equal(ConservativeFallbackBudget, fallback.LoaderBudget.MaxRawBytes);
        Assert.Equal(claimed.Sha256, fallback.SourceSha256["xbl_config"]);
    }

    // -------------------------------------------------------------- assertions

    private static void AssertEvidenceKeepsRuntimeUnverified(InternalSlotLoaderBudget budget)
    {
        string evidence = budget.Evidence;
        Assert.True(
            evidence.Contains("GetVariable", StringComparison.Ordinal),
            "evidence must keep naming the unverified runtime GetVariable path: " + evidence);
        Assert.True(
            evidence.Contains("unverified", StringComparison.Ordinal),
            "evidence must keep marking the runtime result as unverified: " + evidence);
        Assert.True(
            evidence.Contains("capacity", StringComparison.Ordinal),
            "evidence must keep marking the hardware capacity as unverified: " + evidence);
    }

    // ---------------------------------------------------------------- fixtures

    private sealed class SlotMaterialInputs
    {
        public SlotMaterialInputs(
            VerifiedEdlFile boot, VerifiedEdlFile vendor, VerifiedEdlFile init)
        {
            Boot = boot;
            Vendor = vendor;
            Init = init;
        }

        public VerifiedEdlFile Boot { get; }
        public VerifiedEdlFile Vendor { get; }
        public VerifiedEdlFile Init { get; }
    }

    private static SlotMaterialInputs WriteSyntheticSlotInputs(
        TestWorkspace work, string slot, long vendorRamdiskSize)
    {
        VerifiedEdlFile boot = work.Claim(
            BuildBootV4(BuildTinyArm64Image(), ramdiskSize: 0),
            "boot_" + slot + ".img");
        VerifiedEdlFile vendor = work.Claim(
            BuildVendorV4(vendorRamdiskSize),
            "vendor_boot_" + slot + ".img");
        VerifiedEdlFile init = work.Claim(
            BuildBootV4(Array.Empty<byte>(), ramdiskSize: (int)InitRamdiskSize),
            "init_boot_" + slot + ".img");
        return new SlotMaterialInputs(boot, vendor, init);
    }

    /// <summary>A valid Android v4 boot image whose kernel is one tiny plain ARM64 Image.</summary>
    private static byte[] BuildBootV4(byte[] kernel, int ramdiskSize)
    {
        byte[] header = new byte[BootHeaderSize];
        Encoding.ASCII.GetBytes("ANDROID!").CopyTo(header, 0);
        WriteU32(header, 8, (uint)kernel.Length);
        WriteU32(header, 12, (uint)ramdiskSize);
        WriteU32(header, 20, BootHeaderSize);
        WriteU32(header, 40, AndroidBootVersion);
        WriteU32(header, 1580, 0);

        using MemoryStream output = new MemoryStream();
        output.Write(header, 0, header.Length);
        PadToPage(output);
        output.Write(kernel, 0, kernel.Length);
        PadToPage(output);
        WriteFilled(output, 0x5A, ramdiskSize);
        PadToPage(output);
        return output.ToArray();
    }

    /// <summary>A v4 vendor_boot with page 4096 and the caller's ramdisk length actually present.</summary>
    private static byte[] BuildVendorV4(long ramdiskSize)
    {
        byte[] header = new byte[VendorHeaderSize];
        Encoding.ASCII.GetBytes("VNDRBOOT").CopyTo(header, 0);
        WriteU32(header, 8, VendorBootVersion);
        WriteU32(header, 12, Page);
        WriteU32(header, 24, (uint)ramdiskSize);
        WriteU32(header, 2096, VendorHeaderSize);
        WriteU32(header, 2100, 0);
        WriteU32(header, 2112, 0);
        WriteU32(header, 2116, 0);
        WriteU32(header, 2120, 0);
        WriteU32(header, 2124, 0);

        using MemoryStream output = new MemoryStream();
        output.Write(header, 0, header.Length);
        PadToPage(output);
        WriteFilled(output, 0xA5, (int)ramdiskSize);
        PadToPage(output);
        return output.ToArray();
    }

    /// <summary>
    /// One tiny plain ARM64 Image. Word 0 is a B (not a BL) and the composite words stay zero, so the
    /// reader must treat this as a normal kernel rather than a kshim container.
    /// </summary>
    private static byte[] BuildTinyArm64Image()
    {
        const int size = 320;
        byte[] image = new byte[size];
        WriteU32(image, 0, 0x14000100);
        WriteU32(image, 4, 0);
        WriteU64(image, 8, 0x80000);
        WriteU64(image, 16, size);
        WriteU64(image, 24, 0x0A000000);
        Arm64Magic.CopyTo(image, 56);
        return image;
    }

    // --------------------------------------------------------------- fixture I/O

    private static VerifiedEdlFile ClaimMountedFixture(string fileName)
    {
        string path = RequireMountedFixture(fileName);
        byte[] bytes = File.ReadAllBytes(path);
        return new VerifiedEdlFile(path, bytes.LongLength, Sha256Hex(bytes));
    }

    private static string RequireMountedFixture(string fileName)
    {
        string root = Environment.GetEnvironmentVariable(FixtureRootVariable) ?? string.Empty;
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new InvalidOperationException(
                FixtureRootVariable + " must name the mounted external loader capture directory.");
        }
        string path = Path.Combine(root, fileName);
        if (!File.Exists(path))
        {
            throw new FileNotFoundException(
                "the external loader capture is missing from "
                    + FixtureRootVariable + ": " + fileName,
                path);
        }
        return path;
    }

    /// <summary>
    /// Runs the production container decoder over the two mounted captures without any Reader wiring, so
    /// later mechanical mutation tests can reuse the same CLI-visible PE and window outputs.
    /// </summary>
    private static (byte[] Pe, long WindowBytes) DecodeMountedContainers(
        string ablName, string xblName)
    {
        byte[] ablBytes = File.ReadAllBytes(RequireMountedFixture(ablName));
        byte[] xblBytes = File.ReadAllBytes(RequireMountedFixture(xblName));

        Type loaderType = typeof(InternalSlotMaterialReader).Assembly.GetType(
            "FreedomInstaller.Core.InternalSlotLoaderStructure", throwOnError: true)!;
        MethodInfo? decode = loaderType.GetMethod(
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

        object?[] arguments = { ablBytes, xblBytes, CancellationToken.None, null, 0L };
        object? decoded = decode!.Invoke(null, arguments);
        Assert.True(
            decoded is bool success && success,
            "TryDecodeContainers must report true for the mounted supported loader pair ("
                + ablName + ", " + xblName + ").");
        return ((byte[])arguments[3]!, (long)arguments[4]!);
    }

    /// <summary>
    /// Test-owned scratch directory under an explicitly configured root. There is deliberately no
    /// local-directory or system-temp fallback: without a configured root the test fails.
    /// </summary>
    private sealed class TestWorkspace : IDisposable
    {
        private const string PrimaryRootVariable = "EDL_CLIENT_TEST_WORK_ROOT";
        private const string SecondaryRootVariable = "TEST_ARTIFACT_ROOT";

        public TestWorkspace()
        {
            string? root = Environment.GetEnvironmentVariable(PrimaryRootVariable);
            if (string.IsNullOrWhiteSpace(root))
            {
                root = Environment.GetEnvironmentVariable(SecondaryRootVariable);
            }
            if (string.IsNullOrWhiteSpace(root))
            {
                throw new InvalidOperationException(
                    PrimaryRootVariable + " or " + SecondaryRootVariable
                        + " must name an explicit test work root; no local or system temp fallback is used.");
            }
            Dir = Path.Combine(root, "lb01-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Dir);
        }

        public string Dir { get; }

        public VerifiedEdlFile Claim(byte[] bytes, string name)
        {
            string path = Path.Combine(Dir, name);
            File.WriteAllBytes(path, bytes);
            return new VerifiedEdlFile(path, bytes.LongLength, Sha256Hex(bytes));
        }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Dir, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    // ----------------------------------------------------------------- helpers

    private static void PadToPage(MemoryStream output)
    {
        long remainder = output.Length % Page;
        if (remainder != 0)
        {
            WriteFilled(output, 0, (int)(Page - remainder));
        }
    }

    private static void WriteFilled(MemoryStream output, byte value, int count)
    {
        byte[] chunk = new byte[Math.Min(count, 64 * 1024)];
        if (value != 0)
        {
            Array.Fill(chunk, value);
        }
        int remaining = count;
        while (remaining > 0)
        {
            int take = Math.Min(remaining, chunk.Length);
            output.Write(chunk, 0, take);
            remaining -= take;
        }
    }

    private static void WriteU32(byte[] buffer, int offset, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset, 4), value);

    private static void WriteU64(byte[] buffer, int offset, ulong value) =>
        BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(offset, 8), value);

    private static int CountDifferences(byte[] left, byte[] right)
    {
        int differing = 0;
        for (int index = 0; index < left.Length; index++)
        {
            if (left[index] != right[index])
            {
                differing++;
            }
        }
        return differing;
    }

    private static string Sha256Hex(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    // ----------------------------------------------------- PE map and mutations

    /// <summary>
    /// One reflection bridge to the internal pure matcher. The matcher stays internal and the
    /// production surface is unchanged; the tests only ask the same question of a decoded copy.
    /// </summary>
    private static bool MatchDecodedPe(byte[] pe)
    {
        Type loaderType = typeof(InternalSlotMaterialReader).Assembly.GetType(
            "FreedomInstaller.Core.InternalSlotLoaderStructure", throwOnError: true)!;
        MethodInfo? match = loaderType.GetMethod(
            "MatchesArm64Pe",
            BindingFlags.NonPublic | BindingFlags.Static,
            binder: null,
            types: new[] { typeof(byte[]), typeof(CancellationToken) },
            modifiers: null);
        Assert.NotNull(match);

        object? result = match!.Invoke(null, new object?[] { pe, CancellationToken.None });
        return result is bool matched && matched;
    }

    private static bool TryDecodeContainersFor(byte[] abl, byte[] xbl)
    {
        Type loaderType = typeof(InternalSlotMaterialReader).Assembly.GetType(
            "FreedomInstaller.Core.InternalSlotLoaderStructure", throwOnError: true)!;
        MethodInfo? decode = loaderType.GetMethod(
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
        return decoded is bool success && success;
    }

    /// <summary>RVA to file offset through the PE section table, never a raw-offset guess.</summary>
    private static int MapRvaThroughPeSections(byte[] pe, long rva, int length)
    {
        int eLfanew = BinaryPrimitives.ReadInt32LittleEndian(pe.AsSpan(0x3C, 4));
        Assert.Equal(0x00004550u, BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(eLfanew, 4)));
        int count = BinaryPrimitives.ReadUInt16LittleEndian(pe.AsSpan(eLfanew + 6, 2));
        int optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(pe.AsSpan(eLfanew + 20, 2));
        int table = eLfanew + 24 + optionalSize;

        for (int i = 0; i < count; i++)
        {
            int section = table + i * 40;
            uint virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(section + 8, 4));
            uint virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(section + 12, 4));
            uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(section + 16, 4));
            uint rawPointer = BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(section + 20, 4));

            if (rva < virtualAddress)
            {
                continue;
            }

            long delta = rva - virtualAddress;
            if (delta + length > rawSize || delta + length > virtualSize)
            {
                continue;
            }

            long offset = (long)rawPointer + delta;
            Assert.True(
                offset >= 0 && offset + length <= pe.Length,
                "the mapped section span must stay inside the decoded PE: " + offset);
            return (int)offset;
        }

        throw new InvalidOperationException(
            "RVA 0x" + rva.ToString("x") + " is not backed by PE section raw data.");
    }

    /// <summary>
    /// A zero run inside one page of a raw-backed, non-executable section: a legal place for the
    /// relocated UTF16 literals. The span must already be zero, so relocation never overwrites data.
    /// </summary>
    private static (long Rva, int Offset) FindZeroDataSpan(
        byte[] pe,
        int length,
        long firstStart,
        int firstLength,
        long secondStart,
        int secondLength)
    {
        int eLfanew = BinaryPrimitives.ReadInt32LittleEndian(pe.AsSpan(0x3C, 4));
        int count = BinaryPrimitives.ReadUInt16LittleEndian(pe.AsSpan(eLfanew + 6, 2));
        int optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(pe.AsSpan(eLfanew + 20, 2));
        int table = eLfanew + 24 + optionalSize;

        for (int i = 0; i < count; i++)
        {
            int section = table + i * 40;
            uint virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(section + 8, 4));
            uint virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(section + 12, 4));
            uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(section + 16, 4));
            uint rawPointer = BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(section + 20, 4));
            uint characteristics = BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(section + 36, 4));

            if ((characteristics & 0x20000000u) != 0u || rawSize == 0u || rawPointer == 0u)
            {
                continue;
            }

            uint span = virtualSize == 0u ? rawSize : Math.Min(rawSize, virtualSize);
            for (uint delta = 0; delta + (uint)length <= span; delta += 32u)
            {
                long rva = virtualAddress + delta;
                if ((rva & 0xFFFL) + length > Page)
                {
                    continue;
                }

                if (rva < firstStart + firstLength && firstStart < rva + length)
                {
                    continue;
                }

                if (rva < secondStart + secondLength && secondStart < rva + length)
                {
                    continue;
                }

                long offset = (long)rawPointer + delta;
                if (offset + length > pe.Length)
                {
                    break;
                }

                bool zero = true;
                for (int index = 0; index < length; index++)
                {
                    if (pe[offset + index] != 0)
                    {
                        zero = false;
                        break;
                    }
                }

                if (zero)
                {
                    return (rva, (int)offset);
                }
            }
        }

        throw new InvalidOperationException(
            "the decoded PE has no zero raw-backed non-executable data span.");
    }

    private static long DecodeAddressPair(byte[] pe, long adrpRva, long addRva)
    {
        int adrpOffset = MapRvaThroughPeSections(pe, adrpRva, 4);
        int addOffset = MapRvaThroughPeSections(pe, addRva, 4);
        uint adrp = BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(adrpOffset, 4));
        uint add = BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(addOffset, 4));

        Assert.Equal(0x90000000u, adrp & 0x9F000000u);
        Assert.Equal(0x91000000u, add & 0xFF800000u);
        int rd = (int)(adrp & 0x1Fu);
        Assert.Equal(rd, (int)(add & 0x1Fu));
        Assert.Equal(rd, (int)((add >> 5) & 0x1Fu));

        long immlo = (long)((adrp >> 29) & 0x3u);
        long immhi = (long)((adrp >> 5) & 0x7FFFFu);
        long imm = (immhi << 2) | immlo;
        if ((imm & 0x100000L) != 0L)
        {
            imm -= 0x200000L;
        }

        long page = (adrpRva & ~0xFFFL) + imm * 4096L;
        long addImm = (add & 0x00400000u) != 0u
            ? (long)((add >> 10) & 0xFFFu) << 12
            : (long)((add >> 10) & 0xFFFu);
        return page + addImm;
    }

    /// <summary>Rewrites one ADRP x0 / ADD x0, x0 pair with exact operand encoding.</summary>
    private static void RetargetAddressPair(byte[] pe, int adrpOffset, long adrpRva, long targetRva)
    {
        long atPage = adrpRva & ~0xFFFL;
        long targetPage = targetRva & ~0xFFFL;
        long pageDelta = targetPage - atPage;
        Assert.Equal(0L, pageDelta % 4096L);

        long pages = pageDelta / 4096L;
        Assert.InRange(pages, -(1L << 20), (1L << 20) - 1L);

        long encoded = pages & 0x1FFFFFL;
        uint immlo = (uint)(encoded & 0x3L);
        uint immhi = (uint)((encoded >> 2) & 0x7FFFFL);
        uint adrp = 0x90000000u | (immlo << 29) | (immhi << 5);
        uint add = 0x91000000u | ((uint)(targetRva & 0xFFFL) << 10);

        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(adrpOffset, 4), adrp);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(adrpOffset + 4, 4), add);
    }

    private static bool Arm64Utf16At(byte[] pe, long rva, string text)
    {
        int length = text.Length * 2 + 2;
        int offset = MapRvaThroughPeSections(pe, rva, length);
        for (int i = 0; i < text.Length; i++)
        {
            char value = text[i];
            if (pe[offset + i * 2] != (byte)(value & 0xFF) ||
                pe[offset + i * 2 + 1] != (byte)((value >> 8) & 0xFF))
            {
                return false;
            }
        }

        return pe[offset + text.Length * 2] == 0 && pe[offset + text.Length * 2 + 1] == 0;
    }

    private static void WriteUtf16(byte[] pe, int offset, string text)
    {
        Span<byte> span = pe.AsSpan(offset, text.Length * 2 + 2);
        for (int i = 0; i < span.Length; i++)
        {
            Assert.Equal((byte)0, span[i]);
        }

        for (int i = 0; i < text.Length; i++)
        {
            char value = text[i];
            span[i * 2] = (byte)(value & 0xFF);
            span[i * 2 + 1] = (byte)((value >> 8) & 0xFF);
        }
    }

    private static void EraseUtf16(byte[] pe, long rva, string text)
    {
        int length = text.Length * 2 + 2;
        int offset = MapRvaThroughPeSections(pe, rva, length);
        Assert.True(
            Arm64Utf16At(pe, rva, text),
            "the original literal must be present before it is erased: " + text);
        pe.AsSpan(offset, length).Clear();
    }

    // -------------------------------------------------------- ELF64 duplicate FDT

    private static (int Offset, int Size) FindFdtLoadPayload(byte[] elf)
    {
        Assert.True(elf.Length >= 64, "the mounted XBL is shorter than an ELF64 header");
        Assert.Equal(0x464C457Fu, BinaryPrimitives.ReadUInt32LittleEndian(elf.AsSpan(0, 4)));
        Assert.Equal((byte)2, elf[4]);

        ulong tableOffset = BinaryPrimitives.ReadUInt64LittleEndian(elf.AsSpan(32));
        int tableCount = BinaryPrimitives.ReadUInt16LittleEndian(elf.AsSpan(56));

        for (int i = 0; i < tableCount; i++)
        {
            int program = (int)tableOffset + i * 56;
            if (BinaryPrimitives.ReadUInt32LittleEndian(elf.AsSpan(program, 4)) != 1u)
            {
                continue;
            }

            ulong fileOffset = BinaryPrimitives.ReadUInt64LittleEndian(elf.AsSpan(program + 8));
            ulong fileSize = BinaryPrimitives.ReadUInt64LittleEndian(elf.AsSpan(program + 32));
            if (fileSize < 40 || fileOffset + fileSize > (ulong)elf.Length)
            {
                continue;
            }

            if (BinaryPrimitives.ReadUInt32BigEndian(elf.AsSpan((int)fileOffset, 4)) != 0xD00DFEEDu)
            {
                continue;
            }

            return ((int)fileOffset, (int)fileSize);
        }

        throw new InvalidOperationException(
            "the mounted A-slot XBL has no LOAD segment beginning with an FDT.");
    }

    /// <summary>
    /// A small legal ELF64 image whose two non-overlapping LOAD segments each carry the complete same
    /// FDT payload, with memsz == filesz and both raw ranges inside the file.
    /// </summary>
    private static byte[] BuildDuplicateFdtXbl(byte[] fdt)
    {
        const int HeaderSize = 64;
        const int ProgramSize = 56;
        int first = HeaderSize + 2 * ProgramSize;
        int second = first + fdt.Length;

        byte[] image = new byte[second + fdt.Length];
        image[0] = 0x7F;
        image[1] = (byte)'E';
        image[2] = (byte)'L';
        image[3] = (byte)'F';
        image[4] = 2;
        image[5] = 1;
        image[6] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(16), 2);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(18), 0xB7);
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(20), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(32), HeaderSize);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(52), HeaderSize);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(54), ProgramSize);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(56), 2);

        WriteLoadSegment(image, HeaderSize, first, 0x10000UL, fdt.Length);
        WriteLoadSegment(image, HeaderSize + ProgramSize, second, 0x200000UL, fdt.Length);

        fdt.CopyTo(image, first);
        fdt.CopyTo(image, second);
        return image;
    }

    private static void WriteLoadSegment(
        byte[] image, int at, int fileOffset, ulong virtualAddress, int size)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(at, 4), 1u);
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(at + 4, 4), 4u);
        BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(at + 8, 8), (ulong)fileOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(at + 16, 8), virtualAddress);
        BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(at + 24, 8), virtualAddress);
        BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(at + 32, 8), (ulong)size);
        BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(at + 40, 8), (ulong)size);
        BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(at + 48, 8), 1UL);
    }
}
