// Pure synthetic/public GBL direct-source fixture.
// Every byte is either generated in-process (RSA 4096 parent/child, pattern partitions, a
// hand-built 119-byte DTB) or read from the two required public fixture inputs. Nothing in this
// file claims OEM naming, device support, Complete, Ready, or any physical-test result.
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Owns an isolated <see cref="EdlRawBootBuilderTests.Workspace"/> plus three borrowed
/// <see cref="EdlRawAvbChainTests.AvbFixture"/> instances and exposes only raw, synthetic/public
/// inputs. It never manufactures a Ready/verified plan and never re-signs production material.
/// </summary>
internal sealed class GblDirectSourceFixture : IDisposable
{
    internal const long EfispBytes = 3L * 1024 * 1024;

    internal const int DtbSize = 119;

    private const string AblVariable = "G5_PUBLIC_ABL_PATH";

    private const string LoaderRootVariable = "G5_LOADER_FIXTURE_ROOT";

    private const long AblBytes = 270136;

    private const string AblSha256 =
        "A7B278E11E6C7AA2A930C69E0811F3C0C3DADFE066F5753A7C975B4BACF991BA";

    private const long XblBytes = 381708;

    private const string XblSha256 =
        "737E87430B19A0D83D885DE207584A77711B5F26F1852FFD381DAEEE2A8893F9";

    private static readonly MethodInfo MakeVendorMethod = typeof(InternalSlotMaterialReaderTests)
        .GetMethod("MakeVendor", BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("InternalSlotMaterialReaderTests.MakeVendor was not found");

    private EdlRawBootBuilderTests.Workspace _workspace = null!;

    private RSA _parentKey = null!;

    private RSA _childKey = null!;

    private EdlRawAvbChainTests.AvbFixture _parentA = null!;

    private EdlRawAvbChainTests.AvbFixture _parentB = null!;

    private EdlRawAvbChainTests.AvbFixture _child = null!;

    internal GblDirectSourceFixture(string region = "PRC", bool mismatchParentBootChild = false)
        : this(region, mismatchParentBootChild, null)
    {
    }

    internal GblDirectSourceFixture(string region, bool mismatchParentBootChild, ulong? androidTextOffset)
    {
        Region = region;
        MismatchParentBootChild = mismatchParentBootChild;

        try
        {
            _workspace = new EdlRawBootBuilderTests.Workspace();

            // Two independent 4096-bit principals per fixture; the AvbFixtures only borrow them.
            _parentKey = RSA.Create(4096);
            _childKey = RSA.Create(4096);
            _parentA = new EdlRawAvbChainTests.AvbFixture(_parentKey);
            _parentB = new EdlRawAvbChainTests.AvbFixture(_parentKey);
            _child = new EdlRawAvbChainTests.AvbFixture(_childKey);

            ParentPublicKeySha256 = Sha256Hex(_parentA.KeyBlob);
            BootChildPublicKeySha256 = Sha256Hex(_child.KeyBlob);

            // One root per parent slot. Slot A normally chains boot to the child key; the mismatch
            // flag only rewrites that single descriptor, so the RSA root still verifies while the
            // parent/child key line is deliberately wrong.
            byte[] bootDescriptorA = mismatchParentBootChild
                ? _parentA.ChainFor("boot", 3, 4)
                : _child.ChainFor("boot", 3, 4);
            byte[] rootA = _parentA.BuildRootPartition(
                bootDescriptorA,
                _parentA.ChainFor("recovery", 1, 8),
                _parentA.ChainFor("vbmeta_system", 2, 16));
            File.WriteAllBytes(_parentA.VbmetaPath, rootA);

            byte[] rootB = _parentB.BuildRootPartition(
                _child.ChainFor("boot", 3, 4),
                _parentB.ChainFor("recovery", 1, 8),
                _parentB.ChainFor("vbmeta_system", 2, 16));
            File.WriteAllBytes(_parentB.VbmetaPath, rootB);

            // Slot fixtures stay untouched by production; only the P1 boot-leaf writer runs.
            EdlRawBootBuilderTests.SlotFixture slotA =
                EdlRawBootBuilderTests.CreateSlot(_workspace, "a", 0x31);
            EdlRawBootBuilderTests.SlotFixture slotB =
                EdlRawBootBuilderTests.CreateSlot(_workspace, "b", 0x71);
            if (androidTextOffset is ulong textOffset)
            {
                PatchAndroidTextOffset(slotA, textOffset);
                PatchAndroidTextOffset(slotB, textOffset);
            }
            slotA.CurrentBoot = _child.RewriteBootLeaf(slotA.CurrentBoot.Path);
            slotB.CurrentBoot = _child.RewriteBootLeaf(slotB.CurrentBoot.Path);

            // Required public ABI inputs: pinned by length and full SHA before any use. No fallback,
            // and G5_ACTUAL is never consulted. Both slots share the same read-only public files.
            VerifiedEdlFile abl = PinnedFile(AblVariable, relativeName: null, AblBytes, AblSha256);
            VerifiedEdlFile xbl = PinnedFile(LoaderRootVariable, "xbl_config.elf", XblBytes, XblSha256);

            EfispSource = CreateEfispSource();

            // Rebuild each slot's vendor boot with a complete region DTB, preserving its own ramdisk.
            VendorBoot = BuildVendor(slotA, "a", region);
            slotA.VendorBoot = VendorBoot;
            VerifiedEdlFile vendorBootB = BuildVendor(slotB, "b", region);
            slotB.VendorBoot = vendorBootB;

            var avb = new Dictionary<string, VerifiedEdlFile>(StringComparer.Ordinal)
            {
                ["recovery_a"] = Measure(_parentA.RecoveryPath),
                ["vbmeta_system_a"] = Measure(_parentA.VbmetaSystemPath),
                ["vbmeta_a"] = Measure(_parentA.VbmetaPath),
                ["recovery_b"] = Measure(_parentB.RecoveryPath),
                ["vbmeta_system_b"] = Measure(_parentB.VbmetaSystemPath),
                ["vbmeta_b"] = Measure(_parentB.VbmetaPath),
            };
            AvbSources = avb;

            // Sources are exactly the five real per-slot inputs; AVB metadata stays separate.
            Sources = new Dictionary<string, VerifiedEdlFile>(StringComparer.Ordinal)
            {
                ["boot_a"] = slotA.CurrentBoot,
                ["vendor_boot_a"] = slotA.VendorBoot,
                ["init_boot_a"] = slotA.InitBoot,
                ["abl_a"] = abl,
                ["xbl_config_a"] = xbl,
                ["boot_b"] = slotB.CurrentBoot,
                ["vendor_boot_b"] = slotB.VendorBoot,
                ["init_boot_b"] = slotB.InitBoot,
                ["abl_b"] = abl,
                ["xbl_config_b"] = xbl,
            };
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    internal string Region { get; }

    internal bool MismatchParentBootChild { get; }

    // Opt-in synthetic ABI alignment: rewrite only the ARM64 header text_offset (LE64 @8) in the
    // base image and at the boot-leaf body offset 4096+8, BEFORE _child.RewriteBootLeaf re-signs.
    private static void PatchAndroidTextOffset(EdlRawBootBuilderTests.SlotFixture slot, ulong textOffset)
    {
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(
            slot.BaseImage.AsSpan(8, 8), textOffset);
        byte[] header = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(header, textOffset);
        using var stream = new FileStream(
            slot.CurrentBoot.Path, FileMode.Open, FileAccess.Write, FileShare.None);
        stream.Seek(4096 + 8, SeekOrigin.Begin);
        stream.Write(header, 0, header.Length);
    }

    internal IReadOnlyDictionary<string, VerifiedEdlFile> Sources { get; }

    internal IReadOnlyDictionary<string, VerifiedEdlFile> AvbSources { get; }

    internal VerifiedEdlFile EfispSource { get; }

    internal VerifiedEdlFile VendorBoot { get; }

    internal string ParentPublicKeySha256 { get; }

    internal string BootChildPublicKeySha256 { get; }

    public void Dispose()
    {
        // Fixtures borrow the RSA principals, so they go first, then the keys, then the workspace.
        _parentA?.Dispose();
        _parentB?.Dispose();
        _child?.Dispose();
        _parentKey?.Dispose();
        _childKey?.Dispose();
        _workspace?.Dispose();

        _parentA = null!;
        _parentB = null!;
        _child = null!;
        _parentKey = null!;
        _childKey = null!;
        _workspace = null!;
    }

    private VerifiedEdlFile BuildVendor(
        EdlRawBootBuilderTests.SlotFixture slot,
        string slotName,
        string region)
    {
        byte[] header = ReadRange(slot.VendorBoot.Path, 0, 28);
        if (!string.Equals(Encoding.ASCII.GetString(header, 0, 8), "VNDRBOOT", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("the slot vendor boot is not a VNDRBOOT image");
        }

        int page = checked((int)ReadLeU32(header, 12));
        int ramdiskSize = checked((int)ReadLeU32(header, 24));
        if (page <= 0)
        {
            throw new InvalidDataException("the slot vendor boot declares an invalid page size");
        }

        // Preserve the existing small ramdisk (header page @12 / ramdisk size @24).
        byte[] ramdisk = ramdiskSize == 0
            ? Array.Empty<byte>()
            : ReadRange(slot.VendorBoot.Path, page, ramdiskSize);

        byte[] dtb = BuildRegionDtb(region);
        byte[] vendor = InvokeMakeVendor(ramdisk, dtb);

        string path = Path.Combine(_workspace!.Root, "vendor_boot_" + slotName + ".img");
        File.WriteAllBytes(path, vendor);
        return Measure(path);
    }

    private VerifiedEdlFile CreateEfispSource()
    {
        string path = Path.Combine(_workspace!.Root, "efisp.img");
        using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            // Sparse 3 MiB of zeros; only the length is materialised, never a host array.
            stream.SetLength(EfispBytes);
        }

        return Measure(path);
    }

    private static byte[] InvokeMakeVendor(byte[] ramdisk, byte[] dtb)
    {
        ParameterInfo[] parameters = MakeVendorMethod.GetParameters();
        var arguments = new object?[parameters.Length];
        for (int index = 0; index < parameters.Length; index++)
        {
            arguments[index] = parameters[index].HasDefaultValue
                ? parameters[index].DefaultValue
                : parameters[index].ParameterType.IsValueType
                    ? Activator.CreateInstance(parameters[index].ParameterType)
                    : null;
        }

        arguments[0] = ramdisk;
        arguments[1] = dtb;

        object result = MakeVendorMethod.Invoke(null, arguments)
            ?? throw new InvalidOperationException("InternalSlotMaterialReaderTests.MakeVendor returned null");
        return (byte[])result;
    }

    /// <summary>
    /// Complete 119-byte flattened-device-tree: BE header, 16-byte empty reserve map, one empty
    /// root node, one <c>product_region</c> node whose <c>region</c> property is the 3-char token,
    /// plus the trailing string table. This is a public synthetic property name only.
    /// </summary>
    private static byte[] BuildRegionDtb(string region)
    {
        var dtb = new byte[DtbSize];

        WriteBeU32(dtb, 0, 0xD00DFEEDu); // magic
        WriteBeU32(dtb, 4, DtbSize);     // totalsize
        WriteBeU32(dtb, 8, 56);          // off_dt_struct
        WriteBeU32(dtb, 12, 112);        // off_dt_strings
        WriteBeU32(dtb, 16, 40);         // off_mem_rsvmap
        WriteBeU32(dtb, 20, 17);         // version
        WriteBeU32(dtb, 24, 16);         // last_comp_version
        WriteBeU32(dtb, 28, 0);          // boot_cpuid_phys
        WriteBeU32(dtb, 32, 7);          // size_dt_strings
        WriteBeU32(dtb, 36, 56);         // size_dt_struct

        // 40..55: empty reserve map (16 zero bytes).

        WriteBeU32(dtb, 56, 1);          // FDT_BEGIN_NODE (root)
        // 60..63: empty root node name.
        WriteBeU32(dtb, 64, 1);          // FDT_BEGIN_NODE (product_region)

        byte[] nodeName = Encoding.ASCII.GetBytes("product_region");
        Buffer.BlockCopy(nodeName, 0, dtb, 68, nodeName.Length); // NUL + pad are already zero.

        WriteBeU32(dtb, 84, 3);          // FDT_PROP
        WriteBeU32(dtb, 88, 4);          // value length
        WriteBeU32(dtb, 92, 0);          // name offset ("region")

        byte[] value = Encoding.ASCII.GetBytes(RegionToken(region));
        Buffer.BlockCopy(value, 0, dtb, 96, 3); // trailing NUL is already zero.

        WriteBeU32(dtb, 100, 2);         // FDT_END_NODE
        WriteBeU32(dtb, 104, 2);         // FDT_END_NODE
        WriteBeU32(dtb, 108, 9);         // FDT_END

        byte[] strings = Encoding.ASCII.GetBytes("region");
        Buffer.BlockCopy(strings, 0, dtb, 112, strings.Length); // trailing NUL is already zero.

        return dtb;
    }

    private static string RegionToken(string region) =>
        region.Length == 3 && IsAscii(region) ? region : "UNK";

    private static bool IsAscii(string value)
    {
        foreach (char character in value)
        {
            if (character > 0x7F)
            {
                return false;
            }
        }

        return true;
    }

    private static VerifiedEdlFile PinnedFile(
        string variable,
        string? relativeName,
        long expectedLength,
        string expectedSha256)
    {
        string? root = Environment.GetEnvironmentVariable(variable);
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new InvalidOperationException(variable + " must name the required public fixture input.");
        }

        string path = relativeName is null
            ? Path.GetFullPath(root)
            : Path.GetFullPath(Path.Combine(root, relativeName));

        var info = new FileInfo(path);
        if (!info.Exists)
        {
            throw new InvalidOperationException(variable + " does not exist: " + path);
        }

        if (info.Length != expectedLength)
        {
            throw new InvalidOperationException(
                variable + " length mismatch: " + info.Length + " != " + expectedLength);
        }

        string sha256 = Sha256File(path);
        if (!string.Equals(sha256, expectedSha256, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(variable + " SHA-256 mismatch: " + sha256);
        }

        return new VerifiedEdlFile(path, info.Length, sha256);
    }

    private static VerifiedEdlFile Measure(string path)
    {
        string full = Path.GetFullPath(path);
        var info = new FileInfo(full);
        if (!info.Exists)
        {
            throw new FileNotFoundException("the fixture file was not found", full);
        }

        return new VerifiedEdlFile(full, info.Length, Sha256File(full));
    }

    internal static string Sha256File(string path)
    {
        using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.SequentialScan);
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[81920];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            hash.AppendData(buffer, 0, read);
        }

        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static string Sha256Hex(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));

    internal static byte[] ReadRange(string path, long offset, int count)
    {
        byte[] buffer = new byte[count];
        using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.SequentialScan);
        stream.Position = offset;
        int read = 0;
        while (read < count)
        {
            int chunk = stream.Read(buffer, read, count - read);
            if (chunk <= 0)
            {
                throw new InvalidDataException("unexpected end of file while reading a fixture range");
            }

            read += chunk;
        }

        return buffer;
    }

    internal static uint ReadLeU32(byte[] buffer, int offset) =>
        (uint)(buffer[offset]
            | (buffer[offset + 1] << 8)
            | (buffer[offset + 2] << 16)
            | (buffer[offset + 3] << 24));

    internal static uint ReadBeU32(byte[] buffer, int offset) =>
        (uint)((buffer[offset] << 24)
            | (buffer[offset + 1] << 16)
            | (buffer[offset + 2] << 8)
            | buffer[offset + 3]);

    internal static ulong ReadBeU64(byte[] buffer, int offset)
    {
        ulong value = 0;
        for (int index = 0; index < 8; index++)
        {
            value = (value << 8) | buffer[offset + index];
        }

        return value;
    }

    private static void WriteBeU32(byte[] buffer, int offset, uint value)
    {
        buffer[offset] = (byte)(value >> 24);
        buffer[offset + 1] = (byte)(value >> 16);
        buffer[offset + 2] = (byte)(value >> 8);
        buffer[offset + 3] = (byte)value;
    }
}

/// <summary>
/// Two-case theory that only inspects the raw synthetic/public inputs; it does not assert any
/// Ready, Complete, or verified-plan state.
/// </summary>
public sealed class GblDirectSourceFixtureTests
{
    private const long AblBytes = 270136;

    private const string AblSha256 =
        "A7B278E11E6C7AA2A930C69E0811F3C0C3DADFE066F5753A7C975B4BACF991BA";

    private const long XblBytes = 381708;

    private const string XblSha256 =
        "737E87430B19A0D83D885DE207584A77711B5F26F1852FFD381DAEEE2A8893F9";

    [Theory]
    [InlineData("PRC")]
    [InlineData("ROW")]
    public void ExposesRawSyntheticInputsForReadySession(string region)
    {
        using var fixture = new GblDirectSourceFixture(region);

        Assert.Equal(region, fixture.Region);
        Assert.False(fixture.MismatchParentBootChild);

        Assert.Equal(10, fixture.Sources.Count);
        Assert.Equal(6, fixture.AvbSources.Count);

        foreach (string role in new[]
                 {
                     "boot_a", "vendor_boot_a", "init_boot_a", "abl_a", "xbl_config_a",
                     "boot_b", "vendor_boot_b", "init_boot_b", "abl_b", "xbl_config_b",
                 })
        {
            Assert.True(fixture.Sources.ContainsKey(role), "missing source role: " + role);
        }

        foreach (string role in new[]
                 {
                     "recovery_a", "vbmeta_system_a", "vbmeta_a",
                     "recovery_b", "vbmeta_system_b", "vbmeta_b",
                 })
        {
            Assert.True(fixture.AvbSources.ContainsKey(role), "missing AVB role: " + role);
            Assert.False(fixture.Sources.ContainsKey(role), "AVB metadata must not overlap Sources: " + role);
        }

        // Sparse owned efisp is exactly 3 MiB.
        Assert.Equal(GblDirectSourceFixture.EfispBytes, fixture.EfispSource.Length);

        // Raw public ABI pins, re-measured from the referenced read-only files for both slots.
        AssertPinned(fixture.Sources["abl_a"], AblBytes, AblSha256);
        AssertPinned(fixture.Sources["abl_b"], AblBytes, AblSha256);
        AssertPinned(fixture.Sources["xbl_config_a"], XblBytes, XblSha256);
        AssertPinned(fixture.Sources["xbl_config_b"], XblBytes, XblSha256);

        // Parent and child principals stay distinct even in the positive case.
        Assert.NotEqual(fixture.ParentPublicKeySha256, fixture.BootChildPublicKeySha256);
        Assert.NotEqual(string.Empty, fixture.ParentPublicKeySha256);
        Assert.NotEqual(string.Empty, fixture.BootChildPublicKeySha256);

        // The rebuilt vendor boot carries the complete 119-byte region DTB.
        AssertVendorDtb(fixture.VendorBoot, region);

        // The original boot leaves still authenticate against their own embedded RSA key.
        AssertBootBlobAuthenticated(fixture.Sources["boot_a"]);
        AssertBootBlobAuthenticated(fixture.Sources["boot_b"]);
    }

    private static void AssertPinned(VerifiedEdlFile file, long length, string sha256)
    {
        Assert.Equal(length, file.Length);
        Assert.Equal(sha256, file.Sha256);
        Assert.Equal(length, new FileInfo(file.Path).Length);
        Assert.Equal(sha256, GblDirectSourceFixture.Sha256File(file.Path));
    }

    private static void AssertVendorDtb(VerifiedEdlFile vendor, string region)
    {
        byte[] header = GblDirectSourceFixture.ReadRange(vendor.Path, 0, 2128);
        Assert.Equal("VNDRBOOT", Encoding.ASCII.GetString(header, 0, 8));

        int page = checked((int)GblDirectSourceFixture.ReadLeU32(header, 12));
        int ramdiskSize = checked((int)GblDirectSourceFixture.ReadLeU32(header, 24));
        int headerSize = checked((int)GblDirectSourceFixture.ReadLeU32(header, 2096));
        uint declaredDtbSize = GblDirectSourceFixture.ReadLeU32(header, 2100);

        Assert.True(page > 0);
        Assert.Equal((uint)GblDirectSourceFixture.DtbSize, declaredDtbSize);

        long dtbOffset = RoundUp(headerSize, page) + RoundUp(ramdiskSize, page);
        Assert.True(dtbOffset + GblDirectSourceFixture.DtbSize <= vendor.Length);

        byte[] dtb = GblDirectSourceFixture.ReadRange(
            vendor.Path, dtbOffset, GblDirectSourceFixture.DtbSize);

        Assert.Equal((uint)GblDirectSourceFixture.DtbSize, declaredDtbSize);
        Assert.Equal(0xD00DFEEDu, GblDirectSourceFixture.ReadBeU32(dtb, 0));
        Assert.Equal((uint)GblDirectSourceFixture.DtbSize, GblDirectSourceFixture.ReadBeU32(dtb, 4));

        uint offStruct = GblDirectSourceFixture.ReadBeU32(dtb, 8);
        uint offStrings = GblDirectSourceFixture.ReadBeU32(dtb, 12);
        uint offReserve = GblDirectSourceFixture.ReadBeU32(dtb, 16);
        uint version = GblDirectSourceFixture.ReadBeU32(dtb, 20);
        uint lastCompatible = GblDirectSourceFixture.ReadBeU32(dtb, 24);
        uint cpu = GblDirectSourceFixture.ReadBeU32(dtb, 28);
        uint sizeStrings = GblDirectSourceFixture.ReadBeU32(dtb, 32);
        uint sizeStruct = GblDirectSourceFixture.ReadBeU32(dtb, 36);

        Assert.Equal(56u, offStruct);
        Assert.Equal(112u, offStrings);
        Assert.Equal(40u, offReserve);
        Assert.Equal(17u, version);
        Assert.Equal(16u, lastCompatible);
        Assert.Equal(0u, cpu);
        Assert.Equal(7u, sizeStrings);
        Assert.Equal(56u, sizeStruct);
        Assert.Equal(offStrings, offStruct + sizeStruct);
        Assert.Equal((uint)GblDirectSourceFixture.DtbSize, offStrings + sizeStrings);

        for (int index = 40; index < 56; index++)
        {
            Assert.Equal(0, dtb[index]);
        }

        Assert.Equal(1u, GblDirectSourceFixture.ReadBeU32(dtb, 56));
        Assert.Equal(1u, GblDirectSourceFixture.ReadBeU32(dtb, 64));
        Assert.Equal("product_region", Encoding.ASCII.GetString(dtb, 68, 14));
        Assert.Equal(0, dtb[82]);
        Assert.Equal(3u, GblDirectSourceFixture.ReadBeU32(dtb, 84));
        Assert.Equal(4u, GblDirectSourceFixture.ReadBeU32(dtb, 88));
        Assert.Equal(0u, GblDirectSourceFixture.ReadBeU32(dtb, 92));
        Assert.Equal(region, Encoding.ASCII.GetString(dtb, 96, 3));
        Assert.Equal(0, dtb[99]);
        Assert.Equal(2u, GblDirectSourceFixture.ReadBeU32(dtb, 100));
        Assert.Equal(2u, GblDirectSourceFixture.ReadBeU32(dtb, 104));
        Assert.Equal(9u, GblDirectSourceFixture.ReadBeU32(dtb, 108));
        Assert.Equal("region", Encoding.ASCII.GetString(dtb, 112, 6));
        Assert.Equal(0, dtb[118]);
    }

    private static void AssertBootBlobAuthenticated(VerifiedEdlFile boot)
    {
        Assert.True(boot.Length > 128);

        // Only the 64-byte footer and the small (<= 64 KiB) vbmeta blob are read.
        byte[] footer = GblDirectSourceFixture.ReadRange(boot.Path, boot.Length - 64, 64);
        Assert.Equal("AVBf", Encoding.ASCII.GetString(footer, 0, 4));

        ulong vbmetaOffset = GblDirectSourceFixture.ReadBeU64(footer, 20);
        ulong vbmetaSize = GblDirectSourceFixture.ReadBeU64(footer, 28);

        Assert.True(vbmetaSize > 0);
        Assert.True(vbmetaSize <= 64 * 1024);
        Assert.True((long)vbmetaOffset + (long)vbmetaSize <= boot.Length);

        byte[] blob = GblDirectSourceFixture.ReadRange(
            boot.Path, (long)vbmetaOffset, (int)vbmetaSize);
        EdlRawAvbChainTests.AvbFixture.AssertAuthenticatedSignedBlob(blob);
    }

    private static long RoundUp(long value, int alignment) =>
        (value + alignment - 1) / alignment * alignment;
}
