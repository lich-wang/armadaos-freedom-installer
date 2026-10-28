// STOCK-01: real behavioral tests of the frozen original-boot verifier.
// The Core method is internal and the assembly has no InternalsVisibleTo, so a
// narrow reflection adapter invokes the REAL method, awaits its REAL task,
// unwraps TargetInvocationException and reads the REAL facts object. Nothing is
// stubbed or reimplemented: every case signs genuine RSA-4096 metadata with the
// in-process synthetic fixtures and asserts the verifier's crypto/payload
// behaviour on the bytes it actually reads.
using System;
using System.Buffers.Binary;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using AvbFixture = FreedomInstaller.Core.Tests.EdlRawAvbChainTests.AvbFixture;

namespace FreedomInstaller.Core.Tests;

public sealed class BootMaintenanceStockOriginalTests
{
    private const int BootPartitionBytes = 262144;

    private const int BootHeaderBytes = 4096;

    private const int AvbFooterBytes = 64;

    private const int PlainKernelBytes = 4096;

    private const ulong FrozenRollbackIndex = 0x1122334455667788UL;

    private const uint FrozenRollbackLocation = 7;

    private const string ProjectPinnedKeySha256 =
        "7728E30F50BFA5CEA165F473175A08803F6A8346642B5AA10913E9D9E6DEFEF6";

    private static readonly MethodInfo VerifyMethod = typeof(EdlRawBootBuilder).GetMethod(
        "VerifyStockOriginalBootAsync",
        BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException(
            "EdlRawBootBuilder.VerifyStockOriginalBootAsync was not found");

    private static readonly Lazy<RSA> ParentKey = new(
        () => RSA.Create(4096), LazyThreadSafetyMode.ExecutionAndPublication);

    private static readonly Lazy<RSA> ChildKey = new(
        () => RSA.Create(4096), LazyThreadSafetyMode.ExecutionAndPublication);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AuthenticBoundStockOriginalSucceedsForRawAndGzipKernels(bool gzip)
    {
        using AvbFixture parent = new(ParentKey.Value);
        using AvbFixture child = new(ChildKey.Value);

        byte[] kernel = PlainKernel(PlainKernelBytes, imageSize: null);
        byte[] stored = gzip ? Gzip(kernel) : kernel;

        string bootPath = WriteBoot(child, parent.Root, stored, "boot-stock.img");
        string rootPath = WriteRoot(parent, child, parent.Root, "vbmeta-stock.img");

        VerifiedEdlFile bootClaim = Claim(bootPath);
        VerifiedEdlFile rootClaim = Claim(rootPath);
        string[] before = Snapshot(parent.Root);

        object facts = await VerifyAsync(bootClaim, rootClaim);

        Assert.Equal(bootClaim.Path, FactFile(facts, "Boot").Path);
        Assert.Equal(bootClaim.Sha256, FactFile(facts, "Boot").Sha256);
        Assert.Equal(rootClaim.Path, FactFile(facts, "RootVbmeta").Path);
        Assert.Equal(rootClaim.Sha256, FactFile(facts, "RootVbmeta").Sha256);
        Assert.Equal((long)(BootHeaderBytes + RoundUp(stored.Length, 4096)), FactLong(facts, "ImageSize"));
        Assert.Equal(64, FactText(facts, "Digest").Length);

        // The two principals are independently generated and genuinely distinct,
        // and neither is the project's pinned AOSP key.
        Assert.True(FactBool(facts, "SignatureVerified"));
        Assert.True(FactBool(facts, "PayloadDigestVerified"));
        // Production hashes are lowercase hex; normalize the observed facts to
        // uppercase so both key comparisons use the same case throughout.
        string bootKeySha256 = FactText(facts, "BootPublicKeySha256").ToUpperInvariant();
        string rootKeySha256 = FactText(facts, "RootPublicKeySha256").ToUpperInvariant();

        Assert.Equal(Sha256Hex(child.KeyBlob), bootKeySha256);
        Assert.Equal(Sha256Hex(parent.KeyBlob), rootKeySha256);
        Assert.NotEqual(bootKeySha256, rootKeySha256);
        Assert.NotEqual(ProjectPinnedKeySha256, bootKeySha256);
        Assert.NotEqual(ProjectPinnedKeySha256, rootKeySha256);

        Assert.Equal(FrozenRollbackIndex, FactUlong(facts, "RollbackIndex"));
        Assert.Equal(FrozenRollbackLocation, FactUint(facts, "RollbackIndexLocation"));

        // The verifier is read-only: both inputs keep their bytes and no file is added.
        Assert.Equal(bootClaim.Sha256, Claim(bootPath).Sha256);
        Assert.Equal(rootClaim.Sha256, Claim(rootPath).Sha256);
        Assert.Equal(before, Snapshot(parent.Root));
    }

    [Fact]
    public async Task PlainBssImageSizeAbovePhysicalKernelLengthIsAccepted()
    {
        using AvbFixture parent = new(ParentKey.Value);
        using AvbFixture child = new(ChildKey.Value);

        // A real ARM64 image_size includes BSS and may exceed the physical kernel
        // bytes; no fabricated loader budget is applied.
        byte[] kernel = PlainKernel(PlainKernelBytes, imageSize: 65536);

        string bootPath = WriteBoot(child, parent.Root, kernel, "boot-bss.img");
        string rootPath = WriteRoot(parent, child, parent.Root, "vbmeta-bss.img");

        object facts = await VerifyAsync(Claim(bootPath), Claim(rootPath));

        Assert.Equal((long)(BootHeaderBytes + RoundUp(kernel.Length, 4096)), FactLong(facts, "ImageSize"));
        Assert.True(FactBool(facts, "SignatureVerified"));
        Assert.True(FactBool(facts, "PayloadDigestVerified"));
    }

    [Fact]
    public async Task PayloadTamperAfterSigningWithRefreshedWholeClaimFailsDigest()
    {
        using AvbFixture parent = new(ParentKey.Value);
        using AvbFixture child = new(ChildKey.Value);

        string bootPath = WriteBoot(child, parent.Root, PlainKernel(PlainKernelBytes, null), "boot-tamper.img");
        string rootPath = WriteRoot(parent, child, parent.Root, "vbmeta-tamper.img");

        byte[] bootBytes = File.ReadAllBytes(bootPath);
        bootBytes[BootHeaderBytes + 128] ^= 0x5A;
        File.WriteAllBytes(bootPath, bootBytes);

        // The outer claim is refreshed, and the leaf metadata signature is still
        // authentic; only the signed payload digest is now stale.
        VerifiedEdlFile refreshed = Claim(bootPath);

        InvalidDataException failure = await Assert.ThrowsAsync<InvalidDataException>(
            () => VerifyAsync(refreshed, Claim(rootPath)));

        Assert.Contains("digest", failure.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ValidSignaturesWithWrongDeclaredChildKeyFailBinding()
    {
        using AvbFixture parent = new(ParentKey.Value);
        using AvbFixture child = new(ChildKey.Value);

        string bootPath = WriteBoot(child, parent.Root, PlainKernel(PlainKernelBytes, null), "boot-binding.img");

        // The root chain declares the PARENT key for boot while the leaf is really
        // signed by the child. Both signatures are valid on their own.
        string rootPath = WriteRoot(parent, parent, parent.Root, "vbmeta-binding.img");

        InvalidDataException failure = await Assert.ThrowsAsync<InvalidDataException>(
            () => VerifyAsync(Claim(bootPath), Claim(rootPath)));

        Assert.Contains("not bound", failure.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SelfConsistentlyResignedProjectCompositeIsRejectedAsProject(bool gzip)
    {
        using AvbFixture parent = new(ParentKey.Value);
        using AvbFixture child = new(ChildKey.Value);

        byte[] composite = ProjectCompositeKernel();
        byte[] stored = gzip ? Gzip(composite) : composite;

        // RewriteBootLeaf re-signs the CURRENT payload digest, so the leaf, the
        // chain binding and the whole claim are all self-consistent here.
        string bootPath = WriteBoot(child, parent.Root, stored, "boot-project.img");
        string rootPath = WriteRoot(parent, child, parent.Root, "vbmeta-project.img");

        // The leaf itself really is authentic and self-consistent; only the kernel
        // shape is project material.
        AvbFixture.AssertAuthenticatedSignedBlob(ExtractSignedBlob(bootPath));

        InvalidDataException failure = await Assert.ThrowsAsync<InvalidDataException>(
            () => VerifyAsync(Claim(bootPath), Claim(rootPath)));

        Assert.Contains("project", failure.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("kshim", failure.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PlainKernelCarryingArbitraryKpmfBytesIsAccepted()
    {
        using AvbFixture parent = new(ParentKey.Value);
        using AvbFixture child = new(ChildKey.Value);

        byte[] kernel = PlainKernel(PlainKernelBytes, null);
        WriteU32Le(kernel, 512, 0x464D504B);
        WriteU32Le(kernel, 520, 7);
        WriteU32Le(kernel, 524, 1);
        WriteU32Le(kernel, 528, 8000);

        // Reserved composite header fields stay zero, so the KPMF bytes are just
        // payload content and must not be substring-scanned as a project kernel.
        string bootPath = WriteBoot(child, parent.Root, kernel, "boot-kpmf-plain.img");
        string rootPath = WriteRoot(parent, child, parent.Root, "vbmeta-kpmf-plain.img");

        object facts = await VerifyAsync(Claim(bootPath), Claim(rootPath));

        Assert.True(FactBool(facts, "SignatureVerified"));
        Assert.True(FactBool(facts, "PayloadDigestVerified"));
    }

    [Fact]
    public async Task TamperedRootSignatureWithRefreshedClaimFailsRootAuthentication()
    {
        using AvbFixture parent = new(ParentKey.Value);
        using AvbFixture child = new(ChildKey.Value);

        string bootPath = WriteBoot(child, parent.Root, PlainKernel(PlainKernelBytes, null), "boot-root-tamper.img");
        string rootPath = WriteRoot(parent, child, parent.Root, "vbmeta-root-tamper.img");

        // auth = 256-byte header + 576-byte block; flip inside the 512-byte
        // signature that starts at auth offset 64.
        byte[] rootBytes = File.ReadAllBytes(rootPath);
        rootBytes[256 + 64 + 100] ^= 0x5A;
        File.WriteAllBytes(rootPath, rootBytes);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => VerifyAsync(Claim(bootPath), Claim(rootPath)));
    }

    [Fact]
    public async Task NullAndPreCancelledInputsFailBeforeAnyIo()
    {
        string absent = Path.Combine(
            TestArtifactRoot.Resolve(),
            "stock-absent-" + Guid.NewGuid().ToString("N"));

        var bootClaim = new VerifiedEdlFile(Path.Combine(absent, "boot.img"), 4096, new string('0', 64));
        var rootClaim = new VerifiedEdlFile(Path.Combine(absent, "vbmeta.img"), 4096, new string('0', 64));

        await Assert.ThrowsAsync<ArgumentNullException>(() => VerifyAsync(null!, rootClaim));
        await Assert.ThrowsAsync<ArgumentNullException>(() => VerifyAsync(bootClaim, null!));

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => VerifyAsync(bootClaim, rootClaim, cancellation.Token));

        Assert.False(Directory.Exists(absent));
    }

    // ------------------------------------------------------------ narrow access adapter

    private static async Task<object> VerifyAsync(
        VerifiedEdlFile boot,
        VerifiedEdlFile rootVbmeta,
        CancellationToken ct = default)
    {
        object? invocation;
        try
        {
            invocation = VerifyMethod.Invoke(null, new object?[] { boot, rootVbmeta, ct });
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }

        var task = (Task)invocation!;
        await task.ConfigureAwait(false);

        PropertyInfo result = task.GetType().GetProperty("Result")
            ?? throw new InvalidOperationException("verified task exposed no Result property");
        return result.GetValue(task)!;
    }

    private static PropertyInfo FactProperty(object facts, string name)
    {
        return facts.GetType().GetProperty(name, BindingFlags.Instance | BindingFlags.Public)
            ?? throw new InvalidOperationException("facts property not found: " + name);
    }

    private static VerifiedEdlFile FactFile(object facts, string name)
    {
        return (VerifiedEdlFile)FactProperty(facts, name).GetValue(facts)!;
    }

    private static string FactText(object facts, string name)
    {
        return (string)FactProperty(facts, name).GetValue(facts)!;
    }

    private static long FactLong(object facts, string name)
    {
        return (long)FactProperty(facts, name).GetValue(facts)!;
    }

    private static ulong FactUlong(object facts, string name)
    {
        return (ulong)FactProperty(facts, name).GetValue(facts)!;
    }

    private static uint FactUint(object facts, string name)
    {
        return (uint)FactProperty(facts, name).GetValue(facts)!;
    }

    private static bool FactBool(object facts, string name)
    {
        return (bool)FactProperty(facts, name).GetValue(facts)!;
    }

    // ------------------------------------------------------------ synthetic inputs

    private static string WriteBoot(AvbFixture signer, string directory, byte[] kernel, string name)
    {
        int imageSize = BootHeaderBytes + RoundUp(kernel.Length, 4096);
        Assert.True(imageSize <= 1024 * 1024, "synthetic boot body must stay within the 1 MiB fixture bound");

        var image = new byte[BootPartitionBytes];
        Encoding.ASCII.GetBytes("ANDROID!").CopyTo(image, 0);
        WriteU32Le(image, 8, (uint)kernel.Length);
        WriteU32Le(image, 12, 0);
        WriteU32Le(image, 20, 1584);
        WriteU32Le(image, 40, 4);
        WriteU32Le(image, 1580, 0);
        Buffer.BlockCopy(kernel, 0, image, BootHeaderBytes, kernel.Length);

        int footer = image.Length - AvbFooterBytes;
        Encoding.ASCII.GetBytes("AVBf").CopyTo(image, footer);
        WriteU32Be(image, footer + 4, 1);
        WriteU32Be(image, footer + 8, 0);
        WriteU64Be(image, footer + 12, (ulong)imageSize);
        WriteU64Be(image, footer + 20, (ulong)imageSize);
        WriteU64Be(image, footer + 28, 0);

        string path = Path.Combine(directory, name);
        File.WriteAllBytes(path, image);

        signer.RewriteBootLeaf(path);
        return path;
    }

    private static string WriteRoot(AvbFixture parent, AvbFixture bootKeyOwner, string directory, string name)
    {
        byte[] partition = parent.BuildRootPartition(
            bootKeyOwner.ChainFor("boot", 3, 4),
            parent.ChainFor("recovery", 1, 8),
            parent.ChainFor("vbmeta_system", 2, 16));

        string path = Path.Combine(directory, name);
        File.WriteAllBytes(path, partition);
        return path;
    }

    private static VerifiedEdlFile Claim(string path)
    {
        byte[] bytes = File.ReadAllBytes(path);
        return new VerifiedEdlFile(
            Path.GetFullPath(path),
            bytes.Length,
            Convert.ToHexString(SHA256.HashData(bytes)));
    }

    private static byte[] ExtractSignedBlob(string bootPath)
    {
        byte[] image = File.ReadAllBytes(bootPath);
        int footer = image.Length - AvbFooterBytes;
        long offset = checked((long)ReadU64Be(image, footer + 20));
        long size = checked((long)ReadU64Be(image, footer + 28));

        Assert.True(offset >= 0 && size > 0 && offset + size <= image.Length);

        byte[] blob = new byte[size];
        Buffer.BlockCopy(image, (int)offset, blob, 0, blob.Length);
        return blob;
    }

    private static ulong ReadU64Be(byte[] buffer, int offset)
    {
        return BinaryPrimitives.ReadUInt64BigEndian(buffer.AsSpan(offset, 8));
    }

    private static string[] Snapshot(string directory)
    {
        return Directory.GetFiles(directory, "*", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(directory, path))
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToArray();
    }

    private static string Sha256Hex(byte[] data)
    {
        return Convert.ToHexString(SHA256.HashData(data));
    }

    private static byte[] PlainKernel(int length, ulong? imageSize)
    {
        Assert.True(length >= 64, "an ARM64 image needs at least the 64-byte header");

        var raw = new byte[length];
        WriteU32Le(raw, 0, 0x14000000u);
        WriteU64Le(raw, 16, imageSize ?? (ulong)length);
        Encoding.ASCII.GetBytes("ARMd").CopyTo(raw, 56);
        return raw;
    }

    // A structurally legal seven-entry project composite: BL to a positive
    // 4-aligned shim, ARM64 image_size equal to the whole raw length, a bounded
    // KPMF manifest that ends exactly at the raw end, and seven 56-byte records
    // with four-byte name padding.
    private static byte[] ProjectCompositeKernel()
    {
        const int payloadBytes = 4096;
        const int shimOffset = 1024;
        const int manifestOffset = payloadBytes;
        const int entryBytes = 56;
        const int recordBytes = 60; // 56-byte header + 4-byte name, already 4-aligned
        const int manifestBytes = 60 + (7 * recordBytes);

        var raw = new byte[manifestOffset + manifestBytes];

        WriteU32Le(raw, 0, 0x94000000u | (uint)(shimOffset / 4));
        WriteU32Le(raw, 4, 0x14000000u);
        WriteU64Le(raw, 16, (ulong)raw.Length);
        WriteU64Le(raw, 32, manifestOffset);
        WriteU64Le(raw, 40, manifestBytes);
        WriteU64Le(raw, 48, shimOffset);
        Encoding.ASCII.GetBytes("ARMd").CopyTo(raw, 56);

        // A coherent little-endian plain ARM64 header inside the Image1 payload.
        WriteU32Le(raw, 128, 0x14000000u);
        WriteU64Le(raw, 128 + 16, 64);
        Encoding.ASCII.GetBytes("ARMd").CopyTo(raw, 128 + 56);

        var entries = new (string Name, ulong Offset, ulong Size, uint Type, uint Flags, uint Dtb, uint Align)[]
        {
            ("img0", 0, 64, 1u, 5u, 0u, 2u),
            ("img1", 128, 64, 1u, 12u, 3u, 2u),
            ("img2", 128, 64, 1u, 12u, 4u, 2u),
            ("img3", 256, 64, 5u, 0u, 0u, 3u),
            ("img4", 320, 64, 5u, 0u, 0u, 3u),
            ("img5", 384, 64, 4u, 0u, 0u, 4u),
            ("shim", 1024, 128, 3u, 4u, 0u, 2u),
        };

        // This negative must be structurally legal so the factory rejects it as a
        // project composite and not as an unrelated format error.
        int baseEntries = 0;
        foreach (var entry in entries)
        {
            if ((entry.Flags & 1u) != 0)
            {
                baseEntries++;
            }

            Assert.True(entry.Offset + entry.Size <= payloadBytes, "entry payload must end before the manifest");
            Assert.True(entry.Align <= 21, "alignment exponent must be in the ARM64 supported range");
        }

        Assert.Equal(1, baseEntries);
        Assert.Equal(0ul, entries[0].Offset);
        Assert.True(entries[0].Size >= 64);
        Assert.Equal(5u, entries[(int)entries[1].Dtb].Type);
        Assert.Equal(5u, entries[(int)entries[2].Dtb].Type);

        int position = manifestOffset;
        WriteU32Le(raw, position, 0x464D504B);
        WriteU16Le(raw, position + 4, 0);
        WriteU16Le(raw, position + 6, 1);
        WriteU32Le(raw, position + 8, 7);
        WriteU32Le(raw, position + 12, 1);
        WriteU32Le(raw, position + 16, 8000);

        // Backup words preserve the pre-composite plain header fields:
        // original first 64-bit word, original image_size, then zero reserves.
        WriteU64Le(raw, position + 20, 0x0000000014000000UL);
        WriteU64Le(raw, position + 28, 64);
        WriteU64Le(raw, position + 36, 0);
        WriteU64Le(raw, position + 44, 0);
        WriteU64Le(raw, position + 52, 0);

        int cursor = position + 60;

        for (int index = 0; index < entries.Length; index++)
        {
            var entry = entries[index];
            WriteU64Le(raw, cursor, entry.Offset);
            WriteU64Le(raw, cursor + 8, entry.Size);
            WriteU32Le(raw, cursor + 16, entry.Type);
            WriteU32Le(raw, cursor + 20, entry.Flags);
            WriteU64Le(raw, cursor + 24, entry.Offset);
            WriteU32Le(raw, cursor + 32, 0);
            WriteU32Le(raw, cursor + 36, entry.Dtb);
            WriteU32Le(raw, cursor + 40, entry.Align);
            WriteU64Le(raw, cursor + 44, 0);
            WriteU32Le(raw, cursor + 52, (uint)entry.Name.Length);
            Encoding.UTF8.GetBytes(entry.Name).CopyTo(raw, cursor + entryBytes);

            cursor += recordBytes;
        }

        Assert.Equal(raw.Length, cursor);
        return raw;
    }

    private static byte[] Gzip(byte[] data)
    {
        using var output = new MemoryStream();
        using (var compressor = new GZipStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            compressor.Write(data, 0, data.Length);
        }

        return output.ToArray();
    }

    private static int RoundUp(int value, int alignment)
    {
        int remainder = value % alignment;
        return remainder == 0 ? value : value + (alignment - remainder);
    }

    private static void WriteU16Le(byte[] buffer, int offset, ushort value)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(offset, 2), value);
    }

    private static void WriteU32Le(byte[] buffer, int offset, uint value)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset, 4), value);
    }

    private static void WriteU64Le(byte[] buffer, int offset, ulong value)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(offset, 8), value);
    }

    private static void WriteU32Be(byte[] buffer, int offset, uint value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(offset, 4), value);
    }

    private static void WriteU64Be(byte[] buffer, int offset, ulong value)
    {
        BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(offset, 8), value);
    }
}
