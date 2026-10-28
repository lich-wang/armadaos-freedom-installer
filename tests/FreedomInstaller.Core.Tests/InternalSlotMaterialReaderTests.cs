using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class InternalSlotMaterialReaderTests
{
    private const uint BootMagicVersion = 4;
    private const uint FlagBase = 1;
    private const uint FlagExec = 4;
    private const uint FlagHasDtb = 8;
    private const uint TypeLinux = 1;
    private const uint TypeShim = 3;
    private const uint TypeBlob = 4;
    private const uint TypeDtb = 5;
    private const uint ManifestMagic = 0x464D504B;
    private const uint BootPage = 4096;
    private const uint KnownAblBytes = 1048576;
    private const uint KnownXblBytes = 352256;
    private const long KnownRoom = 254713856;

    private static readonly byte[] Arm64Magic = { (byte)'A', (byte)'R', (byte)'M', 0x64 };
    private static readonly byte[] BootRamdisk = RepeatText("BOOT-RAMDISK-BYTES", 6);
    private static readonly byte[] VendorRamdisk = RepeatText("VENDOR-RAMDISK-BYTES", 5);

    // ------------------------------------------------------------ fixtures

    private static byte[] Repeat(byte value, int count)
    {
        byte[] result = new byte[count];
        Array.Fill(result, value);
        return result;
    }

    private static byte[] RepeatText(string text, int times)
    {
        byte[] unit = Encoding.ASCII.GetBytes(text);
        byte[] result = new byte[unit.Length * times];
        for (int i = 0; i < times; i++)
        {
            Buffer.BlockCopy(unit, 0, result, i * unit.Length, unit.Length);
        }
        return result;
    }

    private static byte[] Ascii(string text) => Encoding.ASCII.GetBytes(text);

    private static byte[] MakeArm64(
        int size = 320,
        uint code0 = 0x14000100,
        uint code1 = 0,
        long? imageSize = null,
        ulong textOffset = 0x80000,
        ulong flags = 0x0A000000,
        byte[]? magic = null,
        ulong res2 = 0,
        ulong res3 = 0,
        ulong res4 = 0)
    {
        byte[] buffer = new byte[size];
        W32(buffer, 0, code0);
        W32(buffer, 4, code1);
        W64(buffer, 8, textOffset);
        W64(buffer, 16, (ulong)(imageSize ?? size));
        W64(buffer, 24, flags);
        W64(buffer, 32, res2);
        W64(buffer, 40, res3);
        W64(buffer, 48, res4);
        (magic ?? Arm64Magic).CopyTo(buffer, 56);
        return buffer;
    }

    private static byte[] MakeBoot(
        byte[]? kernel = null,
        byte[]? ramdisk = null,
        byte[]? signature = null,
        byte[]? magic = null,
        uint version = BootMagicVersion,
        int headerSize = 1584,
        int? headerSizeField = null,
        int page = 4096,
        int? kernelSize = null,
        int? ramdiskSize = null,
        int? signatureSize = null)
    {
        kernel ??= Array.Empty<byte>();
        ramdisk ??= Array.Empty<byte>();
        signature ??= Array.Empty<byte>();
        headerSize = Math.Max(headerSize, 1584);
        byte[] header = new byte[headerSize];
        (magic ?? Ascii("ANDROID!")).CopyTo(header, 0);
        W32(header, 8, (uint)(kernelSize ?? kernel.Length));
        W32(header, 12, (uint)(ramdiskSize ?? ramdisk.Length));
        W32(header, 20, (uint)(headerSizeField ?? headerSize));
        W32(header, 40, version);
        W32(header, 1580, (uint)(signatureSize ?? signature.Length));

        using var output = new MemoryStream();
        output.Write(header);
        PadToPage(output, page);
        output.Write(kernel);
        PadToPage(output, page);
        output.Write(ramdisk);
        PadToPage(output, page);
        output.Write(signature);
        return output.ToArray();
    }

    private static byte[] MakeVendor(
        byte[]? ramdisk = null,
        byte[]? dtb = null,
        byte[]? table = null,
        byte[]? bootconfig = null,
        int page = 4096,
        int headerSize = 2128,
        int? headerSizeField = null,
        uint version = 4,
        uint count = 0,
        uint entrySize = 0,
        byte[]? magic = null,
        int? ramdiskSize = null,
        int? tableSize = null)
    {
        ramdisk ??= Array.Empty<byte>();
        dtb ??= Array.Empty<byte>();
        table ??= Array.Empty<byte>();
        bootconfig ??= Array.Empty<byte>();
        headerSize = Math.Max(headerSize, 2128);
        byte[] header = new byte[headerSize];
        (magic ?? Ascii("VNDRBOOT")).CopyTo(header, 0);
        W32(header, 8, version);
        W32(header, 12, (uint)page);
        W32(header, 24, (uint)(ramdiskSize ?? ramdisk.Length));
        W32(header, 2096, (uint)(headerSizeField ?? headerSize));
        W32(header, 2100, (uint)dtb.Length);
        W32(header, 2112, (uint)(tableSize ?? table.Length));
        W32(header, 2116, count);
        W32(header, 2120, entrySize);
        W32(header, 2124, (uint)bootconfig.Length);

        using var output = new MemoryStream();
        output.Write(header);
        PadToPage(output, page);
        output.Write(ramdisk);
        PadToPage(output, page);
        output.Write(dtb);
        PadToPage(output, page);
        output.Write(table);
        PadToPage(output, page);
        output.Write(bootconfig);
        return output.ToArray();
    }

    private static void PadToPage(MemoryStream output, int page)
    {
        long remainder = output.Length % page;
        if (remainder != 0)
        {
            output.Write(new byte[page - remainder]);
        }
    }

    private sealed class Spec
    {
        public string Name = "e";
        public uint Type = TypeLinux;
        public uint Flags;
        public byte[] Payload = Array.Empty<byte>();
        public int? Offset;
        public int? Size;
        public int? Share;
        public int? RecordSize;
        public byte[]? Pad;
        public ulong Load;
        public uint Entry;
        public uint Dtb;
        public uint Align = 2;
        public ulong Copy;
    }

    private static List<Spec> DefaultSpecs(byte[] baseImage) => new()
    {
        new Spec { Name = "base", Type = TypeLinux, Flags = FlagBase | FlagExec, Payload = baseImage },
        new Spec { Name = "shim", Type = TypeShim, Flags = FlagExec, Payload = Repeat((byte)'S', 64) },
        new Spec { Name = "linux", Type = TypeLinux, Flags = FlagExec | FlagHasDtb, Dtb = 3, Payload = Repeat((byte)'L', 32) },
        new Spec { Name = "dtb", Type = TypeDtb, Flags = 0, Payload = Repeat((byte)'D', 32) },
        new Spec { Name = "blob", Type = TypeBlob, Flags = 0, Payload = Repeat((byte)'B', 32) },
    };

    private static (byte[] Image, List<(int Offset, int Size)> Positions) MakeKshim(
        IReadOnlyList<Spec> specs,
        ushort vmajor = 0,
        ushort vminor = 1,
        uint defaultIndex = 0,
        int? count = null,
        uint manifestMagic = ManifestMagic,
        int msizeExtra = 0,
        int moffDelta = 0,
        byte[]? tail = null,
        uint? w0 = null,
        uint? w1 = null,
        ulong[]? backup = null,
        long? imageSize = null,
        byte[]? tableExtra = null)
    {
        var positions = new List<(int Offset, int Size)>();
        int cursor = 0;
        foreach (Spec spec in specs)
        {
            int offset;
            int size;
            if (spec.Share is int share)
            {
                (offset, size) = positions[share];
            }
            else
            {
                offset = spec.Offset ?? Align4(cursor);
                size = spec.Size ?? spec.Payload.Length;
            }
            positions.Add((offset, size));
            cursor = Math.Max(cursor, offset + size);
        }

        int manifestOffset = Align4(cursor) + moffDelta;
        byte[] basePayload = specs[0].Payload;
        ulong[] backupValues = backup ?? new ulong[5];
        if (backup is null)
        {
            backupValues[0] = R64(basePayload, 0);
            backupValues[1] = R64(basePayload, 16);
            backupValues[2] = R64(basePayload, 32);
            backupValues[3] = R64(basePayload, 40);
            backupValues[4] = R64(basePayload, 48);
        }

        using var tableStream = new MemoryStream();
        for (int i = 0; i < specs.Count; i++)
        {
            Spec spec = specs[i];
            (int offset, int size) = positions[i];
            byte[] name = Encoding.UTF8.GetBytes(spec.Name);
            int padLength = (4 - ((56 + name.Length) % 4)) % 4;
            byte[] pad = spec.Pad ?? new byte[padLength];
            byte[] record = new byte[56 + name.Length + pad.Length];
            W64(record, 0, (ulong)offset);
            W64(record, 8, (ulong)(spec.RecordSize ?? size));
            W32(record, 16, spec.Type);
            W32(record, 20, spec.Flags);
            W64(record, 24, spec.Load);
            W32(record, 32, spec.Entry);
            W32(record, 36, spec.Dtb);
            W32(record, 40, spec.Align);
            W64(record, 44, spec.Copy);
            W32(record, 52, (uint)name.Length);
            name.CopyTo(record, 56);
            pad.CopyTo(record, 56 + name.Length);
            tableStream.Write(record);
        }
        if (tableExtra is not null)
        {
            tableStream.Write(tableExtra);
        }
        byte[] table = tableStream.ToArray();

        uint entryCount = (uint)(count ?? specs.Count);
        byte[] manifest = new byte[60 + table.Length];
        W32(manifest, 0, manifestMagic);
        W16(manifest, 4, vmajor);
        W16(manifest, 6, vminor);
        W32(manifest, 8, entryCount);
        W32(manifest, 12, defaultIndex);
        W32(manifest, 16, 1000);
        for (int i = 0; i < 5; i++)
        {
            W64(manifest, 20 + i * 8, backupValues[i]);
        }
        table.CopyTo(manifest, 60);
        int manifestSize = manifest.Length + msizeExtra;

        byte[] tailBytes = tail ?? Array.Empty<byte>();
        int total = manifestOffset + manifest.Length + tailBytes.Length;
        byte[] buffer = new byte[total];
        for (int i = 0; i < specs.Count; i++)
        {
            byte[] payload = specs[i].Payload;
            if (payload.Length != 0)
            {
                Buffer.BlockCopy(payload, 0, buffer, positions[i].Offset, payload.Length);
            }
        }

        int shimOffset = positions.Count > 1 ? positions[1].Offset : 0;
        uint word0 = w0 ?? (0x94000000u | ((uint)(shimOffset >> 2) & 0x03FFFFFFu));
        uint word1;
        if (w1 is uint explicitWord1)
        {
            word1 = explicitWord1;
        }
        else
        {
            uint original0 = (uint)(backupValues[0] & 0xFFFFFFFF);
            uint original1 = (uint)(backupValues[0] >> 32);
            word1 = (original0 & 0xFC000000) == 0x14000000 &&
                    (original1 & 0xFC000000) != 0x14000000
                ? 0x14000000u | ((original0 - 1) & 0x03FFFFFFu)
                : original1;
        }

        W32(buffer, 0, word0);
        W32(buffer, 4, word1);
        W64(buffer, 16, (ulong)(imageSize ?? total));
        W64(buffer, 32, (ulong)manifestOffset);
        W64(buffer, 40, (ulong)manifestSize);
        W64(buffer, 48, (ulong)shimOffset);
        manifest.CopyTo(buffer, manifestOffset);
        tailBytes.CopyTo(buffer, manifestOffset + manifest.Length);
        return (buffer, positions);
    }

    private static byte[] Gzip(byte[] raw)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            gzip.Write(raw);
        }
        return output.ToArray();
    }

    private static byte[] RawDeflate(byte[] raw)
    {
        using var output = new MemoryStream();
        using (var deflate = new DeflateStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            deflate.Write(raw);
        }
        return output.ToArray();
    }

    private static byte[] BuildOptionalGzip(byte[] raw, bool corruptHeaderCrc)
    {
        byte[] deflate = RawDeflate(raw);
        using var output = new MemoryStream();
        output.Write(new byte[] { 0x1F, 0x8B, 8, 0x1E });
        output.Write(new byte[4]);
        output.WriteByte(0);
        output.WriteByte(255);
        W16(output, 4);
        output.Write(new byte[] { 1, 2, 3, 4 });
        output.Write(Ascii("kernel.bin\0"));
        output.Write(Ascii("synthetic\0"));
        ushort headerCrc = (ushort)Crc32(output.ToArray());
        if (corruptHeaderCrc)
        {
            headerCrc ^= 1;
        }
        W16(output, headerCrc);
        output.Write(deflate);
        W32(output, Crc32(raw));
        W32(output, (uint)raw.Length);
        return output.ToArray();
    }

    // ------------------------------------------------------------- workdir

    private sealed class WorkDir : IDisposable
    {
        public WorkDir()
        {
            string? root = Environment.GetEnvironmentVariable("EDL_CLIENT_TEST_WORK_ROOT");
            if (string.IsNullOrWhiteSpace(root))
            {
                throw new InvalidOperationException(
                    "EDL_CLIENT_TEST_WORK_ROOT must name an existing test work root.");
            }
            Dir = Path.Combine(root, "smc001-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Dir);
        }

        public string Dir { get; }

        public VerifiedEdlFile Claim(
            string name, byte[] bytes, long? length = null, string? sha256 = null)
        {
            string path = Path.Combine(Dir, name);
            File.WriteAllBytes(path, bytes);
            return new VerifiedEdlFile(
                path, length ?? bytes.LongLength, sha256 ?? ShaHex(bytes));
        }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Dir, true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private static Task<InternalSlotMaterial> ResolveAsync(
        WorkDir work,
        byte[] kernel,
        string slot = "a",
        byte[]? current = null,
        byte[]? vendor = null,
        byte[]? init = null,
        byte[]? abl = null,
        byte[]? xbl = null)
    {
        byte[] currentBytes = current ?? MakeBoot(
            kernel: kernel, ramdisk: BootRamdisk, signature: Repeat((byte)'S', 21));
        byte[] vendorBytes = vendor ?? MakeVendor(ramdisk: VendorRamdisk);
        byte[] initBytes = init ?? MakeBoot(
            kernel: Array.Empty<byte>(), ramdisk: Array.Empty<byte>(),
            signature: Ascii("initsig"));
        byte[] ablBytes = abl ?? Ascii("abl-unknown-bytes");
        byte[] xblBytes = xbl ?? Ascii("xbl-config-unknown-bytes");
        return InternalSlotMaterialReader.AnalyzeAsync(
            slot,
            work.Claim("current.img", currentBytes),
            work.Claim("vendor.img", vendorBytes),
            work.Claim("init.img", initBytes),
            work.Claim("abl.bin", ablBytes),
            work.Claim("xbl.bin", xblBytes));
    }

    // --------------------------------------------------------------- tests

    [Fact]
    public async Task PlainKernelReturnsExactByteIdentityAndMetadata()
    {
        using var work = new WorkDir();
        byte[] kernel = MakeArm64(512);
        InternalSlotMaterial material = await ResolveAsync(work, kernel);

        Assert.Equal("a", material.Slot);
        Assert.False(material.IsKshim);
        Assert.Equal(kernel.LongLength, material.BaseImageLength);
        Assert.Equal(512L, material.BaseImageSize);
        Assert.Equal(0x80000UL, material.BaseTextOffset);
        Assert.Equal(ShaHex(kernel), material.BaseImageSha256);
        Assert.Equal(BootRamdisk.Length, material.BootRamdiskSize);
        Assert.Equal(VendorRamdisk.Length, material.VendorRamdiskSize);
        Assert.Equal(0, material.InitRamdiskSize);
        Assert.Equal(BootRamdisk.Length + VendorRamdisk.Length, material.TotalRamdiskSize);
        Assert.Equal(4096, material.PageSize);
        Assert.Equal(134217728, material.LoaderBudget.MaxRawBytes);
        Assert.False(material.LoaderBudget.KnownLoaderMatch);
        Assert.Equal("conservative-default", material.LoaderBudget.Profile);
        Assert.False(material.OemSignedRestored);
        Assert.Equal("android-arm64-kernel-only", material.RecoveryScope);
        Assert.False(material.SignatureVerificationPerformed);
        Assert.Equal(5, material.SourceSha256.Count);
        Assert.Equal(5, material.SourceLengths.Count);
    }

    [Fact]
    public async Task PlainKernelRetainsTailBeyondImageSize()
    {
        using var work = new WorkDir();
        byte[] kernel = MakeArm64(400, imageSize: 128);
        Assert.True(kernel.Length > 128);
        InternalSlotMaterial material = await ResolveAsync(work, kernel);

        Assert.Equal(400, material.BaseImageLength);
        Assert.Equal(128L, material.BaseImageSize);
        Assert.Equal(ShaHex(kernel), material.BaseImageSha256);
        Assert.False(material.IsKshim);
    }

    [Fact]
    public async Task GzipPlainKernelMatchesDecompressedBytes()
    {
        using var work = new WorkDir();
        byte[] raw = MakeArm64(700);
        InternalSlotMaterial material = await ResolveAsync(work, Gzip(raw));

        Assert.Equal(raw.LongLength, material.BaseImageLength);
        Assert.Equal(ShaHex(raw), material.BaseImageSha256);
        Assert.False(material.IsKshim);
    }

    [Fact]
    public async Task InvalidArm64HeadersRejected()
    {
        var cases = new (string Name, byte[] Kernel)[]
        {
            ("short", new byte[32]),
            ("qc-wrapper", Concat(Ascii("UNCOMPRESSED_IMG"), new byte[200])),
            ("bad-magic", MakeArm64(128, magic: Ascii("XXXX"))),
            ("small-image-size", MakeArm64(320, imageSize: 32)),
            ("huge-image-size", MakeArm64(320, imageSize: 200 * 1024 * 1024)),
        };
        foreach ((string name, byte[] kernel) in cases)
        {
            using var work = new WorkDir();
            await Assert.ThrowsAsync<InvalidDataException>(
                () => ResolveAsync(work, kernel));
            Assert.NotEqual(string.Empty, name);
        }
    }

    [Fact]
    public async Task RawKshimRestoresOriginalBaseAndFiveBackupWords()
    {
        using var work = new WorkDir();
        byte[] baseImage = MakeArm64(320);
        (byte[] raw, List<(int Offset, int Size)> positions) =
            MakeKshim(DefaultSpecs(baseImage));
        InternalSlotMaterial material = await ResolveAsync(work, raw);

        Assert.True(material.IsKshim);
        Assert.Equal(baseImage.LongLength, material.BaseImageLength);
        Assert.Equal(ShaHex(baseImage), material.BaseImageSha256);
        Assert.True(positions[1].Offset > 0);
        Assert.Equal(ShaHex(baseImage), material.BaseImageSha256.ToLowerInvariant());
    }

    [Theory]
    [InlineData(0UL)]
    [InlineData(0x8000000000080000UL)]
    public async Task KshimReportsRecoveredBaseHeaderFacts(ulong textOffset)
    {
        using var work = new WorkDir();
        byte[] baseImage = MakeArm64(320, imageSize: 512, textOffset: textOffset);
        (byte[] raw, _) = MakeKshim(DefaultSpecs(baseImage));
        InternalSlotMaterial material = await ResolveAsync(work, raw);

        Assert.True(material.IsKshim);
        Assert.Equal(320, material.BaseImageLength);
        Assert.Equal(512L, material.BaseImageSize);
        Assert.Equal(textOffset, material.BaseTextOffset);
        Assert.Equal(ShaHex(baseImage), material.BaseImageSha256);
    }

    [Fact]
    public async Task GzipKshimRestoresOriginalBase()
    {
        using var work = new WorkDir();
        byte[] baseImage = MakeArm64(320);
        (byte[] raw, _) = MakeKshim(DefaultSpecs(baseImage));
        InternalSlotMaterial material = await ResolveAsync(work, Gzip(raw));

        Assert.True(material.IsKshim);
        Assert.Equal(ShaHex(baseImage), material.BaseImageSha256);
    }

    [Fact]
    public async Task SlotsProduceIndependentResults()
    {
        byte[] baseA = MakeArm64(320);
        byte[] baseB = MakeArm64(448, code0: 0x14000200);
        (byte[] rawA, _) = MakeKshim(DefaultSpecs(baseA));
        (byte[] rawB, _) = MakeKshim(DefaultSpecs(baseB));

        using var workA = new WorkDir();
        using var workB = new WorkDir();
        InternalSlotMaterial materialA = await ResolveAsync(workA, rawA, slot: "a");
        InternalSlotMaterial materialB = await ResolveAsync(workB, rawB, slot: "b");

        Assert.Equal("a", materialA.Slot);
        Assert.Equal("b", materialB.Slot);
        Assert.Equal(ShaHex(baseA), materialA.BaseImageSha256);
        Assert.Equal(ShaHex(baseB), materialB.BaseImageSha256);
        Assert.NotEqual(materialA.BaseImageSha256, materialB.BaseImageSha256);
    }

    [Fact]
    public async Task ExactAliasBetweenExecutableLinuxEntriesAllowed()
    {
        using var work = new WorkDir();
        byte[] baseImage = MakeArm64(320);
        List<Spec> specs = DefaultSpecs(baseImage);
        specs.Add(new Spec
        {
            Name = "linux-alias", Type = TypeLinux, Flags = FlagExec, Share = 2,
        });
        (byte[] raw, _) = MakeKshim(specs);
        InternalSlotMaterial material = await ResolveAsync(work, raw);

        Assert.Equal(ShaHex(baseImage), material.BaseImageSha256);
        Assert.True(material.IsKshim);
    }

    [Fact]
    public async Task ExactAliasOutsideLinuxPairRejected()
    {
        var extras = new (string Name, Spec Spec)[]
        {
            ("blob-shares-linux", new Spec
            {
                Name = "blob-alias", Type = TypeBlob, Flags = 0, Share = 2,
            }),
            ("dtb-shares-shim", new Spec
            {
                Name = "dtb-alias", Type = TypeDtb, Flags = 0, Share = 1,
            }),
        };
        foreach ((string name, Spec extra) in extras)
        {
            using var work = new WorkDir();
            byte[] baseImage = MakeArm64(320);
            List<Spec> specs = DefaultSpecs(baseImage);
            specs.Add(extra);
            (byte[] raw, _) = MakeKshim(specs);
            InvalidDataException error = await Assert.ThrowsAsync<InvalidDataException>(
                () => ResolveAsync(work, raw));
            Assert.Contains("exact interval", error.Message);
            Assert.NotEqual(string.Empty, name);
        }
    }

    [Fact]
    public async Task PartialAliasAndBaseOverlapRejected()
    {
        byte[] baseImage = MakeArm64(320);
        int linuxOffset = Align4(Align4(baseImage.Length) + 64);
        var cases = new (string Name, Spec Spec)[]
        {
            ("partial-alias", new Spec
            {
                Name = "linux-alias", Type = TypeLinux, Flags = FlagExec,
                Offset = linuxOffset + 4, Size = 20,
            }),
            ("base-overlap", new Spec
            {
                Name = "intruder", Type = TypeBlob, Flags = 0, Offset = 8, Size = 16,
            }),
        };
        foreach ((string name, Spec extra) in cases)
        {
            using var work = new WorkDir();
            List<Spec> specs = DefaultSpecs(baseImage);
            specs.Add(extra);
            (byte[] raw, _) = MakeKshim(specs);
            await Assert.ThrowsAsync<InvalidDataException>(() => ResolveAsync(work, raw));
            Assert.NotEqual(string.Empty, name);
        }
    }

    [Fact]
    public async Task NestedRecoveredKshimRejected()
    {
        using var work = new WorkDir();
        byte[] baseImage = MakeArm64(320);
        ulong[] backup = new ulong[5];
        backup[0] = R64(baseImage, 0);
        backup[1] = R64(baseImage, 16);
        backup[2] = 0x1000;
        backup[3] = R64(baseImage, 40);
        backup[4] = R64(baseImage, 48);
        (byte[] raw, _) = MakeKshim(DefaultSpecs(baseImage), backup: backup);

        await Assert.ThrowsAsync<InvalidDataException>(() => ResolveAsync(work, raw));
    }

    [Fact]
    public async Task ManifestHeaderMutationsRejected()
    {
        string[] names =
        {
            "magic", "vmajor", "vminor", "count-zero", "default-range",
            "size-past-end", "trailing-bytes", "count-past-table",
            "damaged-magic-bytes",
        };
        foreach (string name in names)
        {
            using var work = new WorkDir();
            byte[] baseImage = MakeArm64(320);
            List<Spec> specs = DefaultSpecs(baseImage);
            byte[] raw = name switch
            {
                "magic" => MakeKshim(specs, manifestMagic: 0).Image,
                "vmajor" => MakeKshim(specs, vmajor: 1).Image,
                "vminor" => MakeKshim(specs, vminor: 2).Image,
                "count-zero" => MakeKshim(specs, count: 0).Image,
                "default-range" => MakeKshim(specs, defaultIndex: 9).Image,
                "size-past-end" => MakeKshim(specs, msizeExtra: 4).Image,
                "trailing-bytes" => MakeKshim(specs, tail: new byte[8]).Image,
                "count-past-table" => MakeKshim(specs, count: 6).Image,
                "damaged-magic-bytes" => MakeKshim(specs).Image,
                _ => throw new InvalidOperationException(name),
            };
            if (name == "damaged-magic-bytes")
            {
                int offset = (int)R64(raw, 32);
                raw[offset] = 0xDE;
                raw[offset + 1] = 0xAD;
                raw[offset + 2] = 0xBE;
                raw[offset + 3] = 0xEF;
            }
            await Assert.ThrowsAsync<InvalidDataException>(() => ResolveAsync(work, raw));
        }
    }

    [Fact]
    public async Task EntryPayloadPastManifestRejected()
    {
        using var work = new WorkDir();
        byte[] baseImage = MakeArm64(320);
        List<Spec> specs = DefaultSpecs(baseImage);
        specs.Add(new Spec
        {
            Name = "oversize", Type = TypeBlob, Flags = 0,
            Payload = Repeat((byte)'E', 32), RecordSize = 4096,
        });
        (byte[] raw, _) = MakeKshim(specs);

        await Assert.ThrowsAsync<InvalidDataException>(() => ResolveAsync(work, raw));
    }

    [Fact]
    public async Task EntryCountAndAlignmentLimitsRejected()
    {
        using (var work = new WorkDir())
        {
            byte[] baseImage = MakeArm64(320);
            List<Spec> specs = DefaultSpecs(baseImage);
            for (int i = 0; i < 46; i++)
            {
                specs.Add(new Spec
                {
                    Name = "blob" + i, Type = TypeBlob, Flags = 0,
                    Payload = Repeat((byte)'Z', 32),
                });
            }
            Assert.Equal(51, specs.Count);
            (byte[] raw, _) = MakeKshim(specs);
            await Assert.ThrowsAsync<InvalidDataException>(() => ResolveAsync(work, raw));
        }

        foreach (uint align in new uint[] { 1, 22 })
        {
            using var work = new WorkDir();
            byte[] baseImage = MakeArm64(320);
            List<Spec> specs = DefaultSpecs(baseImage);
            specs[0].Align = align;
            (byte[] raw, _) = MakeKshim(specs);
            await Assert.ThrowsAsync<InvalidDataException>(() => ResolveAsync(work, raw));
        }
    }

    [Fact]
    public async Task BaseEntryMutationsRejected()
    {
        var cases = new (string Name, Action<Spec> Mutate)[]
        {
            ("no-base", spec => spec.Flags = FlagExec),
            ("no-exec", spec => spec.Flags = FlagBase),
            ("wrong-type", spec => spec.Type = TypeBlob),
            ("has-dtb", spec => spec.Flags = FlagBase | FlagExec | FlagHasDtb),
            ("qc-flag", spec => spec.Flags = FlagBase | FlagExec | 16),
            ("copy-flag", spec => spec.Flags = FlagBase | FlagExec | 2),
            ("unknown-flag", spec => spec.Flags = FlagBase | FlagExec | 32),
        };
        foreach ((string name, Action<Spec> mutate) in cases)
        {
            using var work = new WorkDir();
            byte[] baseImage = MakeArm64(320);
            List<Spec> specs = DefaultSpecs(baseImage);
            mutate(specs[0]);
            (byte[] raw, _) = MakeKshim(specs);
            await Assert.ThrowsAsync<InvalidDataException>(() => ResolveAsync(work, raw));
            Assert.NotEqual(string.Empty, name);
        }

        using (var work = new WorkDir())
        {
            byte[] baseImage = MakeArm64(320);
            List<Spec> specs = DefaultSpecs(baseImage);
            specs.Add(new Spec
            {
                Name = "base2", Type = TypeLinux, Flags = FlagBase | FlagExec,
                Payload = Repeat((byte)'X', 64),
            });
            (byte[] raw, _) = MakeKshim(specs);
            await Assert.ThrowsAsync<InvalidDataException>(() => ResolveAsync(work, raw));
        }
    }

    [Fact]
    public async Task NonZeroNamePaddingRejected()
    {
        using var work = new WorkDir();
        byte[] baseImage = MakeArm64(320);
        List<Spec> specs = DefaultSpecs(baseImage);
        specs[0].Name = "base12";
        specs[0].Pad = new byte[] { 1, 2 };
        (byte[] raw, _) = MakeKshim(specs);

        await Assert.ThrowsAsync<InvalidDataException>(() => ResolveAsync(work, raw));
    }

    [Fact]
    public async Task ShimEntryMutationsRejected()
    {
        byte[] baseImage = MakeArm64(320);
        int shimOffset;
        {
            (byte[] _, List<(int Offset, int Size)> positions) =
                MakeKshim(DefaultSpecs(baseImage));
            shimOffset = positions[1].Offset;
        }
        Assert.True(shimOffset > 0);

        var wordCases = new (string Name, uint? W0, uint? W1)[]
        {
            ("bad-bl-target",
               0x94000000u | (((uint)(shimOffset + 4) >> 2) & 0x03FFFFFFu), null),
            ("not-bl", 0x14000000u, null),
            ("bad-word1", null, 0x14000000u),
        };
        foreach ((string name, uint? w0, uint? w1) in wordCases)
        {
            using var work = new WorkDir();
            (byte[] raw, _) = MakeKshim(DefaultSpecs(baseImage), w0: w0, w1: w1);
            await Assert.ThrowsAsync<InvalidDataException>(() => ResolveAsync(work, raw));
            Assert.NotEqual(string.Empty, name);
        }

        using (var work = new WorkDir())
        {
            List<Spec> specs = DefaultSpecs(baseImage);
            specs[1].Type = TypeBlob;
            (byte[] raw, _) = MakeKshim(specs);
            await Assert.ThrowsAsync<InvalidDataException>(() => ResolveAsync(work, raw));
        }

        using (var work = new WorkDir())
        {
            List<Spec> specs = DefaultSpecs(baseImage);
            specs[1].Payload = Array.Empty<byte>();
            specs[1].Size = 0;
            (byte[] raw, _) = MakeKshim(specs);
            await Assert.ThrowsAsync<InvalidDataException>(() => ResolveAsync(work, raw));
        }
    }

    [Fact]
    public async Task DtbReferenceMutationsRejected()
    {
        foreach (uint reference in new uint[] { 9, 4 })
        {
            using var work = new WorkDir();
            byte[] baseImage = MakeArm64(320);
            List<Spec> specs = DefaultSpecs(baseImage);
            specs[2].Dtb = reference;
            (byte[] raw, _) = MakeKshim(specs);
            await Assert.ThrowsAsync<InvalidDataException>(() => ResolveAsync(work, raw));
        }
    }

    [Fact]
    public async Task BootHeaderMutationsRejected()
    {
        byte[] kernel = MakeArm64(320);
        var cases = new (string Name, byte[] Current)[]
        {
            ("magic", MakeBoot(kernel: kernel, magic: Ascii("NOTMAGIC"))),
            ("version", MakeBoot(kernel: kernel, version: 3)),
            ("header-size", MakeBoot(kernel: kernel, headerSizeField: 1583)),
            ("short", Concat(Ascii("ANDROID!"), new byte[100])),
            ("empty-kernel", MakeBoot(kernel: Array.Empty<byte>())),
        };
        foreach ((string name, byte[] current) in cases)
        {
            using var work = new WorkDir();
            await Assert.ThrowsAsync<InvalidDataException>(
                () => ResolveAsync(work, kernel, current: current));
            Assert.NotEqual(string.Empty, name);
        }
    }

    [Fact]
    public async Task BootRegionTruncationRejected()
    {
        using var work = new WorkDir();
        byte[] kernel = MakeArm64(320);
        byte[] current = MakeBoot(
            kernel: kernel, ramdisk: BootRamdisk, signature: Repeat((byte)'S', 16));
        await Assert.ThrowsAsync<InvalidDataException>(
            () => ResolveAsync(work, kernel, current: current[..^1]));
    }

    [Fact]
    public async Task InitBootRequiresZeroKernel()
    {
        using var work = new WorkDir();
        byte[] init = MakeBoot(kernel: MakeArm64(64), ramdisk: Array.Empty<byte>());
        await Assert.ThrowsAsync<InvalidDataException>(
            () => ResolveAsync(work, MakeArm64(320), init: init));
    }

    [Fact]
    public void SlotAndArgumentValidation()
    {
        using var work = new WorkDir();
        VerifiedEdlFile dummy = new(Path.Combine(work.Dir, "missing"), 0, new string('0', 64));

        Assert.Throws<ArgumentException>(() =>
        {
            _ = InternalSlotMaterialReader.AnalyzeAsync("c", dummy, dummy, dummy, dummy, dummy);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            _ = InternalSlotMaterialReader.AnalyzeAsync("A", dummy, dummy, dummy, dummy, dummy);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            _ = InternalSlotMaterialReader.AnalyzeAsync(
                string.Empty, dummy, dummy, dummy, dummy, dummy);
        });
        Assert.ThrowsAny<ArgumentException>(() =>
        {
            _ = InternalSlotMaterialReader.AnalyzeAsync("a", null!, dummy, dummy, dummy, dummy);
        });
        Assert.ThrowsAny<ArgumentException>(() =>
        {
            _ = InternalSlotMaterialReader.AnalyzeAsync("a", dummy, dummy, dummy, dummy, null!);
        });
    }

    [Fact]
    public async Task VendorHeaderMutationsRejected()
    {
        var cases = new (string Name, byte[] Vendor)[]
        {
            ("magic", MakeVendor(magic: Ascii("NOTVENDOR"))),
            ("version", MakeVendor(version: 3)),
            ("page-small", MakeVendor(page: 3000)),
            ("page-large", MakeVendor(page: 131072)),
            ("page-not-power-of-two", MakeVendor(page: 12288)),
            ("header-size-field", MakeVendor(headerSizeField: 2127)),
            ("short", Concat(Ascii("VNDRBOOT"), new byte[100])),
        };
        foreach ((string name, byte[] vendor) in cases)
        {
            using var work = new WorkDir();
            await Assert.ThrowsAsync<InvalidDataException>(
                () => ResolveAsync(work, MakeArm64(320), vendor: vendor));
            Assert.NotEqual(string.Empty, name);
        }
    }

    [Fact]
    public async Task VendorTableCombinationsRejected()
    {
        var cases = new (string Name, byte[] Vendor)[]
        {
            ("empty-count-nonempty-table",
                MakeVendor(table: new byte[64], count: 0, entrySize: 0)),
            ("empty-count-bad-entry-size",
                MakeVendor(table: Array.Empty<byte>(), count: 0, entrySize: 64)),
            ("count-with-empty-table",
                MakeVendor(table: Array.Empty<byte>(), count: 1, entrySize: 0)),
            ("entry-size-too-small",
                MakeVendor(table: new byte[64], count: 1, entrySize: 64)),
            ("count-times-entry-too-big",
                MakeVendor(table: new byte[128], count: 2, entrySize: 108)),
        };
        foreach ((string name, byte[] vendor) in cases)
        {
            using var work = new WorkDir();
            await Assert.ThrowsAsync<InvalidDataException>(
                () => ResolveAsync(work, MakeArm64(320), vendor: vendor));
            Assert.NotEqual(string.Empty, name);
        }
    }

    [Fact]
    public async Task VendorEmptyTableWithRealEntrySizeAccepted()
    {
        using var work = new WorkDir();
        byte[] kernel = MakeArm64(320);
        byte[] vendor = MakeVendor(ramdisk: VendorRamdisk, count: 0, entrySize: 108);
        InternalSlotMaterial material = await ResolveAsync(work, kernel, vendor: vendor);

        Assert.Equal(ShaHex(kernel), material.BaseImageSha256);
        Assert.Equal(VendorRamdisk.Length, material.VendorRamdiskSize);
        Assert.Equal(
            BootRamdisk.Length + VendorRamdisk.Length,
            material.TotalRamdiskSize);
        Assert.Equal(134217728, material.LoaderBudget.MaxRawBytes);
    }

    [Fact]
    public async Task VendorPage8192DrivesPageAndBudget()
    {
        using var work = new WorkDir();
        byte[] kernel = MakeArm64(320);
        byte[] vendor = MakeVendor(ramdisk: VendorRamdisk, page: 8192);
        InternalSlotMaterial material = await ResolveAsync(work, kernel, vendor: vendor);

        Assert.Equal(ShaHex(kernel), material.BaseImageSha256);
        Assert.Equal(8192, material.PageSize);
        Assert.False(material.LoaderBudget.KnownLoaderMatch);
        Assert.Equal(134217728, material.LoaderBudget.MaxRawBytes);
    }

    [Fact]
    public async Task VendorRegionTruncationRejected()
    {
        using var work = new WorkDir();
        byte[] vendor = MakeVendor(
            ramdisk: VendorRamdisk, dtb: Repeat((byte)'D', 40),
            bootconfig: RepeatText("cfg", 4));
        await Assert.ThrowsAsync<InvalidDataException>(
            () => ResolveAsync(work, MakeArm64(320), vendor: vendor[..^1]));
    }

    [Fact]
    public async Task VendorRamdiskSizeComesFromHeader()
    {
        using var work = new WorkDir();
        byte[] vendor = MakeVendor(ramdisk: VendorRamdisk);
        InternalSlotMaterial material = await ResolveAsync(work, MakeArm64(320), vendor: vendor);

        Assert.Equal(VendorRamdisk.Length, material.VendorRamdiskSize);
        Assert.Equal(
            BootRamdisk.Length + VendorRamdisk.Length,
            material.TotalRamdiskSize);
    }

    [Fact]
    public async Task StaleClaimsRejected()
    {
        byte[] kernel = MakeArm64(320);
        foreach (string mode in new[] { "length", "sha", "format" })
        {
            using var work = new WorkDir();
            byte[] currentBytes = MakeBoot(
                kernel: kernel, ramdisk: BootRamdisk, signature: Repeat((byte)'S', 21));
            VerifiedEdlFile current = mode switch
            {
                "length" => work.Claim(
                    "current.img", currentBytes, length: currentBytes.Length + 1),
                "sha" => work.Claim(
                    "current.img", currentBytes, sha256: new string('0', 64)),
                "format" => work.Claim(
                    "current.img", currentBytes, sha256: new string('z', 64)),
                _ => throw new InvalidOperationException(mode),
            };
            VerifiedEdlFile vendor = work.Claim("vendor.img", MakeVendor(ramdisk: VendorRamdisk));
            VerifiedEdlFile init = work.Claim(
                "init.img", MakeBoot(signature: Ascii("initsig")));
            VerifiedEdlFile abl = work.Claim("abl.bin", Ascii("abl-unknown-bytes"));
            VerifiedEdlFile xbl = work.Claim("xbl.bin", Ascii("xbl-config-unknown-bytes"));

            await Assert.ThrowsAsync<InvalidDataException>(
                () => InternalSlotMaterialReader.AnalyzeAsync(
                    "a", current, vendor, init, abl, xbl));

            using (var probe = new FileStream(
                current.Path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                Assert.True(probe.CanWrite);
            }
        }
    }

    [Fact]
    public async Task ClaimedShaCaseInsensitive()
    {
        using var work = new WorkDir();
        byte[] kernel = MakeArm64(320);
        byte[] currentBytes = MakeBoot(
            kernel: kernel, ramdisk: BootRamdisk, signature: Repeat((byte)'S', 21));
        VerifiedEdlFile current = work.Claim(
            "current.img", currentBytes, sha256: ShaHex(currentBytes).ToUpperInvariant());
        VerifiedEdlFile vendor = work.Claim("vendor.img", MakeVendor(ramdisk: VendorRamdisk));
        VerifiedEdlFile init = work.Claim("init.img", MakeBoot(signature: Ascii("initsig")));
        VerifiedEdlFile abl = work.Claim("abl.bin", Ascii("abl-unknown-bytes"));
        VerifiedEdlFile xbl = work.Claim("xbl.bin", Ascii("xbl-config-unknown-bytes"));

        InternalSlotMaterial material = await InternalSlotMaterialReader.AnalyzeAsync(
            "a", current, vendor, init, abl, xbl);
        Assert.Equal(ShaHex(kernel), material.BaseImageSha256);
    }

    [Fact]
    public async Task SourceHashesAndLengthsCoverAllFiveRoles()
    {
        using var work = new WorkDir();
        byte[] kernel = MakeArm64(320);
        byte[] currentBytes = MakeBoot(
            kernel: kernel, ramdisk: BootRamdisk, signature: Repeat((byte)'S', 21));
        byte[] vendorBytes = MakeVendor(ramdisk: VendorRamdisk);
        byte[] initBytes = MakeBoot(signature: Ascii("initsig"));
        byte[] ablBytes = Ascii("abl-unknown-bytes");
        byte[] xblBytes = Ascii("xbl-config-unknown-bytes");

        InternalSlotMaterial material = await InternalSlotMaterialReader.AnalyzeAsync(
            "a",
            work.Claim("current.img", currentBytes),
            work.Claim("vendor.img", vendorBytes),
            work.Claim("init.img", initBytes),
            work.Claim("abl.bin", ablBytes),
            work.Claim("xbl.bin", xblBytes));

        var expected = new Dictionary<string, byte[]>
        {
            ["current_boot"] = currentBytes,
            ["vendor_boot"] = vendorBytes,
            ["init_boot"] = initBytes,
            ["abl"] = ablBytes,
            ["xbl_config"] = xblBytes,
        };
        foreach ((string role, byte[] bytes) in expected)
        {
            Assert.Equal(ShaHex(bytes), material.SourceSha256[role]);
            Assert.Equal(bytes.LongLength, material.SourceLengths[role]);
            Assert.Equal(ShaHex(bytes).ToLowerInvariant(), material.SourceSha256[role]);
        }
    }

    [Fact]
    public async Task ResultDictionariesAreReadOnlyCopies()
    {
        using var work = new WorkDir();
        InternalSlotMaterial material = await ResolveAsync(work, MakeArm64(320));

        var sha = Assert.IsAssignableFrom<IDictionary<string, string>>(material.SourceSha256);
        var lengths = Assert.IsAssignableFrom<IDictionary<string, long>>(material.SourceLengths);
        Assert.Throws<NotSupportedException>(() => { sha["extra"] = "value"; });
        Assert.Throws<NotSupportedException>(() => { lengths["extra"] = 1; });
        Assert.Equal(5, material.SourceSha256.Count);
        Assert.Equal(5, material.SourceLengths.Count);
    }

    [Fact]
    public async Task InvalidGzipStreamsRejected()
    {
        var cases = new (string Name, byte[] Kernel)[]
        {
            ("too-short", new byte[] { 0x1F, 0x8B }),
            ("bad-method", Concat(new byte[] { 0x1F, 0x8B, 0x09 }, new byte[20])),
            ("reserved-flag", new byte[] { 0x1F, 0x8B, 8, 0x20, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0 }),
            ("bad-deflate", Concat(new byte[] { 0x1F, 0x8B, 8, 0 }, new byte[20])),
        };
        foreach ((string name, byte[] kernel) in cases)
        {
            using var work = new WorkDir();
            await Assert.ThrowsAsync<InvalidDataException>(() => ResolveAsync(work, kernel));
            Assert.NotEqual(string.Empty, name);
        }
    }

    [Fact]
    public async Task TruncatedGzipTrailerRejected()
    {
        byte[] payload = Gzip(MakeArm64(400));
        foreach (byte[] kernel in new[] { payload[..^8], payload[..^1] })
        {
            using var work = new WorkDir();
            await Assert.ThrowsAsync<InvalidDataException>(() => ResolveAsync(work, kernel));
        }
    }

    [Fact]
    public async Task ConcatenatedAndTrailingGzipRejected()
    {
        byte[] payload = Gzip(MakeArm64(400));
        foreach (byte[] kernel in new[] { Concat(payload, payload), Concat(payload, Ascii("JUNK")) })
        {
            using var work = new WorkDir();
            await Assert.ThrowsAsync<InvalidDataException>(() => ResolveAsync(work, kernel));
        }
    }

    [Fact]
    public async Task OptionalGzipHeaderFieldsAccepted()
    {
        using var work = new WorkDir();
        byte[] raw = MakeArm64(700);
        InternalSlotMaterial material = await ResolveAsync(work, BuildOptionalGzip(raw, false));

        Assert.Equal(ShaHex(raw), material.BaseImageSha256);
        Assert.False(material.IsKshim);
    }

    [Fact]
    public async Task GzipHeaderCrcMismatchRejected()
    {
        using var work = new WorkDir();
        byte[] raw = MakeArm64(700);
        await Assert.ThrowsAsync<InvalidDataException>(
            () => ResolveAsync(work, BuildOptionalGzip(raw, true)));
    }

    [Fact]
    public async Task TruncatedDeflateRetainingTrailerRejected()
    {
        using var work = new WorkDir();
        byte[] valid = Gzip(MakeArm64(768));
        byte[] body = valid[..^8];
        byte[] trailer = valid[^8..];
        byte[] truncated = Concat(body[..^1], trailer);
        Assert.Equal(valid.Length - 1, truncated.Length);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => ResolveAsync(work, truncated));
    }

    [Fact]
    public void BoundedInflateHonorsSmallLimit()
    {
        byte[] payload = Gzip(Repeat((byte)'A', 10000));
        Assert.Equal(Repeat((byte)'A', 10000), InvokeInflate(payload, 10000));
        Assert.Throws<InvalidDataException>(() => { _ = InvokeInflate(payload, 9999); });
        Assert.Throws<InvalidDataException>(() => { _ = InvokeInflate(payload, 10); });
    }

    [Fact]
    public void BoundedInflateAcceptsExactLimit()
    {
        byte[] raw = MakeArm64(768);
        byte[] payload = Gzip(raw);
        Assert.Equal(raw, InvokeInflate(payload, raw.Length));
        Assert.Throws<InvalidDataException>(
            () => { _ = InvokeInflate(payload, raw.Length - 1); });
    }

    [Fact]
    public void KnownLoaderProfileMatchesStaticReference()
    {
        InternalSlotLoaderBudget budget = InvokeBudget(
            KnownAblSha, KnownAblBytes, KnownXblSha, KnownXblBytes,
            4096, 0, 8633118, 2457793, 3);

        Assert.True(budget.KnownLoaderMatch);
        Assert.Equal(KnownRoom, budget.MaxRawBytes);
        Assert.Equal("tb322fc-abl259-xbl-config-ramdisk-derived", budget.Profile);
        Assert.Contains("268435456", budget.Formula);
        Assert.Contains("11090911", budget.Formula);
        Assert.Equal(ExpectedKnownEvidence, budget.Evidence);
    }

    [Fact]
    public void KnownLoaderTracksRamdiskTotal()
    {
        InternalSlotLoaderBudget budget = InvokeBudget(
            KnownAblSha, KnownAblBytes, KnownXblSha, KnownXblBytes,
            4096, 0, 8633118 + 4096, 2457793, 3);

        Assert.True(budget.KnownLoaderMatch);
        Assert.Equal(KnownRoom - 4096, budget.MaxRawBytes);
        Assert.Contains("11095007", budget.Formula);
    }

    [Fact]
    public void KnownLoaderRequiresFullIdentity()
    {
        string badAblHash = "f" + KnownAblSha[1..];
        Assert.False(InvokeBudget(
            badAblHash, KnownAblBytes, KnownXblSha, KnownXblBytes,
            4096, 0, 8633118, 2457793, 3).KnownLoaderMatch);
        Assert.False(InvokeBudget(
            KnownAblSha, KnownAblBytes + 1, KnownXblSha, KnownXblBytes,
            4096, 0, 8633118, 2457793, 3).KnownLoaderMatch);
        Assert.False(InvokeBudget(
            KnownAblSha, KnownAblBytes, new string('0', 64), KnownXblBytes,
            4096, 0, 8633118, 2457793, 3).KnownLoaderMatch);
        Assert.False(InvokeBudget(
            KnownAblSha, KnownAblBytes, KnownXblSha, KnownXblBytes - 4,
            4096, 0, 8633118, 2457793, 3).KnownLoaderMatch);
        Assert.False(InvokeBudget(
            KnownAblSha, KnownAblBytes, KnownXblSha, KnownXblBytes,
            8192, 0, 8633118, 2457793, 3).KnownLoaderMatch);
        Assert.False(InvokeBudget(
            KnownAblSha, KnownAblBytes, KnownXblSha, KnownXblBytes,
            4096, 0, 8633118, 2457793, 2).KnownLoaderMatch);

        foreach (InternalSlotLoaderBudget budget in new[]
        {
            InvokeBudget(badAblHash, KnownAblBytes, KnownXblSha, KnownXblBytes,
                4096, 0, 8633118, 2457793, 3),
            InvokeBudget(KnownAblSha, KnownAblBytes, KnownXblSha, KnownXblBytes,
                4096, 0, 8633118, 2457793, 2),
        })
        {
            Assert.Equal(134217728, budget.MaxRawBytes);
            Assert.Equal("max_raw_bytes = 134217728 (conservative fallback)", budget.Formula);
        }
    }

    [Fact]
    public void KnownBPairMatchesStaticReference()
    {
        InternalSlotLoaderBudget budget = InvokeBudget(
            KnownBAblSha, KnownAblBytes, KnownBXblSha, KnownXblBytes,
            4096, 0, 8633118, 2457793, 3);

        Assert.True(budget.KnownLoaderMatch);
        Assert.Equal(254713856, budget.MaxRawBytes);
        Assert.Equal("tb322fc-abl259-xbl-config-ramdisk-derived", budget.Profile);
        Assert.Equal(ExpectedKnownEvidence, budget.Evidence);

        InternalSlotLoaderBudget grown = InvokeBudget(
            KnownBAblSha, KnownAblBytes, KnownBXblSha, KnownXblBytes,
            4096, 0, 8633118 + 4096, 2457793, 3);

        Assert.True(grown.KnownLoaderMatch);
        Assert.Equal(254713856 - 4096, grown.MaxRawBytes);
    }

    [Fact]
    public void KnownBCrossPairsStayUnknown()
    {
        foreach (InternalSlotLoaderBudget budget in new[]
        {
            InvokeBudget(KnownAblSha, KnownAblBytes, KnownBXblSha, KnownXblBytes,
                4096, 0, 8633118, 2457793, 3),
            InvokeBudget(KnownBAblSha, KnownAblBytes, KnownXblSha, KnownXblBytes,
                4096, 0, 8633118, 2457793, 3),
        })
        {
            Assert.False(budget.KnownLoaderMatch);
            Assert.Equal(134217728, budget.MaxRawBytes);
            Assert.Equal("conservative-default", budget.Profile);
        }
    }

    [Fact]
    public void KnownBRequiresFullIdentity()
    {
        foreach ((string ablSha, long ablBytes, string xblSha, long xblBytes, int page, int headers) in new[]
        {
            ("f" + KnownBAblSha[1..], KnownAblBytes, KnownBXblSha, KnownXblBytes, 4096, 3),
            (KnownBAblSha, KnownAblBytes, "f" + KnownBXblSha[1..], KnownXblBytes, 4096, 3),
            (KnownBAblSha, KnownAblBytes + 1, KnownBXblSha, KnownXblBytes, 4096, 3),
            (KnownBAblSha, KnownAblBytes, KnownBXblSha, KnownXblBytes - 4, 4096, 3),
            (KnownBAblSha, KnownAblBytes, KnownBXblSha, KnownXblBytes, 8192, 3),
            (KnownBAblSha, KnownAblBytes, KnownBXblSha, KnownXblBytes, 4096, 2),
        })
        {
            InternalSlotLoaderBudget budget = InvokeBudget(
                ablSha, ablBytes, xblSha, xblBytes,
                page, 0, 8633118, 2457793, headers);

            Assert.False(budget.KnownLoaderMatch);
            Assert.Equal(134217728, budget.MaxRawBytes);
            Assert.Equal("conservative-default", budget.Profile);
        }
    }

    [Fact]
    public async Task ActualUnknownLoaderBytesStayConservative()
    {
        using var work = new WorkDir();
        byte[] abl = new byte[KnownAblBytes];
        byte[] xbl = new byte[KnownXblBytes];
        InternalSlotMaterial material = await ResolveAsync(
            work, MakeArm64(320), abl: abl, xbl: xbl);

        Assert.False(material.LoaderBudget.KnownLoaderMatch);
        Assert.Equal(134217728, material.LoaderBudget.MaxRawBytes);
        Assert.Equal((long)KnownAblBytes, material.SourceLengths["abl"]);
        Assert.Equal((long)KnownXblBytes, material.SourceLengths["xbl_config"]);
    }

    // ------------------------------------------------------------ helpers

    private static byte[] InvokeInflate(byte[] data, long limit)
    {
        MethodInfo method = typeof(InternalSlotMaterialReader).GetMethod(
            "InflateGzip", BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException("InflateGzip not found");
        try
        {
            return (byte[])method.Invoke(null, new object[] { data, limit, CancellationToken.None })!;
        }
        catch (TargetInvocationException ex) when (ex.InnerException is InvalidDataException inner)
        {
            throw inner;
        }
    }

    private static InternalSlotLoaderBudget InvokeBudget(
        string ablSha, long ablBytes, string xblSha, long xblBytes,
        int pageSize, long bootRamdisk, long vendorRamdisk, long initRamdisk,
        int v4HeaderCount)
    {
        MethodInfo method = typeof(InternalSlotMaterialReader).GetMethod(
            "ComputeLoaderBudget", BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException("ComputeLoaderBudget not found");
        try
        {
            return (InternalSlotLoaderBudget)method.Invoke(null, new object[]
            {
                ablSha, ablBytes, xblSha, xblBytes, pageSize,
                bootRamdisk, vendorRamdisk, initRamdisk, v4HeaderCount,
            })!;
        }
        catch (TargetInvocationException ex) when (ex.InnerException is InvalidDataException inner)
        {
            throw inner;
        }
    }

    private const string KnownAblSha =
        "e7062378a1fe977df95341e5d3023dd510cffb283b11902a7cdbe74ba3e43885";
    private const string KnownXblSha =
        "88e56e47c12b68bca70b8943739bc3114ad6f9166ebc654945919bb1a158fbed";
    private const string KnownBAblSha =
        "811489f0cefb662bccf91a89d2b50187cc1e8fb949486421fe19f820981ecae0";
    private const string KnownBXblSha =
        "1a937da630c966372a67ba60d0103997f61ce7d1df086b7b6c68e4fcc0ba73c3";
    private const string ExpectedKnownEvidence =
        "identified ABL/xbl_config full sha256+length as a reviewed exact A or B pair, page 4096, three validated v4 headers; static normal GetVariable success path and matching XBL LOAD/FDT capacity arithmetic only; runtime GetVariable results and physical B-slot capacity remain unverified";

    private static string ShaHex(byte[] data) =>
        Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private static int Align4(int value) => (value + 3) & ~3;

    private static uint Crc32(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFFu;
        foreach (byte value in data)
        {
            crc ^= value;
            for (int bit = 0; bit < 8; bit++)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
            }
        }
        return crc ^ 0xFFFFFFFFu;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        int length = 0;
        foreach (byte[] part in parts)
        {
            length += part.Length;
        }
        byte[] result = new byte[length];
        int offset = 0;
        foreach (byte[] part in parts)
        {
            Buffer.BlockCopy(part, 0, result, offset, part.Length);
            offset += part.Length;
        }
        return result;
    }

    private static void W16(byte[] buffer, int offset, ushort value) =>
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(offset, 2), value);

    private static void W16(Stream stream, ushort value)
    {
        Span<byte> bytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(bytes, value);
        stream.Write(bytes);
    }

    private static void W32(byte[] buffer, int offset, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset, 4), value);

    private static void W32(Stream stream, uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, value);
        stream.Write(bytes);
    }

    private static void W64(byte[] buffer, int offset, ulong value) =>
        BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(offset, 8), value);

    private static ulong R64(byte[] buffer, int offset) =>
        BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(offset, 8));
}
