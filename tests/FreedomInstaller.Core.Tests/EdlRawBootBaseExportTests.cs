using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// BR001: the internal export entry reuses the existing five-source verification and
/// recovery unchanged, then writes the already recovered base image to a caller-owned
/// private path. No bytes are exposed through the public reader API.
/// </summary>
public sealed class EdlRawBootBaseExportTests
{
    private const BindingFlags PrivateStatic = BindingFlags.NonPublic | BindingFlags.Static;

    private static readonly byte[] BootRamdisk = Ascii("BOOT-RAMDISK-BYTES");
    private static readonly byte[] VendorRamdisk = Ascii("VENDOR-RAMDISK-BYTES");

    // ------------------------------------------------------------- workdir

    private sealed class WorkDir : IDisposable
    {
        public WorkDir()
        {
            Dir = Path.Combine(
                TestArtifactRoot.Resolve(), "br001-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Dir);
        }

        public string Dir { get; }

        public string OutputPath(string name)
        {
            string build = Path.Combine(Dir, "build");
            Directory.CreateDirectory(build);
            return Path.Combine(build, name);
        }

        public VerifiedEdlFile Claim(
            string name, byte[] bytes, long? length = null, string? sha256 = null)
        {
            string path = Path.Combine(Dir, name);
            File.WriteAllBytes(path, bytes);
            return new VerifiedEdlFile(path, length ?? bytes.LongLength, sha256 ?? ShaHex(bytes));
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

    // ------------------------------------------------------------ sources

    private static (byte[] Current, byte[] Vendor, byte[] Init, byte[] Abl, byte[] Xbl)
        DefaultSources(byte[] kernel) => (
            FixtureBoot(kernel, BootRamdisk, Ascii("BOOT-SIGNATURE")),
            FixtureVendor(VendorRamdisk),
            FixtureBoot(Array.Empty<byte>(), Array.Empty<byte>(), Ascii("initsig")),
            Ascii("abl-unknown-bytes"),
            Ascii("xbl-config-unknown-bytes"));

    private static (VerifiedEdlFile Current, VerifiedEdlFile Vendor, VerifiedEdlFile Init,
        VerifiedEdlFile Abl, VerifiedEdlFile Xbl) ClaimAll(
        WorkDir work,
        (byte[] Current, byte[] Vendor, byte[] Init, byte[] Abl, byte[] Xbl) sources) => (
            work.Claim("current.img", sources.Current),
            work.Claim("vendor.img", sources.Vendor),
            work.Claim("init.img", sources.Init),
            work.Claim("abl.bin", sources.Abl),
            work.Claim("xbl.bin", sources.Xbl));

    private static (string Path, byte[] Bytes)[] Snapshot(
        (VerifiedEdlFile Current, VerifiedEdlFile Vendor, VerifiedEdlFile Init,
            VerifiedEdlFile Abl, VerifiedEdlFile Xbl) claims,
        (byte[] Current, byte[] Vendor, byte[] Init, byte[] Abl, byte[] Xbl) sources) => new[]
        {
            (claims.Current.Path, sources.Current),
            (claims.Vendor.Path, sources.Vendor),
            (claims.Init.Path, sources.Init),
            (claims.Abl.Path, sources.Abl),
            (claims.Xbl.Path, sources.Xbl),
        };

    private static void AssertSourcesUnchanged(
        (string Path, byte[] Bytes)[] expected)
    {
        foreach ((string path, byte[] bytes) in expected)
        {
            Assert.Equal(bytes.LongLength, new FileInfo(path).Length);
            Assert.Equal(ShaHex(bytes), ShaHex(File.ReadAllBytes(path)));
        }
    }

    // -------------------------------------------------------- export bridge

    private static async Task<InternalSlotMaterial> ExportAsync(
        string slot,
        VerifiedEdlFile currentBoot,
        VerifiedEdlFile vendorBoot,
        VerifiedEdlFile initBoot,
        VerifiedEdlFile abl,
        VerifiedEdlFile xblConfig,
        string outputPath,
        CancellationToken token = default)
    {
        MethodInfo method = typeof(InternalSlotMaterialReader).GetMethod(
            "AnalyzeAndExportBaseAsync", PrivateStatic)
            ?? throw new InvalidOperationException("AnalyzeAndExportBaseAsync not found");
        var task = (Task<InternalSlotMaterial>)method.Invoke(null, new object?[]
        {
            slot, currentBoot, vendorBoot, initBoot, abl, xblConfig, outputPath, token,
        })!;
        return await task;
    }

    // ------------------------------------------------- fixture helper bridge

    private static object? InvokeFixture(string name, params object?[] arguments)
    {
        MethodInfo method = typeof(InternalSlotMaterialReaderTests).GetMethod(
            name, PrivateStatic)
            ?? throw new InvalidOperationException(name + " fixture helper not found");
        return method.Invoke(null, arguments);
    }

    private static byte[] FixtureArm64(
        int size = 320, long? imageSize = null, ulong textOffset = 0x80000)
    {
        return (byte[])InvokeFixture(
            "MakeArm64",
            size,
            0x14000100u,
            0u,
            (object?)imageSize ?? Type.Missing,
            textOffset,
            0x0A000000UL,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing)!;
    }

    private static byte[] FixtureBoot(
        byte[]? kernel = null, byte[]? ramdisk = null, byte[]? signature = null)
    {
        return (byte[])InvokeFixture(
            "MakeBoot",
            (object?)kernel ?? Type.Missing,
            (object?)ramdisk ?? Type.Missing,
            (object?)signature ?? Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing)!;
    }

    private static byte[] FixtureVendor(byte[]? ramdisk = null)
    {
        return (byte[])InvokeFixture(
            "MakeVendor",
            (object?)ramdisk ?? Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing)!;
    }

    private static byte[] FixtureKshim(object specs)
    {
        var result = (ValueTuple<byte[], List<(int Offset, int Size)>>)InvokeFixture(
            "MakeKshim",
            specs,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing,
            Type.Missing)!;
        return result.Item1;
    }

    private static object FixtureDefaultSpecs(byte[] baseImage) =>
        InvokeFixture("DefaultSpecs", baseImage)!;

    private static byte[] FixtureGzip(byte[] raw) => (byte[])InvokeFixture("Gzip", raw)!;

    // --------------------------------------------------------------- tests

    [Fact]
    public async Task PlainKernelExportWritesExactRecoveredBaseBytes()
    {
        using var work = new WorkDir();
        byte[] kernel = FixtureArm64(512);
        var sources = DefaultSources(kernel);
        var claims = ClaimAll(work, sources);
        string output = work.OutputPath("base-plain.img");

        InternalSlotMaterial material = await ExportAsync(
            "a", claims.Current, claims.Vendor, claims.Init, claims.Abl, claims.Xbl, output);

        Assert.False(material.IsKshim);
        Assert.Equal("a", material.Slot);
        Assert.Equal(kernel.LongLength, material.BaseImageLength);
        Assert.Equal(512L, material.BaseImageSize);
        Assert.Equal(0x80000UL, material.BaseTextOffset);
        Assert.Equal(ShaHex(kernel), material.BaseImageSha256);

        byte[] exported = File.ReadAllBytes(output);
        Assert.Equal(kernel.LongLength, exported.LongLength);
        Assert.Equal(kernel, exported);
        Assert.Equal(material.BaseImageSha256, ShaHex(exported));
        Assert.Equal(material.BaseImageLength, new FileInfo(output).Length);

        AssertSourcesUnchanged(Snapshot(claims, sources));
    }

    [Fact]
    public async Task RawKshimExportWritesRestoredBaseBytes()
    {
        using var work = new WorkDir();
        byte[] baseImage = FixtureArm64(320);
        byte[] raw = FixtureKshim(FixtureDefaultSpecs(baseImage));
        var sources = DefaultSources(raw);
        var claims = ClaimAll(work, sources);
        string output = work.OutputPath("base-kshim.img");

        InternalSlotMaterial material = await ExportAsync(
            "a", claims.Current, claims.Vendor, claims.Init, claims.Abl, claims.Xbl, output);

        Assert.True(material.IsKshim);
        Assert.Equal(baseImage.LongLength, material.BaseImageLength);
        Assert.Equal(ShaHex(baseImage), material.BaseImageSha256);

        byte[] exported = File.ReadAllBytes(output);
        Assert.Equal(baseImage, exported);
        Assert.Equal(material.BaseImageSha256, ShaHex(exported));

        AssertSourcesUnchanged(Snapshot(claims, sources));
    }

    [Fact]
    public async Task GzipKshimExportWritesRestoredBaseBytes()
    {
        using var work = new WorkDir();
        byte[] baseImage = FixtureArm64(320);
        byte[] raw = FixtureKshim(FixtureDefaultSpecs(baseImage));
        var sources = DefaultSources(FixtureGzip(raw));
        var claims = ClaimAll(work, sources);
        string output = work.OutputPath("base-gzip-kshim.img");

        InternalSlotMaterial material = await ExportAsync(
            "a", claims.Current, claims.Vendor, claims.Init, claims.Abl, claims.Xbl, output);

        Assert.True(material.IsKshim);
        Assert.Equal(baseImage.LongLength, material.BaseImageLength);
        Assert.Equal(ShaHex(baseImage), material.BaseImageSha256);

        byte[] exported = File.ReadAllBytes(output);
        Assert.Equal(baseImage, exported);
        Assert.Equal(ShaHex(baseImage), ShaHex(exported));

        AssertSourcesUnchanged(Snapshot(claims, sources));
    }

    [Fact]
    public async Task ExistingOutputIsRefusedWithSentinelAndSourcesPreserved()
    {
        using var work = new WorkDir();
        byte[] kernel = FixtureArm64(512);
        var sources = DefaultSources(kernel);
        var claims = ClaimAll(work, sources);
        string output = work.OutputPath("base-sentinel.img");
        byte[] sentinel = Ascii("SENTINEL-EXISTING-OUTPUT-MUST-SURVIVE");
        File.WriteAllBytes(output, sentinel);

        await Assert.ThrowsAsync<IOException>(() => ExportAsync(
            "a", claims.Current, claims.Vendor, claims.Init, claims.Abl, claims.Xbl, output));

        Assert.Equal(sentinel, File.ReadAllBytes(output));
        Assert.Equal(sentinel.LongLength, new FileInfo(output).Length);
        AssertSourcesUnchanged(Snapshot(claims, sources));
    }

    [Fact]
    public async Task StaleClaimFailsBeforeAnyOutputIsCreated()
    {
        using var work = new WorkDir();
        byte[] kernel = FixtureArm64(512);
        var sources = DefaultSources(kernel);
        var claims = (
            Current: work.Claim("current.img", sources.Current, sha256: new string('0', 64)),
            Vendor: work.Claim("vendor.img", sources.Vendor),
            Init: work.Claim("init.img", sources.Init),
            Abl: work.Claim("abl.bin", sources.Abl),
            Xbl: work.Claim("xbl.bin", sources.Xbl));
        string output = work.OutputPath("base-stale.img");

        await Assert.ThrowsAsync<InvalidDataException>(() => ExportAsync(
            "a", claims.Current, claims.Vendor, claims.Init, claims.Abl, claims.Xbl, output));

        Assert.False(File.Exists(output));
        AssertSourcesUnchanged(Snapshot(claims, sources));
    }

    [Fact]
    public async Task PreCancelledTokenProducesNoOutput()
    {
        using var work = new WorkDir();
        byte[] kernel = FixtureArm64(512);
        var sources = DefaultSources(kernel);
        var claims = ClaimAll(work, sources);
        string output = work.OutputPath("base-cancelled.img");
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ExportAsync(
            "a", claims.Current, claims.Vendor, claims.Init, claims.Abl, claims.Xbl,
            output, cts.Token));

        Assert.False(File.Exists(output));
        AssertSourcesUnchanged(Snapshot(claims, sources));
    }

    // ------------------------------------------------------------- helpers

    private static byte[] Ascii(string text) => Encoding.ASCII.GetBytes(text);

    private static string ShaHex(byte[] data) =>
        Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
}
