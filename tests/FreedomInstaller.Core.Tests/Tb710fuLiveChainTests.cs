using System;
using System.Collections.Generic;
using System.Threading;
using System.Buffers.Binary;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Real-device check of the TB710FU AOSP-preserving boot-only route, against partitions read from a TB710FU.
/// Skipped unless TB710FU_LIVE_PARTITIONS names a directory with vbmeta_a.img, vbmeta_b.img and boot_a.img (a
/// Freedom-installed kShim boot). The repacked candidate is left under TEST_ARTIFACT_ROOT so it can also be checked
/// with AOSP avbtool against the real vbmeta chain.
/// </summary>
public sealed class Tb710fuLiveChainTests
{
    private static string? LiveDirectory()
    {
        string? directory = Environment.GetEnvironmentVariable("TB710FU_LIVE_PARTITIONS");
        return string.IsNullOrWhiteSpace(directory) ? null : directory;
    }

    private static VerifiedEdlFile Claim(string path)
    {
        using FileStream stream = File.OpenRead(path);
        return new VerifiedEdlFile(path, stream.Length, Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant());
    }

    [Theory]
    [InlineData("vbmeta_a.img")]
    [InlineData("vbmeta_b.img")]
    public async Task The_real_root_vbmeta_and_its_boot_chain_are_the_aosp_key(string name)
    {
        string? directory = LiveDirectory();
        if (directory is null)
            return;

        EdlRawOriginalBootChainFacts facts = await EdlRawBootBuilder.AuthenticatePreservedBootChainAsync(
            Claim(Path.Combine(directory, name)));

        // The same comparison the AOSP-preserving route makes before it plans any boot-only write.
        Assert.Equal(EdlRawBootBuilder.SigningPublicKeySha256, facts.PublicKeySha256, ignoreCase: true);
        Assert.Equal(EdlRawBootBuilder.SigningPublicKeySha256, facts.BootChainPublicKeySha256, ignoreCase: true);
    }

    [Fact]
    public async Task The_real_kshim_boot_repacks_into_a_same_size_candidate()
    {
        string? directory = LiveDirectory();
        string? artifacts = Environment.GetEnvironmentVariable("TEST_ARTIFACT_ROOT");
        if (directory is null || string.IsNullOrWhiteSpace(artifacts))
            return;

        string work = Path.Combine(artifacts, "tb710fu-live-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(work);

        string bootPath = Path.Combine(directory, "boot_a.img");
        string rawPath = Path.Combine(work, "kshim-raw.bin");
        ExtractKernel(bootPath, rawPath);

        string candidatePath = Path.Combine(work, "boot.img");
        VerifiedEdlFile boot = Claim(bootPath);
        VerifiedEdlFile raw = Claim(rawPath);
        // The real bound is the loader budget of the source material; this check is about the signature, so the raw
        // image's own length is the bound.
        EdlRawBootEnvelope envelope = await EdlRawBootBuilder.RepackKshimHybridEnvelopeAsync(
            boot, raw, raw.Length, candidatePath);

        Assert.Equal(boot.Length, envelope.CandidateBoot.Length);
        Assert.Equal(2, envelope.AlgorithmType);
        File.WriteAllText(Path.Combine(work, "candidate-path.txt"), candidatePath);
    }

    [Theory]
    [InlineData("a", "a", "b", "b", "a,b")]
    [InlineData("a", "a", "b", "a", "a,b")]
    [InlineData("a", "b", "b", "b", "a,b")]
    public void The_gate_authenticates_every_target_and_every_source(
        string targetA, string sourceA, string targetB, string sourceB, string expected)
    {
        var map = new Dictionary<string, string> { [targetA] = sourceA, [targetB] = sourceB };
        Assert.Equal(expected.Split(','), InternalInstallPreparationContext.PreservedAospRootSlots(map));
    }

    [Fact]
    public void A_single_target_sourced_from_the_other_slot_checks_both_roots()
    {
        var map = new Dictionary<string, string> { ["b"] = "a" };
        Assert.Equal(new[] { "a", "b" }, InternalInstallPreparationContext.PreservedAospRootSlots(map));
    }

    [Fact]
    public async Task A_target_sourced_from_the_other_slot_has_its_own_real_root_authenticated()
    {
        string? directory = LiveDirectory();
        if (directory is null)
            return;

        var files = new Dictionary<string, EdlCapturedRegion>
        {
            ["vbmeta_a"] = Region("vbmeta_a", Path.Combine(directory, "vbmeta_a.img")),
            ["vbmeta_b"] = Region("vbmeta_b", Path.Combine(directory, "vbmeta_b.img")),
        };

        IReadOnlyList<string> roles = await InternalInstallPreparationContext.RequirePreservedAospChainAsync(
            new Dictionary<string, string> { ["a"] = "a", ["b"] = "a" }, files, CancellationToken.None);

        Assert.Equal(new[] { "vbmeta_a", "vbmeta_b" }, roles);
    }

    [Fact]
    public async Task A_target_whose_own_root_is_not_the_aosp_chain_is_refused()
    {
        string? directory = LiveDirectory();
        if (directory is null || !File.Exists(Path.Combine(directory, "vbmeta_system_a.img")))
            return;

        // vbmeta_b stands in with the real RSA2048 vbmeta_system: a root that does not chain boot to the AOSP key.
        var files = new Dictionary<string, EdlCapturedRegion>
        {
            ["vbmeta_a"] = Region("vbmeta_a", Path.Combine(directory, "vbmeta_a.img")),
            ["vbmeta_b"] = Region("vbmeta_b", Path.Combine(directory, "vbmeta_system_a.img")),
        };

        await Assert.ThrowsAnyAsync<Exception>(() => InternalInstallPreparationContext.RequirePreservedAospChainAsync(
            new Dictionary<string, string> { ["a"] = "a", ["b"] = "a" }, files, CancellationToken.None));
    }

    [Fact]
    public void The_real_all_zero_misc_resolves_the_current_slot_from_the_boot_gpt()
    {
        string? directory = LiveDirectory();
        if (directory is null || !File.Exists(Path.Combine(directory, "gpt_lun4_primary.img")))
            return;

        // The live TB710FU keeps the AOSP boot_control block at misc offset 2048 entirely zero, so the current slot
        // must come from the boot_a/boot_b GPT flags, exactly as on the Y700.
        byte[] misc = File.ReadAllBytes(Path.Combine(directory, "misc.img"));
        Assert.True(misc.AsSpan(2048, 32).IndexOfAnyExcept((byte)0) < 0);
        Assert.True(CurrentBootSlot.UsesQualcommGptSlot("TB710FU"));

        byte[] primary = File.ReadAllBytes(Path.Combine(directory, "gpt_lun4_primary.img"));
        byte[] backup = File.ReadAllBytes(Path.Combine(directory, "gpt_lun4_backup.img"));
        const int sectorSize = 4096;
        long alternateLba = BinaryPrimitives.ReadInt64LittleEndian(primary.AsSpan(sectorSize + 32));
        GptTable table = OriginalGptImporter.Parse(primary, backup, sectorSize, (alternateLba + 1) * sectorSize);

        // Read on 2026-11-18: boot_a active, priority 3, successful; boot_b marked unbootable.
        Assert.Equal("a", CurrentBootSlot.ResolveActiveSlot(table));
    }

    private static EdlCapturedRegion Region(string role, string path)
    {
        VerifiedEdlFile claim = Claim(path);
        return new EdlCapturedRegion(role, 0, 0, claim.Length / 4096, 4096, null, path, claim.Length, claim.Sha256);
    }

    /// <summary>The gzip-compressed kernel of a boot v4 image, decompressed: the packed kShim raw image.</summary>
    private static void ExtractKernel(string bootPath, string rawPath)
    {
        byte[] header = new byte[4096];
        using (FileStream boot = File.OpenRead(bootPath))
        {
            boot.ReadExactly(header);
            Assert.Equal("ANDROID!", System.Text.Encoding.ASCII.GetString(header, 0, 8));
            Assert.Equal(4u, BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(40)));
            int kernelSize = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(8)));
            byte[] kernel = new byte[kernelSize];
            boot.ReadExactly(kernel);
            using var gzip = new GZipStream(new MemoryStream(kernel), CompressionMode.Decompress);
            using FileStream raw = File.Create(rawPath);
            gzip.CopyTo(raw);
        }
    }
}
