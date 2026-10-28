using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class EdlRawBootEnvelopeTests
{
    private static readonly MethodInfo RepackMethod = typeof(EdlRawBootBuilder).GetMethod(
        "RepackEnvelopeAsync",
        BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("EdlRawBootBuilder.RepackEnvelopeAsync was not found");

    private static readonly MethodInfo VerifyCandidateVbmetaSignatureMethod = typeof(EdlRawBootBuilder).GetMethod(
        "VerifyCandidateVbmetaSignature",
        BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("EdlRawBootBuilder.VerifyCandidateVbmetaSignature was not found");

    private static readonly MethodInfo LoadAvbSigningKeyMethod = typeof(EdlRawBootBuilder).GetMethod(
        "LoadAvbSigningKey",
        BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("EdlRawBootBuilder.LoadAvbSigningKey was not found");

    // Canonical avbtool AvbHashDescriptor bytes for the boot slot, encoded by hand:
    // 176 bytes, tag 2, nbf 160, image_size 8192, "sha256", partition_name_len 4,
    // salt_len 1, digest_len 32, flags 0, 60 reserved zero bytes, then the
    // length-delimited name "boot" (no NUL), salt A5, 32 digest bytes 0x11, 7 pad.
    private const string CanonicalHashDescriptorHex =
        "0000000000000002" +
        "00000000000000A0" +
        "0000000000002000" +
        "7368613235360000" +
        "0000000000000000" +
        "0000000000000000" +
        "0000000000000000" +
        "00000004" +
        "00000001" +
        "00000020" +
        "00000000" +
        "0000000000000000" +
        "0000000000000000" +
        "0000000000000000" +
        "0000000000000000" +
        "0000000000000000" +
        "0000000000000000" +
        "0000000000000000" +
        "00000000" +
        "626F6F74" +
        "A5" +
        "11111111111111111111111111111111" +
        "11111111111111111111111111111111" +
        "00000000000000";

    [Fact]
    public async Task Sha256Slot_Repack_ProducesVerifiedEnvelopeAndPhysicalLayout()
    {
        string directory = NewDirectory("be001-sha256");
        string sourcePath = Path.Combine(directory, "source-boot.img");
        string rawPath = Path.Combine(directory, "packed-raw.img");
        string outputPath = Path.Combine(directory, "candidate-boot.img");

        var spec = new SourceSpec
        {
            PartitionSize = 262144,
            KernelSize = 12288,
            Algorithm = "sha256",
            Salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 },
            RollbackIndex = 11,
            RollbackLocation = 2,
        };
        spec.Properties.Add(("com.android.build.boot.fingerprint", "synthetic/one"));
        spec.Properties.Add(("com.android.build.boot.os_version", "13"));
        spec.Properties.Add(("com.android.build.boot.fingerprint", "synthetic/duplicate"));

        SourceLayout layout = WriteSource(sourcePath, spec);
        byte[] raw = BuildRawImage(5000);
        File.WriteAllBytes(rawPath, raw);

        VerifiedEdlFile source = Verify(sourcePath);
        VerifiedEdlFile rawFile = Verify(rawPath);

        EdlRawBootEnvelope envelope = await RepackAsync(source, rawFile, raw.Length, outputPath);

        int gzipLength = GzipLength(raw);
        int expectedOriginal = 4096 + RoundUp(gzipLength, 4096);
        Assert.Equal((long)gzipLength, envelope.CompressedKernelBytes);
        Assert.Equal((long)expectedOriginal, envelope.OriginalImageSize);
        Assert.Equal((long)expectedOriginal, envelope.VbmetaOffset);
        Assert.True(envelope.VbmetaBytes > 256);
        Assert.Equal("sha256", envelope.HashAlgorithm);
        Assert.Equal(ToHex(spec.Salt), envelope.SaltHex);
        Assert.Equal(0u, envelope.HashDescriptorFlags);
        Assert.Equal(11UL, envelope.RollbackIndex);
        Assert.Equal(2u, envelope.RollbackIndexLocation);
        Assert.Equal(2, envelope.AlgorithmType);
        Assert.False(envelope.OemSigned);
        Assert.True(envelope.SignatureVerificationPerformed);
        Assert.False(envelope.HardwareRollbackVerified);
        Assert.Equal(3, envelope.Properties.Count);
        Assert.Equal("com.android.build.boot.fingerprint", envelope.Properties[0].Key);
        Assert.Equal("synthetic/one", envelope.Properties[0].Value);
        Assert.Equal("com.android.build.boot.os_version", envelope.Properties[1].Key);
        Assert.Equal("synthetic/duplicate", envelope.Properties[2].Value);
        Assert.Equal(64, envelope.DigestHex.Length);

        byte[] sourceBytes = File.ReadAllBytes(sourcePath);
        byte[] output = File.ReadAllBytes(outputPath);
        AssertRsa4096Vbmeta(output, (int)envelope.VbmetaOffset);
        Assert.Equal(spec.PartitionSize, output.Length);
        Assert.Equal((uint)gzipLength, ReadLeU32(output, 8));
        for (int i = 0; i < 4096; i++)
        {
            if (i < 8 || i >= 12)
            {
                Assert.Equal(sourceBytes[i], output[i]);
            }
        }

        Assert.Equal("AVBf", Encoding.ASCII.GetString(output, output.Length - 64, 4));
        Assert.Equal(1u, ReadBeU32(output, output.Length - 60));
        Assert.Equal((ulong)expectedOriginal, ReadBeU64(output, output.Length - 52));
        Assert.Equal((ulong)expectedOriginal, ReadBeU64(output, output.Length - 44));
        Assert.Equal((ulong)envelope.VbmetaBytes, ReadBeU64(output, output.Length - 36));

        using (MemoryStream compressed = new(output, 4096, gzipLength, writable: false))
        using (GZipStream decompressor = new(compressed, CompressionMode.Decompress))
        using (MemoryStream inflated = new())
        {
            decompressor.CopyTo(inflated);
            Assert.Equal(raw, inflated.ToArray());
        }

        byte[] expectedDigest = SaltedDigest("sha256", spec.Salt, output, expectedOriginal);
        Assert.Equal(expectedDigest, ReadOutputHashDigest(output, (int)envelope.VbmetaOffset));
        Assert.Equal(ToHex(expectedDigest), envelope.DigestHex);

        byte[] sourceVbmeta = new byte[layout.VbmetaSize];
        Buffer.BlockCopy(sourceBytes, layout.VbmetaOffset, sourceVbmeta, 0, sourceVbmeta.Length);
        Assert.Equal(ToHex(SHA256.HashData(sourceVbmeta)), envelope.SourceEmbeddedVbmetaSha256);

        Assert.Equal(Path.GetFullPath(outputPath), envelope.CandidateBoot.Path);
        Assert.Equal((long)output.Length, envelope.CandidateBoot.Length);
        Assert.Equal(ToHex(SHA256.HashData(output)), envelope.CandidateBoot.Sha256);
    }

    [Fact]
    public async Task Sha512Slot_PreservesDistinctMetadataAndDuplicateProperties()
    {
        string directory = NewDirectory("be001-sha512");
        string sourcePath = Path.Combine(directory, "source-boot.img");
        string rawPath = Path.Combine(directory, "packed-raw.img");
        string outputPath = Path.Combine(directory, "candidate-boot.img");

        var spec = new SourceSpec
        {
            PartitionSize = 262144,
            KernelSize = 8192,
            Algorithm = "sha512",
            Salt = new byte[24],
            Flags = 1,
            RollbackIndex = 42,
            RollbackLocation = 5,
        };
        for (int i = 0; i < spec.Salt.Length; i++)
        {
            spec.Salt[i] = (byte)(0x80 + i);
        }

        spec.Properties.Add(("slot", "b"));
        spec.Properties.Add(("slot", "b-again"));

        SourceLayout layout = WriteSource(sourcePath, spec);
        byte[] raw = BuildRawImage(7000);
        File.WriteAllBytes(rawPath, raw);

        VerifiedEdlFile source = Verify(sourcePath);
        VerifiedEdlFile rawFile = Verify(rawPath);

        EdlRawBootEnvelope envelope = await RepackAsync(source, rawFile, raw.Length, outputPath);

        Assert.Equal("sha512", envelope.HashAlgorithm);
        Assert.Equal(ToHex(spec.Salt), envelope.SaltHex);
        Assert.Equal(1u, envelope.HashDescriptorFlags);
        Assert.Equal(42UL, envelope.RollbackIndex);
        Assert.Equal(5u, envelope.RollbackIndexLocation);
        Assert.Equal(128, envelope.DigestHex.Length);
        Assert.Equal(2, envelope.Properties.Count);
        Assert.Equal("slot", envelope.Properties[0].Key);
        Assert.Equal("b", envelope.Properties[0].Value);
        Assert.Equal("b-again", envelope.Properties[1].Value);

        byte[] output = File.ReadAllBytes(outputPath);
        AssertRsa4096Vbmeta(output, (int)envelope.VbmetaOffset);
        int expectedOriginal = 4096 + RoundUp(GzipLength(raw), 4096);
        Assert.Equal(2u, ReadBeU32(output, (int)envelope.VbmetaOffset + 8));
        Assert.Equal(
            SaltedDigest("sha512", spec.Salt, output, expectedOriginal),
            ReadOutputHashDigest(output, (int)envelope.VbmetaOffset));
        Assert.NotEqual((long)layout.VbmetaOffset, envelope.VbmetaOffset);
    }

    [Fact]
    public async Task CanonicalHashDescriptor_LengthDelimitedNameWithoutNul_IsAcceptedAndReemitted()
    {
        byte[] canonical = Convert.FromHexString(CanonicalHashDescriptorHex);
        Assert.Equal(176, canonical.Length);
        Assert.Equal(0xA5, canonical[136]);

        string directory = NewDirectory("be001-canonical");
        string sourcePath = Path.Combine(directory, "source-boot.img");
        string rawPath = Path.Combine(directory, "packed-raw.img");
        string outputPath = Path.Combine(directory, "candidate-boot.img");

        var spec = new SourceSpec { PartitionSize = 262144, KernelSize = 4096 };
        spec.RawHashDescriptor = canonical;
        WriteSource(sourcePath, spec);

        byte[] raw = BuildRawImage(5000);
        File.WriteAllBytes(rawPath, raw);

        EdlRawBootEnvelope envelope = await RepackAsync(Verify(sourcePath), Verify(rawPath), raw.Length, outputPath);

        Assert.Equal(8192L, envelope.OriginalImageSize);
        Assert.Equal("sha256", envelope.HashAlgorithm);
        Assert.Equal("a5", envelope.SaltHex);
        Assert.Equal(0u, envelope.HashDescriptorFlags);
        Assert.Empty(envelope.Properties);

        byte[] output = File.ReadAllBytes(outputPath);
        int hashDescriptor = (int)envelope.VbmetaOffset
            + 256
            + (int)ReadBeU64(output, (int)envelope.VbmetaOffset + 12);
        Assert.Equal(4u, ReadBeU32(output, hashDescriptor + 56));
        Assert.Equal("boot", Encoding.ASCII.GetString(output, hashDescriptor + 132, 4));
        Assert.Equal(0xA5, output[hashDescriptor + 136]);

        byte[] expectedDigest = SaltedDigest("sha256", new byte[] { 0xA5 }, output, 8192);
        Assert.Equal(expectedDigest, ReadOutputHashDigest(output, (int)envelope.VbmetaOffset));
        Assert.Equal(ToHex(expectedDigest), envelope.DigestHex);
    }

    [Fact]
    public async Task CanonicalHashDescriptor_WithLegacyDigestLengthAt56_IsRejected()
    {
        byte[] canonical = Convert.FromHexString(CanonicalHashDescriptorHex);
        WriteBeU32(canonical, 56, 32);

        string directory = NewDirectory("be001-canonical-legacy-name");
        string sourcePath = Path.Combine(directory, "source-boot.img");
        string rawPath = Path.Combine(directory, "packed-raw.img");
        string outputPath = Path.Combine(directory, "candidate-boot.img");

        var spec = new SourceSpec { PartitionSize = 262144, KernelSize = 4096 };
        spec.RawHashDescriptor = canonical;
        WriteSource(sourcePath, spec);

        byte[] raw = BuildRawImage(5000);
        File.WriteAllBytes(rawPath, raw);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => RepackAsync(Verify(sourcePath), Verify(rawPath), raw.Length, outputPath));
    }

    [Fact]
    public async Task Rejects_NonZeroRamdisk()
    {
        SourceFixture fixture = CreateFixture("be001-ramdisk", spec => spec.RamdiskSize = 1);
        await Assert.ThrowsAsync<InvalidDataException>(
            () => RepackAsync(fixture.Source, fixture.Raw, fixture.Raw.Length, fixture.OutputPath));
    }

    [Fact]
    public async Task Rejects_NonZeroSignature()
    {
        SourceFixture fixture = CreateFixture("be001-signature", spec => spec.SignatureSize = 4);
        await Assert.ThrowsAsync<InvalidDataException>(
            () => RepackAsync(fixture.Source, fixture.Raw, fixture.Raw.Length, fixture.OutputPath));
    }

    [Fact]
    public async Task Rejects_FooterOriginalImageSizeBelowKernelMinimum()
    {
        SourceFixture fixture = CreateFixture("be001-footer-small", spec => spec.FooterOriginalImageSize = 4096L);
        await Assert.ThrowsAsync<InvalidDataException>(
            () => RepackAsync(fixture.Source, fixture.Raw, fixture.Raw.Length, fixture.OutputPath));
    }

    [Fact]
    public async Task Rejects_FooterVbmetaOffsetBelowImage()
    {
        SourceFixture fixture = CreateFixture("be001-footer-offset", spec => spec.FooterVbmetaOffset = 4096L);
        await Assert.ThrowsAsync<InvalidDataException>(
            () => RepackAsync(fixture.Source, fixture.Raw, fixture.Raw.Length, fixture.OutputPath));
    }

    [Fact]
    public async Task Rejects_FooterVbmetaRangeOverflow()
    {
        SourceFixture fixture = CreateFixture("be001-footer-overflow", spec => spec.FooterVbmetaSize = spec.PartitionSize);
        await Assert.ThrowsAsync<InvalidDataException>(
            () => RepackAsync(fixture.Source, fixture.Raw, fixture.Raw.Length, fixture.OutputPath));
    }

    [Fact]
    public async Task Rejects_UnknownDescriptorTag()
    {
        SourceFixture fixture = CreateFixture(
            "be001-unknown-tag",
            spec => spec.RawPropertyDescriptors.Add(RawDescriptor(3, new byte[8])));
        await Assert.ThrowsAsync<InvalidDataException>(
            () => RepackAsync(fixture.Source, fixture.Raw, fixture.Raw.Length, fixture.OutputPath));
    }

    [Fact]
    public async Task Rejects_MissingHashDescriptor()
    {
        SourceFixture fixture = CreateFixture(
            "be001-missing-hash",
            spec =>
            {
                spec.HashDescriptorCopies = 0;
                spec.Properties.Add(("only", "property"));
            });
        await Assert.ThrowsAsync<InvalidDataException>(
            () => RepackAsync(fixture.Source, fixture.Raw, fixture.Raw.Length, fixture.OutputPath));
    }

    [Fact]
    public async Task Rejects_DuplicateHashDescriptor()
    {
        SourceFixture fixture = CreateFixture("be001-duplicate-hash", spec => spec.HashDescriptorCopies = 2);
        await Assert.ThrowsAsync<InvalidDataException>(
            () => RepackAsync(fixture.Source, fixture.Raw, fixture.Raw.Length, fixture.OutputPath));
    }

    [Fact]
    public async Task Rejects_UnsupportedHashDescriptorFlags()
    {
        SourceFixture fixture = CreateFixture(
            "be001-bad-flags",
            spec => spec.RawHashDescriptor = BuildHashDescriptor(
                "sha256",
                RoundUp(4096 + spec.KernelSize, 4096),
                spec.Salt,
                32,
                2));
        await Assert.ThrowsAsync<InvalidDataException>(
            () => RepackAsync(fixture.Source, fixture.Raw, fixture.Raw.Length, fixture.OutputPath));
    }

    [Fact]
    public async Task Rejects_WrongDigestLengthForAlgorithm()
    {
        SourceFixture fixture = CreateFixture("be001-bad-digest", spec => spec.DigestLength = 31);
        await Assert.ThrowsAsync<InvalidDataException>(
            () => RepackAsync(fixture.Source, fixture.Raw, fixture.Raw.Length, fixture.OutputPath));
    }

    [Fact]
    public async Task Rejects_TruncatedHashDescriptorBody()
    {
        SourceFixture fixture = CreateFixture(
            "be001-truncated",
            spec =>
            {
                byte[] full = BuildHashDescriptor(
                    "sha256",
                    RoundUp(4096 + spec.KernelSize, 4096),
                    spec.Salt,
                    32,
                    0);
                spec.RawHashDescriptor = full.Take(full.Length - 8).ToArray();
            });
        await Assert.ThrowsAsync<InvalidDataException>(
            () => RepackAsync(fixture.Source, fixture.Raw, fixture.Raw.Length, fixture.OutputPath));
    }

    [Fact]
    public async Task Rejects_HashImageSizeThatDoesNotMatchFooter()
    {
        SourceFixture fixture = CreateFixture(
            "be001-hash-image-size",
            spec => spec.RawHashDescriptor = BuildHashDescriptor(
                "sha256",
                RoundUp(4096 + spec.KernelSize, 4096) + 4096,
                spec.Salt,
                32,
                0));
        await Assert.ThrowsAsync<InvalidDataException>(
            () => RepackAsync(fixture.Source, fixture.Raw, fixture.Raw.Length, fixture.OutputPath));
    }

    [Fact]
    public async Task Rejects_StaleLengthClaim()
    {
        SourceFixture fixture = CreateFixture("be001-stale-length", _ => { });
        VerifiedEdlFile staleClaim = Verify(fixture.SourcePath);
        File.WriteAllBytes(fixture.SourcePath, File.ReadAllBytes(fixture.SourcePath).Concat(new byte[4096]).ToArray());

        await Assert.ThrowsAsync<InvalidDataException>(
            () => RepackAsync(staleClaim, fixture.Raw, fixture.Raw.Length, fixture.OutputPath));
    }

    [Fact]
    public async Task Rejects_ChangedShaClaim()
    {
        SourceFixture fixture = CreateFixture("be001-stale-sha", _ => { });
        VerifiedEdlFile staleClaim = Verify(fixture.SourcePath);
        byte[] bytes = File.ReadAllBytes(fixture.SourcePath);
        bytes[4096 + 3] ^= 0x5A;
        File.WriteAllBytes(fixture.SourcePath, bytes);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => RepackAsync(staleClaim, fixture.Raw, fixture.Raw.Length, fixture.OutputPath));
    }

    [Fact]
    public async Task Rejects_PackedRawWithoutArm64Magic()
    {
        string directory = NewDirectory("be001-raw-magic");
        string sourcePath = Path.Combine(directory, "source-boot.img");
        string rawPath = Path.Combine(directory, "packed-raw.img");
        string outputPath = Path.Combine(directory, "candidate-boot.img");

        WriteSource(sourcePath, new SourceSpec());
        byte[] raw = BuildRawImage(5000);
        raw[56] = 0;
        File.WriteAllBytes(rawPath, raw);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => RepackAsync(Verify(sourcePath), Verify(rawPath), raw.Length, outputPath));
    }

    [Fact]
    public async Task Rejects_PackedRawImageSizeMismatch()
    {
        string directory = NewDirectory("be001-raw-size");
        string sourcePath = Path.Combine(directory, "source-boot.img");
        string rawPath = Path.Combine(directory, "packed-raw.img");
        string outputPath = Path.Combine(directory, "candidate-boot.img");

        WriteSource(sourcePath, new SourceSpec());
        byte[] raw = BuildRawImage(5000);
        WriteLeU64(raw, 16, (ulong)raw.Length + 8);
        File.WriteAllBytes(rawPath, raw);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => RepackAsync(Verify(sourcePath), Verify(rawPath), raw.Length, outputPath));
    }

    [Fact]
    public async Task ExistingOutput_IsPreservedAndInputsRemainUntouched()
    {
        SourceFixture fixture = CreateFixture("be001-existing", _ => { });
        byte[] sentinel = { 9, 8, 7, 6, 5 };
        File.WriteAllBytes(fixture.OutputPath, sentinel);
        string sourceBefore = ToHex(SHA256.HashData(File.ReadAllBytes(fixture.SourcePath)));
        string rawBefore = ToHex(SHA256.HashData(File.ReadAllBytes(fixture.RawPath)));

        await Assert.ThrowsAsync<IOException>(
            () => RepackAsync(fixture.Source, fixture.Raw, fixture.Raw.Length, fixture.OutputPath));

        Assert.Equal(sentinel, File.ReadAllBytes(fixture.OutputPath));
        Assert.Equal(sourceBefore, ToHex(SHA256.HashData(File.ReadAllBytes(fixture.SourcePath))));
        Assert.Equal(rawBefore, ToHex(SHA256.HashData(File.ReadAllBytes(fixture.RawPath))));
        Assert.Equal(fixture.Source, Verify(fixture.SourcePath));
        Assert.Equal(fixture.Raw, Verify(fixture.RawPath));
    }

    [Fact]
    public async Task CancelledToken_StopsBeforeProducingOutput()
    {
        SourceFixture fixture = CreateFixture("be001-cancelled", _ => { });
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => RepackAsync(fixture.Source, fixture.Raw, fixture.Raw.Length, fixture.OutputPath, cancellation.Token));

        Assert.False(File.Exists(fixture.OutputPath));
    }

    [Fact]
    public async Task Capacity_ExactReserveBoundaryIsAccepted()
    {
        byte[] raw = BuildRawImage(5000);
        int gzipLength = GzipLength(raw);
        int expectedOriginal = 4096 + RoundUp(gzipLength, 4096);
        int partitionSize = expectedOriginal + 65536 + 4096;

        string directory = NewDirectory("be001-capacity-fit");
        string sourcePath = Path.Combine(directory, "source-boot.img");
        string rawPath = Path.Combine(directory, "packed-raw.img");
        string outputPath = Path.Combine(directory, "candidate-boot.img");

        WriteSource(sourcePath, new SourceSpec { PartitionSize = partitionSize, KernelSize = 4096 });
        File.WriteAllBytes(rawPath, raw);

        EdlRawBootEnvelope envelope = await RepackAsync(Verify(sourcePath), Verify(rawPath), raw.Length, outputPath);

        Assert.Equal((long)expectedOriginal, envelope.OriginalImageSize);
        Assert.Equal((long)partitionSize, new FileInfo(outputPath).Length);
    }

    [Fact]
    public async Task Capacity_OnePageBelowReserveBoundaryIsRejected()
    {
        byte[] raw = BuildRawImage(5000);
        int gzipLength = GzipLength(raw);
        int expectedOriginal = 4096 + RoundUp(gzipLength, 4096);
        int partitionSize = expectedOriginal + 65536;

        string directory = NewDirectory("be001-capacity-short");
        string sourcePath = Path.Combine(directory, "source-boot.img");
        string rawPath = Path.Combine(directory, "packed-raw.img");
        string outputPath = Path.Combine(directory, "candidate-boot.img");

        WriteSource(sourcePath, new SourceSpec { PartitionSize = partitionSize, KernelSize = 4096 });
        File.WriteAllBytes(rawPath, raw);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => RepackAsync(Verify(sourcePath), Verify(rawPath), raw.Length, outputPath));
        Assert.False(File.Exists(outputPath));
    }

    [Theory]
    [InlineData("authentication-hash")]
    [InlineData("auxiliary")]
    [InlineData("signature")]
    public async Task CandidateVbmetaVerifier_RejectsEditsToHashAuxiliaryAndSignature(string mutation)
    {
        byte[] vbmeta = await BuildCandidateVbmetaAsync("be001-verify-" + mutation);
        InvokeVerifyCandidateVbmetaSignature(vbmeta);

        const int authStart = 256;
        const int auxStart = 256 + 576;
        int offset = mutation switch
        {
            "authentication-hash" => authStart + 5,
            "auxiliary" => auxStart + 9,
            "signature" => authStart + 32 + 7,
            _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
        };

        vbmeta[offset] ^= 0x5A;
        Assert.Throws<InvalidDataException>(() => InvokeVerifyCandidateVbmetaSignature(vbmeta));
    }

    [Fact]
    public void AvbSigningKeyLoader_RejectsNonRsaPem()
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string pem = ecdsa.ExportPkcs8PrivateKeyPem();
        using MemoryStream stream = new(Encoding.ASCII.GetBytes(pem));

        Assert.Throws<InvalidDataException>(() => InvokeLoadAvbSigningKey(stream));
    }

    [Fact]
    public void AvbSigningKeyLoader_RejectsUnpinned4096BitRsaPem()
    {
        using RSA rsa = RSA.Create(4096);
        string pem = rsa.ExportPkcs8PrivateKeyPem();
        using MemoryStream stream = new(Encoding.ASCII.GetBytes(pem));

        Assert.Throws<InvalidDataException>(() => InvokeLoadAvbSigningKey(stream));
    }

    private static async Task<byte[]> BuildCandidateVbmetaAsync(string name)
    {
        string directory = NewDirectory(name);
        string sourcePath = Path.Combine(directory, "source-boot.img");
        string rawPath = Path.Combine(directory, "packed-raw.img");
        string outputPath = Path.Combine(directory, "candidate-boot.img");

        WriteSource(sourcePath, new SourceSpec());
        byte[] raw = BuildRawImage(5000);
        File.WriteAllBytes(rawPath, raw);

        EdlRawBootEnvelope envelope = await RepackAsync(Verify(sourcePath), Verify(rawPath), raw.Length, outputPath);
        byte[] image = File.ReadAllBytes(outputPath);
        byte[] vbmeta = new byte[(int)envelope.VbmetaBytes];
        Buffer.BlockCopy(image, (int)envelope.VbmetaOffset, vbmeta, 0, vbmeta.Length);
        return vbmeta;
    }

    private static void InvokeVerifyCandidateVbmetaSignature(byte[] vbmeta)
    {
        try
        {
            VerifyCandidateVbmetaSignatureMethod.Invoke(null, new object[] { vbmeta });
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            throw exception.InnerException;
        }
    }

    private static void InvokeLoadAvbSigningKey(Stream stream)
    {
        try
        {
            using RSA key = (RSA)LoadAvbSigningKeyMethod.Invoke(null, new object[] { stream })!;
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            throw exception.InnerException;
        }
    }

    private static SourceFixture CreateFixture(string name, Action<SourceSpec> configure)
    {
        string directory = NewDirectory(name);
        string sourcePath = Path.Combine(directory, "source-boot.img");
        string rawPath = Path.Combine(directory, "packed-raw.img");
        string outputPath = Path.Combine(directory, "candidate-boot.img");

        var spec = new SourceSpec();
        configure(spec);
        WriteSource(sourcePath, spec);

        byte[] raw = BuildRawImage(5000);
        File.WriteAllBytes(rawPath, raw);

        return new SourceFixture(sourcePath, rawPath, outputPath, Verify(sourcePath), Verify(rawPath));
    }

    private static Task<EdlRawBootEnvelope> RepackAsync(
        VerifiedEdlFile source,
        VerifiedEdlFile raw,
        long maxRawBytes,
        string outputPath,
        CancellationToken cancellationToken = default)
    {
        object? result;
        try
        {
            result = RepackMethod.Invoke(
                null,
                new object[] { source, raw, maxRawBytes, outputPath, cancellationToken });
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            throw exception.InnerException;
        }

        return (Task<EdlRawBootEnvelope>)result!;
    }

    private static VerifiedEdlFile Verify(string path)
    {
        byte[] bytes = File.ReadAllBytes(path);
        return new VerifiedEdlFile(Path.GetFullPath(path), bytes.Length, ToHex(SHA256.HashData(bytes)));
    }

    private static string NewDirectory(string name)
    {
        string root = TestArtifactRoot.Resolve().ToString();
        string directory = Path.Combine(root, name + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }

    private static SourceLayout WriteSource(string path, SourceSpec spec)
    {
        int original = RoundUp(4096 + spec.KernelSize, 4096);
        byte[] vbmeta = BuildVbmeta(spec, original);
        byte[] image = new byte[spec.PartitionSize];

        WriteAscii(image, 0, "ANDROID!");
        WriteLeU32(image, 8, (uint)spec.KernelSize);
        WriteLeU32(image, 12, spec.RamdiskSize);
        WriteLeU32(image, 20, 1584);
        WriteLeU32(image, 40, spec.HeaderVersion);
        WriteLeU32(image, 1580, spec.SignatureSize);
        for (int i = 4096; i < 4096 + spec.KernelSize; i++)
        {
            image[i] = 0x5A;
        }

        Buffer.BlockCopy(vbmeta, 0, image, original, vbmeta.Length);

        WriteAscii(image, image.Length - 64, spec.FooterMagic);
        WriteBeU32(image, image.Length - 60, spec.FooterMajor);
        WriteBeU32(image, image.Length - 56, 0);
        WriteBeU64(image, image.Length - 52, (ulong)(spec.FooterOriginalImageSize ?? original));
        WriteBeU64(image, image.Length - 44, (ulong)(spec.FooterVbmetaOffset ?? original));
        WriteBeU64(image, image.Length - 36, (ulong)(spec.FooterVbmetaSize ?? vbmeta.Length));

        File.WriteAllBytes(path, image);
        return new SourceLayout(spec.PartitionSize, original, original, vbmeta.Length, original + 256);
    }

    private static byte[] BuildVbmeta(SourceSpec spec, int imageSize)
    {
        int digestLength = spec.DigestLength ?? (spec.Algorithm == "sha512" ? 64 : 32);
        byte[] hashDescriptor = spec.RawHashDescriptor
            ?? BuildHashDescriptor(spec.Algorithm, imageSize, spec.Salt, digestLength, spec.Flags);
        var descriptors = new List<byte[]>();
        for (int i = 0; i < spec.HashDescriptorCopies; i++)
        {
            descriptors.Add(hashDescriptor);
        }

        foreach ((string key, string value) in spec.Properties)
        {
            descriptors.Add(BuildPropertyDescriptor(key, value));
        }

        descriptors.AddRange(spec.RawPropertyDescriptors);

        int descriptorBytes = descriptors.Sum(item => item.Length);
        int auxSize = RoundUp(descriptorBytes, 64);
        byte[] vbmeta = new byte[256 + auxSize];

        WriteAscii(vbmeta, 0, "AVB0");
        WriteBeU32(vbmeta, 4, 1);
        WriteBeU32(vbmeta, 8, 0);
        WriteBeU64(vbmeta, 12, 0);
        WriteBeU64(vbmeta, 20, (ulong)auxSize);
        WriteBeU32(vbmeta, 28, 0);
        WriteBeU64(vbmeta, 64, (ulong)descriptorBytes);
        WriteBeU64(vbmeta, 80, (ulong)descriptorBytes);
        WriteBeU64(vbmeta, 96, 0);
        WriteBeU64(vbmeta, 104, (ulong)descriptorBytes);
        WriteBeU64(vbmeta, 112, spec.RollbackIndex);
        WriteBeU32(vbmeta, 120, spec.HeaderFlags);
        WriteBeU32(vbmeta, 124, spec.RollbackLocation);
        WriteAscii(vbmeta, 128, "avbtool-synthetic");

        int position = 256;
        foreach (byte[] descriptor in descriptors)
        {
            Buffer.BlockCopy(descriptor, 0, vbmeta, position, descriptor.Length);
            position += descriptor.Length;
        }

        return vbmeta;
    }

    private static byte[] BuildHashDescriptor(
        string algorithm,
        int imageSize,
        byte[] salt,
        int digestLength,
        uint flags)
    {
        const string name = "boot";
        int exactLength = 132 + name.Length + salt.Length + digestLength;
        byte[] descriptor = new byte[RoundUp(exactLength, 8)];

        WriteBeU64(descriptor, 0, 2);
        WriteBeU64(descriptor, 8, (ulong)(descriptor.Length - 16));
        WriteBeU64(descriptor, 16, (ulong)imageSize);
        WriteAscii(descriptor, 24, algorithm);
        WriteBeU32(descriptor, 56, (uint)name.Length);
        WriteBeU32(descriptor, 60, (uint)salt.Length);
        WriteBeU32(descriptor, 64, (uint)digestLength);
        WriteBeU32(descriptor, 68, flags);

        int position = 132;
        WriteAscii(descriptor, position, name);
        position += name.Length;
        Buffer.BlockCopy(salt, 0, descriptor, position, salt.Length);
        position += salt.Length;
        for (int i = 0; i < digestLength; i++)
        {
            descriptor[position + i] = (byte)(0x30 + i);
        }

        return descriptor;
    }

    private static byte[] BuildPropertyDescriptor(string key, string value)
    {
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] valueBytes = Encoding.UTF8.GetBytes(value);
        int exactLength = 32 + keyBytes.Length + 1 + valueBytes.Length + 1;
        byte[] descriptor = new byte[RoundUp(exactLength, 8)];

        WriteBeU64(descriptor, 0, 0);
        WriteBeU64(descriptor, 8, (ulong)(descriptor.Length - 16));
        WriteBeU64(descriptor, 16, (ulong)keyBytes.Length);
        WriteBeU64(descriptor, 24, (ulong)valueBytes.Length);
        Buffer.BlockCopy(keyBytes, 0, descriptor, 32, keyBytes.Length);
        Buffer.BlockCopy(valueBytes, 0, descriptor, 32 + keyBytes.Length + 1, valueBytes.Length);
        return descriptor;
    }

    private static byte[] RawDescriptor(ulong tag, byte[] payload)
    {
        byte[] descriptor = new byte[RoundUp(16 + payload.Length, 8)];
        WriteBeU64(descriptor, 0, tag);
        WriteBeU64(descriptor, 8, (ulong)(descriptor.Length - 16));
        Buffer.BlockCopy(payload, 0, descriptor, 16, payload.Length);
        return descriptor;
    }

    private static byte[] BuildRawImage(int length)
    {
        byte[] raw = new byte[length];
        WriteLeU64(raw, 16, (ulong)length);
        WriteAscii(raw, 56, "ARMd");
        return raw;
    }

    private static int GzipLength(byte[] data)
    {
        using MemoryStream output = new();
        using (GZipStream compressor = new(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            compressor.Write(data, 0, data.Length);
        }

        return checked((int)output.Length);
    }

    private static byte[] SaltedDigest(string algorithm, byte[] salt, byte[] image, int length)
    {
        HashAlgorithmName name = algorithm == "sha512" ? HashAlgorithmName.SHA512 : HashAlgorithmName.SHA256;
        using IncrementalHash hash = IncrementalHash.CreateHash(name);
        hash.AppendData(salt);
        hash.AppendData(image.AsSpan(0, length));
        return hash.GetHashAndReset();
    }

    private static byte[] ReadOutputHashDigest(byte[] image, int vbmetaOffset)
    {
        int authSize = (int)ReadBeU64(image, vbmetaOffset + 12);
        int auxBase = vbmetaOffset + 256 + authSize;
        int descriptorsOffset = (int)ReadBeU64(image, vbmetaOffset + 96);
        int descriptorsSize = (int)ReadBeU64(image, vbmetaOffset + 104);
        int position = auxBase + descriptorsOffset;
        int end = position + descriptorsSize;

        while (position < end)
        {
            ulong tag = ReadBeU64(image, position);
            long total = 16 + (long)ReadBeU64(image, position + 8);
            if (tag == 2)
            {
                uint nameLength = ReadBeU32(image, position + 56);
                uint saltLength = ReadBeU32(image, position + 60);
                uint digestLength = ReadBeU32(image, position + 64);
                int digestStart = position + 132 + (int)nameLength + (int)saltLength;
                byte[] digest = new byte[digestLength];
                Buffer.BlockCopy(image, digestStart, digest, 0, digest.Length);
                return digest;
            }

            position += (int)total;
        }

        throw new InvalidOperationException("output hash descriptor was not found");
    }

    // Independent oracle for the AVB SHA256_RSA4096 candidate contract. Reads the
    // emitted vbmeta region directly, checks every header field, re-hashes header
    // concatenated with the full auxiliary block, and authenticates the signature
    // with the embedded 4096-bit public key blob. It shares no production type and
    // no production digest helper, and its SHA256 authentication is fixed regardless
    // of the source hash descriptor algorithm (SHA256 or SHA512).
    private static void AssertRsa4096Vbmeta(byte[] image, int vbmetaOffset)
    {
        Assert.True(vbmetaOffset >= 0);
        Assert.True(vbmetaOffset + 256 <= image.Length);

        byte[] header = new byte[256];
        Buffer.BlockCopy(image, vbmetaOffset, header, 0, header.Length);

        Assert.Equal("AVB0", Encoding.ASCII.GetString(header, 0, 4));
        Assert.Equal(2u, ReadBeU32(header, 28));

        int authSize = (int)ReadBeU64(header, 12);
        int auxSize = (int)ReadBeU64(header, 20);
        Assert.Equal(576, authSize);
        Assert.Equal(0, auxSize % 64);
        Assert.True(vbmetaOffset + 256 + authSize + auxSize <= image.Length);

        byte[] auth = new byte[authSize];
        Buffer.BlockCopy(image, vbmetaOffset + 256, auth, 0, authSize);
        byte[] aux = new byte[auxSize];
        Buffer.BlockCopy(image, vbmetaOffset + 256 + authSize, aux, 0, auxSize);

        int descriptorsLength = (int)ReadBeU64(header, 104);
        Assert.Equal(0UL, ReadBeU64(header, 32));
        Assert.Equal(32UL, ReadBeU64(header, 40));
        Assert.Equal(32UL, ReadBeU64(header, 48));
        Assert.Equal(512UL, ReadBeU64(header, 56));
        Assert.Equal((ulong)descriptorsLength, ReadBeU64(header, 64));
        Assert.Equal(1032UL, ReadBeU64(header, 72));
        Assert.Equal((ulong)(descriptorsLength + 1032), ReadBeU64(header, 80));
        Assert.Equal(0UL, ReadBeU64(header, 88));
        Assert.Equal(0UL, ReadBeU64(header, 96));
        Assert.Equal((ulong)descriptorsLength, ReadBeU64(header, 104));

        Assert.Equal(
            (ulong)(256 + authSize + auxSize),
            ReadBeU64(image, image.Length - 36));

        byte[] digest = auth.AsSpan(0, 32).ToArray();
        using (IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            hash.AppendData(header);
            hash.AppendData(aux);
            Assert.Equal(hash.GetHashAndReset(), digest);
        }

        for (int i = 544; i < authSize; i++)
        {
            Assert.Equal(0, auth[i]);
        }

        Assert.True(descriptorsLength + 1032 <= auxSize);
        for (int i = descriptorsLength + 1032; i < auxSize; i++)
        {
            Assert.Equal(0, aux[i]);
        }

        byte[] publicKey = new byte[1032];
        Buffer.BlockCopy(aux, descriptorsLength, publicKey, 0, publicKey.Length);
        Assert.Equal(4096u, ReadBeU32(publicKey, 0));
        Assert.Equal(
            "7728E30F50BFA5CEA165F473175A08803F6A8346642B5AA10913E9D9E6DEFEF6",
            Convert.ToHexString(SHA256.HashData(publicKey)));

        byte[] modulus = new byte[512];
        Buffer.BlockCopy(publicKey, 8, modulus, 0, modulus.Length);
        Assert.Equal(
            "36949B827927C883836897AB67EB01360795186CB81FACA37EF7DE583A1B65B1",
            Convert.ToHexString(SHA256.HashData(modulus)));

        byte[] signature = new byte[512];
        Buffer.BlockCopy(auth, 32, signature, 0, signature.Length);

        using RSA rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = modulus,
            Exponent = new byte[] { 0x01, 0x00, 0x01 },
        });
        Assert.True(
            rsa.VerifyHash(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            "vbmeta signature must authenticate SHA256(header || auxiliary) with the embedded RSA-4096 key");
    }

    private static int RoundUp(int value, int alignment)
    {
        int remainder = value % alignment;
        return remainder == 0 ? value : value + (alignment - remainder);
    }

    private static string ToHex(byte[] bytes)
    {
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static uint ReadLeU32(byte[] buffer, int offset)
    {
        return BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offset, 4));
    }

    private static uint ReadBeU32(byte[] buffer, int offset)
    {
        return BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(offset, 4));
    }

    private static ulong ReadBeU64(byte[] buffer, int offset)
    {
        return BinaryPrimitives.ReadUInt64BigEndian(buffer.AsSpan(offset, 8));
    }

    private static void WriteLeU32(byte[] buffer, int offset, uint value)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset, 4), value);
    }

    private static void WriteLeU64(byte[] buffer, int offset, ulong value)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(offset, 8), value);
    }

    private static void WriteBeU32(byte[] buffer, int offset, uint value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(offset, 4), value);
    }

    private static void WriteBeU64(byte[] buffer, int offset, ulong value)
    {
        BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(offset, 8), value);
    }

    private static void WriteAscii(byte[] buffer, int offset, string text)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(text);
        Buffer.BlockCopy(bytes, 0, buffer, offset, bytes.Length);
    }

    private sealed class SourceSpec
    {
        public int PartitionSize { get; set; } = 262144;

        public int KernelSize { get; set; } = 8192;

        public string Algorithm { get; set; } = "sha256";

        public byte[] Salt { get; set; } = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

        public int? DigestLength { get; set; }

        public uint Flags { get; set; }

        public ulong RollbackIndex { get; set; } = 11;

        public uint RollbackLocation { get; set; } = 2;

        public List<(string Key, string Value)> Properties { get; } = new();

        public byte[]? RawHashDescriptor { get; set; }

        public int HashDescriptorCopies { get; set; } = 1;

        public List<byte[]> RawPropertyDescriptors { get; } = new();

        public uint HeaderFlags { get; set; }

        public uint HeaderVersion { get; set; } = 4;

        public uint RamdiskSize { get; set; }

        public uint SignatureSize { get; set; }

        public string FooterMagic { get; set; } = "AVBf";

        public uint FooterMajor { get; set; } = 1;

        public long? FooterOriginalImageSize { get; set; }

        public long? FooterVbmetaOffset { get; set; }

        public long? FooterVbmetaSize { get; set; }
    }

    private sealed record SourceLayout(
        int PartitionSize,
        int OriginalImageSize,
        int VbmetaOffset,
        int VbmetaSize,
        int HashDescriptorOffset);

    private sealed record SourceFixture(
        string SourcePath,
        string RawPath,
        string OutputPath,
        VerifiedEdlFile Source,
        VerifiedEdlFile Raw);
}
