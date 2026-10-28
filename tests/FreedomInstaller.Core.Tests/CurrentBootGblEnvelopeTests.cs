// regression specification of the narrow current-GBL envelope
// primitive. The current GBL hybrid (footer image_size = new payload, OEM
// descriptor image_size = old stock size) is built with the real existing
// preservation helper over the genuine native fixture, then consumed by the
// new primitive through one reflection adapter (the test assembly has no
// friend access). Every oracle is an independent BCL hash, footer, blob or
// gzip read; nothing is accepted on method existence alone and no OEM
// payload verification or hardware acceptance is asserted.
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;
using AvbFixture = FreedomInstaller.Core.Tests.EdlRawAvbChainTests.AvbFixture;

namespace FreedomInstaller.Core.Tests;

public sealed class CurrentBootGblEnvelopeTests : IClassFixture<EdlRawGblEnvelopeTests.SharedFixture>, IDisposable
{
    private const long RawBudgetBytes = 64L * 1024L * 1024L;

    private const int FooterSizeBytes = 64;

    private const int VbmetaHeaderSizeBytes = 256;

    private const int MaxMetadataArrayBytes = 1024 * 1024;

    private readonly EdlRawGblEnvelopeTests.SharedFixture _fixture;

    private readonly List<IDisposable> _stagedSources = new();

    public CurrentBootGblEnvelopeTests(EdlRawGblEnvelopeTests.SharedFixture fixture)
    {
        _fixture = fixture;
    }

    public void Dispose()
    {
        foreach (IDisposable staged in _stagedSources)
        {
            staged.Dispose();
        }

        _stagedSources.Clear();
    }

    // ------------------------------------------------ 1. the actual bug regression

    [Fact]
    public async Task Repack_CurrentGblHybridFooterNewDescriptorOld_PreservesSignedBlobAndReportsStaleDigest()
    {
        EdlRawGblEnvelopeTests.SharedFixture fx = _fixture;
        string caseDir = NewCaseDirectory(fx);
        string sourcePath = await StageCurrentGblSourceAsync(fx, caseDir, "current-gbl-source.img");
        string rawPath = BuildRawVariant(fx, caseDir, "default-zero.raw", 0u);
        string candidatePath = Path.Combine(caseDir, "effective.img");

        // bug precondition: the hybrid footer already disagrees with the signed descriptor
        (long footerNewSize, long footerBlobOffset, long footerBlobSize) = ReadFooter(sourcePath);
        byte[] sourceBlob = ReadRange(sourcePath, footerBlobOffset, footerBlobSize);
        AvbFixture.AssertAuthenticatedSignedBlob(sourceBlob);
        (long signedOldSize, byte[] salt, byte[] descriptorDigest) = ParseBootHashDescriptor(sourceBlob);
        Assert.Equal(ReadFooter(fx.NormalOriginal.Path).ImageSize, signedOldSize);
        Assert.NotEqual(footerNewSize, signedOldSize);

        string originalSha = Sha256OfFile(fx.NormalOriginal.Path);
        string builtSha = Sha256OfFile(fx.NormalBuilt.CandidateBoot.Path);
        string sourceSha = Sha256OfFile(sourcePath);
        string rawSha = Sha256OfFile(rawPath);
        string[] entriesBefore = EntriesOf(caseDir);

        object result = (await InvokeAwaitAsync(
            RepackMethod,
            Claim(sourcePath),
            Claim(rawPath),
            RawBudgetBytes,
            candidatePath,
            CancellationToken.None))!;

        // candidate is a real file of the unchanged partition length
        VerifiedEdlFile candidate = ClaimOf(result, "Candidate");
        Assert.Equal(Path.GetFullPath(candidatePath), Path.GetFullPath(candidate.Path));
        long partitionLength = new FileInfo(sourcePath).Length;
        Assert.Equal(partitionLength, new FileInfo(candidatePath).Length);
        Assert.Equal(new FileInfo(fx.NormalOriginal.Path).Length, partitionLength);

        // footer carries the new payload geometry, blob size unchanged
        (long newImageSize, long newBlobOffset, long newBlobSize) = ReadFooter(candidatePath);
        Assert.Equal(newImageSize, Num(result, "PayloadBytes"));
        Assert.Equal(newBlobOffset, Num(result, "VbmetaOffset"));
        Assert.Equal(newBlobSize, Num(result, "VbmetaBytes"));
        Assert.Equal(footerBlobSize, newBlobSize);
        Assert.NotEqual(signedOldSize, newImageSize);

        // exact original signed blob, authenticated again at the new location
        byte[] candidateBlob = ReadRange(candidatePath, newBlobOffset, newBlobSize);
        Assert.True(candidateBlob.AsSpan().SequenceEqual(sourceBlob));
        AvbFixture.AssertAuthenticatedSignedBlob(candidateBlob);

        // the candidate kernel decompresses to exactly the new raw variant
        Assert.Equal(rawSha, DecompressedKernelSha256(candidatePath));
        Assert.NotEqual(Sha256OfFile(fx.NormalBuilt.PackedRaw.Path), rawSha);
        Assert.Equal(Sha256OfPrefix(candidatePath, newImageSize), Text(result, "PayloadSha256"));

        // facts come from the old signed descriptor; the digest is honestly stale
        object facts = Read(result, "Facts");
        Assert.Equal(Convert.ToHexString(SHA256.HashData(sourceBlob)).ToLowerInvariant(), Text(facts, "SignedVbmetaSha256"));
        Assert.Equal(fx.DefaultOemKeySha.ToLowerInvariant(), Text(facts, "PublicKeySha256"));
        Assert.Equal(signedOldSize, Num(facts, "SignedContentBytes"));
        Assert.Equal(Convert.ToHexString(descriptorDigest).ToLowerInvariant(), Text(facts, "SignedContentDigestHex"));
        Assert.Equal(SaltedSha256Hex(salt, candidatePath, signedOldSize), Text(facts, "EffectiveContentDigestHex"));
        Assert.NotEqual(Text(facts, "SignedContentDigestHex"), Text(facts, "EffectiveContentDigestHex"));
        Assert.False(Bool(facts, "ContentDigestMatches"));

        // nothing but zeros between the blob and the footer
        AssertAllZero(candidatePath, newBlobOffset + newBlobSize, partitionLength - FooterSizeBytes);

        // inputs untouched, no temp left behind
        Assert.Equal(originalSha, Sha256OfFile(fx.NormalOriginal.Path));
        Assert.Equal(builtSha, Sha256OfFile(fx.NormalBuilt.CandidateBoot.Path));
        Assert.Equal(sourceSha, Sha256OfFile(sourcePath));
        Assert.Equal(
            entriesBefore.Append(Path.GetFileName(candidatePath)).OrderBy(name => name, StringComparer.Ordinal).ToArray(),
            EntriesOf(caseDir));
    }

    // ------------------------------------------------ 2. second pass over own output

    [Fact]
    public async Task Repack_SecondPassFromOwnOutput_SecondVariant_KeepsExactOemBlobAndReportsGeometry()
    {
        EdlRawGblEnvelopeTests.SharedFixture fx = _fixture;
        string caseDir = NewCaseDirectory(fx);
        string sourcePath = await StageCurrentGblSourceAsync(fx, caseDir, "current-gbl-source.img");
        string rawPath1 = BuildRawVariant(fx, caseDir, "default-zero.raw", 0u);
        string candidatePath1 = Path.Combine(caseDir, "effective-1.img");

        object result1 = (await InvokeAwaitAsync(
            RepackMethod,
            Claim(sourcePath),
            Claim(rawPath1),
            RawBudgetBytes,
            candidatePath1,
            CancellationToken.None))!;

        byte[] oemBlob = SignedBlobOf(fx.NormalOriginal.Path);
        byte[] blob1 = SignedBlobOf(candidatePath1);
        Assert.True(blob1.AsSpan().SequenceEqual(oemBlob));

        // second repack: the first output becomes the source, another nonzero default
        string rawPath2 = BuildRawVariant(fx, caseDir, "default-two.raw", 2u);
        string candidatePath2 = Path.Combine(caseDir, "effective-2.img");
        object result2 = (await InvokeAwaitAsync(
            RepackMethod,
            Claim(candidatePath1),
            Claim(rawPath2),
            RawBudgetBytes,
            candidatePath2,
            CancellationToken.None))!;

        // no AOSP intermediate: the same OEM blob, same OEM key, authenticated again
        (long imageSize2, long blobOffset2, long blobSize2) = ReadFooter(candidatePath2);
        byte[] blob2 = ReadRange(candidatePath2, blobOffset2, blobSize2);
        Assert.True(blob2.AsSpan().SequenceEqual(oemBlob));
        AvbFixture.AssertAuthenticatedSignedBlob(blob2);
        object facts2 = Read(result2, "Facts");
        Assert.Equal(fx.DefaultOemKeySha.ToLowerInvariant(), Text(facts2, "PublicKeySha256"));

        // the reported hash geometry is the actual physical geometry
        Assert.Equal(imageSize2, Num(result2, "PayloadBytes"));
        Assert.Equal(blobOffset2, Num(result2, "VbmetaOffset"));
        Assert.Equal(blobSize2, Num(result2, "VbmetaBytes"));
        Assert.Equal(Sha256OfPrefix(candidatePath2, imageSize2), Text(result2, "PayloadSha256"));
        Assert.Equal(Sha256OfFile(rawPath2), DecompressedKernelSha256(candidatePath2));
        Assert.False(Bool(facts2, "ContentDigestMatches"));
        Assert.Equal(new FileInfo(sourcePath).Length, new FileInfo(candidatePath2).Length);
    }

    // ------------------------------------------------ 3. corrupted source RSA blob

    [Fact]
    public async Task Repack_CorruptSignedBlobWithFreshClaim_IsRejectedWithoutOutput()
    {
        EdlRawGblEnvelopeTests.SharedFixture fx = _fixture;
        string caseDir = NewCaseDirectory(fx);
        string sourcePath = await StageCurrentGblSourceAsync(fx, caseDir, "current-gbl-source.img");
        string rawPath = BuildRawVariant(fx, caseDir, "default-zero.raw", 0u);
        string candidatePath = Path.Combine(caseDir, "effective.img");

        string tamperedPath = Path.Combine(caseDir, "tampered-source.img");
        CopyFile(sourcePath, tamperedPath);
        (long _, long blobOffset, long _) = ReadFooter(tamperedPath);
        FlipByte(tamperedPath, blobOffset + VbmetaHeaderSizeBytes + 64);

        // a refreshed whole-file claim passes the outer claim check but the
        // authenticated leaf reader must still reject the broken RSA blob
        VerifiedEdlFile freshClaim = Claim(tamperedPath);
        string tamperedSha = Sha256OfFile(tamperedPath);
        string[] entriesBefore = EntriesOf(caseDir);

        await Assert.ThrowsAsync<InvalidDataException>(() => InvokeAwaitAsync(
            RepackMethod,
            freshClaim,
            Claim(rawPath),
            RawBudgetBytes,
            candidatePath,
            CancellationToken.None));

        Assert.False(File.Exists(candidatePath));
        Assert.Equal(entriesBefore, EntriesOf(caseDir));
        Assert.Equal(tamperedSha, Sha256OfFile(tamperedPath));
        Assert.Equal(Sha256OfFile(fx.NormalOriginal.Path), Sha256OfFile(fx.NormalOriginal.Path));
    }

    // ------------------------------------------------ 4. raw claim / budget mismatch

    [Theory]
    [InlineData("claim")]
    [InlineData("budget")]
    public async Task Repack_RawClaimOrBudgetMismatch_IsRejectedWithoutOutput(string variant)
    {
        EdlRawGblEnvelopeTests.SharedFixture fx = _fixture;
        string caseDir = NewCaseDirectory(fx);
        string sourcePath = await StageCurrentGblSourceAsync(fx, caseDir, "current-gbl-source.img");
        string rawPath = BuildRawVariant(fx, caseDir, "default-zero.raw", 0u);
        string candidatePath = Path.Combine(caseDir, "effective.img");
        string[] entriesBefore = EntriesOf(caseDir);

        VerifiedEdlFile rawClaim;
        long budget = RawBudgetBytes;
        if (variant == "claim")
        {
            string staleSha = Sha256OfFile(rawPath);
            FlipByte(rawPath, 4096 + 16);
            rawClaim = new VerifiedEdlFile(Path.GetFullPath(rawPath), new FileInfo(rawPath).Length, staleSha);
        }
        else
        {
            rawClaim = Claim(rawPath);
            budget = new FileInfo(rawPath).Length - 1;
        }

        await Assert.ThrowsAsync<InvalidDataException>(() => InvokeAwaitAsync(
            RepackMethod,
            Claim(sourcePath),
            rawClaim,
            budget,
            candidatePath,
            CancellationToken.None));

        Assert.False(File.Exists(candidatePath));
        Assert.Equal(entriesBefore, EntriesOf(caseDir));
    }

    // ------------------------------------------------ 5. existing candidate sentinel

    [Fact]
    public async Task Repack_ExistingCandidateSurvivesCreateNewRefusal()
    {
        EdlRawGblEnvelopeTests.SharedFixture fx = _fixture;
        string caseDir = NewCaseDirectory(fx);
        string sourcePath = await StageCurrentGblSourceAsync(fx, caseDir, "current-gbl-source.img");
        string rawPath = BuildRawVariant(fx, caseDir, "default-zero.raw", 0u);
        string candidatePath = Path.Combine(caseDir, "effective.img");
        byte[] sentinel = Encoding.ASCII.GetBytes("sentinel-payload");
        File.WriteAllBytes(candidatePath, sentinel);
        string[] entriesBefore = EntriesOf(caseDir);

        await Assert.ThrowsAsync<IOException>(() => InvokeAwaitAsync(
            RepackMethod,
            Claim(sourcePath),
            Claim(rawPath),
            RawBudgetBytes,
            candidatePath,
            CancellationToken.None));

        Assert.True(sentinel.AsSpan().SequenceEqual(File.ReadAllBytes(candidatePath)));
        Assert.Equal(entriesBefore, EntriesOf(caseDir));
    }

    // ------------------------------------------------ 6. precancel, no I/O

    [Fact]
    public async Task Repack_AlreadyCancelledTokenTouchesNothing()
    {
        EdlRawGblEnvelopeTests.SharedFixture fx = _fixture;
        string caseDir = NewCaseDirectory(fx);

        // both claims point at files that do not exist: any I/O would fail loudly
        var missing = new VerifiedEdlFile(
            Path.Combine(caseDir, "missing-source.img"), 1, new string('0', 64));
        string candidatePath = Path.Combine(caseDir, "effective.img");

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => InvokeAwaitAsync(
            RepackMethod,
            missing,
            missing,
            RawBudgetBytes,
            candidatePath,
            cancellation.Token));

        Assert.Empty(EntriesOf(caseDir));
        Assert.False(File.Exists(candidatePath));
    }

    // ------------------------------------------------ reflection boundary

    private static readonly MethodInfo RepackMethod = RequireMethod(
        typeof(EdlRawBootBuilder),
        "RepackCurrentGblEnvelopeAsync",
        typeof(VerifiedEdlFile),
        typeof(VerifiedEdlFile),
        typeof(long),
        typeof(string),
        typeof(CancellationToken));

    private static readonly MethodInfo PreserveMethod = RequireMethod(
        typeof(EdlRawBootBuilder),
        "PreserveOriginalSignedBootMetadataAsync",
        typeof(EdlRawBuiltBoot),
        typeof(VerifiedEdlFile),
        typeof(string),
        typeof(CancellationToken));

    private static MethodInfo RequireMethod(Type type, string name, params Type[] parameters)
    {
        MethodInfo? method = type.GetMethod(
            name,
            BindingFlags.NonPublic | BindingFlags.Static,
            binder: null,
            types: parameters,
            modifiers: null);
        Assert.NotNull(method);
        return method!;
    }

    private static async Task<object?> InvokeAwaitAsync(MethodInfo method, params object?[] arguments)
    {
        object? invocation;
        try
        {
            invocation = method.Invoke(null, arguments);
        }
        catch (TargetInvocationException ex) when (ex.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
            throw;
        }

        Task task = Assert.IsAssignableFrom<Task>(invocation);
        await task.ConfigureAwait(false);
        PropertyInfo? result = task.GetType().GetProperty("Result");
        return result?.GetValue(task);
    }

    private static object Read(object instance, string name)
    {
        object? value = instance.GetType()
            .GetProperty(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            ?.GetValue(instance);
        Assert.NotNull(value);
        return value!;
    }

    private static string Text(object instance, string name) =>
        Convert.ToString(Read(instance, name), CultureInfo.InvariantCulture)!;

    private static long Num(object instance, string name) =>
        Convert.ToInt64(Read(instance, name), CultureInfo.InvariantCulture);

    private static bool Bool(object instance, string name) =>
        Convert.ToBoolean(Read(instance, name), CultureInfo.InvariantCulture);

    private static VerifiedEdlFile ClaimOf(object instance, string name) =>
        Assert.IsType<VerifiedEdlFile>(Read(instance, name));

    // ------------------------------------------------ independent byte oracles

    private static string NewCaseDirectory(EdlRawGblEnvelopeTests.SharedFixture fixture)
    {
        string directory = Path.Combine(fixture.Workspace.Root, "current-gbl-case-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }

    // Real existing GBL wrapper source: the genuine preservation helper turns
    // the fixture build into the current-GBL hybrid (new footer, old blob).
    private async Task<string> StageCurrentGblSourceAsync(
        EdlRawGblEnvelopeTests.SharedFixture fixture,
        string caseDir,
        string sourceName)
    {
        string sourcePath = Path.Combine(caseDir, sourceName);
        object? preserved = await InvokeAwaitAsync(
            PreserveMethod,
            fixture.NormalBuilt,
            fixture.NormalOriginal,
            sourcePath,
            CancellationToken.None);
        _stagedSources.Add(Assert.IsAssignableFrom<IDisposable>(preserved));
        Assert.True(File.Exists(sourcePath));
        return sourcePath;
    }

    private static string BuildRawVariant(
        EdlRawGblEnvelopeTests.SharedFixture fixture,
        string caseDir,
        string rawName,
        uint defaultValue)
    {
        string rawPath = Path.Combine(caseDir, rawName);
        CopyFile(fixture.NormalBuilt.PackedRaw.Path, rawPath);
        long rawLength = new FileInfo(rawPath).Length;

        byte[] head = ReadRange(rawPath, 0, 64);
        Assert.Equal("ARMd", Encoding.ASCII.GetString(head, 56, 4));
        long manifestOffset = (long)ReadLeU64(head, 32);
        Assert.True(manifestOffset > 0 && manifestOffset + 64 <= rawLength, "manifest offset out of bounds");

        // only the default word changes (ARM64 manifest offset LE64 at 32, default at +12)
        Assert.NotEqual(defaultValue, ReadU32At(rawPath, manifestOffset + 12));
        WriteU32At(rawPath, manifestOffset + 12, defaultValue);
        Assert.Equal(rawLength, new FileInfo(rawPath).Length);
        return rawPath;
    }

    private static (long ImageSize, long VbmetaOffset, long VbmetaSize) ReadFooter(string path)
    {
        using FileStream stream = OpenRead(path);
        var footer = new byte[FooterSizeBytes];
        stream.Position = stream.Length - FooterSizeBytes;
        ReadAll(stream, footer);
        Assert.Equal("AVBf", Encoding.ASCII.GetString(footer, 0, 4));
        Assert.Equal(1u, ReadBeU32(footer, 4));
        return (
            checked((long)ReadBeU64(footer, 12)),
            checked((long)ReadBeU64(footer, 20)),
            checked((long)ReadBeU64(footer, 28)));
    }

    private static byte[] SignedBlobOf(string path)
    {
        (_, long offset, long size) = ReadFooter(path);
        Assert.InRange(size, 1, MaxMetadataArrayBytes);
        return ReadRange(path, offset, size);
    }

    private static (long ImageSize, byte[] Salt, byte[] Digest) ParseBootHashDescriptor(byte[] blob)
    {
        Assert.True(blob.Length >= VbmetaHeaderSizeBytes);
        long authSize = (long)ReadBeU64(blob, 12);
        long auxSize = (long)ReadBeU64(blob, 20);
        long auxStart = VbmetaHeaderSizeBytes + authSize;
        long descriptorsOffset = (long)ReadBeU64(blob, 96);
        long descriptorsEnd = descriptorsOffset + (long)ReadBeU64(blob, 104);
        Assert.True(auxStart + descriptorsEnd <= blob.Length, "descriptor region outside the blob");

        long position = descriptorsOffset;
        while (position < descriptorsEnd)
        {
            Assert.True(descriptorsEnd - position >= 16, "truncated descriptor header");
            int at = (int)(auxStart + position);
            ulong tag = ReadBeU64(blob, at);
            long length = 16L + (long)ReadBeU64(blob, at + 8);
            if (tag == 2)
            {
                Assert.True(length >= 136, "hash descriptor too small");
                long imageSize = (long)ReadBeU64(blob, at + 16);
                uint saltLength = ReadBeU32(blob, at + 60);
                uint digestLength = ReadBeU32(blob, at + 64);
                Assert.True(132 + 4 + (long)saltLength + digestLength <= length, "descriptor fields exceed length");
                var salt = new byte[saltLength];
                Buffer.BlockCopy(blob, at + 136, salt, 0, salt.Length);
                var digest = new byte[digestLength];
                Buffer.BlockCopy(blob, checked(at + 136 + (int)saltLength), digest, 0, digest.Length);
                Assert.Equal("boot", Encoding.ASCII.GetString(blob, at + 132, 4));
                return (imageSize, salt, digest);
            }

            position += length;
        }

        throw new InvalidOperationException("no AVB hash descriptor found");
    }

    private static string DecompressedKernelSha256(string path)
    {
        using FileStream stream = OpenRead(path);
        var head = new byte[64];
        stream.Position = 0;
        ReadAll(stream, head);
        Assert.Equal("ANDROID!", Encoding.ASCII.GetString(head, 0, 8));
        long compressedLength = ReadLeU32(head, 8);
        Assert.InRange(compressedLength, 1, 32L * 1024L * 1024L);

        var compressed = new byte[compressedLength];
        stream.Position = 4096;
        ReadAll(stream, compressed);
        using var source = new MemoryStream(compressed);
        using GZipStream gzip = new GZipStream(source, CompressionMode.Decompress);
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[81920];
        int read;
        while ((read = gzip.Read(buffer, 0, buffer.Length)) > 0)
        {
            hash.AppendData(buffer, 0, read);
        }

        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private static string SaltedSha256Hex(byte[] salt, string path, long count)
    {
        Assert.True(count >= 0);
        using FileStream stream = OpenRead(path);
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(salt);
        var buffer = new byte[81920];
        long remaining = count;
        while (remaining > 0)
        {
            int chunk = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
            Assert.True(chunk > 0, "truncated salted digest range");
            hash.AppendData(buffer, 0, chunk);
            remaining -= chunk;
        }

        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private static string Sha256OfPrefix(string path, long count)
    {
        Assert.True(count >= 0);
        using FileStream stream = OpenRead(path);
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[81920];
        long remaining = count;
        while (remaining > 0)
        {
            int chunk = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
            Assert.True(chunk > 0, "truncated payload prefix");
            hash.AppendData(buffer, 0, chunk);
            remaining -= chunk;
        }

        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private static string Sha256OfFile(string path)
    {
        using FileStream stream = OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static VerifiedEdlFile Claim(string path) =>
        new(Path.GetFullPath(path), new FileInfo(path).Length, Sha256OfFile(path));

    private static byte[] ReadRange(string path, long offset, long count)
    {
        Assert.True(count >= 0 && count <= MaxMetadataArrayBytes, "metadata reads are bounded to 1 MiB");
        var data = new byte[count];
        using FileStream stream = OpenRead(path);
        stream.Position = offset;
        ReadAll(stream, data);
        return data;
    }

    private static void ReadAll(Stream stream, byte[] buffer)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int chunk = stream.Read(buffer, read, buffer.Length - read);
            Assert.True(chunk > 0, "unexpected end of file while reading bytes");
            read += chunk;
        }
    }

    private static FileStream OpenRead(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.SequentialScan);

    private static void CopyFile(string source, string destination)
    {
        using FileStream input = OpenRead(source);
        using var output = new FileStream(destination, FileMode.Create, FileAccess.Write, FileShare.None, 81920);
        input.CopyTo(output, 81920);
        output.Flush(true);
    }

    private static void FlipByte(string path, long offset)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        Assert.True(offset >= 0 && offset < stream.Length, "tamper offset must stay inside the file");
        stream.Position = offset;
        int value = stream.ReadByte();
        Assert.True(value >= 0);
        stream.Position = offset;
        stream.WriteByte((byte)(value ^ 0x5A));
        stream.Flush(true);
    }

    private static uint ReadU32At(string path, long offset)
    {
        using FileStream stream = OpenRead(path);
        stream.Position = offset;
        var buffer = new byte[4];
        ReadAll(stream, buffer);
        return BinaryPrimitives.ReadUInt32LittleEndian(buffer);
    }

    private static void WriteU32At(string path, long offset, uint value)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        stream.Position = offset;
        var buffer = new byte[4];
        Assert.Equal(4, stream.Read(buffer, 0, 4));
        BinaryPrimitives.WriteUInt32LittleEndian(buffer, value);
        stream.Position = offset;
        stream.Write(buffer, 0, buffer.Length);
        stream.Flush(true);
    }

    private static void AssertAllZero(string path, long from, long to)
    {
        Assert.True(to >= from);
        using FileStream stream = OpenRead(path);
        stream.Position = from;
        var buffer = new byte[81920];
        long remaining = to - from;
        while (remaining > 0)
        {
            int chunk = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
            Assert.True(chunk > 0, "truncated candidate tail");
            for (int index = 0; index < chunk; index++)
            {
                Assert.True(buffer[index] == 0, "the area after the signed blob must be zeroed");
            }

            remaining -= chunk;
        }
    }

    private static string[] EntriesOf(string directory) => Directory.Exists(directory)
        ? Directory.GetFileSystemEntries(directory).Select(Path.GetFileName).OrderBy(name => name, StringComparer.Ordinal).ToArray()!
        : Array.Empty<string>();

    private static uint ReadBeU32(byte[] data, int offset) =>
        BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset, 4));

    private static ulong ReadBeU64(byte[] data, int offset) =>
        BinaryPrimitives.ReadUInt64BigEndian(data.AsSpan(offset, 8));

    private static uint ReadLeU32(byte[] data, int offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));

    private static ulong ReadLeU64(byte[] data, int offset) =>
        BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset, 8));
}
