// GBL-RED-TESTS: focused specification of the original signed boot envelope.
// Production API is intentionally absent: every API-dependent case fails on the reflected method
// lookup itself (Assert.NotNull outside the negative-Throws callback), never on a compile error and
// never on an accepted negative. Case 1 validates the genuine shared fixture without the new API.
// No 96 MiB partition is ever materialised as an array; only 64-byte footers and <= 1 MiB metadata.
using System;
using System.Buffers.Binary;
using System.Globalization;
using System.IO;
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

public sealed class EdlRawGblEnvelopeTests : IClassFixture<EdlRawGblEnvelopeTests.SharedFixture>
{
    private const int FooterSize = 64;

    private const int VbmetaHeaderSize = 256;

    private const long MaxSmallArray = 1024L * 1024L;

    private const long GoldenLimit = 64L * 1024L;

    private readonly SharedFixture _fixture;

    public EdlRawGblEnvelopeTests(SharedFixture fixture)
    {
        _fixture = fixture;
    }

    // ---------------------------------------------------------------- 1. fixture oracle (no new API)

    [Fact]
    public async Task GenuineBuildsExposeAuthenticOriginalsWithoutClaimingOemEnvelope()
    {
        SharedFixture fx = _fixture;
        int checkedCases = 0;

        foreach ((EdlRawBuiltBoot built, VerifiedEdlFile original, bool budget) in new[]
                 {
                     (fx.NormalBuilt, fx.NormalOriginal, false),
                     (fx.BudgetBuilt, fx.BudgetOriginal, true),
                 })
        {
            Assert.True(File.Exists(built.CandidateBoot.Path), "real builder candidate must exist");
            Assert.True(File.Exists(original.Path), "independently signed original must exist");

            (byte[] blob, long blobOffset) = ExtractSignedBlob(original.Path);
            Assert.Equal(blobOffset, ReadFooter64(original.Path).VbmetaOffset);

            // The original is genuine: signed by the independent OEM key, verified by the P1 oracle only.
            AvbFixture.AssertAuthenticatedSignedBlob(blob);
            Assert.Equal(2u, ReadBeU32(blob, 28));
            Assert.Equal(fx.DefaultOemKeySha, Convert.ToHexString(SHA256.HashData(fx.DefaultOem.KeyBlob)));

            if (budget)
            {
                Assert.True(blob.Length > GoldenLimit, "budget original must exceed the 64 KiB leaf budget");
            }
            else
            {
                Assert.True(blob.Length <= GoldenLimit, "normal original must fit the 64 KiB leaf budget");
            }

            // Binding: the stock signed blob still present in the original is the one the source build saw.
            string blobSha = Convert.ToHexString(SHA256.HashData(blob));
            Assert.Equal(blobSha, Text(built.Envelope, "SourceEmbeddedVbmetaSha256"));

            // The rebuilt candidate keeps its own (new) payload boundary, far past the stock layout.
            long newBoundary = Num(built.Envelope, "VbmetaOffset");
            long stockBoundary = ReadFooter64(original.Path).VbmetaOffset;
            Assert.True(newBoundary > stockBoundary, "the rebuilt payload boundary must move past the stock one");
            Assert.True(Num(built.Envelope, "OriginalImageSize") > 0);

            // The source build stays a strict AOSP candidate and makes no OEM claim.
            Assert.False(Bool(built.Envelope, "OemSigned"), "a genuine builder envelope must never claim an OEM signature");
            Assert.True(Bool(built.Envelope, "SignatureVerificationPerformed"));
            if (TryRead(built.Envelope, "PublicKeySha256") is string sourceKey)
            {
                Assert.NotEqual(fx.DefaultOemKeySha, sourceKey);
            }

            await InvokeRevalidateAsync(built);
            checkedCases++;
        }

        Assert.Equal(2, checkedCases);
        Assert.NotEqual(fx.DefaultOemKeySha, fx.OtherOemKeySha);
    }

    // ---------------------------------------------------------------- 2. positive preservation

    [Fact]
    public async Task Preserve_ValidOemOriginal_RebuildsEffectiveCandidateOverExactSignedBlob()
    {
        MethodInfo preserve = PreserveMethod();
        SharedFixture fx = _fixture;
        string caseDir = NewCaseDirectory(fx);
        string candidatePath = Path.Combine(caseDir, "effective.img");

        string sourceCandidateSha = Sha256OfFile(fx.NormalBuilt.CandidateBoot.Path);
        string sourceBinding = Text(fx.NormalBuilt.Envelope, "SourceEmbeddedVbmetaSha256");
        long sourceBoundary = Num(fx.NormalBuilt.Envelope, "VbmetaOffset");
        long sourcePayloadEnd = Num(fx.NormalBuilt.Envelope, "OriginalImageSize");

        (byte[] originalBlob, long originalBlobOffset) = ExtractSignedBlob(fx.NormalOriginal.Path);
        string originalBlobSha = Convert.ToHexString(SHA256.HashData(originalBlob));
        Assert.Equal(sourceBinding, originalBlobSha);
        Assert.NotEqual(sourceBoundary, originalBlobOffset);

        object result = (await InvokeAwaitAsync(
            preserve,
            fx.NormalBuilt,
            fx.NormalOriginal,
            candidatePath,
            CancellationToken.None))!;

        // borrowed source, claimed original, own effective output
        Assert.Same(fx.NormalBuilt, Read(result, "SourceBuiltBoot"));
        VerifiedEdlFile claimedOriginal = ClaimOf(result, "OriginalBoot");
        Assert.Equal(Path.GetFullPath(fx.NormalOriginal.Path), Path.GetFullPath(claimedOriginal.Path));
        Assert.Equal(new FileInfo(fx.NormalOriginal.Path).Length, claimedOriginal.Length);
        Assert.Equal(Sha256OfFile(fx.NormalOriginal.Path), ClaimSha(claimedOriginal));

        VerifiedEdlFile effective = ClaimOf(result, "EffectiveCandidate");
        Assert.Equal(Path.GetFullPath(candidatePath), Path.GetFullPath(effective.Path));
        Assert.Equal(new FileInfo(candidatePath).Length, effective.Length);
        Assert.Equal(Sha256OfFile(candidatePath), ClaimSha(effective));

        // the source candidate file and its envelope facts stay byte-identical
        Assert.Equal(sourceCandidateSha, Sha256OfFile(fx.NormalBuilt.CandidateBoot.Path));
        Assert.Equal(sourceBinding, Text(fx.NormalBuilt.Envelope, "SourceEmbeddedVbmetaSha256"));
        Assert.Equal(sourcePayloadEnd, Num(fx.NormalBuilt.Envelope, "OriginalImageSize"));
        Assert.Equal(sourceBoundary, Num(fx.NormalBuilt.Envelope, "VbmetaOffset"));

        // footer: kept source boundary, exact original blob length, new (not stock) image size
        (long imageSize, long vbmetaOffset, long vbmetaSize) = ReadFooter64(candidatePath);
        Assert.Equal(sourcePayloadEnd, imageSize);
        Assert.Equal(sourceBoundary, vbmetaOffset);
        Assert.Equal(originalBlob.Length, vbmetaSize);

        // the effective blob is the original signed blob, authenticated independently
        byte[] effectiveBlob = ReadRange(candidatePath, vbmetaOffset, vbmetaSize);
        Assert.True(effectiveBlob.AsSpan().SequenceEqual(originalBlob));
        Assert.Equal(originalBlobSha, Convert.ToHexString(SHA256.HashData(effectiveBlob)));
        AvbFixture.AssertAuthenticatedSignedBlob(effectiveBlob);

        // payload prefix is unchanged through the source vbmeta boundary (byte equality, independent of the claim)
        string sourcePrefix = Sha256OfPrefix(fx.NormalBuilt.CandidateBoot.Path, sourceBoundary);
        Assert.Equal(sourcePrefix, Sha256OfPrefix(candidatePath, sourceBoundary));

        // the payload claim is the original image size, not the vbmeta boundary
        string expectedPayloadSha = Sha256OfPrefix(fx.NormalBuilt.CandidateBoot.Path, sourcePayloadEnd);
        Assert.Equal(expectedPayloadSha, Text(result, "PayloadSha256"));
        Assert.Equal(expectedPayloadSha, Sha256OfPrefix(candidatePath, sourcePayloadEnd));
        Assert.Equal(sourcePayloadEnd, Num(result, "PayloadBytes"));
        Assert.Equal(sourceBoundary, Num(result, "VbmetaOffset"));
        Assert.Equal(originalBlob.Length, Num(result, "VbmetaBytes"));

        // nothing but zeros between the blob and the footer
        AssertAllZero(candidatePath, vbmetaOffset + vbmetaSize, new FileInfo(candidatePath).Length - FooterSize);

        object facts = Read(result, "OriginalSignatureFacts");
        Assert.True(Bool(facts, "OriginalSignatureValid"));
        Assert.Equal(originalBlobSha, Text(facts, "SignedVbmetaSha256"));
        Assert.Equal(fx.DefaultOemKeySha, Text(facts, "PublicKeySha256"));
        Assert.Equal(2u, (uint)Num(facts, "AlgorithmType"));
        Assert.Equal(ReadBeU32(originalBlob, 4), (uint)Num(facts, "RequiredMajor"));
        Assert.Equal(ReadBeU32(originalBlob, 8), (uint)Num(facts, "RequiredMinor"));
        Assert.Equal(ReadBeU64(originalBlob, 112), (ulong)Num(facts, "RollbackIndex"));
        Assert.Equal(ReadBeU32(originalBlob, 120), (uint)Num(facts, "Flags"));
        Assert.Equal(ReadBeU32(originalBlob, 124), (uint)Num(facts, "RollbackIndexLocation"));

        // signed content is the stock body prefix; the effective digest covers the same byte count
        (long stockImageSize, _, _) = ReadFooter64(fx.NormalOriginal.Path);
        byte[] salt = PatternSalt(0xB4, 16);
        Assert.Equal(stockImageSize, Num(facts, "SignedContentBytes"));
        Assert.Equal(SaltedHexOfRange(fx.NormalOriginal.Path, stockImageSize, salt), Text(facts, "SignedContentDigestHex"));
        Assert.Equal(SaltedHexOfRange(candidatePath, stockImageSize, salt), Text(facts, "EffectiveContentDigestHex"));
        Assert.False(Bool(facts, "ContentDigestMatches"));

        // owning the wrapper never disposes the borrowed source
        Assert.IsAssignableFrom<IDisposable>(result).Dispose();
        await InvokeRevalidateAsync(fx.NormalBuilt);
    }

    // ---------------------------------------------------------------- 3-5. invalid originals

    [Theory]
    [InlineData("binding")]
    [InlineData("whole-claim")]
    [InlineData("signature")]
    public async Task Preserve_InvalidOriginalVariants_AreRejectedBeforeAnyOutput(string variant)
    {
        MethodInfo preserve = PreserveMethod();
        SharedFixture fx = _fixture;
        string caseDir = NewCaseDirectory(fx);
        string candidatePath = Path.Combine(caseDir, "effective.img");
        string copyPath = Path.Combine(caseDir, variant + "-original.img");
        CopyFile(fx.NormalOriginal.Path, copyPath);

        VerifiedEdlFile mutated;
        switch (variant)
        {
            case "binding":
                mutated = fx.OtherOem.RewriteBootLeaf(copyPath);
                Assert.NotEqual(Text(fx.NormalBuilt.Envelope, "SourceEmbeddedVbmetaSha256"), ExtractBlobSha(copyPath));
                AvbFixture.AssertAuthenticatedSignedBlob(ExtractSignedBlob(copyPath).Blob);
                break;

            case "whole-claim":
                FlipByte(copyPath, 4096 + 16);
                // stale whole-file claim: same length, the pre-flip digest
                mutated = new VerifiedEdlFile(
                    Path.GetFullPath(copyPath),
                    new FileInfo(copyPath).Length,
                    Sha256OfFile(fx.NormalOriginal.Path));
                break;

            default:
                long blobOffset = ReadFooter64(copyPath).VbmetaOffset;
                FlipByte(copyPath, blobOffset + VbmetaHeaderSize + 64);
                mutated = Claim(copyPath);
                break;
        }

        string sourceSha = Sha256OfFile(fx.NormalBuilt.CandidateBoot.Path);
        string originalSha = Sha256OfFile(fx.NormalOriginal.Path);
        string[] before = EntriesOf(caseDir);

        await Assert.ThrowsAsync<InvalidDataException>(() => InvokeAwaitAsync(
            preserve,
            fx.NormalBuilt,
            mutated,
            candidatePath,
            CancellationToken.None));

        Assert.False(File.Exists(candidatePath));
        Assert.Equal(before, EntriesOf(caseDir));
        Assert.Equal(sourceSha, Sha256OfFile(fx.NormalBuilt.CandidateBoot.Path));
        Assert.Equal(originalSha, Sha256OfFile(fx.NormalOriginal.Path));
        await InvokeRevalidateAsync(fx.NormalBuilt);
    }

    // ---------------------------------------------------------------- 6. 64 KiB budget

    [Fact]
    public async Task OriginalSignedMetadataExceeding64KiBBudgetIsRejected()
    {
        MethodInfo preserve = PreserveMethod();
        SharedFixture fx = _fixture;
        string caseDir = NewCaseDirectory(fx);
        string candidatePath = Path.Combine(caseDir, "effective.img");

        (byte[] blob, long blobOffset) = ExtractSignedBlob(fx.BudgetOriginal.Path);
        Assert.True(blob.Length > GoldenLimit, "genuine budget original must be larger than the bounded leaf reader");
        AvbFixture.AssertAuthenticatedSignedBlob(blob);
        Assert.Equal(blobOffset, ReadFooter64(fx.BudgetOriginal.Path).VbmetaOffset);
        Assert.True(File.Exists(fx.BudgetBuilt.CandidateBoot.Path));

        string[] before = EntriesOf(caseDir);
        await Assert.ThrowsAsync<InvalidDataException>(() => InvokeAwaitAsync(
            preserve,
            fx.BudgetBuilt,
            fx.BudgetOriginal,
            candidatePath,
            CancellationToken.None));

        Assert.False(File.Exists(candidatePath));
        Assert.Equal(before, EntriesOf(caseDir));
        await InvokeRevalidateAsync(fx.BudgetBuilt);
    }

    // ---------------------------------------------------------------- 7. cancellation

    [Fact]
    public async Task AlreadyCancelledTokenStopsPreservationWithoutOutput()
    {
        MethodInfo preserve = PreserveMethod();
        SharedFixture fx = _fixture;
        string caseDir = NewCaseDirectory(fx);
        string candidatePath = Path.Combine(caseDir, "effective.img");

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        string sourceSha = Sha256OfFile(fx.NormalBuilt.CandidateBoot.Path);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => InvokeAwaitAsync(
            preserve,
            fx.NormalBuilt,
            fx.NormalOriginal,
            candidatePath,
            cancellation.Token));

        Assert.False(File.Exists(candidatePath));
        Assert.Empty(EntriesOf(caseDir));
        Assert.Equal(sourceSha, Sha256OfFile(fx.NormalBuilt.CandidateBoot.Path));
        await InvokeRevalidateAsync(fx.NormalBuilt);
    }

    // ---------------------------------------------------------------- 8. ownership and revalidation

    [Fact]
    public async Task WrapperOwnsOnlyItsEffectiveCandidateAndRejectsUseAfterDispose()
    {
        MethodInfo preserve = PreserveMethod();
        SharedFixture fx = _fixture;
        string caseDir = NewCaseDirectory(fx);
        string candidatePath = Path.Combine(caseDir, "effective.img");
        string sentinel = Path.Combine(caseDir, "sibling.sentinel");
        File.WriteAllBytes(sentinel, Encoding.ASCII.GetBytes("keep-me"));

        string sourceSha = Sha256OfFile(fx.NormalBuilt.CandidateBoot.Path);
        string originalSha = Sha256OfFile(fx.NormalOriginal.Path);
        string sourcePath = fx.NormalBuilt.CandidateBoot.Path;

        object wrapper = (await InvokeAwaitAsync(
            preserve,
            fx.NormalBuilt,
            fx.NormalOriginal,
            candidatePath,
            CancellationToken.None))!;

        VerifiedEdlFile effective = ClaimOf(wrapper, "EffectiveCandidate");
        Assert.Equal(Path.GetFullPath(candidatePath), Path.GetFullPath(effective.Path));
        await InvokeRevalidateAsync(wrapper);

        var disposable = Assert.IsAssignableFrom<IDisposable>(wrapper);
        disposable.Dispose();
        disposable.Dispose();

        Assert.False(File.Exists(candidatePath));
        Assert.True(File.Exists(sentinel), "a sibling in the same directory must survive");
        Assert.True(File.Exists(sourcePath), "the borrowed source candidate must survive");
        Assert.True(File.Exists(fx.NormalOriginal.Path), "the original input must survive");
        Assert.Equal(sourceSha, Sha256OfFile(sourcePath));
        Assert.Equal(originalSha, Sha256OfFile(fx.NormalOriginal.Path));
        Assert.True(Bool(wrapper, "IsDisposed"));

        await InvokeRevalidateAsync(fx.NormalBuilt);
        await Assert.ThrowsAnyAsync<ObjectDisposedException>(() => InvokeRevalidateAsync(wrapper));
    }

    // ---------------------------------------------------------------- 9. parent principal differs

    [Fact]
    public async Task Authenticate_OriginalBootChainKeepsParentPrincipalOutOfBootChildKey()
    {
        MethodInfo authenticate = AuthenticateMethod();
        SharedFixture fx = _fixture;
        string caseDir = NewCaseDirectory(fx);

        byte[] root = fx.OtherOem.BuildRootPartition(
            fx.DefaultOem.ChainFor("boot", 3, 0),
            fx.OtherOem.ChainFor("recovery", 1, 0),
            fx.OtherOem.ChainFor("vbmeta_system", 2, 0));
        string rootPath = Path.Combine(caseDir, "vbmeta.img");
        File.WriteAllBytes(rootPath, root);
        Assert.Equal(65536, root.Length);

        VerifiedEdlFile claim = Claim(rootPath);
        Assert.NotEqual(KeyBlobSha(fx.OtherOem), KeyBlobSha(fx.DefaultOem));

        int blobLength = AvbBlobLength(root);
        byte[] blob = ReadRange(rootPath, 0, blobLength);
        AvbFixture.AssertAuthenticatedSignedBlob(blob);
        string blobSha = Convert.ToHexString(SHA256.HashData(blob));

        string rootSha = Sha256OfFile(rootPath);
        string[] before = EntriesOf(caseDir);

        object facts = (await InvokeAwaitAsync(authenticate, claim, CancellationToken.None))!;

        VerifiedEdlFile original = ClaimOf(facts, "Original");
        Assert.Equal(Path.GetFullPath(rootPath), Path.GetFullPath(original.Path));
        Assert.Equal(claim.Length, original.Length);
        Assert.Equal(rootSha, ClaimSha(original));
        Assert.Equal(blobSha, Text(facts, "SignedVbmetaSha256"));
        Assert.Equal(KeyBlobSha(fx.OtherOem), Text(facts, "PublicKeySha256"));
        Assert.Equal(KeyBlobSha(fx.DefaultOem), Text(facts, "BootChainPublicKeySha256"));
        Assert.NotEqual(Text(facts, "PublicKeySha256"), Text(facts, "BootChainPublicKeySha256"));

        // read-only: no candidate, no mutation
        Assert.Equal(before, EntriesOf(caseDir));
        Assert.Equal(rootSha, Sha256OfFile(rootPath));
    }

    // ---------------------------------------------------------------- 10. parent signature tampered

    [Fact]
    public async Task Authenticate_TamperedParentSignatureFailsEvenWithRefreshedWholeClaim()
    {
        MethodInfo authenticate = AuthenticateMethod();
        SharedFixture fx = _fixture;
        string caseDir = NewCaseDirectory(fx);

        byte[] root = fx.OtherOem.BuildRootPartition(
            fx.DefaultOem.ChainFor("boot", 3, 0),
            fx.OtherOem.ChainFor("recovery", 1, 0),
            fx.OtherOem.ChainFor("vbmeta_system", 2, 0));
        string rootPath = Path.Combine(caseDir, "vbmeta-tampered.img");
        File.WriteAllBytes(rootPath, root);

        FlipByte(rootPath, VbmetaHeaderSize + 64);
        VerifiedEdlFile claim = Claim(rootPath);

        string tamperedSha = Sha256OfFile(rootPath);
        string[] before = EntriesOf(caseDir);

        await Assert.ThrowsAsync<InvalidDataException>(() => InvokeAwaitAsync(
            authenticate,
            claim,
            CancellationToken.None));

        Assert.Equal(before, EntriesOf(caseDir));
        Assert.Equal(tamperedSha, Sha256OfFile(rootPath));
    }

    // ---------------------------------------------------------------- reflection boundary

    private static MethodInfo PreserveMethod() => RequireMethod(
        typeof(EdlRawBootBuilder),
        "PreserveOriginalSignedBootMetadataAsync",
        typeof(EdlRawBuiltBoot),
        typeof(VerifiedEdlFile),
        typeof(string),
        typeof(CancellationToken));

    private static MethodInfo AuthenticateMethod() => RequireMethod(
        typeof(EdlRawBootBuilder),
        "AuthenticateOriginalBootChainAsync",
        typeof(VerifiedEdlFile),
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

    private static async Task InvokeRevalidateAsync(object target)
    {
        MethodInfo method = target.GetType()
            .GetMethods(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)
            .First(candidate => string.Equals(candidate.Name, "RevalidateAsync", StringComparison.Ordinal)
                && (candidate.GetParameters().Length == 0 || candidate.GetParameters().Length == 1));
        object?[] arguments = method.GetParameters().Length == 0
            ? Array.Empty<object?>()
            : new object?[] { CancellationToken.None };

        object? invocation;
        try
        {
            invocation = method.Invoke(target, arguments);
        }
        catch (TargetInvocationException ex) when (ex.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
            throw;
        }

        if (invocation is Task task)
        {
            await task.ConfigureAwait(false);
        }
    }

    private static object Read(object instance, string name)
    {
        object? value = TryRead(instance, name);
        Assert.NotNull(value);
        return value;
    }

    private static object? TryRead(object instance, string name) => instance.GetType()
        .GetProperty(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
        ?.GetValue(instance);

    private static string Text(object instance, string name) =>
        Convert.ToString(Read(instance, name), CultureInfo.InvariantCulture)!.ToUpperInvariant();

    private static long Num(object instance, string name) => Convert.ToInt64(Read(instance, name), CultureInfo.InvariantCulture);

    private static bool Bool(object instance, string name) => Convert.ToBoolean(Read(instance, name), CultureInfo.InvariantCulture);

    private static VerifiedEdlFile ClaimOf(object instance, string name) =>
        Assert.IsType<VerifiedEdlFile>(Read(instance, name));

    private static string ClaimSha(VerifiedEdlFile file) => Text(file, "Sha256");

    // ---------------------------------------------------------------- independent byte helpers

    private static string NewCaseDirectory(SharedFixture fixture)
    {
        string directory = Path.Combine(fixture.Workspace.Root, "case-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }

    private static (long OriginalImageSize, long VbmetaOffset, long VbmetaSize) ReadFooter64(string path)
    {
        using var stream = OpenRead(path);
        var footer = new byte[FooterSize];
        stream.Position = stream.Length - FooterSize;
        ReadExactly(stream, footer);
        Assert.Equal("AVBf", Encoding.ASCII.GetString(footer, 0, 4));
        Assert.Equal(1u, ReadBeU32(footer, 4));
        return (
            checked((long)ReadBeU64(footer, 12)),
            checked((long)ReadBeU64(footer, 20)),
            checked((long)ReadBeU64(footer, 28)));
    }

    private static (byte[] Blob, long Offset) ExtractSignedBlob(string path)
    {
        (_, long offset, long size) = ReadFooter64(path);
        Assert.True(size > 0 && size <= MaxSmallArray, "signed blob must stay within the bounded leaf reader");
        return (ReadRange(path, offset, size), offset);
    }

    private static string KeyBlobSha(AvbFixture fixture) => Convert.ToHexString(SHA256.HashData(fixture.KeyBlob));

    private static string ExtractBlobSha(string path) => Convert.ToHexString(SHA256.HashData(ExtractSignedBlob(path).Blob));

    private static int AvbBlobLength(byte[] data)
    {
        Assert.Equal("AVB0", Encoding.ASCII.GetString(data, 0, 4));
        long authentication = checked((long)ReadBeU64(data, 12));
        long auxiliary = checked((long)ReadBeU64(data, 20));
        return checked(VbmetaHeaderSize + (int)authentication + (int)auxiliary);
    }

    private static byte[] ReadRange(string path, long offset, long count)
    {
        Assert.True(count >= 0 && count <= MaxSmallArray, "metadata reads are bounded to 1 MiB");
        var data = new byte[count];
        using var stream = OpenRead(path);
        stream.Position = offset;
        ReadExactly(stream, data);
        return data;
    }

    private static void ReadExactly(Stream stream, byte[] buffer)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int chunk = stream.Read(buffer, read, buffer.Length - read);
            Assert.True(chunk > 0, "unexpected end of file while reading fixture bytes");
            read += chunk;
        }
    }

    private static FileStream OpenRead(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.SequentialScan);

    private static string Sha256OfFile(string path)
    {
        using var stream = OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string Sha256OfPrefix(string path, long count)
    {
        Assert.True(count >= 0);
        using var stream = OpenRead(path);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[81920];
        long remaining = count;
        while (remaining > 0)
        {
            int chunk = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
            Assert.True(chunk > 0, "truncated payload prefix");
            hash.AppendData(buffer, 0, chunk);
            remaining -= chunk;
        }

        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static string SaltedHexOfRange(string path, long count, byte[] salt)
    {
        Assert.True(count >= 0);
        using var stream = OpenRead(path);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(salt);
        var buffer = new byte[81920];
        long remaining = count;
        while (remaining > 0)
        {
            int chunk = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
            Assert.True(chunk > 0, "truncated signed content range");
            hash.AppendData(buffer, 0, chunk);
            remaining -= chunk;
        }

        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static byte[] PatternSalt(byte seed, int length)
    {
        var salt = new byte[length];
        for (int index = 0; index < salt.Length; index++)
        {
            salt[index] = unchecked((byte)(seed + index * 7));
        }

        return salt;
    }

    private static void CopyFile(string source, string destination)
    {
        using var input = OpenRead(source);
        using var output = new FileStream(destination, FileMode.Create, FileAccess.Write, FileShare.None, 81920);
        input.CopyTo(output, 81920);
        output.Flush(true);
    }

    private static void FlipByte(string path, long offset)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        Assert.True(offset >= 0 && offset < stream.Length, "tamper offset must stay inside the fixture");
        stream.Position = offset;
        int value = stream.ReadByte();
        Assert.True(value >= 0);
        stream.Position = offset;
        stream.WriteByte((byte)(value ^ 0x5A));
        stream.Flush(true);
    }

    private static void AssertAllZero(string path, long from, long to)
    {
        Assert.True(to >= from);
        using var stream = OpenRead(path);
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

    private static VerifiedEdlFile Claim(string path)
    {
        string full = Path.GetFullPath(path);
        return new VerifiedEdlFile(full, new FileInfo(full).Length, Sha256OfFile(full));
    }

    private static uint ReadBeU32(byte[] data, int offset) =>
        BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset, 4));

    private static ulong ReadBeU64(byte[] data, int offset) =>
        BinaryPrimitives.ReadUInt64BigEndian(data.AsSpan(offset, 8));

    // ---------------------------------------------------------------- genuine shared fixture

    public sealed class SharedFixture : IAsyncLifetime, IDisposable
    {
        private const string LinuxPackerVariable = "EDL_RAW_LINUX_PACKER_PATH";

        private const string LinuxUnpackerVariable = "EDL_RAW_LINUX_UNPACKER_PATH";

        private RSA? _otherOemKey;

        internal EdlRawBootTools Tools = null!;

        internal EdlRawBootBuilderTests.SyntheticPackage Package = null!;

        internal EdlRawBootBuilderTests.Workspace Workspace = null!;

        internal EdlRawBootBuilderTests.LinuxOracleRunner Runner = null!;

        internal AvbFixture DefaultOem = null!;

        internal AvbFixture OtherOem = null!;

        internal EdlRawBuiltBoot NormalBuilt = null!;

        internal EdlRawBuiltBoot BudgetBuilt = null!;

        internal VerifiedEdlFile NormalOriginal = null!;

        internal VerifiedEdlFile BudgetOriginal = null!;

        internal string DefaultOemKeySha = string.Empty;

        internal string OtherOemKeySha = string.Empty;

        public async Task InitializeAsync()
        {
            string linuxPacker = RequireVariable(LinuxPackerVariable);
            string linuxUnpacker = RequireVariable(LinuxUnpackerVariable);

            Tools = await EdlRawBootBuilderTests.LoadToolsAsync();
            Package = new EdlRawBootBuilderTests.SyntheticPackage();
            Workspace = new EdlRawBootBuilderTests.Workspace();

            DefaultOem = new AvbFixture();
            _otherOemKey = RSA.Create(4096);
            OtherOem = new AvbFixture(_otherOemKey);
            DefaultOemKeySha = KeyBlobSha(DefaultOem);
            OtherOemKeySha = KeyBlobSha(OtherOem);

            Runner = new EdlRawBootBuilderTests.LinuxOracleRunner(Tools, linuxPacker, linuxUnpacker);

            EdlRawBootBuilderTests.SlotFixture slotA = EdlRawBootBuilderTests.CreateSlot(Workspace, "a", 0x31);
            EdlRawBootBuilderTests.SlotFixture slotB = EdlRawBootBuilderTests.CreateSlot(Workspace, "b", 0x71);

            // The original is the stock boot body signed independently by the OEM key, never re-signed.
            slotA.CurrentBoot = DefaultOem.RewriteBootLeaf(slotA.CurrentBoot.Path);
            NormalOriginal = slotA.CurrentBoot;
            slotB.CurrentBoot = DefaultOem.RewriteBootLeaf(slotB.CurrentBoot.Path, extraAuxPaddingBytes: 65536);
            BudgetOriginal = slotB.CurrentBoot;

            NormalBuilt = await EdlRawBootBuilder.BuildAsync(
                EdlRawBootBuilderTests.CreateRequest(slotA, Package, Tools, Workspace),
                Runner);
            BudgetBuilt = await EdlRawBootBuilder.BuildAsync(
                EdlRawBootBuilderTests.CreateRequest(slotB, Package, Tools, Workspace),
                Runner);
        }

        public Task DisposeAsync()
        {
            NormalBuilt?.Dispose();
            BudgetBuilt?.Dispose();
            Tools?.Dispose();
            Package?.Dispose();
            Workspace?.Dispose();
            DefaultOem?.Dispose();
            OtherOem?.Dispose();
            // deterministic: the RSA this fixture created must close whether xUnit drives IAsyncLifetime or IDisposable
            Dispose();
            return Task.CompletedTask;
        }

        public void Dispose()
        {
            // The static P1 source key is never disposed; only the RSA this fixture created is owned.
            _otherOemKey?.Dispose();
            _otherOemKey = null;
        }

        private static string RequireVariable(string name)
        {
            string? value = Environment.GetEnvironmentVariable(name);
            Assert.False(string.IsNullOrWhiteSpace(value), name + " must be set; this suite never skips");
            return value!;
        }
    }
}
