// STOCK-CHAIN-1: real behavioral tests of the read-only companion-chain verifier.
// The Core method is internal and the assembly has no InternalsVisibleTo, so a
// narrow reflection adapter invokes the REAL method, awaits its REAL task,
// unwraps TargetInvocationException and reads the REAL facts object. Nothing is
// stubbed or reimplemented: every case signs genuine RSA-4096 metadata with the
// in-process synthetic AvbFixture fixtures and asserts the verifier's
// crypto/payload behaviour on the bytes it actually reads.
using System;
using System.Buffers.Binary;
using System.IO;
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

public sealed class BootMaintenanceStockChainTests
{
    private const int HeaderSize = 256;

    private const int FooterSize = 64;

    private const int RecoverySize = 128 * 1024;

    private const int PhysicalSize = 32768;

    private static readonly MethodInfo VerifyMethod =
        typeof(FreedomInstaller.Core.EdlRawBootBuilder)
            .GetMethod("VerifyStockMaintenanceChainAsync", BindingFlags.NonPublic | BindingFlags.Static)
        ?? throw new InvalidOperationException("stock maintenance chain verifier method not found");

    [Fact]
    public async Task PositiveRekey_ProvesChainClosureAndSourcePayload()
    {
        using ChainRun run = CreateChain(new ChainSpec());
        VerifiedEdlFile sourceRootClaim = Claim(run.SourceRootPath);
        VerifiedEdlFile sourceRecoveryClaim = Claim(run.SourceRecoveryPath);
        VerifiedEdlFile currentRootClaim = Claim(run.CurrentRootPath);

        object facts = await VerifyAsync(
            sourceRootClaim,
            sourceRecoveryClaim,
            Claim(run.SourceSystemPath),
            currentRootClaim,
            Claim(run.CurrentRecoveryPath),
            Claim(run.CurrentSystemPath));

        // Factual echoes of the exact claims that were proven.
        Assert.Same(sourceRootClaim, FactGet(facts, "SourceRoot"));
        Assert.Same(sourceRecoveryClaim, FactGet(facts, "SourceRecovery"));
        Assert.Same(currentRootClaim, FactGet(facts, "CurrentRoot"));

        // Proven recovery payload facts.
        Assert.Equal(run.RecoveryImageSize, (long)FactGet(facts, "RecoveryImageSize"));
        Assert.Equal(run.RecoveryDigestHex, (string)FactGet(facts, "RecoveryDigestHex"));

        // AOSP rekey: source and current keys differ but each child is pinned
        // by its own root chain exactly.
        Assert.NotEqual(
            (string)FactGet(facts, "SourceRootKeySha256"),
            (string)FactGet(facts, "CurrentRootKeySha256"));
        Assert.NotEqual(
            (string)FactGet(facts, "SourceRecoveryKeySha256"),
            (string)FactGet(facts, "CurrentRecoveryKeySha256"));
        Assert.NotEqual(
            (string)FactGet(facts, "SourceVbmetaSystemKeySha256"),
            (string)FactGet(facts, "CurrentVbmetaSystemKeySha256"));
        Assert.Equal(Sha256Hex(run.SourceRecoveryKeyBlob), (string)FactGet(facts, "SourceRecoveryKeySha256"));
        Assert.Equal(Sha256Hex(run.SourceSystemKeyBlob), (string)FactGet(facts, "SourceVbmetaSystemKeySha256"));
        Assert.Equal(Sha256Hex(run.CurrentRecoveryKeyBlob), (string)FactGet(facts, "CurrentRecoveryKeySha256"));
        Assert.Equal(Sha256Hex(run.CurrentSystemKeyBlob), (string)FactGet(facts, "CurrentVbmetaSystemKeySha256"));

        // Frozen declarations surfaced factually (fixture root metadata is
        // signed with rollback 0x1122334455667788, location 7, flags 4).
        Assert.Equal(0x1122334455667788UL, (ulong)FactGet(facts, "RollbackIndex"));
        Assert.Equal(7U, (uint)FactGet(facts, "RollbackIndexLocation"));
        Assert.Equal(4U, (uint)FactGet(facts, "Flags"));
        Assert.False(string.IsNullOrEmpty((string)FactGet(facts, "RootNonChainDescriptorsSha256")));
    }

    [Fact]
    public async Task TamperedSourceRecoveryPayload_IsRejected()
    {
        using ChainRun run = CreateChain(new ChainSpec());
        byte[] tampered = File.ReadAllBytes(run.SourceRecoveryPath);
        tampered[100] ^= 0xFF;
        string path = Path.Combine(run.RootDirectory, "source-recovery-tampered.img");
        File.WriteAllBytes(path, tampered);

        // The outer claim is refreshed for the tampered file, so only the
        // physical payload proof against the authenticated descriptor can
        // reject it.
        await Assert.ThrowsAsync<InvalidDataException>(() => VerifyAsync(
            Claim(run.SourceRootPath),
            Claim(path),
            Claim(run.SourceSystemPath),
            Claim(run.CurrentRootPath),
            Claim(run.CurrentRecoveryPath),
            Claim(run.CurrentSystemPath)));
    }

    [Fact]
    public async Task WrongSourceRecoveryChainKey_IsRejected()
    {
        var spec = new ChainSpec { PinSourceRecoveryChainToCurrentRecoveryOwner = true };
        using ChainRun run = CreateChain(spec);

        await Assert.ThrowsAsync<InvalidDataException>(() => VerifyClaims(run));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CorruptedMetadataSignature_IsRejected(bool corruptCurrent)
    {
        using ChainRun run = CreateChain(new ChainSpec());
        string badPath;
        if (corruptCurrent)
        {
            byte[] corrupted = CorruptAuthSignature(File.ReadAllBytes(run.CurrentSystemPath), 0);
            badPath = Path.Combine(run.RootDirectory, "current-system-badsig.img");
            File.WriteAllBytes(badPath, corrupted);
        }
        else
        {
            byte[] corrupted = CorruptAuthSignature(File.ReadAllBytes(run.SourceRootPath), 0);
            badPath = Path.Combine(run.RootDirectory, "source-root-badsig.img");
            File.WriteAllBytes(badPath, corrupted);
        }

        VerifiedEdlFile badClaim = Claim(badPath);
        await Assert.ThrowsAsync<InvalidDataException>(() => VerifyAsync(
            corruptCurrent ? Claim(run.SourceRootPath) : badClaim,
            Claim(run.SourceRecoveryPath),
            Claim(run.SourceSystemPath),
            Claim(run.CurrentRootPath),
            Claim(run.CurrentRecoveryPath),
            corruptCurrent ? badClaim : Claim(run.CurrentSystemPath)));
    }

    [Fact]
    public async Task ChangedCurrentSystemDescriptors_IsRejected()
    {
        // Same child key, same root declarations, only the authenticated
        // vbmeta_system descriptors differ: the root chain key does not commit
        // child descriptors, so the child metadata compare must catch it.
        var spec = new ChainSpec { AddExtraCurrentSystemDescriptor = true };
        using ChainRun run = CreateChain(spec);

        await Assert.ThrowsAsync<InvalidDataException>(() => VerifyClaims(run));
    }

    [Theory]
    [InlineData(9U, 8U)]
    [InlineData(1U, 9U)]
    public async Task CurrentRootChainDeclarationMismatch_IsRejected(uint location, uint flags)
    {
        var spec = new ChainSpec
        {
            CurrentRecoveryChainLocation = location,
            CurrentRecoveryChainFlags = flags
        };
        using ChainRun run = CreateChain(spec);

        await Assert.ThrowsAsync<InvalidDataException>(() => VerifyClaims(run));
    }

    [Fact]
    public async Task Precancelled_DoesNotTouchPaths()
    {
        using ChainRun run = CreateChain(new ChainSpec());
        string absent = Path.Combine(run.RootDirectory, "absent.img");
        using var cancellations = new CancellationTokenSource();
        cancellations.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => VerifyAsync(
            Claim(run.SourceRootPath),
            Claim(run.SourceRecoveryPath),
            Claim(run.SourceSystemPath),
            Claim(run.CurrentRootPath),
            Claim(run.CurrentRecoveryPath),
            new VerifiedEdlFile(absent, 1, new string('0', 64)),
            cancellations.Token));

        Assert.False(File.Exists(absent));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public async Task NullInput_IsRejected(int position)
    {
        using ChainRun run = CreateChain(new ChainSpec());
        var claims = new VerifiedEdlFile?[]
        {
            Claim(run.SourceRootPath),
            Claim(run.SourceRecoveryPath),
            Claim(run.SourceSystemPath),
            Claim(run.CurrentRootPath),
            Claim(run.CurrentRecoveryPath),
            Claim(run.CurrentSystemPath)
        };
        claims[position] = null;

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => VerifyArgs(claims, CancellationToken.None));
    }

    [Fact]
    public async Task RecoveryMetadataWithAdditionalSystemHashDescriptor_ProvesSelfOnly()
    {
        // The recovery metadata legitimately carries its exact 'recovery' tag-2
        // self hash plus another existing valid tag-2 (the fixture system hash
        // descriptor). All signatures are genuine and identical bytes are used
        // for source and current, so only the self hash must be selected and
        // the physical proof must pass.
        var spec = new ChainSpec { AddExtraSystemHashToRecovery = true };
        using ChainRun run = CreateChain(spec);

        object facts = await VerifyClaims(run);

        Assert.Equal(run.RecoveryImageSize, (long)FactGet(facts, "RecoveryImageSize"));
        Assert.Equal(run.RecoveryDigestHex, (string)FactGet(facts, "RecoveryDigestHex"));
    }

    // ------------------------------------------------------------ scenario build

    internal sealed class ChainSpec
    {
        public uint SourceRecoveryChainLocation = 1;

        public uint SourceRecoveryChainFlags = 8;

        public uint CurrentRecoveryChainLocation = 1;

        public uint CurrentRecoveryChainFlags = 8;

        public bool PinSourceRecoveryChainToCurrentRecoveryOwner;

        public bool AddExtraCurrentSystemDescriptor;

        public bool AddExtraSystemHashToRecovery;
    }

    internal sealed class ChainRun : IDisposable
    {
        public ChainRun(AvbFixture[] fixtures, RSA[] keys)
        {
            _fixtures = fixtures;
            _keys = keys;
        }

        private readonly AvbFixture[] _fixtures;

        private readonly RSA[] _keys;

        public string RootDirectory = string.Empty;

        public string SourceRootPath = string.Empty;

        public string SourceRecoveryPath = string.Empty;

        public string SourceSystemPath = string.Empty;

        public string CurrentRootPath = string.Empty;

        public string CurrentRecoveryPath = string.Empty;

        public string CurrentSystemPath = string.Empty;

        public byte[] SourceRecoveryKeyBlob = Array.Empty<byte>();

        public byte[] SourceSystemKeyBlob = Array.Empty<byte>();

        public byte[] CurrentRecoveryKeyBlob = Array.Empty<byte>();

        public byte[] CurrentSystemKeyBlob = Array.Empty<byte>();

        public long RecoveryImageSize = PhysicalSize;

        public string RecoveryDigestHex = string.Empty;

        public AvbFixture SourceBootKeyOwner => _fixtures[1];

        public VerifiedEdlFile SourceRootClaim => Claim(SourceRootPath);

        public VerifiedEdlFile SourceRecoveryClaim => Claim(SourceRecoveryPath);

        public VerifiedEdlFile SourceVbmetaSystemClaim => Claim(SourceSystemPath);

        public VerifiedEdlFile CurrentRootClaim => Claim(CurrentRootPath);

        public VerifiedEdlFile CurrentRecoveryClaim => Claim(CurrentRecoveryPath);

        public VerifiedEdlFile CurrentVbmetaSystemClaim => Claim(CurrentSystemPath);

        public void Dispose()
        {
            foreach (AvbFixture fixture in _fixtures)
            {
                fixture.Dispose();
            }

            foreach (RSA key in _keys)
            {
                key.Dispose();
            }

            try
            {
                if (Directory.Exists(RootDirectory)) Directory.Delete(RootDirectory, true);
            }
            catch
            {
            }
        }
    }

    internal static ChainRun CreateChain(ChainSpec spec)
    {
        string root = Path.Combine(
            TestArtifactRoot.Resolve(),
            "stockchain-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);

        RSA[] keys = new[]
        {
            RSA.Create(4096),
            RSA.Create(4096),
            RSA.Create(4096),
            RSA.Create(4096),
            RSA.Create(4096),
            RSA.Create(4096),
            RSA.Create(4096)
        };
        var fixtures = new AvbFixture?[7];
        try
        {
            AvbFixture sourceParent = fixtures[0] = new AvbFixture(keys[0]);
            AvbFixture bootOwner = fixtures[1] = new AvbFixture(keys[1]);
            AvbFixture sourceRecoveryOwner = fixtures[2] = new AvbFixture(keys[2]);
            AvbFixture sourceSystemOwner = fixtures[3] = new AvbFixture(keys[3]);
            AvbFixture currentParent = fixtures[4] = new AvbFixture(keys[4]);
            AvbFixture currentRecoveryOwner = fixtures[5] = new AvbFixture(keys[5]);
            AvbFixture currentSystemOwner = fixtures[6] = new AvbFixture(keys[6]);

            // Taken before any PlainDescriptors overwrite: an existing valid
            // tag-2 (system) hash descriptor reused verbatim in the recovery
            // metadata of both groups when the spec asks for it.
            byte[] systemHashDescriptor = sourceSystemOwner.PlainDescriptors
                .First(d => GetU64(d, 0) == 2UL);

            byte[] payload = PatternBlock(PhysicalSize, 0x21);
            byte[] salt = PatternBlock(16, 0x9D);
            byte[] digest = SHA256.HashData(salt.Concat(payload).ToArray());
            byte[] recoveryDescriptor = RecoveryHashDescriptor(PhysicalSize, salt, digest, "sha256");

            byte[]? extraRecoveryDescriptor = spec.AddExtraSystemHashToRecovery
                ? systemHashDescriptor
                : null;
            byte[] sourceRecoveryPartition = BuildRecoveryPartition(
                sourceRecoveryOwner, recoveryDescriptor, extraRecoveryDescriptor);
            byte[] currentRecoveryPartition = BuildRecoveryPartition(
                currentRecoveryOwner, recoveryDescriptor, extraRecoveryDescriptor);

            byte[] sourceSystemPartition = sourceSystemOwner.BuildRootPartition();
            if (spec.AddExtraCurrentSystemDescriptor)
            {
                currentSystemOwner.PlainDescriptors = currentSystemOwner.PlainDescriptors
                    .Append(UnknownDescriptor(77, 8))
                    .ToArray();
            }

            byte[] currentSystemPartition = currentSystemOwner.BuildRootPartition();

            AvbFixture sourceRecoveryPinner = spec.PinSourceRecoveryChainToCurrentRecoveryOwner
                ? currentRecoveryOwner
                : sourceRecoveryOwner;
            byte[] sourceRootPartition = sourceParent.BuildRootPartition(
                bootOwner.ChainFor("boot", 3, 4),
                sourceRecoveryPinner.ChainFor(
                    "recovery", spec.SourceRecoveryChainLocation, spec.SourceRecoveryChainFlags),
                sourceSystemOwner.ChainFor("vbmeta_system", 2, 16));
            byte[] currentRootPartition = currentParent.BuildRootPartition(
                bootOwner.ChainFor("boot", 3, 4),
                currentRecoveryOwner.ChainFor(
                    "recovery", spec.CurrentRecoveryChainLocation, spec.CurrentRecoveryChainFlags),
                currentSystemOwner.ChainFor("vbmeta_system", 2, 16));

            return new ChainRun(fixtures, keys)
            {
                RootDirectory = root,
                SourceRootPath = WriteArtifact(root, "source-root.img", sourceRootPartition),
                SourceRecoveryPath = WriteArtifact(root, "source-recovery.img", sourceRecoveryPartition),
                SourceSystemPath = WriteArtifact(root, "source-system.img", sourceSystemPartition),
                CurrentRootPath = WriteArtifact(root, "current-root.img", currentRootPartition),
                CurrentRecoveryPath = WriteArtifact(root, "current-recovery.img", currentRecoveryPartition),
                CurrentSystemPath = WriteArtifact(root, "current-system.img", currentSystemPartition),
                SourceRecoveryKeyBlob = sourceRecoveryOwner.KeyBlob,
                SourceSystemKeyBlob = sourceSystemOwner.KeyBlob,
                CurrentRecoveryKeyBlob = currentRecoveryOwner.KeyBlob,
                CurrentSystemKeyBlob = currentSystemOwner.KeyBlob,
                RecoveryImageSize = PhysicalSize,
                RecoveryDigestHex = Convert.ToHexString(digest).ToLowerInvariant()
            };
        }
        catch
        {
            foreach (AvbFixture? fixture in fixtures)
            {
                fixture?.Dispose();
            }

            foreach (RSA key in keys)
            {
                key.Dispose();
            }

            try
            {
                if (Directory.Exists(root)) Directory.Delete(root, true);
            }
            catch
            {
            }

            throw;
        }
    }

    private static byte[] BuildRecoveryPartition(
        AvbFixture owner,
        byte[] recoveryHashDescriptor,
        byte[]? extraHashDescriptor)
    {
        // With zero chain descriptors BuildRootPartition emits a valid signed
        // LEAF blob at partition offset 0.
        owner.PlainDescriptors = extraHashDescriptor is null
            ? new[] { recoveryHashDescriptor }
            : new[] { recoveryHashDescriptor, extraHashDescriptor };
        byte[] partition = owner.BuildRootPartition();
        ulong auth = GetU64(partition, 12);
        ulong aux = GetU64(partition, 20);
        int blobLength = HeaderSize + checked((int)auth) + checked((int)aux);

        var recovery = new byte[RecoverySize];
        FillPattern(recovery, 0, PhysicalSize, 0x21);
        Buffer.BlockCopy(partition, 0, recovery, PhysicalSize, blobLength);

        var footer = new byte[FooterSize];
        Encoding.ASCII.GetBytes("AVBf").CopyTo(footer, 0);
        PutU32(footer, 4, 1);
        PutU32(footer, 8, 0);
        PutU64(footer, 12, PhysicalSize);
        PutU64(footer, 20, PhysicalSize);
        PutU64(footer, 28, (ulong)blobLength);
        Buffer.BlockCopy(footer, 0, recovery, recovery.Length - FooterSize, FooterSize);
        return recovery;
    }

    private static byte[] RecoveryHashDescriptor(long imageSize, byte[] salt, byte[] digest, string algorithm)
    {
        int exact = 132 + 8 + salt.Length + digest.Length;
        int total = (exact + 7) & ~7;
        var descriptor = new byte[total];
        PutU64(descriptor, 0, 2);
        PutU64(descriptor, 8, (ulong)(total - 16));
        PutU64(descriptor, 16, (ulong)imageSize);
        Encoding.ASCII.GetBytes(algorithm).CopyTo(descriptor, 24);
        PutU32(descriptor, 56, 8);
        PutU32(descriptor, 60, (uint)salt.Length);
        PutU32(descriptor, 64, (uint)digest.Length);
        PutU32(descriptor, 68, 0);
        Encoding.ASCII.GetBytes("recovery").CopyTo(descriptor, 132);
        salt.CopyTo(descriptor, 140);
        digest.CopyTo(descriptor, 140 + salt.Length);
        return descriptor;
    }

    private static byte[] UnknownDescriptor(ulong tag, int payloadBytes)
    {
        var descriptor = new byte[16 + payloadBytes];
        PutU64(descriptor, 0, tag);
        PutU64(descriptor, 8, (ulong)payloadBytes);
        FillPattern(descriptor, 16, payloadBytes, 0x5A);
        return descriptor;
    }

    private static byte[] CorruptAuthSignature(byte[] partition, int blobOffset)
    {
        var corrupted = (byte[])partition.Clone();
        ulong signatureOffset = GetU64(corrupted, blobOffset + 48);
        int signatureStart = blobOffset + HeaderSize + checked((int)signatureOffset);
        corrupted[signatureStart + 3] ^= 0xFF;
        return corrupted;
    }

    // ------------------------------------------------------------ helpers

    private static Task<object> VerifyClaims(ChainRun run)
    {
        return VerifyAsync(
            Claim(run.SourceRootPath),
            Claim(run.SourceRecoveryPath),
            Claim(run.SourceSystemPath),
            Claim(run.CurrentRootPath),
            Claim(run.CurrentRecoveryPath),
            Claim(run.CurrentSystemPath));
    }

    private static Task<object> VerifyAsync(
        VerifiedEdlFile sourceRoot,
        VerifiedEdlFile sourceRecovery,
        VerifiedEdlFile sourceSystem,
        VerifiedEdlFile currentRoot,
        VerifiedEdlFile currentRecovery,
        VerifiedEdlFile currentSystem,
        CancellationToken ct = default)
    {
        return VerifyArgs(
            new VerifiedEdlFile?[] { sourceRoot, sourceRecovery, sourceSystem, currentRoot, currentRecovery, currentSystem },
            ct);
    }

    private static async Task<object> VerifyArgs(VerifiedEdlFile?[] claims, CancellationToken ct)
    {
        var arguments = new object?[7];
        for (int i = 0; i < 6; i++)
        {
            arguments[i] = claims[i];
        }

        arguments[6] = ct;

        object? invocation;
        try
        {
            invocation = VerifyMethod.Invoke(null, arguments);
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

    private static object FactGet(object facts, string name)
    {
        return facts.GetType().GetProperty(name, BindingFlags.Instance | BindingFlags.Public)?.GetValue(facts)
            ?? throw new InvalidOperationException("facts property not found: " + name);
    }

    private static VerifiedEdlFile Claim(string path)
    {
        byte[] bytes = File.ReadAllBytes(path);
        return new VerifiedEdlFile(
            Path.GetFullPath(path),
            bytes.Length,
            Convert.ToHexString(SHA256.HashData(bytes)));
    }

    private static string Sha256Hex(byte[] bytes)
    {
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    private static string WriteArtifact(string directory, string name, byte[] bytes)
    {
        string path = Path.Combine(directory, name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static byte[] PatternBlock(int size, byte value)
    {
        var block = new byte[size];
        for (int i = 0; i < size; i++)
        {
            block[i] = value;
        }

        return block;
    }

    private static void FillPattern(byte[] target, int offset, int count, byte value)
    {
        for (int i = 0; i < count; i++)
        {
            target[offset + i] = value;
        }
    }

    private static ulong GetU64(byte[] buffer, int offset)
    {
        return BinaryPrimitives.ReadUInt64BigEndian(buffer.AsSpan(offset, 8));
    }

    private static void PutU64(byte[] buffer, int offset, ulong value)
    {
        BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(offset, 8), value);
    }

    private static void PutU32(byte[] buffer, int offset, uint value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(offset, 4), value);
    }
}
