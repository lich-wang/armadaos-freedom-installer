using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace FreedomInstaller.Core.Tests
{
    public sealed class EdlRawAvbChainTests : IClassFixture<EdlRawAvbChainTests.AvbFixture>
    {
        private const string TargetKeySha256 = "7728E30F50BFA5CEA165F473175A08803F6A8346642B5AA10913E9D9E6DEFEF6";
        private const string ExportRootEnvironmentVariable = "AVB_CHAIN_FIXTURE_EXPORT_DIR";
        private const int KeyBlobSize = 1032;
        private const int HeaderSize = 256;
        private const int AuthSize = 576;
        private const int FooterSize = 64;
        private const int RecoverySize = 128 * 1024;
        private const int StandaloneSize = 64 * 1024;
        private const ulong FrozenRollbackIndex = 0x1122334455667788UL;
        private const uint FrozenFlags = 4;
        private const uint FrozenLocation = 7;

        private static readonly object SignGate = new object();

        private static readonly Lazy<RSA> SourceKey = new Lazy<RSA>(
            () => RSA.Create(4096), LazyThreadSafetyMode.ExecutionAndPublication);

        private readonly AvbFixture _fx;

        public EdlRawAvbChainTests(AvbFixture fx)
        {
            _fx = fx;
        }

        [Fact]
        public void SyntheticOriginalsVerifyIndependentlyAndKeepFrozenLayout()
        {
            var fx = _fx;
            Assert.Equal(RecoverySize, fx.RecoveryBytes.Length);
            Assert.Equal(StandaloneSize, fx.VbmetaSystemBytes.Length);
            Assert.Equal(StandaloneSize, fx.VbmetaBytes.Length);

            var recovery = Parse(fx.RecoveryBytes, BlobOffsetFor("Recovery", fx.RecoveryBytes));
            var system = Parse(fx.VbmetaSystemBytes, BlobOffsetFor("VbmetaSystem", fx.VbmetaSystemBytes));
            var root = Parse(fx.VbmetaBytes, BlobOffsetFor("Vbmeta", fx.VbmetaBytes));

            foreach (var parsed in new[] { recovery, system, root })
            {
                Assert.Equal(1u, parsed.Major);
                Assert.Equal(2u, parsed.Minor);
                Assert.Equal(2u, parsed.Algorithm);
                Assert.Equal(FrozenRollbackIndex, parsed.RollbackIndex);
                Assert.Equal(FrozenFlags, parsed.Flags);
                Assert.Equal(FrozenLocation, parsed.RollbackLocation);
                Assert.Equal(KeyBlobSize, parsed.KeyBlob.Length);
                Assert.Equal(fx.KeyBlob, parsed.KeyBlob);
                AssertBlobAuthVerifies(parsed.Partition, parsed);
            }

            Assert.Equal(32768, recovery.BlobOffset);
            Assert.Equal(32768UL, BinaryPrimitives.ReadUInt64BigEndian(fx.RecoveryBytes.AsSpan(RecoverySize - FooterSize + 12, 8)));
            Assert.Equal(0, system.BlobOffset);
            Assert.Equal(0, root.BlobOffset);

            var plainTags = recovery.Descriptors.Where(d => d.Tag != 4).Select(d => d.Tag).ToArray();
            Assert.Equal(new ulong[] { 0, 2, 1, 77 }, plainTags);
            Assert.Empty(system.Descriptors.Where(d => d.Tag == 4));
            Assert.Equal(plainTags, system.Descriptors.Where(d => d.Tag != 4).Select(d => d.Tag).ToArray());
            Assert.Equal(plainTags, root.Descriptors.Where(d => d.Tag != 4).Select(d => d.Tag).ToArray());

            var chains = root.Descriptors.Where(d => d.Tag == 4).ToList();
            Assert.Equal(3, chains.Count);
            Assert.Equal(new[] { "boot", "recovery", "vbmeta_system" }, chains.Select(c => DescName(fx.VbmetaBytes, c)).ToArray());
            Assert.Equal(new uint[] { 3, 1, 2 }, chains.Select(c => c.Location).ToArray());
            Assert.Equal(new uint[] { 4, 8, 16 }, chains.Select(c => c.Flags).ToArray());
            foreach (var chain in chains)
            {
                Assert.Equal(KeyBlobSize, chain.KeyLength);
                Assert.Equal(fx.KeyBlob, DescKey(fx.VbmetaBytes, chain));
            }
        }

        [Fact]
        public void SyntheticHeadersEncodeStandardFieldsAsBigEndianU64()
        {
            var fx = _fx;
            var blobs = new[]
            {
                (Bytes: fx.RecoveryBytes, Offset: BlobOffsetFor("Recovery", fx.RecoveryBytes)),
                (Bytes: fx.VbmetaSystemBytes, Offset: BlobOffsetFor("VbmetaSystem", fx.VbmetaSystemBytes)),
                (Bytes: fx.VbmetaBytes, Offset: BlobOffsetFor("Vbmeta", fx.VbmetaBytes))
            };

            foreach (var blob in blobs)
            {
                int offset = blob.Offset;
                Assert.Equal(0UL, ReadU64(blob.Bytes, offset + 32));
                Assert.Equal(32UL, ReadU64(blob.Bytes, offset + 40));
                Assert.Equal(64UL, ReadU64(blob.Bytes, offset + 48));
                Assert.Equal(512UL, ReadU64(blob.Bytes, offset + 56));
                Assert.Equal(64UL, ReadU64(blob.Bytes, offset + 64));
                Assert.Equal((ulong)KeyBlobSize, ReadU64(blob.Bytes, offset + 72));
                Assert.Equal(0UL, ReadU64(blob.Bytes, offset + 80));
                Assert.Equal(0UL, ReadU64(blob.Bytes, offset + 88));
                Assert.Equal(64UL + (ulong)KeyBlobSize + 40UL, ReadU64(blob.Bytes, offset + 96));
                Assert.NotEqual(0UL, ReadU64(blob.Bytes, offset + 104));
            }
        }

        [Theory]
        [InlineData("Recovery")]
        [InlineData("VbmetaSystem")]
        [InlineData("Vbmeta")]
        public async Task ResignAvbNodeReplacesOnlyKeysAndPreservesEverythingElse(string kindName)
        {
            var fx = _fx;
            byte[] sourceBytes = kindName == "Recovery" ? fx.RecoveryBytes
                : kindName == "VbmetaSystem" ? fx.VbmetaSystemBytes
                : fx.VbmetaBytes;
            string sourcePath = kindName == "Recovery" ? fx.RecoveryPath
                : kindName == "VbmetaSystem" ? fx.VbmetaSystemPath
                : fx.VbmetaPath;

            var original = new VerifiedEdlFile(sourcePath, sourceBytes.Length, Hex(SHA256.HashData(sourceBytes)));
            string candidatePath = Path.Combine(fx.Root, "candidate-" + kindName + ".img");
            if (File.Exists(candidatePath)) File.Delete(candidatePath);

            object node = await InvokeResignAsync(original, kindName, candidatePath);

            Assert.Equal(sourceBytes, File.ReadAllBytes(sourcePath));
            Assert.True(File.Exists(candidatePath), "successful resign must produce the candidate file");
            byte[] candidateBytes = File.ReadAllBytes(candidatePath);
            Assert.Equal(sourceBytes.Length, candidateBytes.Length);

            var originalClaim = (VerifiedEdlFile)Value(node, "Original");
            Assert.Equal(sourcePath, originalClaim.Path);
            Assert.Equal(sourceBytes.Length, originalClaim.Length);
            Assert.Equal(Hex(SHA256.HashData(sourceBytes)), originalClaim.Sha256.ToUpperInvariant());

            var candidateClaim = (VerifiedEdlFile)Value(node, "Candidate");
            Assert.Equal(candidatePath, candidateClaim.Path);
            Assert.Equal(candidateBytes.Length, candidateClaim.Length);
            Assert.Equal(Hex(SHA256.HashData(candidateBytes)), candidateClaim.Sha256.ToUpperInvariant());
            Assert.Equal(kindName, Value(node, "Kind").ToString());

            var builderType = typeof(VerifiedEdlFile).Assembly.GetType("FreedomInstaller.Core.EdlRawBootBuilder", false, false);
            Assert.NotNull(builderType);
            var signingKeyProperty = builderType.GetProperty(
                "SigningPublicKeySha256", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
            Assert.NotNull(signingKeyProperty);
            Assert.Equal(TargetKeySha256, (string)signingKeyProperty.GetValue(null));

            int blobOffset = BlobOffsetFor(kindName, sourceBytes);
            var src = Parse(sourceBytes, blobOffset);
            Assert.Equal(Hex(SHA256.HashData(src.KeyBlob)), ((string)Value(node, "OriginalPublicKeySha256")).ToUpperInvariant());
            var cand = Parse(candidateBytes, blobOffset);

            Assert.Equal((long)blobOffset, Convert.ToInt64(Value(node, "VbmetaOffset")));
            Assert.Equal((long)cand.BlobLength, Convert.ToInt64(Value(node, "VbmetaBytes")));
            Assert.Equal(FrozenRollbackIndex, Convert.ToUInt64(Value(node, "RollbackIndex")));
            Assert.Equal((ulong)FrozenLocation, Convert.ToUInt64(Value(node, "RollbackIndexLocation")));
            Assert.Equal((ulong)FrozenFlags, Convert.ToUInt64(Value(node, "Flags")));
            Assert.Equal(1UL, Convert.ToUInt64(Value(node, "RequiredMajor")));
            Assert.Equal(2UL, Convert.ToUInt64(Value(node, "RequiredMinor")));

            Assert.Equal(1u, cand.Major);
            Assert.Equal(2u, cand.Minor);
            Assert.Equal(2u, cand.Algorithm);
            Assert.Equal(FrozenRollbackIndex, cand.RollbackIndex);
            Assert.Equal(FrozenFlags, cand.Flags);
            Assert.Equal(FrozenLocation, cand.RollbackLocation);
            Assert.Equal(src.AuthSize, cand.AuthSize);
            Assert.Equal(src.AuxSize, cand.AuxSize);
            Assert.Equal(src.DescSize, cand.DescSize);
            Assert.Equal(src.DescOffset, cand.DescOffset);

            Assert.NotEqual(TargetKeySha256, Hex(SHA256.HashData(src.KeyBlob)));
            Assert.Equal(TargetKeySha256, Hex(SHA256.HashData(cand.KeyBlob)));
            Assert.Equal(TargetKeySha256, ((string)Value(node, "PublicKeySha256")).ToUpperInvariant());
            AssertBlobAuthVerifies(candidateBytes, cand);

            var srcNonChain = src.Descriptors.Where(d => d.Tag != 4).Select(d => d.Raw).ToList();
            var candNonChain = cand.Descriptors.Where(d => d.Tag != 4).Select(d => d.Raw).ToList();
            Assert.Equal(srcNonChain.Count, candNonChain.Count);
            for (int i = 0; i < srcNonChain.Count; i++) Assert.Equal(srcNonChain[i], candNonChain[i]);
            var expectedNonChainSha = Hex(SHA256.HashData(srcNonChain.SelectMany(x => x).ToArray()));
            Assert.Equal(expectedNonChainSha, ((string)Value(node, "NonChainDescriptorsSha256")).ToUpperInvariant());

            var srcChains = src.Descriptors.Where(d => d.Tag == 4).ToList();
            var candChains = cand.Descriptors.Where(d => d.Tag == 4).ToList();
            var chainHashes = (IReadOnlyDictionary<string, string>)Value(node, "ChainPublicKeySha256");
            Assert.Equal(srcChains.Count, candChains.Count);
            Assert.Equal(srcChains.Count, chainHashes.Count);

            if (kindName == "Vbmeta")
            {
                var names = new[] { "boot", "recovery", "vbmeta_system" };
                Assert.Equal(names, candChains.Select(c => DescName(candidateBytes, c)).ToArray());
                for (int i = 0; i < candChains.Count; i++)
                {
                    Assert.Equal(srcChains[i].Location, candChains[i].Location);
                    Assert.Equal(srcChains[i].Flags, candChains[i].Flags);
                    Assert.Equal(srcChains[i].KeyLength, candChains[i].KeyLength);
                    Assert.Equal(KeyBlobSize, candChains[i].KeyLength);
                    Assert.Equal(TargetKeySha256, Hex(SHA256.HashData(DescKey(candidateBytes, candChains[i]))));
                    Assert.True(chainHashes.ContainsKey(names[i]), "chain hash missing for " + names[i]);
                    Assert.Equal(TargetKeySha256, chainHashes[names[i]].ToUpperInvariant());
                }
            }

            var allowed = BuildAllowedMask(sourceBytes.Length, src);
            int firstUnexpected = -1;
            for (int i = 0; i < sourceBytes.Length; i++)
            {
                if (!allowed[i] && sourceBytes[i] != candidateBytes[i])
                {
                    firstUnexpected = i;
                    break;
                }
            }

            Assert.True(firstUnexpected < 0, "byte " + firstUnexpected + " outside the four allowed ranges changed");

            ExportCandidateGroupIfRequested(kindName, candidateBytes, cand.KeyBlob, fx);
        }

        [Theory]
        [InlineData("missing")]
        [InlineData("duplicate")]
        [InlineData("extra")]
        public async Task RootChainMissingDuplicateOrExtraIsRejected(string caseName)
        {
            var fx = _fx;
            var api = RequireApi();
            using var negative = new NegativeCase(fx.Root, "chain-" + caseName);

            byte[][] chains;
            int expectedChainCount;
            switch (caseName)
            {
                case "missing":
                    chains = new[] { fx.ChainFor("boot", 3, 4), fx.ChainFor("recovery", 1, 8) };
                    expectedChainCount = 2;
                    break;
                case "duplicate":
                    chains = new[]
                    {
                        fx.ChainFor("boot", 3, 4),
                        fx.ChainFor("boot", 1, 8),
                        fx.ChainFor("vbmeta_system", 2, 16)
                    };
                    expectedChainCount = 3;
                    break;
                default:
                    chains = new[]
                    {
                        fx.ChainFor("boot", 3, 4),
                        fx.ChainFor("recovery", 1, 8),
                        fx.ChainFor("vbmeta_system", 2, 16),
                        fx.ChainFor("vbmeta_vendor", 5, 32)
                    };
                    expectedChainCount = 4;
                    break;
            }

            byte[] source = fx.BuildRootPartition(chains);

            var parsed = Parse(source, 0);
            var manifest = parsed.Descriptors.Where(d => d.Tag != 4).ToArray();
            Assert.Equal(fx.PlainDescriptors.Length, manifest.Length);
            for (int i = 0; i < manifest.Length; i++)
                Assert.Equal(fx.PlainDescriptors[i], manifest[i].Raw);
            Assert.Equal(expectedChainCount, parsed.Descriptors.Count(d => d.Tag == 4));
            foreach (var chain in parsed.Descriptors.Where(d => d.Tag == 4))
                Assert.Equal(KeyBlobSize, chain.KeyLength);
            AssertBlobAuthVerifies(source, parsed);

            negative.WriteSource(source);
            var claim = new VerifiedEdlFile(negative.SourcePath, source.Length, Hex(SHA256.HashData(source)));
            string[] before = negative.Snapshot();

            await Assert.ThrowsAsync<InvalidDataException>(
                () => InvokeResignAsync(api, claim, "Vbmeta", negative.CandidatePath));

            negative.AssertClean(before, source);
        }

        [Theory]
        [InlineData("claim-sha")]
        [InlineData("claim-length")]
        [InlineData("auth-hash")]
        [InlineData("auth-signature")]
        [InlineData("footer-range")]
        [InlineData("footer-budget")]
        [InlineData("key-metadata")]
        [InlineData("algorithm")]
        [InlineData("key-size")]
        [InlineData("key-bits")]
        public async Task InvalidSourceClaimAuthenticationBoundsOrKeyIsRejected(string caseName)
        {
            var fx = _fx;
            var api = RequireApi();
            using var negative = new NegativeCase(fx.Root, "source-" + caseName);

            byte[] source;
            string kindName;
            long claimedLength;
            string claimedSha;

            switch (caseName)
            {
                case "claim-sha":
                {
                    source = (byte[])fx.VbmetaSystemBytes.Clone();
                    kindName = "VbmetaSystem";
                    claimedLength = source.Length;
                    claimedSha = new string('0', 64);
                    break;
                }
                case "claim-length":
                {
                    source = (byte[])fx.VbmetaSystemBytes.Clone();
                    kindName = "VbmetaSystem";
                    claimedLength = source.Length + 1;
                    claimedSha = string.Empty;
                    break;
                }
                case "auth-hash":
                {
                    source = WithFlippedByte(fx.VbmetaSystemBytes, HeaderSize);
                    kindName = "VbmetaSystem";
                    claimedLength = source.Length;
                    claimedSha = string.Empty;
                    break;
                }
                case "auth-signature":
                {
                    source = WithFlippedByte(fx.VbmetaSystemBytes, HeaderSize + 64);
                    kindName = "VbmetaSystem";
                    claimedLength = source.Length;
                    claimedSha = string.Empty;
                    break;
                }
                case "footer-range":
                {
                    source = WithU64(fx.RecoveryBytes, fx.RecoveryBytes.Length - FooterSize + 20, (ulong)(fx.RecoveryBytes.Length - 32));
                    kindName = "Recovery";
                    claimedLength = source.Length;
                    claimedSha = string.Empty;
                    break;
                }
                case "footer-budget":
                {
                    source = WithU64(fx.RecoveryBytes, fx.RecoveryBytes.Length - FooterSize + 28, 65537UL);
                    kindName = "Recovery";
                    claimedLength = source.Length;
                    claimedSha = string.Empty;
                    break;
                }
                case "key-metadata":
                {
                    source = (byte[])fx.VbmetaSystemBytes.Clone();
                    PutU64(source, 80, 0UL);
                    PutU64(source, 88, 8UL);
                    ReauthenticateWithSourceKey(source, 0);
                    kindName = "VbmetaSystem";
                    claimedLength = source.Length;
                    claimedSha = string.Empty;
                    break;
                }
                case "algorithm":
                {
                    source = WithU32(fx.VbmetaSystemBytes, 28, 1);
                    ReauthenticateWithSourceKey(source, 0);
                    kindName = "VbmetaSystem";
                    claimedLength = source.Length;
                    claimedSha = string.Empty;
                    break;
                }
                case "key-size":
                {
                    source = WithU64(fx.VbmetaSystemBytes, 72, 1031UL);
                    ReauthenticateWithSourceKey(source, 0);
                    kindName = "VbmetaSystem";
                    claimedLength = source.Length;
                    claimedSha = string.Empty;
                    break;
                }
                case "key-bits":
                {
                    source = (byte[])fx.VbmetaSystemBytes.Clone();
                    PutU32(source, HeaderSize + AuthSize + 64, 2048);
                    ReauthenticateWithSourceKey(source, 0);
                    kindName = "VbmetaSystem";
                    claimedLength = source.Length;
                    claimedSha = string.Empty;
                    break;
                }
                default:
                    throw new InvalidOperationException("unknown source fault case " + caseName);
            }

            negative.WriteSource(source);
            var claim = new VerifiedEdlFile(
                negative.SourcePath,
                claimedLength,
                claimedSha.Length == 0 ? Hex(SHA256.HashData(source)) : claimedSha);
            string[] before = negative.Snapshot();

            await Assert.ThrowsAsync<InvalidDataException>(
                () => InvokeResignAsync(api, claim, kindName, negative.CandidatePath));

            negative.AssertClean(before, source);
        }

        [Fact]
        public async Task PreCancelledTokenIsRejectedWithoutTouchingTheFilesystem()
        {
            var fx = _fx;
            var api = RequireApi();
            using var negative = new NegativeCase(fx.Root, "cancel");

            byte[] source = fx.VbmetaSystemBytes;
            negative.WriteSource(source);
            var claim = new VerifiedEdlFile(negative.SourcePath, source.Length, Hex(SHA256.HashData(source)));
            string[] before = negative.Snapshot();

            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();

            await Assert.ThrowsAsync<OperationCanceledException>(
                () => InvokeResignAsync(api, claim, "VbmetaSystem", negative.CandidatePath, cancellation.Token));

            negative.AssertClean(before, source);
        }

        private static AvbApi RequireApi()
        {
            var assembly = typeof(VerifiedEdlFile).Assembly;
            var builderType = assembly.GetType("FreedomInstaller.Core.EdlRawBootBuilder", false, false);
            Assert.NotNull(builderType);
            var method = builderType.GetMethod(
                "ResignAvbNodeAsync",
                BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
            Assert.NotNull(method);
            var kindType = assembly.GetType("FreedomInstaller.Core.EdlRawAvbNodeKind", false, false);
            Assert.NotNull(kindType);
            Assert.True(kindType.IsEnum, "EdlRawAvbNodeKind must be an enum");
            foreach (string name in new[] { "Recovery", "VbmetaSystem", "Vbmeta" })
                Assert.True(Enum.IsDefined(kindType, name), "kind enum must define " + name);

            return new AvbApi { Method = method, KindType = kindType };
        }

        private sealed class AvbApi
        {
            public MethodInfo Method;
            public Type KindType;
        }

        private static Task<object> InvokeResignAsync(VerifiedEdlFile original, string kindName, string candidatePath)
        {
            return InvokeResignAsync(RequireApi(), original, kindName, candidatePath, CancellationToken.None);
        }

        private static async Task<object> InvokeResignAsync(
            AvbApi api,
            VerifiedEdlFile original,
            string kindName,
            string candidatePath,
            CancellationToken cancellationToken = default)
        {
            object kind = Enum.Parse(api.KindType, kindName);

            object returned;
            try
            {
                returned = api.Method.Invoke(
                    null, new object[] { original, kind, candidatePath, cancellationToken });
            }
            catch (TargetInvocationException ex) when (ex.InnerException != null)
            {
                throw ex.InnerException;
            }

            var task = returned as Task;
            if (task == null) throw new InvalidOperationException("ResignAvbNodeAsync must return a Task");

            await task.ConfigureAwait(false);

            var resultProperty = task.GetType().GetProperty("Result", BindingFlags.Public | BindingFlags.Instance);
            if (resultProperty == null) throw new InvalidOperationException("resign task must expose Result");
            object node = resultProperty.GetValue(task);
            if (node == null) throw new InvalidOperationException("ResignAvbNodeAsync must return a node");
            return node;
        }

        private static byte[] WithFlippedByte(byte[] source, int offset)
        {
            var copy = (byte[])source.Clone();
            copy[offset] ^= 0xFF;
            return copy;
        }

        private static byte[] WithU32(byte[] source, int offset, uint value)
        {
            var copy = (byte[])source.Clone();
            PutU32(copy, offset, value);
            return copy;
        }

        private static byte[] WithU64(byte[] source, int offset, ulong value)
        {
            var copy = (byte[])source.Clone();
            PutU64(copy, offset, value);
            return copy;
        }

        private static void ReauthenticateWithSourceKey(byte[] partition, int blobOffset)
        {
            int authSize = checked((int)ReadU64(partition, blobOffset + 12));
            int auxSize = checked((int)ReadU64(partition, blobOffset + 20));
            int hashOffset = checked((int)ReadU64(partition, blobOffset + 32));
            int hashLength = checked((int)ReadU64(partition, blobOffset + 40));
            int sigOffset = checked((int)ReadU64(partition, blobOffset + 48));
            int sigLength = checked((int)ReadU64(partition, blobOffset + 56));
            Assert.Equal(AuthSize, authSize);
            Assert.Equal(32, hashLength);
            Assert.Equal(512, sigLength);

            int authOffset = blobOffset + HeaderSize;
            int auxOffset = authOffset + authSize;
            var hashed = new byte[HeaderSize + auxSize];
            Buffer.BlockCopy(partition, blobOffset, hashed, 0, HeaderSize);
            Buffer.BlockCopy(partition, auxOffset, hashed, HeaderSize, auxSize);

            byte[] hash = SHA256.HashData(hashed);
            byte[] signature;
            lock (SignGate)
            {
                signature = SourceKey.Value.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }

            Buffer.BlockCopy(hash, 0, partition, authOffset + hashOffset, hash.Length);
            Buffer.BlockCopy(signature, 0, partition, authOffset + sigOffset, signature.Length);
        }

        private static void ExportCandidateGroupIfRequested(
            string kindName, byte[] candidateBytes, byte[] candidateKeyBlob, AvbFixture fixture)
        {
            if (!TryGetExportRoot(out string exportRoot)) return;
            string directory = Path.Combine(exportRoot, "candidate");
            Directory.CreateDirectory(directory);
            string canonicalName = CanonicalFileName(kindName);
            string canonicalPath = Path.Combine(directory, canonicalName);
            File.WriteAllBytes(canonicalPath, candidateBytes);
            File.WriteAllBytes(Path.Combine(directory, "system.img"), fixture.SystemLeafBytes);
            File.WriteAllBytes(Path.Combine(directory, "vendor.img"), fixture.VendorLeafBytes);
            File.WriteAllBytes(Path.Combine(directory, "public.avbpubkey"), candidateKeyBlob);
            Assert.True(File.Exists(canonicalPath), "candidate export is missing " + canonicalName);
        }

        private static string CanonicalFileName(string kindName)
        {
            if (kindName == "Recovery") return "recovery.img";
            if (kindName == "VbmetaSystem") return "vbmeta_system.img";
            if (kindName == "Vbmeta") return "vbmeta.img";
            throw new InvalidOperationException("unknown kind " + kindName);
        }

        private static bool TryGetExportRoot(out string exportRoot)
        {
            exportRoot = string.Empty;
            string configured = Environment.GetEnvironmentVariable(ExportRootEnvironmentVariable);
            if (string.IsNullOrEmpty(configured)) return false;

            string normalized = configured.TrimEnd('/');
            if (!IsEvidenceDirectory(normalized))
                throw new InvalidOperationException(
                    ExportRootEnvironmentVariable + " must be an absolute Linux path at /evidence or beneath /evidence/.");

            exportRoot = normalized;
            return true;
        }

        private static bool IsEvidenceDirectory(string path)
        {
            if (path.Length == 0 || path[0] != '/') return false;
            string[] segments = path.Split('/');
            if (segments.Length < 2 || segments[0].Length != 0) return false;
            if (!string.Equals(segments[1], "evidence", StringComparison.Ordinal)) return false;
            for (int i = 1; i < segments.Length; i++)
            {
                string segment = segments[i];
                if (segment.Length == 0) return false;
                if (segment == "." || segment == "..") return false;
                if (segment.IndexOf('\\') >= 0 || segment.IndexOf(':') >= 0) return false;
            }

            return true;
        }

        private static object Value(object target, string name)
        {
            var property = target.GetType().GetProperty(
                name, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(property);
            object value = property.GetValue(target);
            Assert.NotNull(value);
            return value;
        }

        private static bool[] BuildAllowedMask(int partitionLength, ParsedAvb src)
        {
            var mask = new bool[partitionLength];
            Mark(mask, src.BlobOffset + HeaderSize, 32);
            Mark(mask, src.BlobOffset + HeaderSize + 64, 512);
            Mark(mask, src.KeyOffset, KeyBlobSize);
            foreach (var chain in src.Descriptors.Where(d => d.Tag == 4))
                Mark(mask, chain.Offset + 92 + chain.NameLength, chain.KeyLength);
            return mask;
        }

        private static void Mark(bool[] mask, int offset, int length)
        {
            for (int i = 0; i < length; i++)
            {
                Assert.True(offset + i >= 0 && offset + i < mask.Length, "allowed range escapes partition");
                mask[offset + i] = true;
            }
        }

        private static int BlobOffsetFor(string kind, byte[] partition)
        {
            if (!string.Equals(kind, "Recovery", StringComparison.Ordinal)) return 0;
            int footer = partition.Length - FooterSize;
            Assert.Equal("AVBf", Encoding.ASCII.GetString(partition, footer, 4));
            Assert.Equal(1u, ReadU32(partition, footer + 4));
            Assert.Equal(0u, ReadU32(partition, footer + 8));
            Assert.Equal(32768UL, ReadU64(partition, footer + 12));
            Assert.Equal(32768UL, ReadU64(partition, footer + 20));
            return (int)ReadU64(partition, footer + 20);
        }

        private static ParsedAvb Parse(byte[] partition, int blobOffset)
        {
            var parsed = new ParsedAvb { Partition = partition, BlobOffset = blobOffset };
            Assert.True(blobOffset >= 0 && blobOffset + HeaderSize + AuthSize <= partition.Length, "blob offset out of range");
            Assert.Equal("AVB0", Encoding.ASCII.GetString(partition, blobOffset, 4));
            parsed.Major = ReadU32(partition, blobOffset + 4);
            parsed.Minor = ReadU32(partition, blobOffset + 8);
            parsed.AuthSize = (int)ReadU64(partition, blobOffset + 12);
            parsed.AuxSize = (int)ReadU64(partition, blobOffset + 20);
            parsed.Algorithm = ReadU32(partition, blobOffset + 28);
            int hashOffset = checked((int)ReadU64(partition, blobOffset + 32));
            int hashLength = checked((int)ReadU64(partition, blobOffset + 40));
            int sigOffset = checked((int)ReadU64(partition, blobOffset + 48));
            int sigLength = checked((int)ReadU64(partition, blobOffset + 56));
            int keyOffset = checked((int)ReadU64(partition, blobOffset + 64));
            int keyLength = checked((int)ReadU64(partition, blobOffset + 72));
            parsed.DescOffset = checked((int)ReadU64(partition, blobOffset + 96));
            parsed.DescSize = checked((int)ReadU64(partition, blobOffset + 104));
            parsed.RollbackIndex = ReadU64(partition, blobOffset + 112);
            parsed.Flags = ReadU32(partition, blobOffset + 120);
            parsed.RollbackLocation = ReadU32(partition, blobOffset + 124);
            Assert.Equal(AuthSize, parsed.AuthSize);

            parsed.AuthOffset = blobOffset + HeaderSize;
            parsed.AuxOffset = parsed.AuthOffset + parsed.AuthSize;
            Assert.True(parsed.AuxOffset + parsed.AuxSize <= partition.Length, "aux block out of range");
            parsed.KeyOffset = parsed.AuxOffset + keyOffset;
            parsed.Hash = Slice(partition, parsed.AuthOffset + hashOffset, hashLength);
            parsed.Signature = Slice(partition, parsed.AuthOffset + sigOffset, sigLength);
            parsed.KeyBlob = Slice(partition, parsed.KeyOffset, keyLength);

            int position = parsed.AuxOffset + parsed.DescOffset;
            int end = position + parsed.DescSize;
            Assert.True(end <= parsed.AuxOffset + parsed.AuxSize, "descriptor range out of range");
            while (position < end)
            {
                ulong tag = ReadU64(partition, position);
                long following = (long)ReadU64(partition, position + 8);
                long total = 16 + following;
                Assert.True(total > 16 && position + total <= end, "descriptor overruns descriptor block");
                var descriptor = new RawDesc
                {
                    Tag = tag,
                    Offset = position,
                    Raw = Slice(partition, position, (int)total)
                };
                if (tag == 4)
                {
                    descriptor.Location = ReadU32(partition, position + 16);
                    descriptor.NameLength = (int)ReadU32(partition, position + 20);
                    descriptor.KeyLength = (int)ReadU32(partition, position + 24);
                    descriptor.Flags = ReadU32(partition, position + 28);
                }

                parsed.Descriptors.Add(descriptor);
                position += (int)total;
            }

            Assert.Equal(end, position);
            return parsed;
        }

        private static void AssertBlobAuthVerifies(byte[] partition, ParsedAvb parsed)
        {
            var header = Slice(partition, parsed.BlobOffset, HeaderSize);
            var aux = Slice(partition, parsed.AuxOffset, parsed.AuxSize);
            var hashed = new byte[header.Length + aux.Length];
            Buffer.BlockCopy(header, 0, hashed, 0, header.Length);
            Buffer.BlockCopy(aux, 0, hashed, header.Length, aux.Length);
            var hash = SHA256.HashData(hashed);
            Assert.Equal(hash, parsed.Hash);

            using var rsa = RSA.Create();
            rsa.ImportParameters(KeyParams(parsed.KeyBlob));
            Assert.True(
                rsa.VerifyHash(parsed.Hash, parsed.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                "AVB RSA signature must verify with the embedded OEM key");
        }

        private static RSAParameters KeyParams(byte[] keyBlob)
        {
            Assert.Equal(KeyBlobSize, keyBlob.Length);
            Assert.Equal(4096u, ReadU32(keyBlob, 0));
            var modulus = new byte[512];
            Buffer.BlockCopy(keyBlob, 8, modulus, 0, 512);
            return new RSAParameters { Modulus = modulus, Exponent = new byte[] { 1, 0, 1 } };
        }

        private static string DescName(byte[] partition, RawDesc descriptor) =>
            Encoding.ASCII.GetString(partition, descriptor.Offset + 92, descriptor.NameLength);

        private static byte[] DescKey(byte[] partition, RawDesc descriptor) =>
            Slice(partition, descriptor.Offset + 92 + descriptor.NameLength, descriptor.KeyLength);

        private static byte[] Slice(byte[] source, int offset, int length)
        {
            Assert.True(offset >= 0 && length >= 0 && offset + length <= source.Length, "slice out of range");
            var result = new byte[length];
            Buffer.BlockCopy(source, offset, result, 0, length);
            return result;
        }

        private static string Hex(byte[] value) => Convert.ToHexString(value);

        private static uint ReadU32(byte[] buffer, int offset) => BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(offset, 4));
        private static ulong ReadU64(byte[] buffer, int offset) => BinaryPrimitives.ReadUInt64BigEndian(buffer.AsSpan(offset, 8));
        private static void PutU32(byte[] buffer, int offset, uint value) => BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(offset, 4), value);
        private static void PutU64(byte[] buffer, int offset, ulong value) => BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(offset, 8), value);

        private static void FillPattern(byte[] buffer, int offset, int length, byte seed)
        {
            for (int i = 0; i < length; i++) buffer[offset + i] = (byte)(seed + i * 7);
        }

        private sealed class NegativeCase : IDisposable
        {
            private readonly string _directory;

            public NegativeCase(string fixtureRoot, string label)
            {
                _directory = Path.Combine(fixtureRoot, "case-" + label + "-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(_directory);
                SourcePath = Path.Combine(_directory, "source.img");
                CandidatePath = Path.Combine(_directory, "candidate.img");
            }

            public string SourcePath { get; }
            public string CandidatePath { get; }

            public void WriteSource(byte[] bytes)
            {
                File.WriteAllBytes(SourcePath, bytes);
            }

            public string[] Snapshot()
            {
                return Directory.GetFileSystemEntries(_directory)
                    .OrderBy(entry => entry, StringComparer.Ordinal)
                    .ToArray();
            }

            public void AssertClean(string[] expectedEntries, byte[] expectedSource)
            {
                Assert.False(File.Exists(CandidatePath), "rejected resignation must not leave a candidate file");
                Assert.Equal(
                    expectedEntries,
                    Directory.GetFileSystemEntries(_directory)
                        .OrderBy(entry => entry, StringComparer.Ordinal)
                        .ToArray());
                Assert.Equal(expectedSource, File.ReadAllBytes(SourcePath));
            }

            public void Dispose()
            {
                try
                {
                    if (Directory.Exists(_directory)) Directory.Delete(_directory, true);
                }
                catch
                {
                }
            }
        }

        internal sealed class ParsedAvb
        {
            public byte[] Partition = Array.Empty<byte>();
            public int BlobOffset;
            public int AuthSize;
            public int AuxSize;
            public int AuthOffset;
            public int AuxOffset;
            public int KeyOffset;
            public int DescOffset;
            public int DescSize;
            public uint Major;
            public uint Minor;
            public uint Algorithm;
            public uint Flags;
            public uint RollbackLocation;
            public ulong RollbackIndex;
            public byte[] Hash = Array.Empty<byte>();
            public byte[] Signature = Array.Empty<byte>();
            public byte[] KeyBlob = Array.Empty<byte>();
            public readonly List<RawDesc> Descriptors = new List<RawDesc>();
            public int BlobLength => AuxOffset + AuxSize - BlobOffset;
        }

        internal sealed class RawDesc
        {
            public ulong Tag;
            public int Offset;
            public byte[] Raw = Array.Empty<byte>();
            public uint Location;
            public uint Flags;
            public int NameLength;
            public int KeyLength;
        }

        public sealed class AvbFixture : IDisposable
        {
            public string Root = string.Empty;
            public byte[] KeyBlob = Array.Empty<byte>();
            public byte[][] PlainDescriptors = Array.Empty<byte[]>();
            public byte[] SystemLeafBytes = Array.Empty<byte>();
            public byte[] VendorLeafBytes = Array.Empty<byte>();
            public string RecoveryPath = string.Empty;
            public string VbmetaSystemPath = string.Empty;
            public string VbmetaPath = string.Empty;
            public byte[] RecoveryBytes = Array.Empty<byte>();
            public byte[] VbmetaSystemBytes = Array.Empty<byte>();
            public byte[] VbmetaBytes = Array.Empty<byte>();

            private readonly RSA _sourceKey;

            public AvbFixture()
                : this(SourceKey.Value)
            {
            }

            internal AvbFixture(RSA? originalKey)
            {
                _sourceKey = originalKey ?? SourceKey.Value;
                string parent = TestArtifactRoot.Resolve();
                Root = Path.Combine(parent, "avbchain-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(Root);

                RSA rsa = _sourceKey;
                KeyBlob = BuildKeyBlob(rsa);

                SystemLeafBytes = PatternBlock(4096, 0x61);
                VendorLeafBytes = PatternBlock(4096, 0x6B);
                byte[] systemSalt = PatternBlock(16, 0x9D);
                byte[] vendorSalt = PatternBlock(16, 0xA7);

                var plain = new[]
                {
                    PropertyDescriptor("com.android.build.fingerprint", "synthetic/avb/chain"),
                    HashDescriptor("system", 4096, systemSalt, SystemLeafBytes),
                    HashtreeDescriptor("vendor", 4096, vendorSalt, VendorLeafBytes),
                    UnknownDescriptor(77, 48)
                };
                PlainDescriptors = plain;

                byte[] recoveryBlob = BuildBlob(rsa, KeyBlob, plain);
                var recovery = new byte[RecoverySize];
                FillPattern(recovery, 0, recovery.Length, 0x21);
                Buffer.BlockCopy(recoveryBlob, 0, recovery, 32768, recoveryBlob.Length);
                var footer = new byte[FooterSize];
                Encoding.ASCII.GetBytes("AVBf").CopyTo(footer, 0);
                PutU32(footer, 4, 1);
                PutU32(footer, 8, 0);
                PutU64(footer, 12, 32768);
                PutU64(footer, 20, 32768);
                PutU64(footer, 28, (ulong)recoveryBlob.Length);
                Buffer.BlockCopy(footer, 0, recovery, recovery.Length - FooterSize, FooterSize);

                byte[] systemBlob = BuildBlob(rsa, KeyBlob, plain);
                var system = new byte[StandaloneSize];
                FillPattern(system, 0, system.Length, 0x40);
                Buffer.BlockCopy(systemBlob, 0, system, 0, systemBlob.Length);
                FillPattern(system, systemBlob.Length, system.Length - systemBlob.Length, 0x77);

                var rootDescriptors = plain.Concat(new[]
                {
                    ChainDescriptor("boot", KeyBlob, 3, 4),
                    ChainDescriptor("recovery", KeyBlob, 1, 8),
                    ChainDescriptor("vbmeta_system", KeyBlob, 2, 16)
                }).ToArray();
                byte[] rootBlob = BuildBlob(rsa, KeyBlob, rootDescriptors);
                var root = new byte[StandaloneSize];
                FillPattern(root, 0, root.Length, 0x58);
                Buffer.BlockCopy(rootBlob, 0, root, 0, rootBlob.Length);
                FillPattern(root, rootBlob.Length, root.Length - rootBlob.Length, 0x88);

                RecoveryPath = Path.Combine(Root, "recovery.img");
                VbmetaSystemPath = Path.Combine(Root, "vbmeta_system.img");
                VbmetaPath = Path.Combine(Root, "vbmeta.img");
                File.WriteAllBytes(RecoveryPath, recovery);
                File.WriteAllBytes(VbmetaSystemPath, system);
                File.WriteAllBytes(VbmetaPath, root);
                File.WriteAllBytes(Path.Combine(Root, "system.img"), SystemLeafBytes);
                File.WriteAllBytes(Path.Combine(Root, "vendor.img"), VendorLeafBytes);
                RecoveryBytes = recovery;
                VbmetaSystemBytes = system;
                VbmetaBytes = root;

                ExportSourceGroupIfRequested();
            }

            public byte[] BuildRootPartition(params byte[][] chainDescriptors)
            {
                var descriptors = new List<byte[]>(PlainDescriptors);
                descriptors.AddRange(chainDescriptors);
                byte[] blob = BuildBlob(_sourceKey, KeyBlob, descriptors.ToArray());
                Assert.True(blob.Length <= StandaloneSize, "synthetic root blob must fit the standalone partition");
                var partition = new byte[StandaloneSize];
                FillPattern(partition, 0, partition.Length, 0x58);
                Buffer.BlockCopy(blob, 0, partition, 0, blob.Length);
                FillPattern(partition, blob.Length, partition.Length - blob.Length, 0x88);
                return partition;
            }

            public byte[] ChainFor(string name, uint location, uint flags)
            {
                return ChainDescriptor(name, KeyBlob, location, flags);
            }

            internal VerifiedEdlFile RewriteBootLeaf(string bootPath, int extraAuxPaddingBytes = 0)
            {
                string fullPath = Path.GetFullPath(bootPath);

                using var stream = new FileStream(fullPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                long fileLength = stream.Length;
                Assert.True(fileLength > FooterSize * 2, "boot partition is too small for an AVB footer");

                var originalFooter = new byte[FooterSize];
                stream.Position = fileLength - FooterSize;
                int footerRead = 0;
                while (footerRead < FooterSize)
                {
                    int chunk = stream.Read(originalFooter, footerRead, FooterSize - footerRead);
                    Assert.True(chunk > 0, "boot partition footer is truncated");
                    footerRead += chunk;
                }

                Assert.Equal("AVBf", Encoding.ASCII.GetString(originalFooter, 0, 4));
                Assert.Equal(1u, ReadU32(originalFooter, 4));
                long originalImageSize = checked((long)ReadU64(originalFooter, 12));
                long vbmetaOffset = checked((long)ReadU64(originalFooter, 20));
                Assert.True(
                    originalImageSize >= 0 && originalImageSize <= vbmetaOffset,
                    "original image must end before the vbmeta blob");
                Assert.True(originalImageSize <= 1024 * 1024, "boot body prefix must stay within the 1 MiB test bound");
                Assert.True(vbmetaOffset <= fileLength - FooterSize, "vbmeta blob must end before the footer");

                var bodyPrefix = new byte[(int)originalImageSize];
                stream.Position = 0;
                int bodyRead = 0;
                while (bodyRead < bodyPrefix.Length)
                {
                    int chunk = stream.Read(bodyPrefix, bodyRead, bodyPrefix.Length - bodyRead);
                    Assert.True(chunk > 0, "boot partition body is truncated");
                    bodyRead += chunk;
                }

                byte[] bootDescriptor = HashDescriptor("boot", originalImageSize, PatternBlock(16, 0xB4), bodyPrefix);
                byte[] blob = BuildBlob(
                    _sourceKey,
                    KeyBlob,
                    new[] { bootDescriptor },
                    flags: 0,
                    extraAuxPaddingBytes: extraAuxPaddingBytes);
                Assert.True(
                    blob.Length <= fileLength - FooterSize - vbmetaOffset,
                    "signed boot blob must fit before the original footer");

                var newFooter = (byte[])originalFooter.Clone();
                PutU64(newFooter, 28, (ulong)blob.Length);

                stream.SetLength(vbmetaOffset);
                stream.Position = vbmetaOffset;
                stream.Write(blob, 0, blob.Length);
                stream.SetLength(fileLength);
                stream.Position = fileLength - FooterSize;
                stream.Write(newFooter, 0, FooterSize);
                stream.Flush(true);

                stream.Position = 0;
                string sha256 = Convert.ToHexString(SHA256.HashData(stream));
                return new VerifiedEdlFile(fullPath, fileLength, sha256);
            }

            internal static void AssertAuthenticatedSignedBlob(byte[] blob)
            {
                var parsed = Parse(blob, 0);
                AssertBlobAuthVerifies(blob, parsed);
            }

            private void ExportSourceGroupIfRequested()
            {
                if (!TryGetExportRoot(out string exportRoot)) return;
                string directory = Path.Combine(exportRoot, "source");
                Directory.CreateDirectory(directory);
                File.WriteAllBytes(Path.Combine(directory, "recovery.img"), RecoveryBytes);
                File.WriteAllBytes(Path.Combine(directory, "vbmeta_system.img"), VbmetaSystemBytes);
                File.WriteAllBytes(Path.Combine(directory, "vbmeta.img"), VbmetaBytes);
                File.WriteAllBytes(Path.Combine(directory, "system.img"), SystemLeafBytes);
                File.WriteAllBytes(Path.Combine(directory, "vendor.img"), VendorLeafBytes);
                File.WriteAllBytes(Path.Combine(directory, "public.avbpubkey"), KeyBlob);
                Assert.True(
                    File.Exists(Path.Combine(directory, "public.avbpubkey")),
                    "source export must contain the public AVB key blob");
            }

            public void Dispose()
            {
                try
                {
                    if (Directory.Exists(Root)) Directory.Delete(Root, true);
                }
                catch
                {
                }
            }

            private static byte[] BuildBlob(
                RSA rsa, byte[] keyBlob, byte[][] descriptors,
                uint flags = FrozenFlags, int extraAuxPaddingBytes = 0)
            {
                Assert.True(
                    extraAuxPaddingBytes >= 0 && extraAuxPaddingBytes <= 1024 * 1024,
                    "extra aux padding must stay within the 1 MiB test bound");
                int descriptorTotal = descriptors.Sum(d => d.Length);
                int auxRaw = 64 + KeyBlobSize + 40 + descriptorTotal + extraAuxPaddingBytes;
                int auxSize = (auxRaw + 63) & ~63;
                var aux = new byte[auxSize];
                FillPattern(aux, 0, 64, 0xA5);
                Buffer.BlockCopy(keyBlob, 0, aux, 64, KeyBlobSize);
                FillPattern(aux, 64 + KeyBlobSize, 40, 0x3C);
                int position = 64 + KeyBlobSize + 40;
                foreach (var descriptor in descriptors)
                {
                    Buffer.BlockCopy(descriptor, 0, aux, position, descriptor.Length);
                    position += descriptor.Length;
                }

                FillPattern(aux, position, auxSize - position, 0x96);

                var header = new byte[HeaderSize];
                Encoding.ASCII.GetBytes("AVB0").CopyTo(header, 0);
                PutU32(header, 4, 1);
                PutU32(header, 8, 2);
                PutU64(header, 12, AuthSize);
                PutU64(header, 20, (ulong)auxSize);
                PutU32(header, 28, 2);
                PutU64(header, 32, 0UL);
                PutU64(header, 40, 32UL);
                PutU64(header, 48, 64UL);
                PutU64(header, 56, 512UL);
                PutU64(header, 64, 64UL);
                PutU64(header, 72, (ulong)KeyBlobSize);
                PutU64(header, 80, 0UL);
                PutU64(header, 88, 0UL);
                PutU64(header, 96, (ulong)(64 + KeyBlobSize + 40));
                PutU64(header, 104, (ulong)descriptorTotal);
                PutU64(header, 112, FrozenRollbackIndex);
                PutU32(header, 120, flags);
                PutU32(header, 124, FrozenLocation);
                var release = Encoding.ASCII.GetBytes("avbtool 1.2.0");
                Buffer.BlockCopy(release, 0, header, 128, release.Length);
                header[128 + release.Length] = 0;

                var hashed = new byte[HeaderSize + auxSize];
                Buffer.BlockCopy(header, 0, hashed, 0, HeaderSize);
                Buffer.BlockCopy(aux, 0, hashed, HeaderSize, auxSize);
                byte[] hash = SHA256.HashData(hashed);
                byte[] signature;
                lock (SignGate)
                {
                    signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }

                var auth = new byte[AuthSize];
                FillPattern(auth, 0, AuthSize, 0x5C);
                Buffer.BlockCopy(hash, 0, auth, 0, 32);
                Buffer.BlockCopy(signature, 0, auth, 64, 512);

                var blob = new byte[HeaderSize + AuthSize + auxSize];
                Buffer.BlockCopy(header, 0, blob, 0, HeaderSize);
                Buffer.BlockCopy(auth, 0, blob, HeaderSize, AuthSize);
                Buffer.BlockCopy(aux, 0, blob, HeaderSize + AuthSize, auxSize);
                return blob;
            }

            private static byte[] BuildKeyBlob(RSA rsa)
            {
                var parameters = rsa.ExportParameters(false);
                Assert.NotNull(parameters.Modulus);
                Assert.Equal(512, parameters.Modulus.Length);
                byte[] modulus = (byte[])parameters.Modulus.Clone();
                uint low = BinaryPrimitives.ReadUInt32BigEndian(modulus.AsSpan(508, 4));
                uint inverse = Inverse32(low);
                uint n0inv = unchecked(0u - inverse);
                var n = new BigInteger(modulus, true, true);
                byte[] rr = ToFixed(BigInteger.ModPow(new BigInteger(2), 8192, n), 512);

                var blob = new byte[KeyBlobSize];
                PutU32(blob, 0, 4096);
                PutU32(blob, 4, n0inv);
                Buffer.BlockCopy(modulus, 0, blob, 8, 512);
                Buffer.BlockCopy(rr, 0, blob, 520, 512);
                return blob;
            }

            private static uint Inverse32(uint value)
            {
                uint estimate = value;
                for (int i = 0; i < 5; i++) estimate *= 2u - value * estimate;
                return estimate;
            }

            private static byte[] ToFixed(BigInteger value, int length)
            {
                byte[] raw = value.ToByteArray(true, true);
                if (raw.Length == length) return raw;
                Assert.True(raw.Length < length, "integer does not fit target width");
                var padded = new byte[length];
                Buffer.BlockCopy(raw, 0, padded, length - raw.Length, raw.Length);
                return padded;
            }

            private static byte[] PropertyDescriptor(string key, string value)
            {
                byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                byte[] valueBytes = Encoding.UTF8.GetBytes(value);
                int body = 16 + keyBytes.Length + 1 + valueBytes.Length + 1;
                int total = (16 + body + 7) & ~7;
                var descriptor = new byte[total];
                PutU64(descriptor, 0, 0);
                PutU64(descriptor, 8, (ulong)(total - 16));
                PutU64(descriptor, 16, (ulong)keyBytes.Length);
                PutU64(descriptor, 24, (ulong)valueBytes.Length);
                Buffer.BlockCopy(keyBytes, 0, descriptor, 32, keyBytes.Length);
                int cursor = 32 + keyBytes.Length;
                descriptor[cursor] = 0;
                cursor++;
                Buffer.BlockCopy(valueBytes, 0, descriptor, cursor, valueBytes.Length);
                cursor += valueBytes.Length;
                descriptor[cursor] = 0;
                FillPattern(descriptor, cursor + 1, total - cursor - 1, 0x11);
                return descriptor;
            }

            private static byte[] HashDescriptor(string name, long imageSize, byte[] salt, byte[] leaf)
            {
                byte[] nameBytes = Encoding.ASCII.GetBytes(name);
                byte[] digest = SHA256.HashData(Concat(salt, leaf));
                int dynamicLength = 132 + nameBytes.Length + salt.Length + digest.Length;
                int total = (dynamicLength + 7) & ~7;
                var descriptor = new byte[total];
                PutU64(descriptor, 0, 2);
                PutU64(descriptor, 8, (ulong)(total - 16));
                PutU64(descriptor, 16, (ulong)imageSize);
                Encoding.ASCII.GetBytes("sha256").CopyTo(descriptor, 24);
                PutU32(descriptor, 56, (uint)nameBytes.Length);
                PutU32(descriptor, 60, (uint)salt.Length);
                PutU32(descriptor, 64, (uint)digest.Length);
                PutU32(descriptor, 68, 0);
                Buffer.BlockCopy(nameBytes, 0, descriptor, 132, nameBytes.Length);
                int cursor = 132 + nameBytes.Length;
                Buffer.BlockCopy(salt, 0, descriptor, cursor, salt.Length);
                Buffer.BlockCopy(digest, 0, descriptor, cursor + salt.Length, digest.Length);
                FillPattern(descriptor, cursor + salt.Length + digest.Length, total - cursor - salt.Length - digest.Length, 0x45);
                return descriptor;
            }

            private static byte[] HashtreeDescriptor(string name, long imageSize, byte[] salt, byte[] leaf)
            {
                byte[] nameBytes = Encoding.ASCII.GetBytes(name);
                byte[] digest = SHA256.HashData(Concat(salt, leaf));
                int dynamicLength = 180 + nameBytes.Length + salt.Length + digest.Length;
                int total = (dynamicLength + 7) & ~7;
                var descriptor = new byte[total];
                PutU64(descriptor, 0, 1);
                PutU64(descriptor, 8, (ulong)(total - 16));
                PutU32(descriptor, 16, 1);
                PutU64(descriptor, 20, (ulong)imageSize);
                PutU64(descriptor, 28, 4096UL);
                PutU64(descriptor, 36, 0UL);
                PutU32(descriptor, 44, 4096);
                PutU32(descriptor, 48, 4096);
                PutU32(descriptor, 52, 0);
                PutU64(descriptor, 56, 0UL);
                PutU64(descriptor, 64, 0UL);
                Encoding.ASCII.GetBytes("sha256").CopyTo(descriptor, 72);
                PutU32(descriptor, 104, (uint)nameBytes.Length);
                PutU32(descriptor, 108, (uint)salt.Length);
                PutU32(descriptor, 112, (uint)digest.Length);
                PutU32(descriptor, 116, 0);
                Buffer.BlockCopy(nameBytes, 0, descriptor, 180, nameBytes.Length);
                int cursor = 180 + nameBytes.Length;
                Buffer.BlockCopy(salt, 0, descriptor, cursor, salt.Length);
                Buffer.BlockCopy(digest, 0, descriptor, cursor + salt.Length, digest.Length);
                FillPattern(descriptor, cursor + salt.Length + digest.Length, total - cursor - salt.Length - digest.Length, 0x49);
                return descriptor;
            }

            private static byte[] UnknownDescriptor(ulong tag, int payloadLength)
            {
                var descriptor = new byte[16 + payloadLength];
                PutU64(descriptor, 0, tag);
                PutU64(descriptor, 8, (ulong)payloadLength);
                FillPattern(descriptor, 16, payloadLength, 0x61);
                return descriptor;
            }

            private static byte[] PatternBlock(int length, byte seed)
            {
                var block = new byte[length];
                FillPattern(block, 0, length, seed);
                return block;
            }

            private static byte[] Concat(byte[] first, byte[] second)
            {
                var result = new byte[first.Length + second.Length];
                Buffer.BlockCopy(first, 0, result, 0, first.Length);
                Buffer.BlockCopy(second, 0, result, first.Length, second.Length);
                return result;
            }

            private static byte[] ChainDescriptor(string name, byte[] keyBlob, uint location, uint flags)
            {
                byte[] nameBytes = Encoding.ASCII.GetBytes(name);
                int dynamicLength = 92 + nameBytes.Length + keyBlob.Length;
                int total = (dynamicLength + 7) & ~7;
                var descriptor = new byte[total];
                PutU64(descriptor, 0, 4);
                PutU64(descriptor, 8, (ulong)(total - 16));
                PutU32(descriptor, 16, location);
                PutU32(descriptor, 20, (uint)nameBytes.Length);
                PutU32(descriptor, 24, (uint)keyBlob.Length);
                PutU32(descriptor, 28, flags);
                Buffer.BlockCopy(nameBytes, 0, descriptor, 92, nameBytes.Length);
                Buffer.BlockCopy(keyBlob, 0, descriptor, 92 + nameBytes.Length, keyBlob.Length);
                int cursor = 92 + nameBytes.Length + keyBlob.Length;
                FillPattern(descriptor, cursor, total - cursor, 0x71);
                return descriptor;
            }
        }
    }
}
