// one shared same-epoch proof that installed slot B already carries a valid
// initialized project boot while its four ancillary loaders (vendor_boot, init_boot,
// abl, xbl_config) are still factory zero and slot A stays the real source material.
// The proof owns read leases over eleven claimed inputs and its own generated child,
// recovers A's actual base with the existing five-source reader, authenticates B's
// signed vbmeta through the bounded leaf reader, decodes and natively unpacks B with
// the pinned unpacker, and requires the unpacked BaseImage to equal the exported A
// base byte-for-byte. It proves file relationships only: no fresh-device, lock-state,
// Ready, stock-B, OEM-payload or Android-B-bootable claim is made. The strict
// EdlRawInactiveSlotBackup five-zero baseline is not used or changed here.
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// Factual carrier of the initialized-inactive-B proof. It holds the caller's eleven
/// verified input leases, this proof's own tools lease and its own three output leases
/// until <see cref="Dispose"/>, then closes everything and deletes only its own GUID
/// child. Caller inputs, the chosen parent and any sentinel files are never touched.
/// </summary>
internal sealed class CurrentBootInitializedInactiveProof : IDisposable
{
    private readonly List<FileStream> _inputStreams;

    private readonly List<FileStream> _outputLeases;

    private readonly EdlRawBootTools _ownTools;

    private readonly string _ownChild;

    private int _disposed;

    internal CurrentBootInitializedInactiveProof(
        string profileId,
        VerifiedEdlFile sourceBoot,
        VerifiedEdlFile targetBoot,
        InternalSlotMaterial sourceMaterial,
        VerifiedEdlFile reconstructedBase,
        VerifiedEdlFile projectRaw,
        IReadOnlyDictionary<string, string> payloadSha256,
        VerifiedEdlFile verificationReport,
        EdlRawBootTools ownTools,
        List<FileStream> inputStreams,
        List<FileStream> outputLeases,
        string ownChild,
        IReadOnlyDictionary<string, VerifiedEdlFile> claims)
    {
        ProfileId = profileId;
        SourceBoot = sourceBoot;
        TargetBoot = targetBoot;
        SourceMaterial = sourceMaterial;
        ReconstructedBase = reconstructedBase;
        ProjectRaw = projectRaw;
        PayloadSha256 = payloadSha256;
        VerificationReport = verificationReport;
        _ownTools = ownTools;
        _inputStreams = inputStreams;
        _outputLeases = outputLeases;
        _ownChild = ownChild;
        Claims = new ReadOnlyDictionary<string, VerifiedEdlFile>(
            new Dictionary<string, VerifiedEdlFile>(claims, StringComparer.Ordinal));
    }

    /// <summary>The complete profile id the proof was resolved against.</summary>
    public string ProfileId { get; }

    /// <summary>The real source slot: always <c>a</c> for this proof.</summary>
    public string SourceSlot => "a";

    /// <summary>The initialized inactive project slot: always <c>b</c> for this proof.</summary>
    public string TargetSlot => "b";

    /// <summary>The verified claim of slot A's current boot.</summary>
    public VerifiedEdlFile SourceBoot { get; }

    /// <summary>The verified claim of slot B's initialized project boot.</summary>
    public VerifiedEdlFile TargetBoot { get; }

    /// <summary>The actual five-source material measured from slot A.</summary>
    public InternalSlotMaterial SourceMaterial { get; }

    /// <summary>This proof's exported slot-A base image inside its own child.</summary>
    public VerifiedEdlFile ReconstructedBase { get; }

    /// <summary>This proof's decoded slot-B project raw inside its own child.</summary>
    public VerifiedEdlFile ProjectRaw { get; }

    /// <summary>Observed SHA-256 of every physical unpacked payload by file name.</summary>
    public IReadOnlyDictionary<string, string> PayloadSha256 { get; }

    /// <summary>This proof's JSON report inside its own child.</summary>
    public VerifiedEdlFile VerificationReport { get; }

    /// <summary>The eleven role-mapped input claims this proof binds.</summary>
    public IReadOnlyDictionary<string, VerifiedEdlFile> Claims { get; }

    /// <summary>True once this proof's leases were released and its child deleted.</summary>
    public bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    internal void RequireUsable() => ObjectDisposedException.ThrowIf(IsDisposed, this);

    internal Task RevalidateAsync(CancellationToken ct = default) =>
        EdlRawBootBuilder.RevalidateInitializedInactiveProofAsync(this, ct);

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        foreach (FileStream stream in _outputLeases)
        {
            InitBCloseQuietly(stream);
        }

        foreach (FileStream stream in _inputStreams)
        {
            InitBCloseQuietly(stream);
        }

        _ownTools.Dispose();

        try
        {
            Directory.Delete(_ownChild, true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static void InitBCloseQuietly(FileStream stream)
    {
        try
        {
            stream.Dispose();
        }
        catch (IOException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }
}

public static partial class EdlRawBootBuilder
{
    // Proves that installed B holds a valid initialized project boot over still-zero
    // ancillary loaders while A remains real. Same-epoch file facts only.
    internal static Task<CurrentBootInitializedInactiveProof> VerifyInitializedInactiveSlotAsync(
        string profileId,
        string actualCurrentSlot,
        string targetSlot,
        VerifiedEdlFile sourceBoot,
        VerifiedEdlFile sourceVendorBoot,
        VerifiedEdlFile sourceInitBoot,
        VerifiedEdlFile sourceAbl,
        VerifiedEdlFile sourceXblConfig,
        VerifiedEdlFile inactiveProjectBoot,
        VerifiedEdlFile inactiveVendorBoot,
        VerifiedEdlFile inactiveInitBoot,
        VerifiedEdlFile inactiveAbl,
        VerifiedEdlFile inactiveXblConfig,
        VerifiedEdlFile sourceRootVbmeta,
        EdlRawBootTools tools,
        ICommandRunner runner,
        string chosenParent,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(sourceBoot);
        ArgumentNullException.ThrowIfNull(sourceVendorBoot);
        ArgumentNullException.ThrowIfNull(sourceInitBoot);
        ArgumentNullException.ThrowIfNull(sourceAbl);
        ArgumentNullException.ThrowIfNull(sourceXblConfig);
        ArgumentNullException.ThrowIfNull(inactiveProjectBoot);
        ArgumentNullException.ThrowIfNull(inactiveVendorBoot);
        ArgumentNullException.ThrowIfNull(inactiveInitBoot);
        ArgumentNullException.ThrowIfNull(inactiveAbl);
        ArgumentNullException.ThrowIfNull(inactiveXblConfig);
        ArgumentNullException.ThrowIfNull(sourceRootVbmeta);
        ArgumentNullException.ThrowIfNull(tools);
        ArgumentNullException.ThrowIfNull(runner);

        if (string.IsNullOrWhiteSpace(profileId))
        {
            throw new ArgumentException("profile id is required.", nameof(profileId));
        }

        if (!string.Equals(actualCurrentSlot, "a", StringComparison.Ordinal) ||
            !string.Equals(targetSlot, "b", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "only current slot 'a' with inactive target 'b' is provable here.",
                nameof(targetSlot));
        }

        ct.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(chosenParent) || !Directory.Exists(chosenParent))
        {
            throw new ArgumentException(
                "chosen parent must be an existing scratch directory.", nameof(chosenParent));
        }

        return Task.Run(
            () => VerifyInitializedInactiveCore(
                profileId,
                sourceBoot,
                sourceVendorBoot,
                sourceInitBoot,
                sourceAbl,
                sourceXblConfig,
                inactiveProjectBoot,
                inactiveVendorBoot,
                inactiveInitBoot,
                inactiveAbl,
                inactiveXblConfig,
                sourceRootVbmeta,
                tools,
                runner,
                Path.GetFullPath(chosenParent),
                ct),
            ct);
    }

    private static async Task<CurrentBootInitializedInactiveProof> VerifyInitializedInactiveCore(
        string profileId,
        VerifiedEdlFile sourceBoot,
        VerifiedEdlFile sourceVendorBoot,
        VerifiedEdlFile sourceInitBoot,
        VerifiedEdlFile sourceAbl,
        VerifiedEdlFile sourceXblConfig,
        VerifiedEdlFile inactiveProjectBoot,
        VerifiedEdlFile inactiveVendorBoot,
        VerifiedEdlFile inactiveInitBoot,
        VerifiedEdlFile inactiveAbl,
        VerifiedEdlFile inactiveXblConfig,
        VerifiedEdlFile sourceRootVbmeta,
        EdlRawBootTools tools,
        ICommandRunner runner,
        string chosenParent,
        CancellationToken ct)
    {
        EdlDeviceProfile? profile = EdlDeviceProfiles.FindById(profileId);
        if (profile is null)
        {
            throw new ArgumentException("profile id is not a known EDL profile.", nameof(profileId));
        }

        profile.RequireComplete();

        string ownChild = Path.Combine(chosenParent, "bm-initb1-" + Guid.NewGuid().ToString("N"));
        if (Directory.Exists(ownChild))
        {
            throw new InvalidOperationException(
                "initialized inactive proof child directory already exists");
        }

        var inputStreams = new List<FileStream>();
        var outputLeases = new List<FileStream>();
        EdlRawBootTools? ownTools = null;
        bool childCreated = false;
        try
        {
            Directory.CreateDirectory(ownChild);
            childCreated = true;
            ct.ThrowIfCancellationRequested();

            // This proof's own tools lease is taken before any native execution;
            // the caller's tools instance is never disposed by this proof.
            ownTools = await tools.AcquireAsync(ct);

            // Eleven held input leases, each opened, length-checked and claim-verified.
            FileStream aBoot = InitBOpenHeldInput(inputStreams, "source current_boot", sourceBoot, ct);
            FileStream sVendor = InitBOpenHeldInput(inputStreams, "source vendor_boot", sourceVendorBoot, ct);
            FileStream sInit = InitBOpenHeldInput(inputStreams, "source init_boot", sourceInitBoot, ct);
            FileStream sAbl = InitBOpenHeldInput(inputStreams, "source abl", sourceAbl, ct);
            FileStream sXbl = InitBOpenHeldInput(inputStreams, "source xbl_config", sourceXblConfig, ct);
            FileStream bBoot = InitBOpenHeldInput(inputStreams, "inactive project boot", inactiveProjectBoot, ct);
            FileStream bVendor = InitBOpenHeldInput(inputStreams, "inactive vendor_boot", inactiveVendorBoot, ct);
            FileStream bInit = InitBOpenHeldInput(inputStreams, "inactive init_boot", inactiveInitBoot, ct);
            FileStream bAbl = InitBOpenHeldInput(inputStreams, "inactive abl", inactiveAbl, ct);
            FileStream bXbl = InitBOpenHeldInput(inputStreams, "inactive xbl_config", inactiveXblConfig, ct);
            FileStream sRoot = InitBOpenHeldInput(inputStreams, "source root vbmeta", sourceRootVbmeta, ct);

            // The four inactive ancillary loaders must still be entirely factory zero;
            // B's boot must be an actual nonzero project image.
            InitBScanChunkAllZero(bVendor, "inactive vendor_boot", ct);
            InitBScanChunkAllZero(bInit, "inactive init_boot", ct);
            InitBScanChunkAllZero(bAbl, "inactive abl", ct);
            InitBScanChunkAllZero(bXbl, "inactive xbl_config", ct);
            InitBScanChunkAnyNonZero(bBoot, "inactive project boot", ct);

            // Slot A is real source material: the actual recovered base is exported.
            string baseAPath = Path.Combine(ownChild, "BaseA.bin");
            InternalSlotMaterial material = await InternalSlotMaterialReader.AnalyzeAndExportBaseAsync(
                "a", sourceBoot, sourceVendorBoot, sourceInitBoot, sourceAbl, sourceXblConfig,
                baseAPath, ct);
            long budget = material.LoaderBudget.MaxRawBytes;
            if (budget <= 0)
            {
                throw new InvalidDataException("source A loader budget is not positive");
            }

            // B must carry the exact v4 boot shape before any metadata work.
            long bLength = bBoot.Length;
            if (bLength < BootHeaderBytes || bLength % PageSize != 0)
            {
                throw new InvalidDataException("inactive project boot length must be a positive multiple of 4096");
            }

            bBoot.Position = 0;
            byte[] bHeader = new byte[BootHeaderBytes];
            ReadExactly(bBoot, bHeader, 0, bHeader.Length);
            if (!bHeader.AsSpan(0, 8).SequenceEqual(AndroidMagic))
            {
                throw new InvalidDataException("inactive project boot magic is not ANDROID!");
            }

            if (ReadLeU32(bHeader, 40) != 4 || ReadLeU32(bHeader, 20) != 1584)
            {
                throw new InvalidDataException("inactive project boot must have the Android v4 header shape");
            }

            if (ReadLeU32(bHeader, 12) != 0)
            {
                throw new InvalidDataException("inactive project boot ramdisk_size is nonzero");
            }

            if (ReadLeU32(bHeader, 1580) != 0)
            {
                throw new InvalidDataException("inactive project boot signature_size is nonzero");
            }

            // The signed vbmeta is authenticated by the shared bounded RSA leaf reader;
            // the signed image size comes only from the descriptor inside that blob.
            AvbNodeMetadata bMeta = AvbNodeReadFooterLeafMetadata(bBoot, bLength, ct);
            long signedSize = CurrentBootSignedImageSize(bMeta);
            if (signedSize <= 0 || signedSize > bLength - AvbFooterBytes)
            {
                throw new InvalidDataException("inactive project signed image size is outside the partition bounds");
            }

            ParsedVbmeta parsed = ParseVbmeta(bBoot, bMeta.VbmetaOffset, bMeta.VbmetaSize, signedSize, ct);

            bBoot.Position = 0;
            string effectiveDigest = ComputeSaltedDigest(
                bBoot, parsed.Hash.Salt, parsed.Hash.ImageSize, HashNameFor(parsed.Hash.Algorithm), ct);
            string storedDigest = ToHex(parsed.Hash.Digest);
            bool digestMatches = string.Equals(effectiveDigest, storedDigest, StringComparison.OrdinalIgnoreCase);
            bool pinnedLeaf = string.Equals(
                bMeta.SourcePublicKeySha256, AvbPublicKeySha256, StringComparison.OrdinalIgnoreCase);
            if (pinnedLeaf && !digestMatches)
            {
                throw new InvalidDataException(
                    "pinned AOSP boot leaf digest does not match the inactive project payload");
            }

            // The vbmeta here is the genuine SOURCE A root signed metadata, not a
            // B parent. When B's leaf key is not the pinned AOSP key (preserve
            // route), that OEM B leaf key must match the source A root's boot
            // child key; parent and child keys may legally differ. When B's leaf
            // IS the pinned AOSP key, its own RSA signature and physical digest
            // were already required above; the old OEM source root is not required
            // to have signed it, because the legitimate AOSP transition changes
            // the key — the higher sealed authority must check the actual known-
            // lock state before any Ready claim. No third trust route exists and
            // unknown keys are never accepted here. This remains file, native and
            // base lineage only: no hardware acceptance, no Android-B-bootable.
            var chain = await AuthenticateOriginalBootChainAsync(sourceRootVbmeta, ct);
            if (!pinnedLeaf && !string.Equals(
                    chain.BootChainPublicKeySha256,
                    bMeta.SourcePublicKeySha256,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "non-pinned inactive project boot leaf key does not match the source A root boot child key");
            }

            // Decode B with the measured A budget, prove the real menu table, then
            // hand the raw to the pinned native unpacker for the actual graph proof.
            bBoot.Position = 0;
            var (rawBytes, rawSha256) = CurrentBootDecodeComposite(bBoot, budget, ct);
            if (rawBytes is null || rawBytes.Length == 0 || rawBytes.LongLength > budget)
            {
                throw new InvalidDataException("decoded inactive project raw is empty or exceeds the measured budget");
            }

            _ = CurrentBootParseMenu(rawBytes, ct);

            string rawPath = Path.Combine(ownChild, "ProjectB.raw");
            WriteNewFile(rawPath, rawBytes, "initialized inactive project raw", ct);

            await RunNativeAsync(
                runner,
                ownTools.Unpacker.Path,
                new[] { "ProjectB.raw", "unpacked-b" },
                ownChild,
                "initialized inactive project unpack",
                ct);

            string unpackDir = Path.Combine(ownChild, "unpacked-b");
            string configPath = Path.Combine(unpackDir, "config.cfg");

            // The shared menu parser already proved entry 0 is the BASE payload
            // (type 1, flags BASE|EXEC, no alias). This read only bounds and
            // UTF-8-checks the actual native config without a second parser.
            _ = CurrentBootReadConfigLines(configPath, ct);

            _ = CurrentBootHashUnpackedPayloads(unpackDir, ct);

            string nativeBasePath = Path.Combine(unpackDir, "BaseImage");
            long nativeBaseLength = InitBRequireRegularFile(nativeBasePath, "unpacked B BaseImage");
            string nativeBaseSha = HashFileSha256(nativeBasePath, ct);

            long baseALength = new FileInfo(baseAPath).Length;
            string baseASha = HashFileSha256(baseAPath, ct);
            if (nativeBaseLength != baseALength || nativeBaseLength != material.BaseImageLength)
            {
                throw new InvalidDataException("unpacked B BaseImage length differs from the exported source A base");
            }

            if (!string.Equals(nativeBaseSha, baseASha, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(nativeBaseSha, material.BaseImageSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("unpacked B BaseImage is not exactly the exported source A base");
            }

            var payloadSha = new SortedDictionary<string, string>(StringComparer.Ordinal);
            foreach (string payloadPath in Directory.EnumerateFiles(unpackDir))
            {
                string name = Path.GetFileName(payloadPath);
                if (string.Equals(name, "config.cfg", StringComparison.Ordinal))
                {
                    continue;
                }

                payloadSha[name] = HashFileSha256(payloadPath, ct);
            }

            if (payloadSha.Count == 0)
            {
                throw new InvalidDataException("unpacked B produced no physical payloads");
            }

            // Every input claim is re-verified over its held stream before return.
            InitBReverify(aBoot, sourceBoot, "source current_boot", ct);
            InitBReverify(sVendor, sourceVendorBoot, "source vendor_boot", ct);
            InitBReverify(sInit, sourceInitBoot, "source init_boot", ct);
            InitBReverify(sAbl, sourceAbl, "source abl", ct);
            InitBReverify(sXbl, sourceXblConfig, "source xbl_config", ct);
            InitBReverify(bBoot, inactiveProjectBoot, "inactive project boot", ct);
            InitBReverify(bVendor, inactiveVendorBoot, "inactive vendor_boot", ct);
            InitBReverify(bInit, inactiveInitBoot, "inactive init_boot", ct);
            InitBReverify(bAbl, inactiveAbl, "inactive abl", ct);
            InitBReverify(bXbl, inactiveXblConfig, "inactive xbl_config", ct);
            InitBReverify(sRoot, sourceRootVbmeta, "source root vbmeta", ct);

            byte[] reportBytes = InitBReportJson(
                profileId,
                sourceBoot,
                inactiveProjectBoot,
                material,
                budget,
                baseASha,
                baseALength,
                nativeBaseSha,
                nativeBaseLength,
                rawSha256,
                rawBytes.LongLength,
                payloadSha,
                bMeta,
                pinnedLeaf,
                digestMatches,
                storedDigest,
                effectiveDigest,
                chain.BootChainPublicKeySha256);

            string reportPath = Path.Combine(ownChild, "initialized-inactive-b.report.json");
            WriteNewFile(reportPath, reportBytes, "initialized inactive project report", ct);

            long rawLength = new FileInfo(rawPath).Length;
            long reportLength = new FileInfo(reportPath).Length;
            string rawShaOnDisk = HashFileSha256(rawPath, ct);
            string reportSha = HashFileSha256(reportPath, ct);

            var projectRaw = new VerifiedEdlFile(rawPath, rawLength, rawShaOnDisk);
            var reconstructedBase = new VerifiedEdlFile(baseAPath, baseALength, baseASha);
            var report = new VerifiedEdlFile(reportPath, reportLength, reportSha);

            InitBOpenOwnLease(outputLeases, projectRaw, "project raw", ct);
            InitBOpenOwnLease(outputLeases, reconstructedBase, "reconstructed base", ct);
            InitBOpenOwnLease(outputLeases, report, "verification report", ct);

            var claims = new Dictionary<string, VerifiedEdlFile>(StringComparer.Ordinal)
            {
                ["boot_a"] = sourceBoot,
                ["vendor_boot_a"] = sourceVendorBoot,
                ["init_boot_a"] = sourceInitBoot,
                ["abl_a"] = sourceAbl,
                ["xbl_config_a"] = sourceXblConfig,
                ["boot_b"] = inactiveProjectBoot,
                ["vendor_boot_b"] = inactiveVendorBoot,
                ["init_boot_b"] = inactiveInitBoot,
                ["abl_b"] = inactiveAbl,
                ["xbl_config_b"] = inactiveXblConfig,
                ["vbmeta_a"] = sourceRootVbmeta
            };

            return new CurrentBootInitializedInactiveProof(
                profileId,
                sourceBoot,
                inactiveProjectBoot,
                material,
                reconstructedBase,
                projectRaw,
                new ReadOnlyDictionary<string, string>(payloadSha),
                report,
                ownTools,
                inputStreams,
                outputLeases,
                ownChild,
                claims);
        }
        catch
        {
            foreach (FileStream stream in outputLeases)
            {
                CloseQuietly(stream);
            }

            foreach (FileStream stream in inputStreams)
            {
                CloseQuietly(stream);
            }

            ownTools?.Dispose();

            if (childCreated)
            {
                try
                {
                    Directory.Delete(ownChild, true);
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }

            throw;
        }
    }

    private static void InitBReverify(
        FileStream stream,
        VerifiedEdlFile claim,
        string role,
        CancellationToken ct)
    {
        stream.Position = 0;
        VerifyClaim(stream, claim, role, ct);
    }

    // Rebinds every proof claim to a fresh capture: each of the eleven role-mapped
    // inputs and the three owned outputs is reopened and verified over its whole
    // claimed bytes. The proof must stay usable throughout.
    internal static Task RevalidateInitializedInactiveProofAsync(
        CurrentBootInitializedInactiveProof proof,
        CancellationToken ct = default)
    {
        return Task.Run(
            () =>
            {
                proof.RequireUsable();
                var opened = new List<FileStream>();
                try
                {
                    foreach (KeyValuePair<string, VerifiedEdlFile> claim in proof.Claims)
                    {
                        ct.ThrowIfCancellationRequested();
                        InitBOpenHeldInput(opened, claim.Key, claim.Value, ct);
                    }

                    ct.ThrowIfCancellationRequested();
                    InitBOpenHeldInput(opened, "reconstructed base", proof.ReconstructedBase, ct);

                    ct.ThrowIfCancellationRequested();
                    InitBOpenHeldInput(opened, "project raw", proof.ProjectRaw, ct);

                    ct.ThrowIfCancellationRequested();
                    InitBOpenHeldInput(opened, "verification report", proof.VerificationReport, ct);

                    ct.ThrowIfCancellationRequested();
                    proof.RequireUsable();
                }
                finally
                {
                    foreach (FileStream stream in opened)
                    {
                        CloseQuietly(stream);
                    }
                }
            },
            ct);
    }

    // Opens one held read lease, checks the claim shape, and lets the shared
    // claim verifier prove length and whole-file SHA over the held bytes.
    private static FileStream InitBOpenHeldInput(
        List<FileStream> opened,
        string role,
        VerifiedEdlFile claim,
        CancellationToken ct)
    {
        if (claim.Length <= 0 || !InitBIsSha256Hex(claim.Sha256))
        {
            throw new InvalidDataException(role + " claim is not a positive-length 64-hex SHA-256 claim");
        }

        string fullPath = InitBRequirePlainFile(claim.Path, role);
        FileStream stream;
        try
        {
            stream = new FileStream(
                fullPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                CopyChunkBytes,
                FileOptions.SequentialScan);
        }
        catch (Exception exception)
            when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new InvalidDataException(role + ": cannot open the claimed input", exception);
        }

        opened.Add(stream);
        if (stream.Length != claim.Length)
        {
            throw new InvalidDataException(role + " length differs from its claim");
        }

        VerifyClaim(stream, claim, role, ct);
        return stream;
    }

    private static void InitBOpenOwnLease(
        List<FileStream> leases,
        VerifiedEdlFile claim,
        string role,
        CancellationToken ct)
    {
        FileStream stream = new FileStream(
            claim.Path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            CopyChunkBytes,
            FileOptions.SequentialScan);
        leases.Add(stream);
        VerifyClaim(stream, claim, role, ct);
    }

    private static void InitBScanChunkAllZero(FileStream stream, string role, CancellationToken ct)
    {
        stream.Position = 0;
        var buffer = new byte[81920];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            ct.ThrowIfCancellationRequested();
            for (int index = 0; index < read; index++)
            {
                if (buffer[index] != 0)
                {
                    throw new InvalidDataException(role + " is not factory zero");
                }
            }
        }

        stream.Position = 0;
    }

    private static void InitBScanChunkAnyNonZero(FileStream stream, string role, CancellationToken ct)
    {
        stream.Position = 0;
        var buffer = new byte[81920];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            ct.ThrowIfCancellationRequested();
            for (int index = 0; index < read; index++)
            {
                if (buffer[index] != 0)
                {
                    stream.Position = 0;
                    return;
                }
            }
        }

        throw new InvalidDataException(role + " is still entirely zero");
    }

    private static bool InitBIsSha256Hex(string? value)
    {
        if (value is null || value.Length != 64)
        {
            return false;
        }

        foreach (char character in value)
        {
            if (character is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F'))
            {
                continue;
            }

            return false;
        }

        return true;
    }

    private static string InitBRequirePlainFile(string? path, string subject)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Contains('\0'))
        {
            throw new InvalidDataException(subject + " path is empty");
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception exception)
            when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new InvalidDataException(subject + " path cannot be normalized", exception);
        }

        var file = new FileInfo(fullPath);
        if (!file.Exists || InitBIsLink(file))
        {
            throw new InvalidDataException(subject + " is not a regular file");
        }

        DirectoryInfo? directory = file.Directory;
        if (directory is null || InitBIsLink(directory))
        {
            throw new InvalidDataException(subject + " containing directory is a reparse point");
        }

        return fullPath;
    }

    private static long InitBRequireRegularFile(string path, string subject)
    {
        string fullPath = InitBRequirePlainFile(path, subject);
        return new FileInfo(fullPath).Length;
    }

    private static bool InitBIsLink(FileSystemInfo info) =>
        (info.Attributes & FileAttributes.ReparsePoint) != 0 || info.LinkTarget is not null;

    // Simple observed-facts report. It records only what was measured; it never
    // claims readiness, stock B, OEM payload validity or an Android-bootable B.
    private static byte[] InitBReportJson(
        string profileId,
        VerifiedEdlFile sourceBoot,
        VerifiedEdlFile targetBoot,
        InternalSlotMaterial material,
        long budget,
        string baseSha,
        long baseLength,
        string nativeBaseSha,
        long nativeBaseLength,
        string rawSha,
        long rawLength,
        IReadOnlyDictionary<string, string> payloadSha,
        AvbNodeMetadata bMeta,
        bool pinnedLeaf,
        bool digestMatches,
        string storedDigest,
        string effectiveDigest,
        string sourceRootBootKeySha256)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteString("scope", "same-epoch-file-chain-only");
            writer.WriteString("profileId", profileId);
            writer.WriteString("sourceSlot", "a");
            writer.WriteString("targetSlot", "b");
            writer.WriteString("sourceBootSha256", sourceBoot.Sha256);
            writer.WriteNumber("sourceBootLength", sourceBoot.Length);
            writer.WriteString("targetBootSha256", targetBoot.Sha256);
            writer.WriteNumber("targetBootLength", targetBoot.Length);
            writer.WriteString("sourceBaseSha256", baseSha);
            writer.WriteNumber("sourceBaseLength", baseLength);
            writer.WriteString("nativeBaseSha256", nativeBaseSha);
            writer.WriteNumber("nativeBaseLength", nativeBaseLength);
            writer.WriteString("projectRawSha256", rawSha);
            writer.WriteNumber("projectRawLength", rawLength);
            writer.WriteNumber("loaderBudgetMaxRawBytes", budget);
            writer.WriteString("measuredBaseImageSha256", material.BaseImageSha256);
            writer.WriteStartObject("payloadSha256");
            foreach (KeyValuePair<string, string> pair in payloadSha)
            {
                writer.WriteString(pair.Key, pair.Value);
            }

            writer.WriteEndObject();
            writer.WriteString("bootLeafVbmetaSha256", AvbNodeSha256Hex(bMeta.Blob));
            writer.WriteNumber("bootLeafVbmetaBytes", bMeta.VbmetaSize);
            writer.WriteNumber("bootLeafVbmetaOffset", bMeta.VbmetaOffset);
            writer.WriteString("bootLeafKeySha256", bMeta.SourcePublicKeySha256);
            writer.WriteBoolean("bootLeafKeyIsPinnedAosp", pinnedLeaf);
            writer.WriteString("sourceRootBootKeySha256", sourceRootBootKeySha256);
            writer.WriteString("storedOemDigestHex", storedDigest);
            writer.WriteString("effectiveDigestHex", effectiveDigest);
            writer.WriteBoolean("oemDigestMatches", digestMatches);
            writer.WriteEndObject();
        }

        return buffer.ToArray();
    }
}
