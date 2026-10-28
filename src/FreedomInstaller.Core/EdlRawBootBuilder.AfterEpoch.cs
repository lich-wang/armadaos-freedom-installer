// real after-update epoch witness. After an OTA, fresh slot A is the
// only current Android material, while initialized inactive B may still carry the
// project base built from the original OEM A. This call reopens the explicitly chosen
// original installation backup, proves with the existing stock and five-zero verifiers
// that the old set is untouched OEM A plus original five-zero B, runs the real
// cryptographic+graph+decode+native unpack proof that fresh B's project base equals the
// OLD A base, and separately measures and exports the FRESH A base. SourceMaterial and
// ReconstructedBase therefore always describe fresh A; TemplateBasisBaseSha256 is the
// historical old base. IsSameEpoch is the constant derived characterization false: this
// witness never claims same-epoch equivalence and no old material becomes current
// Android material. It owns only its own leases, its own proof objects and its own GUID
// child; caller inputs, the chosen parent and any sentinels are never touched.
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// Factual carrier of the after-update epoch proof. It holds the reopened historical
/// backup set, the strict original five-zero proof, the real initialized-inactive
/// native proof, its own verified leases and its own GUID child until
/// <see cref="Dispose"/>, then closes every owned resource and deletes only its own
/// child. Caller inputs and the chosen parent are never disposed or deleted.
/// </summary>
internal sealed class CurrentBootAfterEpochWitness : IDisposable
{
    private readonly InternalBackupSet _oldSet;

    private readonly EdlRawInactiveSlotBackup _oldZeroProof;

    private readonly CurrentBootInitializedInactiveProof _nativeProof;

    private readonly List<FileStream> _heldStreams;

    private readonly List<FileStream> _outputLeases;

    private readonly VerifiedEdlFile _originalManifestClaim;

    private readonly string _parentDirectory;

    private readonly string _ownChild;

    private int _disposed;

    // Factory-only constructor. Every argument is an actual verified object produced by
    // the real proof sequence; no caller bools, readiness flags or fake validity exist.
    internal CurrentBootAfterEpochWitness(
        string profileId,
        InternalSlotMaterial sourceMaterial,
        VerifiedEdlFile reconstructedBase,
        VerifiedEdlFile projectRaw,
        IReadOnlyDictionary<string, VerifiedEdlFile> claims,
        string templateBasisBaseSha256,
        string originalBackupDirectory,
        string originalBackupManifestSha256,
        string currentBackupManifestSha256,
        VerifiedEdlFile verificationReport,
        VerifiedEdlFile originalManifestClaim,
        InternalBackupSet oldSet,
        EdlRawInactiveSlotBackup oldZeroProof,
        CurrentBootInitializedInactiveProof nativeProof,
        List<FileStream> heldStreams,
        List<FileStream> outputLeases,
        string parentDirectory,
        string ownChild)
    {
        ProfileId = profileId;
        SourceMaterial = sourceMaterial;
        ReconstructedBase = reconstructedBase;
        ProjectRaw = projectRaw;
        TemplateBasisBaseSha256 = templateBasisBaseSha256;
        OriginalBackupDirectory = originalBackupDirectory;
        OriginalBackupManifestSha256 = originalBackupManifestSha256;
        CurrentBackupManifestSha256 = currentBackupManifestSha256;
        VerificationReport = verificationReport;
        _originalManifestClaim = originalManifestClaim;
        _oldSet = oldSet;
        _oldZeroProof = oldZeroProof;
        _nativeProof = nativeProof;
        _heldStreams = heldStreams;
        _outputLeases = outputLeases;
        _parentDirectory = parentDirectory;
        _ownChild = ownChild;
        Claims = new ReadOnlyDictionary<string, VerifiedEdlFile>(
            new Dictionary<string, VerifiedEdlFile>(claims, StringComparer.Ordinal));
    }

    /// <summary>The complete profile id the witness was resolved against.</summary>
    public string ProfileId { get; }

    /// <summary>The actual current slot whose fresh material this witness exports: always <c>a</c>.</summary>
    public string SourceSlot => "a";

    /// <summary>The initialized inactive project slot this witness characterizes: always <c>b</c>.</summary>
    public string TargetSlot => "b";

    /// <summary>The actual five-source material measured and exported from FRESH slot A.</summary>
    public InternalSlotMaterial SourceMaterial { get; }

    /// <summary>The FRESH slot A base export inside this witness's own child.</summary>
    public VerifiedEdlFile ReconstructedBase { get; }

    /// <summary>The FRESH slot B project raw decoded by the held native proof.</summary>
    public VerifiedEdlFile ProjectRaw { get; }

    /// <summary>The exact eleven FRESH role-mapped claims this witness binds.</summary>
    public IReadOnlyDictionary<string, VerifiedEdlFile> Claims { get; }

    /// <summary>SHA-256 of the OLD A base proven by the native proof: B's historical template basis.</summary>
    public string TemplateBasisBaseSha256 { get; }

    /// <summary>The actually reopened original backup directory path.</summary>
    public string OriginalBackupDirectory { get; }

    /// <summary>Manifest SHA-256 of the reopened original backup set as verified by its loader.</summary>
    public string OriginalBackupManifestSha256 { get; }

    /// <summary>Manifest SHA-256 captured from the caller's current backup set.</summary>
    public string CurrentBackupManifestSha256 { get; }

    /// <summary>This witness's durable JSON report inside its own child.</summary>
    public VerifiedEdlFile VerificationReport { get; }

    /// <summary>Derived characterization: old template and fresh A are never same-epoch.</summary>
    public bool IsSameEpoch => false;

    /// <summary>True once this witness's owned resources were released and its child deleted.</summary>
    public bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    internal void RequireUsable() => ObjectDisposedException.ThrowIf(IsDisposed, this);

    internal Task RevalidateAsync(CancellationToken ct = default) =>
        EdlRawBootBuilder.AfterEpochRevalidateWitnessAsync(this, ct);

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        EdlRawBootBuilder.AfterEpochDisposeOwnedResources(this);
    }

    // Narrowly scoped accessors so the builder partial can revalidate and release the
    // witness's owned real proof resources. No public authority is exposed.
    internal InternalBackupSet OwnedOldSet => _oldSet;

    internal EdlRawInactiveSlotBackup OwnedOldZeroProof => _oldZeroProof;

    internal CurrentBootInitializedInactiveProof OwnedNativeProof => _nativeProof;

    internal IReadOnlyList<FileStream> OwnedHeldStreams => _heldStreams;

    internal IReadOnlyList<FileStream> OwnedOutputLeases => _outputLeases;

    internal string OwnedParentDirectory => _parentDirectory;

    internal string OwnedChildDirectory => _ownChild;

    internal VerifiedEdlFile OwnedOriginalManifestClaim => _originalManifestClaim;
}

public static partial class EdlRawBootBuilder
{
    private const string AfterEpochChildPrefix = "bm-after-epoch-";

    // The exact eleven FRESH claims: the five current slot-A loaders, the five slot-B
    // loaders and slot A's root vbmeta. No old backup claim is ever output here.
    private static readonly string[] AfterEpochFreshClaimKeys =
    {
        "boot_a",
        "vendor_boot_a",
        "init_boot_a",
        "abl_a",
        "xbl_config_a",
        "boot_b",
        "vendor_boot_b",
        "init_boot_b",
        "abl_b",
        "xbl_config_b",
        "vbmeta_a",
    };

    internal static async Task<CurrentBootAfterEpochWitness> VerifyAfterUpdateInactiveSlotAsync(
        EdlClient client,
        InternalBackupSet currentBackup,
        string actualCurrentSlot,
        string originalBackupDirectory,
        EdlRawBootTools tools,
        ICommandRunner runner,
        string chosenParent,
        CancellationToken ct = default)
    {
        // Guards first: no file IO happens before every argument is checked.
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(currentBackup);
        ArgumentNullException.ThrowIfNull(tools);
        ArgumentNullException.ThrowIfNull(runner);
        if (actualCurrentSlot is not "a")
        {
            throw new ArgumentException(
                "the after-update epoch proof requires the actual current slot 'a'.", nameof(actualCurrentSlot));
        }

        if (string.IsNullOrWhiteSpace(originalBackupDirectory))
        {
            throw new ArgumentException(
                "an original installation backup directory is required.", nameof(originalBackupDirectory));
        }

        if (string.IsNullOrWhiteSpace(chosenParent))
        {
            throw new ArgumentException("a chosen parent directory is required.", nameof(chosenParent));
        }

        ct.ThrowIfCancellationRequested();

        if (!Path.IsPathFullyQualified(chosenParent))
        {
            throw new ArgumentException("chosen parent must be a fully qualified path.", nameof(chosenParent));
        }

        string parentDirectory = Path.GetFullPath(chosenParent);
        if (!Directory.Exists(parentDirectory))
        {
            throw new ArgumentException("chosen parent does not exist.", nameof(parentDirectory));
        }

        string ownChild = Path.Combine(parentDirectory, AfterEpochChildPrefix + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(ownChild);

        List<FileStream> opened = new();
        List<FileStream> ownLeases = new();
        InternalBackupSet? oldSet = null;
        EdlRawInactiveSlotBackup? oldZero = null;
        CurrentBootInitializedInactiveProof? nativeProof = null;
        try
        {
            // Profile identity must agree between toolchain and current backup; the
            // historical loader additionally revalidates binding, hardware, geometry
            // and full source hashes against the current set.
            string profileId = client.Toolchain.ProfileId;
            if (string.IsNullOrWhiteSpace(profileId))
            {
                throw new InvalidDataException("toolchain profile id is missing.");
            }

            if (!string.Equals(profileId, currentBackup.ProfileId, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "current backup profile does not match the toolchain profile.");
            }

            // Hold independently verified read leases over the exact eleven FRESH claims.
            Dictionary<string, VerifiedEdlFile> freshClaims = new(StringComparer.Ordinal);
            foreach (string key in AfterEpochFreshClaimKeys)
            {
                if (!currentBackup.Files.TryGetValue(key, out EdlCapturedRegion? region))
                {
                    throw new InvalidDataException(
                        "current backup is missing the fresh '" + key + "' claim.");
                }

                VerifiedEdlFile claim = AfterEpochClaim(region, key);
                freshClaims[key] = claim;
                ct.ThrowIfCancellationRequested();
                InitBOpenHeldInput(opened, key, claim, ct);
            }

            IReadOnlyDictionary<string, VerifiedEdlFile> claimsView =
                new ReadOnlyDictionary<string, VerifiedEdlFile>(freshClaims);

            // The fresh set's own misc partition must state the device is really on A.
            VerifiedEdlFile freshMisc = AfterEpochRequiredClaim(currentBackup, "misc");
            BootSlotControlFacts freshSlot = await BootSlotControl.ReadAsync(freshMisc, ct);
            if (freshSlot.CurrentSlot is not "a")
            {
                throw new InvalidDataException(
                    "current backup misc does not report the actual current slot a.");
            }

            // Reopen the explicitly selected original installation backup as a read-only
            // historical template source. This loader is not OEM authorization; it only
            // proves same profile, hardware, geometry and full source hashes.
            oldSet = await InternalInstallBackup.OpenBootMaintenanceProjectTemplateAsync(
                client, currentBackup, originalBackupDirectory, ct);

            // The historical set's misc must also report slot a, and its boot/vbmeta must
            // pass the strict stock original proof: untouched OEM A, not a project boot.
            VerifiedEdlFile oldMisc = AfterEpochRequiredClaim(oldSet, "misc");
            BootSlotControlFacts oldSlot = await BootSlotControl.ReadAsync(oldMisc, ct);
            if (oldSlot.CurrentSlot is not "a")
            {
                throw new InvalidDataException("original backup misc does not report slot a.");
            }

            VerifiedEdlFile oldBoot = AfterEpochRequiredClaim(oldSet, "boot_a");
            VerifiedEdlFile oldVbmeta = AfterEpochRequiredClaim(oldSet, "vbmeta_a");
            BootStockOriginalFacts stock = await VerifyStockOriginalBootAsync(oldBoot, oldVbmeta, ct);

            // Strict original five-zero proof over the original set's inactive B.
            oldZero = await EdlRawInactiveSlotBackup.VerifyAsync(
                profileId,
                "a",
                "b",
                AfterEpochRequiredClaim(oldSet, "boot_b"),
                AfterEpochRequiredClaim(oldSet, "vendor_boot_b"),
                AfterEpochRequiredClaim(oldSet, "init_boot_b"),
                AfterEpochRequiredClaim(oldSet, "abl_b"),
                AfterEpochRequiredClaim(oldSet, "xbl_config_b"),
                ct);

            // Real cryptographic+graph+decode+native unpack proof with OLD A as source and
            // FRESH B as the initialized project slot. This proves fresh B's project base
            // equals the OLD A base; no equality to the new A is claimed or checked here.
            nativeProof = await VerifyInitializedInactiveSlotAsync(
                profileId,
                "a",
                "b",
                oldBoot,
                AfterEpochRequiredClaim(oldSet, "vendor_boot_a"),
                AfterEpochRequiredClaim(oldSet, "init_boot_a"),
                AfterEpochRequiredClaim(oldSet, "abl_a"),
                AfterEpochRequiredClaim(oldSet, "xbl_config_a"),
                freshClaims["boot_b"],
                freshClaims["vendor_boot_b"],
                freshClaims["init_boot_b"],
                freshClaims["abl_b"],
                freshClaims["xbl_config_b"],
                oldVbmeta,
                tools,
                runner,
                ownChild,
                ct);

            // Measure and export the FRESH A base separately. SourceMaterial and
            // ReconstructedBase come only from this fresh result, never from history.
            string freshBasePath = Path.Combine(ownChild, "fresh-A-base.bin");
            InternalSlotMaterial freshMaterial = await InternalSlotMaterialReader.AnalyzeAndExportBaseAsync(
                "a",
                freshClaims["boot_a"],
                freshClaims["vendor_boot_a"],
                freshClaims["init_boot_a"],
                freshClaims["abl_a"],
                freshClaims["xbl_config_a"],
                freshBasePath,
                ct);
            VerifiedEdlFile freshBase = new(freshBasePath, freshMaterial.BaseImageLength, freshMaterial.BaseImageSha256);
            InitBOpenOwnLease(ownLeases, freshBase, "fresh A base", ct);

            // Retain the original backup manifest as its own verified claim with a held
            // lease, separate from the eleven role claims.
            string manifestPath = Path.GetFullPath(oldSet.ManifestPath);
            var manifestFile = new FileInfo(manifestPath);
            VerifiedEdlFile originalManifest = new(manifestPath, manifestFile.Length, oldSet.ManifestSha256);
            InitBOpenOwnLease(ownLeases, originalManifest, "original backup manifest", ct);

            // One truthful JSON report of the facts observed above.
            string reportPath = Path.Combine(ownChild, "after-epoch-witness.json");
            byte[] reportBytes = AfterEpochBuildReportBytes(
                profileId,
                oldSet.DirectoryPath,
                oldSet.ManifestSha256,
                currentBackup.ManifestSha256,
                nativeProof.ReconstructedBase.Sha256,
                freshBase,
                nativeProof.VerificationReport,
                nativeProof.ProjectRaw,
                stock,
                claimsView);
            WriteNewFile(reportPath, reportBytes, "after-epoch witness report", ct);
            VerifiedEdlFile report = new(reportPath, new FileInfo(reportPath).Length, HashFileSha256(reportPath, ct));
            InitBOpenOwnLease(ownLeases, report, "after-epoch witness report", ct);

            // Immediate revalidation before the witness is handed out.
            await nativeProof.RevalidateAsync(ct);
            nativeProof.RequireUsable();
            oldZero.RequireUsable();
            List<FileStream> recheck = new();
            try
            {
                foreach (KeyValuePair<string, VerifiedEdlFile> claim in claimsView)
                {
                    ct.ThrowIfCancellationRequested();
                    InitBOpenHeldInput(recheck, claim.Key, claim.Value, ct);
                }

                ct.ThrowIfCancellationRequested();
                InitBOpenHeldInput(recheck, "fresh A base", freshBase, ct);

                ct.ThrowIfCancellationRequested();
                InitBOpenHeldInput(recheck, "after-epoch witness report", report, ct);

                ct.ThrowIfCancellationRequested();
                InitBOpenOwnLease(recheck, originalManifest, "original backup manifest", ct);
            }
            finally
            {
                foreach (FileStream stream in recheck)
                {
                    CloseQuietly(stream);
                }
            }

            ct.ThrowIfCancellationRequested();
            ObjectDisposedException.ThrowIf(nativeProof.IsDisposed, nativeProof);

            return new CurrentBootAfterEpochWitness(
                profileId,
                freshMaterial,
                freshBase,
                nativeProof.ProjectRaw,
                claimsView,
                nativeProof.ReconstructedBase.Sha256,
                oldSet.DirectoryPath,
                oldSet.ManifestSha256,
                currentBackup.ManifestSha256,
                report,
                originalManifest,
                oldSet,
                oldZero,
                nativeProof,
                opened,
                ownLeases,
                parentDirectory,
                ownChild);
        }
        catch
        {
            // A factory failure closes every acquired owned resource and removes only its
            // own GUID child. Cleanup never hides the original verification failure.
            AfterEpochAbandonFactory(opened, ownLeases, oldSet, oldZero, nativeProof, parentDirectory, ownChild);
            throw;
        }
    }

    // Converts one captured region into a verified file claim after shape checks.
    private static VerifiedEdlFile AfterEpochClaim(EdlCapturedRegion region, string role)
    {
        ArgumentNullException.ThrowIfNull(region);
        if (string.IsNullOrWhiteSpace(region.FilePath)
            || region.Length <= 0
            || string.IsNullOrWhiteSpace(region.Sha256))
        {
            throw new InvalidDataException("captured '" + role + "' region is not a usable file claim.");
        }

        return new VerifiedEdlFile(region.FilePath, region.Length, region.Sha256);
    }

    // Looks up one required role in a backup set, rejecting missing keys outright.
    private static VerifiedEdlFile AfterEpochRequiredClaim(InternalBackupSet set, string key)
    {
        ArgumentNullException.ThrowIfNull(set);
        if (!set.Files.TryGetValue(key, out EdlCapturedRegion? region))
        {
            throw new InvalidDataException("backup set is missing the '" + key + "' claim.");
        }

        return AfterEpochClaim(region, key);
    }

    // Serializes the witness report facts; every value is an actually observed result.
    private static byte[] AfterEpochBuildReportBytes(
        string profileId,
        string originalBackupDirectory,
        string originalBackupManifestSha256,
        string currentBackupManifestSha256,
        string templateBasisBaseSha256,
        VerifiedEdlFile freshBase,
        VerifiedEdlFile nativeReport,
        VerifiedEdlFile nativeProjectRaw,
        BootStockOriginalFacts stock,
        IReadOnlyDictionary<string, VerifiedEdlFile> claims)
    {
        ArgumentNullException.ThrowIfNull(freshBase);
        ArgumentNullException.ThrowIfNull(nativeReport);
        ArgumentNullException.ThrowIfNull(nativeProjectRaw);
        ArgumentNullException.ThrowIfNull(stock);
        ArgumentNullException.ThrowIfNull(claims);

        using var target = new MemoryStream();
        using (var writer = new Utf8JsonWriter(target))
        {
            writer.WriteStartObject();
            writer.WriteString("profileId", profileId);
            writer.WriteString("actualCurrentSlot", "a");
            writer.WriteString("targetSlot", "b");
            writer.WriteBoolean("isSameEpoch", false);
            writer.WriteString("originalBackupDirectory", originalBackupDirectory);
            writer.WriteString("originalBackupManifestSha256", originalBackupManifestSha256);
            writer.WriteString("currentBackupManifestSha256", currentBackupManifestSha256);
            writer.WriteString("templateBasisBaseSha256", templateBasisBaseSha256);
            writer.WriteString("freshABaseSha256", freshBase.Sha256);
            writer.WriteString("nativeProofReportSha256", nativeReport.Sha256);
            writer.WriteString("nativeProofProjectRawSha256", nativeProjectRaw.Sha256);
            writer.WriteStartObject("stockOriginalBoot");
            writer.WriteNumber("imageSize", stock.ImageSize);
            writer.WriteString("bootPublicKeySha256", stock.BootPublicKeySha256);
            writer.WriteString("rootPublicKeySha256", stock.RootPublicKeySha256);
            writer.WriteString("digest", stock.Digest);
            writer.WriteNumber("rollbackIndex", stock.RollbackIndex);
            writer.WriteNumber("rollbackIndexLocation", stock.RollbackIndexLocation);
            writer.WriteEndObject();
            writer.WriteStartObject("freshRoleClaims");
            foreach (KeyValuePair<string, VerifiedEdlFile> claim in claims)
            {
                writer.WriteStartObject(claim.Key);
                writer.WriteString("path", claim.Value.Path);
                writer.WriteNumber("length", claim.Value.Length);
                writer.WriteString("sha256", claim.Value.Sha256);
                writer.WriteEndObject();
            }

            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        return target.ToArray();
    }

    // Repeats the exact revalidation facts: reopen and rehash the eleven fresh claims,
    // the fresh A base, the witness report and the original manifest, then confirm the
    // owned proofs are still alive. No parser or native machinery is duplicated here.
    internal static async Task AfterEpochRevalidateWitnessAsync(
        CurrentBootAfterEpochWitness witness,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(witness);
        witness.RequireUsable();
        ct.ThrowIfCancellationRequested();

        witness.OwnedNativeProof.RequireUsable();
        await witness.OwnedNativeProof.RevalidateAsync(ct);
        witness.OwnedNativeProof.RequireUsable();
        witness.OwnedOldZeroProof.RequireUsable();

        List<FileStream> opened = new();
        try
        {
            foreach (KeyValuePair<string, VerifiedEdlFile> claim in witness.Claims)
            {
                ct.ThrowIfCancellationRequested();
                InitBOpenHeldInput(opened, claim.Key, claim.Value, ct);
            }

            ct.ThrowIfCancellationRequested();
            InitBOpenHeldInput(opened, "fresh A base", witness.ReconstructedBase, ct);

            ct.ThrowIfCancellationRequested();
            InitBOpenHeldInput(opened, "after-epoch witness report", witness.VerificationReport, ct);

            // The original old-B five-zero claims and original misc were actual witness
            // antecedents; rebind their exact held claims by whole length and SHA. Their
            // earlier semantic facts (zero scan, slot fact) are not redone here.
            ct.ThrowIfCancellationRequested();
            InitBOpenHeldInput(opened, "original boot_b", witness.OwnedOldZeroProof.CurrentBoot, ct);

            ct.ThrowIfCancellationRequested();
            InitBOpenHeldInput(opened, "original vendor_boot_b", witness.OwnedOldZeroProof.VendorBoot, ct);

            ct.ThrowIfCancellationRequested();
            InitBOpenHeldInput(opened, "original init_boot_b", witness.OwnedOldZeroProof.InitBoot, ct);

            ct.ThrowIfCancellationRequested();
            InitBOpenHeldInput(opened, "original abl_b", witness.OwnedOldZeroProof.Abl, ct);

            ct.ThrowIfCancellationRequested();
            InitBOpenHeldInput(opened, "original xbl_config_b", witness.OwnedOldZeroProof.XblConfig, ct);

            ct.ThrowIfCancellationRequested();
            InitBOpenHeldInput(opened, "original misc", AfterEpochRequiredClaim(witness.OwnedOldSet, "misc"), ct);

            ct.ThrowIfCancellationRequested();
            InitBOpenOwnLease(opened, witness.OwnedOriginalManifestClaim, "original backup manifest", ct);

            ct.ThrowIfCancellationRequested();
            witness.RequireUsable();
        }
        finally
        {
            foreach (FileStream stream in opened)
            {
                CloseQuietly(stream);
            }
        }
    }

    // Releases every owned resource. A single close failure never skips the remaining
    // closes, and only the exact factory-created GUID child is deleted.
    internal static void AfterEpochDisposeOwnedResources(CurrentBootAfterEpochWitness witness)
    {
        ArgumentNullException.ThrowIfNull(witness);

        foreach (FileStream stream in witness.OwnedHeldStreams)
        {
            try
            {
                stream.Dispose();
            }
            catch
            {
                // Every close is attempted even when an earlier one throws.
            }
        }

        foreach (FileStream stream in witness.OwnedOutputLeases)
        {
            try
            {
                stream.Dispose();
            }
            catch
            {
                // Every close is attempted even when an earlier one throws.
            }
        }

        try
        {
            witness.OwnedOldZeroProof.Dispose();
        }
        catch
        {
            // Every owned proof release is attempted.
        }

        try
        {
            witness.OwnedNativeProof.Dispose();
        }
        catch
        {
            // Every owned proof release is attempted.
        }

        try
        {
            witness.OwnedOldSet.Dispose();
        }
        catch
        {
            // Every owned proof release is attempted.
        }

        try
        {
            AfterEpochDeleteOwnChild(witness.OwnedParentDirectory, witness.OwnedChildDirectory);
        }
        catch
        {
            // Child removal failures never mask disposal of the owned resources above.
        }
    }

    // Deletes only a child that matches the normalized parent plus the exact factory
    // prefix and a valid GUID suffix. No broad delete or prune is performed.
    private static void AfterEpochDeleteOwnChild(string parentDirectory, string ownChild)
    {
        if (string.IsNullOrWhiteSpace(parentDirectory) || string.IsNullOrWhiteSpace(ownChild))
        {
            return;
        }

        string parent = Path.TrimEndingDirectorySeparator(Path.GetFullPath(parentDirectory));
        string child = Path.TrimEndingDirectorySeparator(Path.GetFullPath(ownChild));
        string? childParent = Path.GetDirectoryName(child);
        if (string.IsNullOrEmpty(childParent))
        {
            return;
        }

        childParent = Path.TrimEndingDirectorySeparator(childParent);
        if (!string.Equals(childParent, parent, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        string name = Path.GetFileName(child);
        if (!name.StartsWith(AfterEpochChildPrefix, StringComparison.Ordinal))
        {
            return;
        }

        if (!Guid.TryParse(name.Substring(AfterEpochChildPrefix.Length), out _))
        {
            return;
        }

        if (Directory.Exists(child))
        {
            Directory.Delete(child, true);
        }
    }

    // Factory failure path: close everything acquired so far and remove only the own
    // child, swallowing cleanup errors so the original failure propagates unchanged.
    private static void AfterEpochAbandonFactory(
        List<FileStream> opened,
        List<FileStream> ownLeases,
        InternalBackupSet? oldSet,
        EdlRawInactiveSlotBackup? oldZero,
        CurrentBootInitializedInactiveProof? nativeProof,
        string parentDirectory,
        string ownChild)
    {
        foreach (FileStream stream in opened)
        {
            try
            {
                stream.Dispose();
            }
            catch
            {
                // Cleanup must not hide the original verification failure.
            }
        }

        foreach (FileStream stream in ownLeases)
        {
            try
            {
                stream.Dispose();
            }
            catch
            {
                // Cleanup must not hide the original verification failure.
            }
        }

        if (oldZero is not null)
        {
            try
            {
                oldZero.Dispose();
            }
            catch
            {
                // Cleanup must not hide the original verification failure.
            }
        }

        if (nativeProof is not null)
        {
            try
            {
                nativeProof.Dispose();
            }
            catch
            {
                // Cleanup must not hide the original verification failure.
            }
        }

        if (oldSet is not null)
        {
            try
            {
                oldSet.Dispose();
            }
            catch
            {
                // Cleanup must not hide the original verification failure.
            }
        }

        try
        {
            AfterEpochDeleteOwnChild(parentDirectory, ownChild);
        }
        catch
        {
            // Cleanup must not hide the original verification failure.
        }
    }
}
