using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// The TF boot-chain authority half of one internal install preparation: it re-uses the existing private
/// backup binding, source-slot, GBL-input and AVB gates to capture one sealed source authority for the later
/// sealed TF planner. Nothing here writes a device, claims readiness or builds a package; the captured object
/// owns only its own held leases, its own inactive-slot proofs and its own evidence child directory.
/// </summary>
internal sealed partial class InternalInstallPreparationContext
{
    /// <summary>
    /// The material keys the slot reader reports, paired with the capture role each must equal in the verified
    /// backup. The pairing is fixed here so no caller can compare a hash or length to the wrong capture.
    /// </summary>
    private static readonly (string MaterialKey, string CaptureRole)[] TfMaterialClaimPairs =
    {
        ("current_boot", "boot"),
        ("vendor_boot", "vendor_boot"),
        ("init_boot", "init_boot"),
        ("abl", "abl"),
        ("xbl_config", "xbl_config"),
    };

    /// <summary>
    /// Captures one sealed TF boot authority from one verified internal-install backup. The existing private
    /// gates stay the only authorities: the backup binding authenticates the manifest, identity, profile, six
    /// GPTs and every actual capture; the strict five-zero rule decides the source map; the existing GBL gate
    /// decides GBL mode or keeps the exact AOSP signed-root and metadata preparation. A non-null result owns
    /// only the newly opened held claims, the newly opened inactive proofs and its own evidence child; the
    /// caller's backup and tools are never touched. Any failure releases every opened resource before the
    /// original gate failure is rethrown. This is a source authority plus real metadata candidates only —
    /// never a device writer, an internal package or a Ready claim.
    /// </summary>
    internal static Task<TfBootAuthority> PrepareTfBootAuthorityAsync(
        InternalBackupSet backup,
        string currentSlot,
        BootloaderState lockState,
        string chosenParent,
        CancellationToken ct = default)
    {
        return TfBootAuthority.CreateAsync(backup, currentSlot, lockState, chosenParent, ct);
    }

    /// <summary>
    /// Captures one sealed TF boot authority where an already fully verified same-epoch initialized-B proof
    /// replaces the strict five-zero inactive-target run for the B project template. The caller transfers the
    /// proof's ownership only on successful authority creation; on any failure the caller still owns and
    /// disposes it. This is not a cross-epoch witness: the proof's exact eleven claims must equal this source
    /// backup's verified captures, and every existing lock/GBL/AVB gate still runs unchanged.
    /// </summary>
    internal static Task<TfBootAuthority> PrepareTfBootAuthorityAsync(
        InternalBackupSet backup,
        string currentSlot,
        BootloaderState lockState,
        string chosenParent,
        CurrentBootInitializedInactiveProof initializedInactiveProof,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(initializedInactiveProof);
        return TfBootAuthority.CreateAsync(
            backup, currentSlot, lockState, chosenParent, ct, initializedInactiveProof);
    }

    /// <summary>
    /// Captures one sealed TF boot authority where a fully verified cross-OTA after-epoch witness replaces
    /// the strict five-zero inactive-target run for the B project template. The witness is a distinct type
    /// from the same-epoch initialized-B proof: its current-A material is fresh, not the old template base,
    /// so its eleven claims are compared to this backup's verified captures only as current bytes, and its
    /// current backup manifest SHA must equal this backup's manifest SHA. The caller transfers the witness's
    /// ownership only on successful authority creation; on any failure the caller still owns and disposes
    /// it. Every existing lock/GBL/AVB gate still runs unchanged; no TF or U same-epoch path accepts this
    /// witness.
    /// </summary>
    internal static Task<TfBootAuthority> PrepareAfterBootAuthorityAsync(
        InternalBackupSet backup,
        string currentSlot,
        BootloaderState lockState,
        string chosenParent,
        CurrentBootAfterEpochWitness witness,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(witness);
        return TfBootAuthority.CreateAsync(
            backup,
            currentSlot,
            lockState,
            chosenParent,
            ct,
            initializedInactiveProof: null,
            afterEpochWitness: witness);
    }

    /// <summary>
    /// Creates the unique owned evidence child under the caller-chosen parent. The parent must already exist
    /// and stays normalized; the child is created fresh, is verified to stay inside the parent and never
    /// replaces an existing path. There is no local or temp fallback.
    /// </summary>
    private static string CreateTfBootAuthorityChild(string chosenParent, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(chosenParent))
        {
            throw new ArgumentException(
                "An existing parent directory for the TF boot authority is required.", nameof(chosenParent));
        }

        ct.ThrowIfCancellationRequested();

        string parent = Path.GetFullPath(chosenParent);
        if (!Directory.Exists(parent))
        {
            throw new DirectoryNotFoundException(
                "The TF boot authority parent directory is missing: " + parent + ".");
        }

        RequireNonReparseDirectory(parent, "the TF boot authority parent directory");

        string child = Path.Combine(parent, "tf-boot-authority-" + Guid.NewGuid().ToString("N"));
        string fullChild = Path.GetFullPath(child);
        string rootPrefix = Path.EndsInDirectorySeparator(parent)
            ? parent
            : parent + Path.DirectorySeparatorChar;
        if (!fullChild.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "tf-boot-authority-parent-escape: the authority child does not stay inside its parent directory.");
        }

        if (Directory.Exists(fullChild) || File.Exists(fullChild))
        {
            throw new InvalidOperationException(
                "tf-boot-authority-child-collision: the unique authority child already exists.");
        }

        Directory.CreateDirectory(fullChild);
        return fullChild;
    }

    /// <summary>
    /// Re-proves the GBL common loader window exactly as the existing GBL completion does: the selected
    /// source's real ABL bytes and the current slot's real XBL bytes are taken from the held claims, each is
    /// re-hashed against its verified source, and the existing recognizer must succeed. The unmeasured
    /// fallback is never accepted and the recognizer's exact evidence is returned for the authority to hold.
    /// </summary>
    private static string RequireTfGblCommonLoaderEvidence(
        GblPreparationInputs inputs,
        BackupFacts backup,
        List<HeldClaim> claims,
        CancellationToken ct)
    {
        string selected = inputs.RuntimeSelectedSourceSlot;
        if (!inputs.Sources.TryGetValue(selected, out GblSourceEvidence? selectedSource)
            || selectedSource is null)
        {
            throw new InvalidDataException(
                "gbl-source-material-mismatch: no verified source evidence for runtime source slot '"
                + selected + "'.");
        }

        string selectedAblRole = "abl_" + selected;
        byte[] selectedAblRaw = ReadGblHeldBytes(selectedAblRole, selectedSource.Abl, claims, ct);
        if (!SameSha(GblSha256Hex(selectedAblRaw), selectedSource.Abl.Sha256))
        {
            throw new InvalidDataException(
                "gbl-abl-bytes-mismatch: '" + selectedAblRole + "' does not match the verified source.");
        }

        string currentXblRole = "xbl_config_" + inputs.CurrentSlot;
        VerifiedEdlFile currentXbl = Claim(backup.Files, currentXblRole);
        byte[] currentXblRaw = ReadGblHeldBytes(currentXblRole, currentXbl, claims, ct);
        if (!SameSha(GblSha256Hex(currentXblRaw), currentXbl.Sha256))
        {
            throw new InvalidDataException(
                "gbl-abl-bytes-mismatch: '" + currentXblRole + "' does not match the verified source.");
        }

        if (!InternalSlotLoaderStructure.TryRecognize(
                selectedAblRaw, currentXblRaw, ct, out string commonEvidence))
        {
            throw new InvalidOperationException(
                "requires-compatible-bootloader: the selected ABL and the current XBL share no proven common loader window"
                + " under the recognized 256 MiB profile; the 128 MiB fallback is not measured.");
        }

        return commonEvidence;
    }

    /// <summary>
    /// Releases exactly the resources this preparation opened: every held claim stream, every inactive-slot
    /// proof and the generated own child directory. A single close failure never skips the remaining closes,
    /// and a cleanup that does not fully succeed is reported, never silently represented as success. No
    /// caller path, shared cache or other directory is ever deleted.
    /// </summary>
    private static void ReleaseTfBootAuthorityResources(
        List<HeldClaim> claims,
        IReadOnlyDictionary<string, EdlRawInactiveSlotBackup> inactiveTargets,
        string? ownChild)
    {
        List<Exception>? errors = null;

        foreach (HeldClaim claim in claims)
        {
            try
            {
                claim.Stream.Dispose();
            }
            catch (Exception error)
            {
                (errors ??= new List<Exception>()).Add(error);
            }
        }

        claims.Clear();

        foreach (EdlRawInactiveSlotBackup proof in inactiveTargets.Values)
        {
            try
            {
                proof.Dispose();
            }
            catch (Exception error)
            {
                (errors ??= new List<Exception>()).Add(error);
            }
        }

        if (ownChild is not null)
        {
            try
            {
                if (Directory.Exists(ownChild))
                {
                    Directory.Delete(ownChild, true);
                }
            }
            catch (Exception error)
            {
                (errors ??= new List<Exception>()).Add(error);
            }
        }

        if (errors is not null)
        {
            throw new AggregateException(
                "tf-boot-authority-cleanup-incomplete: owned leases or the own evidence child did not fully release.",
                errors);
        }
    }

    /// <summary>
    /// One sealed TF boot-chain authority: the authenticated backup facts, the actual source map, the held
    /// inactive-slot proofs and either the real GBL EFI claims with the proven common loader window or the
    /// real AOSP metadata nodes. It is never a device writer, an internal package or a Ready claim, and its
    /// private gate inputs stay private: construction happens only through <see cref="Capture"/> so no caller
    /// can supply a validity flag. The instance owns only its own leases, proofs and evidence child.
    /// </summary>
    internal sealed class TfBootAuthority : IDisposable
    {
        private readonly string _directoryPath;
        private readonly string _model;
        private readonly string _profileId;
        private readonly string _currentSlot;
        private readonly string _backupManifestSha256;
        private readonly BootloaderState _lockState;
        private readonly IReadOnlyDictionary<string, EdlCapturedRegion> _files;
        private readonly IReadOnlyDictionary<string, string> _sourceSlots;
        private readonly IReadOnlyDictionary<string, EdlRawInactiveSlotBackup> _inactiveTargets;
        private readonly IReadOnlyList<DirectAvbMetadataNode> _avbNodes;
        private readonly GblPreparationInputs? _gblInputs;
        private readonly string? _commonLoaderEvidence;
        private readonly CurrentBootInitializedInactiveProof? _initializedInactiveProof;
        private readonly CurrentBootAfterEpochWitness? _afterEpochWitness;
        private readonly string _ownChild;
        private readonly List<HeldClaim> _claims;
        private int _disposed;

        private TfBootAuthority(
            string directoryPath,
            string model,
            string profileId,
            string currentSlot,
            string backupManifestSha256,
            BootloaderState lockState,
            IReadOnlyDictionary<string, EdlCapturedRegion> files,
            IReadOnlyDictionary<string, string> sourceSlots,
            IReadOnlyDictionary<string, EdlRawInactiveSlotBackup> inactiveTargets,
            IReadOnlyList<DirectAvbMetadataNode> avbNodes,
            GblPreparationInputs? gblInputs,
            string? commonLoaderEvidence,
            CurrentBootInitializedInactiveProof? initializedInactiveProof,
            string ownChild,
            List<HeldClaim> claims,
            CurrentBootAfterEpochWitness? afterEpochWitness = null)
        {
            _directoryPath = directoryPath;
            _model = model;
            _profileId = profileId;
            _currentSlot = currentSlot;
            _backupManifestSha256 = backupManifestSha256;
            _lockState = lockState;
            _files = files;
            _sourceSlots = sourceSlots;
            _inactiveTargets = inactiveTargets;
            _avbNodes = avbNodes;
            _gblInputs = gblInputs;
            _commonLoaderEvidence = commonLoaderEvidence;
            _initializedInactiveProof = initializedInactiveProof;
            _afterEpochWitness = afterEpochWitness;
            _ownChild = ownChild;
            _claims = claims;
        }

        /// <summary>
        /// The moved outer gate body: the only construction path, running every existing guard, gate,
        /// order, resource transfer and failure cleanup exactly as before. Only accessible public input
        /// types appear in the signature, so no private gate type leaks through the internal API.
        /// </summary>
        internal static async Task<TfBootAuthority> CreateAsync(
            InternalBackupSet backup,
            string currentSlot,
            BootloaderState lockState,
            string chosenParent,
            CancellationToken ct,
            CurrentBootInitializedInactiveProof? initializedInactiveProof = null,
            CurrentBootAfterEpochWitness? afterEpochWitness = null)
        {
            ArgumentNullException.ThrowIfNull(backup);
            ArgumentNullException.ThrowIfNull(currentSlot);

            if (initializedInactiveProof is not null && afterEpochWitness is not null)
            {
                throw new InvalidOperationException(
                    "tf-boot-authority-witness-exclusive: the same-epoch initialized-B proof and the "
                    + "after-epoch witness are mutually exclusive; only one may be supplied.");
            }

            if (currentSlot is not ("a" or "b"))
            {
                throw new InvalidOperationException(
                    "unsupported-current-slot: the TF boot authority supports exactly the observed slot a or "
                    + "slot b, not '" + currentSlot + "'.");
            }

            if (lockState is not (BootloaderState.Unknown or BootloaderState.Locked or BootloaderState.Unlocked))
            {
                throw new InvalidOperationException(
                    "requires-compatible-bootloader: the TF boot authority accepts only the defined lock facts "
                    + "Unknown, Locked or Unlocked; an undefined BootloaderState value is refused.");
            }

            ct.ThrowIfCancellationRequested();

            List<HeldClaim> claims = new();
            Dictionary<string, EdlRawInactiveSlotBackup> inactiveTargets = new(StringComparer.Ordinal);
            string? ownChild = null;

            try
            {
                // Own only this new child under the caller-chosen existing parent; no local or temp fallback.
                ownChild = CreateTfBootAuthorityChild(chosenParent, ct);

                // The existing binding stays the only manifest, identity, profile, GPT and capture authority;
                // no manifest is re-parsed here. Every opened lease lands in the local claims list.
                BackupFacts facts = BindBackup(backup, claims, ct);

                // The observed boot-control slot must agree with the requested slot. The virtual A/B merge
                // policy is a separate shared gate owned elsewhere and is deliberately not inferred from the
                // merge bits here; the later sealed TF planner requires that separate gate.
                BootSlotControlFacts slotControl = await BootSlotControl
                    .ReadAsync(Claim(facts.Files, "misc"), ct)
                    .ConfigureAwait(false);
                if (!string.Equals(slotControl.CurrentSlot, currentSlot, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        "tf-boot-authority-slot-mismatch: the verified misc capture reports slot '"
                        + slotControl.CurrentSlot + "', not the requested slot '" + currentSlot + "'.");
                }

                // The one strict five-zero inactive proof per valid target and the actual source map. Every
                // proof lease is kept until the authority is disposed; ABL, system B or the source map are
                // never copied or relabelled across slots. With a non-null initialized-B proof the strict
                // helper is not run: the proof itself must bind exactly to this backup before the source map
                // is accepted, and inactiveTargets stays empty — no Android-B backup is fabricated.
                Dictionary<string, string> sourceSlots;
                if (afterEpochWitness is not null)
                {
                    sourceSlots = await BindAfterEpochWitnessAsync(
                        afterEpochWitness,
                        facts,
                        currentSlot,
                        ct).ConfigureAwait(false);
                }
                else if (initializedInactiveProof is not null)
                {
                    sourceSlots = await BindInitializedInactiveProofAsync(
                        initializedInactiveProof,
                        facts,
                        currentSlot,
                        ct).ConfigureAwait(false);
                }
                else
                {
                    sourceSlots = await DetermineDirectSourceSlotsAsync(
                        facts.ProfileId,
                        currentSlot,
                        facts.Files,
                        inactiveTargets,
                        ct).ConfigureAwait(false);
                }

                // The existing GBL gate decides GBL mode: a non-null result already proves the parent original
                // RSA chain, the actual ABL EfispLoad detector, the vendor PRC/ROW consensus, the exact embedded
                // EFI asset and the real captured EFI target. A null result is the AOSP path and keeps its exact
                // signed-root and metadata preparation below. No guessed allowlist and no unconditional fallback.
                GblPreparationInputs? gblInputs = await PrepareDirectGblInputsAsync(
                    currentSlot,
                    lockState,
                    sourceSlots,
                    facts,
                    ownChild,
                    claims,
                    ct).ConfigureAwait(false);

                IReadOnlyList<DirectAvbMetadataNode> avbNodes;
                string? commonLoaderEvidence = null;

                if (gblInputs is null)
                {
                    // AOSP mode: the same facts, claims and eligibility produce the signed vbmeta roots and the
                    // three metadata nodes per self-sourced target, preserving original locked/unlocked
                    // eligibility, metadata roles and empty-B exclusions. AOSP requires a current known lock
                    // fact, so an Unknown input never reaches this candidate preparation.
                    if (lockState is not (BootloaderState.Locked or BootloaderState.Unlocked))
                    {
                        throw new InvalidOperationException(
                            "requires-current-bootloader-state: the AOSP path requires a current known lock fact "
                            + "(Locked or Unlocked); an Unknown lock state cannot prove AOSP eligibility.");
                    }

                    IReadOnlyDictionary<string, EdlRawResignedAvbNode> avbRoots = await PrepareDirectAvbRootsAsync(
                        currentSlot,
                        lockState,
                        sourceSlots,
                        facts.Files,
                        ownChild,
                        claims,
                        ct).ConfigureAwait(false);

                    avbNodes = await PrepareDirectAvbNodesAsync(
                        avbRoots,
                        sourceSlots,
                        facts.Files,
                        ownChild,
                        claims,
                        ct).ConfigureAwait(false);
                }
                else
                {
                    // GBL mode produces no AOSP metadata candidate at all and re-proves the exact common
                    // selected-ABL / current-XBL window with the existing recognizer; the unmeasured 128 MiB
                    // fallback is never accepted. Only the real GBL EFI claims are exposed afterwards.
                    avbNodes = Array.Empty<DirectAvbMetadataNode>();
                    commonLoaderEvidence = RequireTfGblCommonLoaderEvidence(gblInputs, facts, claims, ct);
                }

                TfBootAuthority authority = TfBootAuthority.Capture(
                    facts,
                    currentSlot,
                    lockState,
                    sourceSlots,
                    inactiveTargets,
                    avbNodes,
                    gblInputs,
                    commonLoaderEvidence,
                    initializedInactiveProof: initializedInactiveProof,
                    ownChild: ownChild,
                    claims: claims,
                    afterEpochWitness: afterEpochWitness);

                return authority;
            }
            catch (Exception failure)
            {
                try
                {
                    // Release every opened held stream, inactive proof and the generated own child; the caller's
                    // backup stays untouched. The original gate failure stays the reported cause.
                    ReleaseTfBootAuthorityResources(claims, inactiveTargets, ownChild);
                }
                catch (Exception cleanup)
                {
                    throw new AggregateException(failure.Message, failure, cleanup);
                }

                throw;
            }
        }

        /// <summary>
        /// The exact claim keys an initialized-B proof must carry, and no others: both slots' five boot-chain
        /// materials plus the A-slot vbmeta. Any extra or missing key rejects the proof outright.
        /// </summary>
        private static readonly string[] TfInitializedInactiveProofClaimKeys =
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

        /// <summary>
        /// Binds one already fully verified same-epoch initialized-B proof to this exact backup before the
        /// proof may replace the strict five-zero run. The current slot must be A and the proof must report
        /// source A, target B and the same profile; the proof must be live and revalidate live against its
        /// own files. Every one of its eleven claims must equal this backup's verified capture by full
        /// normalized path, length and SHA-256, and the proof's own source/target boot files must equal the
        /// backup's boot_a/boot_b claims by the same comparison. The source map is A sourcing itself; no
        /// inactive target is fabricated and no Android-B backup is pretended.
        /// </summary>
        private static async Task<Dictionary<string, string>> BindInitializedInactiveProofAsync(
            CurrentBootInitializedInactiveProof proof,
            BackupFacts facts,
            string currentSlot,
            CancellationToken ct)
        {
            if (!string.Equals(currentSlot, "a", StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "tf-boot-authority-initialized-proof-slot-mismatch: the initialized-B proof applies only "
                    + "to current slot a, not '" + currentSlot + "'.");
            }

            if (!string.Equals(proof.SourceSlot, "a", StringComparison.Ordinal)
                || !string.Equals(proof.TargetSlot, "b", StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "tf-boot-authority-initialized-proof-slot-mismatch: the initialized-B proof reports source '"
                    + proof.SourceSlot + "' and target '" + proof.TargetSlot + "', not source a and target b.");
            }

            if (!string.Equals(proof.ProfileId, facts.ProfileId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "tf-boot-authority-initialized-proof-profile-mismatch: the initialized-B proof binds profile '"
                    + proof.ProfileId + "', not this backup's profile '" + facts.ProfileId + "'.");
            }

            proof.RequireUsable();
            await proof.RevalidateAsync(ct).ConfigureAwait(false);

            if (proof.Claims.Count != TfInitializedInactiveProofClaimKeys.Length)
            {
                throw new InvalidDataException(
                    "tf-boot-authority-initialized-proof-claims-mismatch: the initialized-B proof carries "
                    + proof.Claims.Count + " claims, not exactly "
                    + TfInitializedInactiveProofClaimKeys.Length + ".");
            }

            foreach (string key in TfInitializedInactiveProofClaimKeys)
            {
                if (!proof.Claims.TryGetValue(key, out VerifiedEdlFile? claim) || claim is null)
                {
                    throw new InvalidDataException(
                        "tf-boot-authority-initialized-proof-claims-mismatch: the initialized-B proof is missing "
                        + "the claim '" + key + "'.");
                }

                VerifiedEdlFile backupClaim = Claim(facts.Files, key);
                RequireTfVerifiedEdlFileEquality(claim, backupClaim, "initialized-B proof claim '" + key + "'");
            }

            RequireTfVerifiedEdlFileEquality(
                proof.SourceBoot, Claim(facts.Files, "boot_a"), "initialized-B proof source boot");
            RequireTfVerifiedEdlFileEquality(
                proof.TargetBoot, Claim(facts.Files, "boot_b"), "initialized-B proof target boot");

            return new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["a"] = "a",
                ["b"] = "a",
            };
        }

        /// <summary>
        /// Binds one already fully verified cross-OTA after-epoch witness to this exact backup before the
        /// witness may replace the strict five-zero run. The witness is deliberately a distinct type from
        /// the same-epoch initialized-B proof: its current-A material is fresh, so its claims are compared
        /// to this backup's verified captures only as current bytes — the old template base is never
        /// compared with the current A. The current slot must be A with source a and target b, the witness
        /// profile must match, IsSameEpoch must be false, the witness's current backup manifest SHA must
        /// equal this backup's manifest SHA, and the witness must be live and revalidate live against its
        /// own files. Every one of the exact eleven keys must be present with no extras, and each fresh
        /// claim must equal this backup's verified capture by full normalized path, length and SHA-256.
        /// The source map is a sourcing itself (a to a, b to a); no inactive target is fabricated and no
        /// Android-B validity is pretended.
        /// </summary>
        private static async Task<Dictionary<string, string>> BindAfterEpochWitnessAsync(
            CurrentBootAfterEpochWitness witness,
            BackupFacts facts,
            string currentSlot,
            CancellationToken ct)
        {
            if (!string.Equals(currentSlot, "a", StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "tf-boot-authority-after-epoch-witness-slot-mismatch: the after-epoch witness applies "
                    + "only to current slot a, not '" + currentSlot + "'.");
            }

            if (!string.Equals(witness.SourceSlot, "a", StringComparison.Ordinal)
                || !string.Equals(witness.TargetSlot, "b", StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "tf-boot-authority-after-epoch-witness-slot-mismatch: the after-epoch witness reports "
                    + "source '" + witness.SourceSlot + "' and target '" + witness.TargetSlot
                    + "', not source a and target b.");
            }

            if (!string.Equals(witness.ProfileId, facts.ProfileId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "tf-boot-authority-after-epoch-witness-profile-mismatch: the after-epoch witness binds "
                    + "profile '" + witness.ProfileId + "', not this backup's profile '"
                    + facts.ProfileId + "'.");
            }

            if (witness.IsSameEpoch)
            {
                throw new InvalidOperationException(
                    "tf-boot-authority-after-epoch-witness-epoch-mismatch: the after-epoch witness reports "
                    + "IsSameEpoch true; this authority accepts only a genuinely cross-epoch witness.");
            }

            if (!string.Equals(
                    witness.CurrentBackupManifestSha256,
                    facts.ManifestSha256,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "tf-boot-authority-after-epoch-witness-manifest-mismatch: the after-epoch witness binds "
                    + "current backup manifest '" + witness.CurrentBackupManifestSha256
                    + "', not this backup's manifest '" + facts.ManifestSha256 + "'.");
            }

            witness.RequireUsable();
            await witness.RevalidateAsync(ct).ConfigureAwait(false);

            if (witness.Claims.Count != TfInitializedInactiveProofClaimKeys.Length)
            {
                throw new InvalidDataException(
                    "tf-boot-authority-after-epoch-witness-claims-mismatch: the after-epoch witness carries "
                    + witness.Claims.Count + " claims, not exactly "
                    + TfInitializedInactiveProofClaimKeys.Length + ".");
            }

            foreach (string key in TfInitializedInactiveProofClaimKeys)
            {
                if (!witness.Claims.TryGetValue(key, out VerifiedEdlFile? claim) || claim is null)
                {
                    throw new InvalidDataException(
                        "tf-boot-authority-after-epoch-witness-claims-mismatch: the after-epoch witness is "
                        + "missing the fresh claim '" + key + "'.");
                }

                VerifiedEdlFile backupClaim = Claim(facts.Files, key);
                RequireTfVerifiedEdlFileEquality(claim, backupClaim, "after-epoch witness claim '" + key + "'");
            }

            return new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["a"] = "a",
                ["b"] = "a",
            };
        }

        /// <summary>
        /// Requires two verified files to be the same actual file: full normalized exact path, length and
        /// SHA-256 (the hash compared OrdinalIgnoreCase). No filename-only or SHA-only equivalence and no
        /// stale backup substitution is accepted.
        /// </summary>
        private static void RequireTfVerifiedEdlFileEquality(
            VerifiedEdlFile actual,
            VerifiedEdlFile expected,
            string subject)
        {
            string actualPath = Path.GetFullPath(actual.Path);
            string expectedPath = Path.GetFullPath(expected.Path);
            if (!string.Equals(actualPath, expectedPath, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "tf-boot-authority-initialized-proof-claims-mismatch: " + subject
                    + " path '" + actualPath + "' does not equal the verified backup path '" + expectedPath + "'.");
            }

            if (actual.Length != expected.Length)
            {
                throw new InvalidDataException(
                    "tf-boot-authority-initialized-proof-claims-mismatch: " + subject
                    + " length " + actual.Length + " does not equal the verified backup length "
                    + expected.Length + ".");
            }

            if (!SameSha(actual.Sha256, expected.Sha256))
            {
                throw new InvalidDataException(
                    "tf-boot-authority-initialized-proof-claims-mismatch: " + subject
                    + " does not hash to the verified backup SHA-256.");
            }
        }

        /// <summary>
        /// The only construction path: the moved CreateAsync calls this after every gate has already passed, so
        /// no validity flag exists and the private gate inputs never appear in a signature. Maps and lists
        /// are defensively copied; the held-claim list transfers to the authority.
        /// </summary>
        private static TfBootAuthority Capture(
            BackupFacts facts,
            string currentSlot,
            BootloaderState lockState,
            IReadOnlyDictionary<string, string> sourceSlots,
            Dictionary<string, EdlRawInactiveSlotBackup> inactiveTargets,
            IReadOnlyList<DirectAvbMetadataNode> avbNodes,
            GblPreparationInputs? gblInputs,
            string? commonLoaderEvidence,
            CurrentBootInitializedInactiveProof? initializedInactiveProof,
            string ownChild,
            List<HeldClaim> claims,
            CurrentBootAfterEpochWitness? afterEpochWitness = null)
        {
            return new TfBootAuthority(
                facts.Directory,
                facts.Model,
                facts.ProfileId,
                currentSlot,
                facts.ManifestSha256,
                lockState,
                new ReadOnlyDictionary<string, EdlCapturedRegion>(
                    new Dictionary<string, EdlCapturedRegion>(facts.Files, StringComparer.Ordinal)),
                new ReadOnlyDictionary<string, string>(
                    new Dictionary<string, string>(sourceSlots, StringComparer.Ordinal)),
                new ReadOnlyDictionary<string, EdlRawInactiveSlotBackup>(
                    new Dictionary<string, EdlRawInactiveSlotBackup>(inactiveTargets, StringComparer.Ordinal)),
                new ReadOnlyCollection<DirectAvbMetadataNode>(new List<DirectAvbMetadataNode>(avbNodes)),
                gblInputs,
                commonLoaderEvidence,
                initializedInactiveProof,
                ownChild,
                claims,
                afterEpochWitness: afterEpochWitness);
        }

        /// <summary>The normalized backup directory the authority was captured from.</summary>
        internal string DirectoryPath => _directoryPath;

        /// <summary>The device model the verified backup binds.</summary>
        internal string Model => _model;

        /// <summary>The profile id the verified backup binds.</summary>
        internal string ProfileId => _profileId;

        /// <summary>The requested slot letter, exactly <c>a</c> or <c>b</c>, agreed by the verified misc capture.</summary>
        internal string CurrentSlot => _currentSlot;

        /// <summary>The SHA-256 the verified backup manifest actually hashed to at capture time.</summary>
        internal string BackupManifestSha256 => _backupManifestSha256;

        /// <summary>The confirmed bootloader lock fact the authority was captured under.</summary>
        internal BootloaderState LockState => _lockState;

        /// <summary>The verified capture regions, defensively copied; never a mutable source map.</summary>
        internal IReadOnlyDictionary<string, EdlCapturedRegion> Files => _files;

        /// <summary>The actual target-to-source slot map. A target whose source is the opposite slot is a factory-empty system; its Android system validity is never claimed.</summary>
        internal IReadOnlyDictionary<string, string> SourceSlots => _sourceSlots;

        /// <summary>The held strict five-zero inactive-slot proofs, keyed by target slot.</summary>
        internal IReadOnlyDictionary<string, EdlRawInactiveSlotBackup> InactiveTargets => _inactiveTargets;

        /// <summary>The real AOSP metadata nodes, or empty in GBL mode; AOSP candidates are never mixed into GBL mode.</summary>
        internal IReadOnlyList<DirectAvbMetadataNode> AvbNodes => _avbNodes;

        /// <summary>Whether the existing GBL gate proved this source a real GBL source.</summary>
        internal bool UsesGbl => _gblInputs is not null;

        /// <summary>The real captured EFI target region in GBL mode, otherwise null.</summary>
        internal EdlCapturedRegion? EfispTarget => _gblInputs?.EfispTarget;

        /// <summary>The verified EFI candidate file in GBL mode, otherwise null.</summary>
        internal VerifiedEdlFile? EfispCandidate => _gblInputs?.EfispCandidate;

        /// <summary>The verified embedded EFI runtime asset in GBL mode, otherwise null.</summary>
        internal VerifiedEdlFile? RuntimeAsset => _gblInputs?.RuntimeAsset;

        /// <summary>The runtime-selected source slot in GBL mode, otherwise null.</summary>
        internal string? RuntimeSelectedSourceSlot => _gblInputs?.RuntimeSelectedSourceSlot;

        /// <summary>The exact common-loader-window evidence the existing recognizer produced in GBL mode, otherwise null.</summary>
        internal string? CommonLoaderEvidence => _commonLoaderEvidence;

        /// <summary>
        /// The owned same-epoch initialized-B proof this authority was captured with, or null on the ordinary
        /// strict five-zero route. The successful authority owns this proof; its input files are never deleted.
        /// </summary>
        internal CurrentBootInitializedInactiveProof? InitializedInactiveProof => _initializedInactiveProof;

        /// <summary>
        /// The owned cross-OTA after-epoch witness this authority was captured with, or null on every
        /// ordinary, strict five-zero, TF/U same-epoch and initialized-proof route. The successful authority
        /// owns this witness; its input files are never deleted.
        /// </summary>
        internal CurrentBootAfterEpochWitness? AfterEpochWitness => _afterEpochWitness;

        private bool IsDisposed => _disposed != 0;

        /// <summary>
        /// Rechecks every held stream: the current length must still equal the captured length and the full
        /// re-hash must still equal the captured SHA-256; the five actual target captures are among these
        /// held claims. Each held inactive proof is checked for its disposed guard only — that guard is not
        /// restated as a full re-read. No device command is issued.
        /// </summary>
        internal async Task RevalidateAsync(CancellationToken ct = default)
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);
            ct.ThrowIfCancellationRequested();

            foreach (HeldClaim claim in _claims)
            {
                ct.ThrowIfCancellationRequested();

                FileStream stream = claim.Stream;
                if (stream.Length != claim.Length)
                {
                    throw new InvalidDataException(
                        "tf-boot-authority-claim-changed: '" + claim.Subject
                        + "' changed length after the authority was captured.");
                }

                if (!SameSha(HashHeld(stream, ct), claim.Sha256))
                {
                    throw new InvalidDataException(
                        "tf-boot-authority-claim-changed: '" + claim.Subject
                        + "' no longer hashes to the SHA-256 captured by the authority.");
                }
            }

            foreach (EdlRawInactiveSlotBackup proof in _inactiveTargets.Values)
            {
                ct.ThrowIfCancellationRequested();
                proof.RequireUsable();
            }

            if (_initializedInactiveProof is not null)
            {
                ct.ThrowIfCancellationRequested();
                _initializedInactiveProof.RequireUsable();
                await _initializedInactiveProof.RevalidateAsync(ct).ConfigureAwait(false);
            }

            if (_afterEpochWitness is not null)
            {
                ct.ThrowIfCancellationRequested();
                _afterEpochWitness.RequireUsable();
                await _afterEpochWitness.RevalidateAsync(ct).ConfigureAwait(false);
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }

        /// <summary>
        /// Returns the actual authenticated parent boot-chain public key of one GBL source, for the later
        /// real OEM envelope equality check. It is never an assumed fixed key. Refuses a disposed authority,
        /// a non-GBL authority and an unknown source slot.
        /// </summary>
        internal string RequireGblParentBootKey(string sourceSlot)
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);
            ArgumentNullException.ThrowIfNull(sourceSlot);

            if (_gblInputs is null)
            {
                throw new InvalidOperationException(
                    "tf-boot-authority-not-gbl: this authority is not a GBL authority, so no parent boot chain exists.");
            }

            if (!_gblInputs.Sources.TryGetValue(sourceSlot, out GblSourceEvidence? evidence)
                || evidence is null)
            {
                throw new InvalidDataException(
                    "tf-boot-authority-unknown-source: no authenticated parent boot chain for source '"
                    + sourceSlot + "'.");
            }

            return evidence.ParentBootChain.BootChainPublicKeySha256;
        }

        /// <summary>
        /// Proves and returns the actual allowed raw bytes per unique source slot. The material and raw
        /// length maps must carry exactly the unique source set of the source map; each material must report
        /// its own slot and its five source hashes and lengths must equal the captured boot, vendor_boot,
        /// init_boot, abl and xbl_config claims; actual raw lengths are positive and within the own loader
        /// budget. In GBL mode the existing common-window runtime formula is re-applied against the selected
        /// runtime source material instead of trusting a fallback or a caller budget. This is a byte-bound
        /// proof only — parent-key equality and the full envelope stay with the later shared helpers.
        /// </summary>
        internal IReadOnlyDictionary<string, long> RequireRuntimeRawBounds(
            IReadOnlyDictionary<string, InternalSlotMaterial> materialsBySource,
            IReadOnlyDictionary<string, long> rawLengthsBySource,
            CancellationToken ct = default)
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);
            ArgumentNullException.ThrowIfNull(materialsBySource);
            ArgumentNullException.ThrowIfNull(rawLengthsBySource);
            ct.ThrowIfCancellationRequested();

            HashSet<string> expected = new(_sourceSlots.Values, StringComparer.Ordinal);
            if (!expected.SetEquals(materialsBySource.Keys))
            {
                throw new InvalidDataException(
                    "tf-boot-authority-material-set-mismatch: the material map does not carry exactly the unique "
                    + "source slots of the source map.");
            }

            if (!expected.SetEquals(rawLengthsBySource.Keys))
            {
                throw new InvalidDataException(
                    "tf-boot-authority-raw-length-set-mismatch: the raw-length map does not carry exactly the unique "
                    + "source slots of the source map.");
            }

            InternalSlotMaterial? selectedMaterial = null;
            if (_gblInputs is not null)
            {
                if (!materialsBySource.TryGetValue(
                        _gblInputs.RuntimeSelectedSourceSlot, out selectedMaterial)
                    || selectedMaterial is null)
                {
                    throw new InvalidDataException(
                        "tf-boot-authority-material-set-mismatch: no material for the selected runtime source slot '"
                        + _gblInputs.RuntimeSelectedSourceSlot + "'.");
                }
            }

            Dictionary<string, long> bounds = new(StringComparer.Ordinal);
            foreach (string source in expected)
            {
                ct.ThrowIfCancellationRequested();

                InternalSlotMaterial material = materialsBySource[source];
                if (!string.Equals(material.Slot, source, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "tf-boot-authority-material-slot-mismatch: material for source '" + source
                        + "' reports slot '" + material.Slot + "'.");
                }

                RequireTfMaterialMatchesClaims(material, source, ct);

                long rawLength = rawLengthsBySource[source];
                if (rawLength <= 0)
                {
                    throw new InvalidOperationException(
                        "tf-boot-authority-raw-length-not-positive: source '" + source
                        + "' reports raw length " + rawLength + ".");
                }

                long bound;
                if (_gblInputs is null)
                {
                    bound = material.LoaderBudget.MaxRawBytes;
                    if (bound <= 0)
                    {
                        throw new InvalidOperationException(
                            "requires-compatible-bootloader: no positive loader budget for source '" + source
                            + "' (maxRawBytes=" + bound + ").");
                    }
                }
                else
                {
                    if (!material.LoaderBudget.KnownLoaderMatch
                        || !selectedMaterial!.LoaderBudget.KnownLoaderMatch
                        || material.PageSize != 4096
                        || selectedMaterial.PageSize != 4096
                        || material.LoaderBudget.MaxRawBytes <= 0
                        || selectedMaterial.LoaderBudget.MaxRawBytes <= 0)
                    {
                        throw new InvalidOperationException(
                            "requires-compatible-bootloader: no statically derived 4096-byte-page loader budget for source '"
                            + source + "' (known=" + material.LoaderBudget.KnownLoaderMatch
                            + ", pageSize=" + material.PageSize
                            + ", maxRawBytes=" + material.LoaderBudget.MaxRawBytes + ").");
                    }

                    long ramdiskDelta = Math.Max(
                        0L,
                        checked(AlignGblUp4096(material.TotalRamdiskSize)
                            - AlignGblUp4096(selectedMaterial.TotalRamdiskSize)));
                    bound = Math.Min(
                        material.LoaderBudget.MaxRawBytes,
                        checked(selectedMaterial.LoaderBudget.MaxRawBytes - ramdiskDelta));
                    if (bound <= 0)
                    {
                        throw new InvalidOperationException(
                            "requires-compatible-bootloader: runtime raw bound for source '" + source
                            + "' is not positive (bound=" + bound + ", ramdiskDelta=" + ramdiskDelta + ").");
                    }
                }

                if (rawLength > bound)
                {
                    throw new InvalidOperationException(
                        "requires-compatible-bootloader: raw " + rawLength + " bytes for source '" + source
                        + "' exceeds the statically derived runtime raw bound " + bound + " bytes.");
                }

                bounds.Add(source, bound);
            }

            return new ReadOnlyDictionary<string, long>(bounds);
        }

        /// <summary>
        /// Checks one material's five source hashes and lengths against the captured claims it must equal.
        /// The pairing is fixed and the capture roles keep the actual reader spelling.
        /// </summary>
        private void RequireTfMaterialMatchesClaims(
            InternalSlotMaterial material,
            string source,
            CancellationToken ct)
        {
            foreach ((string materialKey, string captureRole) in TfMaterialClaimPairs)
            {
                ct.ThrowIfCancellationRequested();

                VerifiedEdlFile capture = Claim(_files, captureRole + "_" + source);
                if (!material.SourceSha256.TryGetValue(materialKey, out string? materialSha256)
                    || !SameSha(materialSha256, capture.Sha256))
                {
                    throw new InvalidDataException(
                        "tf-boot-authority-material-hash-mismatch: '" + materialKey + "' for slot '" + source
                        + "' disagrees with the captured '" + captureRole + "'.");
                }

                if (!material.SourceLengths.TryGetValue(materialKey, out long materialLength)
                    || materialLength != capture.Length)
                {
                    throw new InvalidDataException(
                        "tf-boot-authority-material-length-mismatch: '" + materialKey + "' for slot '" + source
                        + "' disagrees with the captured '" + captureRole + "' length.");
                }
            }
        }

        /// <summary>
        /// Releases the owned held streams, then the owned inactive proofs, then the owned initialized-B
        /// proof, then the exact own child directory. Idempotent, and a single close failure never skips the
        /// remaining closes. A cleanup that does not fully succeed is thrown, never silently represented as
        /// success. No caller path, shared cache or proof input file is ever deleted.
        /// </summary>
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            List<Exception>? errors = null;
            try
            {
                ReleaseTfBootAuthorityResources(_claims, _inactiveTargets, ownChild: null);
            }
            catch (Exception error)
            {
                (errors ??= new List<Exception>()).Add(error);
            }

            if (_initializedInactiveProof is not null)
            {
                try
                {
                    _initializedInactiveProof.Dispose();
                }
                catch (Exception error)
                {
                    (errors ??= new List<Exception>()).Add(error);
                }
            }

            if (_afterEpochWitness is not null)
            {
                try
                {
                    _afterEpochWitness.Dispose();
                }
                catch (Exception error)
                {
                    (errors ??= new List<Exception>()).Add(error);
                }
            }

            if (_ownChild is not null)
            {
                try
                {
                    if (Directory.Exists(_ownChild))
                    {
                        Directory.Delete(_ownChild, true);
                    }
                }
                catch (Exception error)
                {
                    (errors ??= new List<Exception>()).Add(error);
                }
            }

            if (errors is not null)
            {
                throw new AggregateException(
                    "tf-boot-authority-cleanup-incomplete: owned leases or the own evidence child did not fully release.",
                    errors);
            }
        }
    }
}
