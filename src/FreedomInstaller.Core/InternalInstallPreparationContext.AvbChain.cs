using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// The early-gate AVB half of one internal install preparation: the source-slot decision that buys the strict
/// inactive-slot proof once, and the signed vbmeta root preparation that never substitutes a candidate fact for
/// an original one. Nothing here writes a device, claims readiness or re-parses an AVB image itself; the one
/// chain parser behind <see cref="EdlRawBootBuilder"/> stays the only authority.
/// </summary>
internal sealed partial class InternalInstallPreparationContext
{
    /// <summary>
    /// The signed vbmeta roots this preparation actually produced, keyed by target slot. It stays empty until a
    /// factory wires the helpers below, so no caller can observe an unproven root.
    /// </summary>
    private readonly IReadOnlyDictionary<string, EdlRawResignedAvbNode> _directAvbRoots =
        new ReadOnlyDictionary<string, EdlRawResignedAvbNode>(
            new Dictionary<string, EdlRawResignedAvbNode>(StringComparer.Ordinal));

    /// <summary>
    /// One actual metadata node of the direct AVB chain: the target slot it belongs to, the fixed role it was
    /// produced for and the signed node this preparation holds.
    /// </summary>
    internal sealed record DirectAvbMetadataNode(
        string Slot,
        string Role,
        EdlRawResignedAvbNode Node);

    /// <summary>
    /// The three chain descriptors the signed vbmeta root must pin to the one signing key this build trusts.
    /// </summary>
    private static readonly string[] DirectAvbChainRoles = { "boot", "recovery", "vbmeta_system" };

    /// <summary>
    /// The fixed metadata order of one self-sourced target: the recovery node, the system vbmeta node and the
    /// pinned root node last. The kind travels with the role, so no caller can pair them differently.
    /// </summary>
    private static readonly (string Role, EdlRawAvbNodeKind Kind)[] DirectAvbMetadataRoles =
    {
        ("recovery", EdlRawAvbNodeKind.Recovery),
        ("vbmeta_system", EdlRawAvbNodeKind.VbmetaSystem),
        ("vbmeta", EdlRawAvbNodeKind.Vbmeta),
    };

    /// <summary>
    /// The metadata nodes this preparation actually produced, one entry per target slot and role. It stays empty
    /// until a factory wires the helper below, so no caller can observe an unproven node.
    /// </summary>
    private readonly IReadOnlyList<DirectAvbMetadataNode> _directAvbNodes =
        Array.Empty<DirectAvbMetadataNode>();

    internal IReadOnlyList<DirectAvbMetadataNode> DirectAvbNodes => _directAvbNodes;

    /// <summary>
    /// Decides the source slot of both fixed targets in <see cref="SlotOrder"/>, defaulting every target to
    /// itself. Only an opposite, non-current target whose actual boot header is all zero may buy the strict
    /// five-file inactive-slot proof, and that proof is added to the caller's map immediately so the caller
    /// owns its leases and releases them in its own finally block.
    /// <para>
    /// Nothing else is bought here: no 4 KiB prefix alone is a success, no A metadata is copied into B, no full
    /// B read is asserted and neither slot is re-analysed or re-scanned. The observed current slot never falls
    /// back to another source. The single proof is returned to the caller for the one existing builder call.
    /// </para>
    /// </summary>
    private static async Task<Dictionary<string, string>> DetermineDirectSourceSlotsAsync(
        string profileId,
        string currentSlot,
        IReadOnlyDictionary<string, EdlCapturedRegion> files,
        Dictionary<string, EdlRawInactiveSlotBackup> inactiveTargets,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(inactiveTargets);

        if (currentSlot is not ("a" or "b"))
        {
            throw new InvalidOperationException(
                "unsupported-current-slot: the direct source-slot decision supports exactly the observed "
                + "slot a or slot b, not '" + currentSlot + "'.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        Dictionary<string, string> sourceSlots = new(StringComparer.Ordinal);

        foreach (string target in SlotOrder)
        {
            cancellationToken.ThrowIfCancellationRequested();

            string sourceSlot = target;

            if (!string.Equals(target, currentSlot, StringComparison.Ordinal)
                && IsBootHeaderZero(Claim(files, "boot_" + target), cancellationToken))
            {
                EdlRawInactiveSlotBackup proof = await EdlRawInactiveSlotBackup
                    .VerifyAsync(
                        profileId,
                        currentSlot,
                        target,
                        Claim(files, "boot_" + target),
                        Claim(files, "vendor_boot_" + target),
                        Claim(files, "init_boot_" + target),
                        Claim(files, "abl_" + target),
                        Claim(files, "xbl_config_" + target),
                        cancellationToken)
                    .ConfigureAwait(false);

                inactiveTargets.Add(target, proof);
                sourceSlot = proof.SourceSlot;
            }

            sourceSlots.Add(target, sourceSlot);
        }

        return sourceSlots;
    }

    /// <summary>
    /// Resigns the original vbmeta root of every target slot that keeps its own source material, current slot
    /// first then the other. A target whose source slot is the opposite slot is a factory-empty system that
    /// receives the boot-only treatment, so its actual metadata stays untouched and no root is produced.
    /// <para>
    /// Each returned node is authenticated on its original public key only, held through a read lease over the
    /// signed candidate and then kept by target slot for later reuse. The genuine backup claim of the original
    /// root is never replaced by a candidate claim.
    /// </para>
    /// </summary>
    private static async Task<IReadOnlyDictionary<string, EdlRawResignedAvbNode>> PrepareDirectAvbRootsAsync(
        string currentSlot,
        BootloaderState fastbootLockState,
        IReadOnlyDictionary<string, string> sourceSlots,
        IReadOnlyDictionary<string, EdlCapturedRegion> files,
        string evidenceDirectory,
        List<HeldClaim> claims,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sourceSlots);
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(claims);

        if (string.IsNullOrWhiteSpace(evidenceDirectory))
        {
            throw new ArgumentException(
                "An explicit evidence directory is required for the signed AVB roots.", nameof(evidenceDirectory));
        }

        string[] targets = string.Equals(currentSlot, "a", StringComparison.Ordinal)
            ? new[] { "a", "b" }
            : string.Equals(currentSlot, "b", StringComparison.Ordinal)
                ? new[] { "b", "a" }
                : throw new InvalidOperationException(
                    "unsupported-current-slot: the direct AVB roots support exactly the observed slot a or "
                    + "slot b, not '" + currentSlot + "'.");

        cancellationToken.ThrowIfCancellationRequested();

        Dictionary<string, EdlRawResignedAvbNode> roots = new(StringComparer.Ordinal);

        foreach (string target in targets)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!sourceSlots.TryGetValue(target, out string? sourceSlot) || sourceSlot is null)
            {
                throw new InvalidDataException(
                    "The direct source-slot map carries no source for slot '" + target + "'.");
            }

            if (!string.Equals(sourceSlot, target, StringComparison.Ordinal))
            {
                continue;
            }

            EdlRawResignedAvbNode node = await EdlRawBootBuilder
                .ResignAvbNodeAsync(
                    Claim(files, "vbmeta_" + target),
                    EdlRawAvbNodeKind.Vbmeta,
                    Path.Combine(evidenceDirectory, "avb-vbmeta_" + target + ".bin"),
                    cancellationToken)
                .ConfigureAwait(false);

            HoldAvbCandidate("avb-vbmeta_" + target, node.Candidate, claims, cancellationToken);
            RequireDirectAvbRootTrust(target, fastbootLockState, node);

            roots.Add(target, node);
        }

        return new ReadOnlyDictionary<string, EdlRawResignedAvbNode>(roots);
    }

    /// <summary>
    /// Builds the three metadata nodes of every target slot that keeps its own source material, in the fixed
    /// order recovery, vbmeta_system then vbmeta. A target whose source slot is the opposite slot is a
    /// factory-empty system: it buys no node at all, so no A metadata is ever copied into B and its own
    /// genuine metadata backups stay untouched.
    /// <para>
    /// The first two nodes are resigned from the target's own backup claim into a new file owned by this
    /// preparation and held as a new read lease. The third reuses the already authenticated and already held
    /// root of the same slot instead of resigning it a second time. Every node is checked against its own
    /// actual backup range and against the one signing key this build trusts, and the root must pin exactly the
    /// three chain descriptors instead of silently keeping an OEM key. Neither an original nor a candidate file
    /// is ever replaced.
    /// </para>
    /// </summary>
    private static async Task<IReadOnlyList<DirectAvbMetadataNode>> PrepareDirectAvbNodesAsync(
        IReadOnlyDictionary<string, EdlRawResignedAvbNode> roots,
        IReadOnlyDictionary<string, string> sourceSlots,
        IReadOnlyDictionary<string, EdlCapturedRegion> files,
        string evidenceDirectory,
        List<HeldClaim> claims,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(roots);
        ArgumentNullException.ThrowIfNull(sourceSlots);
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(claims);

        if (string.IsNullOrWhiteSpace(evidenceDirectory))
        {
            throw new ArgumentException(
                "An explicit evidence directory is required for the signed AVB metadata.",
                nameof(evidenceDirectory));
        }

        cancellationToken.ThrowIfCancellationRequested();

        List<DirectAvbMetadataNode> nodes = new();

        foreach (string slot in SlotOrder)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!sourceSlots.TryGetValue(slot, out string? sourceSlot) || sourceSlot is null)
            {
                throw new InvalidDataException(
                    "The direct source-slot map carries no source for slot '" + slot + "'.");
            }

            // A factory-empty system keeps its actual metadata untouched: it receives no node and no metadata
            // is carried over from the current slot.
            if (!string.Equals(sourceSlot, slot, StringComparison.Ordinal))
            {
                continue;
            }

            foreach ((string role, EdlRawAvbNodeKind kind) in DirectAvbMetadataRoles)
            {
                cancellationToken.ThrowIfCancellationRequested();

                string target = role + "_" + slot;
                EdlCapturedRegion region = RequireDirectAvbTarget(files, target);
                EdlRawResignedAvbNode node;

                if (kind == EdlRawAvbNodeKind.Vbmeta)
                {
                    if (!roots.TryGetValue(slot, out EdlRawResignedAvbNode? root) || root is null)
                    {
                        throw new InvalidOperationException(
                            "The direct AVB root map carries no signed vbmeta root for slot '" + slot + "'.");
                    }

                    RequireDirectAvbChain(root, slot);
                    node = root;
                }
                else
                {
                    node = await EdlRawBootBuilder
                        .ResignAvbNodeAsync(
                            Claim(files, target),
                            kind,
                            Path.Combine(evidenceDirectory, "avb-" + target + ".bin"),
                            cancellationToken)
                        .ConfigureAwait(false);

                    HoldAvbCandidate("avb-" + target, node.Candidate, claims, cancellationToken);
                }

                RequireDirectAvbNode(target, slot, role, kind, region, node);

                // The node is keyed by the full partition role it belongs to, so the confirmation names the
                // actual backup it was signed from instead of a bare prefix.
                nodes.Add(new DirectAvbMetadataNode(slot, target, node));
            }
        }

        return Array.AsReadOnly(nodes.ToArray());
    }

    private static EdlCapturedRegion RequireDirectAvbTarget(
        IReadOnlyDictionary<string, EdlCapturedRegion> files,
        string role)
    {
        if (!files.TryGetValue(role, out EdlCapturedRegion? region) || region is null)
        {
            throw new InvalidDataException("The backup set carries no '" + role + "' capture.");
        }

        return region;
    }

    /// <summary>
    /// Requires one built node to be the expected kind over the actual full partition range and to be signed
    /// by the one signing key this build trusts.
    /// </summary>
    private static void RequireDirectAvbNode(
        string target,
        string slot,
        string role,
        EdlRawAvbNodeKind kind,
        EdlCapturedRegion region,
        EdlRawResignedAvbNode node)
    {
        if (node.Kind != kind
            || node.Original.Length != region.Length
            || !SameSha(node.Original.Sha256, region.Sha256)
            || node.Candidate.Length != region.Length
            || !SameSha(node.PublicKeySha256, EdlRawBootBuilder.SigningPublicKeySha256))
        {
            throw new InvalidDataException(
                "The signed '" + target + "' node of slot " + slot + " is not the actual '" + role
                + "' partition, its actual original or the trusted signing key.");
        }
    }

    /// <summary>
    /// Requires the signed root to pin exactly the boot, recovery and vbmeta_system chain descriptors to the
    /// one signing key this build trusts. A missing or different descriptor is refused instead of being kept.
    /// </summary>
    private static void RequireDirectAvbChain(EdlRawResignedAvbNode root, string slot)
    {
        if (root.ChainPublicKeySha256.Count != DirectAvbChainRoles.Length)
        {
            throw new InvalidOperationException(
                "requires-direct-avb-chain: the vbmeta_" + slot + " root pins "
                + root.ChainPublicKeySha256.Count + " chain descriptors instead of exactly the "
                + DirectAvbChainRoles.Length + " boot, recovery and vbmeta_system descriptors.");
        }

        foreach (string chainRole in DirectAvbChainRoles)
        {
            if (!root.ChainPublicKeySha256.TryGetValue(chainRole, out string? sha256)
                || sha256 is null
                || !SameSha(sha256, EdlRawBootBuilder.SigningPublicKeySha256))
            {
                throw new InvalidOperationException(
                    "requires-direct-avb-chain: the vbmeta_" + slot + " root does not pin the trusted signing "
                    + "key for the '" + chainRole + "' chain descriptor; an OEM key is never kept.");
            }
        }
    }

    /// <summary>
    /// Holds the builder's signed candidate as a new read lease with its actual length and hash, adding the
    /// claim only once both match. On any refusal only this stream is released.
    /// </summary>
    private static void HoldAvbCandidate(
        string subject,
        VerifiedEdlFile candidate,
        List<HeldClaim> claims,
        CancellationToken cancellationToken)
    {
        FileStream stream = OpenRead(candidate.Path);

        try
        {
            if (stream.Length != candidate.Length)
            {
                throw new InvalidDataException(
                    "The signed '" + subject + "' candidate is " + stream.Length + " bytes, not the "
                    + candidate.Length + " bytes the builder reported.");
            }

            string sha256 = HashHeld(stream, cancellationToken);
            if (!SameSha(sha256, candidate.Sha256))
            {
                throw new InvalidDataException(
                    "The signed '" + subject + "' candidate does not hash to the bytes the builder reported.");
            }

            claims.Add(new HeldClaim(subject, candidate.Path, candidate.Length, sha256, stream));
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Authenticates one original signed root against the actual bootloader fact. An unlocked bootloader passes;
    /// a locked one passes only when the original root key is the compatible signing key this build trusts;
    /// every other state, including an unknown one, is refused instead of being read as unlocked. This proves
    /// only that no verifiable compatible bootloader evidence exists for the signing-root transition on this
    /// state, never that any other device or build would reject the root.
    /// </summary>
    private static void RequireDirectAvbRootTrust(
        string target,
        BootloaderState fastbootLockState,
        EdlRawResignedAvbNode node)
    {
        if (fastbootLockState == BootloaderState.Unlocked)
        {
            return;
        }

        if (fastbootLockState == BootloaderState.Locked
            && SameSha(node.OriginalPublicKeySha256, EdlRawBootBuilder.SigningPublicKeySha256))
        {
            return;
        }

        throw new InvalidOperationException(
            "requires-compatible-bootloader: the original vbmeta_" + target + " signing root is not verifiable "
            + "under the observed bootloader state '" + fastbootLockState + "'; there is no verifiable "
            + "compatible bootloader evidence for the signing-root transition.");
    }

    // ------------------------------------------------------------------ confirmation record

    /// <summary>
    /// The direct AVB chain section of the confirmation: the one signing key this build trusts, then both
    /// built slots in the fixed write order. Each slot records its own actual metadata nodes and - only for a
    /// factory-empty system - the three genuine metadata backups it deliberately leaves untouched. The old
    /// slot array, the image format and the restore plan are not restated here, no hardware readiness is
    /// claimed and nothing is asserted about an independent Android B system.
    /// </summary>
    private void WriteDirectAvbConfirmation(Utf8JsonWriter json)
    {
        json.WriteStartObject("avbChain");
        json.WriteString(
            "signingPublicKeySha256", EdlRawBootBuilder.SigningPublicKeySha256.ToUpperInvariant());

        json.WriteStartArray("slots");
        foreach (string slot in SlotOrder)
        {
            if (!_directBoots.TryGetValue(slot, out EdlRawBuiltBoot? built) || built is null)
            {
                throw new InvalidOperationException(
                    "The direct AVB chain has no built result for slot " + slot + ".");
            }

            WriteDirectAvbSlot(json, slot, built);
        }

        json.WriteEndArray();
        json.WriteEndObject();
    }

    private void WriteDirectAvbSlot(Utf8JsonWriter json, string slot, EdlRawBuiltBoot built)
    {
        // The boot-only treatment is only ever the strict five-file proof's own verdict, never a comparison
        // this writer invents.
        bool factoryEmpty = built.UsesInactiveSlotBackup;

        List<DirectAvbMetadataNode> nodes = new();
        foreach (DirectAvbMetadataNode node in _directAvbNodes)
        {
            if (string.Equals(node.Slot, slot, StringComparison.Ordinal))
            {
                nodes.Add(node);
            }
        }

        if (nodes.Count != (factoryEmpty ? 0 : DirectAvbMetadataRoles.Length))
        {
            throw new InvalidOperationException(
                "The direct AVB chain carries " + nodes.Count + " metadata nodes for slot " + slot
                + ", not the actual preparation facts.");
        }

        json.WriteStartObject();
        json.WriteString("slot", slot);
        json.WriteString("sourceSlot", built.SourceSlot);
        json.WriteBoolean("nonbootableSystem", built.UsesInactiveSlotBackup);

        json.WriteStartArray("metadataNodes");
        foreach (DirectAvbMetadataNode node in nodes)
        {
            WriteDirectAvbNode(json, slot, node, factoryEmpty);
        }

        json.WriteEndArray();

        json.WriteStartArray("preservedMetadata");
        if (factoryEmpty)
        {
            // The genuine own-slot backups, recorded as they are - even an all-zero or otherwise invalid one -
            // without parsing them or claiming an independent Android B system behind them.
            foreach ((string role, _) in DirectAvbMetadataRoles)
            {
                string target = role + "_" + slot;
                EdlCapturedRegion region = RequireDirectAvbTarget(target);

                json.WriteStartObject();
                json.WriteString("role", target);
                json.WriteStartObject("original");
                json.WriteNumber("length", region.Length);
                json.WriteString("sha256", region.Sha256.ToUpperInvariant());
                json.WriteEndObject();
                json.WriteEndObject();
            }
        }

        json.WriteEndArray();
        json.WriteEndObject();
    }

    private void WriteDirectAvbNode(
        Utf8JsonWriter json,
        string slot,
        DirectAvbMetadataNode node,
        bool factoryEmpty)
    {
        if (factoryEmpty || !string.Equals(node.Slot, slot, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The direct AVB chain carries a metadata node that is not part of slot " + slot + ".");
        }

        // The node role is already the full partition role of the actual backup it was signed from.
        EdlCapturedRegion region = RequireDirectAvbTarget(node.Role);

        json.WriteStartObject();
        json.WriteString("role", node.Role);

        json.WriteStartObject("original");
        json.WriteNumber("length", node.Node.Original.Length);
        json.WriteString("sha256", node.Node.Original.Sha256.ToUpperInvariant());
        json.WriteString("publicKeySha256", node.Node.OriginalPublicKeySha256.ToUpperInvariant());
        json.WriteEndObject();

        json.WriteStartObject("candidate");
        json.WriteNumber("length", node.Node.Candidate.Length);
        json.WriteString("sha256", node.Node.Candidate.Sha256.ToUpperInvariant());
        json.WriteString("publicKeySha256", node.Node.PublicKeySha256.ToUpperInvariant());
        json.WriteEndObject();

        json.WriteStartObject("targetBefore");
        json.WriteNumber("length", region.Length);
        json.WriteString("sha256", region.Sha256.ToUpperInvariant());
        json.WriteEndObject();

        json.WriteStartObject("target");
        json.WriteNumber("lun", region.Lun);
        json.WriteNumber("startSector", region.StartSector);
        json.WriteNumber("sectorCount", region.SectorCount);
        json.WriteNumber("sectorSize", region.SectorSize);
        json.WriteEndObject();

        json.WriteNumber("vbmetaOffset", node.Node.VbmetaOffset);
        json.WriteNumber("vbmetaBytes", node.Node.VbmetaBytes);
        json.WriteNumber("rollbackIndex", node.Node.RollbackIndex);
        json.WriteNumber("rollbackIndexLocation", node.Node.RollbackIndexLocation);
        json.WriteNumber("flags", node.Node.Flags);
        json.WriteNumber("requiredMajor", node.Node.RequiredMajor);
        json.WriteNumber("requiredMinor", node.Node.RequiredMinor);
        json.WriteString("nonChainDescriptorsSha256", node.Node.NonChainDescriptorsSha256.ToUpperInvariant());

        if (string.Equals(node.Role, "vbmeta_" + slot, StringComparison.Ordinal))
        {
            json.WriteStartObject("chainPublicKeySha256");
            foreach (string chainRole in DirectAvbChainRoles)
            {
                if (!node.Node.ChainPublicKeySha256.TryGetValue(chainRole, out string? sha256) || sha256 is null)
                {
                    throw new InvalidOperationException(
                        "The direct AVB root node does not pin the '" + chainRole + "' chain descriptor.");
                }

                json.WriteString(chainRole, sha256.ToUpperInvariant());
            }

            json.WriteEndObject();
        }

        json.WriteEndObject();
    }

    private EdlCapturedRegion RequireDirectAvbTarget(string role)
    {
        if (!_backupFiles.TryGetValue(role, out EdlCapturedRegion? region) || region is null)
        {
            throw new InvalidOperationException("The direct AVB chain has no actual '" + role + "' backup.");
        }

        return region;
    }
}
