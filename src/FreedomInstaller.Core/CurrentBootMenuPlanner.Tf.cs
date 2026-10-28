using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text.Json;

namespace FreedomInstaller.Core;

public sealed class TfBootPlan : IDisposable
{
    private static readonly HashSet<string> ValidSlots = new(StringComparer.Ordinal) { "a", "b" };

    private int _disposed;

    public TfBootPurpose Purpose { get; }
    public CurrentBootMenuPlan MenuPlan { get; }
    public string Model { get; }
    public string CurrentSlot { get; }
    public string SourceBackupDirectory { get; }
    public string SourceBackupManifestSha256 { get; }
    public string TargetBackupDirectory { get; }
    public string TargetBackupManifestSha256 { get; }
    public string PackageManifestFingerprint { get; }
    public bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    internal InternalInstallPreparationContext.TfBootAuthority SourceAuthority { get; }
    internal TfPreparedCardImages Images { get; }
    internal InternalBackupSet SourceBackup { get; }
    internal InternalBackupSet TargetBackup { get; }
    internal IReadOnlyDictionary<string, TfPackedPayload> Payloads { get; }
    internal EdlRawBootTools OwnedTools { get; }

    internal TfBootPlan(
        TfBootPurpose purpose,
        CurrentBootMenuPlan menuPlan,
        InternalBackupSet sourceBackup,
        InternalBackupSet targetBackup,
        TfPreparedCardImages images,
        InternalInstallPreparationContext.TfBootAuthority sourceAuthority,
        EdlRawBootTools ownedTools,
        IReadOnlyDictionary<string, TfPackedPayload> payloads)
    {
        ArgumentNullException.ThrowIfNull(menuPlan);
        ArgumentNullException.ThrowIfNull(sourceBackup);
        ArgumentNullException.ThrowIfNull(targetBackup);
        ArgumentNullException.ThrowIfNull(images);
        ArgumentNullException.ThrowIfNull(sourceAuthority);
        ArgumentNullException.ThrowIfNull(ownedTools);
        ArgumentNullException.ThrowIfNull(payloads);
        if (purpose is not (TfBootPurpose.FinalTf or TfBootPurpose.RamMaintenance))
        {
            throw new ArgumentException($"Unknown {nameof(TfBootPurpose)} value '{purpose}'.", nameof(purpose));
        }
        if (!string.Equals(sourceBackup.Model, targetBackup.Model, StringComparison.Ordinal))
        {
            throw new ArgumentException("Source and target backup models disagree.");
        }
        if (!string.Equals(targetBackup.Model, images.Contract.DeviceModel, StringComparison.Ordinal))
        {
            throw new ArgumentException("Target backup model and prepared card image device model disagree.");
        }
        if (!string.Equals(menuPlan.BackupManifestSha256, targetBackup.ManifestSha256, StringComparison.Ordinal))
        {
            throw new ArgumentException("Menu plan backup manifest does not match the target backup set.");
        }
        if (!ReferenceEquals(menuPlan.Binding, targetBackup.Binding))
        {
            throw new ArgumentException("Menu plan binding is not the target backup binding instance.");
        }
        if (!ValidSlots.Contains(menuPlan.CurrentSlot))
        {
            throw new ArgumentException($"Menu plan current slot '{menuPlan.CurrentSlot}' is not 'a' or 'b'.");
        }

        Purpose = purpose;
        MenuPlan = menuPlan;
        SourceBackup = sourceBackup;
        TargetBackup = targetBackup;
        Images = images;
        SourceAuthority = sourceAuthority;
        OwnedTools = ownedTools;
        Model = sourceBackup.Model;
        CurrentSlot = menuPlan.CurrentSlot;
        SourceBackupDirectory = sourceBackup.DirectoryPath;
        SourceBackupManifestSha256 = sourceBackup.ManifestSha256;
        TargetBackupDirectory = targetBackup.DirectoryPath;
        TargetBackupManifestSha256 = targetBackup.ManifestSha256;
        PackageManifestFingerprint = images.Contract.ManifestFingerprint;

        var copy = new Dictionary<string, TfPackedPayload>(payloads.Count, StringComparer.Ordinal);
        foreach (var pair in payloads)
        {
            copy.Add(pair.Key, pair.Value);
        }
        Payloads = new ReadOnlyDictionary<string, TfPackedPayload>(copy);
    }

    internal async Task RevalidateAsync(CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        ct.ThrowIfCancellationRequested();
        if (MenuPlan.IsDisposed)
        {
            throw new ObjectDisposedException(nameof(CurrentBootMenuPlan));
        }

        await SourceAuthority.RevalidateAsync(ct).ConfigureAwait(false);
        await Images.RevalidateAsync(ct).ConfigureAwait(false);
        await OwnedTools.RevalidateAsync(ct).ConfigureAwait(false);

        await VerifyFileAsync(MenuPlan.VerificationReport, "menu plan verification report", ct).ConfigureAwait(false);
        foreach (var slot in MenuPlan.Slots)
        {
            if (slot.Candidate is { } candidate)
            {
                await VerifyFileAsync(candidate, $"slot '{slot.Original.Path}' candidate", ct).ConfigureAwait(false);
            }
        }
        foreach (var companion in MenuPlan.Companions)
        {
            await VerifyFileAsync(companion.Candidate, $"companion '{companion.Original.Path}' candidate", ct).ConfigureAwait(false);
        }

        foreach (var payload in GetDistinctPayloads())
        {
            await VerifyFileAsync(payload.PackedRaw, $"packed raw '{payload.SourceSlot}'", ct).ConfigureAwait(false);
            await VerifyFileAsync(payload.BaseImage, $"base image '{payload.SourceSlot}'", ct).ConfigureAwait(false);
            await VerifyFileAsync(payload.VerificationReport, $"payload verification report '{payload.SourceSlot}'", ct).ConfigureAwait(false);
        }
    }

    private List<TfPackedPayload> GetDistinctPayloads()
    {
        var seen = new HashSet<TfPackedPayload>();
        var result = new List<TfPackedPayload>();
        foreach (var payload in Payloads.Values)
        {
            if (seen.Add(payload))
            {
                result.Add(payload);
            }
        }
        return result;
    }

    private static async Task VerifyFileAsync(VerifiedEdlFile claim, string subject, CancellationToken ct)
    {
        await using var stream = new FileStream(
            claim.Path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 1 << 16,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length != claim.Length)
        {
            throw new InvalidDataException($"{subject}: length {stream.Length} does not match claim {claim.Length}.");
        }
        var hash = await SHA256.HashDataAsync(stream, ct).ConfigureAwait(false);
        var actual = Convert.ToHexString(hash);
        if (!string.Equals(actual, claim.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException($"{subject}: SHA256 mismatch for '{claim.Path}'.");
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        var errors = new List<Exception>();

        foreach (var payload in GetDistinctPayloads())
        {
            try
            {
                payload.Dispose();
            }
            catch (Exception ex)
            {
                errors.Add(ex);
            }
        }

        try
        {
            SourceAuthority.Dispose();
        }
        catch (Exception ex)
        {
            errors.Add(ex);
        }

        try
        {
            OwnedTools.Dispose();
        }
        catch (Exception ex)
        {
            errors.Add(ex);
        }

        try
        {
            MenuPlan.Dispose();
        }
        catch (Exception ex)
        {
            errors.Add(ex);
        }

        try
        {
            if (Directory.Exists(MenuPlan.DirectoryPath))
            {
                errors.Add(new IOException($"Generated menu directory '{MenuPlan.DirectoryPath}' still exists after disposal."));
            }
        }
        catch (Exception ex)
        {
            errors.Add(ex);
        }

        if (errors.Count > 0)
        {
            throw new AggregateException("TfBootPlan disposal encountered one or more failures.", errors);
        }
    }
}

public static partial class CurrentBootMenuPlanner
{
    private static readonly HashSet<string> ValidSlots = new(StringComparer.Ordinal) { "a", "b" };

    public static async Task<TfBootPlan> PrepareTfAsync(
        InternalBackupSet currentBackup,
        string currentSlot,
        BootloaderState lockState,
        TfPreparedCardImages images,
        TfBootPurpose purpose,
        EdlRawBootTools tools,
        ICommandRunner runner,
        string chosenParent,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(currentBackup);
        ArgumentNullException.ThrowIfNull(images);
        ArgumentNullException.ThrowIfNull(tools);
        ArgumentNullException.ThrowIfNull(runner);
        ArgumentException.ThrowIfNullOrWhiteSpace(currentSlot);
        ArgumentException.ThrowIfNullOrWhiteSpace(chosenParent);
        if (!ValidSlots.Contains(currentSlot))
        {
            throw new ArgumentException($"Current slot '{currentSlot}' is not 'a' or 'b'.", nameof(currentSlot));
        }
        if (purpose is not (TfBootPurpose.FinalTf or TfBootPurpose.RamMaintenance))
        {
            throw new ArgumentException($"Unknown {nameof(TfBootPurpose)} value '{purpose}'.", nameof(purpose));
        }
        if (lockState is not (BootloaderState.Unknown or BootloaderState.Locked or BootloaderState.Unlocked))
        {
            throw new ArgumentException($"Unknown {nameof(BootloaderState)} value '{lockState}'.", nameof(lockState));
        }

        NormalizeParent(chosenParent);
        RequireBoundBackup(currentBackup);
        if (!string.Equals(images.Contract.DeviceModel, currentBackup.Model, StringComparison.Ordinal))
        {
            throw new ArgumentException("Prepared card image device model does not match the backup model.");
        }
        if (purpose == TfBootPurpose.RamMaintenance && images.Contract.MaintenanceInitramfs is null)
        {
            throw new ArgumentException("RamMaintenance requires the package maintenance initramfs.");
        }

        await images.RevalidateAsync(ct).ConfigureAwait(false);

        var parent = NormalizeParent(chosenParent);
        var child = Path.Combine(parent, $"tf-boot-plan-{Guid.NewGuid():N}");
        Directory.CreateDirectory(child);

        EdlRawBootTools? ownTools = null;
        InternalInstallPreparationContext.TfBootAuthority? authority = null;
        CurrentBootInitializedInactiveProof? initializedProof = null;
        var payloads = new Dictionary<string, TfPackedPayload>(StringComparer.Ordinal);
        var outputLeases = new List<FileStream>();
        CurrentBootMenuPlan? menuPlan = null;
        try
        {
            ownTools = await tools.AcquireAsync(ct).ConfigureAwait(false);

            // 1/2. Initialized-project shape: current slot 'a', all four real B ancillary captures wholly
            // zero, boot_b not wholly zero. This is only a shape predicate; the factory below proves the
            // actual native graph, ancillary zeros, source-A physical base and parent key.
            var useInitializedProofPath = false;
            if (string.Equals(currentSlot, "a", StringComparison.Ordinal))
            {
                var bAncillaryAllZero =
                    await IsWhollyZeroAsync(RequireRole(currentBackup, "vendor_boot_b"), ct).ConfigureAwait(false) &&
                    await IsWhollyZeroAsync(RequireRole(currentBackup, "init_boot_b"), ct).ConfigureAwait(false) &&
                    await IsWhollyZeroAsync(RequireRole(currentBackup, "abl_b"), ct).ConfigureAwait(false) &&
                    await IsWhollyZeroAsync(RequireRole(currentBackup, "xbl_config_b"), ct).ConfigureAwait(false);
                var bBootNotZero = !await IsWhollyZeroAsync(RequireRole(currentBackup, "boot_b"), ct).ConfigureAwait(false);
                useInitializedProofPath = bAncillaryAllZero && bBootNotZero;
            }

            if (useInitializedProofPath)
            {
                initializedProof = await EdlRawBootBuilder.VerifyInitializedInactiveSlotAsync(
                    currentBackup.ProfileId,
                    "a",
                    "b",
                    RequireRole(currentBackup, "boot_a"),
                    RequireRole(currentBackup, "vendor_boot_a"),
                    RequireRole(currentBackup, "init_boot_a"),
                    RequireRole(currentBackup, "abl_a"),
                    RequireRole(currentBackup, "xbl_config_a"),
                    RequireRole(currentBackup, "boot_b"),
                    RequireRole(currentBackup, "vendor_boot_b"),
                    RequireRole(currentBackup, "init_boot_b"),
                    RequireRole(currentBackup, "abl_b"),
                    RequireRole(currentBackup, "xbl_config_b"),
                    RequireRole(currentBackup, "vbmeta_a"),
                    ownTools,
                    runner,
                    child,
                    ct).ConfigureAwait(false);
                authority = await InternalInstallPreparationContext.PrepareTfBootAuthorityAsync(
                    currentBackup, currentSlot, lockState, child, initializedProof, ct).ConfigureAwait(false);
                initializedProof = null; // successful transfer: the authority now owns the proof
            }
            else
            {
                authority = await InternalInstallPreparationContext.PrepareTfBootAuthorityAsync(
                    currentBackup, currentSlot, lockState, child, ct).ConfigureAwait(false);
            }

            if (!string.Equals(authority.Model, currentBackup.Model, StringComparison.Ordinal) ||
                !string.Equals(authority.CurrentSlot, currentSlot, StringComparison.Ordinal) ||
                !string.Equals(authority.BackupManifestSha256, currentBackup.ManifestSha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException("Prepared TF boot authority does not reflect the requested backup identity.");
            }

            // 3. Build one packed payload per distinct actual source slot.
            var sourceDirs = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var source in authority.SourceSlots.Values.Distinct(StringComparer.Ordinal))
            {
                var sourceDir = Path.Combine(child, $"source-{source}");
                Directory.CreateDirectory(sourceDir);
                sourceDirs[source] = sourceDir;

                var efisp = currentBackup.Files.TryGetValue("efisp", out var efispRegion)
                    ? new CurrentBootEfispFacts(efispRegion.Lun, efispRegion.SectorCount, efispRegion.SectorSize, efispRegion.Length, efispRegion.Sha256)
                    : null;
                var inputs = new CurrentBootSlotInputs(
                    source,
                    RequireRole(currentBackup, $"boot_{source}"),
                    RequireRole(currentBackup, $"vendor_boot_{source}"),
                    RequireRole(currentBackup, $"init_boot_{source}"),
                    RequireRole(currentBackup, $"abl_{source}"),
                    RequireRole(currentBackup, $"xbl_config_{source}"),
                    RequireRole(currentBackup, $"vbmeta_{source}"),
                    efisp,
                    ownTools,
                    runner,
                    sourceDir,
                    Path.Combine(sourceDir, "base.bin"),
                    Path.Combine(sourceDir, "original.raw"),
                    Path.Combine(sourceDir, "changed.raw"),
                    Path.Combine(sourceDir, "unpacked-original"),
                    Path.Combine(sourceDir, "unpacked-changed"),
                    Path.Combine(sourceDir, "candidate.bin"));
                payloads[source] = await EdlRawBootBuilder.TfBuildPayloadAsync(inputs, images, purpose, ct).ConfigureAwait(false);
            }

            // 3b. B-template payload: only when the bound initialized-inactive proof is present and this is
            // FinalTf. Actual source facts remain A; the proof's B ProjectRaw is the menu template. Stored
            // under dictionary key 'b' while SourceSlot/Material.Slot stay 'a'.
            if (authority.InitializedInactiveProof is { } templateProof && purpose == TfBootPurpose.FinalTf)
            {
                if (!string.Equals(templateProof.SourceSlot, "a", StringComparison.Ordinal) ||
                    !string.Equals(templateProof.TargetSlot, "b", StringComparison.Ordinal))
                {
                    throw new InvalidDataException("Initialized inactive proof does not map source 'a' to target 'b'.");
                }
                var templateDir = Path.Combine(child, "template-b");
                Directory.CreateDirectory(templateDir);
                var efispTemplate = currentBackup.Files.TryGetValue("efisp", out var efispTemplateRegion)
                    ? new CurrentBootEfispFacts(efispTemplateRegion.Lun, efispTemplateRegion.SectorCount, efispTemplateRegion.SectorSize, efispTemplateRegion.Length, efispTemplateRegion.Sha256)
                    : null;
                var templateInputs = new CurrentBootSlotInputs(
                    "a",
                    RequireRole(currentBackup, "boot_a"),
                    RequireRole(currentBackup, "vendor_boot_a"),
                    RequireRole(currentBackup, "init_boot_a"),
                    RequireRole(currentBackup, "abl_a"),
                    RequireRole(currentBackup, "xbl_config_a"),
                    RequireRole(currentBackup, "vbmeta_a"),
                    efispTemplate,
                    ownTools,
                    runner,
                    templateDir,
                    Path.Combine(templateDir, "base.bin"),
                    Path.Combine(templateDir, "original.raw"),
                    Path.Combine(templateDir, "changed.raw"),
                    Path.Combine(templateDir, "unpacked-original"),
                    Path.Combine(templateDir, "unpacked-changed"),
                    Path.Combine(templateDir, "candidate.bin"));
                payloads["b"] = await EdlRawBootBuilder.TfBuildPayloadFromInitializedInactiveAsync(
                    templateInputs, images, purpose, templateProof, ct).ConfigureAwait(false);
            }

            // 4. Actual raw bounds from the shared owner, then revalidation before envelopes.
            // Group owned payloads by ACTUAL source slot (payload.SourceSlot/Material.Slot), not
            // dictionary key: the 'a' and 'b' entries may share true source A but differ as menu
            // templates. All measured source facts within a group must agree; the bound uses the
            // maximum packed raw length over the group.
            var actualSources = payloads.Values
                .Select(p => p.SourceSlot)
                .Distinct(StringComparer.Ordinal)
                .ToList();
            var materialsBySource = new Dictionary<string, InternalSlotMaterial>(actualSources.Count, StringComparer.Ordinal);
            var rawLengthsBySource = new Dictionary<string, long>(actualSources.Count, StringComparer.Ordinal);
            foreach (var source in actualSources)
            {
                var group = payloads.Values.Where(p => string.Equals(p.SourceSlot, source, StringComparison.Ordinal)).ToList();
                var first = group[0];
                if (!string.Equals(first.Material.Slot, source, StringComparison.Ordinal))
                {
                    throw new InvalidDataException($"Payload material slot '{first.Material.Slot}' does not match actual source '{source}'.");
                }
                foreach (var member in group.Skip(1))
                {
                    if (!string.Equals(member.Material.Slot, source, StringComparison.Ordinal))
                    {
                        throw new InvalidDataException($"Payload material slot '{member.Material.Slot}' does not match actual source '{source}'.");
                    }
                    if (!SameMeasuredFacts(first.Material.SourceSha256, member.Material.SourceSha256) ||
                        !SameMeasuredFacts(first.Material.SourceLengths, member.Material.SourceLengths))
                    {
                        throw new InvalidDataException($"Payloads sharing source '{source}' disagree on measured source hashes/lengths.");
                    }
                    if (first.Material.PageSize != member.Material.PageSize ||
                        first.Material.TotalRamdiskSize != member.Material.TotalRamdiskSize ||
                        first.Material.LoaderBudget.MaxRawBytes != member.Material.LoaderBudget.MaxRawBytes)
                    {
                        throw new InvalidDataException($"Payloads sharing source '{source}' disagree on measured material facts.");
                    }
                }
                materialsBySource[source] = first.Material;
                rawLengthsBySource[source] = group.Max(p => p.PackedRaw.Length);
            }
            var rawBounds = authority.RequireRuntimeRawBounds(materialsBySource, rawLengthsBySource, ct);
            await authority.RevalidateAsync(ct).ConfigureAwait(false);
            await images.RevalidateAsync(ct).ConfigureAwait(false);
            await ownTools.RevalidateAsync(ct).ConfigureAwait(false);

            // 5. Selected targets: inactive first, actual current last; RamMaintenance only current.
            var targets = new List<string>();
            if (purpose == TfBootPurpose.RamMaintenance)
            {
                targets.Add(currentSlot);
            }
            else if (currentSlot == "a")
            {
                targets.Add("b");
                targets.Add("a");
            }
            else
            {
                targets.Add("a");
                targets.Add("b");
            }

            var slots = new List<CurrentBootMenuSlot>();
            var companions = new List<CurrentBootMenuCompanion>();
            var selectedTargets = new HashSet<string>(targets, StringComparer.Ordinal);
            var reportTargets = new List<object>();

            foreach (var target in targets)
            {
                var boundProof = authority.InitializedInactiveProof;
                TfPackedPayload payload;
                string source;
                if (boundProof is { } targetTemplateProof &&
                    purpose == TfBootPurpose.FinalTf &&
                    string.Equals(target, targetTemplateProof.TargetSlot, StringComparison.Ordinal) &&
                    payloads.TryGetValue(targetTemplateProof.TargetSlot, out var templatePayload))
                {
                    // B-template payload keyed by target 'b'; its actual source is still A.
                    payload = templatePayload;
                    source = payload.SourceSlot;
                }
                else
                {
                    if (!authority.SourceSlots.TryGetValue(target, out source))
                    {
                        throw new InvalidDataException($"No sealed source slot for target '{target}'.");
                    }
                    if (!payloads.TryGetValue(source, out payload!))
                    {
                        throw new InvalidDataException($"No packed payload for source slot '{source}'.");
                    }
                }
                if (!string.Equals(payload.Material.Slot, source, StringComparison.Ordinal))
                {
                    throw new InvalidDataException($"Payload material slot '{payload.Material.Slot}' does not match source '{source}'.");
                }
                var targetOriginal = RequireRole(currentBackup, $"boot_{target}");
                var sourceBoot = RequireRole(currentBackup, $"boot_{source}");
                if (target != source)
                {
                    var admittedByOriginalProof = authority.InactiveTargets.ContainsKey(target);
                    var admittedByBoundProof =
                        boundProof is { } bp &&
                        string.Equals(bp.SourceSlot, source, StringComparison.Ordinal) &&
                        string.Equals(bp.TargetSlot, target, StringComparison.Ordinal) &&
                        string.Equals(bp.TargetBoot.Path, targetOriginal.Path, StringComparison.Ordinal) &&
                        bp.TargetBoot.Length == targetOriginal.Length &&
                        string.Equals(bp.TargetBoot.Sha256, targetOriginal.Sha256, StringComparison.OrdinalIgnoreCase);
                    if (!admittedByOriginalProof && !admittedByBoundProof)
                    {
                        throw new InvalidDataException($"Cross-source target '{target}' has no sealed inactive target proof.");
                    }
                    boundProof?.RequireUsable();
                }
                if (target != source)
                {
                    // The source envelope wraps the verified source-A original; the B target keeps its
                    // own whole captured claim from currentBackup.
                    if (targetOriginal.Length != sourceBoot.Length)
                    {
                        throw new InvalidDataException($"Boot image length mismatch between source '{source}' and target '{target}'.");
                    }
                }
                if (payload.PackedRaw.Length > rawBounds[source])
                {
                    throw new InvalidDataException($"Packed raw length for '{source}' exceeds the runtime bound.");
                }

                var sourceDir = sourceDirs[source];
                var candidatePath = Path.Combine(sourceDir, $"candidate-{target}.bin");
                VerifiedEdlFile candidate;
                BootMaintenanceBootTrust trust;
                string? metadataSha256;
                bool payloadDigestMatchesOem;
                if (authority.UsesGbl)
                {
                    var gbl = await EdlRawBootBuilder.RepackCurrentGblEnvelopeAsync(
                        sourceBoot, payload.PackedRaw, rawBounds[source], candidatePath, ct).ConfigureAwait(false);
                    if (!gbl.Facts.OriginalSignatureValid)
                    {
                        throw new InvalidDataException($"GBL envelope for target '{target}' failed original signature validation.");
                    }
                    var expectedKey = authority.RequireGblParentBootKey(source);
                    if (!string.Equals(gbl.Facts.PublicKeySha256, expectedKey, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidDataException($"GBL envelope public key for target '{target}' does not match the parent boot key.");
                    }
                    candidate = gbl.Candidate;
                    trust = BootMaintenanceBootTrust.GblPreserveOem;
                    metadataSha256 = gbl.Facts.SignedVbmetaSha256;
                    payloadDigestMatchesOem = gbl.Facts.ContentDigestMatches;
                }
                else
                {
                    var envelope = await EdlRawBootBuilder.RepackEnvelopeAsync(
                        sourceBoot, payload.PackedRaw, rawBounds[source], candidatePath, ct).ConfigureAwait(false);
                    candidate = envelope.CandidateBoot;
                    trust = BootMaintenanceBootTrust.AospResigned;
                    metadataSha256 = envelope.SourceEmbeddedVbmetaSha256;
                    payloadDigestMatchesOem = false;
                }
                if (candidate.Length != targetOriginal.Length)
                {
                    throw new InvalidDataException($"Candidate length for target '{target}' does not equal the target boot image length.");
                }

                var candidateLease = OpenOutputLease(candidate, $"boot candidate '{target}'", ct);
                outputLeases.Add(candidateLease);

                slots.Add(new CurrentBootMenuSlot(
                    target,
                    source,
                    payload.Material.IsKshim ? BootMaintenanceSourceKind.Project : BootMaintenanceSourceKind.StockOriginal,
                    trust,
                    targetOriginal,
                    candidate,
                    payload.PayloadSha256,
                    metadataSha256,
                    payloadDigestMatchesOem));

                reportTargets.Add(new
                {
                    target,
                    source,
                    candidate_path = candidate.Path,
                    candidate_length = candidate.Length,
                    candidate_sha256 = candidate.Sha256,
                    trust = trust.ToString(),
                    metadata_sha256 = metadataSha256,
                    payload_digest_matches_oem = payloadDigestMatchesOem
                });
            }

            // 7. Companions.
            if (!authority.UsesGbl)
            {
                foreach (var node in authority.AvbNodes)
                {
                    if (!selectedTargets.Contains(node.Slot))
                    {
                        continue;
                    }
                    var original = RequireRole(currentBackup, node.Role);
                    var originalClaim = node.Node.Original;
                    if (!string.Equals(Path.GetFullPath(original.Path), Path.GetFullPath(originalClaim.Path), StringComparison.Ordinal) ||
                        original.Length != originalClaim.Length ||
                        !string.Equals(original.Sha256, originalClaim.Sha256, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidDataException($"AVB companion original facts mismatch for '{node.Role}'.");
                    }
                    var candidate = node.Node.Candidate;
                    if (candidate.Length != original.Length)
                    {
                        throw new InvalidDataException($"AVB companion candidate length mismatch for '{node.Role}'.");
                    }
                    if (candidate.Length == original.Length &&
                        string.Equals(candidate.Sha256, original.Sha256, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var lease = OpenOutputLease(candidate, $"companion candidate '{node.Role}'", ct);
                    outputLeases.Add(lease);
                    companions.Add(new CurrentBootMenuCompanion(node.Slot, node.Role, original, candidate));
                }
            }

            if (purpose != TfBootPurpose.FinalTf)
            {
                // unreachable by design today: GBL maintenance keeps zero AOSP companions
            }

            if (authority.UsesGbl)
            {
                if (authority.EfispTarget is not { } efispTarget ||
                    authority.EfispCandidate is not { } efispCandidate ||
                    !currentBackup.Files.TryGetValue("efisp", out var backupEfisp))
                {
                    throw new InvalidDataException("GBL authority is missing the efisp target, candidate, or backup efisp file.");
                }
                if (efispTarget.Role != backupEfisp.Role ||
                    efispTarget.Lun != backupEfisp.Lun ||
                    efispTarget.StartSector != backupEfisp.StartSector ||
                    efispTarget.SectorCount != backupEfisp.SectorCount ||
                    efispTarget.SectorSize != backupEfisp.SectorSize ||
                    efispTarget.Length != backupEfisp.Length ||
                    !string.Equals(efispTarget.FilePath, backupEfisp.FilePath, StringComparison.Ordinal) ||
                    !string.Equals(efispTarget.Sha256, backupEfisp.Sha256, StringComparison.OrdinalIgnoreCase) ||
                    (backupEfisp.PartUuid is { } partUuid &&
                     !string.Equals(efispTarget.PartUuid, partUuid, StringComparison.OrdinalIgnoreCase)))
                {
                    throw new InvalidDataException("Authority EFIS target facts do not match the captured backup efisp region.");
                }
                var efispOriginal = RequireRole(currentBackup, "efisp");
                if (efispCandidate.Length != efispOriginal.Length)
                {
                    throw new InvalidDataException("EFIS candidate length does not equal the whole backup efisp original.");
                }
                if (efispCandidate.Length == efispOriginal.Length &&
                    string.Equals(efispCandidate.Sha256, efispOriginal.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    // no-op re-wrap
                }
                else
                {
                    var lease = OpenOutputLease(efispCandidate, "companion candidate 'efisp'", ct);
                    outputLeases.Add(lease);
                    companions.Add(new CurrentBootMenuCompanion(currentSlot, "efisp", efispOriginal, efispCandidate));
                }
            }

            // 8. Factual verification report.
            var reportPath = Path.Combine(child, "verification-report.json");
            var report = new
            {
                purpose = purpose.ToString(),
                model = currentBackup.Model,
                current_slot = currentSlot,
                lock_state = lockState.ToString(),
                backup_manifest_sha256 = currentBackup.ManifestSha256,
                package_manifest_fingerprint = images.Contract.ManifestFingerprint,
                source_map = authority.SourceSlots,
                payloads = payloads.Select(p => new
                {
                    payload_key = p.Key,
                    source_slot = p.Value.SourceSlot,
                    material_slot = p.Value.Material.Slot,
                    is_kshim = p.Value.Material.IsKshim,
                    raw_bound = rawBounds[p.Value.SourceSlot],
                    packed_raw_length = p.Value.PackedRaw.Length,
                    default_index = p.Value.DefaultIndex,
                    runtime_sha256 = p.Value.RuntimeSha256,
                    payload_sha256 = p.Value.PayloadSha256,
                    original_payload_sha256 = p.Value.OriginalPayloadSha256,
                    verification_report_sha256 = p.Value.VerificationReport.Sha256
                }),
                targets = reportTargets,
                initialized_inactive_proof = authority.InitializedInactiveProof is { } proof
                    ? new
                    {
                        source_slot = proof.SourceSlot,
                        target_slot = proof.TargetSlot,
                        target_boot_sha256 = proof.TargetBoot.Sha256,
                        verification_report_sha256 = proof.VerificationReport.Sha256
                    }
                    : null,
                companions = companions.Select(c => new
                {
                    slot = c.Slot,
                    role = c.Role,
                    original_sha256 = c.Original.Sha256,
                    candidate_sha256 = c.Candidate.Sha256
                })
            };
            VerifiedEdlFile reportClaim;
            await using (var reportStream = new FileStream(
                reportPath,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 1 << 16,
                FileOptions.Asynchronous))
            {
                await using var writer = new StreamWriter(reportStream, leaveOpen: true);
                var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
                await writer.WriteAsync(json).ConfigureAwait(false);
                await writer.FlushAsync(ct).ConfigureAwait(false);
                await reportStream.FlushAsync(ct).ConfigureAwait(false);
                reportStream.Seek(0, SeekOrigin.Begin);
                var sha = Convert.ToHexString(await SHA256.HashDataAsync(reportStream, ct).ConfigureAwait(false));
                reportClaim = new VerifiedEdlFile(reportPath, reportStream.Length, sha);
            }
            var reportLease = OpenOutputLease(reportClaim, "menu plan verification report", ct);
            outputLeases.Add(reportLease);

            // 9. Own the plan and transfer ownership once.
            menuPlan = new CurrentBootMenuPlan(
                child, slots, companions, reportClaim, outputLeases, currentSlot, currentBackup.Binding, currentBackup.ManifestSha256);
            var plan = new TfBootPlan(purpose, menuPlan, currentBackup, currentBackup, images, authority, ownTools, payloads);
            menuPlan = null;
            authority = null;
            ownTools = null;
            payloads.Clear();
            return plan;
        }
        catch (Exception error)
        {
            var cleanupErrors = new List<Exception>();
            foreach (var payload in payloads.Values.Distinct())
            {
                try
                {
                    payload.Dispose();
                }
                catch (Exception ex)
                {
                    cleanupErrors.Add(ex);
                }
            }
            payloads.Clear();

            // A proof still owned locally here means the authority never took it over: dispose it
            // before the authority and tool lease. An authority-owned proof is released with the
            // authority and must not be disposed twice.
            if (initializedProof is not null)
            {
                try
                {
                    initializedProof.Dispose();
                }
                catch (Exception ex)
                {
                    cleanupErrors.Add(ex);
                }
                initializedProof = null;
            }

            if (authority is not null)
            {
                try
                {
                    authority.Dispose();
                }
                catch (Exception ex)
                {
                    cleanupErrors.Add(ex);
                }
            }

            if (ownTools is not null)
            {
                try
                {
                    ownTools.Dispose();
                }
                catch (Exception ex)
                {
                    cleanupErrors.Add(ex);
                }
            }

            foreach (var lease in outputLeases)
            {
                try
                {
                    await lease.DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    cleanupErrors.Add(ex);
                }
            }
            outputLeases.Clear();

            if (menuPlan is not null)
            {
                try
                {
                    menuPlan.Dispose();
                }
                catch (Exception ex)
                {
                    cleanupErrors.Add(ex);
                }
            }
            else
            {
                TryRemoveFreshChild(parent, child, cleanupErrors);
            }

            throw cleanupErrors.Count > 0
                ? new AggregateException("PrepareTfAsync failed; cleanup errors are attached.", new[] { error }.Concat(cleanupErrors))
                : error;
        }
    }

    // Shape predicate only: reads the claimed file content and reports whether it is wholly zero
    // across its exact declared length. Never an authorization proof; full hashes are verified
    // independently by the proof factory and BindBackup.
    private static async Task<bool> IsWhollyZeroAsync(VerifiedEdlFile claim, CancellationToken ct)
    {
        await using var stream = new FileStream(
            claim.Path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 1 << 16,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length != claim.Length)
        {
            throw new InvalidDataException($"Shape predicate: length {stream.Length} does not match claim {claim.Length} for '{claim.Path}'.");
        }
        var buffer = new byte[1 << 16];
        while (true)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false);
            if (read == 0)
            {
                return true;
            }
            for (var i = 0; i < read; i++)
            {
                if (buffer[i] != 0)
                {
                    return false;
                }
            }
        }
    }

    private static bool SameMeasuredFacts(IReadOnlyDictionary<string, long> left, IReadOnlyDictionary<string, long> right)
    {
        if (left.Count != right.Count)
        {
            return false;
        }
        foreach (var pair in left)
        {
            if (!right.TryGetValue(pair.Key, out var value) ||
                pair.Value != value)
            {
                return false;
            }
        }
        return true;
    }

    private static bool SameMeasuredFacts(IReadOnlyDictionary<string, string> left, IReadOnlyDictionary<string, string> right)
    {
        if (left.Count != right.Count)
        {
            return false;
        }
        foreach (var pair in left)
        {
            if (!right.TryGetValue(pair.Key, out var value) ||
                !string.Equals(pair.Value, value, StringComparison.Ordinal))
            {
                return false;
            }
        }
        return true;
    }

    private static void TryRemoveFreshChild(string parent, string child, List<Exception> errors)
    {
        try
        {
            var fullParent = Path.GetFullPath(parent);
            var fullChild = Path.GetFullPath(child);
            if (string.Equals(fullChild, fullParent, StringComparison.Ordinal))
            {
                errors.Add(new InvalidOperationException($"Refusing to remove non-contained path '{fullChild}'."));
                return;
            }
            var prefix = fullParent;
            if (!prefix.EndsWith(Path.DirectorySeparatorChar) && !prefix.EndsWith(Path.AltDirectorySeparatorChar))
            {
                prefix += Path.DirectorySeparatorChar;
            }
            if (!fullChild.StartsWith(prefix, StringComparison.Ordinal))
            {
                errors.Add(new InvalidOperationException($"Refusing to remove non-contained path '{fullChild}'."));
                return;
            }
            if (Directory.Exists(fullChild))
            {
                Directory.Delete(fullChild, recursive: true);
            }
        }
        catch (Exception ex)
        {
            errors.Add(ex);
        }
    }
}
