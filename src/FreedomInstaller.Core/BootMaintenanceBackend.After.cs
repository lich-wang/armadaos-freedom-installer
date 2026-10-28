using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// The real <see cref="MaintenanceMode.AfterUpdate"/> slice of <see cref="BootMaintenanceBackend"/>:
/// a factory that verifies the caller's claims exactly like the shared core, then reuses the existing
/// TF boot authority, the existing template/base analyzer and the existing boot builder owners to
/// produce prepared Android project candidates for both slots. This partial defines no execution code;
/// the shared body hooks the plan through the mode dispatch.
/// </summary>
public sealed partial class BootMaintenanceBackend
{
    private const string AfterTemplateRequiredCode = "boot-maintenance-project-template-required";

    private const string AfterRepairPackageRequiredCode = "boot-maintenance-repair-package-required";

    private const string AfterTemplateEpochUnprovenCode = "boot-maintenance-template-epoch-unproven";

    private const int AfterCopyChunkBytes = 64 * 1024;

    private static readonly string[] AfterSlots = { "a", "b" };

    private static readonly string[] AfterAvbRolePrefixes = { "recovery_", "vbmeta_system_", "vbmeta_" };

    /// <summary>The TF boot authority this backend owns; assigned by the factory after construction.</summary>
    private InternalInstallPreparationContext.TfBootAuthority? _afterAuthority;

    /// <summary>The immutable repair contract of the no-template fallback route; otherwise null.</summary>
    private EdlRawPackageContract? _afterFallbackContract;

    /// <summary>The installed-Linux facts the fallback contract produced at preparation time.</summary>
    private InstalledLinuxBootFacts? _afterFallbackFacts;

    /// <summary>
    /// The AfterUpdate preparation core. Supports both fact origins: the Android route re-checks the
    /// Step-1 slot against the fresh misc control, the historical route trusts only the fresh capture;
    /// the bootloader lock fact always comes from the live Android check or stays Unknown.
    /// </summary>
    private static async Task<BootMaintenanceBackend> CreateAfterPreparedCoreAsync(
        MaintenanceDeviceFacts deviceFacts,
        EdlClient client,
        InternalBackupSet currentBackup,
        BootMaintenanceSources sources,
        ICommandRunner runner,
        string evidenceParent,
        IProgress<InternalInstallProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(deviceFacts);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(currentBackup);
        ArgumentNullException.ThrowIfNull(sources);
        ArgumentNullException.ThrowIfNull(runner);

        if (evidenceParent is null)
        {
            throw new ArgumentNullException(nameof(evidenceParent));
        }

        if (evidenceParent.Trim().Length == 0)
        {
            throw new ArgumentException(
                "An explicit evidence parent directory is required; there is no default location.",
                nameof(evidenceParent));
        }

        cancellationToken.ThrowIfCancellationRequested();

        await RequireDeviceFactsAsync(deviceFacts, client, cancellationToken).ConfigureAwait(false);
        RequireTrustedProfile(client);
        RequireCallerBackupBinding(client, currentBackup);

        string parent = Path.GetFullPath(evidenceParent);
        if (File.Exists(parent))
        {
            throw new IOException("The evidence parent is a file, not a directory: '" + parent + "'.");
        }

        if (!Directory.Exists(parent))
        {
            throw new IOException("The evidence parent directory does not exist: '" + parent + "'.");
        }

        string evidenceDirectory = Path.Combine(parent, "boot-maint-after-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(evidenceDirectory);

        progress?.Report(new InternalInstallProgress(
            InternalInstallStage.Revalidating,
            InternalInstallProgressKind.Started,
            InternalInstallWriteState.NoneIssued,
            null,
            0,
            0,
            "after-reopening-current-backup"));

        var ownedResources = new List<IDisposable>();
        InternalBackupSet ownedCurrent = null!;
        InternalBackupSet source = null!;
        try
        {
            ownedCurrent = await InternalInstallBackup
                .OpenExistingAsync(client, currentBackup.DirectoryPath, null, cancellationToken)
                .ConfigureAwait(false);

            if (!string.Equals(
                    ownedCurrent.ManifestSha256,
                    currentBackup.ManifestSha256,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    ForgedBackupCode + ": the re-opened backup manifest does not hash to the manifest the "
                    + "caller passed; the selected backup is not the session's current rollback proof.");
            }

            RequireSameCapture(ownedCurrent, currentBackup);

            await ProbeSixLunsAsync(client, ownedCurrent, cancellationToken).ConfigureAwait(false);
            await ReadbackEveryCurrentRegionAsync(
                client, ownedCurrent, evidenceDirectory, progress, cancellationToken).ConfigureAwait(false);

            BootSlotControlFacts miscFacts = await BootSlotControl
                .ReadAsync(RegionClaim(ownedCurrent.Files, "misc", "the current rollback capture"), cancellationToken)
                .ConfigureAwait(false);

            BootVirtualAbControlFacts virtualAbFacts = await BootVirtualAbControl
                .ReadAsync(RegionClaim(ownedCurrent.Files, "misc", "the current rollback capture"), cancellationToken)
                .ConfigureAwait(false);

            if (!virtualAbFacts.IsFormatValid || virtualAbFacts.State != BootVirtualAbState.Completed)
            {
                throw new InvalidOperationException(
                    "boot-maintenance-ota-not-completed: the fresh misc virtual A/B state is "
                    + virtualAbFacts.State + " (format valid: " + virtualAbFacts.IsFormatValid
                    + "); no AfterUpdate maintenance may run before the OTA merge is Completed.");
            }

            string currentSlot = miscFacts.CurrentSlot;
            if (deviceFacts.AndroidCheck is not null
                && !string.Equals(
                    RequireCurrentSlot(deviceFacts.AndroidCheck), currentSlot, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    DeviceCheckIncompleteCode
                    + ": the Step 1 current slot does not match the freshly verified misc control slot.");
            }

            var tools = sources.BootTools
                ?? throw new ArgumentException(
                    "AfterUpdate preparation requires the verified boot tools.", nameof(sources));

            // The lock fact is only ever the live observed state; a historical backup never declares it.
            BootloaderState lockState =
                deviceFacts.AndroidCheck?.Android?.Identity.BootloaderState ?? BootloaderState.Unknown;

            // Same-epoch initialized inactive B proof: only when the active slot is A, the B boot image
            // itself is populated and every B Android ancillary region is entirely empty. The proof is
            // the builder's own native validation; it is never skipped, never faked, and its ownership
            // transfers to the authority exactly when the authority is created.
            const string captureSubject = "the current rollback capture";
            CurrentBootInitializedInactiveProof? initializedProof = null;
            CurrentBootAfterEpochWitness? afterEpochWitness = null;
            if (currentSlot == "a")
            {
                VerifiedEdlFile bootB = RegionClaim(ownedCurrent.Files, "boot_b", captureSubject);
                bool qualifyingShape =
                    !await EdlRawBootBuilder
                        .CurrentBootDetectEmptyAsync(bootB, cancellationToken)
                        .ConfigureAwait(false)
                    && await EdlRawBootBuilder
                        .CurrentBootDetectEmptyAsync(
                            RegionClaim(ownedCurrent.Files, "vendor_boot_b", captureSubject), cancellationToken)
                        .ConfigureAwait(false)
                    && await EdlRawBootBuilder
                        .CurrentBootDetectEmptyAsync(
                            RegionClaim(ownedCurrent.Files, "init_boot_b", captureSubject), cancellationToken)
                        .ConfigureAwait(false)
                    && await EdlRawBootBuilder
                        .CurrentBootDetectEmptyAsync(
                            RegionClaim(ownedCurrent.Files, "abl_b", captureSubject), cancellationToken)
                        .ConfigureAwait(false)
                    && await EdlRawBootBuilder
                        .CurrentBootDetectEmptyAsync(
                            RegionClaim(ownedCurrent.Files, "xbl_config_b", captureSubject), cancellationToken)
                        .ConfigureAwait(false);

                if (qualifyingShape)
                {
                    try
                    {
                        initializedProof = await EdlRawBootBuilder
                            .VerifyInitializedInactiveSlotAsync(
                                client.Toolchain.ProfileId,
                                currentSlot,
                                "b",
                                RegionClaim(ownedCurrent.Files, "boot_a", captureSubject),
                                RegionClaim(ownedCurrent.Files, "vendor_boot_a", captureSubject),
                                RegionClaim(ownedCurrent.Files, "init_boot_a", captureSubject),
                                RegionClaim(ownedCurrent.Files, "abl_a", captureSubject),
                                RegionClaim(ownedCurrent.Files, "xbl_config_a", captureSubject),
                                bootB,
                                RegionClaim(ownedCurrent.Files, "vendor_boot_b", captureSubject),
                                RegionClaim(ownedCurrent.Files, "init_boot_b", captureSubject),
                                RegionClaim(ownedCurrent.Files, "abl_b", captureSubject),
                                RegionClaim(ownedCurrent.Files, "xbl_config_b", captureSubject),
                                RegionClaim(ownedCurrent.Files, "vbmeta_a", captureSubject),
                                tools,
                                runner,
                                evidenceDirectory,
                                cancellationToken)
                            .ConfigureAwait(false);
                    }
                    catch (InvalidDataException exception) when (
                        string.Equals(
                            exception.Message,
                            "unpacked B BaseImage length differs from the exported source A base",
                            StringComparison.Ordinal)
                        || string.Equals(
                            exception.Message,
                            "unpacked B BaseImage is not exactly the exported source A base",
                            StringComparison.Ordinal))
                    {
                        // Exactly the two base-mismatch refusals mean the fresh B graph was built from the
                        // previous epoch's A. Only a verified first-install original backup can prove the
                        // old template basis; every other failure propagates untouched.
                        string? originalDirectory = sources.OriginalBackupDirectory;
                        if (string.IsNullOrWhiteSpace(originalDirectory))
                        {
                            throw new InvalidOperationException(
                                AfterTemplateEpochUnprovenCode
                                + ": a verified first-install original backup is required to prove the old B "
                                + "template basis after the A update; no candidate may be prepared.",
                                exception);
                        }

                        afterEpochWitness = await EdlRawBootBuilder
                            .VerifyAfterUpdateInactiveSlotAsync(
                                client,
                                ownedCurrent,
                                currentSlot,
                                originalDirectory,
                                tools,
                                runner,
                                evidenceDirectory,
                                cancellationToken)
                            .ConfigureAwait(false);
                    }
                }
            }

            InternalInstallPreparationContext.TfBootAuthority authority;
            try
            {
                if (afterEpochWitness is not null)
                {
                    authority = await InternalInstallPreparationContext
                        .PrepareAfterBootAuthorityAsync(
                            ownedCurrent,
                            currentSlot,
                            lockState,
                            evidenceDirectory,
                            afterEpochWitness,
                            cancellationToken)
                        .ConfigureAwait(false);
                }
                else if (initializedProof is not null)
                {
                    authority = await InternalInstallPreparationContext
                        .PrepareTfBootAuthorityAsync(
                            ownedCurrent,
                            currentSlot,
                            lockState,
                            evidenceDirectory,
                            initializedProof,
                            cancellationToken)
                        .ConfigureAwait(false);
                }
                else
                {
                    authority = await InternalInstallPreparationContext
                        .PrepareTfBootAuthorityAsync(
                            ownedCurrent, currentSlot, lockState, evidenceDirectory, cancellationToken)
                        .ConfigureAwait(false);
                }
            }
            catch
            {
                // Authority creation failed, so it never took ownership of either proof.
                try
                {
                    initializedProof?.Dispose();
                }
                catch (Exception)
                {
                }

                try
                {
                    afterEpochWitness?.Dispose();
                }
                catch (Exception)
                {
                }

                throw;
            }

            ownedResources.Add(authority);

            // Persist the epoch witness report durably in this backend's own evidence directory before any
            // later step can fail: the producer owns its internal children and may release them, so only
            // this copy is the durable proof. The receipt states provenance facts only; it never claims an
            // observed current firmware, a live lock state, or source-B OEM bootability.
            if (authority.AfterEpochWitness is not null)
            {
                CurrentBootAfterEpochWitness witness = authority.AfterEpochWitness;
                string witnessReportCopy = Path.Combine(evidenceDirectory, "after-epoch-witness.report.json");
                await CopyAfterFileAsync(
                        witness.VerificationReport,
                        witnessReportCopy,
                        "the after-update epoch witness verification report",
                        cancellationToken)
                    .ConfigureAwait(false);
                ownedResources.Add(OpenAfterReadLease(
                    witnessReportCopy, "the after-update epoch witness verification report copy"));

                WriteReceipt(evidenceDirectory, "after-epoch-witness", writer =>
                {
                    writer.WriteString("kind", "after-epoch-witness");
                    writer.WriteString("profileId", witness.ProfileId);
                    writer.WriteString("sourceSlot", witness.SourceSlot);
                    writer.WriteString("targetSlot", witness.TargetSlot);
                    writer.WriteString("originalBackupDirectory", witness.OriginalBackupDirectory);
                    writer.WriteString("originalBackupManifestSha256", witness.OriginalBackupManifestSha256);
                    writer.WriteString("currentBackupManifestSha256", witness.CurrentBackupManifestSha256);
                    writer.WriteString("templateBasisBaseSha256", witness.TemplateBasisBaseSha256);
                    writer.WriteString("freshBaseSha256", witness.ReconstructedBase.Sha256);
                    writer.WriteString("freshProjectRawSha256", witness.ProjectRaw.Sha256);
                    writer.WriteString("androidSourceSlot", "a");
                    writer.WriteString("templateTargetSlot", "b");
                    writer.WriteBoolean("isSameEpoch", witness.IsSameEpoch);
                    writer.WriteString("verificationReportSha256", witness.VerificationReport.Sha256);
                });
            }

            progress?.Report(new InternalInstallProgress(
                InternalInstallStage.Revalidating,
                InternalInstallProgressKind.Progress,
                InternalInstallWriteState.NoneIssued,
                currentSlot,
                0,
                1,
                "after-analyzing-current-slots"));

            var materialsBySource = new Dictionary<string, InternalSlotMaterial>(StringComparer.Ordinal);
            var baseBySource = new Dictionary<string, VerifiedEdlFile>(StringComparer.Ordinal);
            var currentTemplateBySlot = new Dictionary<string, VerifiedEdlFile>(StringComparer.Ordinal);

            // Only the unique actual Android source slots of the authority are analyzed and exported;
            // an unproven inactive slot is never a source and is never analyzed as one.
            string[] actualSources = authority.SourceSlots.Values
                .Distinct(StringComparer.Ordinal)
                .OrderBy(static slot => slot, StringComparer.Ordinal)
                .ToArray();
            foreach (string target in AfterSlots)
            {
                RequireAfterSource(authority, target);
            }

            // The epoch witness already exported and holds the fresh source-A material and base; reusing
            // them is required truth, never a second export into base-a.bin.
            foreach (string slot in actualSources)
            {
                cancellationToken.ThrowIfCancellationRequested();

                CurrentBootAfterEpochWitness? epochWitness = authority.AfterEpochWitness;
                if (epochWitness is not null && slot == "a")
                {
                    materialsBySource[slot] = epochWitness.SourceMaterial;
                    baseBySource[slot] = epochWitness.ReconstructedBase;
                    ownedResources.Add(OpenAfterReadLease(
                        epochWitness.ReconstructedBase.Path,
                        "the epoch witness exported Android base image of slot " + slot));

                    if (epochWitness.SourceMaterial.IsKshim)
                    {
                        currentTemplateBySlot[slot] = RegionClaim(
                            ownedCurrent.Files, "boot_" + slot, "the current rollback capture");
                    }
                }
                else
                {
                    InternalSlotMaterial material = await AnalyzeAfterSlotAsync(
                        ownedCurrent.Files,
                        slot,
                        "the current rollback capture",
                        Path.Combine(evidenceDirectory, "base-" + slot + ".bin"),
                        cancellationToken).ConfigureAwait(false);

                    materialsBySource[slot] = material;
                    var exportClaim = new VerifiedEdlFile(
                        Path.Combine(evidenceDirectory, "base-" + slot + ".bin"),
                        material.BaseImageLength,
                        material.BaseImageSha256);
                    ownedResources.Add(OpenAfterReadLease(
                        exportClaim.Path, "the exported Android base image of slot " + slot));
                    baseBySource[slot] = exportClaim;

                    // IsKshim is the analyzer's factual verdict, never a name substring.
                    if (material.IsKshim)
                    {
                        currentTemplateBySlot[slot] = RegionClaim(
                            ownedCurrent.Files, "boot_" + slot, "the current rollback capture");
                    }
                }
            }

            // A proven initialized inactive B — same-epoch proof or old-original epoch witness — carries
            // its own natively validated project graph: its boot image is its own menu template while
            // the Android source remains A.
            if (authority.InitializedInactiveProof is not null || authority.AfterEpochWitness is not null)
            {
                currentTemplateBySlot["b"] = RegionClaim(
                    ownedCurrent.Files, "boot_b", "the current rollback capture");
            }

            string? projectDirectory = sources.ProjectBackupDirectory;
            bool hasProjectSource = !string.IsNullOrWhiteSpace(projectDirectory);
            var historicalTemplateBySlot = new Dictionary<string, VerifiedEdlFile>(StringComparer.Ordinal);
            if (hasProjectSource)
            {
                source = await InternalInstallBackup
                    .OpenBootMaintenanceProjectTemplateAsync(client, ownedCurrent, projectDirectory, cancellationToken)
                    .ConfigureAwait(false);

                foreach (string slot in AfterSlots)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var historicalBoot = RegionClaim(
                        source.Files, "boot_" + slot, "the project template backup");
                    if (await EdlRawBootBuilder
                            .CurrentBootDetectEmptyAsync(historicalBoot, cancellationToken)
                            .ConfigureAwait(false))
                    {
                        continue;
                    }

                    InternalSlotMaterial material = await AnalyzeAfterSlotAsync(
                        source.Files,
                        slot,
                        "the project template backup",
                        Path.Combine(evidenceDirectory, "historical-base-" + slot + ".bin"),
                        cancellationToken).ConfigureAwait(false);

                    if (material.IsKshim)
                    {
                        historicalTemplateBySlot[slot] = historicalBoot;
                        ownedResources.Add(OpenAfterReadLease(
                            Path.Combine(evidenceDirectory, "historical-base-" + slot + ".bin"),
                            "the historical exported base image of slot " + slot));
                    }
                }
            }
            else
            {
                source = await InternalInstallBackup
                    .OpenExistingAsync(client, ownedCurrent.DirectoryPath, null, cancellationToken)
                    .ConfigureAwait(false);
            }

            var rawByTarget = new Dictionary<string, VerifiedEdlFile>(StringComparer.Ordinal);
            var templateSourceSlotByTarget = new Dictionary<string, string>(StringComparer.Ordinal);
            var templateReportShaByTarget = new Dictionary<string, string>(StringComparer.Ordinal);
            EdlRawPackageContract? contract = null;
            InstalledLinuxBootFacts? fallbackFacts = null;

            bool anyTemplate = currentTemplateBySlot.Count > 0 || historicalTemplateBySlot.Count > 0;
            if (anyTemplate)
            {
                foreach (string target in AfterSlots)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (!TryResolveAfterTemplateSlot(
                            target, currentTemplateBySlot, historicalTemplateBySlot, out string templateSlot))
                    {
                        throw new InvalidOperationException(
                            AfterTemplateRequiredCode + ": no current or historical project template exists "
                            + "for target slot '" + target + "'.");
                    }

                    string androidSource = RequireAfterSource(authority, target);
                    VerifiedEdlFile template = currentTemplateBySlot.TryGetValue(templateSlot, out VerifiedEdlFile? current_)
                        ? current_
                        : historicalTemplateBySlot[templateSlot];

                    var payload = await EdlRawBootBuilder
                        .ReplaceTemplateAndroidBaseAsync(
                            template,
                            baseBySource[androidSource],
                            materialsBySource[androidSource].LoaderBudget.MaxRawBytes,
                            tools,
                            runner,
                            evidenceDirectory,
                            cancellationToken)
                        .ConfigureAwait(false);
                    ownedResources.Add(payload);

                    string reportCopy = Path.Combine(evidenceDirectory, "template-report-" + target + ".json");
                    await CopyAfterFileAsync(
                            payload.VerificationReport, reportCopy,
                            "the template verification report of slot " + target, cancellationToken)
                        .ConfigureAwait(false);
                    templateReportShaByTarget[target] = payload.VerificationReport.Sha256;

                    rawByTarget[target] = payload.PackedRaw;
                    templateSourceSlotByTarget[target] = templateSlot;

                    progress?.Report(new InternalInstallProgress(
                        InternalInstallStage.Revalidating,
                        InternalInstallProgressKind.Progress,
                        InternalInstallWriteState.NoneIssued,
                        target,
                        1,
                        2,
                        "after-template-payload"));
                }
            }
            else
            {
                if (GetRepairFallbackTarget(ownedCurrent) != InstallationTarget.Internal)
                {
                    throw new InvalidOperationException(
                        AfterTemplateRequiredCode + ": no current or historical project template exists and the "
                        + "device is not the internal installation target, so no truthful AfterUpdate candidate "
                        + "source is available.");
                }

                var package = sources.RepairPackage
                    ?? throw new InvalidOperationException(
                        AfterRepairPackageRequiredCode + ": the internal fallback route requires the imported "
                        + "repair package because no project template exists.");

                if (!package.Validation.IsValid)
                {
                    throw new InvalidOperationException(
                        AfterRepairPackageRequiredCode + ": the imported repair package failed its own validation.");
                }

                DeviceIdentity identity = deviceFacts.Identity.Identity;
                if (!string.Equals(package.DeviceModel, identity.Model, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        AfterRepairPackageRequiredCode + ": the repair package device model does not match the "
                        + "verified device identity.");
                }

                contract = PackageReader.ReadEdlRawContract(
                    package.PackageDirectory, identity.Model, cancellationToken);

                if (!string.IsNullOrWhiteSpace(contract.EdlProfileId)
                    && !string.Equals(contract.EdlProfileId, client.Toolchain.ProfileId, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        FreshnessCode + ": the repair package EDL profile id does not match the trusted toolchain.");
                }

                if (!string.IsNullOrWhiteSpace(contract.HardwareId)
                    && !string.Equals(contract.HardwareId, client.Toolchain.HardwareId, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(
                        FreshnessCode + ": the repair package hardware id does not match the trusted toolchain.");
                }

                if (contract.FirmwareVersions is { Count: > 0 })
                {
                    string? observed = deviceFacts.AndroidCheck?.Android?.Identity.Firmware?.DisplayId;
                    if (observed is null
                        || !contract.FirmwareVersions.Contains(observed, StringComparer.Ordinal))
                    {
                        throw new InvalidOperationException(
                            FreshnessCode + ": the repair package firmware versions do not exactly contain the "
                            + "observed firmware; a historical backup with unknown firmware cannot grant membership.");
                    }
                }

                fallbackFacts = await BootMaintenanceInstalledLinux
                    .VerifyAsync(client, ownedCurrent, contract, evidenceDirectory, cancellationToken)
                    .ConfigureAwait(false);

                var builtBySource = new Dictionary<string, EdlRawBuiltBoot>(StringComparer.Ordinal);
                foreach (string androidSource in actualSources)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var request = new EdlRawBootBuildRequest(
                        androidSource,
                        RegionClaim(ownedCurrent.Files, "boot_" + androidSource, "the current rollback capture"),
                        RegionClaim(ownedCurrent.Files, "vendor_boot_" + androidSource, "the current rollback capture"),
                        RegionClaim(ownedCurrent.Files, "init_boot_" + androidSource, "the current rollback capture"),
                        RegionClaim(ownedCurrent.Files, "abl_" + androidSource, "the current rollback capture"),
                        RegionClaim(ownedCurrent.Files, "xbl_config_" + androidSource, "the current rollback capture"),
                        contract,
                        tools,
                        evidenceDirectory);

                    EdlRawBuiltBoot built = await EdlRawBootBuilder
                        .BuildAsync(request, runner, cancellationToken)
                        .ConfigureAwait(false);
                    ownedResources.Add(built);
                    builtBySource[androidSource] = built;
                }

                foreach (string target in AfterSlots)
                {
                    string androidSource = RequireAfterSource(authority, target);
                    rawByTarget[target] = builtBySource[androidSource].PackedRaw;
                    templateSourceSlotByTarget[target] = androidSource;
                }
            }

            var rawLengthsBySource = new Dictionary<string, long>(StringComparer.Ordinal);
            foreach (string target in AfterSlots)
            {
                string androidSource = RequireAfterSource(authority, target);
                long length = rawByTarget[target].Length;
                if (!rawLengthsBySource.TryGetValue(androidSource, out long existing) || length > existing)
                {
                    rawLengthsBySource[androidSource] = length;
                }
            }

            IReadOnlyDictionary<string, long> bounds = authority.RequireRuntimeRawBounds(
                materialsBySource, rawLengthsBySource, cancellationToken);
            await authority.RevalidateAsync(cancellationToken).ConfigureAwait(false);

            string inactiveSlot = currentSlot == "a" ? "b" : "a";
            var orderedTargets = new[] { inactiveSlot, currentSlot };

            var bootRegionByTarget = new Dictionary<string, PlannedRegion>(StringComparer.Ordinal);
            var slotSummaries = new List<BootMaintenanceSlotSummary>(2);
            var gblDigestMatchesByTarget = new Dictionary<string, bool>(StringComparer.Ordinal);

            foreach (string target in orderedTargets)
            {
                cancellationToken.ThrowIfCancellationRequested();

                string androidSource = RequireAfterSource(authority, target);
                VerifiedEdlFile raw = rawByTarget[target];
                EdlCapturedRegion targetRegion = RequireRegion(
                    ownedCurrent.Files, "boot_" + target, "the current rollback capture");

                // The envelope wrapper comes only from the fresh actual Android source's own boot when the
                // target differs from it or the target boot is entirely empty: a proven initialized B is
                // project data, never a stale prior-source wrapper to preserve if the OTA changed the
                // source key. The candidate still binds to the target region's real current hash above.
                bool useSourceEnvelope = target != androidSource
                    || await EdlRawBootBuilder
                        .CurrentBootDetectEmptyAsync(
                            RegionClaim(ownedCurrent.Files, "boot_" + target, captureSubject),
                            cancellationToken)
                        .ConfigureAwait(false);
                VerifiedEdlFile envelopeSourceBoot = RegionClaim(
                    ownedCurrent.Files,
                    "boot_" + (useSourceEnvelope ? androidSource : target),
                    captureSubject);

                string candidatePath = Path.Combine(
                    evidenceDirectory, "after-candidate-boot-" + target + ".img");
                VerifiedEdlFile candidate;
                bool contentDigestMatches = false;

                if (authority.UsesGbl)
                {
                    var gbl = await EdlRawBootBuilder
                        .RepackCurrentGblEnvelopeAsync(
                            envelopeSourceBoot, raw, bounds[androidSource], candidatePath, cancellationToken)
                        .ConfigureAwait(false);

                    if (!string.Equals(
                            gbl.Facts.PublicKeySha256,
                            authority.RequireGblParentBootKey(androidSource),
                            StringComparison.Ordinal))
                    {
                        throw new InvalidOperationException(
                            FreshnessCode + ": the preserved GBL envelope of slot " + target
                            + " was not signed by the authority's parent boot key.");
                    }

                    candidate = gbl.Candidate;
                    contentDigestMatches = gbl.Facts.ContentDigestMatches;
                }
                else
                {
                    EdlRawBootEnvelope envelope = await EdlRawBootBuilder
                        .RepackEnvelopeAsync(
                            envelopeSourceBoot, raw, bounds[androidSource], candidatePath, cancellationToken)
                        .ConfigureAwait(false);
                    candidate = envelope.CandidateBoot;
                }

                gblDigestMatchesByTarget[target] = contentDigestMatches;

                if (candidate.Length != targetRegion.Length)
                {
                    throw new InvalidOperationException(
                        PlanIncompleteCode + ": the AfterUpdate candidate boot of slot " + target + " is "
                        + candidate.Length + " bytes, not the real target region length " + targetRegion.Length + ".");
                }

                await RehashHeldFileAsync(
                        candidate.Path, candidate.Length, candidate.Sha256,
                        "AfterUpdate candidate boot of slot " + target, cancellationToken)
                    .ConfigureAwait(false);
                ownedResources.Add(OpenAfterReadLease(
                    candidate.Path, "the AfterUpdate candidate boot of slot " + target));

                bool willWrite = !string.Equals(
                    targetRegion.Sha256, candidate.Sha256, StringComparison.OrdinalIgnoreCase);

                bootRegionByTarget[target] = new PlannedRegion(
                    "boot_" + target,
                    target,
                    targetRegion.Lun,
                    targetRegion.StartSector,
                    targetRegion.SectorCount,
                    targetRegion.Length,
                    targetRegion.Sha256,
                    willWrite ? candidate.Path : null,
                    willWrite ? candidate.Sha256 : null);

                slotSummaries.Add(new BootMaintenanceSlotSummary(
                    target,
                    androidSource,
                    BootMaintenanceSourceKind.Project,
                    RegionClaim(ownedCurrent.Files, "boot_" + androidSource, "the current rollback capture").Sha256,
                    candidate.Sha256,
                    willWrite));

                string candidateShaForReceipt = candidate.Sha256;
                string rawShaForReceipt = raw.Sha256;
                string baseShaForReceipt = baseBySource[androidSource].Sha256;
                WriteReceipt(evidenceDirectory, "after-slot-" + target, writer =>
                {
                    writer.WriteString("kind", "after-slot");
                    writer.WriteString("target", target);
                    writer.WriteString("androidSourceSlot", androidSource);
                    writer.WriteString("templateSourceSlot", templateSourceSlotByTarget[target]);
                    writer.WriteString("currentSha256", targetRegion.Sha256);
                    if (willWrite)
                    {
                        writer.WriteString("candidateSha256", candidateShaForReceipt);
                    }
                    else
                    {
                        writer.WriteNull("candidateSha256");
                    }

                    writer.WriteString("rawSha256", rawShaForReceipt);
                    writer.WriteString("newBaseSha256", baseShaForReceipt);
                    writer.WriteBoolean("usesGbl", authority.UsesGbl);
                    if (authority.UsesGbl)
                    {
                        writer.WriteBoolean("gblContentDigestMatches", gblDigestMatchesByTarget[target]);
                    }

                    writer.WriteBoolean("willWrite", willWrite);
                });

                progress?.Report(new InternalInstallProgress(
                    InternalInstallStage.Revalidating,
                    InternalInstallProgressKind.Progress,
                    InternalInstallWriteState.NoneIssued,
                    target,
                    2,
                    2,
                    "after-candidate-envelope"));
            }

            var avbByRole = new Dictionary<string, (VerifiedEdlFile Original, VerifiedEdlFile? Candidate)>(
                StringComparer.Ordinal);
            foreach (var node in authority.AvbNodes)
            {
                if (!avbByRole.TryAdd(
                        node.Role, (node.Node.Original, node.Node.Candidate)))
                {
                    throw new InvalidOperationException(
                        PlanIncompleteCode + ": the TF boot authority declared duplicate AVB role '"
                        + node.Role + "'.");
                }
            }

            var companionByRole = new Dictionary<string, PlannedRegion>(StringComparer.Ordinal);
            PlannedRegion? efispRegion = null;
            if (authority.EfispCandidate is not null)
            {
                EdlCapturedRegion efispCurrent = RequireRegion(
                    ownedCurrent.Files, "efisp", "the current rollback capture");
                if (efispCurrent.Lun != 4)
                {
                    throw new InvalidOperationException(
                        PlanIncompleteCode + ": the efisp capture is on LUN" + efispCurrent.Lun + ", not LUN4.");
                }

                efispRegion = await BuildAfterCompanionRegionAsync(
                    "efisp", null, efispCurrent, authority.EfispCandidate,
                    evidenceDirectory, ownedResources, cancellationToken).ConfigureAwait(false);
            }

            foreach (string slot in orderedTargets)
            {
                foreach (string prefix in AfterAvbRolePrefixes)
                {
                    string role = prefix + slot;
                    if (!avbByRole.TryGetValue(role, out (VerifiedEdlFile Original, VerifiedEdlFile? Candidate) entry))
                    {
                        continue;
                    }

                    EdlCapturedRegion fresh = RequireRegion(
                        ownedCurrent.Files, role, "the current rollback capture");
                    if (!string.Equals(entry.Original.Path, fresh.FilePath, StringComparison.OrdinalIgnoreCase)
                        || entry.Original.Length != fresh.Length
                        || !string.Equals(entry.Original.Sha256, fresh.Sha256, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException(
                            FreshnessCode + ": the TF authority's original claim for '" + role
                            + "' does not match the freshly read back capture.");
                    }

                    companionByRole[role] = await BuildAfterCompanionRegionAsync(
                        role, slot, fresh, entry.Candidate,
                        evidenceDirectory, ownedResources, cancellationToken).ConfigureAwait(false);
                }
            }

            foreach (string role in avbByRole.Keys)
            {
                bool whitelisted = AfterAvbRolePrefixes.Any(prefix =>
                    role == prefix + "a" || role == prefix + "b");
                if (!whitelisted)
                {
                    throw new InvalidOperationException(
                        PlanIncompleteCode + ": the TF boot authority declared AVB role '" + role
                        + "' outside the boot/recovery/vbmeta/efisp whitelist; no such write may be planned.");
                }
            }

            var plan = new List<PlannedRegion>();
            if (efispRegion is not null)
            {
                plan.Add(efispRegion);
            }

            foreach (string slot in orderedTargets)
            {
                plan.Add(bootRegionByTarget[slot]);
                foreach (string prefix in AfterAvbRolePrefixes)
                {
                    if (companionByRole.TryGetValue(prefix + slot, out PlannedRegion? companion))
                    {
                        plan.Add(companion);
                    }
                }
            }

            ValidateAfterPlan(plan);

            DeviceIdentity preparedIdentity = deviceFacts.Identity.Identity;
            string bindingTag = contract is not null
                ? "pkg=" + contract.ManifestFingerprint
                : "tpl=" + string.Join(";", templateReportShaByTarget
                    .OrderBy(static pair => pair.Key, StringComparer.Ordinal)
                    .Select(static pair => pair.Key + ":" + pair.Value));
            if (authority.AfterEpochWitness is not null)
            {
                bindingTag += ";epoch=" + authority.AfterEpochWitness.VerificationReport.Sha256;
            }
            string preparationId = Path.GetFileName(evidenceDirectory) + "+" + bindingTag;

            string confirmationSha256 = BuildConfirmationSha256(
                MaintenanceMode.AfterUpdate,
                deviceFacts,
                client,
                miscFacts.ControlSha256,
                currentSlot,
                ownedCurrent.ManifestSha256,
                source.ManifestSha256,
                ownedCurrent.Geometries,
                plan,
                preparationId);

            var regionSummaries = new List<BootMaintenanceRegionSummary>(plan.Count);
            foreach (PlannedRegion region in plan)
            {
                regionSummaries.Add(new BootMaintenanceRegionSummary(
                    region.Role,
                    region.Slot,
                    region.Lun,
                    region.StartSector,
                    region.SectorCount,
                    region.Length,
                    region.CurrentSha256,
                    region.CandidateSha256,
                    region.WillWrite));
            }

            BootMaintenancePrepared prepared = new(
                MaintenanceMode.AfterUpdate,
                confirmationSha256,
                preparedIdentity.Model,
                preparedIdentity.Serial,
                deviceFacts.Identity.SocSerial,
                currentSlot,
                ownedCurrent.DirectoryPath,
                evidenceDirectory,
                authority.UsesGbl ? BootMaintenanceBootTrust.GblPreserveOem : BootMaintenanceBootTrust.AospResigned,
                slotSummaries,
                regionSummaries);

            WritePrepareReceipt(evidenceDirectory, MaintenanceMode.AfterUpdate, prepared, plan.Count);
            WriteIdentityContextReceipt(
                evidenceDirectory,
                deviceFacts,
                client,
                RegionClaim(ownedCurrent.Files, "misc", "the current rollback capture").Sha256,
                miscFacts.ControlSha256,
                currentSlot);

            progress?.Report(new InternalInstallProgress(
                InternalInstallStage.Prepared,
                InternalInstallProgressKind.Verified,
                InternalInstallWriteState.NoneIssued,
                currentSlot,
                plan.Count,
                plan.Count,
                "boot-maintenance-after-prepared"));

            BootMaintenanceBackend backend = new(
                MaintenanceMode.AfterUpdate,
                deviceFacts,
                miscFacts.ControlSha256,
                client,
                runner,
                currentBackup,
                ownedCurrent,
                source,
                plan,
                slotSummaries,
                currentSlot,
                evidenceDirectory,
                confirmationSha256,
                prepared,
                ownedResources);

            backend._afterAuthority = authority;
            if (contract is not null && fallbackFacts is not null)
            {
                backend._afterFallbackContract = contract;
                backend._afterFallbackFacts = fallbackFacts;
            }

            return backend;
        }
        catch
        {
            foreach (IDisposable owned in ownedResources)
            {
                try
                {
                    owned.Dispose();
                }
                catch (Exception)
                {
                }
            }

            if (source is not null)
            {
                try
                {
                    source.Dispose();
                }
                catch (Exception)
                {
                }
            }

            if (ownedCurrent is not null)
            {
                try
                {
                    ownedCurrent.Dispose();
                }
                catch (Exception)
                {
                }
            }

            throw;
        }
    }

    /// <summary>
    /// The pre-execution revalidation of the AfterUpdate inputs: the TF boot authority is always
    /// revalidated, and the fallback route re-verifies the installed Linux facts into a fresh evidence
    /// child and compares them exactly before any write may be issued.
    /// </summary>
    private async Task RevalidateAfterInputsAsync(CancellationToken cancellationToken)
    {
        InternalInstallPreparationContext.TfBootAuthority authority = _afterAuthority
            ?? throw new InvalidOperationException(
                "The AfterUpdate backend carries no TF boot authority; it was not created by the factory.");

        await authority.RevalidateAsync(cancellationToken).ConfigureAwait(false);

        if (_afterFallbackContract is null && _afterFallbackFacts is null)
        {
            return;
        }

        if (_afterFallbackContract is null || _afterFallbackFacts is null)
        {
            throw new InvalidOperationException(
                "The AfterUpdate fallback state is incomplete; contract and installed facts must exist together.");
        }

        string recheckDirectory = Path.Combine(
            _evidenceDirectory, "after-recheck-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(recheckDirectory);

        InstalledLinuxBootFacts fresh = await BootMaintenanceInstalledLinux
            .VerifyAsync(_client, _ownedCurrent, _afterFallbackContract, recheckDirectory, cancellationToken)
            .ConfigureAwait(false);

        InstalledLinuxBootFacts prepared = _afterFallbackFacts;
        bool same = fresh.BootUuid == prepared.BootUuid
            && fresh.RootUuid == prepared.RootUuid
            && string.Equals(fresh.SelectedEntryPath, prepared.SelectedEntryPath, StringComparison.Ordinal)
            && string.Equals(fresh.BootChecksum, prepared.BootChecksum, StringComparison.Ordinal)
            && string.Equals(fresh.KernelSha256, prepared.KernelSha256, StringComparison.Ordinal)
            && string.Equals(fresh.InitramfsSha256, prepared.InitramfsSha256, StringComparison.Ordinal);

        if (!same)
        {
            throw new InvalidOperationException(
                FreshnessCode + ": the freshly verified installed Linux facts no longer match the prepared "
                + "fallback facts; no write may be issued.");
        }
    }

    // ------------------------------------------------------------------ AfterUpdate helpers

    private static async Task<InternalSlotMaterial> AnalyzeAfterSlotAsync(
        IReadOnlyDictionary<string, EdlCapturedRegion> files,
        string slot,
        string subject,
        string exportPath,
        CancellationToken cancellationToken)
    {
        return await InternalSlotMaterialReader
            .AnalyzeAndExportBaseAsync(
                slot,
                RegionClaim(files, "boot_" + slot, subject),
                RegionClaim(files, "vendor_boot_" + slot, subject),
                RegionClaim(files, "init_boot_" + slot, subject),
                RegionClaim(files, "abl_" + slot, subject),
                RegionClaim(files, "xbl_config_" + slot, subject),
                exportPath,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static string RequireAfterSource(
        InternalInstallPreparationContext.TfBootAuthority authority, string target)
    {
        if (!authority.SourceSlots.TryGetValue(target, out string? source) || source is not ("a" or "b"))
        {
            throw new InvalidOperationException(
                PlanIncompleteCode + ": the TF boot authority carries no a/b Android source for target slot '"
                + target + "'.");
        }

        return source;
    }

    private static bool TryResolveAfterTemplateSlot(
        string target,
        Dictionary<string, VerifiedEdlFile> currentTemplates,
        Dictionary<string, VerifiedEdlFile> historicalTemplates,
        out string templateSlot)
    {
        string other = target == "a" ? "b" : "a";
        if (currentTemplates.ContainsKey(target))
        {
            templateSlot = target;
            return true;
        }

        if (historicalTemplates.ContainsKey(target))
        {
            templateSlot = target;
            return true;
        }

        if (currentTemplates.ContainsKey(other))
        {
            templateSlot = other;
            return true;
        }

        if (historicalTemplates.ContainsKey(other))
        {
            templateSlot = other;
            return true;
        }

        templateSlot = string.Empty;
        return false;
    }

    private static async Task<PlannedRegion> BuildAfterCompanionRegionAsync(
        string role,
        string? slot,
        EdlCapturedRegion fresh,
        VerifiedEdlFile? candidate,
        string evidenceDirectory,
        List<IDisposable> ownedResources,
        CancellationToken cancellationToken)
    {
        if (candidate is null
            || string.Equals(candidate.Sha256, fresh.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            return new PlannedRegion(
                role, slot, fresh.Lun, fresh.StartSector, fresh.SectorCount, fresh.Length,
                fresh.Sha256, null, null);
        }

        if (candidate.Length != fresh.Length)
        {
            throw new InvalidOperationException(
                PlanIncompleteCode + ": the '" + role + "' candidate is " + candidate.Length
                + " bytes, not the fresh region length " + fresh.Length + ".");
        }

        string destination = Path.Combine(evidenceDirectory, "after-candidate-" + role + ".bin");
        await CopyAfterFileAsync(candidate, destination, "the '" + role + "' candidate", cancellationToken)
            .ConfigureAwait(false);
        ownedResources.Add(OpenAfterReadLease(destination, "the '" + role + "' candidate"));

        return new PlannedRegion(
            role, slot, fresh.Lun, fresh.StartSector, fresh.SectorCount, fresh.Length,
            fresh.Sha256, destination, candidate.Sha256);
    }

    private static void ValidateAfterPlan(IReadOnlyList<PlannedRegion> plan)
    {
        if (plan.Count == 0)
        {
            throw new InvalidOperationException(
                PlanIncompleteCode + ": the AfterUpdate preparation produced no truthful planned region.");
        }

        var seenRoles = new HashSet<string>(StringComparer.Ordinal);
        for (int left = 0; left < plan.Count; left++)
        {
            PlannedRegion region = plan[left];
            bool allowed = region.Role
                is "boot_a" or "boot_b"
                or "recovery_a" or "recovery_b"
                or "vbmeta_system_a" or "vbmeta_system_b"
                or "vbmeta_a" or "vbmeta_b"
                or "efisp";
            if (!allowed)
            {
                throw new InvalidOperationException(
                    PlanIncompleteCode + ": planned role '" + region.Role
                    + "' is outside the AfterUpdate whitelist; no ABL, xbl, GPT, misc, userdata, root or "
                    + "other write may be planned.");
            }

            if (region.Role == "efisp")
            {
                if (region.Lun != 4 || region.Slot is not null)
                {
                    throw new InvalidOperationException(
                        PlanIncompleteCode + ": the efisp plan entry must sit on LUN4 with no slot label.");
                }
            }
            else if (region.Slot is not ("a" or "b"))
            {
                throw new InvalidOperationException(
                    PlanIncompleteCode + ": planned role '" + region.Role + "' carries no real a/b slot.");
            }

            if (!seenRoles.Add(region.Role))
            {
                throw new InvalidOperationException(
                    PlanIncompleteCode + ": the AfterUpdate plan contains duplicate role '" + region.Role + "'.");
            }

            for (int right = left + 1; right < plan.Count; right++)
            {
                PlannedRegion other = plan[right];
                if (region.Lun != other.Lun)
                {
                    continue;
                }

                long regionEnd = region.StartSector + region.SectorCount;
                long otherEnd = other.StartSector + other.SectorCount;
                if (region.StartSector < otherEnd && other.StartSector < regionEnd)
                {
                    throw new InvalidOperationException(
                        PlanIncompleteCode + ": planned roles '" + region.Role + "' and '" + other.Role
                        + "' overlap on LUN" + region.Lun + ".");
                }
            }
        }
    }

    private static async Task CopyAfterFileAsync(
        VerifiedEdlFile claim,
        string destinationPath,
        string subject,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        using FileStream source = new(
            claim.Path, FileMode.Open, FileAccess.Read, FileShare.Read, AfterCopyChunkBytes, FileOptions.SequentialScan);
        if (source.Length != claim.Length)
        {
            throw new InvalidOperationException(
                FreshnessCode + ": " + subject + " is " + source.Length + " bytes, not the claimed "
                + claim.Length + ".");
        }

        using FileStream output = new(
            destinationPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, AfterCopyChunkBytes);
        var buffer = new byte[AfterCopyChunkBytes];
        using IncrementalHash hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        int read;
        while ((read = await source.ReadAsync(buffer.AsMemory(0, AfterCopyChunkBytes), cancellationToken)
            .ConfigureAwait(false)) > 0)
        {
            output.Write(buffer, 0, read);
            hasher.AppendData(buffer, 0, read);
            cancellationToken.ThrowIfCancellationRequested();
        }

        output.Flush(true);

        string actual = Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
        if (output.Length != claim.Length
            || !string.Equals(actual, claim.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException(subject + " failed its durable copy hash check.");
        }
    }

    private static FileStream OpenAfterReadLease(string path, string subject)
    {
        try
        {
            return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, AfterCopyChunkBytes);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new IOException(subject + " cannot be reopened as a held read lease.", exception);
        }
    }
}
