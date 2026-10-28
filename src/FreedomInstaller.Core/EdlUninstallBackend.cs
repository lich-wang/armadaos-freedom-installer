using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// The only external inputs of the userdata-only uninstall: the original primary and
/// backup GPT files. No stock boot, vbmeta baseline or slot asset exists any more.
/// <para>
/// The paths must be copied from a verified <see cref="UninstallOriginalGptBackup"/>
/// via <see cref="FromVerifiedBackup(UninstallOriginalGptBackup)"/>; the backup is then
/// retained as internal provenance for the uninstall evidence.
/// </para>
/// </summary>
public sealed record UninstallGptAssets(string OriginalPrimaryGptPath, string OriginalBackupGptPath)
{
    /// <summary>
    /// The verified original backup this asset was derived from, or null when the
    /// assets were constructed directly. The uninstall evidence path requires it.
    /// </summary>
    internal UninstallOriginalGptBackup? OriginalBackup { get; private init; }

    /// <summary>
    /// Derives the assets from a verified original backup. The source paths are copied
    /// from the backup's own captured GPT regions; no supplied replacements are taken.
    /// </summary>
    public static UninstallGptAssets FromVerifiedBackup(UninstallOriginalGptBackup backup)
    {
        ArgumentNullException.ThrowIfNull(backup);

        return new UninstallGptAssets(backup.PrimaryGpt.FilePath, backup.BackupGpt.FilePath)
        {
            OriginalBackup = backup,
        };
    }
}

/// <summary>
/// C002 prepared EDL uninstall backend for the fixed operation
/// "remove-linux-preserve-boot".
///
/// The factory stages the two original GPT files, takes one fresh three-region capture of
/// LUN0 (primary GPT, backup GPT and the whole actual misc partition), drives the bundled
/// GPT Python bridge, validates every byte and range it claims, and pins the result
/// durably with read locks. No member here writes to a device, resets one, touches
/// Android or runs a shell; all device writes belong to ReclaimAndroidSpaceAsync and
/// InitializeAndroidAsync.
/// </summary>
public sealed partial class EdlUninstallBackend : IUserdataUninstallBackend, IDisposable
{
    private const int FileBufferBytes = 64 * 1024;
    private const int BridgeTimeoutSeconds = 120;
    private const int ManifestSchemaVersion = 1;
    private const int BcbBytes = 2048;

    // The fixed operation this backend is prepared for; it is part of every digest.
    private const string Operation = "remove-linux-preserve-boot";

    // The capture role order is frozen by EdlUninstallCapture; re-listing it here keeps the
    // reinspection comparison and the manifest independent of dictionary enumeration order.
    private static readonly string[] CaptureRoleOrder =
    {
        "gpt_lun0_primary",
        "gpt_lun0_backup",
        "misc",
    };

    private static readonly string[] GptRegionRoleOrder =
    {
        "backup-array",
        "backup-header",
        "primary-array",
        "primary-header",
    };

    private readonly EdlClient _client;
    private readonly EdlToolchain _tools;
    private readonly EdlEntryResult _binding;
    private readonly DeviceIdentity _identity;
    private readonly EdlUninstallCapture _capture;
    private readonly GptPlanEvidence _plan;
    private readonly ValidatedUninstallInputs _inputs;
    private readonly UserdataUninstallSnapshot _snapshot;
    private readonly string _backupDirectory;
    private readonly string _planFingerprint;
    private readonly IReadOnlyList<PinnedFile> _pinnedFiles;
    private readonly List<FileStream> _locks;
    private readonly CurrentMenuEvidence? _currentMenu;
    private readonly IProgress<EdlUninstallProgress>? _progress;
    private int _disposed;
    private int _poisoned;
    private StepState _step;

    private EdlUninstallBackend(
        EdlClient client,
        EdlToolchain tools,
        EdlEntryResult binding,
        DeviceIdentity identity,
        EdlUninstallCapture capture,
        GptPlanEvidence plan,
        ValidatedUninstallInputs inputs,
        UserdataUninstallSnapshot snapshot,
        string backupDirectory,
        string planFingerprint,
        IReadOnlyList<PinnedFile> pinnedFiles,
        List<FileStream> locks,
        CurrentMenuEvidence? currentMenu = null,
        IProgress<EdlUninstallProgress>? progress = null)
    {
        _client = client;
        _tools = tools;
        _binding = binding;
        _identity = identity;
        _capture = capture;
        _plan = plan;
        _inputs = inputs;
        _snapshot = snapshot;
        _backupDirectory = backupDirectory;
        _planFingerprint = planFingerprint;
        _pinnedFiles = pinnedFiles;
        _locks = locks;
        _currentMenu = currentMenu;
        _progress = progress;
        _step = StepState.Prepared;
    }

    public UserdataUninstallSnapshot Snapshot => _snapshot;

    public string PlanFingerprint => _planFingerprint;

    public string BackupDirectory => _backupDirectory;

    public ValidatedUninstallInputs Inputs => _inputs;

    // Factual current-menu context: null exactly on the legacy route. These are
    // get-only descriptions, never writable readiness or allow flags.
    public string? CurrentSlot => _currentMenu?.CurrentSlot;

    public string? CurrentBackupDirectory => _currentMenu?.CurrentBackupDirectory;

    public string? OriginalBackupDirectory => _currentMenu?.OriginalBackupDirectory;

    public VerifiedEdlFile? CurrentMenuVerificationReport => _currentMenu?.Report;

    public int MenuWriteCount => _currentMenu?.WriteTargets.Count ?? 0;

    // -----------------------------------------------------------------
    // Factory
    // -----------------------------------------------------------------

    /// <summary>
    /// The original legacy seven-argument factory. Its public signature is frozen;
    /// it forwards to the shared private core with no current-menu context and no
    /// progress observer. The new UI never routes through this overload.
    /// </summary>
    public static Task<EdlUninstallBackend> CreatePreparedAsync(
        EdlClient client,
        EdlToolchain tools,
        EdlEntryResult binding,
        UninstallGptAssets assets,
        string workRoot,
        ICommandRunner runner,
        CancellationToken token = default)
    {
        return CreatePreparedCoreAsync(
            client, tools, binding, assets, workRoot, runner,
            currentBackup: null, menuPlan: null, actualCurrentSlot: null,
            progress: null, token);
    }

    /// <summary>
    /// The standard fresh/menu factory: requires the verified original backup
    /// provenance, the loaded current backup set, the prepared boot menu plan and
    /// the actual current slot, plus an optional factual progress observer.
    /// </summary>
    public static Task<EdlUninstallBackend> CreatePreparedAsync(
        EdlClient client,
        EdlToolchain tools,
        EdlEntryResult binding,
        UninstallGptAssets assets,
        InternalBackupSet currentBackup,
        CurrentBootMenuPlan menuPlan,
        string actualCurrentSlot,
        string workRoot,
        ICommandRunner runner,
        IProgress<EdlUninstallProgress>? progress = null,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(currentBackup);
        ArgumentNullException.ThrowIfNull(menuPlan);
        ArgumentNullException.ThrowIfNull(actualCurrentSlot);

        if (!string.Equals(actualCurrentSlot, "a", StringComparison.Ordinal) &&
            !string.Equals(actualCurrentSlot, "b", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The reported current slot '" + actualCurrentSlot + "' is not exactly 'a' or 'b'.");
        }

        return CreatePreparedCoreAsync(
            client, tools, binding, assets, workRoot, runner,
            currentBackup, menuPlan, actualCurrentSlot,
            progress, token);
    }

    private static async Task<EdlUninstallBackend> CreatePreparedCoreAsync(
        EdlClient client,
        EdlToolchain tools,
        EdlEntryResult binding,
        UninstallGptAssets assets,
        string workRoot,
        ICommandRunner runner,
        InternalBackupSet? currentBackup,
        CurrentBootMenuPlan? menuPlan,
        string? actualCurrentSlot,
        IProgress<EdlUninstallProgress>? progress,
        CancellationToken token)
    {
        if (client is null)
        {
            throw new ArgumentNullException(nameof(client));
        }

        if (tools is null)
        {
            throw new ArgumentNullException(nameof(tools));
        }

        if (binding is null)
        {
            throw new ArgumentNullException(nameof(binding));
        }

        if (assets is null)
        {
            throw new ArgumentNullException(nameof(assets));
        }

        if (runner is null)
        {
            throw new ArgumentNullException(nameof(runner));
        }

        // The standard route requires the whole menu context or none of it.
        bool standard = currentBackup is not null || menuPlan is not null
            || actualCurrentSlot is not null;
        if (standard)
        {
            if (currentBackup is null || menuPlan is null || actualCurrentSlot is null)
            {
                throw new ArgumentException(
                    "The standard uninstall route requires the current backup, the menu plan and the actual slot together.");
            }

            // Typed provenance is mandatory on the standard route before any device
            // or durable work begins.
            if (assets.OriginalBackup is null)
            {
                throw new InvalidOperationException(
                    "The standard uninstall route requires the assets to carry verified original backup " +
                    "provenance; derive them with " + nameof(UninstallGptAssets.FromVerifiedBackup) + ".");
            }
        }

        SafeReportStage(progress, Stages.Preparing);

        if (string.IsNullOrWhiteSpace(workRoot))
        {
            throw new ArgumentException("A durable work root is required.", nameof(workRoot));
        }

        token.ThrowIfCancellationRequested();

        // The preparation must run on the very session that was probed: no foreign
        // toolchain, no substituted entry result, no second device identity.
        if (!ReferenceEquals(client.Toolchain, tools))
        {
            throw new InvalidOperationException(
                "The client was not built from the supplied toolchain; a foreign toolchain instance is rejected.");
        }

        if (!Equals(client.Binding, binding))
        {
            throw new InvalidOperationException(
                "The binding is not the client's own entry result; a substituted binding is rejected.");
        }

        string python = RequireToolPath(tools.PythonPath, "python executable");
        string gptCli = RequireToolPath(tools.GptCliPath, "GPT bridge");

        if (string.IsNullOrWhiteSpace(tools.Model))
        {
            throw new InvalidOperationException(
                "The toolchain carries no supported model; the plan cannot be bound to a device.");
        }

        DeviceIdentity identity = binding.AndroidIdentity.Identity;
        if (identity is null)
        {
            throw new InvalidOperationException("The entry result carries no device identity.");
        }

        // The actual model is a real public property of the identity; it only has to
        // corroborate the toolchain value, and the toolchain value is never substituted.
        if (!string.IsNullOrWhiteSpace(identity.Model)
            && !string.Equals(identity.Model, tools.Model, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The toolchain model '" + tools.Model + "' does not match the actual device model '" + identity.Model + "'.");
        }

        // Only the two original GPT files are external inputs; a missing or empty path
        // fails before anything durable is created.
        string originalPrimarySource = RequireExistingFile(assets.OriginalPrimaryGptPath, "original primary GPT");
        string originalBackupSource = RequireExistingFile(assets.OriginalBackupGptPath, "original backup GPT");

        string root = Path.GetFullPath(workRoot);
        if (File.Exists(root))
        {
            throw new IOException("The work root '" + root + "' is a file, not a directory.");
        }

        Directory.CreateDirectory(root);

        string backupDirectory;
        do
        {
            backupDirectory = Path.Combine(root, "edl-uninstall-" + Guid.NewGuid().ToString("N"));
        }
        while (Directory.Exists(backupDirectory) || File.Exists(backupDirectory));

        Directory.CreateDirectory(backupDirectory);

        // Durable backups must never live inside the toolchain's disposable staging area.
        string staging = string.IsNullOrWhiteSpace(tools.StagingDirectory)
            ? string.Empty
            : Path.GetFullPath(tools.StagingDirectory);

        if (staging.Length > 0 && IsSameOrUnder(backupDirectory, staging))
        {
            throw new InvalidOperationException(
                "The backup directory would live inside the toolchain staging area '" + staging +
                "'; durable backups cannot be kept there.");
        }

        var locks = new List<FileStream>();
        var pinned = new List<PinnedFile>();
        EdlUninstallCapture? capture = null;

        try
        {
            string captureDirectory = Path.Combine(backupDirectory, "capture-initial");
            capture = await EdlUninstallCapture
                .CaptureAsync(client, tools, binding, captureDirectory, token)
                .ConfigureAwait(false);

            if (!Equals(capture.Binding, binding))
            {
                throw new InvalidOperationException(
                    "The fresh capture is not bound to the probed entry result.");
            }

            foreach (string role in CaptureRoleOrder)
            {
                if (!capture.Regions.TryGetValue(role, out EdlCapturedRegion? region) || region is null)
                {
                    throw new InvalidOperationException(
                        "The fresh capture is missing the '" + role + "' range.");
                }

                pinned.Add(new PinnedFile("capture:" + role, region.FilePath, region.Length, region.Sha256));
            }

            // The standard fresh/menu route prepares the durable current-menu evidence
            // before any GPT processing; the legacy route performs no current-menu work.
            CurrentMenuEvidence? currentMenu = null;
            if (currentBackup is not null && menuPlan is not null)
            {
                SafeReportStage(progress, Stages.PreflightMenu);
                currentMenu = await PrepareCurrentMenuAsync(
                    client, binding, assets, currentBackup, menuPlan, actualCurrentSlot!,
                    capture, backupDirectory, locks, pinned, token)
                    .ConfigureAwait(false);
            }

            string assetsDirectory = Path.Combine(backupDirectory, "assets");
            Directory.CreateDirectory(assetsDirectory);

            // Only the two original GPT files are staged; their bytes are streamed,
            // hashed, flushed durably and then locked read-only. The standard route
            // already carries verified provenance, so it pins the exact expected
            // length/hash; the legacy route has none and stages with no expectation.
            UninstallOriginalGptBackup? provenance = assets.OriginalBackup;
            StagedFile stagedPrimary = Stage(
                originalPrimarySource, Path.Combine(assetsDirectory, "original_primary_gpt.bin"),
                "original_primary_gpt",
                provenance?.PrimaryGpt.Length ?? -1,
                provenance?.PrimaryGpt.Sha256,
                token);
            AddStaged(stagedPrimary, locks, pinned);

            StagedFile stagedBackup = Stage(
                originalBackupSource, Path.Combine(assetsDirectory, "original_backup_gpt.bin"),
                "original_backup_gpt",
                provenance?.BackupGpt.Length ?? -1,
                provenance?.BackupGpt.Sha256,
                token);
            AddStaged(stagedBackup, locks, pinned);

            // The original GPT pair is parsed with the geometry the device actually
            // reported; there is no fabricated disk path and no sfdisk involvement.
            EdlGeometry lun0 = capture.Lun0Geometry;

            long diskBytes;
            try
            {
                diskBytes = checked(lun0.TotalSectors * lun0.SectorSize);
            }
            catch (OverflowException)
            {
                throw new InvalidOperationException(
                    "LUN0 reported a disk size that overflows a 64-bit byte count.");
            }

            byte[] originalPrimaryBytes = File.ReadAllBytes(stagedPrimary.Path);
            byte[] originalBackupBytes = File.ReadAllBytes(stagedBackup.Path);

            GptTable? originalTable = OriginalGptImporter.Parse(
                originalPrimaryBytes, originalBackupBytes, lun0.SectorSize, diskBytes);

            if (originalTable is null)
            {
                throw new InvalidOperationException("The staged original GPT pair could not be parsed.");
            }

            if (originalTable.SectorSize != lun0.SectorSize || originalTable.DiskBytes != diskBytes)
            {
                throw new InvalidOperationException(
                    "The staged original GPT pair describes a different geometry than the device.");
            }

            ValidatedUninstallInputs? inputs = UninstallEvidenceValidator.ValidateEdl(
                identity, originalTable, capture.Lun0Table, 0);

            if (inputs is null)
            {
                throw new InvalidOperationException(
                    "The EDL evidence validator returned no validated uninstall inputs.");
            }

            if (!Equals(inputs.Identity, identity))
            {
                throw new InvalidOperationException(
                    "The validated inputs belong to a different device identity.");
            }

            if (inputs.Plan is null)
            {
                throw new InvalidOperationException(
                    "The EDL evidence validator returned no Android restore plan.");
            }

            if (inputs.Record is null)
            {
                throw new InvalidOperationException(
                    "The EDL evidence validator returned no installation record.");
            }

            string requestsDirectory = Path.Combine(backupDirectory, "requests");
            string evidenceDirectory = Path.Combine(backupDirectory, "evidence");
            Directory.CreateDirectory(requestsDirectory);
            Directory.CreateDirectory(evidenceDirectory);

            string gptOutputDirectory = Path.Combine(backupDirectory, "gpt-plan");
            if (Directory.Exists(gptOutputDirectory) || File.Exists(gptOutputDirectory))
            {
                throw new IOException(
                    "The GPT output directory must not exist yet: '" + gptOutputDirectory + "'.");
            }

            string gptRequestPath = Path.Combine(requestsDirectory, "gpt.json");

            WriteJson(gptRequestPath, writer =>
            {
                writer.WriteStartObject();
                writer.WriteNumber("schemaVersion", ManifestSchemaVersion);
                writer.WriteNumber("sectorSize", lun0.SectorSize);
                writer.WriteNumber("diskBytes", diskBytes);
                WriteFileReference(writer, "currentPrimary", capture.Regions["gpt_lun0_primary"]);
                WriteFileReference(writer, "currentBackup", capture.Regions["gpt_lun0_backup"]);
                WriteStagedReference(writer, "originalPrimary", stagedPrimary);
                WriteStagedReference(writer, "originalBackup", stagedBackup);
                WriteFileReference(writer, "misc", capture.Regions["misc"]);
                writer.WriteStartObject("owned");
                writer.WriteString("userdataPartUuid", inputs.Record.UserdataPartUuid);
                writer.WriteString("linuxBootPartUuid", inputs.Record.LinuxBootPartUuid);
                writer.WriteString("linuxRootPartUuid", inputs.Record.LinuxRootPartUuid);
                if (inputs.Record.BoardBackupPartUuid is not null)
                {
                    writer.WriteString("boardBackupPartUuid", inputs.Record.BoardBackupPartUuid);
                }
                writer.WriteEndObject();
                writer.WriteString("outputDirectory", gptOutputDirectory);
                writer.WriteEndObject();
            }, token);

            AddPinned(gptRequestPath, "request:gpt", locks, pinned);

            ProcessResult gptResult = await RunBridgeAsync(
                runner, python, new[] { "-B", gptCli, gptRequestPath }, token)
                .ConfigureAwait(false);

            string gptResponsePath = Path.Combine(evidenceDirectory, "gpt-response.json");
            string gptErrorPath = Path.Combine(evidenceDirectory, "gpt-stderr.txt");

            WriteText(gptResponsePath, gptResult.StandardOutput ?? string.Empty);
            WriteText(gptErrorPath, gptResult.StandardError ?? string.Empty);

            AddPinned(gptResponsePath, "response:gpt", locks, pinned);
            AddPinned(gptErrorPath, "stderr:gpt", locks, pinned);

            if (gptResult.ExitCode != 0)
            {
                throw new InvalidOperationException(
                    "The GPT bridge exited with " + gptResult.ExitCode + "." + Detail(gptResult.StandardError));
            }

            if (!Directory.Exists(gptOutputDirectory))
            {
                throw new InvalidOperationException(
                    "The GPT bridge did not create its output directory '" + gptOutputDirectory + "'.");
            }

            GptPlanEvidence plan;

            using (JsonDocument gptDocument = ParseSingleObject(gptResult.StandardOutput, "The GPT bridge"))
            {
                JsonElement gptRoot = gptDocument.RootElement;
                long schemaVersion = Number(gptRoot, "schemaVersion", "The GPT response");

                if (schemaVersion != ManifestSchemaVersion)
                {
                    throw new InvalidOperationException(
                        "The GPT bridge answered with schemaVersion " + schemaVersion + " instead of 1.");
                }

                if (!Flag(gptRoot, "ok", "The GPT response"))
                {
                    throw new InvalidOperationException(
                        "The GPT bridge reported failure." + Detail(gptResult.StandardOutput));
                }

                JsonElement planElement = Object(gptRoot, "plan", "The GPT response");
                plan = await ValidateGptPlanAsync(
                    planElement, capture, inputs, diskBytes, gptOutputDirectory, token)
                    .ConfigureAwait(false);
            }

            foreach (GptRegionExpectation region in plan.Regions)
            {
                AddPinned(region.Path, "gpt-region:" + region.Role, locks, pinned);
            }

            AddPinned(plan.MiscRegion.Path, "gpt-region:misc-bcb", locks, pinned);
            AddPinned(plan.PostPrimary.Path, "gpt-post:primary", locks, pinned);
            AddPinned(plan.PostBackup.Path, "gpt-post:backup", locks, pinned);

            string planFingerprint = ComputePlanFingerprint(
                identity, binding, capture, stagedPrimary, stagedBackup, inputs, plan);

            // The standard route folds the pinned current-menu manifest hash into the
            // same canonical digest under its own domain key; the legacy fingerprint
            // byte algorithm is untouched.
            if (currentMenu is not null)
            {
                var menuBody = new StringBuilder();
                menuBody.Append("domain=current-menu\n")
                    .Append("planFingerprint=").Append(planFingerprint).Append('\n')
                    .Append("manifest.sha256=").Append(currentMenu.Manifest.Sha256).Append('\n');
                planFingerprint = CanonicalHash(menuBody);
            }

            string manifestPath = Path.Combine(backupDirectory, "manifest.json");

            WriteJson(manifestPath, writer => WriteManifest(
                writer, identity, binding, lun0, capture, stagedPrimary, stagedBackup, inputs, plan,
                planFingerprint, currentMenu),
                token);

            AddPinned(manifestPath, "manifest", locks, pinned);

            // Only a successful, freshly captured and fully validated preparation claims
            // maintenance and a completed OTA; nothing here observes a boot.
            var snapshot = new UserdataUninstallSnapshot(
                identity,
                inputs.CurrentTableFingerprint,
                capture.Regions["misc"].Sha256,
                inputs.EvidenceFingerprint,
                true,
                OtaUpdateState.Completed);

            return new EdlUninstallBackend(
                client,
                tools,
                binding,
                identity,
                capture,
                plan,
                inputs,
                snapshot,
                backupDirectory,
                planFingerprint,
                new ReadOnlyCollection<PinnedFile>(pinned),
                locks,
                currentMenu,
                progress);
        }
        catch
        {
            // Every new file and the backup directory stay on disk as evidence; only the
            // handles this factory owns are released.
            if (capture != null)
            {
                capture.Dispose();
            }

            foreach (FileStream stream in locks)
            {
                stream.Dispose();
            }

            locks.Clear();
            throw;
        }
    }

    // -----------------------------------------------------------------
    // Workflow bridge (read-only here)
    // -----------------------------------------------------------------

    public async Task<UserdataUninstallSnapshot> InspectAsync(CancellationToken token = default)
    {
        ThrowIfDisposed();
        token.ThrowIfCancellationRequested();

        // Every call re-reads the three pinned LUN0 ranges from the device: no cached
        // answer and no cached device I/O is ever returned.
        EdlGeometry geometry = await WarmProbeAsync(0, token).ConfigureAwait(false);

        if (!ReferenceEquals(_client.Toolchain, _tools))
        {
            throw new InvalidOperationException(
                "The client toolchain changed since preparation.");
        }

        if (!Equals(_client.Binding, _binding))
        {
            throw new InvalidOperationException(
                "The client's entry result changed since preparation.");
        }

        DeviceIdentity actual = _binding.AndroidIdentity.Identity;
        if (actual is null
            || !string.Equals(actual.Serial, _identity.Serial, StringComparison.Ordinal)
            || !string.Equals(actual.Model, _identity.Model, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The reinspection captured a different device identity.");
        }

        EdlCapturedRegion primary = _capture.Regions["gpt_lun0_primary"];
        EdlCapturedRegion backup = _capture.Regions["gpt_lun0_backup"];
        EdlCapturedRegion misc = _capture.Regions["misc"];

        RequireRange(geometry, primary.StartSector, primary.SectorCount, "gpt_lun0_primary");
        RequireRange(geometry, backup.StartSector, backup.SectorCount, "gpt_lun0_backup");
        RequireRange(geometry, misc.StartSector, misc.SectorCount, "misc");

        string primaryPath = await ReadVerifiedAsync(
            geometry, primary.StartSector, primary.SectorCount, "inspect-primary", null, token)
            .ConfigureAwait(false);

        string backupPath = await ReadVerifiedAsync(
            geometry, backup.StartSector, backup.SectorCount, "inspect-backup", null, token)
            .ConfigureAwait(false);

        string miscPath = await ReadVerifiedAsync(
            geometry, misc.StartSector, misc.SectorCount, "inspect-misc", null, token)
            .ConfigureAwait(false);

        byte[] primaryBytes = await File.ReadAllBytesAsync(primaryPath, token).ConfigureAwait(false);
        byte[] backupBytes = await File.ReadAllBytesAsync(backupPath, token).ConfigureAwait(false);
        byte[] miscBytes = await File.ReadAllBytesAsync(miscPath, token).ConfigureAwait(false);

        long diskBytes = CheckedDiskBytes(geometry);
        GptTable? table;

        try
        {
            table = OriginalGptImporter.Parse(primaryBytes, backupBytes, geometry.SectorSize, diskBytes);
        }
        catch (Exception error) when (error is InvalidOperationException || error is ArgumentException)
        {
            throw new InvalidOperationException(
                "The reinspected GPT pair is not a consistent GPT.", error);
        }

        if (table is null
            || table.SectorSize != geometry.SectorSize
            || table.DiskBytes != diskBytes)
        {
            throw new InvalidOperationException(
                "The reinspected GPT pair does not describe the pinned LUN0 geometry.");
        }

        var fresh = new Dictionary<string, EdlCapturedRegion>(StringComparer.Ordinal)
        {
            ["gpt_lun0_primary"] = new EdlCapturedRegion(
                "gpt_lun0_primary", geometry.Lun, primary.StartSector, primary.SectorCount,
                geometry.SectorSize, null, primaryPath, primaryBytes.LongLength,
                Sha256Bytes(primaryBytes)),
            ["gpt_lun0_backup"] = new EdlCapturedRegion(
                "gpt_lun0_backup", geometry.Lun, backup.StartSector, backup.SectorCount,
                geometry.SectorSize, null, backupPath, backupBytes.LongLength,
                Sha256Bytes(backupBytes)),
            ["misc"] = new EdlCapturedRegion(
                "misc", geometry.Lun, misc.StartSector, misc.SectorCount,
                geometry.SectorSize, misc.PartUuid, miscPath, miscBytes.LongLength,
                Sha256Bytes(miscBytes)),
        };

        CompareGeometry(geometry, _capture.Lun0Geometry, "LUN0");
        CompareTable(table, _capture.Lun0Table, "LUN0");
        CompareRegions(fresh, _capture.Regions);

        await ValidatePinnedFilesAsync(token).ConfigureAwait(false);

        return _snapshot;
    }

    public async Task ValidateRestoreInputsAsync(CancellationToken token)
    {
        ThrowIfDisposed();
        token.ThrowIfCancellationRequested();
        await ValidatePinnedFilesAsync(token).ConfigureAwait(false);

        // The pinned plan stays internally consistent with the pinned geometry; this
        // method never writes and never touches the device.
        RequirePlanGeometry(
            _capture.Lun0Geometry,
            _capture.Regions["gpt_lun0_primary"],
            _capture.Regions["gpt_lun0_backup"]);
    }

    public async Task ReclaimAndroidSpaceAsync(CancellationToken token)
    {
        ThrowIfDisposed();
        token.ThrowIfCancellationRequested();
        EnsureHealthy();

        // The reclaim starts from the prepared stage only. On the standard route the
        // necessary project-default-only boot menu writes are now allowed because a full
        // fresh backup was taken first; the legacy no-menu route still performs no boot
        // work. No stock boot restore, no EFI/ABL writes and no reset are ever issued.
        if (_step != StepState.Prepared)
        {
            throw new InvalidOperationException(
                "Android space cannot be reclaimed from stage " + _step + ".");
        }

        await ValidatePinnedFilesAsync(token).ConfigureAwait(false);

        EdlCapturedRegion primary = _capture.Regions["gpt_lun0_primary"];
        EdlCapturedRegion backup = _capture.Regions["gpt_lun0_backup"];
        EdlCapturedRegion misc = _capture.Regions["misc"];

        // These are fresh reads of the actual captured GPT/misc ranges, not a full capture:
        // LUN0 must not have moved underneath between inspection and the first write.
        EdlGeometry geometry = await WarmProbeAsync(0, token).ConfigureAwait(false);
        RequireRange(geometry, primary.StartSector, primary.SectorCount, "gpt_lun0_primary");
        RequireRange(geometry, backup.StartSector, backup.SectorCount, "gpt_lun0_backup");
        RequireRange(geometry, misc.StartSector, misc.SectorCount, "misc");

        await ReadVerifiedAsync(
            geometry,
            primary.StartSector,
            primary.SectorCount,
            "pre-reclaim-primary",
            primary.Sha256,
            token)
            .ConfigureAwait(false);

        await ReadVerifiedAsync(
            geometry,
            backup.StartSector,
            backup.SectorCount,
            "pre-reclaim-backup",
            backup.Sha256,
            token)
            .ConfigureAwait(false);

        await ReadVerifiedAsync(
            geometry,
            misc.StartSector,
            misc.SectorCount,
            "pre-reclaim-misc",
            misc.Sha256,
            token)
            .ConfigureAwait(false);

        // Standard route: before ANY write, each DISTINCT role boot_a, boot_b and every
        // write-target role is read exactly once from its captured source region, whole,
        // with a full SHA check against the captured hash and the target's pinned
        // original hash. Each involved LUN is warm probed before that LUN is read.
        if (_currentMenu is not null)
        {
            SafeStage(Stages.PreflightMenu);

            var preflightRoles = new List<string>();
            foreach (string bootRole in new[] { "boot_a", "boot_b" })
            {
                preflightRoles.Add(bootRole);
            }

            foreach (MenuWriteTarget target in _currentMenu.WriteTargets)
            {
                if (!preflightRoles.Contains(target.Role))
                {
                    preflightRoles.Add(target.Role);
                }
            }

            var probedLuns = new HashSet<int>();

            foreach (string role in preflightRoles)
            {
                token.ThrowIfCancellationRequested();

                if (!_currentMenu.SourceRegions.TryGetValue(role, out EdlCapturedRegion? region)
                    || region is null)
                {
                    throw new InvalidOperationException(
                        "The current-menu source region for '" + role + "' is missing.");
                }

                EdlGeometry roleGeometry = RequireMenuGeometry(region.Lun);

                if (probedLuns.Add(region.Lun))
                {
                    await WarmProbeAsync(region.Lun, token).ConfigureAwait(false);
                }

                RequireRange(
                    roleGeometry,
                    checked((long)region.StartSector),
                    checked((long)region.SectorCount),
                    "preflight-" + role);

                MenuWriteTarget? target = _currentMenu.WriteTargets.FirstOrDefault(
                    candidate => string.Equals(candidate.Role, role, StringComparison.Ordinal));

                if (target is not null)
                {
                    if (region.Lun != target.Geometry.Lun
                        || checked((long)region.StartSector) != target.StartSector
                        || checked((long)region.SectorCount) != target.SectorCount
                        || region.SectorSize != target.Geometry.SectorSize
                        || region.PartUuid is null
                        || !string.Equals(region.PartUuid, target.PartUuid, StringComparison.OrdinalIgnoreCase)
                        || region.Length != target.Candidate.Length
                        || !string.Equals(region.Sha256, target.OriginalSha256, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException(
                            "The current-menu target '" + target.Role + "' no longer matches its captured extent.");
                    }
                }

                await ReadVerifiedAsync(
                    roleGeometry,
                    region.StartSector,
                    region.SectorCount,
                    "preflight-" + role,
                    region.Sha256,
                    token)
                    .ConfigureAwait(false);
            }
        }

        RequirePlanGeometry(geometry, primary, backup);

        // One warm probe immediately before the four-unit sequence. There is deliberately
        // no probe and no GPT parse between units while the two GPT copies transiently
        // disagree and their CRCs are not yet a valid pair.
        geometry = await WarmProbeAsync(0, token).ConfigureAwait(false);

        // One poisoned write transaction: the standard menu writes, the after-menu warm
        // probe and the whole original GPT unit sequence with its post-write pair
        // read-back share this single catch. Any failure once a write is attempted stops
        // the operation: no GPT unit, no BCB, no reset and no retry follows.
        try
        {
            // Standard route: inside the same poisoned write transaction, before the four
            // GPT units, write each current-menu target in the already-fixed order. Any
            // failure here poisons the backend exactly like a GPT unit failure.
            if (_currentMenu is not null)
        {
            foreach (MenuWriteTarget target in _currentMenu.WriteTargets)
            {
                token.ThrowIfCancellationRequested();
                await ValidatePinnedFilesAsync(token).ConfigureAwait(false);
                SafeStage(Stages.WritingMenu, target.Role);

                if (!string.Equals(
                        await HashFileAsync(target.Candidate.Path, token).ConfigureAwait(false),
                        target.Candidate.Sha256,
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(
                        "The staged candidate '" + target.Candidate.Path + "' no longer hashes to its pinned claim.");
                }

                RequireOwnedLength(
                    target.Candidate.Path, target.Candidate.Length, "current-menu candidate '" + target.Role + "'");

                long expectedBytes;
                try
                {
                    expectedBytes = checked(target.SectorCount * (long)target.Geometry.SectorSize);
                }
                catch (OverflowException)
                {
                    throw new InvalidOperationException(
                        "The current-menu target '" + target.Role + "' overflows a 64-bit byte count.");
                }

                if (target.Candidate.Length != expectedBytes
                    || target.StartSector < 0
                    || target.StartSector > target.Geometry.TotalSectors - target.SectorCount)
                {
                    throw new InvalidOperationException(
                        "The current-menu target '" + target.Role + "' does not match its pinned geometry bounds.");
                }

                WriteProgress(
                    "intent",
                    target.Role,
                    target.Geometry.Lun,
                    target.StartSector,
                    target.SectorCount,
                    target.Candidate.Length,
                    target.Candidate.Sha256,
                    token);

                EdlWriteEvidence evidence = await _client
                    .WriteAsync(
                        target.Geometry.Lun,
                        target.StartSector,
                        target.Candidate,
                        TransferAdapter(Stages.WritingMenu, target.Role),
                        TransferLogPrefix(target.Role),
                        token)
                    .ConfigureAwait(false);

                SafeStage(Stages.VerifyingMenu, target.Role);

                VerifyWriteEvidence(
                    evidence,
                    target.Geometry,
                    target.StartSector,
                    target.SectorCount,
                    target.Candidate.Length,
                    target.Candidate.Sha256,
                    "current-menu '" + target.Role + "'");

                await ReadVerifiedAsync(
                    target.Geometry,
                    target.StartSector,
                    target.SectorCount,
                    "verify-" + target.Role,
                    target.Candidate.Sha256,
                    token)
                    .ConfigureAwait(false);

                WriteProgress(
                    "receipt",
                    target.Role,
                    target.Geometry.Lun,
                    target.StartSector,
                    target.SectorCount,
                    target.Candidate.Length,
                    target.Candidate.Sha256,
                    CancellationToken.None);
            }

            // Every menu target is verified with a warm probe of LUN0 before the GPT
            // units begin.
            await WarmProbeAsync(0, token).ConfigureAwait(false);
        }

        foreach (GptRegionExpectation region in _plan.Regions)
        {
            await ValidatePinnedFilesAsync(token).ConfigureAwait(false);

            (long start, long count) = GptRegionRange(region, geometry);
            RequireOwnedLength(region.Path, region.Bytes, "GPT region '" + region.Role + "'");

            WriteProgress(
                "intent",
                region.Role,
                geometry.Lun,
                start,
                count,
                region.Bytes,
                region.Sha256,
                token);

            EdlWriteEvidence evidence = await _client
                .WriteAsync(
                    geometry.Lun,
                    start,
                    new VerifiedEdlFile(region.Path, region.Bytes, region.Sha256),
                    TransferAdapter(Stages.WritingGpt, region.Role),
                    TransferLogPrefix(region.Role),
                    token)
                .ConfigureAwait(false);

            VerifyWriteEvidence(
                evidence,
                geometry,
                start,
                count,
                region.Bytes,
                region.Sha256,
                region.Role);

            await ReadVerifiedAsync(
                geometry,
                start,
                count,
                "verify-" + region.Role,
                region.Sha256,
                token)
                .ConfigureAwait(false);

            WriteProgress(
                "receipt",
                region.Role,
                geometry.Lun,
                start,
                count,
                region.Bytes,
                region.Sha256,
                CancellationToken.None);
        }

            // A unit read-back cannot see bytes outside the unit: the whole primary and
            // backup captures are the real post-write oracle.
            string postPrimaryPath = await ReadVerifiedAsync(
                geometry,
                0,
                primary.SectorCount,
                "post-primary",
                _plan.PostPrimary.Sha256,
                token)
                .ConfigureAwait(false);

            string postBackupPath = await ReadVerifiedAsync(
                geometry,
                backup.StartSector,
                backup.SectorCount,
                "post-backup",
                _plan.PostBackup.Sha256,
                token)
                .ConfigureAwait(false);

            byte[] postPrimary = await File
                .ReadAllBytesAsync(postPrimaryPath, token)
                .ConfigureAwait(false);
            byte[] postBackup = await File
                .ReadAllBytesAsync(postBackupPath, token)
                .ConfigureAwait(false);

            if (postPrimary.LongLength != primary.Length || postBackup.LongLength != backup.Length)
            {
                throw new InvalidOperationException(
                    "The post-write GPT captures do not carry the captured lengths.");
            }

            long diskBytes = checked(geometry.TotalSectors * (long)geometry.SectorSize);
            GptTable table = OriginalGptImporter.Parse(
                postPrimary, postBackup, geometry.SectorSize, diskBytes);

            // Only now, with both whole captures hash-verified, may the pair be parsed for
            // its double CRC and consistency rules.
            if (table is null
                || table.SectorSize != geometry.SectorSize
                || table.DiskBytes != diskBytes)
            {
                throw new InvalidOperationException(
                    "The post-write GPT pair does not parse into a consistent table.");
            }
        }
        catch
        {
            // No later unit, no BCB, no reset and no automatic retry may follow any write,
            // read or CRC failure at this point.
            MarkUncertain();
            throw;
        }

        _step = StepState.InitializeAndroid;
    }

    /// <summary>
    /// Resolves the pinned geometry for a current-menu LUN; LUN0 stays with the fresh
    /// capture, all other LUNs come from the current-menu geometry copy. Unknown LUNs
    /// are always refused.
    /// </summary>
    private EdlGeometry RequireMenuGeometry(int lun)
    {
        if (lun == 0)
        {
            return _capture.Lun0Geometry;
        }

        if (_currentMenu is not null && _currentMenu.Geometries.TryGetValue(lun, out EdlGeometry? geometry))
        {
            return geometry;
        }

        throw new InvalidOperationException(
            "LUN" + lun + " is not part of the prepared geometry.");
    }

    private void SafeStage(string stage, string? role = null) => ReportStage(stage, role);

    public async Task InitializeAndroidAsync(CancellationToken token)
    {
        ThrowIfDisposed();
        token.ThrowIfCancellationRequested();
        EnsureHealthy();

        if (_step != StepState.InitializeAndroid)
        {
            throw new InvalidOperationException(
                "Android cannot be initialized from stage " + _step + ".");
        }

        EdlCapturedRegion misc = _capture.Regions["misc"];

        try
        {
            await ValidatePinnedFilesAsync(token).ConfigureAwait(false);

            EdlGeometry geometry = await WarmProbeAsync(misc.Lun, token).ConfigureAwait(false);
            RequireRange(geometry, misc.StartSector, misc.SectorCount, "misc");

            SafeStage(Stages.InitializingAndroid, "misc-bcb");

            // The BCB may only be queued when the whole misc region is still exactly the
            // pinned pre-initialization content.
            await ReadVerifiedAsync(
                geometry,
                misc.StartSector,
                misc.SectorCount,
                "pre-initialize-misc",
                _plan.MiscBeforeSha256,
                token)
                .ConfigureAwait(false);

            long count = _plan.MiscRegion.SectorCount;
            long bytes = _plan.MiscRegion.Bytes;
            long expectedBytes;

            try
            {
                expectedBytes = checked(count * (long)geometry.SectorSize);
            }
            catch (OverflowException)
            {
                throw new InvalidOperationException(
                    "The prepared BCB unit overflows a 64-bit byte count.");
            }

            if (count <= 0 || bytes != expectedBytes)
            {
                throw new InvalidOperationException(
                    "The prepared BCB unit does not cover whole sectors at the device sector size.");
            }

            RequireOwnedLength(_plan.MiscRegion.Path, bytes, "prepared BCB unit");

            // The BCB region is relative to the misc partition start. It is never LUN0 LBA0
            // and never the userdata start.
            long start = misc.StartSector + 0;
            if (start == 0 || start == _plan.UserdataStart)
            {
                throw new InvalidOperationException(
                    "The prepared BCB unit would write a protected LUN0 location.");
            }

            RequireRange(geometry, start, count, "misc-bcb");

            WriteProgress(
                "intent",
                "misc-bcb",
                geometry.Lun,
                start,
                count,
                bytes,
                _plan.MiscRegion.Sha256,
                token);

            EdlWriteEvidence evidence = await _client
                .WriteAsync(
                    geometry.Lun,
                    start,
                    new VerifiedEdlFile(_plan.MiscRegion.Path, bytes, _plan.MiscRegion.Sha256),
                    TransferAdapter(Stages.InitializingAndroid, "misc-bcb"),
                    TransferLogPrefix("misc-bcb"),
                    token)
                .ConfigureAwait(false);

            VerifyWriteEvidence(
                evidence,
                geometry,
                start,
                count,
                bytes,
                _plan.MiscRegion.Sha256,
                "misc-bcb");

            // The unit read-back is necessary but not sufficient; the whole misc hash is
            // the pending-factory-reset proof.
            await ReadVerifiedAsync(
                geometry,
                start,
                count,
                "verify-misc-bcb",
                _plan.MiscRegion.Sha256,
                token)
                .ConfigureAwait(false);

            await ReadVerifiedAsync(
                geometry,
                misc.StartSector,
                misc.SectorCount,
                "post-initialize-misc",
                _plan.MiscAfterSha256,
                token)
                .ConfigureAwait(false);

            WriteProgress(
                "receipt",
                "misc-bcb",
                geometry.Lun,
                start,
                count,
                bytes,
                _plan.MiscRegion.Sha256,
                CancellationToken.None);
        }
        catch
        {
            MarkUncertain();
            throw;
        }

        // Queues the factory-reset path only. No boot, no Android acceptance, no erase and
        // no reset command is issued or claimed here.
        _step = StepState.Done;

        // Only the fully verified final whole-misc readback after the actual write
        // claims completion; nothing is derived from display counters.
        ReportStage(Stages.WritesVerified);
    }

    /// <summary>
    /// Releases only the read locks this backend owns plus the initial capture. It never
    /// deletes backups, never disposes the externally owned client/toolchain and never
    /// changes global state.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            _capture.Dispose();
        }
        finally
        {
            foreach (FileStream stream in _locks)
            {
                stream.Dispose();
            }

            _locks.Clear();
        }
    }

    // -----------------------------------------------------------------
    // GPT plan
    // -----------------------------------------------------------------

    private static async Task<GptPlanEvidence> ValidateGptPlanAsync(
        JsonElement plan,
        EdlUninstallCapture capture,
        ValidatedUninstallInputs inputs,
        long diskBytes,
        string outputDirectory,
        CancellationToken token)
    {
        AndroidRestorePlan expectedPlan = inputs.Plan;
        int sectorSize = capture.Lun0Geometry.SectorSize;
        long totalSectors = capture.Lun0Geometry.TotalSectors;

        long userdataStart = Number(plan, "userdataStartLba", "The GPT plan");
        long userdataEnd = Number(plan, "userdataEndLbaExclusive", "The GPT plan");
        long restoredBytes = Number(plan, "restoredBytes", "The GPT plan");

        if (userdataStart != expectedPlan.UserdataStartSector
            || userdataEnd != expectedPlan.UserdataEndSectorExclusive
            || restoredBytes != expectedPlan.RestoredAndroidBytes)
        {
            throw new InvalidOperationException(
                "The GPT plan disagrees with the validated Android restore geometry.");
        }

        var removed = new List<long>();
        JsonElement removedElement = ArrayProperty(plan, "removedPartitionNumbers", "The GPT plan");

        foreach (JsonElement item in removedElement.EnumerateArray())
        {
            removed.Add(Integral(item, "removedPartitionNumbers[]"));
        }

        if (!removed.SequenceEqual(expectedPlan.RemovedPartitionNumbers))
        {
            throw new InvalidOperationException(
                "The GPT plan removed a different set of partitions than the validated inputs.");
        }

        string rawFingerprint = NonEmptyText(plan, "currentRawTableFingerprint", "The GPT plan");
        RequireHex64(rawFingerprint, "The GPT plan field 'currentRawTableFingerprint'");

        // The raw table fingerprint comes from the frozen CLI's own algorithm; it is kept
        // separately and never equated with the managed C# table fingerprint.

        // Expected primary/backup array and header geometry is taken from the captured GPT
        // bytes themselves: entry LBA at header offset 72, entry count at 80, entry size
        // at 84. Nothing about 128 entries or old boot ranges is assumed.
        EdlCapturedRegion currentPrimary = capture.Regions["gpt_lun0_primary"];
        EdlCapturedRegion currentBackup = capture.Regions["gpt_lun0_backup"];

        byte[] primarySlice = await File
            .ReadAllBytesAsync(currentPrimary.FilePath, token)
            .ConfigureAwait(false);
        byte[] backupSlice = await File
            .ReadAllBytesAsync(currentBackup.FilePath, token)
            .ConfigureAwait(false);

        (long Start, long Count) primaryArray = ReadArrayRange(
            primarySlice, sectorSize, sectorSize, totalSectors, "primary");

        (long Start, long Count) backupArray = ReadArrayRange(
            backupSlice, sectorSize, checked(backupSlice.Length - sectorSize), totalSectors, "backup");

        var expectedRanges = new Dictionary<string, (long Start, long Count)>(StringComparer.Ordinal)
        {
            ["backup-array"] = backupArray,
            ["backup-header"] = (checked(totalSectors - 1), 1),
            ["primary-array"] = primaryArray,
            ["primary-header"] = (1, 1),
        };

        JsonElement regionsElement = ArrayProperty(plan, "regions", "The GPT plan");

        JsonElement[] regionItems = regionsElement.EnumerateArray().ToArray();
        if (regionItems.Length != GptRegionRoleOrder.Length)
        {
            throw new InvalidOperationException(
                "The GPT plan described " + regionItems.Length + " regions instead of 4.");
        }

        var regions = new List<GptRegionExpectation>(GptRegionRoleOrder.Length);

        for (int index = 0; index < GptRegionRoleOrder.Length; index++)
        {
            JsonElement item = regionItems[index];
            string role = Text(item, "role", "The GPT plan region");

            if (!string.Equals(role, GptRegionRoleOrder[index], StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "The GPT plan region " + index + " is '" + role + "' instead of '" +
                    GptRegionRoleOrder[index] + "'.");
            }

            long byteOffset = Number(item, "byteOffset", "The GPT plan region '" + role + "'");
            long startSector = Number(item, "startSector", "The GPT plan region '" + role + "'");
            long sectorCount = Number(item, "sectorCount", "The GPT plan region '" + role + "'");
            long bytes = Number(item, "bytes", "The GPT plan region '" + role + "'");
            string sha256 = Hex64(item, "sha256", "The GPT plan region '" + role + "'");
            string path = Text(item, "path", "The GPT plan region '" + role + "'");

            (long ExpectStart, long ExpectCount) = expectedRanges[role];

            if (startSector != ExpectStart || sectorCount != ExpectCount)
            {
                throw new InvalidOperationException(
                    "The GPT plan region '" + role + "' covers sectors " + startSector + "+" +
                    sectorCount + " instead of " + ExpectStart + "+" + ExpectCount + ".");
            }

            if (startSector <= 0 || sectorCount <= 0 || bytes <= 0)
            {
                throw new InvalidOperationException(
                    "The GPT plan region '" + role + "' is not a positive range.");
            }

            if (byteOffset != checked(startSector * sectorSize))
            {
                throw new InvalidOperationException(
                    "The GPT plan region '" + role + "' has a byte offset that does not match its sector.");
            }

            if (bytes != checked(sectorCount * sectorSize))
            {
                throw new InvalidOperationException(
                    "The GPT plan region '" + role + "' has a byte length that does not match its sector count.");
            }

            if (checked(startSector + sectorCount) > totalSectors)
            {
                throw new InvalidOperationException(
                    "The GPT plan region '" + role + "' extends past the end of LUN0.");
            }

            RequireOwnedFile(path, outputDirectory, bytes, sha256, "The GPT plan region '" + role + "'", token);

            regions.Add(new GptRegionExpectation(role, path, byteOffset, bytes, sha256));
        }

        // The misc BCB is relative to the MISC partition, never to LUN0/userdata.
        JsonElement miscRegionElement = Object(plan, "miscRegion", "The GPT plan");
        string miscRole = Text(miscRegionElement, "role", "The GPT plan misc region");
        if (!string.Equals(miscRole, "misc-bcb", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The GPT plan misc region is '" + miscRole + "' instead of 'misc-bcb'.");
        }

        long relativeMiscOffset = Number(miscRegionElement, "relativeMiscOffset", "The GPT plan misc region");
        long miscByteOffset = Number(miscRegionElement, "byteOffset", "The GPT plan misc region");
        long miscStartSector = Number(miscRegionElement, "startSector", "The GPT plan misc region");

        if (relativeMiscOffset != 0 || miscByteOffset != 0 || miscStartSector != 0)
        {
            throw new InvalidOperationException(
                "The GPT plan misc region must start at offset zero of MISC.");
        }

        EdlCapturedRegion misc = capture.Regions["misc"];
        int miscSectorSize = misc.SectorSize;

        long miscBytes;
        try
        {
            miscBytes = checked(((BcbBytes + miscSectorSize - 1) / miscSectorSize) * miscSectorSize);
        }
        catch (OverflowException)
        {
            throw new InvalidOperationException(
                "The MISC sector size produced an overflowing BCB length.");
        }

        long miscBytesField = Number(miscRegionElement, "bytes", "The GPT plan misc region");
        long miscSectorCount = Number(miscRegionElement, "sectorCount", "The GPT plan misc region");
        string miscSha256 = Hex64(miscRegionElement, "sha256", "The GPT plan misc region");
        string miscPath = Text(miscRegionElement, "path", "The GPT plan misc region");

        if (miscBytesField != miscBytes || miscSectorCount != miscBytes / miscSectorSize)
        {
            throw new InvalidOperationException(
                "The GPT plan misc region does not cover exactly one BCB block.");
        }

        RequireOwnedFile(miscPath, outputDirectory, miscBytes, miscSha256, "The GPT plan misc region", token);

        string miscBefore = Hex64(plan, "miscBeforeSha256", "The GPT plan");
        if (!string.Equals(miscBefore, misc.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The GPT plan did not bind the whole captured MISC hash.");
        }

        string miscAfter = Hex64(plan, "miscAfterSha256", "The GPT plan");
        string expectedMiscAfter = await HashPrefixOverlayAsync(
            misc.FilePath, miscBytes, miscPath, token).ConfigureAwait(false);

        if (!string.Equals(miscAfter, expectedMiscAfter, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The GPT plan misc-after hash does not match the single BCB overlay on the captured MISC.");
        }

        // postPrimary/postBackup are read-back expectations for the CURRENT GPT copies with
        // only the four planned regions overlaid; they are never a whole-device write.
        JsonElement postPrimaryElement = Object(plan, "postPrimary", "The GPT plan");
        JsonElement postBackupElement = Object(plan, "postBackup", "The GPT plan");

        PostExpectation postPrimary = ReadPostExpectation(
            postPrimaryElement, "postPrimary", 0, currentPrimary.Length,
            outputDirectory, token);

        PostExpectation postBackup = ReadPostExpectation(
            postBackupElement, "postBackup", checked(diskBytes - currentBackup.Length),
            currentBackup.Length, outputDirectory, token);

        byte[] expectedPrimaryBytes = Overlay(
            await File.ReadAllBytesAsync(currentPrimary.FilePath, token).ConfigureAwait(false),
            0, regions);

        byte[] expectedBackupBytes = Overlay(
            await File.ReadAllBytesAsync(currentBackup.FilePath, token).ConfigureAwait(false),
            checked(diskBytes - currentBackup.Length), regions);

        if (!string.Equals(Sha256Bytes(expectedPrimaryBytes), postPrimary.Sha256, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(Sha256Bytes(expectedBackupBytes), postBackup.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The GPT plan expected read-back contains edits outside the four planned GPT regions.");
        }

        // The expected read-back pair must still form one consistent, CRC-valid GPT pair.
        byte[] postPrimaryBytes = await File
            .ReadAllBytesAsync(postPrimary.Path, token)
            .ConfigureAwait(false);

        byte[] postBackupBytes = await File
            .ReadAllBytesAsync(postBackup.Path, token)
            .ConfigureAwait(false);

        GptTable? postTable;
        try
        {
            postTable = OriginalGptImporter.Parse(postPrimaryBytes, postBackupBytes, sectorSize, diskBytes);
        }
        catch (Exception error) when (error is InvalidOperationException || error is ArgumentException)
        {
            throw new InvalidOperationException(
                "The GPT plan expected read-back pair is not a consistent GPT.", error);
        }

        if (postTable is null)
        {
            throw new InvalidOperationException(
                "The GPT plan expected read-back pair could not be parsed.");
        }

        static void EnsureBoardBackupPartitionRetained(
            string boardBackupPartUuid,
            GptTable currentTable,
            GptTable postTable)
        {
            if (!Guid.TryParse(boardBackupPartUuid, out Guid backupPartGuid))
            {
                throw new InvalidOperationException(
                    "The board backup partition UUID in the device record is not a valid GUID.");
            }

            string expectedUuid = backupPartGuid.ToString();
            string? postName = null;
            string? postNumber = null;
            string? postTypeGuid = null;
            string? postStartSector = null;
            string? postSectorCount = null;
            string? postAttributes = null;
            int postMatches = 0;

            foreach (var partition in postTable.Partitions)
            {
                if (!string.Equals(
                        partition.PartUuid.ToString(),
                        expectedUuid,
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                postMatches++;
                postName = partition.Name;
                postNumber = partition.Number.ToString();
                postTypeGuid = partition.TypeGuid.ToString();
                postStartSector = partition.StartSector.ToString();
                postSectorCount = partition.SectorCount.ToString();
                postAttributes = partition.Attributes.ToString();
            }

            if (postMatches != 1)
            {
                throw new InvalidOperationException(
                    "The GPT plan expected read-back must contain exactly one board backup partition "
                    + "with UUID " + boardBackupPartUuid + ".");
            }

            if (!string.Equals(postName, "ARMADA_BACKUP", StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "The GPT plan expected read-back board backup partition must stay named ARMADA_BACKUP.");
            }

            int currentMatches = 0;
            foreach (var partition in currentTable.Partitions)
            {
                if (!string.Equals(
                        partition.PartUuid.ToString(),
                        expectedUuid,
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                currentMatches++;
                if (!string.Equals(partition.Name, postName, StringComparison.Ordinal)
                    || !string.Equals(partition.Number.ToString(), postNumber, StringComparison.Ordinal)
                    || !string.Equals(
                        partition.TypeGuid.ToString(),
                        postTypeGuid,
                        StringComparison.OrdinalIgnoreCase)
                    || !string.Equals(
                        partition.StartSector.ToString(),
                        postStartSector,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        partition.SectorCount.ToString(),
                        postSectorCount,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        partition.Attributes.ToString(),
                        postAttributes,
                        StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        "The GPT plan must retain the board backup partition unchanged "
                        + "(number, name, type GUID, placement, size, and attributes).");
                }
            }

            if (currentMatches != 1)
            {
                throw new InvalidOperationException(
                    "The current GPT table must contain exactly one board backup partition "
                    + "with UUID " + boardBackupPartUuid + ".");
            }
        }

        if (inputs.Record.BoardBackupPartUuid is not null)
        {
            EnsureBoardBackupPartitionRetained(
                inputs.Record.BoardBackupPartUuid,
                inputs.CurrentTable,
                postTable);
        }

        return new GptPlanEvidence(
            userdataStart,
            userdataEnd,
            restoredBytes,
            new ReadOnlyCollection<long>(removed),
            rawFingerprint,
            miscBefore,
            miscAfter,
            new ReadOnlyCollection<GptRegionExpectation>(regions),
            new MiscRegionExpectation(miscPath, miscBytes, miscSectorCount, miscSha256),
            postPrimary,
            postBackup,
            plan.Clone());
    }

    private static PostExpectation ReadPostExpectation(
        JsonElement element,
        string name,
        long expectedByteOffset,
        long expectedBytes,
        string outputDirectory,
        CancellationToken token)
    {
        long byteOffset = Number(element, "byteOffset", "The GPT plan " + name);
        long bytes = Number(element, "bytes", "The GPT plan " + name);
        string sha256 = Hex64(element, "sha256", "The GPT plan " + name);
        string path = Text(element, "path", "The GPT plan " + name);

        if (byteOffset != expectedByteOffset || bytes != expectedBytes)
        {
            throw new InvalidOperationException(
                "The GPT plan " + name + " does not cover the expected read-back fragment.");
        }

        RequireOwnedFile(path, outputDirectory, bytes, sha256, "The GPT plan " + name, token);

        return new PostExpectation(name, path, byteOffset, bytes, sha256);
    }

    // -----------------------------------------------------------------
    // Reinspection
    // -----------------------------------------------------------------

    private static void CompareGeometry(EdlGeometry actual, EdlGeometry pinned, string name)
    {
        if (actual.Lun != pinned.Lun
            || actual.SectorSize != pinned.SectorSize
            || actual.TotalSectors != pinned.TotalSectors)
        {
            throw new InvalidOperationException(
                "The " + name + " geometry drifted since preparation.");
        }
    }

    private static void CompareTable(GptTable actual, GptTable pinned, string name)
    {
        if (!string.Equals(actual.DeviceId, pinned.DeviceId, StringComparison.Ordinal)
            || actual.SectorSize != pinned.SectorSize
            || actual.DiskBytes != pinned.DiskBytes
            || !string.Equals(actual.DiskGuid, pinned.DiskGuid, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(actual.SourceFingerprint, pinned.SourceFingerprint, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The " + name + " partition table drifted since preparation.");
        }
    }

    private static void CompareRegions(
        IReadOnlyDictionary<string, EdlCapturedRegion> actual,
        IReadOnlyDictionary<string, EdlCapturedRegion> pinned)
    {
        foreach (string role in CaptureRoleOrder)
        {
            if (!actual.TryGetValue(role, out EdlCapturedRegion? region) || region is null)
            {
                throw new InvalidOperationException(
                    "The reinspection is missing the '" + role + "' range.");
            }

            EdlCapturedRegion expected = pinned[role];

            if (region.Lun != expected.Lun
                || region.StartSector != expected.StartSector
                || region.SectorCount != expected.SectorCount
                || region.SectorSize != expected.SectorSize
                || region.Length != expected.Length
                || !string.Equals(region.PartUuid, expected.PartUuid, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(region.Sha256, expected.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "The '" + role + "' range drifted since preparation.");
            }
        }
    }

    private async Task ValidatePinnedFilesAsync(CancellationToken token)
    {
        foreach (PinnedFile file in _pinnedFiles)
        {
            token.ThrowIfCancellationRequested();

            var info = new FileInfo(file.Path);
            if (!info.Exists)
            {
                throw new InvalidOperationException(
                    "The prepared evidence '" + file.Path + "' disappeared.");
            }

            if (info.Length != file.Length)
            {
                throw new InvalidOperationException(
                    "The prepared evidence '" + file.Path + "' changed length.");
            }

            string actual = await HashFileAsync(file.Path, token).ConfigureAwait(false);
            if (!string.Equals(actual, file.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "The prepared evidence '" + file.Path + "' changed content.");
            }
        }
    }

    // -----------------------------------------------------------------
    // Fingerprints
    // -----------------------------------------------------------------

    private static string ComputePlanFingerprint(
        DeviceIdentity identity,
        EdlEntryResult binding,
        EdlUninstallCapture capture,
        StagedFile stagedPrimary,
        StagedFile stagedBackup,
        ValidatedUninstallInputs inputs,
        GptPlanEvidence plan)
    {
        var body = new StringBuilder();

        AppendLine(body, "operation", Operation);
        AppendLine(body, "identity", identity.ToString() ?? string.Empty);
        AppendLine(body, "identity.serial", identity.Serial);
        AppendLine(body, "identity.model", identity.Model);
        AppendLine(body, "identity.bootloaderState", identity.BootloaderState.ToString());
        AppendLine(body, "device.androidSocSerial", binding.AndroidIdentity.SocSerial);
        AppendLine(body, "device.busSerialHex", binding.BusSerialHex);

        AppendLine(body, "lun0.sectorSize", capture.Lun0Geometry.SectorSize);
        AppendLine(body, "lun0.totalSectors", capture.Lun0Geometry.TotalSectors);
        AppendLine(body, "lun0.deviceId", capture.Lun0Table.DeviceId);
        AppendLine(body, "lun0.diskGuid", capture.Lun0Table.DiskGuid);
        AppendLine(body, "lun0.diskBytes", capture.Lun0Table.DiskBytes);
        AppendLine(body, "lun0.sourceFingerprint", capture.Lun0Table.SourceFingerprint);

        foreach (string role in CaptureRoleOrder)
        {
            AppendRegion(body, "capture." + role, capture.Regions[role]);
        }

        AppendLine(body, "asset." + stagedPrimary.Role + ".length", stagedPrimary.Length);
        AppendLine(body, "asset." + stagedPrimary.Role + ".sha256", stagedPrimary.Sha256);
        AppendLine(body, "asset." + stagedBackup.Role + ".length", stagedBackup.Length);
        AppendLine(body, "asset." + stagedBackup.Role + ".sha256", stagedBackup.Sha256);

        AppendLine(body, "inputs.original", inputs.OriginalGptFingerprint);
        AppendLine(body, "inputs.current", inputs.CurrentTableFingerprint);
        AppendLine(body, "inputs.evidence", inputs.EvidenceFingerprint);
        AppendLine(body, "inputs.record.deviceId", inputs.Record.DeviceId);
        AppendLine(body, "inputs.record.userdata", inputs.Record.UserdataPartUuid);
        AppendLine(body, "inputs.record.boot", inputs.Record.LinuxBootPartUuid);
        AppendLine(body, "inputs.record.root", inputs.Record.LinuxRootPartUuid);
        AppendLine(body, "inputs.record.userdataEnd", inputs.Record.OriginalUserdataEndSector);
        if (inputs.Record.BoardBackupPartUuid is not null)
        {
            AppendLine(body, "inputs.record.boardBackup", inputs.Record.BoardBackupPartUuid);
        }

        AppendLine(body, "plan.userdataStart", plan.UserdataStart);
        AppendLine(body, "plan.userdataEnd", plan.UserdataEnd);
        AppendLine(body, "plan.restoredBytes", plan.RestoredBytes);

        foreach (long number in plan.RemovedPartitionNumbers)
        {
            AppendLine(body, "plan.removed", number);
        }

        AppendLine(body, "plan.rawTableFingerprint", plan.CurrentRawTableFingerprint);
        AppendLine(body, "plan.miscBefore", plan.MiscBeforeSha256);
        AppendLine(body, "plan.miscAfter", plan.MiscAfterSha256);

        foreach (GptRegionExpectation region in plan.Regions)
        {
            AppendLine(body, "plan.region." + region.Role + ".offset", region.ByteOffset);
            AppendLine(body, "plan.region." + region.Role + ".bytes", region.Bytes);
            AppendLine(body, "plan.region." + region.Role + ".sha256", region.Sha256);
        }

        AppendLine(body, "plan.misc.bytes", plan.MiscRegion.Bytes);
        AppendLine(body, "plan.misc.sha256", plan.MiscRegion.Sha256);

        AppendLine(body, "plan.post.primary.offset", plan.PostPrimary.ByteOffset);
        AppendLine(body, "plan.post.primary.sha256", plan.PostPrimary.Sha256);
        AppendLine(body, "plan.post.backup.offset", plan.PostBackup.ByteOffset);
        AppendLine(body, "plan.post.backup.sha256", plan.PostBackup.Sha256);

        return CanonicalHash(body);
    }

    private static void AppendRegion(StringBuilder body, string name, EdlCapturedRegion region)
    {
        AppendLine(body, name + ".lun", region.Lun);
        AppendLine(body, name + ".start", region.StartSector);
        AppendLine(body, name + ".count", region.SectorCount);
        AppendLine(body, name + ".sectorSize", region.SectorSize);
        AppendLine(body, name + ".uuid", region.PartUuid ?? string.Empty);
        AppendLine(body, name + ".length", region.Length);
        AppendLine(body, name + ".sha256", region.Sha256);
    }

    private static void AppendLine(StringBuilder body, string key, long value)
    {
        body.Append(key).Append('=').Append(value.ToString(CultureInfo.InvariantCulture)).Append('\n');
    }

    private static void AppendLine(StringBuilder body, string key, string value)
    {
        body.Append(key).Append('=').Append(value).Append('\n');
    }

    private static string CanonicalHash(StringBuilder body) =>
        Sha256Bytes(Encoding.UTF8.GetBytes(body.ToString()));

    // -----------------------------------------------------------------
    // Manifest
    // -----------------------------------------------------------------

    private static void WriteManifest(
        Utf8JsonWriter writer,
        DeviceIdentity identity,
        EdlEntryResult binding,
        EdlGeometry lun0,
        EdlUninstallCapture capture,
        StagedFile stagedPrimary,
        StagedFile stagedBackup,
        ValidatedUninstallInputs inputs,
        GptPlanEvidence plan,
        string planFingerprint,
        CurrentMenuEvidence? currentMenu = null)
    {
        writer.WriteStartObject();
        writer.WriteNumber("schemaVersion", ManifestSchemaVersion);
        writer.WriteString("kind", Operation);
        writer.WriteString("operation", Operation);
        writer.WriteString("createdUtc", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));

        writer.WritePropertyName("identity");
        SerializeIdentity(identity).WriteTo(writer);

        writer.WriteStartObject("device");
        writer.WriteString("serial", identity.Serial);
        writer.WriteString("model", identity.Model);
        writer.WriteString("bootloaderState", identity.BootloaderState.ToString());
        writer.WriteString("androidSocSerial", binding.AndroidIdentity.SocSerial);
        writer.WriteString("busSerialHex", binding.BusSerialHex);
        writer.WriteEndObject();

        writer.WriteStartObject("geometry");
        WriteGeometry(writer, "lun0", lun0);
        writer.WriteEndObject();

        writer.WriteStartObject("table");
        writer.WriteString("deviceId", capture.Lun0Table.DeviceId);
        writer.WriteString("diskGuid", capture.Lun0Table.DiskGuid);
        writer.WriteNumber("sectorSize", capture.Lun0Table.SectorSize);
        writer.WriteNumber("diskBytes", capture.Lun0Table.DiskBytes);
        writer.WriteString("sourceFingerprint", capture.Lun0Table.SourceFingerprint);
        writer.WriteEndObject();

        writer.WriteStartArray("ranges");
        foreach (string role in CaptureRoleOrder)
        {
            EdlCapturedRegion region = capture.Regions[role];
            writer.WriteStartObject();
            writer.WriteString("role", region.Role);
            writer.WriteNumber("lun", region.Lun);
            writer.WriteNumber("startSector", region.StartSector);
            writer.WriteNumber("sectorCount", region.SectorCount);
            writer.WriteNumber("sectorSize", region.SectorSize);
            writer.WriteString("partUuid", region.PartUuid ?? string.Empty);
            writer.WriteString("path", region.FilePath);
            writer.WriteNumber("length", region.Length);
            writer.WriteString("sha256", region.Sha256);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();

        writer.WriteStartArray("assets");
        foreach (StagedFile asset in new[] { stagedPrimary, stagedBackup })
        {
            writer.WriteStartObject();
            writer.WriteString("role", asset.Role);
            writer.WriteString("path", asset.Path);
            writer.WriteNumber("length", asset.Length);
            writer.WriteString("sha256", asset.Sha256);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();

        writer.WriteStartObject("inputs");
        writer.WriteString("originalGptFingerprint", inputs.OriginalGptFingerprint);
        writer.WriteString("currentTableFingerprint", inputs.CurrentTableFingerprint);
        writer.WriteString("evidenceFingerprint", inputs.EvidenceFingerprint);
        writer.WriteStartObject("record");
        writer.WriteString("deviceId", inputs.Record.DeviceId);
        writer.WriteString("userdataPartUuid", inputs.Record.UserdataPartUuid);
        writer.WriteString("linuxBootPartUuid", inputs.Record.LinuxBootPartUuid);
        writer.WriteString("linuxRootPartUuid", inputs.Record.LinuxRootPartUuid);
        if (inputs.Record.BoardBackupPartUuid is not null)
        {
            writer.WriteString("boardBackupPartUuid", inputs.Record.BoardBackupPartUuid);
        }
        writer.WriteNumber("originalUserdataEndSector", inputs.Record.OriginalUserdataEndSector);
        writer.WriteEndObject();
        writer.WriteEndObject();

        writer.WriteStartObject("gpt");
        writer.WriteString("rawTableFingerprint", plan.CurrentRawTableFingerprint);
        writer.WriteString("miscBeforeSha256", plan.MiscBeforeSha256);
        writer.WriteString("miscAfterSha256", plan.MiscAfterSha256);
        writer.WriteNumber("userdataStartLba", plan.UserdataStart);
        writer.WriteNumber("userdataEndLbaExclusive", plan.UserdataEnd);
        writer.WriteNumber("restoredBytes", plan.RestoredBytes);

        writer.WriteStartArray("removedPartitionNumbers");
        foreach (long number in plan.RemovedPartitionNumbers)
        {
            writer.WriteNumberValue(number);
        }

        writer.WriteEndArray();

        writer.WriteStartArray("regions");
        foreach (GptRegionExpectation region in plan.Regions)
        {
            writer.WriteStartObject();
            writer.WriteString("role", region.Role);
            writer.WriteString("path", region.Path);
            writer.WriteNumber("byteOffset", region.ByteOffset);
            writer.WriteNumber("bytes", region.Bytes);
            writer.WriteString("sha256", region.Sha256);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();

        writer.WriteStartObject("miscRegion");
        writer.WriteString("role", "misc-bcb");
        writer.WriteString("path", plan.MiscRegion.Path);
        writer.WriteNumber("bytes", plan.MiscRegion.Bytes);
        writer.WriteNumber("sectorCount", plan.MiscRegion.SectorCount);
        writer.WriteString("sha256", plan.MiscRegion.Sha256);
        writer.WriteEndObject();

        WritePostExpectation(writer, "postPrimary", plan.PostPrimary);
        WritePostExpectation(writer, "postBackup", plan.PostBackup);

        writer.WritePropertyName("plan");
        plan.Raw.WriteTo(writer);

        writer.WriteEndObject();

        // The optional current-menu object carries only the bound plan reference, the
        // slot, both source backup directories, the staged verification report and the
        // write role order/summary; the full slot facts stay hashed inside plan.json.
        // It is a root-level sibling of "gpt", never nested inside it.
        if (currentMenu is not null)
        {
            writer.WriteStartObject("currentMenu");
            writer.WriteStartObject("manifest");
            writer.WriteString("path", currentMenu.Manifest.Path);
            writer.WriteNumber("lengthBytes", currentMenu.Manifest.Length);
            writer.WriteString("sha256", currentMenu.Manifest.Sha256);
            writer.WriteEndObject();
            writer.WriteString("currentSlot", currentMenu.CurrentSlot);
            writer.WriteString("originalBackupDirectory", currentMenu.OriginalBackupDirectory);
            writer.WriteString("currentBackupDirectory", currentMenu.CurrentBackupDirectory);
            writer.WriteStartObject("verificationReport");
            writer.WriteString("path", currentMenu.Report.Path);
            writer.WriteNumber("lengthBytes", currentMenu.Report.Length);
            writer.WriteString("sha256", currentMenu.Report.Sha256);
            writer.WriteEndObject();
            writer.WriteStartArray("writeRoles");
            foreach (MenuWriteTarget target in currentMenu.WriteTargets)
            {
                writer.WriteStringValue(target.Role);
            }

            writer.WriteEndArray();
            writer.WriteNumber("writeCount", currentMenu.WriteTargets.Count);
            writer.WriteNumber("totalCandidateBytes", currentMenu.TotalCandidateBytes);
            writer.WriteEndObject();
        }

        writer.WriteString("planFingerprint", planFingerprint);

        writer.WriteEndObject();
    }

    private static void WriteGeometry(Utf8JsonWriter writer, string name, EdlGeometry geometry)
    {
        writer.WriteStartObject(name);
        writer.WriteNumber("lun", geometry.Lun);
        writer.WriteNumber("sectorSize", geometry.SectorSize);
        writer.WriteNumber("totalSectors", geometry.TotalSectors);
        writer.WriteEndObject();
    }

    private static void WritePostExpectation(Utf8JsonWriter writer, string name, PostExpectation post)
    {
        writer.WriteStartObject(name);
        writer.WriteString("path", post.Path);
        writer.WriteNumber("byteOffset", post.ByteOffset);
        writer.WriteNumber("bytes", post.Bytes);
        writer.WriteString("sha256", post.Sha256);
        writer.WriteEndObject();
    }

    private static void WriteFileReference(Utf8JsonWriter writer, string name, EdlCapturedRegion region)
    {
        writer.WriteStartObject(name);
        writer.WriteString("path", region.FilePath);
        writer.WriteString("sha256", region.Sha256);
        writer.WriteEndObject();
    }

    private static void WriteStagedReference(Utf8JsonWriter writer, string name, StagedFile file)
    {
        writer.WriteStartObject(name);
        writer.WriteString("path", file.Path);
        writer.WriteString("sha256", file.Sha256);
        writer.WriteEndObject();
    }

    private static JsonElement SerializeIdentity(DeviceIdentity identity)
    {
        try
        {
            return JsonSerializer.SerializeToElement(identity);
        }
        catch (Exception error) when (
            error is NotSupportedException || error is InvalidOperationException || error is ArgumentException)
        {
            return JsonSerializer.SerializeToElement(identity.ToString() ?? string.Empty);
        }
    }

    // -----------------------------------------------------------------
    // GPT byte helpers
    // -----------------------------------------------------------------

    private static (long Start, long Count) ReadArrayRange(
        byte[] slice,
        int sectorSize,
        int headerOffset,
        long totalSectors,
        string name)
    {
        if (headerOffset < 0 || headerOffset + 92 > slice.Length)
        {
            throw new InvalidOperationException(
                "The captured " + name + " GPT header does not fit in its slice.");
        }

        ulong entriesLba = BinaryPrimitives.ReadUInt64LittleEndian(slice.AsSpan(headerOffset + 72, 8));
        uint entryCount = BinaryPrimitives.ReadUInt32LittleEndian(slice.AsSpan(headerOffset + 80, 4));
        uint entrySize = BinaryPrimitives.ReadUInt32LittleEndian(slice.AsSpan(headerOffset + 84, 4));

        if (entryCount == 0 || entrySize < 128)
        {
            throw new InvalidOperationException(
                "The captured " + name + " GPT header describes no usable entry array.");
        }

        long arrayBytes;
        try
        {
            arrayBytes = checked((long)entryCount * entrySize);
        }
        catch (OverflowException)
        {
            throw new InvalidOperationException(
                "The captured " + name + " GPT entry array overflows a 64-bit byte count.");
        }

        long arraySectors = (arrayBytes + sectorSize - 1) / sectorSize;

        if (entriesLba < 2 || checked((long)entriesLba + arraySectors) > totalSectors - 1)
        {
            throw new InvalidOperationException(
                "The captured " + name + " GPT entry array falls outside LUN0.");
        }

        return ((long)entriesLba, arraySectors);
    }

    private static byte[] Overlay(
        byte[] baseBytes,
        long baseOffset,
        IReadOnlyList<GptRegionExpectation> regions)
    {
        byte[] copy = (byte[])baseBytes.Clone();

        foreach (GptRegionExpectation region in regions)
        {
            long relative = checked(region.ByteOffset - baseOffset);
            if (relative < 0 || relative >= copy.LongLength)
            {
                continue;
            }

            byte[] overlay = File.ReadAllBytes(region.Path);
            int length = (int)Math.Min(overlay.LongLength, copy.LongLength - relative);
            Array.Copy(overlay, 0, copy, (int)relative, length);
        }

        return copy;
    }

    private static async Task<string> HashPrefixOverlayAsync(
        string basePath,
        long prefixLength,
        string overlayPath,
        CancellationToken token)
    {
        using (IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            byte[] buffer = new byte[FileBufferBytes];

            using (var overlay = new FileStream(
                overlayPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                FileBufferBytes, FileOptions.SequentialScan))
            {
                int read;
                while ((read = await overlay.ReadAsync(buffer.AsMemory(0, buffer.Length), token)
                    .ConfigureAwait(false)) > 0)
                {
                    hash.AppendData(buffer, 0, read);
                }
            }

            using (var baseStream = new FileStream(
                basePath, FileMode.Open, FileAccess.Read, FileShare.Read,
                FileBufferBytes, FileOptions.SequentialScan))
            {
                baseStream.Seek(prefixLength, SeekOrigin.Begin);

                int read;
                while ((read = await baseStream.ReadAsync(buffer.AsMemory(0, buffer.Length), token)
                    .ConfigureAwait(false)) > 0)
                {
                    hash.AppendData(buffer, 0, read);
                }
            }

            return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
        }
    }

    // -----------------------------------------------------------------
    // File helpers
    // -----------------------------------------------------------------

    private static StagedFile Stage(
        string sourcePath,
        string destinationPath,
        string role,
        long expectedLength,
        string? expectedSha256,
        CancellationToken token)
    {
        using (IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            byte[] buffer = new byte[FileBufferBytes];
            long total = 0;

            using (var source = new FileStream(
                sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read,
                FileBufferBytes, FileOptions.SequentialScan))
            using (var destination = new FileStream(
                destinationPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                FileBufferBytes, FileOptions.None))
            {
                while (true)
                {
                    token.ThrowIfCancellationRequested();

                    int read = source.Read(buffer, 0, buffer.Length);
                    if (read <= 0)
                    {
                        break;
                    }

                    destination.Write(buffer, 0, read);
                    hash.AppendData(buffer, 0, read);
                    total += read;
                }

                destination.Flush(true);
            }

            string sha256 = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();

            if (expectedLength >= 0 && total != expectedLength)
            {
                throw new InvalidOperationException(
                    "The '" + role + "' copy holds " + total + " bytes instead of " + expectedLength + ".");
            }

            if (total <= 0)
            {
                throw new IOException("The '" + role + "' source file is empty: '" + sourcePath + "'.");
            }

            if (expectedSha256 != null && !string.Equals(sha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "The '" + role + "' copy does not match the captured range hash.");
            }

            return new StagedFile(role, destinationPath, total, sha256);
        }
    }

    private static void AddStaged(StagedFile file, List<FileStream> locks, List<PinnedFile> pinned) =>
        AddPinned(file.Path, "asset:" + file.Role, locks, pinned);

    private static void AddPinned(
        string path,
        string role,
        List<FileStream> locks,
        List<PinnedFile> pinned)
    {
        var info = new FileInfo(path);
        if (!info.Exists)
        {
            throw new InvalidOperationException("The prepared file '" + path + "' was not produced.");
        }

        // The file is complete at this point; the lock is what keeps it immutable.
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, FileBufferBytes);
        locks.Add(stream);

        pinned.Add(new PinnedFile(role, path, info.Length, HashFile(path)));
    }

    private static void WriteJson(string path, Action<Utf8JsonWriter> body, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        using (var stream = new FileStream(
            path, FileMode.CreateNew, FileAccess.Write, FileShare.None, FileBufferBytes, FileOptions.None))
        {
            using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
            {
                body(writer);
                writer.Flush();
            }

            stream.Flush(true);
        }
    }

    private static void WriteText(string path, string text)
    {
        byte[] bytes = new UTF8Encoding(false).GetBytes(text ?? string.Empty);

        using (var stream = new FileStream(
            path, FileMode.CreateNew, FileAccess.Write, FileShare.None, FileBufferBytes, FileOptions.None))
        {
            stream.Write(bytes, 0, bytes.Length);
            stream.Flush(true);
        }
    }

    private static async Task<string> HashFileAsync(string path, CancellationToken token)
    {
        using (var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read,
            FileBufferBytes, FileOptions.SequentialScan))
        {
            byte[] hash = await SHA256.HashDataAsync(stream, token).ConfigureAwait(false);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
    }

    private static string HashFile(string path)
    {
        using (var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read,
            FileBufferBytes, FileOptions.SequentialScan))
        {
            return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }
    }

    private static string Sha256Bytes(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    // -----------------------------------------------------------------
    // Process bridge
    // -----------------------------------------------------------------

    private static async Task<ProcessResult> RunBridgeAsync(
        ICommandRunner runner,
        string python,
        IReadOnlyList<string> arguments,
        CancellationToken token)
    {
        var command = new ProcessCommand(python, arguments, TimeSpan.FromSeconds(BridgeTimeoutSeconds));
        ProcessResult? result = await runner.RunAsync(command, token).ConfigureAwait(false);

        if (result is null)
        {
            throw new InvalidOperationException("The command runner returned no result for '" + python + "'.");
        }

        return result;
    }

    private static JsonDocument ParseSingleObject(string? text, string what)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            throw new InvalidOperationException(what + " produced no JSON output.");
        }

        JsonDocument document;

        try
        {
            // Default options reject a second JSON value after the object, so a trailing
            // document or an unterminated object is rejected here.
            document = JsonDocument.Parse(text);
        }
        catch (JsonException error)
        {
            throw new InvalidOperationException(
                what + " did not produce one complete JSON object.", error);
        }

        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            document.Dispose();
            throw new InvalidOperationException(what + " did not produce a JSON object.");
        }

        return document;
    }

    // -----------------------------------------------------------------
    // JSON helpers
    // -----------------------------------------------------------------

    private static JsonElement Object(JsonElement parent, string name, string what)
    {
        if (parent.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException(what + " is not a JSON object.");
        }

        if (!parent.TryGetProperty(name, out JsonElement value) || value.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException(what + " is missing the object '" + name + "'.");
        }

        return value;
    }

    private static JsonElement ArrayProperty(JsonElement parent, string name, string what)
    {
        if (parent.ValueKind != JsonValueKind.Object
            || !parent.TryGetProperty(name, out JsonElement value)
            || value.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException(what + " is missing the array '" + name + "'.");
        }

        return value;
    }

    private static string Text(JsonElement parent, string name, string what)
    {
        if (parent.ValueKind != JsonValueKind.Object
            || !parent.TryGetProperty(name, out JsonElement value)
            || value.ValueKind != JsonValueKind.String)
        {
            throw new InvalidOperationException(what + " is missing the string '" + name + "'.");
        }

        return value.GetString() ?? string.Empty;
    }

    private static string NonEmptyText(JsonElement parent, string name, string what)
    {
        string value = Text(parent, name, what);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException(what + " carries an empty '" + name + "'.");
        }

        return value;
    }

    private static string Hex64(JsonElement parent, string name, string what) =>
        Hex64(Text(parent, name, what), what + " field '" + name + "'");

    private static string Hex64(string value, string what)
    {
        RequireHex64(value, what);
        return value;
    }

    private static void RequireHex64(string value, string what)
    {
        if (string.IsNullOrEmpty(value) || value.Length != 64)
        {
            throw new InvalidOperationException(what + " is not a 64-character hex SHA-256.");
        }

        foreach (char character in value)
        {
            bool hex = (character >= '0' && character <= '9')
                || (character >= 'a' && character <= 'f')
                || (character >= 'A' && character <= 'F');

            if (!hex)
            {
                throw new InvalidOperationException(what + " is not a hexadecimal SHA-256.");
            }
        }
    }

    private static long Number(JsonElement parent, string name, string what)
    {
        if (parent.ValueKind != JsonValueKind.Object
            || !parent.TryGetProperty(name, out JsonElement value))
        {
            throw new InvalidOperationException(what + " is missing the number '" + name + "'.");
        }

        return Integral(value, what + " field '" + name + "'");
    }

    private static long Integral(JsonElement value, string what)
    {
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out long number))
        {
            throw new InvalidOperationException(what + " is not an integral number.");
        }

        return number;
    }

    private static bool Flag(JsonElement parent, string name, string what)
    {
        if (parent.ValueKind != JsonValueKind.Object
            || !parent.TryGetProperty(name, out JsonElement value)
            || (value.ValueKind != JsonValueKind.True && value.ValueKind != JsonValueKind.False))
        {
            throw new InvalidOperationException(what + " is missing the boolean '" + name + "'.");
        }

        return value.GetBoolean();
    }

    private static void RequireOwnedFile(
        string path,
        string root,
        long expectedLength,
        string expectedSha256,
        string what,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        if (!IsUnder(path, root))
        {
            throw new InvalidOperationException(
                what + " points outside the planned output directory.");
        }

        var info = new FileInfo(path);
        if (!info.Exists)
        {
            throw new InvalidOperationException(what + " file does not exist.");
        }

        if (info.Length != expectedLength)
        {
            throw new InvalidOperationException(
                what + " file holds " + info.Length + " bytes instead of " + expectedLength + ".");
        }

        string actual = HashFile(path);
        if (!string.Equals(actual, expectedSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(what + " file does not match its declared SHA-256.");
        }
    }

    // -----------------------------------------------------------------
    // Path helpers
    // -----------------------------------------------------------------

    private static string RequireToolPath(string? path, string what)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new IOException("The " + what + " path is empty.");
        }

        return path;
    }

    private static string RequireExistingFile(string? path, string what)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new IOException("The " + what + " path is empty.");
        }

        string full;

        try
        {
            full = Path.GetFullPath(path);
        }
        catch (Exception error) when (error is ArgumentException || error is NotSupportedException)
        {
            throw new IOException("The " + what + " path is not usable: '" + path + "'.", error);
        }

        if (!File.Exists(full))
        {
            throw new FileNotFoundException(
                "The " + what + " file does not exist: '" + full + "'.", full);
        }

        return full;
    }

    private static bool IsSameOrUnder(string path, string root)
    {
        if (string.IsNullOrEmpty(root))
        {
            return false;
        }

        try
        {
            string full = Path.GetFullPath(path);
            string fullRoot = Path.GetFullPath(root);

            if (!fullRoot.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal))
            {
                fullRoot += Path.DirectorySeparatorChar;
            }

            return full.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception error) when (error is ArgumentException || error is NotSupportedException)
        {
            return false;
        }
    }

    private static bool IsUnder(string path, string root) => IsSameOrUnder(path, root);

    private static string Detail(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return string.Empty;
        }

        return " " + Truncate(text.Trim());
    }

    private static string Truncate(string text)
    {
        const int Limit = 2000;
        return text.Length <= Limit ? text : text.Substring(0, Limit);
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(EdlUninstallBackend));
        }
    }

    // -----------------------------------------------------------------
    // Write-stage state and proof helpers
    // -----------------------------------------------------------------

    private enum StepState
    {
        Idle,
        Prepared,
        InitializeAndroid,
        Done,
    }

    private void EnsureHealthy()
    {
        if (Volatile.Read(ref _poisoned) != 0)
        {
            throw new InvalidOperationException(
                "A previous device write or post-write verification is uncertain; " +
                "this backend refuses any further device operation.");
        }
    }

    private void MarkUncertain() => Interlocked.Exchange(ref _poisoned, 1);

    private static void RequireRange(EdlGeometry geometry, long start, long count, string what)
    {
        if (start < 0 || count <= 0 || start > geometry.TotalSectors - count)
        {
            throw new InvalidOperationException(
                "The '" + what + "' range falls outside LUN" + geometry.Lun + ".");
        }
    }

    private static void RequireOwnedLength(string path, long expectedBytes, string what)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length != expectedBytes)
        {
            throw new InvalidOperationException(
                "The " + what + " file does not carry the prepared byte count.");
        }
    }

    private async Task<EdlGeometry> WarmProbeAsync(int lun, CancellationToken token)
    {
        // The initial loader is never carried on a warm probe: the capture already proved
        // the initial Sahara session, and restarting it could disrupt an accepted write.
        EdlProbeEvidence probe = await _client
            .ProbeAsync(lun, false, token)
            .ConfigureAwait(false);

        if (probe is null || probe.Geometry is null)
        {
            throw new InvalidOperationException(
                "The warm probe of LUN" + lun + " returned no geometry.");
        }

        EdlGeometry geometry = probe.Geometry;
        if (geometry.Lun != lun)
        {
            throw new InvalidOperationException(
                "The warm probe returned geometry for LUN" + geometry.Lun +
                " instead of the requested LUN" + lun + ".");
        }

        CompareGeometry(geometry, PinnedGeometry(lun), "LUN" + lun);
        return geometry;
    }

    private EdlGeometry PinnedGeometry(int lun)
    {
        if (lun == 0)
        {
            return _capture.Lun0Geometry;
        }

        if (_currentMenu is not null
            && _currentMenu.Geometries.TryGetValue(lun, out EdlGeometry? geometry))
        {
            return geometry;
        }

        throw new InvalidOperationException(
            "LUN" + lun + " is not part of the prepared geometry.");
    }

    private static void VerifyWriteEvidence(
        EdlWriteEvidence evidence,
        EdlGeometry geometry,
        long start,
        long count,
        long length,
        string sha256,
        string what)
    {
        if (evidence is null || evidence.Geometry is null)
        {
            throw new InvalidOperationException(
                "The " + what + " write returned no geometry-backed evidence.");
        }

        CompareGeometry(evidence.Geometry, geometry, what + " write");

        if (evidence.StartSector != start
            || evidence.SectorCount != count
            || evidence.Length != length
            || !string.Equals(evidence.Sha256, sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The " + what +
                " write evidence does not match the requested whole range and host hash.");
        }
    }

    private async Task<string> ReadVerifiedAsync(
        EdlGeometry geometry,
        long start,
        long count,
        string role,
        string? expectedSha256,
        CancellationToken token)
    {
        long expectedLength;

        try
        {
            expectedLength = checked(count * (long)geometry.SectorSize);
        }
        catch (OverflowException)
        {
            throw new InvalidOperationException(
                "The '" + role + "' read range overflows a 64-bit byte count.");
        }

        string directory = Path.Combine(_backupDirectory, "readback");
        Directory.CreateDirectory(directory);

        string path = Path.Combine(
            directory, role + "-" + Guid.NewGuid().ToString("N") + ".bin");

        token.ThrowIfCancellationRequested();

        EdlReadEvidence evidence = await _client
            .ReadAsync(
                geometry.Lun,
                start,
                count,
                path,
                TransferAdapter(Stages.Reading, role),
                TransferLogPrefix(role),
                token)
            .ConfigureAwait(false);

        if (evidence is null || evidence.Geometry is null)
        {
            throw new InvalidOperationException(
                "The '" + role + "' read returned no geometry-backed evidence.");
        }

        CompareGeometry(evidence.Geometry, geometry, role + " read");

        if (evidence.StartSector != start
            || evidence.SectorCount != count
            || evidence.Length != expectedLength
            || !SamePath(evidence.FilePath, path))
        {
            throw new InvalidOperationException(
                "The '" + role + "' read evidence does not match the requested range and file.");
        }

        var info = new FileInfo(path);
        if (!info.Exists || info.Length != expectedLength)
        {
            throw new InvalidOperationException(
                "The '" + role + "' read did not produce the whole requested file.");
        }

        string actual = await HashFileAsync(path, token).ConfigureAwait(false);

        if (string.IsNullOrEmpty(evidence.Sha256)
            || !string.Equals(actual, evidence.Sha256, StringComparison.OrdinalIgnoreCase)
            || (expectedSha256 != null
                && !string.Equals(actual, expectedSha256, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException(
                "The whole-file SHA-256 of '" + path + "' does not match both the read " +
                "evidence and the pinned expectation.");
        }

        token.ThrowIfCancellationRequested();

        // Only this newly created read-back file is flushed and then pinned read-only; the
        // files that were read from are never reopened for writing.
        FlushDurable(path);
        _locks.Add(new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, FileBufferBytes));

        return path;
    }

    private static bool SamePath(string left, string right)
    {
        try
        {
            return string.Equals(
                Path.GetFullPath(left), Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception error) when (error is ArgumentException || error is NotSupportedException)
        {
            return false;
        }
    }

    private static void FlushDurable(string path)
    {
        using (var writable = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            writable.Flush(true);
        }
    }

    private void WriteProgress(
        string kind,
        string role,
        int lun,
        long start,
        long count,
        long length,
        string sha256,
        CancellationToken token)
    {
        string directory = Path.Combine(_backupDirectory, "progress");
        Directory.CreateDirectory(directory);

        string path = Path.Combine(
            directory,
            kind + "-" + role + "-" + Guid.NewGuid().ToString("N") + ".json");

        WriteJson(path, writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", ManifestSchemaVersion);
            writer.WriteString("kind", kind);
            writer.WriteString("role", role);
            writer.WriteNumber("lun", lun);
            writer.WriteNumber("startSector", start);
            writer.WriteNumber("sectorCount", count);
            writer.WriteNumber("payloadBytes", length);
            writer.WriteString("sha256", sha256);
            writer.WriteString("planFingerprint", _planFingerprint);
            writer.WriteString(
                "createdUtc",
                DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            writer.WriteEndObject();
        }, token);
    }

    private void RequirePlanGeometry(
        EdlGeometry geometry,
        EdlCapturedRegion primary,
        EdlCapturedRegion backup)
    {
        if (_plan.Regions.Count != GptRegionRoleOrder.Length)
        {
            throw new InvalidOperationException(
                "The prepared GPT plan does not contain exactly four write regions.");
        }

        for (int index = 0; index < GptRegionRoleOrder.Length; index++)
        {
            GptRegionExpectation region = _plan.Regions[index];

            if (!string.Equals(region.Role, GptRegionRoleOrder[index], StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "The prepared GPT write regions are not in the pinned order.");
            }

            GptRegionRange(region, geometry);
            RequireOwnedLength(region.Path, region.Bytes, "GPT region '" + region.Role + "'");
        }

        long diskBytes = CheckedDiskBytes(geometry);
        long backupOffset = diskBytes - backup.Length;

        if (_plan.PostPrimary.ByteOffset != 0
            || _plan.PostPrimary.Bytes != primary.Length
            || _plan.PostBackup.ByteOffset != backupOffset
            || _plan.PostBackup.Bytes != backup.Length)
        {
            throw new InvalidOperationException(
                "The prepared post-write GPT expectations do not cover the captured GPT ranges.");
        }
    }

    private static (long Start, long Count) GptRegionRange(
        GptRegionExpectation region,
        EdlGeometry geometry)
    {
        if (region.ByteOffset < 0
            || region.Bytes <= 0
            || region.ByteOffset % geometry.SectorSize != 0
            || region.Bytes % geometry.SectorSize != 0)
        {
            throw new InvalidOperationException(
                "The GPT region '" + region.Role + "' is not aligned to the device sector size.");
        }

        long start = region.ByteOffset / geometry.SectorSize;
        long count = region.Bytes / geometry.SectorSize;

        if (start == 0)
        {
            throw new InvalidOperationException(
                "The GPT region '" + region.Role + "' would rewrite LUN0 LBA0.");
        }

        RequireRange(geometry, start, count, "gpt-region:" + region.Role);
        return (start, count);
    }

    private static long CheckedDiskBytes(EdlGeometry geometry)
    {
        try
        {
            long diskBytes = checked(geometry.TotalSectors * (long)geometry.SectorSize);
            if (diskBytes <= 0)
            {
                throw new InvalidOperationException(
                    "LUN" + geometry.Lun + " reports a non-positive disk size.");
            }

            return diskBytes;
        }
        catch (OverflowException)
        {
            throw new InvalidOperationException(
                "LUN" + geometry.Lun + " reports a disk size that overflows a 64-bit byte count.");
        }
    }

    // -----------------------------------------------------------------
    // Private state
    // -----------------------------------------------------------------

    private sealed class StagedFile
    {
        internal StagedFile(string role, string path, long length, string sha256)
        {
            Role = role;
            Path = path;
            Length = length;
            Sha256 = sha256;
        }

        internal string Role { get; }

        internal string Path { get; }

        internal long Length { get; }

        internal string Sha256 { get; }
    }

    private sealed class PinnedFile
    {
        internal PinnedFile(string role, string path, long length, string sha256)
        {
            Role = role;
            Path = path;
            Length = length;
            Sha256 = sha256;
        }

        internal string Role { get; }

        internal string Path { get; }

        internal long Length { get; }

        internal string Sha256 { get; }
    }

    private sealed class GptRegionExpectation
    {
        internal GptRegionExpectation(
            string role,
            string path,
            long byteOffset,
            long bytes,
            string sha256)
        {
            Role = role;
            Path = path;
            ByteOffset = byteOffset;
            Bytes = bytes;
            Sha256 = sha256;
        }

        internal string Role { get; }

        internal string Path { get; }

        internal long ByteOffset { get; }

        internal long Bytes { get; }

        internal string Sha256 { get; }
    }

    private sealed class MiscRegionExpectation
    {
        internal MiscRegionExpectation(string path, long bytes, long sectorCount, string sha256)
        {
            Path = path;
            Bytes = bytes;
            SectorCount = sectorCount;
            Sha256 = sha256;
        }

        internal string Path { get; }

        internal long Bytes { get; }

        internal long SectorCount { get; }

        internal string Sha256 { get; }
    }

    private sealed class PostExpectation
    {
        internal PostExpectation(string name, string path, long byteOffset, long bytes, string sha256)
        {
            Name = name;
            Path = path;
            ByteOffset = byteOffset;
            Bytes = bytes;
            Sha256 = sha256;
        }

        internal string Name { get; }

        internal string Path { get; }

        internal long ByteOffset { get; }

        internal long Bytes { get; }

        internal string Sha256 { get; }
    }

    private sealed class GptPlanEvidence
    {
        internal GptPlanEvidence(
            long userdataStart,
            long userdataEnd,
            long restoredBytes,
            IReadOnlyList<long> removedPartitionNumbers,
            string currentRawTableFingerprint,
            string miscBeforeSha256,
            string miscAfterSha256,
            IReadOnlyList<GptRegionExpectation> regions,
            MiscRegionExpectation miscRegion,
            PostExpectation postPrimary,
            PostExpectation postBackup,
            JsonElement raw)
        {
            UserdataStart = userdataStart;
            UserdataEnd = userdataEnd;
            RestoredBytes = restoredBytes;
            RemovedPartitionNumbers = removedPartitionNumbers;
            CurrentRawTableFingerprint = currentRawTableFingerprint;
            MiscBeforeSha256 = miscBeforeSha256;
            MiscAfterSha256 = miscAfterSha256;
            Regions = regions;
            MiscRegion = miscRegion;
            PostPrimary = postPrimary;
            PostBackup = postBackup;
            Raw = raw;
        }

        internal long UserdataStart { get; }

        internal long UserdataEnd { get; }

        internal long RestoredBytes { get; }

        internal IReadOnlyList<long> RemovedPartitionNumbers { get; }

        internal string CurrentRawTableFingerprint { get; }

        internal string MiscBeforeSha256 { get; }

        internal string MiscAfterSha256 { get; }

        internal IReadOnlyList<GptRegionExpectation> Regions { get; }

        internal MiscRegionExpectation MiscRegion { get; }

        internal PostExpectation PostPrimary { get; }

        internal PostExpectation PostBackup { get; }

        // Cloned so the manifest keeps the full plan after the response document is disposed.
        internal JsonElement Raw { get; }
    }
}
