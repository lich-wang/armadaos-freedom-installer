using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

public sealed record TfTabletInstallRequest(string EvidenceParent);

public enum TfTabletInstallStage
{
    PreparedTemporary,
    WritingTemporaryBoot,
    AwaitingRamConnection,
    RamConnected,
    CardPrepared,
    WritingCard,
    AwaitingEdlReturn,
    PreparedFinalBoot,
    WritingFinalBoot,
    Completed,
    PreparedRestorePrevious,
    RestoringPrevious,
    RestoredPrevious,
    Failed,
    Cancelled,
    UnknownWriteOutcome
}

public sealed class TfTabletTemporaryPrepared
{
    internal TfTabletTemporaryPrepared(
        string confirmationId,
        TfBootPrepared temporaryBoot,
        TfBootPlan finalBootPlan,
        string backupDirectory,
        string evidenceDirectory,
        string statePath,
        string recoveryJournalPath,
        string model,
        string currentSlot)
    {
        ConfirmationId = confirmationId;
        TemporaryBoot = temporaryBoot;
        FinalBootPlan = finalBootPlan;
        BackupDirectory = backupDirectory;
        EvidenceDirectory = evidenceDirectory;
        StatePath = statePath;
        RecoveryJournalPath = recoveryJournalPath;
        Model = model;
        CurrentSlot = currentSlot;
    }

    public string ConfirmationId { get; }
    public TfBootPrepared TemporaryBoot { get; }
    public TfBootPlan FinalBootPlan { get; }
    public string BackupDirectory { get; }
    public string EvidenceDirectory { get; }
    public string StatePath { get; }
    public string RecoveryJournalPath { get; }
    public string Model { get; }
    public string CurrentSlot { get; }
}

public sealed class TfTabletInstallSnapshot
{
    internal TfTabletInstallSnapshot(
        TfTabletInstallStage stage,
        bool isBusy,
        bool requiresBootRecovery,
        TfBootResult? temporaryResult,
        TfCardWriteEvidence? cardEvidence,
        TfBootResult? finalResult,
        TfBootResult? restoreResult,
        string? error)
    {
        Stage = stage;
        IsBusy = isBusy;
        RequiresBootRecovery = requiresBootRecovery;
        TemporaryResult = temporaryResult;
        CardEvidence = cardEvidence;
        FinalResult = finalResult;
        RestoreResult = restoreResult;
        Error = error;
    }

    public TfTabletInstallStage Stage { get; }
    public bool IsBusy { get; }
    public bool RequiresBootRecovery { get; }
    public TfBootResult? TemporaryResult { get; }
    public TfCardWriteEvidence? CardEvidence { get; }
    public TfBootResult? FinalResult { get; }
    public TfBootResult? RestoreResult { get; }
    public string? Error { get; }
}

// Stage 1 of the TF tablet install workflow: real preparation, temporary RAM boot,
// serial/NCM bootstrap and the public pause/return state. Card writing, final boot
// and restore-previous arrive in later partials using the backend owner APIs.
public sealed partial class TfTabletInstallWorkflow : IAsyncDisposable
{
    private readonly string _evidenceDirectory;
    private readonly string _statePath;

    // Owned by this controller.
    private readonly InternalBackupSet _originalBackup;
    private readonly TfPreparedCardImages _images;
    private readonly TfBootPlan _ramPlan;
    private readonly TfBootPlan _finalPlan;
    private readonly TfBootBackend _tempBackend;

    // Borrowed for the connection phase lifetime; never disposed here.
    private readonly IMaintenanceBundle _toolboxBundle;
    private readonly HttpClient _httpClient;
    private readonly ICommandRunner _runner;
    private readonly ImportedPackage _sourcePackage;

    // Connection phase objects, created and owned by the controller.
    private MaintenanceBootstrap.TfMaintenanceRuntime? _runtime;
    private WindowsMaintenanceConsole? _console;
    private TcpMaintenanceTransfer? _transfer;
    private MaintenanceBootstrap? _bootstrap;

    // Facts.
    private readonly string _nonce;
    private readonly string _confirmationBindSha256;
    private readonly string _rollbackJournalSha256;
    private readonly string _kernelSha256;
    private readonly ulong _socSerial;

    private TfTabletInstallStage _stage = TfTabletInstallStage.PreparedTemporary;
    private bool _requiresBootRecovery;
    private bool _tempAttempted;
    private bool _busy;
    private string? _error;
    private TfBootResult? _tempResult;
    private TfCardWriteEvidence? _cardEvidence;
    private TfBootResult? _finalResult;
    private TfBootResult? _restoreResult;

    private readonly SemaphoreSlim _gate = new(1, 1);
    private int _disposed;

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
            throw new ObjectDisposedException(nameof(TfTabletInstallWorkflow));
    }

    private TfTabletInstallWorkflow(
        string evidenceDirectory,
        string statePath,
        InternalBackupSet originalBackup,
        TfPreparedCardImages images,
        TfBootPlan ramPlan,
        TfBootPlan finalPlan,
        TfBootBackend tempBackend,
        IMaintenanceBundle toolboxBundle,
        HttpClient httpClient,
        ICommandRunner runner,
        ImportedPackage sourcePackage,
        string nonce,
        string confirmationBindSha256,
        string rollbackJournalSha256,
        string kernelSha256,
        ulong socSerial)
    {
        _evidenceDirectory = evidenceDirectory;
        _statePath = statePath;
        _originalBackup = originalBackup;
        _images = images;
        _ramPlan = ramPlan;
        _finalPlan = finalPlan;
        _tempBackend = tempBackend;
        _toolboxBundle = toolboxBundle;
        _httpClient = httpClient;
        _runner = runner;
        _sourcePackage = sourcePackage;
        _nonce = nonce;
        _confirmationBindSha256 = confirmationBindSha256;
        _rollbackJournalSha256 = rollbackJournalSha256;
        _kernelSha256 = kernelSha256;
        _socSerial = socSerial;
    }

    public TfTabletTemporaryPrepared Prepared { get; private set; } = null!;

    public TfTabletInstallSnapshot Snapshot => new(
        _stage,
        _busy,
        _requiresBootRecovery,
        _tempResult,
        _cardEvidence,
        _finalResult,
        _restoreResult,
        _error);

    public static Task<TfTabletInstallWorkflow> PrepareTabletAsync(
        TfTabletInstallRequest request,
        InternalDeviceCheckResult check,
        EdlClient client,
        InternalBackupSet currentBackup,
        ImportedPackage package,
        EdlRawBootTools tools,
        ICommandRunner runner,
        IMaintenanceBundle toolboxBundle,
        HttpClient httpClient,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(check);
        return PrepareCoreAsync(request, history: null, check, client, currentBackup, package, tools, runner, toolboxBundle, httpClient, ct);
    }

    public static Task<TfTabletInstallWorkflow> PrepareTabletFromEdlAsync(
        TfTabletInstallRequest request,
        BootMaintenanceHistoricalIdentity history,
        EdlClient client,
        InternalBackupSet currentBackup,
        ImportedPackage package,
        EdlRawBootTools tools,
        ICommandRunner runner,
        IMaintenanceBundle toolboxBundle,
        HttpClient httpClient,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(history);
        return PrepareCoreAsync(request, history, check: null, client, currentBackup, package, tools, runner, toolboxBundle, httpClient, ct);
    }

    private static async Task<TfTabletInstallWorkflow> PrepareCoreAsync(
        TfTabletInstallRequest request,
        BootMaintenanceHistoricalIdentity? history,
        InternalDeviceCheckResult? check,
        EdlClient client,
        InternalBackupSet currentBackup,
        ImportedPackage package,
        EdlRawBootTools tools,
        ICommandRunner runner,
        IMaintenanceBundle toolboxBundle,
        HttpClient httpClient,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(currentBackup);
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(tools);
        ArgumentNullException.ThrowIfNull(runner);
        ArgumentNullException.ThrowIfNull(toolboxBundle);
        ArgumentNullException.ThrowIfNull(httpClient);
        if (string.IsNullOrWhiteSpace(request.EvidenceParent))
            throw new ArgumentException("Evidence parent is required.", nameof(request));

        var evidenceParent = request.EvidenceParent;
        if (!Path.IsPathRooted(evidenceParent) || !Directory.Exists(evidenceParent))
            throw new DirectoryNotFoundException($"Evidence parent does not exist: {evidenceParent}");

        var evidenceDirectory = Path.Combine(evidenceParent, $"tf-tablet-{Guid.NewGuid():N}");
        Directory.CreateDirectory(evidenceDirectory);
        var statePath = Path.Combine(evidenceDirectory, "tf-tablet-state.json");

        // 1. Own independent reopen of the original snapshot, bound to the same client.
        var original = await InternalInstallBackup.OpenExistingAsync(client, currentBackup.DirectoryPath, null, ct).ConfigureAwait(false);
        bool originalOwned = true;
        try
        {
            if (!string.Equals(original.ManifestSha256, currentBackup.ManifestSha256, StringComparison.Ordinal))
                throw new InvalidOperationException("Original backup manifest SHA does not match the passed backup set.");
            if (!string.Equals(original.Model, currentBackup.Model, StringComparison.Ordinal))
                throw new InvalidOperationException("Original backup model does not match the passed backup set.");

            var misc = original.Files["misc"];
            var slotFacts = await BootSlotControl.ReadAsync(new VerifiedEdlFile(misc.FilePath, misc.Length, misc.Sha256), ct).ConfigureAwait(false);
            var slot = slotFacts.CurrentSlot;
            if (slot is not ("a" or "b"))
                throw new InvalidOperationException($"Active slot from misc is not a/b: '{slot ?? "<null>"}'.");

            BootloaderState lockState;
            if (check is not null)
            {
                if (!string.Equals(check.CurrentSlot, slot, StringComparison.Ordinal))
                    throw new InvalidOperationException($"Device check slot '{check.CurrentSlot}' does not match misc slot '{slot}'.");
                lockState = check.FastbootLockState;
            }
            else
            {
                lockState = BootloaderState.Unknown;
            }

            // 2. Strict TF image capture with the actual maintenance role, plus pinned toolbox preflight.
            var images = await TfPreparedCardImages.CaptureAsync(package, ct).ConfigureAwait(false);
            bool imagesOwned = true;
            try
            {
                if (!images.Contract.Raw.Artifacts.TryGetValue("kernel", out var kernelArtifact) || kernelArtifact is null)
                    throw new InvalidOperationException("Captured TF images are missing the kernel artifact.");
                var kernelSha256 = kernelArtifact.Sha256;
                PreflightToolbox(toolboxBundle);

                // Both real offline plans BEFORE any device/card change.
                var ramPlan = await CurrentBootMenuPlanner.PrepareTfAsync(original, slot, lockState, images, TfBootPurpose.RamMaintenance, tools, runner, evidenceDirectory, ct).ConfigureAwait(false);
                bool ramPlanOwned = true;
                try
                {
                    var finalPlan = await CurrentBootMenuPlanner.PrepareTfAsync(original, slot, lockState, images, TfBootPurpose.FinalTf, tools, runner, evidenceDirectory, ct).ConfigureAwait(false);
                    bool finalPlanOwned = true;
                    try
                    {
                        // 3. Real temporary backend.
                        var tempBackend = check is not null
                            ? await BootMaintenanceBackend.CreateTfPreparedAsync(check, client, currentBackup, ramPlan, runner, evidenceDirectory, null, ct).ConfigureAwait(false)
                            : await BootMaintenanceBackend.CreateTfPreparedFromEdlAsync(history!, client, currentBackup, ramPlan, runner, evidenceDirectory, null, ct).ConfigureAwait(false);
                        try
                        {
                            var prepared = tempBackend.Prepared;
                            ValidateTempPrepared(prepared, original, ramPlan, slot);

                            var journalPath = prepared.RollbackJournalPath;
                            var journalSha = HashFile(journalPath);
                            var nonce = Guid.NewGuid().ToString("N");
                            var bindSha = ComputeConfirmationBindSha256(
                                nonce,
                                prepared.ConfirmationId,
                                finalPlan.PackageManifestFingerprint,
                                finalPlan.TargetBackupManifestSha256,
                                original.ManifestSha256);

                            var socSerial = ParseSocSerial(prepared.SocSerial);

                            var controller = new TfTabletInstallWorkflow(
                                evidenceDirectory, statePath, original, images, ramPlan, finalPlan, tempBackend,
                                toolboxBundle, httpClient, runner, package,
                                nonce, bindSha, journalSha, kernelSha256, socSerial);
                            controller.Prepared = new TfTabletTemporaryPrepared(
                                bindSha,
                                prepared,
                                finalPlan,
                                ramPlan.TargetBackupDirectory,
                                evidenceDirectory,
                                statePath,
                                journalPath,
                                original.Model,
                                slot);
                            controller.PersistState();
                            originalOwned = false; imagesOwned = false; ramPlanOwned = false; finalPlanOwned = false;
                            return controller;
                        }
                        catch (Exception primary)
                        {
                            // Capture the primary failure; attempt only this layer's owned
                            // resource so outer ownership cleanup still runs.
                            try
                            {
                                tempBackend.Dispose();
                            }
                            catch (Exception cleanup)
                            {
                                throw new AggregateException(primary.Message, primary, cleanup);
                            }
                            throw;
                        }
                    }
                    catch (Exception primary)
                    {
                        if (finalPlanOwned)
                        {
                            try { finalPlan.Dispose(); }
                            catch (Exception cleanup)
                            {
                                throw new AggregateException(primary.Message, primary, cleanup);
                            }
                        }
                        throw;
                    }
                }
                catch (Exception primary)
                {
                    if (ramPlanOwned)
                    {
                        try { ramPlan.Dispose(); }
                        catch (Exception cleanup)
                        {
                            throw new AggregateException(primary.Message, primary, cleanup);
                        }
                    }
                    throw;
                }
            }
        catch (Exception primary)
        {
            if (imagesOwned)
            {
                try { images.Dispose(); }
                catch (Exception cleanup)
                {
                    throw new AggregateException(primary.Message, primary, cleanup);
                }
            }
            throw;
        }
    }
    catch (Exception primary)
    {
        if (originalOwned)
        {
            try { original.Dispose(); }
            catch (Exception cleanup)
            {
                throw new AggregateException(primary.Message, primary, cleanup);
            }
        }
        throw;
    }
}

    private static void ValidateTempPrepared(TfBootPrepared prepared, InternalBackupSet original, TfBootPlan ramPlan, string slot)
    {
        if (prepared.Operation != TfBootOperation.Temporary)
            throw new InvalidOperationException($"Temporary backend returned operation {prepared.Operation}.");
        if (prepared.RawPurpose != TfBootPurpose.RamMaintenance)
            throw new InvalidOperationException($"Temporary backend returned raw purpose {prepared.RawPurpose}.");
        if (!string.Equals(prepared.CurrentSlot, slot, StringComparison.Ordinal))
            throw new InvalidOperationException("Temporary backend slot does not match the derived slot.");
        if (!string.Equals(prepared.Model, original.Model, StringComparison.Ordinal))
            throw new InvalidOperationException("Temporary backend model does not match the original backup model.");
        if (!string.Equals(prepared.PackageManifestFingerprint, ramPlan.PackageManifestFingerprint, StringComparison.Ordinal))
            throw new InvalidOperationException("Temporary backend package fingerprint does not match the RAM plan.");
        if (!string.Equals(prepared.SourceBackupDirectory, original.DirectoryPath, StringComparison.Ordinal)
            || !string.Equals(prepared.SourceBackupManifestSha256, original.ManifestSha256, StringComparison.Ordinal))
            throw new InvalidOperationException("Temporary backend source backup pointers do not match the original snapshot.");
        if (!string.Equals(prepared.TargetBackupDirectory, ramPlan.TargetBackupDirectory, StringComparison.Ordinal)
            || !string.Equals(prepared.TargetBackupManifestSha256, ramPlan.TargetBackupManifestSha256, StringComparison.Ordinal))
            throw new InvalidOperationException("Temporary backend target backup pointers do not match the RAM plan.");
        if (string.IsNullOrWhiteSpace(prepared.RollbackJournalPath) || !File.Exists(prepared.RollbackJournalPath))
            throw new InvalidOperationException("Temporary backend did not durably produce a rollback journal.");
    }

    private static void PreflightToolbox(IMaintenanceBundle bundle)
    {
        var meta = bundle.GetAsset(MaintenanceProfiles.ToolboxRole)
            ?? throw new InvalidOperationException($"Maintenance bundle has no '{MaintenanceProfiles.ToolboxRole}' asset.");
        if (meta.Bytes != MaintenanceProfiles.ToolboxBytes)
            throw new InvalidOperationException($"Maintenance bundle toolbox asset reports {meta.Bytes} bytes, pinned {MaintenanceProfiles.ToolboxBytes}.");
        if (!string.Equals(meta.Sha256, MaintenanceProfiles.ToolboxSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Maintenance bundle toolbox asset SHA does not match the pinned value.");

        // Stream-hash the actual toolbox once, bounded memory, against the public pins.
        using var stream = bundle.OpenAsset(MaintenanceProfiles.ToolboxRole)
            ?? throw new InvalidOperationException($"Maintenance bundle could not open '{MaintenanceProfiles.ToolboxRole}'.");
        using var sha = SHA256.Create();
        var buffer = new byte[81920];
        long length = 0;
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            sha.TransformBlock(buffer, 0, read, null, 0);
            length += read;
        }

        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        var hash = Convert.ToHexString(sha.Hash!);
        if (length != MaintenanceProfiles.ToolboxBytes)
            throw new InvalidOperationException($"Toolbox asset length {length} does not match pinned {MaintenanceProfiles.ToolboxBytes}.");
        if (!string.Equals(hash, MaintenanceProfiles.ToolboxSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Toolbox asset SHA does not match the pinned value.");
    }

    private static ulong ParseSocSerial(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            throw new InvalidOperationException("Backend returned an empty SoC serial.");
        if (raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            var hex = raw.Substring(2);
            if (hex.Length == 0 || !ulong.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var parsedHex) || parsedHex == 0)
                throw new InvalidOperationException($"Backend SoC serial is not a strict positive hex value: '{raw}'.");
            return parsedHex;
        }

        if (!ulong.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) || parsed == 0)
            throw new InvalidOperationException($"Backend SoC serial is not a positive decimal value: '{raw}'.");
        return parsed;
    }

    private static string ComputeConfirmationBindSha256(string nonce, string tempConfirmation, string finalPackageFingerprint, string finalTargetManifestSha, string originalManifestSha)
    {
        using var sha = SHA256.Create();
        var material = string.Join("|", nonce, tempConfirmation, finalPackageFingerprint, finalTargetManifestSha, originalManifestSha);
        return Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(material)));
    }

    private static string HashFile(string path)
    {
        using var sha = SHA256.Create();
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(sha.ComputeHash(fs));
    }

    public async Task<TfBootResult> ExecuteTemporaryAsync(string confirmationId, IProgress<InternalInstallProgress>? progress = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(confirmationId);
        ThrowIfDisposed();
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
        }
        catch
        {
            _gate.Release();
            throw;
        }
        if (_busy)
        {
            _gate.Release();
            throw new InvalidOperationException("Another workflow operation is active.");
        }
        _busy = true;
        try
        {
            if (_tempAttempted)
                throw new InvalidOperationException("Temporary boot was already attempted; execution is one-shot.");
            if (Prepared is null)
                throw new InvalidOperationException("Workflow is not prepared.");
            if (!string.Equals(confirmationId, Prepared.ConfirmationId, StringComparison.Ordinal))
                throw new InvalidOperationException("Confirmation id does not match the prepared bind confirmation.");

            // Driver-file availability only; no live USB proof and no OS-version blanket ban.
            var ncmDriver = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "UsbNcm.sys");
            if (!File.Exists(ncmDriver))
                throw new InvalidOperationException("UsbNcm.sys is not present under the Windows drivers directory; serial reader alternative remains available.");

            await _images.RevalidateAsync(ct).ConfigureAwait(false);
            await _ramPlan.RevalidateAsync(ct).ConfigureAwait(false);
            await _finalPlan.RevalidateAsync(ct).ConfigureAwait(false);

            _stage = TfTabletInstallStage.WritingTemporaryBoot;
            _requiresBootRecovery = true;
            _error = null;
            PersistState();

            // One-shot actual temporary write via the backend. The attempt is recorded
            // before any device write so a thrown backend cannot look unattempted.
            _tempAttempted = true;
            TfBootResult result;
            try
            {
                result = await _tempBackend.ExecuteAsync(Prepared.TemporaryBoot.ConfirmationId, progress, ct).ConfigureAwait(false);
            }
            catch
            {
                // A thrown attempt remains one-shot: record actual snapshot uncertainty.
                var snapshot = _tempBackend.Snapshot;
                _error = snapshot.Error ?? "Temporary boot backend threw before returning a result.";
                RecordSnapshotOutcome(snapshot);
                try { PersistState(); }
                catch (Exception persistEx)
                {
                    _error = $"{_error} State persistence failed: {persistEx.Message}";
                }
                throw;
            }
            _tempResult = result;

            if (result.Outcome == BootMaintenanceOutcome.Completed
                && result.WriteState == InternalInstallWriteState.AllVerified
                && result.ResetAccepted == true)
            {
                _stage = TfTabletInstallStage.AwaitingRamConnection;
                _requiresBootRecovery = true;
            }
            else
            {
                // A real NoneIssued Failed/Cancelled may clear responsibility; never infer
                // zero writes from a missing result.
                if (result.WriteState == InternalInstallWriteState.NoneIssued
                    && (result.Outcome == BootMaintenanceOutcome.Failed || result.Outcome == BootMaintenanceOutcome.Cancelled))
                {
                    _requiresBootRecovery = false;
                }
                else
                {
                    _requiresBootRecovery = true;
                }

                _stage = result.Outcome switch
                {
                    BootMaintenanceOutcome.Failed => TfTabletInstallStage.Failed,
                    BootMaintenanceOutcome.Cancelled => TfTabletInstallStage.Cancelled,
                    BootMaintenanceOutcome.UnknownWriteOutcome => TfTabletInstallStage.UnknownWriteOutcome,
                    _ => TfTabletInstallStage.UnknownWriteOutcome
                };
                _error = result.Error;
            }

            try
            {
                PersistState();
            }
            catch (Exception persistEx)
            {
                // A real physical result is never erased or claimed unverified by a
                // persistence failure; the error stays visible next to the genuine result.
                _error = string.IsNullOrEmpty(_error)
                    ? $"State persistence failed: {persistEx.Message}"
                    : $"{_error}; state persistence failed: {persistEx.Message}";
            }
            return result;
        }
        finally
        {
            _busy = false;
            _gate.Release();
        }
    }

    private void RecordSnapshotOutcome(BootMaintenanceSnapshot snapshot)
    {
        if (snapshot.WriteState == InternalInstallWriteState.Unknown)
        {
            // An Unknown state/outcome must stage Unknown before any Failed/Cancelled mapping.
            _stage = TfTabletInstallStage.UnknownWriteOutcome;
        }
        else if (snapshot.Outcome is BootMaintenanceOutcome outcome)
        {
            _stage = outcome switch
            {
                BootMaintenanceOutcome.UnknownWriteOutcome => TfTabletInstallStage.UnknownWriteOutcome,
                BootMaintenanceOutcome.Failed => TfTabletInstallStage.Failed,
                BootMaintenanceOutcome.Cancelled => TfTabletInstallStage.Cancelled,
                _ => TfTabletInstallStage.UnknownWriteOutcome
            };
        }
        else
        {
            _stage = TfTabletInstallStage.UnknownWriteOutcome;
        }

        // A thrown temporary attempt has no TfBootResult: responsibility is preserved
        // even if the snapshot reports NoneIssued; only a genuine returned result's
        // NoneIssued Failed/Cancelled branch (elsewhere) may clear recovery.
        _requiresBootRecovery = true;
    }

    public async Task<IReadOnlyList<TfCardCandidate>> ConnectRamAsync(MaintenanceSerialPort selectedPort, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(selectedPort);
        ThrowIfDisposed();
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
        }
        catch
        {
            _gate.Release();
            throw;
        }
        if (_busy)
        {
            _gate.Release();
            throw new InvalidOperationException("Another workflow operation is active.");
        }
        _busy = true;
        try
        {
            if (_tempResult is null
                || _tempResult.Outcome != BootMaintenanceOutcome.Completed
                || _tempResult.WriteState != InternalInstallWriteState.AllVerified
                || _tempResult.ResetAccepted != true)
                throw new InvalidOperationException("RAM connection requires a verified temporary boot result with accepted reset.");
            if (_runtime is not null)
                throw new InvalidOperationException("RAM runtime is already connected.");

            // Requery actual Windows candidates and match both instance id and port name.
            var candidates = MaintenanceSerialDiscovery.ReadWindows();
            var match = candidates.FirstOrDefault(p =>
                string.Equals(p.DeviceInstanceId, selectedPort.DeviceInstanceId, StringComparison.OrdinalIgnoreCase)
                && string.Equals(p.PortName, selectedPort.PortName, StringComparison.OrdinalIgnoreCase))
                ?? throw new InvalidOperationException("Selected serial port is no longer present among actual USB serial candidates.");

            WindowsMaintenanceConsole? console = null;
            TcpMaintenanceTransfer? transfer = null;
            MaintenanceBootstrap? bootstrap = null;
            MaintenanceBootstrap.TfMaintenanceRuntime? runtime = null;
            Exception? primary = null;
            try
            {
                console = new WindowsMaintenanceConsole(match.PortName);
                await console.OpenAsync(ct).ConfigureAwait(false);
                transfer = new TcpMaintenanceTransfer(_httpClient);
                bootstrap = new MaintenanceBootstrap(console, transfer);
                runtime = await bootstrap.PrepareTfAsync(
                    _toolboxBundle,
                    Prepared.Model,
                    _socSerial,
                    _kernelSha256,
                    _httpClient,
                    ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                primary = ex;
                // Close only what this call acquired; borrowed client/bundle stay alive.
                var cleanupErrors = new List<Exception>();
                if (runtime is not null) { try { await runtime.DisposeAsync().ConfigureAwait(false); } catch (Exception ce) { cleanupErrors.Add(ce); } }
                if (transfer is not null) { try { transfer.Dispose(); } catch (Exception ce) { cleanupErrors.Add(ce); } }
                if (console is not null) { try { await console.DisposeAsync().ConfigureAwait(false); } catch (Exception ce) { cleanupErrors.Add(ce); } }
                _stage = TfTabletInstallStage.AwaitingRamConnection;
                _requiresBootRecovery = true;
                _error = $"RAM connection failed: {primary.Message} The device is expected to be in RAM maintenance mode.";
                try { PersistState(); }
                catch (Exception persistEx)
                {
                    _error = $"{_error} State persistence failed: {persistEx.Message}";
                }
                if (cleanupErrors.Count > 0)
                    throw new AggregateException(primary.Message, new[] { primary }.Concat(cleanupErrors));
                throw primary;
            }

            _runtime = runtime;
            _console = console;
            _transfer = transfer;
            _bootstrap = bootstrap;
            _stage = TfTabletInstallStage.RamConnected;
            _requiresBootRecovery = true;
            _error = null;
            PersistState();

            return await runtime.Session.DiscoverCardsAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _busy = false;
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<TfCardCandidate>> DiscoverCardsAsync(CancellationToken ct = default)
    {
        ThrowIfDisposed();
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (_busy)
                throw new InvalidOperationException("Another workflow operation is active.");
            var runtime = _runtime ?? throw new InvalidOperationException("RAM runtime is not connected.");
            _busy = true;
            try
            {
                return await runtime.Session.DiscoverCardsAsync(ct).ConfigureAwait(false);
            }
            finally
            {
                _busy = false;
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SuspendForEdlReturnAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        if (_busy)
        {
            _gate.Release();
            throw new InvalidOperationException("Another workflow operation is active.");
        }
        _busy = true;
        try
        {
            ThrowIfDisposed();
            // Explicit public manual-9008 pause. Requires either a connected RAM
            // runtime or actual pending temporary-boot recovery evidence; a never-
            // attempted prepared state must not create recovery state.
            var hasPendingTempRecovery = _tempAttempted && _requiresBootRecovery;
            if (_runtime is null && !hasPendingTempRecovery)
                throw new InvalidOperationException("RAM runtime is not connected and no temporary boot attempt is pending; nothing to suspend.");

            // Actual cleanup/pause only: no reboot, no EDL, no sysrq, no busybox reboot command.
            var runtime = _runtime;
            var transfer = _transfer;
            var console = _console;
            _runtime = null;
            _bootstrap = null;
            _transfer = null;
            _console = null;

            var errors = new List<Exception>();

            // Close our own held card target before the runtime pause; a failure here
            // is collected, it must not wipe any earlier state-save failure.
            try { await DisposePreparedCardTargetAsync().ConfigureAwait(false); }
            catch (Exception ex) { errors.Add(ex); }

            if (runtime is not null)
            {
                try { await runtime.DisposeAsync().ConfigureAwait(false); }
                catch (Exception ex) { errors.Add(ex); }
            }
            if (transfer is not null)
            {
                try { transfer.Dispose(); }
                catch (Exception ex) { errors.Add(ex); }
            }
            if (console is not null)
            {
                try { await console.DisposeAsync().ConfigureAwait(false); }
                catch (Exception ex) { errors.Add(ex); }
            }

            _stage = TfTabletInstallStage.AwaitingEdlReturn;
            _requiresBootRecovery = true;
            string? previousError = _error;
            _error = errors.Count > 0
                ? (string.IsNullOrEmpty(previousError)
                    ? string.Join("; ", errors.Select(e => e.Message))
                    : previousError + "; " + string.Join("; ", errors.Select(e => e.Message)))
                : previousError;
            PersistState();

            if (errors.Count > 0)
                throw new AggregateException("Errors while suspending RAM maintenance session.", errors);
        }
        finally
        {
            _busy = false;
            _gate.Release();
        }
    }

    // One small atomic state file: recovery locator and evidence only, never authority.
    private void PersistState()
    {
        var dto = new TfTabletStateFile
            {
                Phase = _stage.ToString(),
                Model = Prepared?.Model ?? string.Empty,
                CurrentSlot = Prepared?.CurrentSlot ?? string.Empty,
                Nonce = _nonce,
                OriginalBackupDirectory = _originalBackup.DirectoryPath,
                OriginalBackupManifestSha256 = _originalBackup.ManifestSha256,
                PackageManifestFingerprint = _images.Contract.ManifestFingerprint,
                PackageSourcePath = _sourcePackage.SourcePath,
                TempConfirmationId = Prepared?.TemporaryBoot.ConfirmationId ?? string.Empty,
                ConfirmationBindSha256 = _confirmationBindSha256,
                FinalPlanTargetBackupDirectory = _finalPlan.TargetBackupDirectory,
                FinalPlanTargetBackupManifestSha256 = _finalPlan.TargetBackupManifestSha256,
                TempBackendRollbackJournalPath = _tempBackend.Prepared.RollbackJournalPath ?? string.Empty,
                RollbackJournalSha256 = _rollbackJournalSha256,
                CurrentRecoveryJournalPath = CurrentRecoveryJournalPath ?? string.Empty,
                FinalPlanVerificationReportPath = _finalPlan.MenuPlan.VerificationReport.Path,
                FinalPlanVerificationReportSha256 = _finalPlan.MenuPlan.VerificationReport.Sha256,
                CardConfirmationId = _preparedCard?.ConfirmationId ?? string.Empty,
                CardTarget = _preparedCard?.Card ?? _cardEvidence?.Target,
                CardLayout = _preparedCard?.Layout ?? _cardEvidence?.Layout,
                CardWriteAttempted = _cardWriteAttempted,
                CardFullyVerified = _cardEvidence?.FullyVerified ?? false,
                CardBootImageSha256 = _cardEvidence?.BootImageSha256 ?? string.Empty,
                CardRootImageSha256 = _cardEvidence?.RootImageSha256 ?? string.Empty,
                ReturnOperation = _returnBackend?.Prepared.Operation.ToString() ?? string.Empty,
                ReturnConfirmationId = _returnBackend?.Prepared.ConfirmationId ?? string.Empty,
                ReturnTargetBackupDirectory = _returnBackend?.Prepared.TargetBackupDirectory ?? string.Empty,
                ReturnTargetBackupManifestSha256 = _returnBackend?.Prepared.TargetBackupManifestSha256 ?? string.Empty,
                ReturnRollbackJournalPath = _returnBackend?.Prepared.RollbackJournalPath ?? string.Empty,
                FinalOutcome = _finalResult?.Outcome.ToString() ?? string.Empty,
                FinalWriteState = _finalResult?.WriteState.ToString() ?? string.Empty,
                FinalResetAccepted = _finalResult?.ResetAccepted ?? false,
                RestoreOutcome = _restoreResult?.Outcome.ToString() ?? string.Empty,
                RestoreWriteState = _restoreResult?.WriteState.ToString() ?? string.Empty,
                RestoreResetAccepted = _restoreResult?.ResetAccepted ?? false,
                TempOutcome = _tempResult?.Outcome.ToString() ?? string.Empty,
                TempWriteState = _tempResult?.WriteState.ToString() ?? string.Empty,
                TempResetAccepted = _tempResult?.ResetAccepted ?? false,
                TempError = _tempResult?.Error ?? string.Empty,
                RequiresBootRecovery = _requiresBootRecovery,
                TempAttempted = _tempAttempted,
                Error = _error ?? string.Empty
            };

            var json = JsonSerializer.Serialize(dto, TfTabletJson.Options);
            var tempPath = $"{_statePath}.tmp-{Guid.NewGuid():N}";
            using (var fs = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var writer = new StreamWriter(fs, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)))
            {
                writer.Write(json);
                writer.Flush();
                fs.Flush(true);
            }

            if (File.Exists(_statePath))
                File.Replace(tempPath, _statePath, null);
            else
                File.Move(tempPath, _statePath);
    }

    private sealed class TfTabletStateFile
    {
        public string Phase { get; set; } = string.Empty;
        public string Model { get; set; } = string.Empty;
        public string CurrentSlot { get; set; } = string.Empty;
        public string Nonce { get; set; } = string.Empty;
        public string OriginalBackupDirectory { get; set; } = string.Empty;
        public string OriginalBackupManifestSha256 { get; set; } = string.Empty;
        public string PackageManifestFingerprint { get; set; } = string.Empty;
        public string PackageSourcePath { get; set; } = string.Empty;
        public string TempConfirmationId { get; set; } = string.Empty;
        public string ConfirmationBindSha256 { get; set; } = string.Empty;
        public string FinalPlanTargetBackupDirectory { get; set; } = string.Empty;
        public string FinalPlanTargetBackupManifestSha256 { get; set; } = string.Empty;
        public string TempBackendRollbackJournalPath { get; set; } = string.Empty;
        public string RollbackJournalSha256 { get; set; } = string.Empty;
        public string CurrentRecoveryJournalPath { get; set; } = string.Empty;
        public string FinalPlanVerificationReportPath { get; set; } = string.Empty;
        public string FinalPlanVerificationReportSha256 { get; set; } = string.Empty;
        public string CardConfirmationId { get; set; } = string.Empty;
        public TfCardTargetIdentity? CardTarget { get; set; }
        public TfCardLayoutPlan? CardLayout { get; set; }
        public bool CardWriteAttempted { get; set; }
        public bool CardFullyVerified { get; set; }
        public string CardBootImageSha256 { get; set; } = string.Empty;
        public string CardRootImageSha256 { get; set; } = string.Empty;
        public string ReturnOperation { get; set; } = string.Empty;
        public string ReturnConfirmationId { get; set; } = string.Empty;
        public string ReturnTargetBackupDirectory { get; set; } = string.Empty;
        public string ReturnTargetBackupManifestSha256 { get; set; } = string.Empty;
        public string ReturnRollbackJournalPath { get; set; } = string.Empty;
        public string FinalOutcome { get; set; } = string.Empty;
        public string FinalWriteState { get; set; } = string.Empty;
        public bool FinalResetAccepted { get; set; }
        public string RestoreOutcome { get; set; } = string.Empty;
        public string RestoreWriteState { get; set; } = string.Empty;
        public bool RestoreResetAccepted { get; set; }
        public string TempOutcome { get; set; } = string.Empty;
        public string TempWriteState { get; set; } = string.Empty;
        public bool TempResetAccepted { get; set; }
        public string TempError { get; set; } = string.Empty;
        public bool RequiresBootRecovery { get; set; }
        public bool TempAttempted { get; set; }
        public string Error { get; set; } = string.Empty;
    }

    private static class TfTabletJson
    {
        public static readonly JsonSerializerOptions Options = new() { WriteIndented = true };
    }

    public async ValueTask DisposeAsync()
    {
        if (Volatile.Read(ref _disposed) != 0)
            return;
        if (!_gate.Wait(0))
            throw new InvalidOperationException("Cannot dispose while a workflow operation is active.");
        try
        {
            ThrowIfDisposed();
            Volatile.Write(ref _disposed, 1);

            // Keep pending responsibility durable first; collect its error and still
            // attempt every owned cleanup below.
            var errors = new List<Exception>();
            try { PersistState(); }
            catch (Exception ex) { errors.Add(ex); }

            // Actual partial hooks, before runtime/tempBackend/plans closes.
            try { await DisposePreparedCardTargetAsync().ConfigureAwait(false); }
            catch (Exception ex) { errors.Add(ex); }
            try { DisposeReturnBackend(); }
            catch (Exception ex) { errors.Add(ex); }

            if (_runtime is not null)
            {
                try { await _runtime.DisposeAsync().ConfigureAwait(false); }
                catch (Exception ex) { errors.Add(ex); }
                _runtime = null;
            }
            // MaintenanceBootstrap is a plain non-disposable class; only the reference is dropped.
            _bootstrap = null;
            if (_transfer is not null)
            {
                try { _transfer.Dispose(); }
                catch (Exception ex) { errors.Add(ex); }
                _transfer = null;
            }
            if (_console is not null)
            {
                try { await _console.DisposeAsync().ConfigureAwait(false); }
                catch (Exception ex) { errors.Add(ex); }
                _console = null;
            }

            try { _tempBackend.Dispose(); }
            catch (Exception ex) { errors.Add(ex); }
            try { _ramPlan.Dispose(); }
            catch (Exception ex) { errors.Add(ex); }
            try { _finalPlan.Dispose(); }
            catch (Exception ex) { errors.Add(ex); }
            try { _images.Dispose(); }
            catch (Exception ex) { errors.Add(ex); }
            try { _originalBackup.Dispose(); }
            catch (Exception ex) { errors.Add(ex); }

            // Borrowed toolbox bundle/http client/client/package/tools/runner/backup are not touched here.
            // Original backups, staged backend evidence and the rollback journal remain on disk.

            if (errors.Count > 0)
                throw new AggregateException("Errors while disposing TF tablet workflow resources.", errors);
        }
        finally
        {
            // Never dispose the gate itself: pending WaitAsync waiters must wake and
            // then fail with ObjectDisposedException from the guards.
            _gate.Release();
        }
    }
}
