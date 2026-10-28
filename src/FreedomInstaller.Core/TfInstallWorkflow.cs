using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

public sealed record TfInstallRequest(
    TfCardCandidate Card,
    IReadOnlyList<string> ProtectedPaths,
    string EvidenceParent);

public enum TfInstallStage
{
    Prepared,
    ProcessingCard,
    WritingTabletBoot,
    Completed,
    Failed,
    Cancelled,
    UnknownWriteOutcome,
}

public enum TfInstallOutcome
{
    Completed,
    Failed,
    Cancelled,
    UnknownWriteOutcome,
}

public sealed class TfInstallPrepared
{
    internal TfInstallPrepared(string confirmationId, TfCardTargetIdentity card, TfCardLayoutPlan layout, TfSpacePlan space,
        string packageManifestFingerprint, string backupDirectory, string evidenceDirectory, TfBootPrepared boot)
    {
        ConfirmationId = confirmationId;
        Card = card;
        Layout = layout;
        Space = space;
        PackageManifestFingerprint = packageManifestFingerprint;
        BackupDirectory = backupDirectory;
        EvidenceDirectory = evidenceDirectory;
        Boot = boot;
    }

    public string ConfirmationId { get; }
    public TfCardTargetIdentity Card { get; }
    public TfCardLayoutPlan Layout { get; }
    public TfSpacePlan Space { get; }
    public string PackageManifestFingerprint { get; }
    public string BackupDirectory { get; }
    public string EvidenceDirectory { get; }
    public TfBootPrepared Boot { get; }
}

public sealed record TfInstallProgress(
    TfInstallStage Stage,
    TfCardWriteProgress? Card,
    InternalInstallProgress? Boot,
    string? Detail);

public sealed class TfInstallSnapshot
{
    internal TfInstallSnapshot(TfInstallStage stage, bool executionStarted, TfCardWriteEvidence? cardEvidence, TfBootResult? bootResult, string? error)
    {
        Stage = stage;
        ExecutionStarted = executionStarted;
        CardEvidence = cardEvidence;
        BootResult = bootResult;
        Error = error;
    }

    public TfInstallStage Stage { get; }
    public bool ExecutionStarted { get; }
    public TfCardWriteEvidence? CardEvidence { get; }
    public TfBootResult? BootResult { get; }
    public string? Error { get; }
}

public sealed class TfInstallResult
{
    internal TfInstallResult(TfInstallOutcome outcome, TfCardWriteEvidence? cardEvidence, TfBootResult? bootResult, string evidenceDirectory, string? error)
    {
        Outcome = outcome;
        CardEvidence = cardEvidence;
        BootResult = bootResult;
        EvidenceDirectory = evidenceDirectory;
        Error = error;
    }

    public TfInstallOutcome Outcome { get; }
    public TfCardWriteEvidence? CardEvidence { get; }
    public TfBootResult? BootResult { get; }
    public string EvidenceDirectory { get; }
    public string? Error { get; }
}

public sealed class TfInstallWorkflow : IAsyncDisposable
{
    private const string ReaderKeyPrefix = "reader:";

    private readonly TfCardCandidate _card;
    private readonly TfPreparedCardImages _images;
    private readonly ITfCardWriteTarget _target;
    private readonly TfBootPlan _plan;
    private readonly TfBootBackend _backend;
    private volatile TfInstallSnapshot _snapshot;
    private int _runState; // 0 idle, 1 executing, 2 finished
    private int _disposed;

    private TfInstallWorkflow(TfInstallPrepared prepared, TfCardCandidate card, TfPreparedCardImages images,
        ITfCardWriteTarget target, TfBootPlan plan, TfBootBackend backend)
    {
        Prepared = prepared;
        _card = card;
        _images = images;
        _target = target;
        _plan = plan;
        _backend = backend;
        _snapshot = new TfInstallSnapshot(TfInstallStage.Prepared, false, null, null, null);
    }

    public TfInstallPrepared Prepared { get; }
    public TfInstallSnapshot Snapshot => Volatile.Read(ref _snapshot);

    public static Task<TfInstallWorkflow> PrepareReaderAsync(
        TfInstallRequest request, InternalDeviceCheckResult check, EdlClient client, InternalBackupSet currentBackup,
        ImportedPackage package, EdlRawBootTools tools, ICommandRunner runner, CancellationToken ct = default)
        => PrepareCoreAsync(request, check, null, client, currentBackup, package, tools, runner, ct);

    public static Task<TfInstallWorkflow> PrepareReaderFromEdlAsync(
        TfInstallRequest request, BootMaintenanceHistoricalIdentity history, EdlClient client, InternalBackupSet currentBackup,
        ImportedPackage package, EdlRawBootTools tools, ICommandRunner runner, CancellationToken ct = default)
        => PrepareCoreAsync(request, null, history, client, currentBackup, package, tools, runner, ct);

    private static async Task<TfInstallWorkflow> PrepareCoreAsync(
        TfInstallRequest request, InternalDeviceCheckResult? check, BootMaintenanceHistoricalIdentity? history,
        EdlClient client, InternalBackupSet currentBackup, ImportedPackage package, EdlRawBootTools tools,
        ICommandRunner runner, CancellationToken ct)
    {
        if (request is null || request.Card is null || string.IsNullOrWhiteSpace(request.Card.Key))
            throw new ArgumentException("Card candidate with key is required.", nameof(request));
        if (!request.Card.Key.StartsWith(ReaderKeyPrefix, StringComparison.Ordinal))
            throw new ArgumentException($"Reader controller requires a '{ReaderKeyPrefix}' prefixed card key.", nameof(request));
        if (request.ProtectedPaths is null)
            throw new ArgumentException("Protected paths are required.", nameof(request));
        if (string.IsNullOrWhiteSpace(request.EvidenceParent) || !Directory.Exists(request.EvidenceParent))
            throw new DirectoryNotFoundException($"Evidence parent must exist: '{request.EvidenceParent}'.");
        if (check is null && history is null)
            throw new ArgumentException("Either an actual device check or a historical EDL identity is required.");
        if (currentBackup is null || package is null || tools is null || runner is null || client is null)
            throw new ArgumentException("Backup, package, client, tools and runner are required (borrowed).");

        bool android = check is not null;
        string nonce = Guid.NewGuid().ToString("N");
        string evidenceChild = Path.Combine(request.EvidenceParent, "tf-reader-" + DateTime.UtcNow.ToString("yyyyMMddTHHmmssfff") + "-" + nonce[..8]);
        Directory.CreateDirectory(evidenceChild);

        string currentSlot = await ReadCurrentSlotAsync(currentBackup, ct).ConfigureAwait(false);
        BootloaderState lockState;
        if (android)
        {
            if (!string.Equals(check!.CurrentSlot, currentSlot, StringComparison.Ordinal))
                throw new InvalidOperationException($"Fresh backup slot '{currentSlot}' does not match Fastboot check slot '{check.CurrentSlot}'.");
            lockState = check.FastbootLockState;
        }
        else
        {
            lockState = BootloaderState.Unknown;
        }

        TfPreparedCardImages images = await TfPreparedCardImages.CaptureAsync(package, ct).ConfigureAwait(false);
        ITfCardWriteTarget? target = null;
        TfBootPlan? plan = null;
        TfBootBackend? backend = null;
        try
        {
            TfSpacePlan space = TfCardSupport.Plan(request.Card, images.Contract.Storage);

            IReadOnlyList<string> protectedPaths = BuildProtectedPaths(request, package, currentBackup, evidenceChild, tools);
            WindowsTfCardWriteTarget opened = await WindowsTfCardWriteTarget.OpenAsync(request.Card, protectedPaths, runner, ct).ConfigureAwait(false);
            target = opened;
            ValidateTargetIdentity(opened.Identity, request.Card);

            TfCardLayoutPlan layout = TfCardLayout.Create(
                opened.Identity.SizeBytes,
                opened.Identity.LogicalSectorSize,
                images.Contract.BootImage.ExpandedBytes,
                images.Contract.RootImage.ExpandedBytes,
                Math.Max(images.Contract.RootImage.ExpandedBytes, space.LinuxRootBytes),
                Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid());

            plan = await CurrentBootMenuPlanner.PrepareTfAsync(
                currentBackup, currentSlot, lockState, images, TfBootPurpose.FinalTf, tools, runner, evidenceChild, ct).ConfigureAwait(false);

            backend = android
                ? await BootMaintenanceBackend.CreateTfPreparedAsync(check!, client, currentBackup, plan, runner, evidenceChild, null, ct).ConfigureAwait(false)
                : await BootMaintenanceBackend.CreateTfPreparedFromEdlAsync(history!, client, currentBackup, plan, runner, evidenceChild, null, ct).ConfigureAwait(false);

            ValidateBootPrepared(backend.Prepared, plan, images, currentBackup, currentSlot);

            string confirmationId = BuildConfirmationId(nonce, opened.Identity, layout, images.Contract.ManifestFingerprint, currentBackup.ManifestSha256, backend.Prepared);
            var prepared = new TfInstallPrepared(confirmationId, opened.Identity, layout, space,
                images.Contract.ManifestFingerprint, currentBackup.DirectoryPath, evidenceChild, backend.Prepared);
            return new TfInstallWorkflow(prepared, request.Card, images, opened, plan, backend);
        }
        catch (Exception primaryEx)
        {
            var cleanupErrors = new List<Exception>();
            if (backend is not null) { try { backend.Dispose(); } catch (Exception ex) { cleanupErrors.Add(ex); } }
            if (plan is not null) { try { plan.Dispose(); } catch (Exception ex) { cleanupErrors.Add(ex); } }
            if (target is not null) { try { await target.DisposeAsync().ConfigureAwait(false); } catch (Exception ex) { cleanupErrors.Add(ex); } }
            try { images.Dispose(); } catch (Exception ex) { cleanupErrors.Add(ex); }
            if (cleanupErrors.Count > 0)
            {
                cleanupErrors.Insert(0, primaryEx);
                throw new AggregateException("One or more errors while cleaning up after prepare failure.", cleanupErrors);
            }
            throw;
        }
    }

    public async Task<TfInstallResult> ExecuteAsync(string confirmationId, IProgress<TfInstallProgress>? progress = null, CancellationToken ct = default)
    {
        lock (_lifecycleLock)
        {
            if (Volatile.Read(ref _disposed) != 0)
                throw new ObjectDisposedException(nameof(TfInstallWorkflow));
            if (!string.Equals(confirmationId, Prepared.ConfirmationId, StringComparison.Ordinal))
                throw new InvalidOperationException("Confirmation ID does not match this prepared workflow.");
            if (Interlocked.CompareExchange(ref _runState, 1, 0) != 0)
                throw new InvalidOperationException("This workflow is executing or has already executed.");
        }

        TfCardWriteEvidence? cardEvidence = null;
        TfBootResult? bootResult = null;
        var stage = TfInstallStage.ProcessingCard;
        var outcome = TfInstallOutcome.Failed;
        string? error = null;
        var cardForwarder = new CardProgressForwarder(value => progress?.Report(new TfInstallProgress(TfInstallStage.ProcessingCard, value, null, value.Detail)));
        var writeObserver = new WriteIntentObserver(_target, this);
        try
        {
            RefreshSnapshot(TfInstallStage.ProcessingCard, null, null, null);
            progress?.Report(new TfInstallProgress(TfInstallStage.ProcessingCard, null, null, "Revalidating captured images, card target and layout plan."));
            await _images.RevalidateAsync(ct).ConfigureAwait(false);
            await _plan.RevalidateAsync(ct).ConfigureAwait(false);
            ValidateTargetIdentity(await _target.RevalidateAsync(ct).ConfigureAwait(false), _card);

            progress?.Report(new TfInstallProgress(TfInstallStage.ProcessingCard, null, null, "Writing and verifying card images."));
            cardEvidence = await TfCardRawWriter.WriteAndVerifyAsync(_images, writeObserver, Prepared.Layout, cardForwarder, ct).ConfigureAwait(false);
            RefreshSnapshot(TfInstallStage.ProcessingCard, cardEvidence, null, null);
            if (!cardEvidence.FullyVerified)
                throw new InvalidOperationException("Card write evidence is not fully verified.");
            ValidateEvidence(cardEvidence);
            if (!string.Equals(cardEvidence.ManifestFingerprint, Prepared.PackageManifestFingerprint, StringComparison.Ordinal))
                throw new InvalidOperationException("Card write evidence manifest fingerprint does not match the prepared fingerprint.");

            stage = TfInstallStage.WritingTabletBoot;
            RefreshSnapshot(stage, cardEvidence, null, null);
            progress?.Report(new TfInstallProgress(stage, cardForwarder.Last, null, "Writing and verifying tablet boot payloads."));
            bootResult = await _backend.ExecuteAsync(Prepared.Boot.ConfirmationId,
                new BootProgressForwarder(() => cardForwarder.Last, progress), ct).ConfigureAwait(false);

            bool cardVerified = cardEvidence.FullyVerified;
            bool bootCompleted = bootResult.Outcome == BootMaintenanceOutcome.Completed
                && bootResult.WriteState == InternalInstallWriteState.AllVerified
                && bootResult.ResetAccepted == true;
            if (bootResult.WriteState == InternalInstallWriteState.Unknown || bootResult.Outcome == BootMaintenanceOutcome.UnknownWriteOutcome)
            {
                outcome = TfInstallOutcome.UnknownWriteOutcome;
                stage = TfInstallStage.UnknownWriteOutcome;
                error = bootResult.Error;
            }
            else if (bootResult.Outcome == BootMaintenanceOutcome.Completed && !(cardVerified && bootCompleted))
            {
                outcome = TfInstallOutcome.UnknownWriteOutcome;
                stage = TfInstallStage.UnknownWriteOutcome;
                error = string.IsNullOrEmpty(bootResult.Error)
                    ? "Boot reported completion but write evidence is incomplete; outcome is unknown."
                    : bootResult.Error + " (Boot reported completion but write evidence is incomplete; outcome is unknown.)";
            }
            else
            {
                outcome = bootCompleted ? TfInstallOutcome.Completed : MapOutcome(bootResult.Outcome);
                stage = bootCompleted ? TfInstallStage.Completed : MapStage(bootResult.Outcome);
                error = bootResult.Error;
            }
            RefreshSnapshot(stage, cardEvidence, bootResult, error);
        }
        catch (OperationCanceledException ex)
        {
            ClassifyFailure(ex.Message, cardEvidence, bootResult, cancelled: true, ref stage, ref outcome, ref error);
            SetSnapshot(stage, cardEvidence, bootResult, error);
        }
        catch (Exception ex)
        {
            ClassifyFailure(ex.Message, cardEvidence, bootResult, cancelled: false, ref stage, ref outcome, ref error);
            SetSnapshot(stage, cardEvidence, bootResult, error);
        }
        try
        {
            await WriteResultFileAsync(outcome, stage, cardEvidence, bootResult, error, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception saveEx)
        {
            string saveError = "Failed to save tf-install-result.json: " + saveEx.Message;
            error = string.IsNullOrEmpty(error) ? saveError : error + " | " + saveError;
            SetSnapshot(stage, cardEvidence, bootResult, error);
        }
        finally
        {
            Volatile.Write(ref _runState, 2);
        }

        return new TfInstallResult(outcome, cardEvidence, bootResult, Prepared.EvidenceDirectory, error);
    }

    private void ClassifyFailure(string message, TfCardWriteEvidence? cardEvidence, TfBootResult? bootResult, bool cancelled,
        ref TfInstallStage stage, ref TfInstallOutcome outcome, ref string? error)
    {
        InternalInstallWriteState writeState = bootResult?.WriteState ?? _backend.Snapshot.WriteState;
        BootMaintenanceOutcome? backendOutcome = bootResult?.Outcome ?? _backend.Snapshot.Outcome;
        string? backendError = bootResult?.Error ?? _backend.Snapshot.Error;
        error = string.IsNullOrEmpty(backendError) ? message : message + " | " + backendError;

        if (writeState == InternalInstallWriteState.Unknown || backendOutcome == BootMaintenanceOutcome.UnknownWriteOutcome)
        {
            stage = TfInstallStage.UnknownWriteOutcome;
            outcome = TfInstallOutcome.UnknownWriteOutcome;
            return;
        }
        bool firstWriteAttempted = Volatile.Read(ref _writeAttempted) != 0;
        if (firstWriteAttempted && (cardEvidence is null || !cardEvidence.FullyVerified))
        {
            stage = TfInstallStage.UnknownWriteOutcome;
            outcome = TfInstallOutcome.UnknownWriteOutcome;
            return;
        }
        if (cancelled)
        {
            stage = TfInstallStage.Cancelled;
            outcome = TfInstallOutcome.Cancelled;
            return;
        }
        stage = TfInstallStage.Failed;
        outcome = TfInstallOutcome.Failed;
    }

    public async ValueTask DisposeAsync()
    {
        lock (_lifecycleLock)
        {
            if (Volatile.Read(ref _disposed) != 0)
                return;
            if (Volatile.Read(ref _runState) == 1)
                throw new InvalidOperationException("Cannot dispose while execution is active.");
            Volatile.Write(ref _disposed, 1);
        }
        var errors = new List<Exception>();
        try { _backend.Dispose(); } catch (Exception ex) { errors.Add(ex); }
        try { _plan.Dispose(); } catch (Exception ex) { errors.Add(ex); }
        try { await _target.DisposeAsync().ConfigureAwait(false); } catch (Exception ex) { errors.Add(ex); }
        try { _images.Dispose(); } catch (Exception ex) { errors.Add(ex); }
        if (errors.Count > 0)
            throw new AggregateException("One or more errors while disposing TfInstallWorkflow-owned resources.", errors);
    }

    private int _writeAttempted;
    private readonly object _lifecycleLock = new object();

    private void RefreshSnapshot(TfInstallStage stage, TfCardWriteEvidence? cardEvidence, TfBootResult? bootResult, string? error)
        => SetSnapshot(stage, cardEvidence, bootResult, error);

    private void SetSnapshot(TfInstallStage stage, TfCardWriteEvidence? cardEvidence, TfBootResult? bootResult, string? error)
        => Volatile.Write(ref _snapshot, new TfInstallSnapshot(stage, Volatile.Read(ref _writeAttempted) != 0, cardEvidence, bootResult, error));

    private void ValidateEvidence(TfCardWriteEvidence evidence)
    {
        TfCardTargetIdentity t = evidence.Target;
        TfCardTargetIdentity f = Prepared.Card;
        bool identity = t.Source == f.Source
            && string.Equals(t.Key, f.Key, StringComparison.Ordinal)
            && string.Equals(t.DevicePath, f.DevicePath, StringComparison.Ordinal)
            && t.SizeBytes == f.SizeBytes
            && t.LogicalSectorSize == f.LogicalSectorSize
            && string.Equals(t.BindingSha256, f.BindingSha256, StringComparison.Ordinal);
        TfCardLayoutPlan l = evidence.Layout;
        TfCardLayoutPlan p = Prepared.Layout;
        bool layout = l.CardBytes == p.CardBytes
            && l.LogicalSectorSize == p.LogicalSectorSize
            && l.TotalSectors == p.TotalSectors
            && l.BootStartSector == p.BootStartSector
            && l.BootSectorCount == p.BootSectorCount
            && l.RootStartSector == p.RootStartSector
            && l.RootSectorCount == p.RootSectorCount
            && l.DiskGuid == p.DiskGuid
            && l.BootGuid == p.BootGuid
            && l.RootGuid == p.RootGuid;
        if (!identity || !layout)
            throw new InvalidOperationException("Card write evidence does not match the frozen target identity and layout.");
    }

    private async Task WriteResultFileAsync(TfInstallOutcome outcome, TfInstallStage stage, TfCardWriteEvidence? cardEvidence, TfBootResult? bootResult, string? error, CancellationToken ct)
    {
        TfCardTargetIdentity t = Prepared.Card;
        TfCardLayoutPlan l = Prepared.Layout;
        var result = new
        {
            confirmationId = Prepared.ConfirmationId,
            outcome = outcome.ToString(),
            stage = stage.ToString(),
            error,
            target = new
            {
                source = t.Source.ToString(), t.Key, t.DevicePath, t.SizeBytes, t.LogicalSectorSize, t.BindingSha256,
            },
            layout = new
            {
                l.CardBytes, l.LogicalSectorSize, l.TotalSectors, l.BootStartSector, l.BootSectorCount,
                l.RootStartSector, l.RootSectorCount, l.DiskGuid, l.BootGuid, l.RootGuid,
            },
            packageManifestFingerprint = Prepared.PackageManifestFingerprint,
            backupDirectory = Prepared.BackupDirectory,
            evidenceDirectory = Prepared.EvidenceDirectory,
            card = cardEvidence is null ? null : new
            {
                cardEvidence.FullyVerified,
                cardEvidence.ManifestFingerprint,
                cardEvidence.BootImageSha256,
                cardEvidence.RootImageSha256,
            },
            boot = bootResult is null ? null : new
            {
                operation = bootResult.Operation.ToString(),
                outcome = bootResult.Outcome.ToString(),
                writeState = bootResult.WriteState.ToString(),
                bootResult.VerifiedRegions,
                bootResult.EvidenceDirectory,
                bootResult.ResetAccepted,
                bootResult.Error,
            },
        };
        string json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
        byte[] bytes = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(json);
        string path = Path.Combine(Prepared.EvidenceDirectory, "tf-install-result.json");
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        await using (var stream = new FileStream(path, options))
        {
            await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
            await stream.FlushAsync(ct).ConfigureAwait(false);
            stream.Flush(flushToDisk: true);
        }
    }

    private async Task WriteIntentMarkerAsync(CancellationToken ct)
    {
        TfCardTargetIdentity t = Prepared.Card;
        TfCardLayoutPlan l = Prepared.Layout;
        var intent = new
        {
            intent = "tf-card-write",
            confirmationId = Prepared.ConfirmationId,
            target = new
            {
                source = t.Source.ToString(), t.Key, t.DevicePath, t.SizeBytes, t.LogicalSectorSize, t.BindingSha256,
            },
            layout = new
            {
                l.CardBytes, l.LogicalSectorSize, l.TotalSectors, l.BootStartSector, l.BootSectorCount,
                l.RootStartSector, l.RootSectorCount,
                diskGuid = l.DiskGuid.ToString(), bootGuid = l.BootGuid.ToString(), rootGuid = l.RootGuid.ToString(),
            },
            packageManifestFingerprint = Prepared.PackageManifestFingerprint,
            bootConfirmationId = Prepared.Boot.ConfirmationId,
        };
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(intent);
        string path = Path.Combine(Prepared.EvidenceDirectory, "tf-card-write-intent.json");
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        await using (var stream = new FileStream(path, options))
        {
            await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
            await stream.FlushAsync(ct).ConfigureAwait(false);
            stream.Flush(flushToDisk: true);
        }
    }

    private sealed class WriteIntentObserver : ITfCardWriteTarget
    {
        private readonly ITfCardWriteTarget _inner;
        private readonly TfInstallWorkflow _owner;
        private int _firstWritePending = 1;

        public WriteIntentObserver(ITfCardWriteTarget inner, TfInstallWorkflow owner)
        {
            _inner = inner;
            _owner = owner;
        }

        public TfCardTargetIdentity Identity => _inner.Identity;

        public ValueTask<TfCardTargetIdentity> RevalidateAsync(CancellationToken ct) => _inner.RevalidateAsync(ct);

        public ValueTask ReadExactlyAsync(long offset, Memory<byte> buffer, CancellationToken ct)
            => _inner.ReadExactlyAsync(offset, buffer, ct);

        public async ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> buffer, CancellationToken ct)
        {
            if (Interlocked.Exchange(ref _firstWritePending, 0) != 0)
                await _owner.OnFirstWriteAttemptAsync(ct).ConfigureAwait(false);
            await _inner.WriteAsync(offset, buffer, ct).ConfigureAwait(false);
        }

        public ValueTask FlushAsync(CancellationToken ct) => _inner.FlushAsync(ct);

        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }

    private async Task OnFirstWriteAttemptAsync(CancellationToken ct)
    {
        await WriteIntentMarkerAsync(ct).ConfigureAwait(false);
        Interlocked.Exchange(ref _writeAttempted, 1);
        RefreshSnapshot(TfInstallStage.ProcessingCard, null, null, null);
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
            throw new ObjectDisposedException(nameof(TfInstallWorkflow));
    }

    private static void ValidateTargetIdentity(TfCardTargetIdentity identity, TfCardCandidate card)
    {
        if (identity.Source != TfCardSource.Reader)
            throw new InvalidOperationException($"Opened card target source is {identity.Source}, expected Reader.");
        if (!string.Equals(identity.Key, card.Key, StringComparison.Ordinal)
            || !string.Equals(identity.DevicePath, card.Path, StringComparison.Ordinal)
            || identity.SizeBytes != card.SizeBytes
            || identity.LogicalSectorSize != card.LogicalSectorSize)
            throw new InvalidOperationException("Opened card target does not match the requested reader candidate key/path/size/sector geometry.");
    }

    private static void ValidateBootPrepared(TfBootPrepared prepared, TfBootPlan plan, TfPreparedCardImages images, InternalBackupSet backup, string currentSlot)
    {
        if (prepared.Operation != TfBootOperation.Final)
            throw new InvalidOperationException($"Boot plan operation is {prepared.Operation}, expected Final.");
        if (prepared.RawPurpose != TfBootPurpose.FinalTf)
            throw new InvalidOperationException($"Boot plan raw purpose is {prepared.RawPurpose}, expected FinalTf.");
        if (!string.Equals(prepared.Model, images.Contract.DeviceModel, StringComparison.Ordinal)
            || !string.Equals(prepared.Model, backup.Model, StringComparison.Ordinal))
            throw new InvalidOperationException("Boot plan model does not match the captured package/backup model.");
        if (!string.Equals(prepared.SourceBackupDirectory, backup.DirectoryPath, StringComparison.Ordinal)
            || !string.Equals(prepared.SourceBackupManifestSha256, backup.ManifestSha256, StringComparison.Ordinal)
            || !string.Equals(prepared.TargetBackupDirectory, plan.TargetBackupDirectory, StringComparison.Ordinal)
            || !string.Equals(prepared.TargetBackupManifestSha256, plan.TargetBackupManifestSha256, StringComparison.Ordinal)
            || !string.Equals(prepared.CurrentSlot, currentSlot, StringComparison.Ordinal)
            || !string.Equals(prepared.PackageManifestFingerprint, images.Contract.ManifestFingerprint, StringComparison.Ordinal)
            || !string.Equals(prepared.PackageManifestFingerprint, plan.PackageManifestFingerprint, StringComparison.Ordinal))
            throw new InvalidOperationException("Boot plan backup/slot/package facts do not match this prepare run.");
    }

    private static async Task<string> ReadCurrentSlotAsync(InternalBackupSet backup, CancellationToken ct)
    {
        EdlCapturedRegion misc = backup.Files.Values.FirstOrDefault(r => string.Equals(r.Role, "misc", StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("Fresh backup does not contain a captured misc region.");
        var file = new VerifiedEdlFile(misc.FilePath, misc.Length, misc.Sha256);
        var facts = await BootSlotControl.ReadAsync(file, ct).ConfigureAwait(false);
        string? slot = facts.CurrentSlot;
        if (!string.Equals(slot, "a", StringComparison.Ordinal) && !string.Equals(slot, "b", StringComparison.Ordinal))
            throw new InvalidOperationException($"Captured misc reports unusable current slot '{slot ?? "<null>"}'.");
        return slot!;
    }

    private static IReadOnlyList<string> BuildProtectedPaths(TfInstallRequest request, ImportedPackage package, InternalBackupSet backup, string evidenceChild, EdlRawBootTools tools)
    {
        var paths = new List<string>();
        void Add(string? p)
        {
            if (!string.IsNullOrWhiteSpace(p))
                paths.Add(p);
        }
        foreach (string p in request.ProtectedPaths)
            Add(p);
        Add(package.SourcePath);
        Add(package.PackageDirectory);
        Add(backup.DirectoryPath);
        Add(evidenceChild);
        Add(tools.Packer?.Path);
        Add(tools.Unpacker?.Path);
        return paths.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static string BuildConfirmationId(string nonce, TfCardTargetIdentity identity, TfCardLayoutPlan layout,
        string packageManifestFingerprint, string sourceBackupManifestSha256, TfBootPrepared boot)
    {
        var canonical = new
        {
            nonce,
            target = new
            {
                source = identity.Source.ToString(), identity.Key, identity.DevicePath,
                identity.SizeBytes, identity.LogicalSectorSize, identity.BindingSha256,
            },
            layout = new
            {
                layout.CardBytes, layout.LogicalSectorSize, layout.TotalSectors, layout.BootStartSector,
                layout.BootSectorCount, layout.RootStartSector, layout.RootSectorCount,
                diskGuid = layout.DiskGuid.ToString(), bootGuid = layout.BootGuid.ToString(), rootGuid = layout.RootGuid.ToString(),
            },
            packageManifestFingerprint,
            sourceBackupManifestSha256,
            boot = new
            {
                confirmationId = boot.ConfirmationId,
                operation = boot.Operation.ToString(),
                purpose = boot.RawPurpose?.ToString(),
            },
        };
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(canonical);
        return Convert.ToHexString(SHA256.HashData(json)).ToLowerInvariant();
    }

    private static TfInstallStage MapStage(BootMaintenanceOutcome outcome) => outcome switch
    {
        BootMaintenanceOutcome.Completed => TfInstallStage.Completed,
        BootMaintenanceOutcome.Failed => TfInstallStage.Failed,
        BootMaintenanceOutcome.Cancelled => TfInstallStage.Cancelled,
        _ => TfInstallStage.UnknownWriteOutcome,
    };

    private static TfInstallOutcome MapOutcome(BootMaintenanceOutcome outcome) => outcome switch
    {
        BootMaintenanceOutcome.Cancelled => TfInstallOutcome.Cancelled,
        BootMaintenanceOutcome.UnknownWriteOutcome => TfInstallOutcome.UnknownWriteOutcome,
        _ => TfInstallOutcome.Failed,
    };

    private sealed class CardProgressForwarder : IProgress<TfCardWriteProgress>
    {
        private readonly Action<TfCardWriteProgress> _sink;
        public CardProgressForwarder(Action<TfCardWriteProgress> sink) => _sink = sink;
        public TfCardWriteProgress? Last { get; private set; }
        public void Report(TfCardWriteProgress value)
        {
            Last = value;
            _sink(value);
        }
    }

    private sealed class BootProgressForwarder : IProgress<InternalInstallProgress>
    {
        private readonly Func<TfCardWriteProgress?> _lastCard;
        private readonly IProgress<TfInstallProgress>? _progress;
        public BootProgressForwarder(Func<TfCardWriteProgress?> lastCard, IProgress<TfInstallProgress>? progress)
        {
            _lastCard = lastCard;
            _progress = progress;
        }
        public void Report(InternalInstallProgress value)
            => _progress?.Report(new TfInstallProgress(TfInstallStage.WritingTabletBoot, _lastCard(), value, null));
    }
}
