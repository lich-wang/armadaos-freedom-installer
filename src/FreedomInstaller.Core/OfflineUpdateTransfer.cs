using System.Security.Cryptography;
using System.Text.Json;

namespace FreedomInstaller.Core;

public sealed record OfflineUpdateSession(
    string SessionId,
    string DeviceModel,
    string RecoveryPartUuid,
    string PackageDescriptorSha256);

public sealed record OfflineUpdateTransferProgress(
    string Phase,
    long? BytesCompleted,
    long? TotalBytes);

public sealed class OfflineUpdateTransferException : Exception
{
    public OfflineUpdateTransferException(string message, JsonElement? receipt = null, Exception? innerException = null)
        : base(message, innerException) => Receipt = receipt?.Clone();

    public JsonElement? Receipt { get; }
}

public sealed class OfflineUpdateTransfer
{
    private const int MaxMetadataBytes = 2 * 1024 * 1024;
    private const int MaxSignatureBytes = 16 * 1024;
    private const int ChunkBytes = 1024 * 1024;
    private const string DescriptorName = "package.update.json";
    private const string SignatureName = "package.update.json.sig";
    private static readonly TimeSpan DefaultPollInterval = TimeSpan.FromSeconds(2);

    private readonly OfflineUpdateRpcClient _client;
    private readonly TimeSpan _pollInterval;

    public OfflineUpdateTransfer(OfflineUpdateRpcClient client, TimeSpan? pollInterval = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        var value = pollInterval ?? DefaultPollInterval;
        if (value <= TimeSpan.Zero || !double.IsFinite(value.TotalSeconds) ||
            value.TotalMilliseconds > uint.MaxValue - 1)
            throw new ArgumentOutOfRangeException(nameof(pollInterval));
        _client = client;
        _pollInterval = value;
    }

    private sealed record PayloadSpec(
        string Path, long Bytes, string Sha256, string FullPath, Version MinimumUpdaterVersion);
    private sealed record DeviceInfo(string Model, string RecoveryPartUuid);
    private sealed record ExportMetadata(string TransactionId, string PlanSha256, string RecoveryManifestSha256);

    /// <summary>
    /// A 0.7 controller reports no proven actual slot: it exposes only the
    /// selected slot plus <c>bootContext=legacy-controller</c>. Such a response
    /// is accepted for the BOTH-slot flow but is never presented as proof of
    /// the running slot.
    /// </summary>
    private readonly record struct SlotInfo(
        string? ActualSlot,
        string? InactiveSlot,
        string? SelectedSlot,
        bool LegacyController);

    /// <summary>
    /// Read-only preflight of the signed package document. The tablet may
    /// inspect the device model, deployment, slots and storage, but this call
    /// creates no session and does not prepare or write anything.
    /// </summary>
    public Task<JsonElement> PreflightAsync(
        ImportedUpdatePackage package,
        CancellationToken token = default) =>
        PreflightAsync(package, null, token);

    /// <summary>
    /// Read-only preflight bound to an existing session of this exact package
    /// and device. The tablet credits the payload bytes the session already
    /// stores, so reconnecting to a prepared session does not demand the whole
    /// compressed payload again. A pass is accepted only when the response
    /// names this session, model and recovery partition.
    /// </summary>
    public async Task<JsonElement> PreflightAsync(
        ImportedUpdatePackage package,
        OfflineUpdateSession? session,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(package);
        token.ThrowIfCancellationRequested();
        var stage = GetStage(package);
        var document = ReadBoundedFile(package.DescriptorPath, stage, MaxMetadataBytes, token);
        var signature = ReadBoundedFile(package.SignaturePath, stage, MaxSignatureBytes, token);
        if (session is null)
        {
            var plain = await _client.PreflightAsync(document, signature, token).ConfigureAwait(false);
            if (plain.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("preflight 响应必须是 JSON 对象。");
            return plain.Clone();
        }

        var normalized = ValidateSession(session, package.DeviceModel);
        _ = VerifyPackage(package, normalized, token);
        var result = await _client.PreflightAsync(document, signature, normalized.SessionId, token).ConfigureAwait(false);
        if (result.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("preflight 响应必须是 JSON 对象。");
        // Evidence for another session, another model or another recovery
        // partition never unlocks this session's prepare/execute.
        Require(result, "sessionId", normalized.SessionId);
        Require(result, "model", normalized.DeviceModel);
        Require(result, "recoveryPartUuid", normalized.RecoveryPartUuid);

        return result.Clone();
    }

    public async Task<OfflineUpdateSession> CreateSessionAsync(
        ImportedUpdatePackage package,
        Func<OfflineUpdateSession, CancellationToken, Task> persistSession,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(persistSession);
        token.ThrowIfCancellationRequested();
        var spec = ReadDescriptor(package, token);
        var signature = ReadBoundedFile(package.SignaturePath, GetStage(package), MaxSignatureBytes, token);
        var infoJson = await _client.GetInfoAsync(token).ConfigureAwait(false);
        var info = ValidateInfo(infoJson, package.DeviceModel, spec.MinimumUpdaterVersion, null);
        // Creating a session starts the upload/prepare flow, so it is the
        // first mutating step and must prove the no-slot-control boot policy.
        RequireNoSlotControlBootPolicy(infoJson);
        var receipt = await _client.BeginAsync(spec.DescriptorBytes, signature, token).ConfigureAwait(false);
        var sessionId = ValidateReceipt(receipt, null, info.Model, info.RecoveryPartUuid, spec, "begin");
        var state = RequiredString(receipt, "state", "begin");
        if (state is not ("uploading" or "uploaded"))
            throw Terminal("创建会话", state, receipt);
        var session = new OfflineUpdateSession(sessionId, info.Model, info.RecoveryPartUuid, spec.DescriptorSha256);
        await persistSession(session, token).ConfigureAwait(false);
        return session;
    }

    public async Task<JsonElement> PrepareAsync(
        ImportedUpdatePackage package, OfflineUpdateSession session,
        IProgress<OfflineUpdateTransferProgress>? progress = null, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(session);
        var normalized = ValidateSession(session, package.DeviceModel);
        var spec = VerifyPackage(package, normalized, token);
        var infoJson = await _client.GetInfoAsync(token).ConfigureAwait(false);
        _ = ValidateInfo(infoJson, normalized.DeviceModel, spec.MinimumUpdaterVersion, normalized.RecoveryPartUuid);
        // Upload, seal and prepare are mutating: never run them against a
        // helper that may still control Android's active/selected slot.
        RequireNoSlotControlBootPolicy(infoJson);
        var receipt = await Status(normalized, spec, token).ConfigureAwait(false);
        var state = RequiredString(receipt, "state", "status");
        if (state == "uploading")
        {
            receipt = await UploadAndSeal(package, normalized, spec, receipt, progress, token).ConfigureAwait(false);
            state = RequiredString(receipt, "state", "seal");
        }
        if (state == "uploaded")
        {
            progress?.Report(new("preparing", null, spec.Bytes));
            receipt = await _client.PrepareAsync(normalized.SessionId, token).ConfigureAwait(false);
            ValidateReceipt(receipt, normalized.SessionId, normalized.DeviceModel, normalized.RecoveryPartUuid, spec, "prepare");
            state = RequiredString(receipt, "state", "prepare");
        }
        while (true)
        {
            switch (state)
            {
                case "prepare_queued":
                case "preparing":
                    progress?.Report(new(state, null, spec.Bytes));
                    await Task.Delay(_pollInterval, token).ConfigureAwait(false);
                    receipt = await Status(normalized, spec, token).ConfigureAwait(false);
                    state = RequiredString(receipt, "state", "status");
                    break;
                case "prepared":
                    _ = ExportData(receipt);
                    progress?.Report(new("prepared", spec.Bytes, spec.Bytes));
                    return receipt.Clone();
                case "up_to_date":
                    progress?.Report(new("up_to_date", spec.Bytes, spec.Bytes));
                    return receipt.Clone();
                default:
                    throw Terminal("离线升级预处理", state, receipt);
            }
        }
    }

    public async Task<SavedOfflineUpdateRecovery> SaveRecoveryAsync(
        ImportedUpdatePackage package, OfflineUpdateSession session, string workRoot,
        IProgress<OfflineUpdateTransferProgress>? progress = null, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(session);
        if (string.IsNullOrWhiteSpace(workRoot)) throw new InvalidDataException("未指定恢复保存目录。");
        var normalized = ValidateSession(session, package.DeviceModel);
        var spec = VerifyPackage(package, normalized, token);
        _ = ValidateInfo(await _client.GetInfoAsync(token).ConfigureAwait(false),
            normalized.DeviceModel, spec.MinimumUpdaterVersion, normalized.RecoveryPartUuid);
        var receipt = await Status(normalized, spec, token).ConfigureAwait(false);
        var state = RequiredString(receipt, "state", "status");
        if (state != "prepared") throw Terminal("恢复导出", state, receipt);
        var meta = ExportData(receipt);
        progress?.Report(new("saving_recovery_metadata", 0, null));
        var plan = await ExportBlob(normalized.SessionId, "plan.json", meta.PlanSha256, token).ConfigureAwait(false);
        ValidateExportedPlan(plan, normalized, meta);
        var manifest = await ExportBlob(normalized.SessionId, "recovery-manifest.json",
            meta.RecoveryManifestSha256, token).ConfigureAwait(false);
        var context = new OfflineUpdateRecoveryContext(meta.TransactionId, normalized.DeviceModel,
            meta.PlanSha256, meta.RecoveryManifestSha256);
        var adapter = progress is null ? null : new SynchronousProgress<OfflineUpdateRecoveryProgress>(
            p => progress.Report(new("saving_recovery", p.BytesCompleted, p.TotalBytes)));
        return await PackageImporter.SaveOfflineUpdateRecoveryAsync(workRoot, context, plan, manifest,
            (path, ct) => Task.FromResult<Stream>(new RpcExportReadStream(_client, normalized.SessionId, path)),
            adapter, token).ConfigureAwait(false);
    }

    public async Task<JsonElement> ExecuteAsync(
        ImportedUpdatePackage package, OfflineUpdateSession session, SavedOfflineUpdateRecovery recovery,
        IProgress<OfflineUpdateTransferProgress>? progress = null, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(recovery);
        var normalized = ValidateSession(session, package.DeviceModel);
        var spec = VerifyPackage(package, normalized, token);
        var infoJson = await _client.GetInfoAsync(token).ConfigureAwait(false);
        _ = ValidateInfo(infoJson, normalized.DeviceModel, spec.MinimumUpdaterVersion, normalized.RecoveryPartUuid);
        // Execution writes both physical boot candidates; it must never run
        // under a helper that still controls the Android slot state.
        RequireNoSlotControlBootPolicy(infoJson);
        var receipt = await Status(normalized, spec, token).ConfigureAwait(false);
        var state = RequiredString(receipt, "state", "status");
        if (state == "prepared")
        {
            var meta = ExportData(receipt);
            var context = new OfflineUpdateRecoveryContext(meta.TransactionId, normalized.DeviceModel,
                meta.PlanSha256, meta.RecoveryManifestSha256);
            var ack = PackageImporter.ValidateSavedOfflineUpdateRecovery(
                recovery, context, normalized.PackageDescriptorSha256, token);
            progress?.Report(new("executing", null, null));
            receipt = await _client.ExecuteAsync(normalized.SessionId, ack, token).ConfigureAwait(false);
            ValidateReceipt(receipt, normalized.SessionId, normalized.DeviceModel,
                normalized.RecoveryPartUuid, spec, "execute");
            state = RequiredString(receipt, "state", "execute");
        }
        else if (state is not ("execute_queued" or "executing" or "awaiting_reboot"))
        {
            throw Terminal("离线升级执行", state, receipt);
        }
        while (true)
        {
            switch (state)
            {
                case "execute_queued":
                case "executing":
                    progress?.Report(new(state, null, null));
                    await Task.Delay(_pollInterval, token).ConfigureAwait(false);
                    receipt = await Status(normalized, spec, token).ConfigureAwait(false);
                    state = RequiredString(receipt, "state", "status");
                    break;
                case "awaiting_reboot":
                    progress?.Report(new("awaiting_reboot", null, null));
                    return receipt.Clone();
                default:
                    throw Terminal("离线升级执行", state, receipt);
            }
        }
    }

    /// <summary>
    /// Ask the tablet to restart into the already activated new deployment.
    /// Sending this request is not proof that the reboot happened: a lost
    /// connection after dispatch must be reported as unknown and resolved by a
    /// later read-only status query.
    /// </summary>
    public async Task<JsonElement> RestartToVerifyAsync(
        OfflineUpdateSession session, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        token.ThrowIfCancellationRequested();
        var normalized = ValidateSession(session, session.DeviceModel);
        // A restart request is mutating and belongs to the same no-slot-control
        // contract as execution; its info read is still read-only.
        var infoJson = await _client.GetInfoAsync(token).ConfigureAwait(false);
        ValidateInfoIdentity(infoJson, normalized);
        RequireNoSlotControlBootPolicy(infoJson);
        var result = await _client.RestartToVerifyAsync(normalized.SessionId, token).ConfigureAwait(false);
        Schema(result);
        Require(result, "sessionId", normalized.SessionId);
        Require(result, "state", "awaiting_reboot");
        var transactionId = GuidD(RequiredString(result, "transactionId", "restart"));
        _ = RequiredString(result, "deployment", "restart");
        if (!result.TryGetProperty("restart", out var restart) || restart.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("restart response is missing the restart record.");
        Schema(restart);
        Require(restart, "transactionId", transactionId);
        var state = RequiredString(restart, "state", "restart");
        // "dispatching" records a restart that an earlier request already put
        // inside the reboot window: the device is still working on that one
        // request, so it is a pending dispatch and is neither rejected nor
        // re-sent. A state outside these three may already have reached the
        // firmware and is still refused.
        if (state is not ("dispatching" or "dispatched" or "uncertain"))
            throw new InvalidDataException("restart response has an unexpected restart state.");
        return result;
    }

    /// <summary>
    /// Read-only status for a session saved by an earlier run, without the
    /// package. Only the durable session/device binding (model, recovery
    /// partition UUID) and the receipt structure are checked, so a restart of
    /// the app can show the tablet's real result without re-importing or
    /// re-validating the upgrade package.
    /// </summary>
    public async Task<JsonElement> QuerySessionStatusAsync(
        OfflineUpdateSession session, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        token.ThrowIfCancellationRequested();
        var normalized = ValidateSessionIdentity(session);
        ValidateInfoIdentity(await _client.GetInfoAsync(token).ConfigureAwait(false), normalized);
        var receipt = await _client.GetStatusAsync(normalized.SessionId, token).ConfigureAwait(false);
        ValidateSessionReceipt(receipt, normalized);
        return receipt.Clone();
    }

    public async Task<JsonElement> QueryStatusAsync(
        ImportedUpdatePackage package, OfflineUpdateSession session, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(session);
        token.ThrowIfCancellationRequested();
        var normalized = ValidateSession(session, package.DeviceModel);
        var spec = VerifyPackage(package, normalized, token);
        _ = ValidateInfo(await _client.GetInfoAsync(token).ConfigureAwait(false),
            normalized.DeviceModel, spec.MinimumUpdaterVersion, normalized.RecoveryPartUuid);
        var receipt = await Status(normalized, spec, token).ConfigureAwait(false);
        _ = RequiredString(receipt, "state", "status");
        return receipt.Clone();
    }

    public async Task<JsonElement> ObserveExecutionAsync(
        ImportedUpdatePackage package, OfflineUpdateSession session,
        IProgress<OfflineUpdateTransferProgress>? progress = null, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(session);
        token.ThrowIfCancellationRequested();
        var normalized = ValidateSession(session, package.DeviceModel);
        var spec = VerifyPackage(package, normalized, token);
        _ = ValidateInfo(await _client.GetInfoAsync(token).ConfigureAwait(false),
            normalized.DeviceModel, spec.MinimumUpdaterVersion, normalized.RecoveryPartUuid);
        var receipt = await Status(normalized, spec, token).ConfigureAwait(false);
        var state = RequiredString(receipt, "state", "status");
        while (true)
        {
            switch (state)
            {
                case "execute_queued":
                case "executing":
                    progress?.Report(new(state, null, null));
                    await Task.Delay(_pollInterval, token).ConfigureAwait(false);
                    receipt = await Status(normalized, spec, token).ConfigureAwait(false);
                    state = RequiredString(receipt, "state", "status");
                    break;
                case "awaiting_reboot":
                    progress?.Report(new("awaiting_reboot", null, null));
                    return receipt.Clone();
                default:
                    throw Terminal("离线升级执行", state, receipt);
            }
        }
    }

    private sealed record DescriptorPayload(
        byte[] DescriptorBytes, string DescriptorSha256, string Path, long Bytes,
        string Sha256, string FullPath, Version MinimumUpdaterVersion)
    {
        public static implicit operator PayloadSpec(DescriptorPayload value) =>
            new(value.Path, value.Bytes, value.Sha256, value.FullPath, value.MinimumUpdaterVersion);
    }

    private static string GetStage(ImportedUpdatePackage package)
    {
        var payload = Path.GetFullPath(package.PackageDirectory);
        if (!string.Equals(Path.GetFileName(payload), "payload", StringComparison.Ordinal))
            throw new InvalidDataException("导入包 payload 目录布局非法。");
        var stage = Directory.GetParent(payload)?.FullName ?? throw new InvalidDataException("导入包缺少 staging 目录。");
        EnsureLocalNoReparse(stage);
        foreach (var (path, name) in new[] { (package.DescriptorPath, DescriptorName), (package.SignaturePath, SignatureName) })
        {
            var full = Path.GetFullPath(path);
            if (Path.GetFileName(full) != name ||
                !string.Equals(Directory.GetParent(full)?.FullName, stage, StringComparison.Ordinal))
                throw new InvalidDataException("描述文件或签名文件不在 payload 的同级 staging 目录。");
        }
        return stage;
    }

    private static DescriptorPayload ReadDescriptor(ImportedUpdatePackage package, CancellationToken token)
    {
        var stage = GetStage(package);
        var bytes = ReadBoundedFile(package.DescriptorPath, stage, MaxMetadataBytes, token);
        using var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions
        { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow });
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            !string.Equals(root.GetRawText(), package.Descriptor.Root.GetRawText(), StringComparison.Ordinal))
            throw new InvalidDataException("原始签名描述文件与已导入 Descriptor.Root 不一致。");
        if (!root.TryGetProperty("supportedModels", out var models) || models.ValueKind != JsonValueKind.Array ||
            !models.EnumerateArray().Any(x => x.ValueKind == JsonValueKind.String && x.GetString() == package.DeviceModel))
            throw new InvalidDataException("描述文件不支持目标设备型号。");
        if (!UpdatePackageDescriptor.SupportsOfflineUpgrade(package.DeviceModel))
            throw new InvalidDataException("当前原生适配器不支持该设备型号的离线升级。");
        var minimum = ParseVersion(RequiredString(root, "minimumUpdaterVersion", "descriptor"));
        if (!root.TryGetProperty("files", out var files) || files.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("描述文件仅支持 files 数组。");
        var matches = files.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.Object &&
            RequiredString(x, "role", "descriptor") == "linux-root").ToArray();
        if (matches.Length != 1) throw new InvalidDataException("描述文件必须且只能包含一个 linux-root 文件。");
        var file = matches[0];
        if (RequiredString(file, "compression", "descriptor") != "gzip")
            throw new InvalidDataException("linux-root 必须使用 gzip 压缩。");
        var relative = RequiredString(file, "path", "descriptor");
        if (!file.TryGetProperty("bytes", out var length) || !length.TryGetInt64(out var size) || size <= 0)
            throw new InvalidDataException("linux-root 文件长度非法。");
        var sha = Sha(RequiredString(file, "sha256", "descriptor"));
        var payloadRoot = Path.GetFullPath(package.PackageDirectory);
        if (Path.IsPathRooted(relative) || relative.Contains('\\')) throw new InvalidDataException("payload 路径非法。");
        var full = Path.GetFullPath(Path.Combine(payloadRoot, relative.Replace('/', Path.DirectorySeparatorChar)));
        if (!Beneath(full, payloadRoot)) throw new InvalidDataException("payload 路径越界。");
        EnsureLocalNoReparse(full);
        var info = new FileInfo(full);
        if (!info.Exists || info.Length != size || (info.Attributes & FileAttributes.Directory) != 0)
            throw new InvalidDataException("payload 文件不存在或长度不匹配。");
        return new(bytes, Convert.ToHexStringLower(SHA256.HashData(bytes)), relative, size, sha, full, minimum);
    }

    private static PayloadSpec VerifyPackage(ImportedUpdatePackage package, OfflineUpdateSession session, CancellationToken token)
    {
        var value = ReadDescriptor(package, token);
        if (value.DescriptorSha256 != session.PackageDescriptorSha256)
            throw new InvalidDataException("导入包描述文件已在会话创建后发生变化。");
        return value;
    }

    private static byte[] ReadBoundedFile(string path, string stage, int maximum, CancellationToken token)
    {
        var full = Path.GetFullPath(path);
        if (!Beneath(full, stage)) throw new InvalidDataException("文件超出 staging 目录。");
        EnsureLocalNoReparse(full);
        using var stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read,
            65536, FileOptions.SequentialScan);
        if (stream.Length <= 0 || stream.Length > maximum) throw new InvalidDataException($"文件长度非法：{path}。");
        var result = new byte[stream.Length];
        stream.ReadExactly(result);
        token.ThrowIfCancellationRequested();
        if (stream.ReadByte() != -1) throw new InvalidDataException("文件超过允许长度。");
        return result;
    }

    private static DeviceInfo ValidateInfo(JsonElement info, string model, Version minimum, string? expectedUuid)
    {
        Schema(info);
        Require(info, "model", model);
        if (ParseVersion(RequiredString(info, "updaterVersion", "info")) < minimum)
            throw new InvalidDataException("设备 updater 版本低于描述文件最低要求。");
        _ = ReadSlots(info, "info");
        _ = RequiredString(info, "deployment", "info");
        var uuid = GuidD(RequiredString(info, "recoveryPartUuid", "info"));
        if (expectedUuid is not null && uuid != expectedUuid) throw new InvalidDataException("恢复分区 UUID 已变化。");
        return new(model, uuid);
    }

    /// <summary>
    /// Every mutating offline upgrade step requires the device to advertise the
    /// exact no-slot-control boot policy. A helper that omits it or reports
    /// another value may still write slot metadata or mark a slot successful,
    /// so it is refused before any begin/upload/seal/prepare/execute/restart
    /// request is sent. Read-only info, preflight, status and recovery export
    /// stay available so a saved session remains inspectable.
    /// </summary>
    private static void RequireNoSlotControlBootPolicy(JsonElement info)
    {
        if (!OfflineUpdateBootPolicy.IsNoSlotControl(info))
            throw new InvalidDataException(
                "设备未声明 dual-boot-no-slot-control 启动策略，升级程序可能更改 Android 的活动槽位；" +
                "已拒绝任何写入操作。请先更新平板上的离线升级组件。");
    }

    private static OfflineUpdateSession ValidateSessionIdentity(OfflineUpdateSession session) =>
        new(SessionId(session.SessionId), session.DeviceModel,
            GuidD(session.RecoveryPartUuid), Sha(session.PackageDescriptorSha256));

    private static void ValidateInfoIdentity(JsonElement info, OfflineUpdateSession session)
    {
        Schema(info);
        Require(info, "model", session.DeviceModel);
        _ = RequiredString(info, "updaterVersion", "info");
        _ = ReadSlots(info, "info");
        _ = RequiredString(info, "deployment", "info");
        // The saved session is only reusable on the same physical device.
        Require(info, "recoveryPartUuid", session.RecoveryPartUuid);
    }

    /// <summary>
    /// Validate a session-only receipt: everything that can be proven without
    /// the package bytes. The payload block is still required to be well formed
    /// but is not compared with a descriptor the caller does not have.
    /// </summary>
    private static void ValidateSessionReceipt(JsonElement receipt, OfflineUpdateSession session)
    {
        Schema(receipt);
        Require(receipt, "sessionId", session.SessionId);
        Require(receipt, "model", session.DeviceModel);
        if (!receipt.TryGetProperty("physical", out var physical) || physical.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("receipt 缺少 physical。");
        Require(physical, "model", session.DeviceModel);
        Require(physical, "recoveryPartUuid", session.RecoveryPartUuid);
        _ = ReadSlots(physical, "status");
        _ = RequiredString(physical, "deployment", "status");
        if (!receipt.TryGetProperty("payload", out var body) || body.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("receipt 缺少 payload。");
        _ = RequiredString(body, "path", "status");
        _ = Sha(RequiredString(body, "sha256", "status"));
        if (!body.TryGetProperty("bytes", out var bytes) || !bytes.TryGetInt64(out var size) || size <= 0)
            throw new InvalidDataException("receipt payload 长度非法。");
        _ = RequiredString(receipt, "state", "status");
        CheckAttention(receipt);
    }

    private static string ValidateReceipt(JsonElement receipt, string? sessionId, string model,
        string uuid, PayloadSpec payload, string label)
    {
        Schema(receipt);
        var sid = SessionId(RequiredString(receipt, "sessionId", label));
        if (sessionId is not null && sid != sessionId) throw new InvalidDataException("receipt sessionId 不匹配。");
        Require(receipt, "model", model);
        if (!receipt.TryGetProperty("physical", out var physical) || physical.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("receipt 缺少 physical。");
        Require(physical, "model", model);
        Require(physical, "recoveryPartUuid", uuid);
        _ = ReadSlots(physical, label);
        _ = RequiredString(physical, "deployment", label);
        if (!receipt.TryGetProperty("payload", out var body) || body.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("receipt 缺少 payload。");
        Require(body, "path", payload.Path);
        Require(body, "sha256", payload.Sha256);
        if (!body.TryGetProperty("bytes", out var bytes) || !bytes.TryGetInt64(out var size) || size != payload.Bytes)
            throw new InvalidDataException("receipt payload 长度不匹配。");
        CheckAttention(receipt);
        return sid;
    }

    private async Task<JsonElement> Status(OfflineUpdateSession session, PayloadSpec spec, CancellationToken token)
    {
        var receipt = await _client.GetStatusAsync(session.SessionId, token).ConfigureAwait(false);
        ValidateReceipt(receipt, session.SessionId, session.DeviceModel, session.RecoveryPartUuid, spec, "status");
        return receipt;
    }

    private async Task<JsonElement> UploadAndSeal(ImportedUpdatePackage package, OfflineUpdateSession session,
        PayloadSpec spec, JsonElement receipt, IProgress<OfflineUpdateTransferProgress>? progress, CancellationToken token)
    {
        _ = package;
        if (!receipt.TryGetProperty("receivedBytes", out var received) || !received.TryGetInt64(out var offset) ||
            offset < 0 || offset > spec.Bytes) throw new InvalidDataException("上传续传偏移非法。");
        await using var stream = new FileStream(spec.FullPath, FileMode.Open, FileAccess.Read, FileShare.Read,
            65536, FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length != spec.Bytes) throw new InvalidDataException("上传文件长度已变化。");
        stream.Position = offset;
        var buffer = new byte[ChunkBytes];
        while (offset < spec.Bytes)
        {
            token.ThrowIfCancellationRequested();
            var count = (int)Math.Min(buffer.Length, spec.Bytes - offset);
            await stream.ReadExactlyAsync(buffer.AsMemory(0, count), token).ConfigureAwait(false);
            var response = await _client.UploadAsync(session.SessionId, offset, buffer.AsMemory(0, count), token).ConfigureAwait(false);
            if (!response.TryGetProperty("receivedBytes", out var value) || !value.TryGetInt64(out var next) || next != offset + count)
                throw new InvalidDataException("upload 响应 receivedBytes 不匹配。");
            offset = next;
            progress?.Report(new("uploading", offset, spec.Bytes));
        }
        var sealedReceipt = await _client.SealAsync(session.SessionId, token).ConfigureAwait(false);
        ValidateReceipt(sealedReceipt, session.SessionId, session.DeviceModel, session.RecoveryPartUuid, spec, "seal");
        return sealedReceipt;
    }

    private async Task<byte[]> ExportBlob(string sessionId, string path, string expectedSha, CancellationToken token)
    {
        using var output = new MemoryStream();
        while (output.Length <= MaxMetadataBytes)
        {
            var count = (int)Math.Min(ChunkBytes, MaxMetadataBytes + 1L - output.Length);
            var part = await _client.ExportAsync(sessionId, path, output.Length, count, token).ConfigureAwait(false);
            if (part is null || part.Length > count) throw new InvalidDataException("范围导出响应长度非法。");
            if (part.Length == 0) break;
            output.Write(part);
            if (output.Length > MaxMetadataBytes) throw new InvalidDataException("导出元数据超过 2 MiB。");
        }
        var bytes = output.ToArray();
        if (bytes.Length == 0 || Convert.ToHexStringLower(SHA256.HashData(bytes)) != expectedSha)
            throw new InvalidDataException($"导出元数据为空或哈希不匹配：{path}。");
        return bytes;
    }

    private static ExportMetadata ExportData(JsonElement receipt)
    {
        ExportMetadata? found = null;
        foreach (var name in new[] { "result", "transaction" })
        {
            if (!receipt.TryGetProperty(name, out var value)) continue;
            if (value.ValueKind != JsonValueKind.Object || RequiredString(value, "state", name) != "awaiting_recovery_export")
                throw new InvalidDataException("prepared receipt 导出事务状态非法。");
            var current = new ExportMetadata(GuidD(RequiredString(value, "transactionId", name)),
                Sha(RequiredString(value, "planSha256", name)),
                Sha(RequiredString(value, "recoveryManifestSha256", name)));
            if (found is not null && found != current) throw new InvalidDataException("result 与 transaction 导出元数据不一致。");
            found = current;
        }
        return found ?? throw new InvalidDataException("prepared receipt 缺少恢复导出元数据。");
    }

    private static void ValidateExportedPlan(byte[] bytes, OfflineUpdateSession session, ExportMetadata meta)
    {
        using var doc = JsonDocument.Parse(bytes);
        var root = doc.RootElement;
        Require(root, "transactionId", meta.TransactionId);
        Require(root, "model", session.DeviceModel);
        Require(root, "packageDescriptorSha256", session.PackageDescriptorSha256);
        Require(root, "recoveryManifestSha256", meta.RecoveryManifestSha256);
    }

    private static OfflineUpdateSession ValidateSession(OfflineUpdateSession session, string model)
    {
        if (session.DeviceModel != model) throw new InvalidDataException("会话与导入包设备型号不匹配。");
        return new(SessionId(session.SessionId), model, GuidD(session.RecoveryPartUuid), Sha(session.PackageDescriptorSha256));
    }

    private static void CheckAttention(JsonElement receipt)
    {
        foreach (var name in new[] { "jobInterrupted", "attentionRequired" })
            if (receipt.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.True)
                throw new OfflineUpdateTransferException($"设备任务要求停止：{name}。", receipt);
    }

    private static OfflineUpdateTransferException Terminal(string operation, string state, JsonElement receipt)
    {
        var detail = receipt.TryGetProperty("result", out var result) && result.ValueKind == JsonValueKind.Object &&
            result.TryGetProperty("state", out var resultState) ? $"，result.state={resultState.GetString()}" : "";
        return new OfflineUpdateTransferException($"{operation}停止，状态：{state}{detail}。", receipt);
    }

    private static Version ParseVersion(string text)
    {
        var parts = text.Split('.');
        if (parts.Length != 3 || parts.Any(p => !int.TryParse(p, out var n) || n < 0))
            throw new InvalidDataException($"版本号必须为数值 x.y.z：{text}。");
        return Version.Parse(text);
    }

    private static string SessionId(string value)
    {
        if (value.Length != 32 || value.Any(c => !(c is >= '0' and <= '9' or >= 'a' and <= 'f')) ||
            !Guid.TryParseExact(value, "N", out _)) throw new InvalidDataException("sessionId 必须为 32 位小写十六进制。");
        return value;
    }

    private static string GuidD(string value)
    {
        if (!Guid.TryParseExact(value, "D", out var guid) || guid == Guid.Empty || value != guid.ToString("D"))
            throw new InvalidDataException("ID 必须为非零小写规范 GUID。");
        return value;
    }

    private static string Sha(string value)
    {
        if (value.Length != 64 || !Sha256Text.IsHex(value, lowercaseOnly: true))
            throw new InvalidDataException("SHA256 必须为 64 位小写十六进制。");
        return value;
    }

    private static void Schema(JsonElement value)
    {
        if (!value.TryGetProperty("schemaVersion", out var schema) || !schema.TryGetInt32(out var number) || number != 1)
            throw new InvalidDataException("schemaVersion 必须为 1。");
    }

    private static string RequiredString(JsonElement value, string name, string label, bool required = true)
    {
        if (!value.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(property.GetString()))
        {
            if (!required) return "";
            throw new InvalidDataException($"{label} 缺少字符串字段 {name}。");
        }
        return property.GetString()!;
    }

    private static void Require(JsonElement value, string name, string expected)
    {
        if (RequiredString(value, name, "json") != expected) throw new InvalidDataException($"字段 {name} 不匹配。");
    }

    /// <summary>
    /// 0.8 reports a proven actual/inactive pair. 0.7 reports
    /// actualSlot=null, inactiveSlot=null, selectedSlot=a|b and
    /// bootContext=legacy-controller. Only that exact legacy shape is accepted;
    /// a half-populated pair is still rejected.
    /// </summary>
    private static SlotInfo ReadSlots(JsonElement value, string label)
    {
        var bootContext = OptionalString(value, "bootContext");
        var actual = OptionalString(value, "actualSlot");
        var inactive = OptionalString(value, "inactiveSlot");
        var selected = OptionalString(value, "selectedSlot");

        if (string.Equals(bootContext, "legacy-controller", StringComparison.Ordinal))
        {
            if (actual is not null || inactive is not null)
                throw new InvalidDataException($"{label} 旧版槽位字段非法。");
            if (selected is not ("a" or "b"))
                throw new InvalidDataException($"{label} 旧版 selectedSlot 非法。");
            return new SlotInfo(null, null, selected, LegacyController: true);
        }

        if (!((actual == "a" && inactive == "b") || (actual == "b" && inactive == "a")))
            throw new InvalidDataException($"{label} 槽位信息非法。");
        return new SlotInfo(actual, inactive, selected, LegacyController: false);
    }

    private static string? OptionalString(JsonElement value, string name)
    {
        if (!value.TryGetProperty(name, out var property))
            return null;
        return property.ValueKind == JsonValueKind.String ? property.GetString() : null;
    }

    private static bool Beneath(string path, string root)
    {
        var relative = Path.GetRelativePath(root, path);
        return relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) &&
            !Path.IsPathRooted(relative);
    }

    private static void EnsureLocalNoReparse(string path)
    {
        var current = Path.GetFullPath(path);
        while (!string.IsNullOrEmpty(current))
        {
            FileSystemInfo info = File.Exists(current) ? new FileInfo(current) : new DirectoryInfo(current);
            info.Refresh();
            if (info.Exists && (info.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException($"路径或祖先包含 reparse point：{current}。");
            current = Path.GetDirectoryName(current);
        }
    }

    private sealed class SynchronousProgress<T> : IProgress<T>
    {
        private readonly Action<T> _report;
        public SynchronousProgress(Action<T> report) => _report = report;
        public void Report(T value) => _report(value);
    }

    private sealed class RpcExportReadStream : Stream
    {
        private readonly OfflineUpdateRpcClient _client;
        private readonly string _sessionId;
        private readonly string _path;
        private long _offset;
        private bool _disposed;

        public RpcExportReadStream(OfflineUpdateRpcClient client, string sessionId, string path)
        { _client = client; _sessionId = sessionId; _path = path; }

        public override bool CanRead => !_disposed;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => _offset; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) =>
            ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (buffer.Length == 0) return 0;
            var count = Math.Min(buffer.Length, ChunkBytes);
            var bytes = await _client.ExportAsync(_sessionId, _path, _offset, count, token).ConfigureAwait(false);
            if (bytes is null || bytes.Length > count) throw new InvalidDataException("范围导出响应长度非法。");
            bytes.CopyTo(buffer);
            _offset = checked(_offset + bytes.Length);
            return bytes.Length;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { _disposed = true; base.Dispose(disposing); }
        public override ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
    }
}
