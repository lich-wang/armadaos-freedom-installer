using System.Security.Cryptography;
using System.Text.Json;

namespace FreedomInstaller.Core;

public sealed record OfflineUpdateRecoveryContext(
    string TransactionId,
    string DeviceModel,
    string PlanSha256,
    string RecoveryManifestSha256);

public sealed record OfflineUpdateRecoveryProgress(
    string RelativePath,
    long BytesCompleted,
    long TotalBytes);

public sealed record SavedOfflineUpdateRecovery(
    string DirectoryPath,
    string ManifestPath,
    string PlanPath,
    byte[] Acknowledgement);

public static partial class PackageImporter
{
    private const int MaxRecoveryMetadataBytes = 2 * 1024 * 1024;
    private const int MaxRecoveryManifestEntries = 128;
    private const long MaxRecoverySingleFileBytes = 256L * 1024 * 1024;
    private const long MaxRecoveryTotalBytes = MaxRecoveryManifestEntries * MaxRecoverySingleFileBytes;
    private const int RecoveryCopyBufferBytes = 64 * 1024;
    private const string OfflineDualPolicy = "offline-dual";
    private const string RecoveryPlanFileName = "plan.json";
    private const string RecoveryManifestFileName = "recovery-manifest.json";
    private const string RecoveryAckFileName = "recovery-ack.json";

    private static readonly HashSet<string> ReservedRecoveryNames = new(StringComparer.OrdinalIgnoreCase)
    {
        RecoveryPlanFileName,
        RecoveryManifestFileName,
        RecoveryAckFileName
    };

    private static readonly HashSet<string> ReservedDosDeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    private sealed record RecoveryFileSpec(string Path, long Bytes, string Sha256);

    public static async Task<SavedOfflineUpdateRecovery> SaveOfflineUpdateRecoveryAsync(
        string workRoot,
        OfflineUpdateRecoveryContext expected,
        byte[] planBytes,
        byte[] manifestBytes,
        Func<string, CancellationToken, Task<Stream>> openSource,
        IProgress<OfflineUpdateRecoveryProgress>? progress = null,
        CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(planBytes);
        ArgumentNullException.ThrowIfNull(manifestBytes);
        ArgumentNullException.ThrowIfNull(openSource);

        if (string.IsNullOrWhiteSpace(workRoot))
        {
            throw new InvalidDataException("未指定离线升级恢复工作目录。");
        }

        var canonicalWorkRoot = PrepareOfflineWorkRoot(workRoot);
        var normalizedTx = ValidateTransactionId(expected.TransactionId);
        var normalizedModel = ValidateDeviceModel(expected.DeviceModel);
        var expectedPlanSha = ValidateLowerHexSha256(expected.PlanSha256, "PlanSha256");
        var expectedManifestSha = ValidateLowerHexSha256(expected.RecoveryManifestSha256, "RecoveryManifestSha256");

        var planSnapshot = (byte[])planBytes.Clone();
        var manifestSnapshot = (byte[])manifestBytes.Clone();

        VerifyMetadataBlob(planSnapshot, expectedPlanSha, RecoveryPlanFileName);
        VerifyMetadataBlob(manifestSnapshot, expectedManifestSha, RecoveryManifestFileName);

        ValidateRecoveryPlanJson(planSnapshot, normalizedTx, normalizedModel, expectedManifestSha);
        var (files, totalBytes) = ParseAndValidateRecoveryManifestJson(manifestSnapshot, normalizedTx, normalizedModel);

        foreach (var file in files)
        {
            _ = ResolveSafePayloadTargetPath(canonicalWorkRoot, file.Path);
        }

        token.ThrowIfCancellationRequested();
        var recoveryDirectory = CreateOfflineStageDirectory(canonicalWorkRoot);

        try
        {
            var planPath = Path.GetFullPath(Path.Combine(recoveryDirectory, RecoveryPlanFileName));
            var manifestPath = Path.GetFullPath(Path.Combine(recoveryDirectory, RecoveryManifestFileName));
            var ackPath = Path.GetFullPath(Path.Combine(recoveryDirectory, RecoveryAckFileName));

            if (!IsBeneath(planPath, recoveryDirectory) ||
                !IsBeneath(manifestPath, recoveryDirectory) ||
                !IsBeneath(ackPath, recoveryDirectory))
            {
                throw new InvalidDataException("离线升级恢复元数据路径超出受控目录。");
            }

            WriteBoundedStageFile(planPath, planSnapshot, token);
            WriteBoundedStageFile(manifestPath, manifestSnapshot, token);

            var buffer = new byte[RecoveryCopyBufferBytes];
            long completedBytes = 0;

            foreach (var entry in files)
            {
                token.ThrowIfCancellationRequested();

                var targetPath = ResolveSafePayloadTargetPath(recoveryDirectory, entry.Path);
                var parentDir = Path.GetDirectoryName(targetPath);
                if (string.IsNullOrEmpty(parentDir) ||
                    (!string.Equals(parentDir, recoveryDirectory, StringComparison.Ordinal) &&
                     !IsBeneath(parentDir, recoveryDirectory)))
                {
                    throw new InvalidDataException($"恢复备份目标目录越界：{entry.Path}。");
                }

                Directory.CreateDirectory(parentDir);
                EnsureSafeDirectoryTree(parentDir, recoveryDirectory);
                EnsureNoReparseAncestors(canonicalWorkRoot);

                await using (var sourceStream = await openSource(entry.Path, token).ConfigureAwait(false)
                    ?? throw new InvalidDataException($"恢复源文件流为空：{entry.Path}。"))
                {
                    using var fileStream = new FileStream(
                        targetPath,
                        FileMode.CreateNew,
                        FileAccess.Write,
                        FileShare.None,
                        RecoveryCopyBufferBytes,
                        FileOptions.SequentialScan);
                    using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

                    long entryWritten = 0;
                    var readLimit = entry.Bytes + 1;

                    while (entryWritten < readLimit)
                    {
                        token.ThrowIfCancellationRequested();
                        var maxRead = (int)Math.Min(buffer.Length, readLimit - entryWritten);
                        var read = await sourceStream.ReadAsync(buffer.AsMemory(0, maxRead), token).ConfigureAwait(false);
                        if (read <= 0)
                        {
                            break;
                        }

                        if (entryWritten + read > entry.Bytes)
                        {
                            throw new InvalidDataException($"恢复源文件超出声明长度：{entry.Path}。");
                        }

                        fileStream.Write(buffer, 0, read);
                        sha256.AppendData(buffer, 0, read);
                        entryWritten += read;
                        completedBytes = checked(completedBytes + read);
                        progress?.Report(new OfflineUpdateRecoveryProgress(entry.Path, completedBytes, totalBytes));
                    }

                    fileStream.Flush(flushToDisk: true);

                    var streamDigest = Convert.ToHexStringLower(sha256.GetHashAndReset());
                    if (entryWritten != entry.Bytes ||
                        !string.Equals(streamDigest, entry.Sha256, StringComparison.Ordinal))
                    {
                        throw new InvalidDataException($"恢复备份文件写入校验失败：{entry.Path}。");
                    }
                }

                VerifyStoredFileOnDisk(targetPath, recoveryDirectory, entry.Bytes, entry.Sha256, buffer, token);
            }

            VerifyStoredFileOnDisk(planPath, recoveryDirectory, planSnapshot.Length, expectedPlanSha, buffer, token);
            VerifyStoredFileOnDisk(manifestPath, recoveryDirectory, manifestSnapshot.Length, expectedManifestSha, buffer, token);

            var ackBytes = BuildRecoveryAcknowledgementBytes(
                normalizedTx,
                expectedPlanSha,
                expectedManifestSha,
                files);

            WriteBoundedStageFile(ackPath, ackBytes, token);
            var ackDigest = Convert.ToHexStringLower(SHA256.HashData(ackBytes));
            VerifyStoredFileOnDisk(ackPath, recoveryDirectory, ackBytes.Length, ackDigest, buffer, token);

            return new SavedOfflineUpdateRecovery(
                recoveryDirectory,
                manifestPath,
                planPath,
                (byte[])ackBytes.Clone());
        }
        catch
        {
            // Only the attempt created above is discarded. A pre-existing bundle below the same work
            // root is never touched, and the cleanup refuses to descend through links.
            DiscardNewRecoveryAttempt(canonicalWorkRoot, recoveryDirectory);
            throw;
        }
    }

    /// <summary>
    /// Removes the recovery attempt this call just created after a cancellation or failure. The
    /// work root and the directory name are revalidated first, so only a direct, ordinary
    /// <c>offline-update-*</c> child created here can be deleted; a failed cleanup never replaces the
    /// original failure.
    /// </summary>
    private static void DiscardNewRecoveryAttempt(string canonicalWorkRoot, string recoveryDirectory)
    {
        try
        {
            CleanupOfflineUpdateStage(canonicalWorkRoot, recoveryDirectory);
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or ArgumentException
            or InvalidDataException)
        {
        }
    }

    private static void VerifyMetadataBlob(byte[] bytes, string expectedSha256, string label)
    {
        if (bytes.Length == 0 || bytes.Length > MaxRecoveryMetadataBytes)
        {
            throw new InvalidDataException($"恢复元数据长度非法：{label}。");
        }

        var actualSha = Convert.ToHexStringLower(SHA256.HashData(bytes));
        if (!string.Equals(actualSha, expectedSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"恢复元数据 SHA256 不匹配：{label}。");
        }
    }

    private static void ValidateRecoveryPlanJson(
        byte[] planBytes,
        string expectedTx,
        string expectedModel,
        string expectedManifestSha)
    {
        using var doc = ParseStrictJsonObject(planBytes, RecoveryPlanFileName);
        var root = doc.RootElement;

        RequireSchemaAndOperation(root, RecoveryPlanFileName);
        RequireExactStringProperty(root, "transactionId", expectedTx, RecoveryPlanFileName);
        RequireDeviceModelMatch(root, expectedModel, RecoveryPlanFileName);
        RequireExactStringProperty(root, "policy", OfflineDualPolicy, RecoveryPlanFileName);
        RequireExactStringProperty(root, "recoveryManifestSha256", expectedManifestSha, RecoveryPlanFileName);

        if (root.TryGetProperty("planSha256", out _))
        {
            throw new InvalidDataException("plan.json 不允许包含自引用 planSha256 字段。");
        }
    }

    private static (List<RecoveryFileSpec> Files, long TotalBytes) ParseAndValidateRecoveryManifestJson(
        byte[] manifestBytes,
        string expectedTx,
        string expectedModel)
    {
        using var doc = ParseStrictJsonObject(manifestBytes, RecoveryManifestFileName);
        var root = doc.RootElement;

        RequireSchemaAndOperation(root, RecoveryManifestFileName);
        RequireExactStringProperty(root, "transactionId", expectedTx, RecoveryManifestFileName);
        RequireDeviceModelMatch(root, expectedModel, RecoveryManifestFileName);

        if (!root.TryGetProperty("files", out var filesElement) ||
            filesElement.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("recovery-manifest.json 缺少有效的 files 数组。");
        }

        var count = filesElement.GetArrayLength();
        if (count <= 0 || count > MaxRecoveryManifestEntries)
        {
            throw new InvalidDataException($"recovery-manifest.json 条目数量非法：{count}。");
        }

        var results = new List<RecoveryFileSpec>(count);
        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long totalBytes = 0;

        foreach (var item in filesElement.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException("recovery-manifest.json 条目必须为 JSON 对象。");
            }

            var path = RequireNonEmptyString(item, "path", RecoveryManifestFileName);
            ValidatePortableRecoveryRelativePath(path);

            if (!seenPaths.Add(path))
            {
                throw new InvalidDataException($"recovery-manifest.json 包含重复路径：{path}。");
            }

            if (!item.TryGetProperty("bytes", out var bytesProp) ||
                bytesProp.ValueKind != JsonValueKind.Number ||
                !bytesProp.TryGetInt64(out var fileBytes) ||
                fileBytes <= 0 ||
                fileBytes > MaxRecoverySingleFileBytes)
            {
                throw new InvalidDataException($"recovery-manifest.json 文件长度非法：{path}。");
            }

            var sha = ValidateLowerHexSha256(
                RequireNonEmptyString(item, "sha256", RecoveryManifestFileName),
                $"{RecoveryManifestFileName}:{path}:sha256");

            totalBytes = checked(totalBytes + fileBytes);
            if (totalBytes > MaxRecoveryTotalBytes)
            {
                throw new InvalidDataException("recovery-manifest.json 总备份大小超出上限。");
            }

            results.Add(new RecoveryFileSpec(path, fileBytes, sha));
        }

        return (results, totalBytes);
    }

    private static void ValidatePortableRecoveryRelativePath(string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath) ||
            relativePath.Contains('\\') ||
            relativePath.StartsWith('/') ||
            relativePath.EndsWith('/') ||
            relativePath.Contains(':') ||
            ReservedRecoveryNames.Contains(relativePath))
        {
            throw new InvalidDataException($"恢复文件路径非法或为保留名称：{relativePath}。");
        }

        foreach (var ch in relativePath)
        {
            if (char.IsControl(ch))
            {
                throw new InvalidDataException($"恢复文件路径包含控制字符：{relativePath}。");
            }
        }

        var segments = relativePath.Split('/');
        if (segments.Length == 1 && ReservedRecoveryNames.Contains(segments[0]))
        {
            throw new InvalidDataException($"恢复文件路径命中保留文件名：{relativePath}。");
        }

        var invalidChars = Path.GetInvalidFileNameChars();
        foreach (var segment in segments)
        {
            if (segment.Length == 0 ||
                segment is "." or ".." ||
                segment.EndsWith(' ') ||
                segment.EndsWith('.') ||
                segment.IndexOfAny(invalidChars) >= 0 ||
                segment.Any(static ch => ch is '<' or '>' or '|' or '?' or '*' or '"'))
            {
                throw new InvalidDataException($"恢复文件路径段非法：{relativePath}。");
            }

            var stem = segment;
            var dotIndex = segment.IndexOf('.');
            if (dotIndex >= 0)
            {
                stem = segment[..dotIndex];
            }

            if (ReservedDosDeviceNames.Contains(stem))
            {
                throw new InvalidDataException($"恢复文件路径包含保留设备名：{relativePath}。");
            }
        }
    }

    private static void VerifyStoredFileOnDisk(
        string filePath,
        string recoveryDirectory,
        long expectedBytes,
        string expectedSha256,
        byte[] buffer,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        EnsureSafeDirectoryTree(Path.GetDirectoryName(filePath) ?? recoveryDirectory, recoveryDirectory);

        var info = new FileInfo(filePath);
        if (!info.Exists ||
            info.LinkTarget is not null ||
            (info.Attributes & FileAttributes.ReparsePoint) != 0 ||
            (info.Attributes & FileAttributes.Directory) != 0)
        {
            throw new InvalidDataException($"落盘恢复文件状态异常：{filePath}。");
        }

        using var fs = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            RecoveryCopyBufferBytes,
            FileOptions.SequentialScan);
        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        long totalRead = 0;
        while (true)
        {
            token.ThrowIfCancellationRequested();
            var read = fs.Read(buffer, 0, buffer.Length);
            if (read <= 0)
            {
                break;
            }

            totalRead = checked(totalRead + read);
            if (totalRead > expectedBytes)
            {
                throw new InvalidDataException($"落盘恢复文件重读长度超出预期：{filePath}。");
            }

            sha256.AppendData(buffer, 0, read);
        }

        var digest = Convert.ToHexStringLower(sha256.GetHashAndReset());
        if (totalRead != expectedBytes ||
            !string.Equals(digest, expectedSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"落盘恢复文件重读校验失败：{filePath}。");
        }
    }

    private static byte[] BuildRecoveryAcknowledgementBytes(
        string transactionId,
        string planSha256,
        string recoveryManifestSha256,
        IReadOnlyList<RecoveryFileSpec> files)
    {
        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", 1);
            writer.WriteString("operation", OfflineUpgradeOperation);
            writer.WriteString("transactionId", transactionId);
            writer.WriteString("planSha256", planSha256);
            writer.WriteString("recoveryManifestSha256", recoveryManifestSha256);
            writer.WriteStartArray("files");
            foreach (var file in files)
            {
                writer.WriteStartObject();
                writer.WriteString("path", file.Path);
                writer.WriteNumber("bytes", file.Bytes);
                writer.WriteString("sha256", file.Sha256);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return ms.ToArray();
    }

    private static JsonDocument ParseStrictJsonObject(byte[] utf8Bytes, string label)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(utf8Bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow
            });
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"解析恢复 JSON 失败：{label}。", ex);
        }

        try
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException($"{label} 根节点必须为 JSON 对象。");
            }

            EnsureNoDuplicateJsonProperties(doc.RootElement, label);
            return doc;
        }
        catch
        {
            doc.Dispose();
            throw;
        }
    }

    private static void EnsureNoDuplicateJsonProperties(JsonElement element, string label)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
            {
                var seen = new HashSet<string>(StringComparer.Ordinal);
                foreach (var prop in element.EnumerateObject())
                {
                    if (!seen.Add(prop.Name))
                    {
                        throw new InvalidDataException($"{label} 包含重复 JSON 属性：{prop.Name}。");
                    }

                    EnsureNoDuplicateJsonProperties(prop.Value, label);
                }

                break;
            }
            case JsonValueKind.Array:
            {
                foreach (var item in element.EnumerateArray())
                {
                    EnsureNoDuplicateJsonProperties(item, label);
                }

                break;
            }
        }
    }

    private static void RequireSchemaAndOperation(JsonElement root, string label)
    {
        if (!root.TryGetProperty("schemaVersion", out var schemaProp) ||
            schemaProp.ValueKind != JsonValueKind.Number ||
            !schemaProp.TryGetInt32(out var schemaVersion) ||
            schemaVersion != 1)
        {
            throw new InvalidDataException($"{label} schemaVersion 必须为 1。");
        }

        RequireExactStringProperty(root, "operation", OfflineUpgradeOperation, label);
    }

    private static void RequireDeviceModelMatch(JsonElement root, string expectedModel, string label)
    {
        RequireExactStringProperty(root, "model", expectedModel, label);
    }

    private static void RequireExactStringProperty(
        JsonElement element,
        string propertyName,
        string expectedValue,
        string label)
    {
        var actual = RequireNonEmptyString(element, propertyName, label);
        if (!string.Equals(actual, expectedValue, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"{label} 字段 {propertyName} 与预期不匹配。");
        }
    }

    private static string RequireNonEmptyString(JsonElement element, string propertyName, string label)
    {
        if (!element.TryGetProperty(propertyName, out var prop) ||
            prop.ValueKind != JsonValueKind.String)
        {
            throw new InvalidDataException($"{label} 缺少字符串字段：{propertyName}。");
        }

        var value = prop.GetString();
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidDataException($"{label} 字段不能为空：{propertyName}。");
        }

        return value;
    }

    private static string ValidateTransactionId(string transactionId)
    {
        if (string.IsNullOrWhiteSpace(transactionId) ||
            !Guid.TryParseExact(transactionId, "D", out var parsed) ||
            parsed == Guid.Empty)
        {
            throw new InvalidDataException("事务 ID 必须为非零标准 GUID。");
        }

        var canonical = parsed.ToString("D");
        if (!string.Equals(transactionId, canonical, StringComparison.Ordinal))
        {
            throw new InvalidDataException("事务 ID 必须为小写规范 GUID 格式。");
        }

        return canonical;
    }

    private static string ValidateDeviceModel(string deviceModel)
    {
        if (string.IsNullOrWhiteSpace(deviceModel))
        {
            throw new InvalidDataException("未指定目标设备型号。");
        }

        var normalized = deviceModel.Trim();
        // The same single offline-upgrade model list as the descriptor gate and the transfer adapter, in its exact
        // canonical (upper-case) spelling.
        if (!string.Equals(normalized, normalized.ToUpperInvariant(), StringComparison.Ordinal)
            || !UpdatePackageDescriptor.SupportsOfflineUpgrade(normalized))
        {
            throw new InvalidDataException($"不支持的离线恢复设备型号：{normalized}。");
        }

        return normalized;
    }

    private static string ValidateLowerHexSha256(string sha256, string label)
    {
        if (string.IsNullOrWhiteSpace(sha256) || sha256.Length != 64)
        {
            throw new InvalidDataException($"{label} 必须为 64 位小写十六进制 SHA256。");
        }

        if (!Sha256Text.IsHex(sha256, lowercaseOnly: true))
        {
            throw new InvalidDataException($"{label} 包含非小写十六进制字符。");
        }

        return sha256;
    }
}
