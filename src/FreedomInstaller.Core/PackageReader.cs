using System.Security.Cryptography;
using System.Text.Json;

namespace FreedomInstaller.Core;

/// <summary>
/// Validates an installation package directory against package contract v1. Read only: files are
/// opened for reading and hashed, nothing is created, renamed, deleted or written to a device.
/// </summary>
public static partial class PackageReader
{
    private const string MetadataFileName = "package.json";

    private const int SupportedSchemaVersion = 1;

    private const int Sha256HexLength = 64;

    /// <summary>Artefact roles the contract v1 requires. The seed content itself is produced elsewhere.</summary>
    private static readonly string[] RequiredRoles = { "ostree-seed", "kernel", "dtb", "runtime" };

    private const string DeploymentKind = "ostree-offline-seed";

    private const string ManifestDigestPrefix = "sha256:";

    /// <summary>The only accepted update origin. Any other registry or repository path is rejected.</summary>
    private const string OriginPrefix = "ostree-image-signed:docker://ghcr.io/mydanyi/armadaos-freedom:";

    private static readonly string[] OriginChannels = { "stable", "beta", "testing" };

    private const string BootFormat = "android-boot-v4";

    private const long BootPartitionBytes = 100_663_296L;

    private const int SupportedInstallerProtocol = 1;

    private const int SupportedMaintenanceProtocol = 1;

    /// <summary>Wire spelling of the <c>installTargets</c> entries, exactly as the manifest must name them.</summary>
    private const string InternalInstallTargetName = "internal";

    private const string TfCardInstallTargetName = "tf";

    /// <summary>
    /// The only accepted <c>deviceModel</c> values and the SoC / board codename each one implies.
    /// A legacy <c>model</c> field is never consulted, not even as a fallback.
    /// </summary>
    private static readonly Dictionary<string, (string Soc, string Device)> SupportedDeviceModels =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["TB322FC"] = ("SM8750", "elden"),
            ["TB323FU"] = ("SM8850", "baldur"),
        };

    /// <summary>
    /// Validates <paramref name="directory"/> against <paramref name="expectedModel"/> using package
    /// contract v1.
    /// <para>
    /// Required metadata: <c>schemaVersion</c> = 1, non-empty <c>packageId</c>, non-empty <c>version</c>
    /// (never "latest"), <c>deviceModel</c> (TB322FC or TB323FU, never the legacy <c>model</c> field),
    /// a boolean <c>testOnly</c>, <c>compatible</c> (soc + board codename matching the device model),
    /// the <c>artifacts</c> list (role / file / bytes / sha256) covering ostree-seed, kernel, dtb and
    /// runtime, <c>deployment</c> (ostree-offline-seed kind, lowercase 64-hex commit, sha256-prefixed
    /// manifest digest and an origin inside the project image repository), the four <c>storage</c>
    /// numbers, <c>bootCompatibility</c> (android-boot-v4, exact partition size, at least one firmware
    /// version) and <c>toolsCompatibility</c> (installer and maintenance protocol 1). Anything unknown
    /// in that list is rejected instead of being ignored.
    /// </para>
    /// <para>
    /// Artefact paths must be relative paths inside the package directory: rooted paths, drive letters,
    /// UNC prefixes, ".." segments and reparse-point (symlink / junction) components are rejected, on
    /// Linux as well as on Windows, so a package cannot point at files outside its own directory.
    /// </para>
    /// <para>
    /// A valid result only means the package is structurally complete. It says nothing about trust,
    /// deployability or whether the target device can boot the declared firmware, and the declared
    /// boot profile still has to be verified against the real device by the write adapter.
    /// <see cref="PackageValidationResult.Storage"/> and the declared metadata are returned only for a
    /// fully valid package.
    /// </para>
    /// </summary>
    public static PackageValidationResult Validate(string directory, string expectedModel)
        => Validate(directory, expectedModel, InstallationTarget.Internal);

    /// <summary>
    /// Validates <paramref name="directory"/> against <paramref name="expectedModel"/> for a specific
    /// <paramref name="target"/> using package contract v1.
    /// <para>
    /// The file, size and SHA-256 checks are exactly the ones of the two-argument overload; the only
    /// additional requirement is that the declared <c>installTargets</c> list contains the requested
    /// target (a package without that list is an internal-only legacy package). Declaring a target is
    /// not a trust statement: the result still reports the package's own <c>testOnly</c> flag.
    /// </para>
    /// </summary>
    public static PackageValidationResult Validate(string directory, string expectedModel, InstallationTarget target)
    {
        var reasons = new List<string>();

        try
        {
            var contract = ValidateCore(directory, expectedModel, target, reasons);

            if (reasons.Count == 0 && contract is not null)
            {
                return new PackageValidationResult(true, Array.Empty<string>(), contract.Storage)
                {
                    TestOnly = contract.TestOnly,
                    PackageId = contract.PackageId,
                    Version = contract.Version,
                    ManifestFingerprint = contract.ManifestFingerprint,
                    DeploymentKind = contract.DeploymentKind,
                };
            }

            if (reasons.Count == 0)
            {
                reasons.Add("安装包校验未完成：没有得到完整的契约声明。");
            }

            return new PackageValidationResult(false, reasons, null);
        }
        catch (Exception exception) when (IsExpectedFailure(exception))
        {
            reasons.Add($"读取安装包时发生错误：{exception.Message}");
            return new PackageValidationResult(false, reasons, null);
        }
    }

    private static PackageContract? ValidateCore(
        string directory,
        string expectedModel,
        InstallationTarget target,
        List<string> reasons)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            reasons.Add("安装包目录参数为空。");
            return null;
        }

        if (string.IsNullOrWhiteSpace(expectedModel))
        {
            reasons.Add("期望型号参数为空，无法确认安装包归属。");
            return null;
        }

        var root = Path.GetFullPath(directory);
        if (!Directory.Exists(root))
        {
            reasons.Add($"安装包目录不存在：{directory}。");
            return null;
        }

        if (IsReparsePoint(root, isDirectory: true))
        {
            reasons.Add($"安装包目录是符号链接或重解析点，拒绝沿其读取：{directory}。");
            return null;
        }

        var metadataPath = Path.Combine(root, MetadataFileName);
        if (!File.Exists(metadataPath))
        {
            reasons.Add($"安装包元数据缺失：{MetadataFileName}。");
            return null;
        }

        if (IsReparsePoint(metadataPath, isDirectory: false))
        {
            reasons.Add($"安装包元数据 {MetadataFileName} 是符号链接或重解析点，拒绝读取。");
            return null;
        }

        var rawMetadata = File.ReadAllBytes(metadataPath);
        using var document = JsonDocument.Parse(rawMetadata);
        var metadata = document.RootElement;

        if (metadata.ValueKind != JsonValueKind.Object)
        {
            reasons.Add($"{MetadataFileName} 的根节点不是 JSON 对象。");
            return null;
        }

        // Schema 2 (direct EDL raw) is a different contract. Dispatch on this same parsed manifest,
        // before the v1 version check, so there is no second read and no TOCTOU window.
        if (TryReadSchemaVersionNumber(metadata, out var declaredSchemaVersion)
            && declaredSchemaVersion == EdlRawSchemaVersion)
        {
            return ValidateEdlRawCore(root, expectedModel, target, rawMetadata, metadata, reasons);
        }

        if (!TryReadSchemaVersion(metadata, reasons))
        {
            return null;
        }

        if (!TryReadPackageIdentity(metadata, reasons, out var packageId, out var version))
        {
            return null;
        }

        if (!TryReadTestOnly(metadata, reasons, out var testOnly))
        {
            return null;
        }

        if (!TryReadPackageModel(metadata, expectedModel, reasons, out var deviceModel))
        {
            return null;
        }

        if (!CheckCompatible(metadata, deviceModel, reasons))
        {
            return null;
        }

        var artifacts = ReadArtifacts(metadata, reasons);
        if (artifacts.Count == 0 || reasons.Count > 0)
        {
            return null;
        }

        foreach (var artifact in artifacts)
        {
            VerifyArtifact(root, artifact, reasons);
        }

        if (reasons.Count > 0)
        {
            return null;
        }

        if (!CheckDeployment(metadata, reasons))
        {
            return null;
        }

        var storage = ReadStorage(metadata, reasons);
        if (storage is null)
        {
            return null;
        }

        if (!CheckBootCompatibility(metadata, reasons))
        {
            return null;
        }

        if (!CheckToolsCompatibility(metadata, reasons))
        {
            return null;
        }

        // Checked inside the same parsed manifest, so no second read and no window between the checks.
        if (!CheckInstallTargets(metadata, target, reasons))
        {
            return null;
        }

        return new PackageContract(
            packageId,
            version,
            testOnly,
            storage,
            Convert.ToHexString(SHA256.HashData(rawMetadata)));
    }

    /// <summary>
    /// Validates a schema 2 raw package on the already parsed manifest. Shared by the public direct
    /// readers and by <see cref="ValidateCore"/> so all entry points enforce exactly the same fields on
    /// exactly one read of the metadata bytes: Internal dispatches the internal-only core and TfCard
    /// dispatches the TF core, both on this same parsed manifest.
    /// </summary>
    private static PackageContract? ValidateEdlRawCore(
        string root,
        string expectedModel,
        InstallationTarget target,
        byte[] rawMetadata,
        JsonElement metadata,
        List<string> reasons)
    {
        switch (target)
        {
            case InstallationTarget.Internal:
                break;
            case InstallationTarget.TfCard:
                try
                {
                    var tfContract = ParseTfRawContractCore(
                        root,
                        expectedModel,
                        rawMetadata,
                        metadata,
                        CancellationToken.None);

                    return new PackageContract(
                        tfContract.PackageId,
                        tfContract.Version,
                        tfContract.Raw.TestOnly,
                        tfContract.Storage,
                        tfContract.ManifestFingerprint,
                        tfContract.Deployment.Kind);
                }
                catch (InvalidDataException exception)
                {
                    reasons.Add(exception.Message);
                    return null;
                }

            default:
                reasons.Add($"未知的安装目标：{target}，拒绝该校验请求。");
                return null;
        }

        try
        {
            var contract = ParseEdlRawContractCore(
                root,
                expectedModel,
                rawMetadata,
                metadata,
                CancellationToken.None);

            return new PackageContract(
                contract.PackageId,
                contract.Version,
                contract.TestOnly,
                contract.Storage,
                contract.ManifestFingerprint,
                contract.Deployment.Kind);
        }
        catch (InvalidDataException exception)
        {
            reasons.Add(exception.Message);
            return null;
        }
    }

    private static bool TryReadSchemaVersion(JsonElement metadata, List<string> reasons)
    {
        if (!metadata.TryGetProperty("schemaVersion", out var schemaElement)
            || schemaElement.ValueKind != JsonValueKind.Number
            || !schemaElement.TryGetInt32(out var schemaVersion))
        {
            reasons.Add($"{MetadataFileName} 缺少可解析的 schemaVersion。");
            return false;
        }

        if (schemaVersion != SupportedSchemaVersion)
        {
            reasons.Add($"不支持的 schemaVersion：{schemaVersion}，当前只接受 {SupportedSchemaVersion}。");
            return false;
        }

        return true;
    }

    private static bool TryReadPackageIdentity(
        JsonElement metadata,
        List<string> reasons,
        out string packageId,
        out string version)
    {
        packageId = string.Empty;
        version = string.Empty;

        var ok = true;

        if (!TryReadString(metadata, "packageId", out packageId))
        {
            reasons.Add($"{MetadataFileName} 缺少非空的 packageId。");
            ok = false;
        }

        if (!TryReadString(metadata, "version", out version))
        {
            reasons.Add($"{MetadataFileName} 缺少非空的 version。");
            return false;
        }

        if (string.Equals(version, "latest", StringComparison.OrdinalIgnoreCase))
        {
            reasons.Add($"{MetadataFileName} 的 version 不能是 latest：安装包必须声明明确的版本号。");
            ok = false;
        }

        return ok;
    }

    private static bool TryReadTestOnly(JsonElement metadata, List<string> reasons, out bool testOnly)
    {
        // Fail-safe: unless the manifest says otherwise, the package counts as a test package.
        testOnly = true;

        if (!metadata.TryGetProperty("testOnly", out var element)
            || (element.ValueKind != JsonValueKind.True && element.ValueKind != JsonValueKind.False))
        {
            reasons.Add($"{MetadataFileName} 缺少必需的布尔字段 testOnly。");
            return false;
        }

        testOnly = element.GetBoolean();
        return true;
    }

    private static bool TryReadPackageModel(
        JsonElement metadata,
        string expectedModel,
        List<string> reasons,
        out string canonicalModel)
    {
        canonicalModel = string.Empty;

        if (!metadata.TryGetProperty("deviceModel", out var modelElement)
            || modelElement.ValueKind != JsonValueKind.String)
        {
            if (metadata.TryGetProperty("model", out _))
            {
                reasons.Add($"{MetadataFileName} 只声明了 legacy model 字段，契约 v1 要求 deviceModel，legacy 字段不能作为缺省放行。");
            }
            else
            {
                reasons.Add($"{MetadataFileName} 缺少 deviceModel 字段。");
            }

            return false;
        }

        var declared = modelElement.GetString()?.Trim() ?? string.Empty;
        if (declared.Length == 0)
        {
            reasons.Add($"{MetadataFileName} 的 deviceModel 为空。");
            return false;
        }

        if (!TryCanonicalizeDeviceModel(declared, out canonicalModel))
        {
            reasons.Add($"安装包声明的 deviceModel {declared} 不在支持列表（TB322FC / TB323FU）内，拒绝使用。");
            return false;
        }

        if (!TryCanonicalizeDeviceModel(expectedModel.Trim(), out var expectedCanonical))
        {
            reasons.Add($"期望型号 {expectedModel.Trim()} 不在支持列表（TB322FC / TB323FU）内，拒绝使用。");
            return false;
        }

        if (!string.Equals(canonicalModel, expectedCanonical, StringComparison.Ordinal))
        {
            reasons.Add($"安装包的 deviceModel {canonicalModel} 与期望型号 {expectedCanonical} 不一致，拒绝使用。");
            return false;
        }

        return true;
    }

    private static bool CheckCompatible(JsonElement metadata, string canonicalModel, List<string> reasons)
    {
        if (!metadata.TryGetProperty("compatible", out var compatible)
            || compatible.ValueKind != JsonValueKind.Object)
        {
            reasons.Add($"{MetadataFileName} 缺少 compatible 对象。");
            return false;
        }

        var expected = SupportedDeviceModels[canonicalModel];
        var ok = true;

        if (!TryReadString(compatible, "soc", out var soc))
        {
            reasons.Add("compatible.soc 缺失或为空。");
            ok = false;
        }
        else if (!string.Equals(soc, expected.Soc, StringComparison.Ordinal))
        {
            reasons.Add($"compatible.soc 必须为 {expected.Soc}（deviceModel {canonicalModel} 的要求），实际为 {soc}。");
            ok = false;
        }

        if (!TryReadString(compatible, "device", out var device))
        {
            reasons.Add("compatible.device 缺失或为空。");
            ok = false;
        }
        else if (!string.Equals(device, expected.Device, StringComparison.Ordinal))
        {
            reasons.Add($"compatible.device 必须为 {expected.Device}（deviceModel {canonicalModel} 的要求），实际为 {device}。");
            ok = false;
        }

        return ok;
    }

    private static List<ArtifactEntry> ReadArtifacts(JsonElement metadata, List<string> reasons)
    {
        var artifacts = new List<ArtifactEntry>();

        if (!metadata.TryGetProperty("artifacts", out var artifactsElement)
            || artifactsElement.ValueKind != JsonValueKind.Array)
        {
            reasons.Add($"{MetadataFileName} 的 artifacts 不是数组。");
            return artifacts;
        }

        var roles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var index = 0;

        foreach (var element in artifactsElement.EnumerateArray())
        {
            var label = $"artifacts[{index}]";
            index++;

            if (element.ValueKind != JsonValueKind.Object)
            {
                reasons.Add($"{label} 不是 JSON 对象。");
                continue;
            }

            if (!TryReadString(element, "role", out var role))
            {
                reasons.Add($"{label} 缺少 role。");
                continue;
            }

            if (!TryReadString(element, "file", out var file))
            {
                reasons.Add($"{label} 缺少 file。");
                continue;
            }

            if (!element.TryGetProperty("bytes", out var bytesElement)
                || bytesElement.ValueKind != JsonValueKind.Number
                || !bytesElement.TryGetInt64(out var bytes))
            {
                reasons.Add($"{label} 的 bytes 缺失或不是整数。");
                continue;
            }

            if (bytes < 0)
            {
                reasons.Add($"{label} 的 bytes 是负数。");
                continue;
            }

            if (!TryReadString(element, "sha256", out var sha256))
            {
                reasons.Add($"{label} 缺少 sha256。");
                continue;
            }

            if (sha256.Length != Sha256HexLength || !IsHex(sha256))
            {
                reasons.Add($"{label} 的 sha256 不是 {Sha256HexLength} 位十六进制字符串。");
                continue;
            }

            if (!roles.Add(role))
            {
                reasons.Add($"artifact 角色 {role} 重复声明。");
                continue;
            }

            if (!files.Add(file))
            {
                reasons.Add($"artifact 文件 {file} 被重复声明。");
                continue;
            }

            artifacts.Add(new ArtifactEntry(role, file, bytes, sha256));
        }

        if (artifacts.Count == 0 && reasons.Count == 0)
        {
            reasons.Add($"{MetadataFileName} 没有声明任何 artifact。");
        }

        foreach (var requiredRole in RequiredRoles)
        {
            if (!roles.Contains(requiredRole))
            {
                reasons.Add($"安装包缺少必需的 artifact 角色：{requiredRole}。");
            }
        }

        return artifacts;
    }

    private static void VerifyArtifact(string root, ArtifactEntry artifact, List<string> reasons)
    {
        if (!TryResolveArtifactPath(root, artifact.FileName, out var path, out var pathReason))
        {
            reasons.Add(pathReason);
            return;
        }

        if (!File.Exists(path))
        {
            reasons.Add($"artifact {artifact.Role} 声明的文件缺失：{artifact.FileName}。");
            return;
        }

        if (IsReparsePoint(path, isDirectory: false))
        {
            reasons.Add($"artifact {artifact.Role} 的文件是符号链接或重解析点，拒绝读取：{artifact.FileName}。");
            return;
        }

        var length = new FileInfo(path).Length;
        if (length != artifact.Bytes)
        {
            reasons.Add($"artifact {artifact.Role} 的文件长度 {length} 与声明的 {artifact.Bytes} 不一致：{artifact.FileName}。");
            return;
        }

        var declared = Convert.FromHexString(artifact.Sha256);
        var actual = ComputeSha256(path);
        if (!CryptographicOperations.FixedTimeEquals(declared, actual))
        {
            reasons.Add($"artifact {artifact.Role} 的 SHA256 与声明不一致：{artifact.FileName}。");
        }
    }

    /// <summary>
    /// Resolves an artefact path inside <paramref name="root"/>. Rejects every form that could leave the
    /// package directory, including Windows style paths while running on Linux.
    /// </summary>
    private static bool TryResolveArtifactPath(string root, string relativePath, out string fullPath, out string reason)
    {
        fullPath = string.Empty;
        reason = string.Empty;

        var candidate = relativePath.Trim();
        if (candidate.Length == 0)
        {
            reason = "artifact 的 file 为空。";
            return false;
        }

        if (candidate.Contains('\0'))
        {
            reason = $"artifact 路径包含空字符：{relativePath}。";
            return false;
        }

        if (candidate[0] == '/' || candidate[0] == '\\' || Path.IsPathRooted(candidate))
        {
            reason = $"artifact 路径必须是安装包目录内的相对路径：{relativePath}。";
            return false;
        }

        if (candidate.Contains(':'))
        {
            reason = $"artifact 路径不能包含盘符、备用数据流或协议前缀：{relativePath}。";
            return false;
        }

        // Split on both separators so a Windows style path is also inspected when running on Linux.
        var segments = candidate.Split(new[] { '/', '\\' }, StringSplitOptions.None);
        foreach (var segment in segments)
        {
            if (segment.Length == 0)
            {
                reason = $"artifact 路径包含空路径段：{relativePath}。";
                return false;
            }

            if (segment == "." || segment == "..")
            {
                reason = $"artifact 路径不能包含相对跳转段（. 或 ..）：{relativePath}。";
                return false;
            }
        }

        var current = root;
        for (var index = 0; index < segments.Length - 1; index++)
        {
            current = Path.Combine(current, segments[index]);
            if (Directory.Exists(current) && IsReparsePoint(current, isDirectory: true))
            {
                reason = $"artifact 路径经过符号链接或重解析点目录，拒绝读取：{relativePath}。";
                return false;
            }
        }

        var resolved = Path.GetFullPath(Path.Combine(current, segments[^1]));
        var relative = Path.GetRelativePath(root, resolved);
        if (relative.Length == 0 || Path.IsPathRooted(relative) || StartsWithParentSegment(relative))
        {
            reason = $"artifact 路径越出安装包目录，拒绝读取：{relativePath}。";
            return false;
        }

        fullPath = resolved;
        return true;
    }

    private static bool StartsWithParentSegment(string relative) =>
        relative == ".."
        || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal)
        || relative.StartsWith("../", StringComparison.Ordinal)
        || relative.StartsWith("..\\", StringComparison.Ordinal);

    private static bool CheckDeployment(JsonElement metadata, List<string> reasons)
    {
        if (!metadata.TryGetProperty("deployment", out var deployment)
            || deployment.ValueKind != JsonValueKind.Object)
        {
            reasons.Add($"{MetadataFileName} 缺少 deployment 对象。");
            return false;
        }

        var ok = true;

        if (!TryReadString(deployment, "kind", out var kind))
        {
            reasons.Add("deployment.kind 缺失或为空。");
            ok = false;
        }
        else if (!string.Equals(kind, DeploymentKind, StringComparison.Ordinal))
        {
            reasons.Add($"deployment.kind 必须为 {DeploymentKind}，实际为 {kind}。");
            ok = false;
        }

        if (!TryReadString(deployment, "commit", out var commit))
        {
            reasons.Add("deployment.commit 缺失或为空。");
            ok = false;
        }
        else if (!IsLowerSha256Hex(commit))
        {
            reasons.Add($"deployment.commit 必须是 {Sha256HexLength} 位小写十六进制 ostree commit。");
            ok = false;
        }

        if (!TryReadString(deployment, "manifestDigest", out var manifestDigest))
        {
            reasons.Add("deployment.manifestDigest 缺失或为空。");
            ok = false;
        }
        else if (!manifestDigest.StartsWith(ManifestDigestPrefix, StringComparison.Ordinal)
            || !IsLowerSha256Hex(manifestDigest[ManifestDigestPrefix.Length..]))
        {
            reasons.Add($"deployment.manifestDigest 必须形如 {ManifestDigestPrefix}{Sha256HexLength} 位小写十六进制。");
            ok = false;
        }

        if (!TryReadString(deployment, "origin", out var origin))
        {
            reasons.Add("deployment.origin 缺失或为空。");
            ok = false;
        }
        else if (!IsProjectOrigin(origin))
        {
            reasons.Add($"deployment.origin 必须指向项目更新源 {OriginPrefix}(stable|beta|testing)，可追加 @{ManifestDigestPrefix}<digest>，实际为 {origin}。");
            ok = false;
        }

        return ok;
    }

    /// <summary>
    /// Accepts only the project image repository with a known channel, optionally pinned to a manifest
    /// digest. Any other registry, repository path or channel is rejected.
    /// </summary>
    private static bool IsProjectOrigin(string origin)
    {
        if (!origin.StartsWith(OriginPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        var tail = origin[OriginPrefix.Length..];
        var separator = tail.IndexOf('@');
        var channel = separator < 0 ? tail : tail[..separator];

        if (!OriginChannels.Contains(channel, StringComparer.Ordinal))
        {
            return false;
        }

        if (separator < 0)
        {
            return true;
        }

        var pinned = tail[(separator + 1)..];
        return pinned.StartsWith(ManifestDigestPrefix, StringComparison.Ordinal)
            && IsLowerSha256Hex(pinned[ManifestDigestPrefix.Length..]);
    }

    private static bool CheckBootCompatibility(JsonElement metadata, List<string> reasons)
    {
        if (!metadata.TryGetProperty("bootCompatibility", out var boot)
            || boot.ValueKind != JsonValueKind.Object)
        {
            reasons.Add($"{MetadataFileName} 缺少 bootCompatibility 对象。");
            return false;
        }

        var ok = true;

        if (!TryReadString(boot, "format", out var format))
        {
            reasons.Add("bootCompatibility.format 缺失或为空。");
            ok = false;
        }
        else if (!string.Equals(format, BootFormat, StringComparison.Ordinal))
        {
            reasons.Add($"bootCompatibility.format 必须为 {BootFormat}，实际为 {format}。");
            ok = false;
        }

        if (!boot.TryGetProperty("partitionBytes", out var bytesElement)
            || bytesElement.ValueKind != JsonValueKind.Number
            || !bytesElement.TryGetInt64(out var partitionBytes))
        {
            reasons.Add("bootCompatibility.partitionBytes 缺失或不是整数。");
            ok = false;
        }
        else if (partitionBytes != BootPartitionBytes)
        {
            reasons.Add($"bootCompatibility.partitionBytes 必须为 {BootPartitionBytes}，实际为 {partitionBytes}。");
            ok = false;
        }

        if (!boot.TryGetProperty("firmwareVersions", out var versions)
            || versions.ValueKind != JsonValueKind.Array)
        {
            reasons.Add("bootCompatibility.firmwareVersions 缺失或不是数组。");
            return false;
        }

        var count = 0;
        foreach (var element in versions.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.String
                || string.IsNullOrWhiteSpace(element.GetString()))
            {
                reasons.Add($"bootCompatibility.firmwareVersions[{count}] 不是非空字符串。");
                ok = false;
            }

            count++;
        }

        if (count == 0)
        {
            reasons.Add("bootCompatibility.firmwareVersions 至少要声明一个固件版本。");
            ok = false;
        }

        return ok;
    }

    private static bool CheckToolsCompatibility(JsonElement metadata, List<string> reasons)
    {
        if (!metadata.TryGetProperty("toolsCompatibility", out var tools)
            || tools.ValueKind != JsonValueKind.Object)
        {
            reasons.Add($"{MetadataFileName} 缺少 toolsCompatibility 对象。");
            return false;
        }

        var installerOk = TryReadProtocol(
            tools,
            "installerProtocol",
            SupportedInstallerProtocol,
            reasons);

        var maintenanceOk = TryReadProtocol(
            tools,
            "maintenanceProtocol",
            SupportedMaintenanceProtocol,
            reasons);

        return installerOk && maintenanceOk;
    }

    private static bool TryReadProtocol(JsonElement tools, string name, int supported, List<string> reasons)
    {
        if (!tools.TryGetProperty(name, out var element)
            || element.ValueKind != JsonValueKind.Number
            || !element.TryGetInt32(out var value))
        {
            reasons.Add($"toolsCompatibility.{name} 缺失或不是整数。");
            return false;
        }

        if (value != supported)
        {
            reasons.Add($"不支持的 toolsCompatibility.{name}：{value}，当前只接受 {supported}。");
            return false;
        }

        return true;
    }

    /// <summary>
    /// Verifies the optional <c>installTargets</c> list. An absent list keeps every legacy package
    /// internal-only; a present list must be a non-empty array of unique, exactly spelled
    /// <c>internal</c> / <c>tf</c> strings and must contain the requested target. Declaring a target is not
    /// a trust statement and never changes the package's own <c>testOnly</c> flag.
    /// </summary>
    private static bool CheckInstallTargets(JsonElement metadata, InstallationTarget target, List<string> reasons)
    {
        string requested;
        switch (target)
        {
            case InstallationTarget.Internal:
                requested = InternalInstallTargetName;
                break;
            case InstallationTarget.TfCard:
                requested = TfCardInstallTargetName;
                break;
            default:
                reasons.Add($"未知的安装目标：{target}，拒绝该校验请求。");
                return false;
        }

        if (!metadata.TryGetProperty("installTargets", out var element))
        {
            // Legacy packages predate the target list: internal only, never a silent TF approval.
            if (!string.Equals(requested, InternalInstallTargetName, StringComparison.Ordinal))
            {
                reasons.Add($"{MetadataFileName} 没有声明 installTargets，旧版安装包只允许安装到设备内置存储。");
                return false;
            }

            return true;
        }

        if (element.ValueKind != JsonValueKind.Array)
        {
            reasons.Add($"{MetadataFileName} 的 installTargets 必须是数组。");
            return false;
        }

        var declared = new HashSet<string>(StringComparer.Ordinal);
        var index = 0;

        foreach (var item in element.EnumerateArray())
        {
            var label = $"installTargets[{index}]";
            index++;

            if (item.ValueKind != JsonValueKind.String)
            {
                reasons.Add($"{label} 不是字符串，installTargets 只接受 {InternalInstallTargetName} / {TfCardInstallTargetName}。");
                return false;
            }

            var value = item.GetString();
            if (value is null
                || (!string.Equals(value, InternalInstallTargetName, StringComparison.Ordinal)
                    && !string.Equals(value, TfCardInstallTargetName, StringComparison.Ordinal)))
            {
                reasons.Add($"{label} 的值 {value} 不是受支持的安装目标（只接受 {InternalInstallTargetName} / {TfCardInstallTargetName}）。");
                return false;
            }

            if (!declared.Add(value))
            {
                reasons.Add($"installTargets 重复声明了安装目标 {value}。");
                return false;
            }
        }

        if (declared.Count == 0)
        {
            reasons.Add($"{MetadataFileName} 的 installTargets 是空数组，至少要声明一个安装目标。");
            return false;
        }

        if (!declared.Contains(requested))
        {
            reasons.Add($"安装包没有声明安装目标 {requested}，拒绝安装到该目标。");
            return false;
        }

        return true;
    }

    private static PackageStorage? ReadStorage(JsonElement metadata, List<string> reasons)
    {
        if (!metadata.TryGetProperty("storage", out var storageElement)
            || storageElement.ValueKind != JsonValueKind.Object)
        {
            reasons.Add($"{MetadataFileName} 缺少 storage 对象。");
            return null;
        }

        var bootOk = TryReadStorageValue(storageElement, "linuxBootBytes", false, reasons, out var linuxBootBytes);
        var systemOk = TryReadStorageValue(storageElement, "systemRequiredBytes", false, reasons, out var systemRequiredBytes);
        var scratchOk = TryReadStorageValue(storageElement, "deploymentScratchBytes", true, reasons, out var deploymentScratchBytes);
        var dataOk = TryReadStorageValue(storageElement, "minimumLinuxDataBytes", false, reasons, out var minimumLinuxDataBytes);

        if (!bootOk || !systemOk || !scratchOk || !dataOk)
        {
            return null;
        }

        try
        {
            _ = checked(linuxBootBytes + systemRequiredBytes + deploymentScratchBytes + minimumLinuxDataBytes);
        }
        catch (OverflowException)
        {
            reasons.Add("storage 各项之和溢出 64 位范围，拒绝该声明。");
            return null;
        }

        return new PackageStorage(linuxBootBytes, systemRequiredBytes, deploymentScratchBytes, minimumLinuxDataBytes);
    }

    private static bool TryReadStorageValue(
        JsonElement storage,
        string name,
        bool allowZero,
        List<string> reasons,
        out long value)
    {
        value = 0;

        if (!storage.TryGetProperty(name, out var element)
            || element.ValueKind != JsonValueKind.Number
            || !element.TryGetInt64(out value))
        {
            reasons.Add($"storage.{name} 缺失或不是整数。");
            return false;
        }

        var invalid = allowZero ? value < 0 : value <= 0;
        if (invalid)
        {
            reasons.Add($"storage.{name} 必须为{(allowZero ? "非负" : "正")}整数。");
            return false;
        }

        return true;
    }

    private static bool TryReadString(JsonElement element, string name, out string value)
    {
        value = string.Empty;

        if (!element.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = property.GetString()?.Trim() ?? string.Empty;
        return value.Length > 0;
    }

    private static bool TryCanonicalizeDeviceModel(string value, out string canonical)
    {
        foreach (var model in SupportedDeviceModels.Keys)
        {
            if (string.Equals(value, model, StringComparison.OrdinalIgnoreCase))
            {
                canonical = model;
                return true;
            }
        }

        canonical = string.Empty;
        return false;
    }

    private static bool IsHex(string value)
    {
        foreach (var character in value)
        {
            if (!char.IsAsciiHexDigit(character))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Exactly 64 characters of lowercase hexadecimal, as used for ostree commits and digests.</summary>
    private static bool IsLowerSha256Hex(string value)
    {
        if (value.Length != Sha256HexLength)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!(char.IsAsciiDigit(character) || (character >= 'a' && character <= 'f')))
            {
                return false;
            }
        }

        return true;
    }

    private static byte[] ComputeSha256(string path)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 1024 * 1024,
            options: FileOptions.SequentialScan);
        return SHA256.HashData(stream);
    }

    private static bool IsReparsePoint(string path, bool isDirectory)
    {
        FileSystemInfo info = isDirectory ? new DirectoryInfo(path) : new FileInfo(path);
        if (!info.Exists)
        {
            return false;
        }

        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            return true;
        }

        return info.LinkTarget is not null;
    }

    /// <summary>
    /// IO, JSON and data-shape failures become reasons. Severe failures (for example out of memory)
    /// are deliberately not caught and propagate to the caller.
    /// </summary>
    private static bool IsExpectedFailure(Exception exception) =>
        exception is IOException
            or UnauthorizedAccessException
            or System.Security.SecurityException
            or JsonException
            or NotSupportedException
            or ArgumentException
            or InvalidOperationException;

    private sealed record ArtifactEntry(string Role, string FileName, long Bytes, string Sha256);

    /// <summary>Everything the manifest declared, kept together so values are only surfaced on success.</summary>
    /// <remarks>
    /// <c>DeploymentKind</c> is route metadata only: <c>edl-raw-v1</c> for a validated schema 2 direct raw
    /// package, <c>null</c> for the schema 1 offline seed path. It is not a Ready, held or device proof.
    /// </remarks>
    private sealed record PackageContract(
        string PackageId,
        string Version,
        bool TestOnly,
        PackageStorage Storage,
        string ManifestFingerprint,
        string? DeploymentKind = null);
}
