using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace FreedomInstaller.Core;

/// <summary>
/// Schema 2 (direct EDL raw) part of <see cref="PackageReader"/>, implementing the approved API-v3
/// metadata declarations of package schema 2.
/// <para>
/// The device model, the EDL profile identifier, the hardware id and the declared Android build are
/// generic package metadata: they are shape and consistency checked, never matched against a pinned
/// device value. Accepting them is not a device-support, loader, Complete or physical-test statement.
/// </para>
/// <para>
/// The Android profile block and the declared firmware list form one optional, coupled declaration group.
/// A standard common package declares neither and carries no Android restriction claim; declaring only
/// one half is rejected, and an explicitly null group is present and still rejected for shape.
/// </para>
/// <para>
/// The reader validates the declared metadata and the actual length and SHA-256 of the seven declared
/// payload files (compressed bytes for the two raw image roles, ordinary bytes for the other five).
/// It never expands a gzip stream, never reads a filesystem superblock, never stages, deletes or holds a
/// file handle, and never claims that a package is Ready, bootable or flashable. Expanded image hashes,
/// filesystem UUID/type/length and final DTB properties stay with the downstream expansion/Prepared
/// implementation.
/// </para>
/// </summary>
public static partial class PackageReader
{
    private const int EdlRawSchemaVersion = 2;

    private const string EdlRawDeploymentKindName = "edl-raw-v1";

    /// <summary>The deployment kind of the TF-card raw package target of the same strict parser.</summary>
    private const string TfRawDeploymentKindName = "tf-raw-v1";

    /// <summary>
    /// The one optional eighth ordinary role of the TF-card target: a maintenance initramfs candidate.
    /// Accepting its bytes here is never evidence of a valid RAM initramfs or an adequate boot budget.
    /// </summary>
    internal const string TfRawMaintenanceInitramfsRole = "tf-maintenance-initramfs";

    /// <summary>The exact bootRecipe.rootMedium value the TF-card target requires.</summary>
    internal const string TfRawRootMediumName = "tf";

    /// <summary>
    /// Wire width of <c>sourceCommit</c>: the 40 lowercase hexadecimal Git revision the package declares.
    /// Only the declared shape is checked here; whether that revision exists, is authentic or matches the
    /// payloads is the producing build's own binding, not this format check.
    /// </summary>
    private const int EdlRawSourceCommitLength = 40;

    /// <summary>Wire width of <c>edlProfile.hardwareId</c>: exactly 16 hexadecimal digits.</summary>
    private const int EdlRawHardwareIdLength = 16;

    private const int EdlRawInstallerProtocol = 2;

    private const int EdlRawBootBuilderProtocol = 1;

    private const long EdlRawLinuxBootBytes = 1_073_741_824L;

    private const long EdlRawRuntimeBytes = 4_194_304L;

    private const int EdlRawSectorSize = 4096;

    private const int EdlRawMaxBootArgsBytes = 4096;

    private const string EdlRawBootImageRole = "linux-boot-raw";

    private const string EdlRawRootImageRole = "linux-root-raw";

    private const string EdlRawDiagnosticSuffix = " rd.break=pre-mount";

    private const string EdlRawDefaultEntry = "android";

    /// <summary>The contract fixes the uppercase <c>UUID=</c> spelling; only the GUID hex itself is case-insensitive.</summary>
    private const string EdlRawRootUuidPrefix = "root=UUID=";

    private const string EdlRawBootUuidPrefix = "boot=UUID=";

    /// <summary>Exactly the seven schema 2 roles, one each. No seed, generic dtb, alias or extra role.</summary>
    private static readonly string[] EdlRawRequiredRoles =
    {
        EdlRawBootImageRole,
        EdlRawRootImageRole,
        "kernel",
        "runtime",
        "initramfs",
        "dtb-normal",
        "dtb-diagnostic",
    };

    /// <summary>Compressed raw image metadata the five ordinary roles must not declare.</summary>
    private static readonly string[] EdlRawImageOnlyFields =
    {
        "compression",
        "expandedBytes",
        "expandedSha256",
        "sectorSize",
        "fsType",
        "fsUuid",
        "minimumPartitionBytes",
    };

    /// <summary>
    /// Reads and validates a schema 2 direct EDL raw package directory.
    /// <para>
    /// Every API-v3 field is enforced: schema 2, the shared package model/compatible metadata checks, the
    /// declared source commit format, the coupled optional profile/firmware declaration group (both present
    /// or both absent, with the declared profile identifier/hardware id/Android build shapes and the exact
    /// firmware membership rule when present), the approved build/tool protocols, the seven exact artifact
    /// roles with confined relative paths, the declared bytes and SHA-256 of the actual files, the two gzip
    /// raw image declarations and the boot recipe bound to the package-fixed filesystem UUIDs.
    /// </para>
    /// <para>
    /// Contract, profile and payload violations throw <see cref="InvalidDataException"/> with the field
    /// name in the message; real IO failures may propagate and a cancelled token stays observable as
    /// <see cref="OperationCanceledException"/>. A schema 1 package is rejected, never reinterpreted as
    /// direct raw. No file is staged, deleted or kept open, and nothing here is a readiness statement.
    /// </para>
    /// </summary>
    public static EdlRawPackageContract ReadEdlRawContract(
        string directory,
        string expectedModel,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(directory))
        {
            throw new InvalidDataException("安装包目录参数为空。");
        }

        if (string.IsNullOrWhiteSpace(expectedModel))
        {
            throw new InvalidDataException("期望型号参数为空，无法确认安装包归属。");
        }

        var root = Path.GetFullPath(directory);
        if (!Directory.Exists(root))
        {
            throw new InvalidDataException($"安装包目录不存在：{directory}。");
        }

        if (IsReparsePoint(root, isDirectory: true))
        {
            throw new InvalidDataException($"安装包目录是符号链接或重解析点，拒绝沿其读取：{directory}。");
        }

        var metadataPath = Path.Combine(root, MetadataFileName);
        if (!File.Exists(metadataPath))
        {
            throw new InvalidDataException($"安装包元数据缺失：{MetadataFileName}。");
        }

        if (IsReparsePoint(metadataPath, isDirectory: false))
        {
            throw new InvalidDataException($"安装包元数据 {MetadataFileName} 是符号链接或重解析点，拒绝读取。");
        }

        var rawMetadata = File.ReadAllBytes(metadataPath);

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(rawMetadata);
        }
        catch (JsonException exception)
        {
            // Only a malformed manifest is converted: IO, cancellation and every other failure stays
            // exactly as it was.
            throw new InvalidDataException(
                $"{MetadataFileName} 不是有效的 JSON 元数据，无法按 schema 2 契约校验。",
                exception);
        }

        using (document)
        {
            var metadata = document.RootElement;

            if (metadata.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException($"{MetadataFileName} 的根节点不是 JSON 对象。");
            }

            if (!TryReadSchemaVersionNumber(metadata, out var schemaVersion)
                || schemaVersion != EdlRawSchemaVersion)
            {
                throw new InvalidDataException(
                    $"ReadEdlRawContract 只接受 schemaVersion {EdlRawSchemaVersion}（直连 EDL 原始镜像），该清单不是 schema 2。");
            }

            return ParseEdlRawContractCore(root, expectedModel, rawMetadata, metadata, cancellationToken);
        }
    }

    /// <summary>
    /// Validates the schema 2 contract on an already parsed manifest. Shared by the public direct reader
    /// and by <see cref="ValidateCore"/> so both entry points enforce exactly the same fields on exactly
    /// one read of the metadata bytes.
    /// </summary>
    private static EdlRawPackageContract ParseEdlRawContractCore(
        string root,
        string expectedModel,
        byte[] rawMetadata,
        JsonElement metadata,
        CancellationToken cancellationToken,
        InstallationTarget target = InstallationTarget.Internal)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var packageId = ReadEdlRawRequiredString(metadata, "packageId", "packageId");
        var version = ReadEdlRawRequiredString(metadata, "version", "version");
        if (string.Equals(version.Trim(), "latest", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException($"{MetadataFileName} 的 version 不能是 latest：必须声明明确的版本号。");
        }

        if (!metadata.TryGetProperty("testOnly", out var testOnlyElement)
            || (testOnlyElement.ValueKind != JsonValueKind.True
                && testOnlyElement.ValueKind != JsonValueKind.False))
        {
            throw new InvalidDataException($"{MetadataFileName} 缺少必需的布尔字段 testOnly。");
        }

        var testOnly = testOnlyElement.GetBoolean();

        // Device support is not decided here: schema 2 reuses exactly the shared package metadata checks
        // (model canonicalisation, expected-model match and the compatible SoC/board map) and never
        // validates a real DTB. The map entries are package platform tags, not device proofs.
        var modelReasons = new List<string>();
        var modelOk = TryReadPackageModel(metadata, expectedModel, modelReasons, out var deviceModel);
        if (modelOk)
        {
            modelOk = CheckCompatible(metadata, deviceModel, modelReasons);
        }

        if (!modelOk)
        {
            throw new InvalidDataException(string.Join(" ", modelReasons));
        }

        // The declared producer revision is a package fact, not a pinned value: only its shape is checked
        // (40 characters, lowercase ASCII hexadecimal, not all zero) and the exact declared string is
        // returned. Nothing is trimmed, case-normalised, defaulted or substituted, and no existence,
        // authenticity or image binding of that Git revision is claimed here.
        var sourceCommit = ReadEdlRawRequiredString(metadata, "sourceCommit", "sourceCommit");
        if (sourceCommit.Length != EdlRawSourceCommitLength
            || sourceCommit.Any(character => (character < '0' || character > '9')
                && (character < 'a' || character > 'f'))
            || sourceCommit.All(character => character == '0'))
        {
            throw new InvalidDataException(
                $"{MetadataFileName} 的 sourceCommit 必须是 {EdlRawSourceCommitLength} 位小写十六进制 Git 修订号"
                + $"（字符只允许 0-9 和 a-f，且不能全为 0），实际为 {sourceCommit}。");
        }

        CheckEdlRawInstallTargets(metadata, target);

        // API-v3: the Android profile block and the declared firmware list are one optional, coupled
        // pair. JSON property presence counts, so an explicit null is present and must still satisfy the
        // required shape; it never turns into an unrestricted package.
        var profilePresent = metadata.TryGetProperty("edlProfile", out var profileElement);
        var boot = ReadEdlRawRequiredObject(metadata, "bootCompatibility", "bootCompatibility");
        var firmwarePresent = boot.TryGetProperty("firmwareVersions", out _);

        if (profilePresent != firmwarePresent)
        {
            throw new InvalidDataException(
                $"{MetadataFileName} 的 edlProfile 与 bootCompatibility.firmwareVersions 必须同时声明或同时省略，只声明其中一项时拒绝。");
        }

        string? profileId = null;
        string? hardwareId = null;
        string? androidBuild = null;

        if (profilePresent)
        {
            if (profileElement.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException($"{MetadataFileName} 的 edlProfile 必须是 JSON 对象。");
            }

            var declaredProfileId = ReadEdlRawRequiredString(profileElement, "id", "edlProfile.id");
            if (!IsEdlRawProfileIdentifier(declaredProfileId))
            {
                throw new InvalidDataException(
                    $"edlProfile.id 必须是 ASCII 标识符（首字符为字母或数字，其余只允许字母、数字、点、下划线和连字符），实际为 {declaredProfileId}。");
            }

            profileId = declaredProfileId;

            var declaredHardwareId = ReadEdlRawRequiredString(
                profileElement,
                "hardwareId",
                "edlProfile.hardwareId");
            if (declaredHardwareId.Length != EdlRawHardwareIdLength || !IsHex(declaredHardwareId))
            {
                throw new InvalidDataException(
                    $"edlProfile.hardwareId 必须是 {EdlRawHardwareIdLength} 位十六进制字符串，实际为 {declaredHardwareId}。");
            }

            // Canonical upper case on return only: no hardware trust, loader identity or fixed value is
            // inferred from it, and the package declaration itself is never rewritten on disk.
            hardwareId = declaredHardwareId.ToUpperInvariant();

            androidBuild = ReadEdlRawRequiredString(profileElement, "androidBuild", "edlProfile.androidBuild");
        }

        // The boot format and partition size stay required for every schema 2 package, with or without
        // the optional Android declarations.
        CheckEdlRawBootFormat(boot);

        var firmwareVersions = firmwarePresent
            ? ReadEdlRawFirmwareVersions(boot, androidBuild!)
            : Array.Empty<string>();

        CheckEdlRawTools(metadata);
        var storage = ReadEdlRawStorage(metadata);
        var payloads = ReadEdlRawPayloads(root, metadata, cancellationToken, target);
        var deployment = ReadEdlRawDeployment(metadata, target);
        var bootRecipe = ReadEdlRawBootRecipe(metadata, payloads, deployment, deviceModel);

        return new EdlRawPackageContract(
            root,
            packageId,
            version,
            deviceModel,
            sourceCommit,
            testOnly,
            Convert.ToHexString(SHA256.HashData(rawMetadata)),
            storage,
            profileId,
            hardwareId,
            androidBuild,
            firmwareVersions,
            payloads.ByRole,
            payloads.BootImage,
            payloads.RootImage,
            deployment,
            bootRecipe);
    }

    /// <summary>
    /// The closed install-target switch of the shared schema-2 parser. Internal keeps the exact
    /// <c>["internal"]</c> check; TfCard accepts exactly one <c>tf</c>; every other target is unknown and
    /// rejected.
    /// </summary>
    private static void CheckEdlRawInstallTargets(JsonElement metadata, InstallationTarget target)
    {
        var expected = target switch
        {
            InstallationTarget.Internal => InternalInstallTargetName,
            InstallationTarget.TfCard => TfCardInstallTargetName,
            _ => throw new InvalidDataException($"未知的安装目标：{target}，拒绝该校验请求。"),
        };

        if (!metadata.TryGetProperty("installTargets", out var element)
            || element.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException($"{MetadataFileName} 的 installTargets 必须是数组。");
        }

        var count = 0;
        foreach (var item in element.EnumerateArray())
        {
            count++;

            if (item.ValueKind != JsonValueKind.String
                || !string.Equals(item.GetString(), expected, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"{MetadataFileName} 的 installTargets 必须精确声明一个 {expected}，不支持混合或其它目标。");
            }
        }

        if (count != 1)
        {
            throw new InvalidDataException(
                $"{MetadataFileName} 的 installTargets 必须精确声明一个 {expected}。");
        }
    }

    /// <summary>
    /// The boot format and partition size are required for every schema 2 package, including a standard
    /// common package that declares no Android profile/firmware group at all.
    /// </summary>
    private static void CheckEdlRawBootFormat(JsonElement boot)
    {
        var format = ReadEdlRawRequiredString(boot, "format", "bootCompatibility.format");
        if (!string.Equals(format, BootFormat, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"bootCompatibility.format 必须为 {BootFormat}，实际为 {format}。");
        }

        var partitionBytes = ReadEdlRawRequiredInt64(
            boot,
            "partitionBytes",
            "bootCompatibility.partitionBytes");
        if (partitionBytes != BootPartitionBytes)
        {
            throw new InvalidDataException(
                $"bootCompatibility.partitionBytes 必须为 {BootPartitionBytes}，实际为 {partitionBytes}。");
        }
    }

    /// <summary>
    /// Reads the declared firmware list of the coupled Android group. Called only when the group is
    /// present, so <paramref name="androidBuild"/> is the declared profile build that the list must
    /// contain by exact ordinal membership.
    /// </summary>
    private static IReadOnlyList<string> ReadEdlRawFirmwareVersions(JsonElement boot, string androidBuild)
    {
        if (!boot.TryGetProperty("firmwareVersions", out var versions)
            || versions.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("bootCompatibility.firmwareVersions 必须是数组。");
        }

        var declared = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var element in versions.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.String)
            {
                throw new InvalidDataException(
                    "bootCompatibility.firmwareVersions 的条目必须是非空的完整字符串。");
            }

            var value = element.GetString() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new InvalidDataException(
                    "bootCompatibility.firmwareVersions 的条目必须是非空的完整字符串。");
            }

            if (!seen.Add(value))
            {
                throw new InvalidDataException(
                    $"bootCompatibility.firmwareVersions 重复声明了固件版本 {value}。");
            }

            declared.Add(value);
        }

        if (declared.Count == 0)
        {
            throw new InvalidDataException("bootCompatibility.firmwareVersions 至少要声明一个固件版本。");
        }

        // Exact ordinal membership, not a substring or prefix match: any number of declared versions is
        // valid, but the complete declared Android build must be one of them. No string is rewritten.
        if (!seen.Contains(androidBuild))
        {
            throw new InvalidDataException(
                $"bootCompatibility.firmwareVersions 必须精确包含 edlProfile.androidBuild {androidBuild}。");
        }

        return declared;
    }

    /// <summary>
    /// The declared EDL profile identifier is a plain ASCII identifier: a letter or digit first, then
    /// letters, digits, dot, underscore or hyphen. The declared spelling is preserved verbatim; no known
    /// value or allowlist is applied here.
    /// </summary>
    private static bool IsEdlRawProfileIdentifier(string value)
    {
        if (value.Length == 0 || !char.IsAsciiLetterOrDigit(value[0]))
        {
            return false;
        }

        for (var index = 1; index < value.Length; index++)
        {
            var character = value[index];
            if (!char.IsAsciiLetterOrDigit(character)
                && character != '.'
                && character != '_'
                && character != '-')
            {
                return false;
            }
        }

        return true;
    }

    private static void CheckEdlRawTools(JsonElement metadata)
    {
        var tools = ReadEdlRawRequiredObject(metadata, "toolsCompatibility", "toolsCompatibility");

        var installer = ReadEdlRawRequiredInt32(
            tools,
            "installerProtocol",
            "toolsCompatibility.installerProtocol");
        if (installer != EdlRawInstallerProtocol)
        {
            throw new InvalidDataException(
                $"不支持的 toolsCompatibility.installerProtocol：{installer}，schema 2 只接受 {EdlRawInstallerProtocol}。");
        }

        var builder = ReadEdlRawRequiredInt32(
            tools,
            "bootBuilderProtocol",
            "toolsCompatibility.bootBuilderProtocol");
        if (builder != EdlRawBootBuilderProtocol)
        {
            throw new InvalidDataException(
                $"不支持的 toolsCompatibility.bootBuilderProtocol：{builder}，schema 2 只接受 {EdlRawBootBuilderProtocol}。");
        }
    }

    private static PackageStorage ReadEdlRawStorage(JsonElement metadata)
    {
        var storageReasons = new List<string>();
        var storage = ReadStorage(metadata, storageReasons);

        if (storage is null)
        {
            throw new InvalidDataException(string.Join(" ", storageReasons));
        }

        if (storage.LinuxBootBytes != EdlRawLinuxBootBytes)
        {
            throw new InvalidDataException(
                $"storage.linuxBootBytes 必须为 {EdlRawLinuxBootBytes}，实际为 {storage.LinuxBootBytes}。");
        }

        return storage;
    }

    /// <summary>
    /// Reads exactly the seven contract roles, resolves each path inside the package, and verifies the
    /// declared length and SHA-256 against the actual file. Nothing is expanded and no handle is kept.
    /// <para>
    /// The closed target selector changes only the allowed role set: Internal keeps exactly the seven
    /// schema-2 roles, while TfCard additionally permits the one optional ordinary role
    /// <c>tf-maintenance-initramfs</c> with all the same duplicate/path/reparse/length/SHA/ordinary-field
    /// checks. Accepting its bytes is not an initramfs-validity or boot-budget statement.
    /// </para>
    /// </summary>
    private static EdlRawPayloads ReadEdlRawPayloads(
        string root,
        JsonElement metadata,
        CancellationToken cancellationToken,
        InstallationTarget target = InstallationTarget.Internal)
    {
        if (!metadata.TryGetProperty("artifacts", out var artifactsElement)
            || artifactsElement.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException($"{MetadataFileName} 的 artifacts 不是数组。");
        }

        var byRole = new Dictionary<string, EdlRawArtifact>(StringComparer.Ordinal);
        var declaredFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var resolvedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        EdlRawImage? bootImage = null;
        EdlRawImage? rootImage = null;
        var index = 0;

        foreach (var element in artifactsElement.EnumerateArray())
        {
            cancellationToken.ThrowIfCancellationRequested();

            var label = $"artifacts[{index}]";
            index++;

            if (element.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException($"{label} 不是 JSON 对象。");
            }

            var role = ReadEdlRawRequiredString(element, "role", $"{label}.role");
            if (!EdlRawRequiredRoles.Contains(role, StringComparer.Ordinal)
                && !(target == InstallationTarget.TfCard
                    && string.Equals(role, TfRawMaintenanceInitramfsRole, StringComparison.Ordinal)))
            {
                throw new InvalidDataException(
                    $"{label} 的 role {role} 不属于 schema 2 直连 EDL 契约的七个角色。");
            }

            if (byRole.ContainsKey(role))
            {
                throw new InvalidDataException($"artifact 角色 {role} 重复声明。");
            }

            var file = ReadEdlRawRequiredString(element, "file", $"{label}.file");
            if (!declaredFiles.Add(file))
            {
                throw new InvalidDataException($"artifact 文件 {file} 被重复声明。");
            }

            var bytes = ReadEdlRawRequiredInt64(element, "bytes", $"{label}.bytes");
            if (bytes <= 0)
            {
                throw new InvalidDataException($"artifact {role} 的 bytes 必须是正整数。");
            }

            var sha256 = ReadEdlRawRequiredString(element, "sha256", $"{label}.sha256");
            if (sha256.Length != Sha256HexLength || !IsHex(sha256))
            {
                throw new InvalidDataException(
                    $"artifact {role} 的 sha256 不是 {Sha256HexLength} 位十六进制字符串。");
            }

            if (!TryResolveArtifactPath(root, file, out var fullPath, out var pathReason))
            {
                throw new InvalidDataException(pathReason);
            }

            if (!resolvedPaths.Add(fullPath))
            {
                throw new InvalidDataException(
                    $"artifact {role} 的 file 解析后与其它 artifact 指向同一个文件：{file}。");
            }

            if (!File.Exists(fullPath))
            {
                throw new InvalidDataException($"artifact {role} 声明的文件缺失：{file}。");
            }

            if (IsReparsePoint(fullPath, isDirectory: false))
            {
                throw new InvalidDataException(
                    $"artifact {role} 的文件是符号链接或重解析点，拒绝读取：{file}。");
            }

            var actualLength = new FileInfo(fullPath).Length;
            if (actualLength != bytes)
            {
                throw new InvalidDataException(
                    $"artifact {role} 的文件长度 {actualLength} 与声明的 {bytes} 不一致：{file}。");
            }

            var declaredHash = Convert.FromHexString(sha256);
            var actualHash = ComputeEdlRawSha256(fullPath, cancellationToken);
            if (!CryptographicOperations.FixedTimeEquals(declaredHash, actualHash))
            {
                throw new InvalidDataException($"artifact {role} 的 SHA256 与声明不一致：{file}。");
            }

            var artifact = new EdlRawArtifact(
                role,
                file,
                fullPath,
                actualLength,
                Convert.ToHexString(actualHash));
            byRole.Add(role, artifact);

            if (string.Equals(role, EdlRawBootImageRole, StringComparison.Ordinal))
            {
                bootImage = ReadEdlRawImage(element, role, artifact, isBoot: true);
            }
            else if (string.Equals(role, EdlRawRootImageRole, StringComparison.Ordinal))
            {
                rootImage = ReadEdlRawImage(element, role, artifact, isBoot: false);
            }
            else
            {
                CheckEdlRawOrdinaryRole(element, role, actualLength);
            }
        }

        cancellationToken.ThrowIfCancellationRequested();

        foreach (var requiredRole in EdlRawRequiredRoles)
        {
            if (!byRole.ContainsKey(requiredRole))
            {
                throw new InvalidDataException($"安装包缺少必需的 artifact 角色：{requiredRole}。");
            }
        }

        if (bootImage is null || rootImage is null)
        {
            throw new InvalidDataException("schema 2 直连 EDL 契约缺少原始镜像声明。");
        }

        if (bootImage.FsUuid == rootImage.FsUuid)
        {
            throw new InvalidDataException(
                $"{EdlRawBootImageRole} 与 {EdlRawRootImageRole} 的 fsUuid 必须是两个不同的非零 GUID。");
        }

        return new EdlRawPayloads(byRole, bootImage, rootImage);
    }

    private static void CheckEdlRawOrdinaryRole(JsonElement element, string role, long actualLength)
    {
        foreach (var field in EdlRawImageOnlyFields)
        {
            if (element.TryGetProperty(field, out _))
            {
                throw new InvalidDataException(
                    $"artifact {role} 不是原始镜像角色，不能声明 {field}。");
            }
        }

        if (string.Equals(role, "runtime", StringComparison.Ordinal) && actualLength != EdlRawRuntimeBytes)
        {
            throw new InvalidDataException(
                $"artifact runtime 的文件长度必须是 {EdlRawRuntimeBytes}，实际为 {actualLength}。");
        }
    }

    private static EdlRawImage ReadEdlRawImage(
        JsonElement element,
        string role,
        EdlRawArtifact artifact,
        bool isBoot)
    {
        var compression = ReadEdlRawRequiredString(element, "compression", $"{role}.compression");
        if (!string.Equals(compression, "gzip", StringComparison.Ordinal))
        {
            throw new InvalidDataException($"artifact {role} 的 compression 必须是 gzip，实际为 {compression}。");
        }

        var expandedBytes = ReadEdlRawRequiredInt64(element, "expandedBytes", $"{role}.expandedBytes");
        if (expandedBytes <= 0)
        {
            throw new InvalidDataException($"artifact {role} 的 expandedBytes 必须是正整数。");
        }

        if (expandedBytes % EdlRawSectorSize != 0)
        {
            throw new InvalidDataException(
                $"artifact {role} 的 expandedBytes 必须是 {EdlRawSectorSize} 的整数倍，实际为 {expandedBytes}。");
        }

        if (isBoot && expandedBytes != EdlRawLinuxBootBytes)
        {
            throw new InvalidDataException(
                $"artifact {role} 的 expandedBytes 必须为 {EdlRawLinuxBootBytes}，实际为 {expandedBytes}。");
        }

        var expandedSha256 = ReadEdlRawRequiredString(
            element,
            "expandedSha256",
            $"{role}.expandedSha256");
        if (expandedSha256.Length != Sha256HexLength || !IsHex(expandedSha256))
        {
            throw new InvalidDataException(
                $"artifact {role} 的 expandedSha256 不是 {Sha256HexLength} 位十六进制字符串。");
        }

        var sectorSize = ReadEdlRawRequiredInt32(element, "sectorSize", $"{role}.sectorSize");
        if (sectorSize != EdlRawSectorSize)
        {
            throw new InvalidDataException(
                $"artifact {role} 的 sectorSize 必须为 {EdlRawSectorSize}，实际为 {sectorSize}。");
        }

        var expectedFsType = isBoot ? "ext4" : "btrfs";
        var fsType = ReadEdlRawRequiredString(element, "fsType", $"{role}.fsType");
        if (!string.Equals(fsType, expectedFsType, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"artifact {role} 的 fsType 必须为 {expectedFsType}，实际为 {fsType}。");
        }

        var fsUuid = ReadEdlRawRequiredGuidD(element, "fsUuid", $"{role}.fsUuid");
        if (fsUuid == Guid.Empty)
        {
            throw new InvalidDataException($"artifact {role} 的 fsUuid 不能是零 UUID。");
        }

        var minimumPartitionBytes = ReadEdlRawRequiredInt64(
            element,
            "minimumPartitionBytes",
            $"{role}.minimumPartitionBytes");
        if (minimumPartitionBytes % EdlRawSectorSize != 0)
        {
            throw new InvalidDataException(
                $"artifact {role} 的 minimumPartitionBytes 必须是 {EdlRawSectorSize} 的整数倍，实际为 {minimumPartitionBytes}。");
        }

        if (isBoot && minimumPartitionBytes != EdlRawLinuxBootBytes)
        {
            throw new InvalidDataException(
                $"artifact {role} 的 minimumPartitionBytes 必须为 {EdlRawLinuxBootBytes}，实际为 {minimumPartitionBytes}。");
        }

        if (!isBoot && minimumPartitionBytes < expandedBytes)
        {
            throw new InvalidDataException(
                $"artifact {role} 的 minimumPartitionBytes {minimumPartitionBytes} 不能小于 expandedBytes {expandedBytes}。");
        }

        return new EdlRawImage(
            artifact,
            compression,
            artifact.Bytes,
            artifact.Sha256,
            expandedBytes,
            expandedSha256.ToUpperInvariant(),
            sectorSize,
            fsType,
            fsUuid,
            minimumPartitionBytes);
    }

    /// <summary>
    /// Reads the deployment block with all commit/origin/manifestDigest/bootChecksum checks unchanged; only
    /// the expected kind follows the closed target switch: Internal expects <c>edl-raw-v1</c> and TfCard
    /// expects <c>tf-raw-v1</c>. The declared kind is never rewritten.
    /// </summary>
    private static EdlRawDeployment ReadEdlRawDeployment(
        JsonElement metadata,
        InstallationTarget target = InstallationTarget.Internal)
    {
        var expectedKind = target switch
        {
            InstallationTarget.Internal => EdlRawDeploymentKindName,
            InstallationTarget.TfCard => TfRawDeploymentKindName,
            _ => throw new InvalidDataException($"未知的安装目标：{target}，拒绝该校验请求。"),
        };

        var deployment = ReadEdlRawRequiredObject(metadata, "deployment", "deployment");

        var kind = ReadEdlRawRequiredString(deployment, "kind", "deployment.kind");
        if (!string.Equals(kind, expectedKind, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"deployment.kind 必须为 {expectedKind}，实际为 {kind}。");
        }

        var commit = ReadEdlRawRequiredString(deployment, "commit", "deployment.commit");
        if (!IsLowerSha256Hex(commit))
        {
            throw new InvalidDataException(
                $"deployment.commit 必须是 {Sha256HexLength} 位小写十六进制。");
        }

        var manifestDigest = ReadEdlRawRequiredString(
            deployment,
            "manifestDigest",
            "deployment.manifestDigest");
        if (!manifestDigest.StartsWith(ManifestDigestPrefix, StringComparison.Ordinal)
            || !IsLowerSha256Hex(manifestDigest[ManifestDigestPrefix.Length..]))
        {
            throw new InvalidDataException(
                $"deployment.manifestDigest 必须形如 {ManifestDigestPrefix}{Sha256HexLength} 位小写十六进制。");
        }

        var origin = ReadEdlRawRequiredString(deployment, "origin", "deployment.origin");
        if (!IsProjectOrigin(origin))
        {
            throw new InvalidDataException(
                $"deployment.origin 必须指向项目更新源 {OriginPrefix}(stable|beta|testing)。");
        }

        // Separate producer fact: never derived from, and never required to equal, the commit.
        var bootChecksum = ReadEdlRawRequiredString(
            deployment,
            "bootChecksum",
            "deployment.bootChecksum");
        if (!IsLowerSha256Hex(bootChecksum))
        {
            throw new InvalidDataException(
                $"deployment.bootChecksum 必须是 {Sha256HexLength} 位小写十六进制。");
        }

        return new EdlRawDeployment(kind, commit, manifestDigest, origin, bootChecksum);
    }

    private static EdlRawBootRecipe ReadEdlRawBootRecipe(
        JsonElement metadata,
        EdlRawPayloads payloads,
        EdlRawDeployment deployment,
        string deviceModel)
    {
        var recipe = ReadEdlRawRequiredObject(metadata, "bootRecipe", "bootRecipe");

        var bootUuid = ReadEdlRawRequiredGuidD(recipe, "bootUuid", "bootRecipe.bootUuid");
        var rootUuid = ReadEdlRawRequiredGuidD(recipe, "rootUuid", "bootRecipe.rootUuid");

        if (bootUuid == Guid.Empty || rootUuid == Guid.Empty)
        {
            throw new InvalidDataException("bootRecipe.bootUuid 和 bootRecipe.rootUuid 都不能是零 UUID。");
        }

        if (bootUuid == rootUuid)
        {
            throw new InvalidDataException("bootRecipe.bootUuid 与 bootRecipe.rootUuid 必须是两个不同的 GUID。");
        }

        if (bootUuid != payloads.BootImage.FsUuid)
        {
            throw new InvalidDataException($"bootRecipe.bootUuid 必须等于 {EdlRawBootImageRole} 的 fsUuid。");
        }

        if (rootUuid != payloads.RootImage.FsUuid)
        {
            throw new InvalidDataException($"bootRecipe.rootUuid 必须等于 {EdlRawRootImageRole} 的 fsUuid。");
        }

        var normal = ReadEdlRawRequiredString(recipe, "normalBootArgs", "bootRecipe.normalBootArgs");
        var diagnostic = ReadEdlRawRequiredString(
            recipe,
            "diagnosticBootArgs",
            "bootRecipe.diagnosticBootArgs");
        var defaultEntry = ReadEdlRawRequiredString(recipe, "defaultEntry", "bootRecipe.defaultEntry");

        if (!string.Equals(defaultEntry, EdlRawDefaultEntry, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"bootRecipe.defaultEntry 必须为 {EdlRawDefaultEntry}，实际为 {defaultEntry}。");
        }

        CheckEdlRawBootArgs(normal, diagnostic, bootUuid, rootUuid, deployment.BootChecksum, deviceModel);

        return new EdlRawBootRecipe(bootUuid, rootUuid, normal, diagnostic, defaultEntry);
    }

    /// <summary>
    /// Verifies the two complete boot argument strings without trimming or rewriting them: single line,
    /// no NUL, at most 4096 UTF-8 bytes each, exactly one <c>root=</c>, <c>boot=</c> and <c>ostree=</c>
    /// parameter, the two UUIDs and the ostree deployment path bound to the declared boot checksum, and
    /// the diagnostic string being either exactly the normal string plus the approved suffix or, for the
    /// canonical <c>TB323FU</c> model only, exactly the G5 verbose boot argument form of the normal string.
    /// </summary>
    private static void CheckEdlRawBootArgs(
        string normal,
        string diagnostic,
        Guid bootUuid,
        Guid rootUuid,
        string bootChecksum,
        string deviceModel)
    {
        CheckEdlRawBootArgsString(normal, "bootRecipe.normalBootArgs");
        CheckEdlRawBootArgsString(diagnostic, "bootRecipe.diagnosticBootArgs");

        var legacyDiagnostic = string.Equals(
            diagnostic,
            normal + EdlRawDiagnosticSuffix,
            StringComparison.Ordinal);
        var isG5 = string.Equals(deviceModel, "TB323FU", StringComparison.Ordinal);
        var g5VerboseDiagnostic = isG5
            && string.Equals(diagnostic, BuildEdlRawG5VerboseBootArgs(normal), StringComparison.Ordinal);

        if (!legacyDiagnostic && !g5VerboseDiagnostic)
        {
            if (isG5)
            {
                throw new InvalidDataException(
                    $"bootRecipe.diagnosticBootArgs 必须精确等于 normalBootArgs 加上后缀{EdlRawDiagnosticSuffix}，"
                    + "或等于 normalBootArgs 的精确 G5 verbose 形式。");
            }

            throw new InvalidDataException(
                $"bootRecipe.diagnosticBootArgs 必须精确等于 normalBootArgs 加上后缀{EdlRawDiagnosticSuffix}。");
        }

        var expectedRoot = EdlRawRootUuidPrefix + rootUuid.ToString("D");
        var expectedBoot = EdlRawBootUuidPrefix + bootUuid.ToString("D");
        var ostree0 = $"ostree=/ostree/boot.0/default/{bootChecksum}/0";
        var ostree1 = $"ostree=/ostree/boot.1/default/{bootChecksum}/0";

        var rootCount = 0;
        var bootCount = 0;
        var ostreeCount = 0;

        foreach (var token in normal.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (token.StartsWith("root=", StringComparison.Ordinal))
            {
                rootCount++;

                // Exact Ordinal prefix: root=uuid=... must not be accepted just because the GUID hex
                // compares case-insensitively.
                if (!token.StartsWith(EdlRawRootUuidPrefix, StringComparison.Ordinal)
                    || !string.Equals(
                        token[EdlRawRootUuidPrefix.Length..],
                        rootUuid.ToString("D"),
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException(
                        $"bootRecipe.normalBootArgs 的 root= 参数必须精确为 {expectedRoot}。");
                }
            }
            else if (token.StartsWith("boot=", StringComparison.Ordinal))
            {
                bootCount++;

                if (!token.StartsWith(EdlRawBootUuidPrefix, StringComparison.Ordinal)
                    || !string.Equals(
                        token[EdlRawBootUuidPrefix.Length..],
                        bootUuid.ToString("D"),
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException(
                        $"bootRecipe.normalBootArgs 的 boot= 参数必须精确为 {expectedBoot}。");
                }
            }
            else if (token.StartsWith("ostree=", StringComparison.Ordinal))
            {
                ostreeCount++;
                if (!string.Equals(token, ostree0, StringComparison.Ordinal)
                    && !string.Equals(token, ostree1, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        $"bootRecipe.normalBootArgs 的 ostree= 参数必须形如 {ostree0}（或 boot.1）。");
                }
            }
        }

        if (rootCount != 1)
        {
            throw new InvalidDataException("bootRecipe.normalBootArgs 必须包含且只包含一个 root= 参数。");
        }

        if (bootCount != 1)
        {
            throw new InvalidDataException("bootRecipe.normalBootArgs 必须包含且只包含一个 boot= 参数。");
        }

        if (ostreeCount != 1)
        {
            throw new InvalidDataException("bootRecipe.normalBootArgs 必须包含且只包含一个 ostree= 参数。");
        }
    }

    private static void CheckEdlRawBootArgsString(string value, string label)
    {
        if (value.Length == 0)
        {
            throw new InvalidDataException($"{label} 为空。");
        }

        foreach (var character in value)
        {
            if (character == '\r' || character == '\n' || character == '\0')
            {
                throw new InvalidDataException($"{label} 不能包含 CR、LF 或 NUL 字符。");
            }
        }

        if (Encoding.UTF8.GetByteCount(value) > EdlRawMaxBootArgsBytes)
        {
            throw new InvalidDataException($"{label} 的 UTF-8 长度不能超过 {EdlRawMaxBootArgsBytes} 字节。");
        }
    }

    private static readonly string[] EdlRawG5VerboseBootArgsExtras =
    {
        "loglevel=8",
        "ignore_loglevel",
        "printk.time=1",
        "initcall_debug",
        "rd.debug",
    };

    /// <summary>
    /// Mirrors the G5 diagnostic boot argument producer exactly: splits on whitespace, drops <c>quiet</c>,
    /// <c>loglevel=*</c> and <c>rd.break</c>/<c>rd.break=*</c>, keeps every remaining token in order with
    /// duplicates, then appends the five verbose extras in order when the exact token is still absent.
    /// </summary>
    private static string BuildEdlRawG5VerboseBootArgs(string normal)
    {
        var tokens = new List<string>();

        foreach (var token in normal.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
        {
            if (string.Equals(token, "quiet", StringComparison.Ordinal)
                || token.StartsWith("loglevel=", StringComparison.Ordinal)
                || string.Equals(token, "rd.break", StringComparison.Ordinal)
                || token.StartsWith("rd.break=", StringComparison.Ordinal))
            {
                continue;
            }

            tokens.Add(token);
        }

        foreach (var extra in EdlRawG5VerboseBootArgsExtras)
        {
            if (!tokens.Contains(extra))
            {
                tokens.Add(extra);
            }
        }

        return string.Join(" ", tokens);
    }

    /// <summary>
    /// Hashes a payload with a bounded buffer and cancellation checks, so a multi-gigabyte compressed
    /// image is never loaded into memory and a cancelled read stops promptly.
    /// </summary>
    private static byte[] ComputeEdlRawSha256(string path, CancellationToken cancellationToken)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 1024 * 1024,
            options: FileOptions.SequentialScan);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        var buffer = new byte[1024 * 1024];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            hash.AppendData(buffer, 0, read);
        }

        cancellationToken.ThrowIfCancellationRequested();
        return hash.GetHashAndReset();
    }

    private static bool TryReadSchemaVersionNumber(JsonElement metadata, out int schemaVersion)
    {
        schemaVersion = 0;

        return metadata.TryGetProperty("schemaVersion", out var element)
            && element.ValueKind == JsonValueKind.Number
            && element.TryGetInt32(out schemaVersion);
    }

    private static string ReadEdlRawRequiredString(JsonElement element, string property, string label)
    {
        if (!element.TryGetProperty(property, out var value)
            || value.ValueKind != JsonValueKind.String)
        {
            throw new InvalidDataException($"{MetadataFileName} 缺少字符串字段 {label}。");
        }

        var text = value.GetString();
        if (string.IsNullOrWhiteSpace(text))
        {
            // Rejected as blank, but never rewritten: the original string is what callers receive.
            throw new InvalidDataException($"{MetadataFileName} 的 {label} 为空或只有空白字符。");
        }

        return text;
    }

    private static JsonElement ReadEdlRawRequiredObject(JsonElement element, string property, string label)
    {
        if (!element.TryGetProperty(property, out var value)
            || value.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException($"{MetadataFileName} 缺少对象 {label}。");
        }

        return value;
    }

    private static long ReadEdlRawRequiredInt64(JsonElement element, string property, string label)
    {
        if (!element.TryGetProperty(property, out var value)
            || value.ValueKind != JsonValueKind.Number
            || !value.TryGetInt64(out var number))
        {
            throw new InvalidDataException($"{label} 缺失或不是整数。");
        }

        return number;
    }

    private static int ReadEdlRawRequiredInt32(JsonElement element, string property, string label)
    {
        if (!element.TryGetProperty(property, out var value)
            || value.ValueKind != JsonValueKind.Number
            || !value.TryGetInt32(out var number))
        {
            throw new InvalidDataException($"{label} 缺失或不是整数。");
        }

        return number;
    }

    private static Guid ReadEdlRawRequiredGuidD(JsonElement element, string property, string label)
    {
        var text = ReadEdlRawRequiredString(element, property, label);
        if (!Guid.TryParseExact(text, "D", out var guid))
        {
            throw new InvalidDataException($"{label} 必须是 GUID-D 格式（8-4-4-4-12），实际为 {text}。");
        }

        return guid;
    }

    /// <summary>The declared and observed payload set of a validated schema 2 package.</summary>
    private sealed record EdlRawPayloads(
        IReadOnlyDictionary<string, EdlRawArtifact> ByRole,
        EdlRawImage BootImage,
        EdlRawImage RootImage);
}
