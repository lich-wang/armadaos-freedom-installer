using System.Text.Json;

namespace FreedomInstaller.Core;

/// <summary>
/// Schema 2 TF-card raw target of <see cref="PackageReader"/>: it runs the exact same strict shared
/// parser as the internal direct route (with the closed TfCard selector for the install targets, the
/// deployment kind and the one optional eighth ordinary role) and additionally requires
/// <c>bootRecipe.rootMedium</c> to be exactly <c>tf</c> and a nonzero, mutually distinct
/// <c>sourceInternalBootUuid</c>/<c>sourceInternalRootUuid</c> pair.
/// <para>
/// Every returned fact is metadata and file-hash validation only. It is NOT a disk, held expanded
/// image, Ready, boot-chain, device or completion proof, and accepting the maintenance-initramfs bytes
/// is not a RAM-initramfs or boot-budget statement. The TF metadata is never rewritten to internal
/// JSON and <c>Raw.Deployment.Kind</c> stays <c>tf-raw-v1</c>.
/// </para>
/// </summary>
public static partial class PackageReader
{
    /// <summary>
    /// Reads and validates a schema 2 TF-card raw package directory with the same directory, manifest,
    /// cancellation, safe-file-read and failure semantics as <see cref="ReadEdlRawContract"/>. A TF
    /// package with the seven shared roles is valid; the optional eighth
    /// <c>tf-maintenance-initramfs</c> ordinary role keeps it valid for PC reader use.
    /// </summary>
    public static TfRawPackageContract ReadTfRawContract(
        string packageDirectory,
        string expectedModel,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(packageDirectory))
        {
            throw new InvalidDataException("安装包目录参数为空。");
        }

        if (string.IsNullOrWhiteSpace(expectedModel))
        {
            throw new InvalidDataException("期望型号参数为空，无法确认安装包归属。");
        }

        var root = Path.GetFullPath(packageDirectory);
        if (!Directory.Exists(root))
        {
            throw new InvalidDataException($"安装包目录不存在：{packageDirectory}。");
        }

        if (IsReparsePoint(root, isDirectory: true))
        {
            throw new InvalidDataException($"安装包目录是符号链接或重解析点，拒绝沿其读取：{packageDirectory}。");
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
                    $"ReadTfRawContract 只接受 schemaVersion {EdlRawSchemaVersion}（TF 卡原始镜像），该清单不是 schema 2。");
            }

            return ParseTfRawContractCore(root, expectedModel, rawMetadata, metadata, cancellationToken);
        }
    }

    /// <summary>
    /// The TF-card core: the shared strict parser under the TfCard selector, plus the TF-only
    /// <c>bootRecipe.rootMedium</c> and source-UUID requirements.
    /// </summary>
    private static TfRawPackageContract ParseTfRawContractCore(
        string root,
        string expectedModel,
        byte[] rawMetadata,
        JsonElement metadata,
        CancellationToken cancellationToken)
    {
        var raw = ParseEdlRawContractCore(
            root,
            expectedModel,
            rawMetadata,
            metadata,
            cancellationToken,
            InstallationTarget.TfCard);

        var recipe = ReadEdlRawRequiredObject(metadata, "bootRecipe", "bootRecipe");

        var rootMedium = ReadEdlRawRequiredString(recipe, "rootMedium", "bootRecipe.rootMedium");
        if (!string.Equals(rootMedium, TfRawRootMediumName, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"bootRecipe.rootMedium 必须为 {TfRawRootMediumName}，实际为 {rootMedium}。");
        }

        var sourceBootUuid = ReadEdlRawRequiredGuidD(
            recipe,
            "sourceInternalBootUuid",
            "bootRecipe.sourceInternalBootUuid");
        var sourceRootUuid = ReadEdlRawRequiredGuidD(
            recipe,
            "sourceInternalRootUuid",
            "bootRecipe.sourceInternalRootUuid");

        if (sourceBootUuid == Guid.Empty || sourceRootUuid == Guid.Empty)
        {
            throw new InvalidDataException(
                "bootRecipe.sourceInternalBootUuid 和 bootRecipe.sourceInternalRootUuid 都不能是零 UUID。");
        }

        if (sourceBootUuid == sourceRootUuid)
        {
            throw new InvalidDataException(
                "bootRecipe.sourceInternalBootUuid 与 bootRecipe.sourceInternalRootUuid 必须是两个不同的 GUID。");
        }

        if (raw.BootRecipe.BootUuid == sourceBootUuid || raw.BootRecipe.BootUuid == sourceRootUuid)
        {
            throw new InvalidDataException(
                "bootRecipe.bootUuid 不能与 TF 来源的内部 boot/root UUID 相同。");
        }

        if (raw.BootRecipe.RootUuid == sourceBootUuid || raw.BootRecipe.RootUuid == sourceRootUuid)
        {
            throw new InvalidDataException(
                "bootRecipe.rootUuid 不能与 TF 来源的内部 boot/root UUID 相同。");
        }

        return new TfRawPackageContract(raw, rootMedium, sourceBootUuid, sourceRootUuid);
    }
}
