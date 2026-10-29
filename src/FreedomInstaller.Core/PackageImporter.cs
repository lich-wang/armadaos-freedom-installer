using System.IO.Compression;
using System.Security;
using System.Text.Json;

namespace FreedomInstaller.Core;

/// <summary>
/// A package selected from a bundle and staged for one installation, together with the validation
/// result that was produced for the selected package.
/// <para>
/// An instance that was staged from a bundle owns exactly one private extraction directory and removes
/// only that directory when it is disposed. A legacy package directory is never owned or deleted.
/// </para>
/// </summary>
public sealed class ImportedPackage : IDisposable
{
    internal ImportedPackage(
        string sourcePath,
        string packageDirectory,
        string deviceModel,
        PackageValidationResult validation,
        string? ownedDirectory,
        string? ownerRoot)
    {
        SourcePath = sourcePath;
        PackageDirectory = packageDirectory;
        DeviceModel = deviceModel;
        Validation = validation;
        _ownedDirectory = ownedDirectory;
        _ownerRoot = ownerRoot;
    }

    /// <summary>
    /// Path the caller passed in: the bundle archive, the split volume that was selected or a legacy
    /// package directory.
    /// </summary>
    public string SourcePath { get; }

    /// <summary>
    /// Directory that holds the validated package for this installation. For a bundle this is the
    /// private extraction directory below the caller's work root; for a legacy directory it is the
    /// original directory.
    /// </summary>
    public string PackageDirectory { get; }

    /// <summary>Canonical device model the selected package was validated against.</summary>
    public string DeviceModel { get; }

    /// <summary>Validation result of the selected package, including its manifest fingerprint.</summary>
    public PackageValidationResult Validation { get; }

    /// <summary>Private directory this instance owns, or null when it does not own one.</summary>
    internal string? OwnedDirectory => _ownedDirectory;

    private readonly string? _ownedDirectory;

    private readonly string? _ownerRoot;

    private int _disposed;

    /// <summary>
    /// Removes the private extraction directory exactly once. The directory is verified to still be
    /// beneath the work root it was created in before anything is deleted; a cleanup failure is
    /// reported as an exception instead of being treated as success.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        var owned = _ownedDirectory;
        var root = _ownerRoot;
        if (owned is null)
        {
            return;
        }

        if (root is null || !PackageImporter.IsBeneath(owned, root))
        {
            throw new IOException($"拒绝删除不受本实例拥有的目录：{owned}");
        }

        if (Directory.Exists(owned))
        {
            Directory.Delete(owned, recursive: true);
        }
    }
}

/// <summary>
/// Selects one model package out of a bundle (or accepts a legacy package directory) and returns it
/// as an <see cref="ImportedPackage"/>.
/// <para>
/// A bundle is a ZIP / ZIP64 archive (the fast path, read with <see cref="ZipArchive"/>) or a 7z,
/// RAR, TAR, tar.gz / tgz, tar.xz / txz, tar.zst / tzst or tar.bz2 / tbz2 archive. The container is
/// identified from its content, never from the file name, and every format ends up in the same
/// validation and cleanup path. A split bundle (raw numeric volumes such as <c>.zip.001</c> or native
/// RAR volumes such as <c>.part1.rar</c>) is resolved to its complete volume group first.
/// </para>
/// <para>
/// Every operational or format problem, including a malformed bundle, a missing or unsupported model
/// and a rejected package contract, is reported through
/// <see cref="ImportedPackage.Validation"/> with <see cref="PackageValidationResult.IsValid"/> false
/// rather than as an exception. Cancellation is the only exception that is preserved.
/// </para>
/// </summary>
public static partial class PackageImporter
{
    private const string BundleFileName = "bundle.json";

    private const string BundleIdentifier = "armadaos-freedom";

    private const string ManifestFileName = "package.json";

    private const int SupportedBundleSchemaVersion = 1;

    private const int SharedBundleSchemaVersion = 2;

    private const int MaxBundleIndexBytes = 4 * 1024 * 1024;

    private const int CopyBufferSize = 80 * 1024;

    private static readonly string[] SupportedModels = { "TB322FC", "TB323FU" };

    /// <summary>
    /// Imports <paramref name="sourcePath"/> for <paramref name="expectedModel"/> and
    /// <paramref name="target"/>, staging any private output below <paramref name="workRoot"/>.
    /// </summary>
    public static Task<ImportedPackage> ImportAsync(
        string sourcePath,
        string expectedModel,
        InstallationTarget target,
        string workRoot,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(sourcePath);
        ArgumentNullException.ThrowIfNull(expectedModel);
        ArgumentNullException.ThrowIfNull(workRoot);

        return Task.Run(() => Import(sourcePath, expectedModel, target, workRoot, token), token);
    }

    /// <summary>True when <paramref name="path"/> resolves strictly below <paramref name="root"/>.</summary>
    internal static bool IsBeneath(string path, string root)
    {
        var fullPath = Path.GetFullPath(path);
        var fullRoot = Path.GetFullPath(root);
        var relative = Path.GetRelativePath(fullRoot, fullPath);

        if (relative.Length == 0 || relative == ".")
        {
            return false;
        }

        if (Path.IsPathRooted(relative))
        {
            return false;
        }

        return relative != ".."
            && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal)
            && !relative.StartsWith("../", StringComparison.Ordinal)
            && !relative.StartsWith("..\\", StringComparison.Ordinal);
    }

    /// <summary>
    /// True when the logical archive stream starts with a ZIP local file header, an empty archive or a
    /// spanned marker (<c>PK\x03\x04</c>, <c>PK\x05\x06</c>, <c>PK\x07\x08</c>). The header decides the
    /// route, so a renamed archive is never handed to the wrong reader and the ZIP fast path stays the
    /// default. The position is restored so the same stream can be handed to the ZIP reader.
    /// </summary>
    private static bool HasZipHeader(Stream stream)
    {
        var position = stream.Position;

        Span<byte> header = stackalloc byte[4];
        int read;

        try
        {
            read = stream.Read(header);
        }
        finally
        {
            stream.Position = position;
        }

        if (read < header.Length)
        {
            return false;
        }

        if (header[0] != (byte)'P' || header[1] != (byte)'K')
        {
            return false;
        }

        return (header[2] == 0x03 && header[3] == 0x04)
            || (header[2] == 0x05 && header[3] == 0x06)
            || (header[2] == 0x07 && header[3] == 0x08);
    }

    private static ImportedPackage Import(
        string sourcePath,
        string expectedModel,
        InstallationTarget target,
        string workRoot,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        var reasons = new List<string>();

        if (!IsSupportedModel(expectedModel))
        {
            reasons.Add($"期望型号 {expectedModel} 不在支持列表（TB322FC / TB323FU）内，拒绝使用。");
            return Invalid(sourcePath, expectedModel, reasons);
        }

        string? stage = null;
        string? root = null;

        try
        {
            if (string.IsNullOrWhiteSpace(workRoot))
            {
                reasons.Add("工作目录为空，无法确定解包位置。");
                return Invalid(sourcePath, expectedModel, reasons);
            }

            root = Path.GetFullPath(workRoot);
            if (!Directory.Exists(root))
            {
                reasons.Add($"工作目录不存在：{workRoot}。");
                return Invalid(sourcePath, expectedModel, reasons);
            }

            var fullSource = Path.GetFullPath(sourcePath);
            if (Directory.Exists(fullSource))
            {
                var legacy = PackageReader.Validate(fullSource, expectedModel, target);
                token.ThrowIfCancellationRequested();
                return new ImportedPackage(sourcePath, fullSource, expectedModel, legacy, null, null);
            }

            var source = ResolveArchiveSource(fullSource);
            token.ThrowIfCancellationRequested();

            if (source.IsNativeRar)
            {
                // A genuine RAR volume set has its own per-volume headers, so it is read by the
                // multi-volume RAR reader in PackageImporter.Archives.cs, never by concatenation.
                return ImportArchive(source, sourcePath, expectedModel, target, root, token);
            }

            using var stream = source.OpenStream();

            if (!HasZipHeader(stream))
            {
                // Everything that is not a ZIP container goes through the general archive reader in
                // PackageImporter.Archives.cs; the ZIP path below is untouched.
                return ImportArchive(source, sourcePath, expectedModel, target, root, token);
            }

            using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);

            var items = new List<ArchiveItem>();
            if (!TryIndexArchive(archive, items, reasons))
            {
                return Invalid(sourcePath, expectedModel, reasons);
            }

            var bundleItem = items.FirstOrDefault(
                item => !item.IsDirectory
                    && string.Equals(item.Name, BundleFileName, StringComparison.OrdinalIgnoreCase));

            if (bundleItem is null)
            {
                reasons.Add($"合集缺少 {BundleFileName}。");
                return Invalid(sourcePath, expectedModel, reasons);
            }

            var rawBundle = ReadLimited(bundleItem.Entry, MaxBundleIndexBytes, token);

            if (!TryReadBundle(
                rawBundle,
                expectedModel,
                reasons,
                out var bundleVersion,
                out var selectedDirectory,
                out var sharedMappings))
            {
                return Invalid(sourcePath, expectedModel, reasons);
            }

            token.ThrowIfCancellationRequested();

            var nodes = items
                .Select(item => new ArchiveNode(item.Name, item.IsDirectory))
                .ToList();

            if (!TryBuildExtractionPlan(nodes, selectedDirectory, sharedMappings, reasons, out var plan))
            {
                return Invalid(sourcePath, expectedModel, reasons);
            }

            var stagePath = Path.Combine(root, Guid.NewGuid().ToString("N"));
            var stageDirectory = Directory.CreateDirectory(stagePath).FullName;
            stage = stageDirectory;

            var entriesByName = new Dictionary<string, ZipArchiveEntry>(StringComparer.Ordinal);
            foreach (var item in items)
            {
                entriesByName[item.Name] = item.Entry;
            }

            foreach (var planned in plan)
            {
                token.ThrowIfCancellationRequested();

                var extractionPath = Path.GetFullPath(Path.Combine(stageDirectory, planned.Destination));
                if (!IsBeneath(extractionPath, stageDirectory))
                {
                    throw new InvalidDataException($"条目路径越出解包目录，拒绝写入：{planned.SourceName}。");
                }

                if (planned.IsDirectory)
                {
                    Directory.CreateDirectory(extractionPath);
                    continue;
                }

                if (!entriesByName.TryGetValue(planned.SourceName, out var entry))
                {
                    throw new InvalidDataException($"合集缺少条目：{planned.SourceName}。");
                }

                var parent = Path.GetDirectoryName(extractionPath);
                if (parent is not null)
                {
                    Directory.CreateDirectory(parent);
                }

                using var input = entry.Open();
                using var output = new FileStream(
                    extractionPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    CopyBufferSize,
                    FileOptions.SequentialScan);
                CopyCancellable(input, output, token);
            }

            token.ThrowIfCancellationRequested();

            var validation = PackageReader.Validate(stageDirectory, expectedModel, target);
            token.ThrowIfCancellationRequested();

            if (!validation.IsValid)
            {
                reasons.AddRange(validation.Reasons);
                DeleteStage(stage, root, reasons);
                return Invalid(sourcePath, expectedModel, reasons);
            }

            if (!string.Equals(validation.Version, bundleVersion, StringComparison.Ordinal))
            {
                reasons.Add($"合集版本 {bundleVersion} 与所选安装包版本 {validation.Version} 不一致，拒绝使用。");
                DeleteStage(stage, root, reasons);
                return Invalid(sourcePath, expectedModel, reasons);
            }

            stage = null;
            return new ImportedPackage(sourcePath, stageDirectory, expectedModel, validation, stageDirectory, root);
        }
        catch (OperationCanceledException)
        {
            TryDeleteStage(stage, root);
            throw;
        }
        catch (Exception exception) when (IsExpectedFailure(exception))
        {
            reasons.Add($"导入安装包时发生错误：{exception.Message}");
            DeleteStage(stage, root, reasons);
            return Invalid(sourcePath, expectedModel, reasons);
        }
    }

    private static ImportedPackage Invalid(string sourcePath, string deviceModel, List<string> reasons)
    {
        if (reasons.Count == 0)
        {
            reasons.Add("导入安装包失败，未得到可用结果。");
        }

        return new ImportedPackage(
            sourcePath,
            string.Empty,
            deviceModel,
            new PackageValidationResult(false, reasons, null),
            null,
            null);
    }

    /// <summary>
    /// Deletes the stage directory and records a failure to do so as a reason: a cleanup that did not
    /// happen must not be reported as a successful import.
    /// </summary>
    private static void DeleteStage(string? stage, string? root, List<string> reasons)
    {
        if (stage is null || root is null)
        {
            return;
        }

        if (!IsBeneath(stage, root))
        {
            reasons.Add($"拒绝清理不在工作目录下的临时目录：{stage}。");
            return;
        }

        try
        {
            if (Directory.Exists(stage))
            {
                Directory.Delete(stage, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            reasons.Add($"临时目录清理失败：{exception.Message}");
        }
    }

    private static void TryDeleteStage(string? stage, string? root)
    {
        if (stage is null || root is null || !IsBeneath(stage, root))
        {
            return;
        }

        try
        {
            if (Directory.Exists(stage))
            {
                Directory.Delete(stage, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static void CopyCancellable(Stream input, Stream output, CancellationToken token)
    {
        var buffer = new byte[CopyBufferSize];
        int read;
        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            token.ThrowIfCancellationRequested();
            output.Write(buffer, 0, read);
        }
    }

    private static byte[] ReadLimited(ZipArchiveEntry entry, int limit, CancellationToken token)
    {
        using var input = entry.Open();
        using var memory = new MemoryStream();

        var buffer = new byte[CopyBufferSize];
        int read;
        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            token.ThrowIfCancellationRequested();

            if (memory.Length + read > limit)
            {
                throw new InvalidDataException($"{BundleFileName} 超出 {limit} 字节上限，拒绝解析。");
            }

            memory.Write(buffer, 0, read);
        }

        return memory.ToArray();
    }

    /// <summary>
    /// Indexes every archive entry and rejects hostile or ambiguous names before anything is written:
    /// traversal, absolute and drive qualified names, empty segments, trailing dot/space aliases,
    /// case-insensitive duplicates and symlink or reparse entries.
    /// </summary>
    private static bool TryIndexArchive(ZipArchive archive, List<ArchiveItem> items, List<string> reasons)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in archive.Entries)
        {
            var name = entry.FullName;

            if (string.IsNullOrEmpty(name))
            {
                reasons.Add("合集包含空名称条目，拒绝使用。");
                return false;
            }

            if (!TryNormalizeArchiveName(name, out var normalized, out var isDirectory, out var reason))
            {
                reasons.Add(reason);
                return false;
            }

            if (!seen.Add(normalized))
            {
                reasons.Add($"合集包含重复条目（忽略大小写）：{name}。");
                return false;
            }

            if (IsSymlinkOrReparse(entry))
            {
                reasons.Add($"合集包含符号链接或重解析点条目，拒绝使用：{name}。");
                return false;
            }

            items.Add(new ArchiveItem(normalized, isDirectory, entry));
        }

        return true;
    }

    /// <summary>
    /// Accepts only forward slash relative entry names with plain segments. Explicit directory entries
    /// (trailing slash) are allowed; everything that could alias, escape or confuse Windows is not.
    /// </summary>
    private static bool TryNormalizeArchiveName(
        string name,
        out string normalized,
        out bool isDirectory,
        out string reason)
    {
        normalized = string.Empty;
        isDirectory = false;
        reason = string.Empty;

        if (name.Contains('\0'))
        {
            reason = $"合集条目路径包含空字符：{name}。";
            return false;
        }

        if (name.Contains('\\'))
        {
            reason = $"合集条目路径必须使用正斜杠：{name}。";
            return false;
        }

        if (name.Contains(':'))
        {
            reason = $"合集条目路径不能包含盘符、备用数据流或协议前缀：{name}。";
            return false;
        }

        if (name[0] == '/')
        {
            reason = $"合集条目路径必须是相对路径：{name}。";
            return false;
        }

        var candidate = name;
        if (candidate.EndsWith('/'))
        {
            isDirectory = true;
            candidate = candidate[..^1];
        }

        if (!TryValidateSegments(candidate, out reason))
        {
            return false;
        }

        normalized = candidate;
        return true;
    }

    /// <summary>Validates a forward slash relative directory declared by the bundle index.</summary>
    private static bool TryNormalizeDirectory(string? value, out string normalized, out string reason)
    {
        normalized = string.Empty;
        reason = string.Empty;

        var candidate = value?.Trim() ?? string.Empty;
        if (candidate.Length == 0)
        {
            reason = $"{BundleFileName} 中的 packages[].directory 为空。";
            return false;
        }

        if (candidate.Contains('\0') || candidate.Contains('\\') || candidate.Contains(':'))
        {
            reason = $"{BundleFileName} 中的目录必须是普通的正斜杠相对路径：{candidate}。";
            return false;
        }

        if (candidate[0] == '/')
        {
            reason = $"{BundleFileName} 中的目录必须是相对路径：{candidate}。";
            return false;
        }

        while (candidate.EndsWith('/'))
        {
            candidate = candidate[..^1];
        }

        if (!TryValidateSegments(candidate, out reason))
        {
            return false;
        }

        normalized = candidate;
        return true;
    }

    private static bool TryValidateSegments(string candidate, out string reason)
    {
        reason = string.Empty;

        if (candidate.Length == 0)
        {
            reason = "合集条目路径为空。";
            return false;
        }

        foreach (var segment in candidate.Split('/'))
        {
            if (segment.Length == 0)
            {
                reason = $"合集条目路径包含空路径段：{candidate}。";
                return false;
            }

            if (segment == "." || segment == "..")
            {
                reason = $"合集条目路径不能包含相对跳转段（. 或 ..）：{candidate}。";
                return false;
            }

            if (segment.EndsWith('.') || segment.EndsWith(' '))
            {
                reason = $"合集条目路径包含以点或空格结尾的路径段（Windows 别名）：{candidate}。";
                return false;
            }

            foreach (var character in segment)
            {
                if (char.IsControl(character))
                {
                    reason = $"合集条目路径包含控制字符：{candidate}。";
                    return false;
                }
            }
        }

        return true;
    }

    private static bool IsSymlinkOrReparse(ZipArchiveEntry entry)
    {
        var attributes = entry.ExternalAttributes;
        var unixMode = (attributes >> 16) & 0xF000;
        if (unixMode == 0xA000)
        {
            return true;
        }

        return ((FileAttributes)(attributes & 0xFFFF) & FileAttributes.ReparsePoint) != 0;
    }

    private static bool IsSupportedModel(string model) =>
        SupportedModels.Contains(model, StringComparer.Ordinal);

    private static bool TryReadBundle(
        byte[] json,
        string expectedModel,
        List<string> reasons,
        out string bundleVersion,
        out string selectedDirectory,
        out List<SharedMapping> sharedMappings)
    {
        bundleVersion = string.Empty;
        selectedDirectory = string.Empty;
        sharedMappings = new List<SharedMapping>();

        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        if (root.ValueKind != JsonValueKind.Object)
        {
            reasons.Add($"{BundleFileName} 的根节点不是 JSON 对象。");
            return false;
        }

        if (!root.TryGetProperty("schemaVersion", out var schemaElement)
            || schemaElement.ValueKind != JsonValueKind.Number
            || !schemaElement.TryGetInt32(out var schemaVersion))
        {
            reasons.Add($"{BundleFileName} 缺少可解析的 schemaVersion。");
            return false;
        }

        if (schemaVersion != SupportedBundleSchemaVersion
            && schemaVersion != SharedBundleSchemaVersion)
        {
            reasons.Add($"不支持的合集 schemaVersion：{schemaVersion}，当前只接受 {SupportedBundleSchemaVersion} 或 {SharedBundleSchemaVersion}。");
            return false;
        }

        var sharedSchema = schemaVersion == SharedBundleSchemaVersion;

        if (!root.TryGetProperty("bundleId", out var idElement)
            || idElement.ValueKind != JsonValueKind.String
            || !string.Equals(idElement.GetString(), BundleIdentifier, StringComparison.Ordinal))
        {
            reasons.Add($"{BundleFileName} 的 bundleId 必须为 {BundleIdentifier}。");
            return false;
        }

        if (!root.TryGetProperty("version", out var versionElement)
            || versionElement.ValueKind != JsonValueKind.String)
        {
            reasons.Add($"{BundleFileName} 缺少 version。");
            return false;
        }

        var declaredVersion = versionElement.GetString()?.Trim() ?? string.Empty;
        if (declaredVersion.Length == 0)
        {
            reasons.Add($"{BundleFileName} 的 version 为空。");
            return false;
        }

        if (string.Equals(declaredVersion, "latest", StringComparison.OrdinalIgnoreCase))
        {
            reasons.Add($"{BundleFileName} 的 version 不能是 latest。");
            return false;
        }

        if (!root.TryGetProperty("packages", out var packagesElement)
            || packagesElement.ValueKind != JsonValueKind.Array)
        {
            reasons.Add($"{BundleFileName} 的 packages 不是数组。");
            return false;
        }

        var models = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var directories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var found = false;

        foreach (var package in packagesElement.EnumerateArray())
        {
            if (package.ValueKind != JsonValueKind.Object)
            {
                reasons.Add($"{BundleFileName} 的 packages 项不是 JSON 对象。");
                return false;
            }

            if (!package.TryGetProperty("deviceModel", out var modelElement)
                || modelElement.ValueKind != JsonValueKind.String)
            {
                reasons.Add($"{BundleFileName} 的 packages[].deviceModel 缺失或不是字符串。");
                return false;
            }

            var model = modelElement.GetString()?.Trim() ?? string.Empty;
            if (model.Length == 0)
            {
                reasons.Add($"{BundleFileName} 的 packages[].deviceModel 为空。");
                return false;
            }

            if (!IsSupportedModel(model)
                && SupportedModels.Contains(model, StringComparer.OrdinalIgnoreCase))
            {
                reasons.Add($"{BundleFileName} 的 deviceModel {model} 与支持的型号只差大小写。");
                return false;
            }

            // A bundle built for more models than this installer knows is still a
            // valid bundle: entries for unknown models get the same shape checks but
            // can never be selected (expectedModel is a supported model), so a newer
            // package does not lock out the models this installer supports.

            if (!package.TryGetProperty("directory", out var directoryElement)
                || directoryElement.ValueKind != JsonValueKind.String)
            {
                reasons.Add($"{BundleFileName} 的 packages[].directory 缺失或不是字符串。");
                return false;
            }

            if (!TryNormalizeDirectory(directoryElement.GetString(), out var directory, out var directoryReason))
            {
                reasons.Add(directoryReason);
                return false;
            }

            if (sharedSchema
                && (string.Equals(directory, SharedSourceRoot, StringComparison.OrdinalIgnoreCase)
                    || directory.StartsWith(SharedSourceRoot + "/", StringComparison.OrdinalIgnoreCase)))
            {
                reasons.Add($"schemaVersion {SharedBundleSchemaVersion} 的 packages[].directory 不能占用共享文件命名空间 {SharedSourceRoot}/：{directory}。");
                return false;
            }

            var mappings = new List<SharedMapping>();
            if (sharedSchema && !TryReadSharedMappings(package, reasons, out mappings))
            {
                return false;
            }

            if (!models.Add(model))
            {
                reasons.Add($"{BundleFileName} 重复声明了 deviceModel {model}。");
                return false;
            }

            if (!directories.Add(directory))
            {
                reasons.Add($"{BundleFileName} 重复声明了目录 {directory}。");
                return false;
            }

            if (!found && IsSupportedModel(model) && string.Equals(model, expectedModel, StringComparison.Ordinal))
            {
                selectedDirectory = directory;
                sharedMappings = mappings;
                found = true;
            }
        }

        if (models.Count == 0)
        {
            reasons.Add($"{BundleFileName} 的 packages 为空，没有任何可选安装包。");
            return false;
        }

        if (!found)
        {
            reasons.Add($"合集不包含请求的 deviceModel {expectedModel}，不做缺省型号推断。");
            return false;
        }

        bundleVersion = declaredVersion;
        return true;
    }

    /// <summary>IO, JSON and data-shape failures become reasons; severe failures propagate.</summary>
    private static bool IsExpectedFailure(Exception exception) =>
        exception is IOException
            or UnauthorizedAccessException
            or SecurityException
            or InvalidDataException
            or JsonException
            or NotSupportedException
            or ArgumentException
            or InvalidOperationException;

    private sealed record ArchiveItem(string Name, bool IsDirectory, ZipArchiveEntry Entry);
}
