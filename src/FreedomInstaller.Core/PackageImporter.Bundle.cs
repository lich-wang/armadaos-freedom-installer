using System.Text.Json;

namespace FreedomInstaller.Core;

/// <summary>
/// Bundle-index side of the importer: the schema2 shared-file mappings and the extraction plan that
/// both the ZIP fast path and the streaming archive path consume.
/// <para>
/// A schema1 index keeps its old meaning and never honors <c>sharedFiles</c>. A schema2 index must
/// declare the array on every package; each entry maps one physical <c>common/</c> archive path to a
/// safe relative destination below the selected package, so a single shared blob can feed both model
/// manifests without being stored twice and without the <c>common/</c> tree ever becoming a package.
/// </para>
/// </summary>
public static partial class PackageImporter
{
    private const string SharedSourceRoot = "common";

    private readonly record struct ArchiveNode(string Name, bool IsDirectory);

    private sealed record SharedMapping(string Source, string Destination);

    private sealed record ExtractionItem(string SourceName, string Destination, bool IsDirectory);

    /// <summary>
    /// Reads and validates the <c>sharedFiles</c> array of one schema2 package. Every mapping of every
    /// package is validated before any package is selected, so an invalid unselected model still
    /// rejects the bundle. Duplicate sources and destinations are rejected case-insensitively within
    /// one model; sources may be shared between different model entries.
    /// </summary>
    private static bool TryReadSharedMappings(
        JsonElement package,
        List<string> reasons,
        out List<SharedMapping> mappings)
    {
        mappings = new List<SharedMapping>();

        if (!package.TryGetProperty("sharedFiles", out var sharedFiles)
            || sharedFiles.ValueKind != JsonValueKind.Array)
        {
            reasons.Add($"{BundleFileName} 的 schemaVersion {SharedBundleSchemaVersion} 要求每个 packages[] 都包含 sharedFiles 数组。");
            return false;
        }

        var sources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var destinations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in sharedFiles.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                reasons.Add($"{BundleFileName} 的 packages[].sharedFiles[] 不是 JSON 对象。");
                return false;
            }

            if (!entry.TryGetProperty("source", out var sourceElement)
                || sourceElement.ValueKind != JsonValueKind.String)
            {
                reasons.Add($"{BundleFileName} 的 packages[].sharedFiles[].source 缺失或不是字符串。");
                return false;
            }

            if (!TryNormalizeSharedPath(
                sourceElement.GetString(),
                true,
                "source",
                out var source,
                out var sourceReason))
            {
                reasons.Add(sourceReason);
                return false;
            }

            if (!entry.TryGetProperty("destination", out var destinationElement)
                || destinationElement.ValueKind != JsonValueKind.String)
            {
                reasons.Add($"{BundleFileName} 的 packages[].sharedFiles[].destination 缺失或不是字符串。");
                return false;
            }

            if (!TryNormalizeSharedPath(
                destinationElement.GetString(),
                false,
                "destination",
                out var destination,
                out var destinationReason))
            {
                reasons.Add(destinationReason);
                return false;
            }

            if (string.Equals(destination, ManifestFileName, StringComparison.OrdinalIgnoreCase))
            {
                reasons.Add($"{BundleFileName} 的共享文件 destination 不能覆盖 {ManifestFileName}：{destination}。");
                return false;
            }

            if (!sources.Add(source))
            {
                reasons.Add($"{BundleFileName} 在同一 packages[] 中重复声明了共享文件 source（忽略大小写）：{source}。");
                return false;
            }

            if (!destinations.Add(destination))
            {
                reasons.Add($"{BundleFileName} 在同一 packages[] 中重复声明了共享文件 destination（忽略大小写）：{destination}。");
                return false;
            }

            mappings.Add(new SharedMapping(source, destination));
        }

        return true;
    }

    /// <summary>
    /// Accepts only a normalized forward slash relative file path with plain segments. A shared source
    /// must additionally live under <c>common/</c> with a non-empty remainder, which keeps the shared
    /// namespace disjoint from every model directory. Directory spellings are rejected so a mapping can
    /// never point at a folder.
    /// </summary>
    private static bool TryNormalizeSharedPath(
        string? value,
        bool requireSharedRoot,
        string field,
        out string normalized,
        out string reason)
    {
        normalized = string.Empty;
        reason = string.Empty;

        var candidate = value?.Trim() ?? string.Empty;
        if (candidate.Length == 0)
        {
            reason = $"{BundleFileName} 的 packages[].sharedFiles[].{field} 为空。";
            return false;
        }

        if (candidate.Contains('\0') || candidate.Contains('\\') || candidate.Contains(':'))
        {
            reason = $"{BundleFileName} 的共享文件 {field} 必须是普通的正斜杠相对路径：{candidate}。";
            return false;
        }

        if (candidate[0] == '/')
        {
            reason = $"{BundleFileName} 的共享文件 {field} 必须是相对路径：{candidate}。";
            return false;
        }

        if (candidate.EndsWith('/'))
        {
            reason = $"{BundleFileName} 的共享文件 {field} 必须是文件路径，不能以斜杠结尾：{candidate}。";
            return false;
        }

        if (!TryValidateSegments(candidate, out reason))
        {
            return false;
        }

        if (requireSharedRoot
            && !candidate.StartsWith(SharedSourceRoot + "/", StringComparison.Ordinal))
        {
            reason = $"{BundleFileName} 的共享文件 {field} 必须位于 {SharedSourceRoot}/ 之下且剩余路径非空：{candidate}。";
            return false;
        }

        normalized = candidate;
        return true;
    }

    /// <summary>
    /// Builds the single extraction plan used by both readers from the complete entry index. The plan
    /// contains every direct entry of the selected subtree with the model prefix stripped, plus one
    /// item per shared mapping at its destination. It requires the selected <c>package.json</c> and
    /// every shared source file to exist as files, and rejects any destination collision with a
    /// direct entry or another mapped file, including file-versus-parent/child conflicts, before a
    /// stage directory exists.
    /// </summary>
    private static bool TryBuildExtractionPlan(
        IReadOnlyList<ArchiveNode> index,
        string selectedDirectory,
        IReadOnlyList<SharedMapping> sharedMappings,
        List<string> reasons,
        out List<ExtractionItem> plan)
    {
        plan = new List<ExtractionItem>();

        var byName = new Dictionary<string, ArchiveNode>(StringComparer.Ordinal);
        foreach (var node in index)
        {
            byName[node.Name] = node;
        }

        var prefix = selectedDirectory + "/";
        var manifestName = prefix + ManifestFileName;
        if (!byName.TryGetValue(manifestName, out var manifest) || manifest.IsDirectory)
        {
            reasons.Add($"合集目录 {selectedDirectory} 下缺少 {ManifestFileName}。");
            return false;
        }

        var occupied = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        foreach (var node in index)
        {
            if (!node.Name.StartsWith(prefix, StringComparison.Ordinal))
            {
                continue;
            }

            var relative = node.Name[prefix.Length..];
            if (relative.Length == 0)
            {
                continue;
            }

            if (!TryReserveExtractionPath(occupied, relative, node.IsDirectory, out var conflict))
            {
                reasons.Add($"合集条目 {node.Name} 与解包目标 {conflict} 冲突，拒绝使用。");
                return false;
            }

            plan.Add(new ExtractionItem(node.Name, relative, node.IsDirectory));
        }

        foreach (var mapping in sharedMappings)
        {
            if (!byName.TryGetValue(mapping.Source, out var source) || source.IsDirectory)
            {
                reasons.Add($"合集缺少共享文件 source {mapping.Source}，拒绝使用。");
                return false;
            }

            if (!TryReserveExtractionPath(occupied, mapping.Destination, false, out var conflict))
            {
                reasons.Add($"共享文件目标 {mapping.Destination} 与已有条目 {conflict} 冲突，拒绝使用。");
                return false;
            }

            plan.Add(new ExtractionItem(mapping.Source, mapping.Destination, false));
        }

        return true;
    }

    /// <summary>
    /// Reserves one relative path and returns false on a case-insensitive duplicate or on a
    /// file-versus-parent/child conflict. A directory may be added above existing files, but a file
    /// may never replace a directory, sit below a file or contain another entry.
    /// </summary>
    private static bool TryReserveExtractionPath(
        Dictionary<string, bool> occupied,
        string path,
        bool isDirectory,
        out string conflict)
    {
        conflict = string.Empty;

        if (occupied.TryGetValue(path, out _))
        {
            conflict = path;
            return false;
        }

        var slash = path.LastIndexOf('/');
        while (slash > 0)
        {
            var parent = path[..slash];
            if (occupied.TryGetValue(parent, out var parentIsDirectory) && !parentIsDirectory)
            {
                conflict = parent;
                return false;
            }

            slash = parent.LastIndexOf('/');
        }

        if (!isDirectory)
        {
            var childPrefix = path + "/";
            foreach (var key in occupied.Keys)
            {
                if (key.StartsWith(childPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    conflict = key;
                    return false;
                }
            }
        }

        occupied[path] = isDirectory;
        return true;
    }
}
