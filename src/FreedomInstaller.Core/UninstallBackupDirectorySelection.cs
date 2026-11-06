using System;
using System.Collections.Generic;
using System.IO;

namespace FreedomInstaller.Core;

/// <summary>
/// 卸载来源目录解析：用户可能选中恢复备份的父目录，而实际清单位于其
/// 唯一一个立即子目录 internal-backup-* 中。本类只负责定位候选目录，
/// 绝不证明备份有效；目录精确匹配、清单哈希、设备与 GPT 校验仍由既有读取器负责。
/// </summary>
public static class UninstallBackupDirectorySelection
{
    public const string ManifestFileName = "backup-manifest.json";
    public const string ManifestSidecarFileName = "backup-manifest.json.sha256";

    public enum SelectionKind
    {
        Selected,
        Missing,
        Multiple,
    }

    public sealed class Result
    {
        public Result(SelectionKind kind, string? directoryPath, IReadOnlyList<string> candidates)
        {
            Kind = kind;
            DirectoryPath = directoryPath;
            Candidates = candidates;
        }

        public SelectionKind Kind { get; }

        public string? DirectoryPath { get; }

        public IReadOnlyList<string> Candidates { get; }
    }

    public static Result Resolve(string selectedDirectory)
    {
        if (string.IsNullOrWhiteSpace(selectedDirectory))
        {
            throw new ArgumentException("Selected directory is required.", nameof(selectedDirectory));
        }

        if (!Path.IsPathFullyQualified(selectedDirectory))
        {
            throw new ArgumentException("Selected directory must be an absolute path.", nameof(selectedDirectory));
        }

        var normalized = Path.TrimEndingDirectorySeparator(Path.GetFullPath(selectedDirectory));

        var info = new DirectoryInfo(normalized);
        if (!info.Exists)
        {
            throw new IOException("Selected directory does not exist: " + normalized);
        }

        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException("Selected directory must not be a reparse point: " + normalized);
        }

        // 直接命中选择目录本身：即使清单或校验文件残缺/损坏也直接返回，交由既有读取器报错，绝不回退到子目录。
        if (HasMarker(normalized))
        {
            return new Result(SelectionKind.Selected, normalized, new[] { normalized });
        }

        // 只检查立即、非重解析点子目录；不递归、不按名称/序号/时间选择。
        var candidates = new List<string>();
        foreach (var child in info.EnumerateDirectories())
        {
            if ((child.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                continue;
            }

            if (HasMarker(child.FullName))
            {
                candidates.Add(Path.TrimEndingDirectorySeparator(child.FullName));
            }
        }

        candidates.Sort(StringComparer.Ordinal);

        return candidates.Count switch
        {
            0 => new Result(SelectionKind.Missing, null, Array.Empty<string>()),
            1 => new Result(SelectionKind.Selected, candidates[0], candidates),
            _ => new Result(SelectionKind.Multiple, null, candidates),
        };
    }

    private static bool HasMarker(string directory)
    {
        return File.Exists(Path.Combine(directory, ManifestFileName))
            || File.Exists(Path.Combine(directory, ManifestSidecarFileName));
    }
}
