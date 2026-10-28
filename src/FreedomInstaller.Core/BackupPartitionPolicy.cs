using System;

namespace FreedomInstaller.Core;

/// <summary>
/// Exact-name policy for partition labels that are never copied into newly generated install backups or
/// recovery archives. Matching is case-insensitive and exact; no wildcard or prefix matching is applied.
/// </summary>
internal static class BackupPartitionPolicy
{
    private static readonly string[] ExcludedNames =
    {
        "userdata", "rawdump", "metadata",
    };

    /// <summary>
    /// Returns <c>true</c> when <paramref name="name"/> is one of the excluded partition labels. A null or
    /// empty name is not excluded. Names such as <c>vbmeta</c>, <c>vbmeta_a</c> or <c>persist</c> are not excluded.
    /// </summary>
    internal static bool IsExcluded(string? name)
    {
        if (string.IsNullOrEmpty(name))
        {
            return false;
        }

        foreach (string excluded in ExcludedNames)
        {
            if (string.Equals(excluded, name, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
