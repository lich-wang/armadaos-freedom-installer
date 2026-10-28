using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;

namespace FreedomInstaller.Core;

/// <summary>
/// The immutable model-specific backup contract: which partition labels on which LUN a model must expose, the
/// GPT roles that are read first, the total number of captured files, and the LUN of every role.
/// <para>
/// There is exactly one authoritative ordered six-LUN role table here. <c>TB322FC</c> keeps all 39 partition
/// labels (51 files); <c>TB323FU</c> drops only <c>proinfo</c>, <c>lenovolock</c>, <c>lenovocust</c> and
/// <c>lenovoraw</c> - all of them on LUN0 - and therefore carries 35 labels and 47 files. No firmware gate, no
/// profile id, no external dependency and no future-model fallback is involved.
/// </para>
/// <para>
/// The baseline model contract never carries the optional <c>efisp</c> role. A snapshot produced by
/// <see cref="WithEfisp"/> or <see cref="ForCapturedRoles"/> may add exactly one <c>efisp</c> at LUN4, in which
/// case the partitions, roles, LUN map and file count describe that selected set while the baseline label and
/// file counts above stay unchanged.
/// </para>
/// <para>
/// The legacy <c>metadata</c> role on LUN0 is no longer part of any new capture. <see cref="ForCapturedRoles"/>
/// still accepts an optional <c>metadata</c> at LUN0 for verification of already-created captures, and
/// <see cref="TryGetKnownLun"/> still recognises it for validation, but <see cref="ForModel"/> never includes it
/// and no public helper to add it is exposed; the role is accepted for legacy validation only.
/// </para>
/// </summary>
internal sealed class InternalInstallBackupRoles
{
    private const string ModelG4 = "TB322FC";
    private const string ModelG5 = "TB323FU";

    private const int LunCount = 6;

    /// <summary>The optional role a selected snapshot may add once, on <see cref="EfispLun"/>.</summary>
    internal const string EfispRole = "efisp";

    /// <summary>The LUN that owns <see cref="EfispRole"/> when it is selected.</summary>
    internal const int EfispLun = 4;

    /// <summary>The legacy role accepted only for already-created captures, on <see cref="LegacyMetadataLun"/>.</summary>
    internal const string LegacyMetadataRole = "metadata";

    /// <summary>The LUN that owns <see cref="LegacyMetadataRole"/> when it appears in a legacy capture.</summary>
    internal const int LegacyMetadataLun = 0;

    /// <summary>
    /// The one authoritative ordered six-LUN role table (index = LUN). Every partition contract is derived
    /// from this table, never restated. <c>metadata</c> is deliberately absent: it is never captured by a new
    /// backup, but legacy captures may still carry it.
    /// </summary>
    private static readonly string[][] OrderedLunRoles =
    {
        new[]
        {
            "proinfo", "lenovolock", "lenovocust", "lenovoraw", "ssd", "persist", "misc", "keystore", "frp",
            "vbmeta_system_a", "vbmeta_system_b",
        },
        new[] { "xbl_a", "xbl_config_a" },
        new[] { "xbl_b", "xbl_config_b" },
        new[] { "cdt" },
        new[]
        {
            "boot_a", "boot_b", "init_boot_a", "init_boot_b", "vendor_boot_a", "vendor_boot_b", "dtbo_a", "dtbo_b",
            "vbmeta_a", "vbmeta_b", "recovery_a", "recovery_b", "devinfo", "uefivarstore", "secdata", "connsec",
            "spunvm", "abl_a", "abl_b",
        },
        new[] { "modemst1", "modemst2", "fsg", "fsc" },
    };

    /// <summary>Labels carried only by TB322FC; every one of them lives on LUN0.</summary>
    private static readonly string[] G5ExcludedPartitions =
    {
        "proinfo", "lenovolock", "lenovocust", "lenovoraw",
    };

    private readonly ReadOnlyCollection<(int Lun, string Name)> _partitions;
    private readonly ReadOnlyCollection<string> _partitionNames;
    private readonly ReadOnlyCollection<string> _requiredRoles;
    private readonly ReadOnlyDictionary<string, int> _roleLuns;
    private readonly int _totalFileCount;
    private readonly bool _hasEfisp;
    private readonly bool _hasLegacyMetadata;

    private InternalInstallBackupRoles(
        ReadOnlyCollection<(int Lun, string Name)> partitions,
        ReadOnlyCollection<string> partitionNames,
        ReadOnlyCollection<string> requiredRoles,
        ReadOnlyDictionary<string, int> roleLuns,
        int totalFileCount,
        bool hasEfisp,
        bool hasLegacyMetadata)
    {
        _partitions = partitions;
        _partitionNames = partitionNames;
        _requiredRoles = requiredRoles;
        _roleLuns = roleLuns;
        _totalFileCount = totalFileCount;
        _hasEfisp = hasEfisp;
        _hasLegacyMetadata = hasLegacyMetadata;
    }

    /// <summary>Every partition the model must expose, in read order, with the LUN that owns it.</summary>
    internal IReadOnlyList<(int Lun, string Name)> Partitions => _partitions;

    /// <summary>The partition labels of <see cref="Partitions"/>, in the same order.</summary>
    internal IReadOnlyList<string> PartitionNames => _partitionNames;

    /// <summary>The twelve GPT roles (primary/backup per LUN, LUN0..LUN5) followed by every selected partition label.</summary>
    internal IReadOnlyList<string> RequiredRoles => _requiredRoles;

    /// <summary>The LUN of every role in <see cref="RequiredRoles"/>.</summary>
    internal IReadOnlyDictionary<string, int> RoleLuns => _roleLuns;

    /// <summary>Number of files described by this snapshot: the GPT roles plus the selected partitions.</summary>
    internal int TotalFileCount => _totalFileCount;

    /// <summary>Reports whether this snapshot selects <c>efisp</c>.</summary>
    internal bool HasEfisp => _hasEfisp;

    /// <summary>Reports whether this snapshot includes the legacy <c>metadata</c> role.</summary>
    internal bool HasLegacyMetadata => _hasLegacyMetadata;

    /// <summary>
    /// Returns the baseline contract of exactly <paramref name="model"/>. A null, blank, padded or unknown model
    /// is rejected; there is no trimming and no default contract. The baseline never carries <c>metadata</c> or
    /// <c>efisp</c>.
    /// </summary>
    internal static InternalInstallBackupRoles ForModel(string model)
    {
        if (string.IsNullOrWhiteSpace(model))
        {
            throw new ArgumentException("A model name is required.", nameof(model));
        }

        bool isG5 = string.Equals(model, ModelG5, StringComparison.Ordinal);
        if (!isG5 && !string.Equals(model, ModelG4, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The model '" + model + "' has no internal backup role contract.", nameof(model));
        }

        (int Lun, string Name)[] partitions = BuildPartitions(isG5);
        return Create(partitions, false, false);
    }

    /// <summary>
    /// Returns the selected contract carrying every role of this snapshot plus exactly one <c>efisp</c> at
    /// <see cref="EfispLun"/>, inserted at the end of the LUN4 group. Repeating the call is idempotent.
    /// </summary>
    internal InternalInstallBackupRoles WithEfisp()
    {
        if (_hasEfisp)
        {
            return this;
        }

        return Create(BuildSelectedPartitions(BasePartitions(), true, _hasLegacyMetadata), true, _hasLegacyMetadata);
    }

    /// <summary>
    /// Returns the exact selected contract of the whole captured role set: the baseline roles of this snapshot
    /// plus <c>efisp</c> and/or the legacy <c>metadata</c> only when those roles are present. Every base role must
    /// appear once, and unknown, empty or duplicated roles are rejected. Only the role-set shape is validated,
    /// never GPT, extent or hash trust. No new capture is ever produced through this method.
    /// </summary>
    internal InternalInstallBackupRoles ForCapturedRoles(IEnumerable<string> capturedRoles)
    {
        if (capturedRoles is null)
        {
            throw new ArgumentNullException(nameof(capturedRoles));
        }

        (int Lun, string Name)[] basePartitions = BasePartitions();
        HashSet<string> baseRoles = BaseRoleNames(basePartitions);
        HashSet<string> seen = new(StringComparer.Ordinal);
        bool hasEfisp = false;
        bool hasLegacyMetadata = false;

        foreach (string role in capturedRoles)
        {
            if (string.IsNullOrEmpty(role))
            {
                throw new InvalidDataException("A captured backup role is empty.");
            }

            if (!seen.Add(role))
            {
                throw new InvalidDataException("The captured backup role '" + role + "' appears more than once.");
            }

            if (string.Equals(role, EfispRole, StringComparison.Ordinal))
            {
                hasEfisp = true;
                continue;
            }

            if (string.Equals(role, LegacyMetadataRole, StringComparison.Ordinal))
            {
                hasLegacyMetadata = true;
                continue;
            }

            if (!baseRoles.Contains(role))
            {
                throw new InvalidDataException(
                    "The captured backup role '" + role + "' is not part of the backup contract.");
            }
        }

        foreach (string role in baseRoles)
        {
            if (!seen.Contains(role))
            {
                throw new InvalidDataException("The captured backup role set is missing '" + role + "'.");
            }
        }

        if (hasEfisp == _hasEfisp && hasLegacyMetadata == _hasLegacyMetadata)
        {
            return this;
        }

        return Create(BuildSelectedPartitions(basePartitions, hasEfisp, hasLegacyMetadata), hasEfisp, hasLegacyMetadata);
    }

    /// <summary>
    /// Reports whether <paramref name="role"/> is a role this helper knows and on which LUN it lives: every base
    /// role of the selected snapshot plus <c>efisp</c> at <see cref="EfispLun"/> and the legacy <c>metadata</c> at
    /// <see cref="LegacyMetadataLun"/>, selected or not. Being known never means the role was captured, and no
    /// partitioned label outside the contract is ever recognised.
    /// </summary>
    internal bool TryGetKnownLun(string role, out int lun)
    {
        if (string.IsNullOrEmpty(role))
        {
            lun = 0;
            return false;
        }

        if (_roleLuns.TryGetValue(role, out lun))
        {
            return true;
        }

        if (string.Equals(role, EfispRole, StringComparison.Ordinal))
        {
            lun = EfispLun;
            return true;
        }

        if (string.Equals(role, LegacyMetadataRole, StringComparison.Ordinal))
        {
            lun = LegacyMetadataLun;
            return true;
        }

        lun = 0;
        return false;
    }

    private (int Lun, string Name)[] BasePartitions()
    {
        List<(int Lun, string Name)> basePartitions = new();

        foreach ((int lun, string name) in _partitions)
        {
            if (!string.Equals(name, EfispRole, StringComparison.Ordinal)
                && !string.Equals(name, LegacyMetadataRole, StringComparison.Ordinal))
            {
                basePartitions.Add((lun, name));
            }
        }

        return basePartitions.ToArray();
    }

    private static HashSet<string> BaseRoleNames((int Lun, string Name)[] basePartitions)
    {
        HashSet<string> roles = new(StringComparer.Ordinal);
        string[] gptRoles = BuildGptRoles();

        foreach (string gptRole in gptRoles)
        {
            roles.Add(gptRole);
        }

        foreach ((int _, string name) in basePartitions)
        {
            roles.Add(name);
        }

        return roles;
    }

    private static (int Lun, string Name)[] BuildSelectedPartitions(
        (int Lun, string Name)[] basePartitions,
        bool hasEfisp,
        bool hasLegacyMetadata)
    {
        (int Lun, string Name)[] selected = basePartitions;

        if (hasLegacyMetadata)
        {
            selected = InsertByLun(selected, (LegacyMetadataLun, LegacyMetadataRole));
        }

        if (hasEfisp)
        {
            selected = InsertByLun(selected, (EfispLun, EfispRole));
        }

        return selected;
    }

    private static (int Lun, string Name)[] InsertByLun(
        (int Lun, string Name)[] basePartitions,
        (int Lun, string Name) insertion)
    {
        int insertAt = basePartitions.Length;
        for (int index = 0; index < basePartitions.Length; index++)
        {
            if (basePartitions[index].Lun > insertion.Lun)
            {
                insertAt = index;
                break;
            }
        }

        (int Lun, string Name)[] selected = new (int Lun, string Name)[basePartitions.Length + 1];
        Array.Copy(basePartitions, 0, selected, 0, insertAt);
        selected[insertAt] = insertion;
        Array.Copy(basePartitions, insertAt, selected, insertAt + 1, basePartitions.Length - insertAt);

        return selected;
    }

    /// <summary>
    /// Wraps one ordered partition set into the immutable contract. Partitions, partition labels, roles, LUN map
    /// and file count are all derived from that set, so optional <c>efisp</c> and legacy <c>metadata</c> entries
    /// are reflected everywhere. <paramref name="hasEfisp"/> and <paramref name="hasLegacyMetadata"/> record the
    /// optional role selections independently of the partition set.
    /// </summary>
    private static InternalInstallBackupRoles Create(
        (int Lun, string Name)[] partitions,
        bool hasEfisp,
        bool hasLegacyMetadata)
    {
        string[] partitionNames = new string[partitions.Length];
        for (int index = 0; index < partitions.Length; index++)
        {
            partitionNames[index] = partitions[index].Name;
        }

        string[] gptRoles = BuildGptRoles();
        string[] requiredRoles = new string[gptRoles.Length + partitionNames.Length];
        Array.Copy(gptRoles, requiredRoles, gptRoles.Length);
        Array.Copy(partitionNames, 0, requiredRoles, gptRoles.Length, partitionNames.Length);

        Dictionary<string, int> roleLuns = new(StringComparer.Ordinal);
        for (int lun = 0; lun < LunCount; lun++)
        {
            roleLuns.Add(GptRoleName(lun, "primary"), lun);
            roleLuns.Add(GptRoleName(lun, "backup"), lun);
        }

        foreach ((int lun, string name) in partitions)
        {
            roleLuns.Add(name, lun);
        }

        return new InternalInstallBackupRoles(
            new ReadOnlyCollection<(int Lun, string Name)>(partitions),
            new ReadOnlyCollection<string>(partitionNames),
            new ReadOnlyCollection<string>(requiredRoles),
            new ReadOnlyDictionary<string, int>(roleLuns),
            requiredRoles.Length,
            hasEfisp,
            hasLegacyMetadata);
    }

    private static (int Lun, string Name)[] BuildPartitions(bool dropG5Excluded)
    {
        List<(int Lun, string Name)> partitions = new();

        for (int lun = 0; lun < OrderedLunRoles.Length; lun++)
        {
            foreach (string name in OrderedLunRoles[lun])
            {
                if (dropG5Excluded && IsExcludedOnG5(name))
                {
                    continue;
                }

                partitions.Add((lun, name));
            }
        }

        return partitions.ToArray();
    }

    private static bool IsExcludedOnG5(string name)
    {
        foreach (string excluded in G5ExcludedPartitions)
        {
            if (string.Equals(excluded, name, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string[] BuildGptRoles()
    {
        string[] roles = new string[LunCount * 2];

        for (int lun = 0; lun < LunCount; lun++)
        {
            roles[lun * 2] = GptRoleName(lun, "primary");
            roles[(lun * 2) + 1] = GptRoleName(lun, "backup");
        }

        return roles;
    }

    private static string GptRoleName(int lun, string slot) => "gpt_lun" + lun + "_" + slot;
}
