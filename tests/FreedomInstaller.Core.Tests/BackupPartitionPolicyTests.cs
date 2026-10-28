using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class BackupPartitionPolicyTests
{
    private const BindingFlags InstanceFlags = BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public;
    private const BindingFlags StaticFlags = BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public;

    private static readonly Type RolesType =
        typeof(GlobalEdlBackup).Assembly.GetType("FreedomInstaller.Core.InternalInstallBackupRoles", throwOnError: true)!;

    private static readonly Type PolicyType =
        typeof(GlobalEdlBackup).Assembly.GetType("FreedomInstaller.Core.BackupPartitionPolicy", throwOnError: true)!;

    private static object ForModel(string model)
    {
        MethodInfo method = RolesType.GetMethod("ForModel", StaticFlags)
            ?? throw new InvalidOperationException("ForModel not found");
        try
        {
            return method.Invoke(null, new object[] { model })
                ?? throw new InvalidOperationException("ForModel returned null");
        }
        catch (TargetInvocationException ex) when (ex.InnerException is not null)
        {
            throw ex.InnerException;
        }
    }

    private static object WithEfisp(object roles)
    {
        MethodInfo method = RolesType.GetMethod("WithEfisp", InstanceFlags)
            ?? throw new InvalidOperationException("WithEfisp not found");
        return method.Invoke(roles, Array.Empty<object>())
            ?? throw new InvalidOperationException("WithEfisp returned null");
    }

    private static object ForCapturedRoles(object roles, IEnumerable<string> captured)
    {
        MethodInfo method = RolesType.GetMethod("ForCapturedRoles", InstanceFlags)
            ?? throw new InvalidOperationException("ForCapturedRoles not found");
        try
        {
            return method.Invoke(roles, new object[] { captured })
                ?? throw new InvalidOperationException("ForCapturedRoles returned null");
        }
        catch (TargetInvocationException ex) when (ex.InnerException is not null)
        {
            throw ex.InnerException;
        }
    }

    private static int TotalFileCount(object roles) =>
        (int)(RolesType.GetProperty("TotalFileCount", InstanceFlags)?.GetValue(roles)
            ?? throw new InvalidOperationException("TotalFileCount not found"));

    private static bool HasEfisp(object roles) =>
        (bool)(RolesType.GetProperty("HasEfisp", InstanceFlags)?.GetValue(roles)
            ?? throw new InvalidOperationException("HasEfisp not found"));

    private static bool HasLegacyMetadata(object roles) =>
        (bool)(RolesType.GetProperty("HasLegacyMetadata", InstanceFlags)?.GetValue(roles)
            ?? throw new InvalidOperationException("HasLegacyMetadata not found"));

    private static IReadOnlyList<string> RequiredRoles(object roles) =>
        (IReadOnlyList<string>)(RolesType.GetProperty("RequiredRoles", InstanceFlags)?.GetValue(roles)
            ?? throw new InvalidOperationException("RequiredRoles not found"));

    private static IReadOnlyDictionary<string, int> RoleLuns(object roles) =>
        (IReadOnlyDictionary<string, int>)(RolesType.GetProperty("RoleLuns", InstanceFlags)?.GetValue(roles)
            ?? throw new InvalidOperationException("RoleLuns not found"));

    private static IReadOnlyList<string> PartitionNames(object roles) =>
        (IReadOnlyList<string>)(RolesType.GetProperty("PartitionNames", InstanceFlags)?.GetValue(roles)
            ?? throw new InvalidOperationException("PartitionNames not found"));

    private static bool IsExcluded(string? role)
    {
        MethodInfo method = PolicyType.GetMethod("IsExcluded", StaticFlags)
            ?? throw new InvalidOperationException("IsExcluded not found");
        return (bool)(method.Invoke(null, new object?[] { role }) ?? false);
    }

    [Fact]
    public void ForModel_G4_Baseline_Has_51_Files()
    {
        object roles = ForModel("TB322FC");
        Assert.Equal(51, TotalFileCount(roles));
        Assert.False(HasEfisp(roles));
        Assert.False(HasLegacyMetadata(roles));
    }

    [Fact]
    public void ForModel_G5_Baseline_Has_47_Files()
    {
        object roles = ForModel("TB323FU");
        Assert.Equal(47, TotalFileCount(roles));
        Assert.False(HasEfisp(roles));
        Assert.False(HasLegacyMetadata(roles));
    }

    [Fact]
    public void ForModel_G4_Unknown_Model_Rejects_With_Mixed_Case()
    {
        Assert.Throws<ArgumentException>(() => ForModel("tb322fc"));
        Assert.Throws<ArgumentException>(() => ForModel("Tb323fu"));
    }

    [Fact]
    public void ForModel_G4_Includes_Proinfo_Lenovolock_Lenovocust_Lenovoraw()
    {
        object roles = ForModel("TB322FC");
        IReadOnlyList<string> partitions = PartitionNames(roles);
        Assert.Contains("proinfo", partitions);
        Assert.Contains("lenovolock", partitions);
        Assert.Contains("lenovocust", partitions);
        Assert.Contains("lenovoraw", partitions);
    }

    [Theory]
    [InlineData("userdata")]
    [InlineData("USERDATA")]
    [InlineData("UserData")]
    [InlineData("rawdump")]
    [InlineData("RawDump")]
    [InlineData("RAWDUMP")]
    [InlineData("metadata")]
    [InlineData("MetaData")]
    [InlineData("METADATA")]
    public void Policy_Excludes_Mixed_Case_Excluded_Names(string name)
    {
        Assert.True(IsExcluded(name), name);
    }

    [Theory]
    [InlineData("super")]
    [InlineData("vbmeta_a")]
    [InlineData("vbmeta_system_b")]
    [InlineData("persist")]
    [InlineData("misc")]
    [InlineData("boot_a")]
    [InlineData("modem")]
    [InlineData("userdata_extra")]
    [InlineData("rawdump2")]
    [InlineData("metadata_backup")]
    [InlineData("")]
    public void Policy_Does_Not_Exclude_Nonmatching_Names(string name)
    {
        Assert.False(IsExcluded(name), name);
    }

    [Fact]
    public void Policy_Does_Not_Exclude_Null()
    {
        Assert.False(IsExcluded(null));
    }

    [Fact]
    public void ForModel_G5_Excludes_Proinfo_Lenovolock_Lenovocust_Lenovoraw_Only()
    {
        object roles = ForModel("TB323FU");
        IReadOnlyList<string> partitions = PartitionNames(roles);
        Assert.DoesNotContain("proinfo", partitions);
        Assert.DoesNotContain("lenovolock", partitions);
        Assert.DoesNotContain("lenovocust", partitions);
        Assert.DoesNotContain("lenovoraw", partitions);
        Assert.Equal(35, partitions.Count);
    }

    [Fact]
    public void Baseline_Policy_Does_Not_Exclude_Vbmeta_Labels()
    {
        Assert.False(IsExcluded("vbmeta_a"));
        Assert.False(IsExcluded("vbmeta_b"));
        Assert.False(IsExcluded("vbmeta_system_a"));
        Assert.False(IsExcluded("vbmeta_system_b"));
    }

    [Fact]
    public void Baseline_Policy_Does_Not_Exclude_Any_Contract_Partition()
    {
        object g4 = ForModel("TB322FC");
        object g5 = ForModel("TB323FU");

        foreach (string name in PartitionNames(g4))
        {
            Assert.False(IsExcluded(name), name);
        }

        foreach (string name in PartitionNames(g5))
        {
            Assert.False(IsExcluded(name), name);
        }
    }

    [Fact]
    public void WithEfisp_Adds_51_To_52_And_47_To_48_Without_Exclusions()
    {
        object g4With = WithEfisp(ForModel("TB322FC"));
        object g5With = WithEfisp(ForModel("TB323FU"));

        Assert.Equal(52, TotalFileCount(g4With));
        Assert.Equal(48, TotalFileCount(g5With));
        Assert.True(HasEfisp(g4With));
        Assert.True(HasEfisp(g5With));
        Assert.False(HasLegacyMetadata(g4With));
        Assert.False(HasLegacyMetadata(g5With));

        foreach (string name in PartitionNames(g4With))
        {
            Assert.False(IsExcluded(name), name);
        }

        foreach (string name in PartitionNames(g5With))
        {
            Assert.False(IsExcluded(name), name);
        }
    }

    [Fact]
    public void WithEfisp_Is_Idempotent()
    {
        object once = WithEfisp(ForModel("TB322FC"));
        object twice = WithEfisp(once);
        Assert.Same(once, twice);
        Assert.Equal(52, TotalFileCount(twice));
    }

    [Fact]
    public void ForCapturedRoles_With_Legacy_Metadata_Reflects_Both_Flags_And_Counts()
    {
        object baseline = ForModel("TB322FC");
        List<string> captured = RequiredRoles(baseline).ToList();
        captured.Add("metadata");

        object selected = ForCapturedRoles(baseline, captured);

        Assert.True(HasLegacyMetadata(selected));
        Assert.False(HasEfisp(selected));
        Assert.Equal(52, TotalFileCount(selected));
        Assert.Equal(0, RoleLuns(selected)["metadata"]);
    }

    [Fact]
    public void WithEfisp_Preserves_Legacy_Metadata_When_Chosen()
    {
        object baseline = ForModel("TB322FC");
        List<string> captured = RequiredRoles(baseline).ToList();
        captured.Add("metadata");

        object selected = ForCapturedRoles(baseline, captured);
        object withEfisp = WithEfisp(selected);

        Assert.True(HasLegacyMetadata(withEfisp));
        Assert.True(HasEfisp(withEfisp));
        Assert.Equal(53, TotalFileCount(withEfisp));
        Assert.Contains("metadata", PartitionNames(withEfisp));
        Assert.Contains("efisp", PartitionNames(withEfisp));
        Assert.Equal(0, RoleLuns(withEfisp)["metadata"]);
        Assert.Equal(4, RoleLuns(withEfisp)["efisp"]);
    }

    [Fact]
    public void ForCapturedRoles_Rejects_Unknown_Userdata_And_Rawdump()
    {
        object baseline = ForModel("TB322FC");
        List<string> captured = RequiredRoles(baseline).ToList();

        List<string> withUserdata = captured.ToList();
        withUserdata.Add("userdata");
        Assert.Throws<System.IO.InvalidDataException>(() => ForCapturedRoles(baseline, withUserdata));

        List<string> withRawdump = captured.ToList();
        withRawdump.Add("rawdump");
        Assert.Throws<System.IO.InvalidDataException>(() => ForCapturedRoles(baseline, withRawdump));
    }

    [Fact]
    public void ForCapturedRoles_Rejects_Duplicate_Roles()
    {
        object baseline = ForModel("TB322FC");
        List<string> captured = RequiredRoles(baseline).ToList();
        captured.Add(captured[0]);

        Assert.Throws<System.IO.InvalidDataException>(() => ForCapturedRoles(baseline, captured));
    }

    [Fact]
    public void ForCapturedRoles_Rejects_Missing_Boot_A()
    {
        object baseline = ForModel("TB322FC");
        List<string> captured = RequiredRoles(baseline).Where(r => r != "boot_a").ToList();

        Assert.Throws<System.IO.InvalidDataException>(() => ForCapturedRoles(baseline, captured));
    }
}
