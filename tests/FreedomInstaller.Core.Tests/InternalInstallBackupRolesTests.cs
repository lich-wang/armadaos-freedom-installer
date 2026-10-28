#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Xunit;

namespace FreedomInstaller.Core.Tests
{
    /// <summary>
    /// Model-specific backup role contract checks.
    /// </summary>
    public sealed class InternalInstallBackupRolesTests
    {
        private const string RolesTypeName = "FreedomInstaller.Core.InternalInstallBackupRoles";

        private const BindingFlags StaticFlags =
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static;

        private const BindingFlags InstanceFlags =
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance;

        private const string G4Model = "TB322FC";
        private const string G5Model = "TB323FU";

        private const int G4PartitionCount = 39;
        private const int G4FileCount = 51;
        private const int G5PartitionCount = 35;
        private const int G5FileCount = 47;

        private const int GptRoleCount = 12;
        private const int LunCount = 6;

        /// <summary>Partitions present on G4 that G5 does not carry.</summary>
        private static readonly string[] G4OnlyPartitions =
        {
            "proinfo", "lenovolock", "lenovocust", "lenovoraw"
        };

        /// <summary>G5 roles that must exist in both A and B slots.</summary>
        private static readonly string[] G5SlottedRoles =
        {
            "boot", "vendor_boot", "init_boot", "abl", "xbl_config", "dtbo", "vbmeta", "recovery"
        };

        /// <summary>G5 roles that must exist exactly once (no slot suffix).</summary>
        private static readonly string[] G5SingleRoles =
        {
            "persist", "modemst1", "modemst2", "fsg", "fsc"
        };

        [Fact]
        public void ForModel_G4_TB322FC_DescribesThirtyNinePartitionsAndTwelveGptRoles()
        {
            object roles = CreateRoles(G4Model);

            IReadOnlyList<(int Lun, string Name)> partitions =
                GetProperty<IReadOnlyList<(int Lun, string Name)>>(roles, "Partitions");
            IReadOnlyList<string> partitionNames =
                GetProperty<IReadOnlyList<string>>(roles, "PartitionNames");
            IReadOnlyList<string> requiredRoles =
                GetProperty<IReadOnlyList<string>>(roles, "RequiredRoles");
            IReadOnlyDictionary<string, int> roleLuns =
                GetProperty<IReadOnlyDictionary<string, int>>(roles, "RoleLuns");
            int totalFileCount = GetInt32(roles, "TotalFileCount");

            Assert.Equal(G4PartitionCount, partitions.Count);
            Assert.Equal(G4PartitionCount, partitionNames.Count);
            Assert.Equal(partitions.Select(p => p.Name).ToList(), partitionNames.ToList());

            Assert.Equal(G4FileCount, totalFileCount);
            Assert.Equal(G4FileCount, requiredRoles.Count);
            Assert.Equal(requiredRoles.Count, roleLuns.Count);

            // Twelve GPT roles first, then every partition name, in partition order.
            Assert.Equal(partitionNames.ToList(), requiredRoles.Skip(GptRoleCount).ToList());
            AssertGptRoleBlock(requiredRoles, roleLuns);

            // Required roles are unique and each partition name maps back to its own LUN.
            Assert.Equal(
                requiredRoles.Count,
                requiredRoles.Distinct(StringComparer.OrdinalIgnoreCase).Count());
            AssertKeysMatchRoles(requiredRoles, roleLuns);
            AssertRoleLunsMatchPartitions(partitions, roleLuns);

            // The four G4-only partitions are mandatory on G4 and live on LUN 0.
            foreach (string name in G4OnlyPartitions)
            {
                Assert.True(Contains(partitionNames, name), "G4 must expose partition '" + name + "'.");
                Assert.True(
                    TryGetLun(roleLuns, name, out int lun),
                    "G4 RoleLuns must contain '" + name + "'.");
                Assert.Equal(0, lun);
            }
        }

        [Fact]
        public void ForModel_G5_TB323FU_DropsTheFourG4OnlyPartitionsAndKeepsRequiredRoles()
        {
            object g4 = CreateRoles(G4Model);
            IReadOnlyList<(int Lun, string Name)> g4Partitions =
                GetProperty<IReadOnlyList<(int Lun, string Name)>>(g4, "Partitions");
            IReadOnlyList<string> g4Names = GetProperty<IReadOnlyList<string>>(g4, "PartitionNames");

            object g5 = CreateRoles(G5Model);
            IReadOnlyList<(int Lun, string Name)> partitions =
                GetProperty<IReadOnlyList<(int Lun, string Name)>>(g5, "Partitions");
            IReadOnlyList<string> partitionNames =
                GetProperty<IReadOnlyList<string>>(g5, "PartitionNames");
            IReadOnlyList<string> requiredRoles =
                GetProperty<IReadOnlyList<string>>(g5, "RequiredRoles");
            IReadOnlyDictionary<string, int> roleLuns =
                GetProperty<IReadOnlyDictionary<string, int>>(g5, "RoleLuns");
            int totalFileCount = GetInt32(g5, "TotalFileCount");

            Assert.Equal(G5PartitionCount, partitions.Count);
            Assert.Equal(G5PartitionCount, partitionNames.Count);
            Assert.Equal(partitions.Select(p => p.Name).ToList(), partitionNames.ToList());

            Assert.Equal(G5FileCount, totalFileCount);
            Assert.Equal(G5FileCount, requiredRoles.Count);

            // G5 keeps the G4 sequence minus proinfo / lenovolock / lenovocust / lenovoraw.
            List<string> expectedNames = g4Names
                .Where(n => !G4OnlyPartitions.Any(o => string.Equals(o, n, StringComparison.OrdinalIgnoreCase)))
                .ToList();
            Assert.Equal(expectedNames, partitionNames.ToList());

            foreach (string name in G4OnlyPartitions)
            {
                Assert.False(
                    Contains(partitionNames, name),
                    "G5 must not carry G4-only partition '" + name + "'.");
            }

            // Same role/partition layout as G4: twelve GPT roles first, then the partition names.
            Assert.Equal(partitionNames.ToList(), requiredRoles.Skip(GptRoleCount).ToList());
            AssertGptRoleBlock(requiredRoles, roleLuns);
            Assert.Equal(
                requiredRoles.Count,
                requiredRoles.Distinct(StringComparer.OrdinalIgnoreCase).Count());
            AssertKeysMatchRoles(requiredRoles, roleLuns);
            AssertRoleLunsMatchPartitions(partitions, roleLuns);

            // G5 required roles: A/B boot images plus the single-instance persist/modem roles.
            foreach (string role in G5SlottedRoles)
            {
                Assert.True(Contains(requiredRoles, role + "_a"), "G5 must require '" + role + "_a'.");
                Assert.True(Contains(requiredRoles, role + "_b"), "G5 must require '" + role + "_b'.");
            }

            foreach (string role in G5SingleRoles)
            {
                Assert.True(Contains(requiredRoles, role), "G5 must require '" + role + "'.");
            }
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        [InlineData("   ")]
        [InlineData("\t")]
        [InlineData("TB999")]
        [InlineData(" TB322FC ")]
        public void ForModel_UnknownOrBlankModel_ThrowsArgumentException(string? model)
        {
            Exception? failure = CaptureFailure(model);

            Assert.NotNull(failure);
            Assert.IsAssignableFrom<ArgumentException>(failure);
        }

        private static void AssertGptRoleBlock(
            IReadOnlyList<string> requiredRoles,
            IReadOnlyDictionary<string, int> roleLuns)
        {
            Assert.True(
                requiredRoles.Count >= GptRoleCount,
                "RequiredRoles must start with " + GptRoleCount + " GPT roles.");

            List<string> gptRoles = requiredRoles.Take(GptRoleCount).ToList();

            for (int lun = 0; lun < LunCount; lun++)
            {
                List<string> onLun = gptRoles
                    .Where(role => TryGetLun(roleLuns, role, out int mapped) && mapped == lun)
                    .ToList();

                Assert.True(
                    onLun.Count == 2,
                    "GPT roles for LUN " + lun + " must be exactly a primary/backup pair, found " + onLun.Count + ".");

                Assert.True(
                    onLun.Any(role => role.IndexOf("primary", StringComparison.OrdinalIgnoreCase) >= 0),
                    "LUN " + lun + " must expose a primary GPT role.");
                Assert.True(
                    onLun.Any(role => role.IndexOf("backup", StringComparison.OrdinalIgnoreCase) >= 0),
                    "LUN " + lun + " must expose a backup GPT role.");
            }

            foreach (string role in gptRoles)
            {
                Assert.True(
                    TryGetLun(roleLuns, role, out int mapped),
                    "GPT role '" + role + "' must be mapped in RoleLuns.");
                Assert.InRange(mapped, 0, LunCount - 1);
            }
        }

        private static void AssertKeysMatchRoles(
            IReadOnlyList<string> requiredRoles,
            IReadOnlyDictionary<string, int> roleLuns)
        {
            HashSet<string> roleSet = new HashSet<string>(requiredRoles, StringComparer.OrdinalIgnoreCase);
            Assert.True(
                roleSet.SetEquals(roleLuns.Keys),
                "RoleLuns must contain exactly the required roles.");
        }

        private static void AssertRoleLunsMatchPartitions(
            IReadOnlyList<(int Lun, string Name)> partitions,
            IReadOnlyDictionary<string, int> roleLuns)
        {
            foreach ((int lun, string name) in partitions)
            {
                Assert.True(
                    TryGetLun(roleLuns, name, out int mapped),
                    "Partition role '" + name + "' must be mapped in RoleLuns.");
                Assert.True(
                    mapped == lun,
                    "Partition role '" + name + "' must map to LUN " + lun + " but mapped to " + mapped + ".");
            }
        }

        private static object CreateRoles(string model)
        {
            Type rolesType = ResolveRolesType();
            MethodInfo method = GetForModelMethod(rolesType);

            try
            {
                object? created = method.Invoke(null, new object?[] { model });
                Assert.NotNull(created);
                Assert.Equal(rolesType, created!.GetType());
                return created;
            }
            catch (TargetInvocationException ex) when (ex.InnerException != null)
            {
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
                throw;
            }
        }

        private static Exception? CaptureFailure(string? model)
        {
            MethodInfo method = GetForModelMethod(ResolveRolesType());

            try
            {
                method.Invoke(null, new object?[] { model });
                return null;
            }
            catch (TargetInvocationException ex)
            {
                return ex.InnerException ?? ex;
            }
        }

        private static MethodInfo GetForModelMethod(Type rolesType)
        {
            MethodInfo method = rolesType.GetMethod(
                "ForModel",
                StaticFlags,
                binder: null,
                types: new[] { typeof(string) },
                modifiers: null)!;

            Assert.NotNull(method);
            Assert.Equal(rolesType, method!.ReturnType);
            return method;
        }

        private static Type ResolveRolesType()
        {
            Type? type = typeof(InternalInstallBackup).Assembly.GetType(RolesTypeName, throwOnError: false);
            Assert.NotNull(type);
            return type!;
        }

        private static T GetProperty<T>(object instance, string name)
            where T : class
        {
            PropertyInfo property = instance.GetType().GetProperty(name, InstanceFlags)!;
            Assert.NotNull(property);

            object? value = property!.GetValue(instance);
            Assert.NotNull(value);
            return Assert.IsAssignableFrom<T>(value);
        }

        private static int GetInt32(object instance, string name)
        {
            PropertyInfo property = instance.GetType().GetProperty(name, InstanceFlags)!;
            Assert.NotNull(property);

            object? value = property!.GetValue(instance);
            Assert.NotNull(value);
            Assert.Equal(typeof(int), value!.GetType());
            return (int)value;
        }

        private static bool Contains(IEnumerable<string> values, string candidate)
        {
            return values.Any(v => string.Equals(v, candidate, StringComparison.OrdinalIgnoreCase));
        }

        private static bool TryGetLun(IReadOnlyDictionary<string, int> roleLuns, string role, out int lun)
        {
            foreach (KeyValuePair<string, int> pair in roleLuns)
            {
                if (string.Equals(pair.Key, role, StringComparison.OrdinalIgnoreCase))
                {
                    lun = pair.Value;
                    return true;
                }
            }

            lun = -1;
            return false;
        }
    }
}
