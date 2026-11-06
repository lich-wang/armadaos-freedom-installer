using System;
using System.Collections.Generic;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class UninstallStockBootRestorationTests
{
    private static readonly MethodInfo RequireMatchingMethod =
        typeof(UninstallStockBootRestoration).GetMethod(
            "RequireMatchingStockPlan",
            BindingFlags.NonPublic | BindingFlags.Static)
        ?? throw new InvalidOperationException("RequireMatchingStockPlan not found via reflection.");

    private const string ShaA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string ShaB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private const string ShaChangedA = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    private const string ShaChangedB = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    private const string ShaBadDesired = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    // --- Early-rejection tests: no client / runner dereference ---

    [Fact]
    public async Task RestoreAfterUninstallAsync_NullResult_Throws()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            UninstallStockBootRestoration.RestoreAfterUninstallAsync(
                null!,
                MakeStockPlan(),
                client: null!,
                originalBackupDirectory: "/backup",
                runner: null!,
                workParent: "/work"));
    }

    [Fact]
    public async Task RestoreAfterUninstallAsync_FailedUninstall_Throws()
    {
        var result = new UninstallResult(
            Success: false,
            Stage: UninstallStage.AwaitingFactoryReset,
            DataMayBeErased: true,
            VerifiedSlots: Array.Empty<string>(),
            Error: "boom");

        await Assert.ThrowsAsync<ArgumentException>(() =>
            UninstallStockBootRestoration.RestoreAfterUninstallAsync(
                result,
                MakeStockPlan(),
                client: null!,
                originalBackupDirectory: "/backup",
                runner: null!,
                workParent: "/work"));
    }

    [Theory]
    [InlineData(UninstallStage.Preflight, false)]
    [InlineData(UninstallStage.BackupCurrentBoot, false)]
    [InlineData(UninstallStage.RestoreBootA, true)]
    [InlineData(UninstallStage.ReclaimAndroidSpace, true)]
    public async Task RestoreAfterUninstallAsync_PartialUninstall_Throws(
        UninstallStage stage, bool dataMayBeErased)
    {
        var result = new UninstallResult(
            Success: true,
            Stage: stage,
            DataMayBeErased: dataMayBeErased,
            VerifiedSlots: Array.Empty<string>(),
            Error: null);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            UninstallStockBootRestoration.RestoreAfterUninstallAsync(
                result,
                MakeStockPlan(),
                client: null!,
                originalBackupDirectory: "/backup",
                runner: null!,
                workParent: "/work"));
    }

    [Fact]
    public async Task RestoreAfterUninstallAsync_DataMayBeErasedFalse_Throws()
    {
        var result = new UninstallResult(
            Success: true,
            Stage: UninstallStage.AwaitingFactoryReset,
            DataMayBeErased: false,
            VerifiedSlots: Array.Empty<string>(),
            Error: null);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            UninstallStockBootRestoration.RestoreAfterUninstallAsync(
                result,
                MakeStockPlan(),
                client: null!,
                originalBackupDirectory: "/backup",
                runner: null!,
                workParent: "/work"));
    }

    [Fact]
    public async Task RestoreAfterUninstallAsync_ActiveEmptySource_ThrowsBeforeClientAccess()
    {
        var result = new UninstallResult(
            Success: true,
            Stage: UninstallStage.AwaitingFactoryReset,
            DataMayBeErased: true,
            VerifiedSlots: new[] { "a", "b" },
            Error: null);

        var plan = MakeStockPlan(slotSourceKindOverride: new Dictionary<string, BootMaintenanceSourceKind>
        {
            ["a"] = BootMaintenanceSourceKind.Empty,
        });

        await Assert.ThrowsAsync<ArgumentException>(() =>
            UninstallStockBootRestoration.RestoreAfterUninstallAsync(
                result,
                plan,
                client: null!,
                originalBackupDirectory: "/backup",
                runner: null!,
                workParent: "/work"));
    }

    [Fact]
    public async Task RestoreAfterUninstallAsync_PreCancelled_Throws()
    {
        var result = new UninstallResult(
            Success: true,
            Stage: UninstallStage.AwaitingFactoryReset,
            DataMayBeErased: true,
            VerifiedSlots: new[] { "a", "b" },
            Error: null);

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            UninstallStockBootRestoration.RestoreAfterUninstallAsync(
                result,
                MakeStockPlan(),
                client: null!,
                originalBackupDirectory: "/backup",
                runner: null!,
                workParent: "/work",
                progress: null,
                token: cts.Token));
    }

    // --- Comparison acceptance: legitimate drift must be accepted ---

    [Fact]
    public void RequireMatchingStockPlan_AcceptsIdenticalPlans()
    {
        RequireMatching(MakeStockPlan(), MakeStockPlan(confirmationId: "different-confirmation"));
    }

    [Fact]
    public void RequireMatchingStockPlan_AcceptsChangedCurrentBeforeShaWhenFinalBytesEqual()
    {
        // Observed current-before SHA changes, but the write target remains the original stock bytes.
        var expected = MakeStockPlan();
        var actual = MakeStockPlan(
            regionShaOverride: new Dictionary<(string, string?), (string Original, string? Candidate)>
            {
                [("boot_a", "a")] = (ShaChangedA, ShaA),
                [("boot_b", "b")] = (ShaChangedB, ShaB),
            });

        RequireMatching(expected, actual);
    }

    [Fact]
    public void RequireMatchingStockPlan_AcceptsNoOpVersusWriteWithSameFinalBytes()
    {
        var desired = ShaA;
        var expected = MakeStockPlan(
            regionShaOverride: new Dictionary<(string, string?), (string Original, string? Candidate)>
            {
                [("boot_a", "a")] = (ShaChangedA, desired),
                [("boot_b", "b")] = (ShaChangedB, ShaB),
            },
            regionWillWriteOverride: true);
        var actual = MakeStockPlan(
            regionShaOverride: new Dictionary<(string, string?), (string Original, string? Candidate)>
            {
                [("boot_a", "a")] = (desired, null),
                [("boot_b", "b")] = (ShaB, null),
            },
            regionWillWriteOverride: false);

        RequireMatching(expected, actual);
    }

    [Fact]
    public void RequireMatchingStockPlan_AcceptsNewConfirmationIdAndNewEvidencePath()
    {
        RequireMatching(
            MakeStockPlan(confirmationId: "confirm-1", evidenceDir: "/evidence/1"),
            MakeStockPlan(confirmationId: "confirm-2", evidenceDir: "/evidence/2", backupDir: "/backup/2"));
    }

    [Fact]
    public void RequireMatchingStockPlan_AcceptsSameInactiveEmptySlotAcrossPlans()
    {
        // Slot B is inactive (current slot is A) and empty on both sides: legitimate, must accept.
        var expected = MakeStockPlan(
            slotSourceKindOverride: new Dictionary<string, BootMaintenanceSourceKind>
            {
                ["b"] = BootMaintenanceSourceKind.Empty,
            });
        var actual = MakeStockPlan(
            slotSourceKindOverride: new Dictionary<string, BootMaintenanceSourceKind>
            {
                ["b"] = BootMaintenanceSourceKind.Empty,
            });

        RequireMatching(expected, actual);
    }

    [Fact]
    public void RequireMatchingStockPlan_AcceptsDesiredShaCaseDifference()
    {
        var expected = MakeStockPlan();
        var actual = MakeStockPlan(
            regionShaOverride: new Dictionary<(string, string?), (string Original, string? Candidate)>
            {
                [("boot_a", "a")] = (ShaA.ToUpperInvariant(), null),
            });

        RequireMatching(expected, actual);
    }

    // --- Comparison rejection ---

    [Theory]
    [InlineData("model")]
    [InlineData("android")]
    [InlineData("soc")]
    [InlineData("slot")]
    public void RequireMatchingStockPlan_RejectsIdentityChange(string field)
    {
        var expected = MakeStockPlan();
        var actual = field switch
        {
            "model" => MakeStockPlan(model: "OtherModel"),
            "android" => MakeStockPlan(androidSerial: "OTHER-ANDROID"),
            "soc" => MakeStockPlan(socSerial: "OTHER-SOC"),
            "slot" => MakeStockPlan(currentSlot: "b"),
            _ => throw new InvalidOperationException(),
        };

        Assert.Throws<InvalidOperationException>(() => RequireMatching(expected, actual));
    }

    [Fact]
    public void RequireMatchingStockPlan_RejectsActualModeChange()
    {
        Assert.Throws<InvalidOperationException>(() =>
            RequireMatching(MakeStockPlan(), MakeStockPlan(mode: MaintenanceMode.BeforeUpdate)));
    }

    [Fact]
    public void RequireMatchingStockPlan_RejectsExpectedModeChange()
    {
        Assert.Throws<ArgumentException>(() =>
            RequireMatching(MakeStockPlan(mode: MaintenanceMode.BeforeUpdate), MakeStockPlan()));
    }

    [Fact]
    public void RequireMatchingStockPlan_RejectsRegionRoleSetChange()
    {
        var actual = MakeStockPlan(regionRoleOverride: new Dictionary<(string, string?), string>
        {
            [("boot_a", "a")] = "vendor_boot_a",
        });

        Assert.Throws<InvalidOperationException>(() => RequireMatching(MakeStockPlan(), actual));
    }

    [Fact]
    public void RequireMatchingStockPlan_RejectsExtraRegion()
    {
        Assert.Throws<InvalidOperationException>(() =>
            RequireMatching(MakeStockPlan(), MakeStockPlan(extraRegion: true)));
    }

    [Fact]
    public void RequireMatchingStockPlan_RejectsRegionExtentChange()
    {
        var actual = MakeStockPlan(
            regionExtentOverride: new Dictionary<(string, string?), (int Lun, long Start, long Count, long Length)>
            {
                [("boot_b", "b")] = (0, 4096, 512, 512 * 4096L),
            });

        Assert.Throws<InvalidOperationException>(() => RequireMatching(MakeStockPlan(), actual));
    }

    [Fact]
    public void RequireMatchingStockPlan_RejectsDesiredHashChange()
    {
        var actual = MakeStockPlan(
            regionShaOverride: new Dictionary<(string, string?), (string Original, string? Candidate)>
            {
                [("boot_a", "a")] = (ShaBadDesired, null),
            });

        Assert.Throws<InvalidOperationException>(() => RequireMatching(MakeStockPlan(), actual));
    }

    [Fact]
    public void RequireMatchingStockPlan_RejectsSlotProvenanceChange()
    {
        var actual = MakeStockPlan(
            slotProvenanceOverride: new Dictionary<string, (string SourceSlot, BootMaintenanceSourceKind Kind)>
            {
                ["b"] = ("a", BootMaintenanceSourceKind.StockOriginal),
            });

        Assert.Throws<InvalidOperationException>(() => RequireMatching(MakeStockPlan(), actual));
    }

    [Fact]
    public void RequireMatchingStockPlan_RejectsActiveEmptySlot()
    {
        // Current slot is A; both sides have empty A so identity/extent checks pass, but the
        // active-slot emptiness must be rejected by the comparison.
        var expected = MakeStockPlan(
            slotSourceKindOverride: new Dictionary<string, BootMaintenanceSourceKind>
            {
                ["a"] = BootMaintenanceSourceKind.Empty,
            });
        var actual = MakeStockPlan(
            slotSourceKindOverride: new Dictionary<string, BootMaintenanceSourceKind>
            {
                ["a"] = BootMaintenanceSourceKind.Empty,
            });

        Assert.Throws<InvalidOperationException>(() => RequireMatching(expected, actual));
    }

    // --- helpers ---

    private static void RequireMatching(BootMaintenancePrepared expected, BootMaintenancePrepared actual)
    {
        try
        {
            RequireMatchingMethod.Invoke(null, new object?[] { expected, actual });
        }
        catch (TargetInvocationException tie) when (tie.InnerException is not null)
        {
            throw tie.InnerException;
        }
    }

    private static BootMaintenancePrepared MakeStockPlan(
        string model = "TB323FU",
        string androidSerial = "SYNTH-ANDROID-1",
        string socSerial = "SYNTH-SOC-1",
        string currentSlot = "a",
        string confirmationId = "confirm-1",
        string evidenceDir = "/evidence/1",
        string backupDir = "/backup/1",
        MaintenanceMode mode = MaintenanceMode.RestoreStock,
        IDictionary<(string Role, string? Slot), (string Original, string? Candidate)>? regionShaOverride = null,
        IDictionary<(string Role, string? Slot), string>? regionRoleOverride = null,
        IDictionary<(string Role, string? Slot), (int Lun, long StartSector, long SectorCount, long Length)>? regionExtentOverride = null,
        IDictionary<string, (string SourceSlot, BootMaintenanceSourceKind Kind)>? slotProvenanceOverride = null,
        IDictionary<string, BootMaintenanceSourceKind>? slotSourceKindOverride = null,
        bool? regionWillWriteOverride = null,
        bool extraRegion = false)
    {
        var regionBase = new Dictionary<(string Role, string? Slot), (int Lun, long StartSector, long SectorCount, long Length, string Sha)>
        {
            [("boot_a", "a")] = (0, 2048, 1024, 1024 * 4096L, ShaA),
            [("boot_b", "b")] = (0, 3072, 1024, 1024 * 4096L, ShaB),
        };

        if (extraRegion)
        {
            regionBase[("vendor_boot_a", "a")] = (1, 4096, 512, 512 * 4096L, ShaA);
        }

        var regions = new List<BootMaintenanceRegionSummary>();
        foreach (KeyValuePair<(string Role, string? Slot), (int Lun, long StartSector, long SectorCount, long Length, string Sha)> entry in regionBase)
        {
            string role = regionRoleOverride is not null && regionRoleOverride.TryGetValue(entry.Key, out string? roleOverride)
                ? roleOverride
                : entry.Key.Role;

            int lun = entry.Value.Lun;
            long start = entry.Value.StartSector;
            long count = entry.Value.SectorCount;
            long length = entry.Value.Length;
            if (regionExtentOverride is not null && regionExtentOverride.TryGetValue(entry.Key, out var extent))
            {
                lun = extent.Lun;
                start = extent.StartSector;
                count = extent.SectorCount;
                length = extent.Length;
            }

            string original = entry.Value.Sha;
            string? candidate = null;
            if (regionShaOverride is not null && regionShaOverride.TryGetValue(entry.Key, out var sha))
            {
                original = sha.Original;
                candidate = sha.Candidate;
            }

            regions.Add(CreateRegion(role, entry.Key.Slot, lun, start, count, length, original, candidate, regionWillWriteOverride ?? false));
        }

        var slots = new List<BootMaintenanceSlotSummary>
        {
            CreateSlot("a", "a", BootMaintenanceSourceKind.StockOriginal, ShaA, null),
            CreateSlot("b", "b", BootMaintenanceSourceKind.StockOriginal, ShaB, null),
        };

        if (slotProvenanceOverride is not null)
        {
            for (int i = 0; i < slots.Count; i++)
            {
                string targetSlot = slots[i].Slot;
                if (slotProvenanceOverride.TryGetValue(targetSlot, out var provenance))
                {
                    slots[i] = CreateSlot(targetSlot, provenance.SourceSlot, provenance.Kind, slots[i].OriginalSha256, slots[i].CandidateSha256);
                }
            }
        }

        if (slotSourceKindOverride is not null)
        {
            for (int i = 0; i < slots.Count; i++)
            {
                string targetSlot = slots[i].Slot;
                if (slotSourceKindOverride.TryGetValue(targetSlot, out BootMaintenanceSourceKind kind))
                {
                    slots[i] = kind == BootMaintenanceSourceKind.Empty
                        ? CreateSlot(targetSlot, targetSlot, BootMaintenanceSourceKind.Empty, string.Empty, null)
                        : CreateSlot(targetSlot, slots[i].SourceSlot, kind, slots[i].OriginalSha256, slots[i].CandidateSha256);
                }
            }
        }

        return CreatePrepared(
            mode,
            confirmationId,
            model,
            androidSerial,
            socSerial,
            currentSlot,
            backupDir,
            evidenceDir,
            slots,
            regions);
    }

    private static BootMaintenanceRegionSummary CreateRegion(
        string role,
        string? slot,
        int lun,
        long startSector,
        long sectorCount,
        long length,
        string originalSha,
        string? candidateSha,
        bool willWrite)
    {
        return (BootMaintenanceRegionSummary)Activator.CreateInstance(
            typeof(BootMaintenanceRegionSummary),
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            args: new object?[] { role, slot, lun, startSector, sectorCount, length, originalSha, candidateSha, willWrite },
            culture: null)!;
    }

    private static BootMaintenanceSlotSummary CreateSlot(
        string slot,
        string sourceSlot,
        BootMaintenanceSourceKind sourceKind,
        string originalSha,
        string? candidateSha)
    {
        bool willWrite = sourceKind == BootMaintenanceSourceKind.Project;
        return (BootMaintenanceSlotSummary)Activator.CreateInstance(
            typeof(BootMaintenanceSlotSummary),
            BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public,
            binder: null,
            args: new object?[] { slot, sourceSlot, sourceKind, originalSha, candidateSha, willWrite },
            culture: null)!;
    }

    private static BootMaintenancePrepared CreatePrepared(
        MaintenanceMode mode,
        string confirmationId,
        string model,
        string androidSerial,
        string socSerial,
        string currentSlot,
        string backupDir,
        string evidenceDir,
        IReadOnlyList<BootMaintenanceSlotSummary> slots,
        IReadOnlyList<BootMaintenanceRegionSummary> regions)
    {
        return (BootMaintenancePrepared)Activator.CreateInstance(
            typeof(BootMaintenancePrepared),
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            args: new object?[]
            {
                mode,
                confirmationId,
                model,
                androidSerial,
                socSerial,
                currentSlot,
                backupDir,
                evidenceDir,
                BootMaintenanceBootTrust.StockOriginal,
                slots,
                regions,
            },
            culture: null)!;
    }
}
