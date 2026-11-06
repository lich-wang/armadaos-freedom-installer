using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// Restores the stock boot plan after a successful uninstall has reached
/// <see cref="UninstallStage.AwaitingFactoryReset"/>. Re-captures current device state,
/// re-prepares the stock boot plan via the EDL backend, verifies it still matches the previously
/// confirmed plan (ignoring legitimately new confirmation ids, current-before SHAs, evidence
/// paths and WillWrite flags so long as the desired final bytes and provenance match), then
/// executes the fresh plan's own execute path. No fallbacks, retries, weaker modes or direct
/// resets are performed here.
/// </summary>
public static class UninstallStockBootRestoration
{
    public static async Task<BootMaintenanceResult> RestoreAfterUninstallAsync(
        UninstallResult uninstallResult,
        BootMaintenancePrepared expectedStockPlan,
        EdlClient client,
        string originalBackupDirectory,
        ICommandRunner runner,
        string workParent,
        IProgress<InternalInstallProgress>? progress = null,
        CancellationToken token = default)
    {
        // Reject unusable uninstall outcomes and plans BEFORE any device I/O or client access.
        ArgumentNullException.ThrowIfNull(uninstallResult);

        if (!uninstallResult.Success ||
            uninstallResult.Stage != UninstallStage.AwaitingFactoryReset ||
            !uninstallResult.DataMayBeErased)
        {
            throw new ArgumentException(
                "Stock boot restoration requires a successful uninstall that is awaiting factory reset "
                + "and whose data may already have been erased.",
                nameof(uninstallResult));
        }

        token.ThrowIfCancellationRequested();

        ArgumentNullException.ThrowIfNull(expectedStockPlan);

        if (expectedStockPlan.Mode != MaintenanceMode.RestoreStock)
        {
            throw new ArgumentException(
                "The expected stock boot plan must be in RestoreStock mode.",
                nameof(expectedStockPlan));
        }

        RequireActiveStockPlan(expectedStockPlan);

        token.ThrowIfCancellationRequested();

        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(runner);
        ArgumentNullException.ThrowIfNull(originalBackupDirectory);
        ArgumentNullException.ThrowIfNull(workParent);

        if (string.IsNullOrWhiteSpace(originalBackupDirectory))
        {
            throw new ArgumentException(
                "The original backup directory must be a non-empty path.",
                nameof(originalBackupDirectory));
        }

        if (string.IsNullOrWhiteSpace(workParent))
        {
            throw new ArgumentException(
                "The work parent directory must be a non-empty path.",
                nameof(workParent));
        }

        token.ThrowIfCancellationRequested();

        using InternalBackupSet fresh = await InternalInstallBackup
            .CreateAsync(client, workParent, progress: null, token)
            .ConfigureAwait(false);

        BootMaintenanceHistoricalIdentity history = await BootMaintenanceBackend
            .ReadHistoricalIdentityAsync(fresh.DirectoryPath, token)
            .ConfigureAwait(false);

        using BootMaintenanceBackend stock = await BootMaintenanceBackend
            .CreatePreparedFromEdlAsync(
                MaintenanceMode.RestoreStock,
                history,
                client,
                fresh,
                new BootMaintenanceSources(OriginalBackupDirectory: originalBackupDirectory),
                runner,
                workParent,
                progress,
                token)
            .ConfigureAwait(false);

        token.ThrowIfCancellationRequested();

        RequireMatchingStockPlan(expectedStockPlan, stock.Prepared);

        token.ThrowIfCancellationRequested();

        return await stock
            .ExecuteAsync(stock.Prepared.ConfirmationId, progress, token)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Rejects an expected plan that has no active stock source for the current slot; such a plan
    /// could not restore the device to a bootable state and must never reach the device.
    /// </summary>
    private static void RequireActiveStockPlan(BootMaintenancePrepared plan)
    {
        bool found = false;

        foreach (BootMaintenanceSlotSummary slot in plan.Slots)
        {
            if (string.Equals(slot.Slot, plan.CurrentSlot, StringComparison.Ordinal))
            {
                found = true;
                if (slot.SourceKind == BootMaintenanceSourceKind.Empty)
                {
                    throw new ArgumentException(
                        "The expected stock plan has an empty active source slot.",
                        nameof(plan));
                }
            }
        }

        if (!found)
        {
            throw new ArgumentException(
                "The expected stock plan has no slot summary for its current slot.",
                nameof(plan));
        }
    }

    /// <summary>
    /// Verifies the freshly prepared stock plan still matches the confirmed plan on everything that
    /// determines installed bytes: mode, device identity, current slot, exact region key set
    /// (Role, Slot) with extents, desired final SHA per region, and slot provenance
    /// (SourceSlot + SourceKind). Legitimately new confirmation ids, backup/evidence paths, changed
    /// current-before SHAs and switching between no-op and write are ignored so long as the desired
    /// final bytes and slot provenance match. Only an inactive slot may be empty on either side.
    /// </summary>
    internal static void RequireMatchingStockPlan(
        BootMaintenancePrepared expected,
        BootMaintenancePrepared actual)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(actual);

        if (expected.Mode != MaintenanceMode.RestoreStock)
        {
            throw new ArgumentException(
                "The expected stock plan must be in RestoreStock mode.",
                nameof(expected));
        }

        if (actual.Mode != MaintenanceMode.RestoreStock)
        {
            throw new InvalidOperationException(
                $"The freshly prepared plan is in {actual.Mode} mode instead of RestoreStock.");
        }

        if (!string.Equals(expected.Model, actual.Model, StringComparison.Ordinal) ||
            !string.Equals(expected.AndroidSerial, actual.AndroidSerial, StringComparison.Ordinal) ||
            !string.Equals(expected.SocSerial, actual.SocSerial, StringComparison.Ordinal) ||
            !string.Equals(expected.CurrentSlot, actual.CurrentSlot, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The freshly prepared stock plan reports a different device identity or current slot.");
        }

        RequireMatchingRegions(expected, actual);
        RequireMatchingSlots(expected, actual);
    }

    private static void RequireMatchingRegions(
        BootMaintenancePrepared expected,
        BootMaintenancePrepared actual)
    {
        Dictionary<(string Role, string? Slot), BootMaintenanceRegionSummary> expectedByKey =
            IndexRegions(expected, "expected");
        Dictionary<(string Role, string? Slot), BootMaintenanceRegionSummary> actualByKey =
            IndexRegions(actual, "freshly prepared");

        if (expectedByKey.Count != actualByKey.Count)
        {
            throw new InvalidOperationException(
                $"The freshly prepared stock plan has {actualByKey.Count} regions; the expected plan has {expectedByKey.Count}.");
        }

        foreach (KeyValuePair<(string Role, string? Slot), BootMaintenanceRegionSummary> entry in expectedByKey)
        {
            if (!actualByKey.TryGetValue(entry.Key, out BootMaintenanceRegionSummary? actualRegion))
            {
                throw new InvalidOperationException(
                    $"The freshly prepared stock plan is missing the region {FormatKey(entry.Key)}.");
            }

            BootMaintenanceRegionSummary expectedRegion = entry.Value;

            if (expectedRegion.Lun != actualRegion.Lun ||
                expectedRegion.StartSector != actualRegion.StartSector ||
                expectedRegion.SectorCount != actualRegion.SectorCount ||
                expectedRegion.Length != actualRegion.Length)
            {
                throw new InvalidOperationException(
                    $"The freshly prepared stock plan changed the extent of region {FormatKey(entry.Key)}.");
            }

            if (!string.Equals(
                    DesiredFinalSha(expectedRegion),
                    DesiredFinalSha(actualRegion),
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"The freshly prepared stock plan changed the desired final bytes of region {FormatKey(entry.Key)}.");
            }
        }
    }

    private static void RequireMatchingSlots(
        BootMaintenancePrepared expected,
        BootMaintenancePrepared actual)
    {
        Dictionary<string, BootMaintenanceSlotSummary> expectedBySlot =
            IndexSlots(expected, "expected");
        Dictionary<string, BootMaintenanceSlotSummary> actualBySlot =
            IndexSlots(actual, "freshly prepared");

        if (expectedBySlot.Count != actualBySlot.Count)
        {
            throw new InvalidOperationException(
                $"The freshly prepared stock plan has {actualBySlot.Count} slot summaries; the expected plan has {expectedBySlot.Count}.");
        }

        foreach (KeyValuePair<string, BootMaintenanceSlotSummary> entry in expectedBySlot)
        {
            if (!actualBySlot.TryGetValue(entry.Key, out BootMaintenanceSlotSummary? actualSlot))
            {
                throw new InvalidOperationException(
                    $"The freshly prepared stock plan is missing the slot summary for '{entry.Key}'.");
            }

            BootMaintenanceSlotSummary expectedSlot = entry.Value;

            if (expectedSlot.SourceKind != actualSlot.SourceKind ||
                !string.Equals(expectedSlot.SourceSlot, actualSlot.SourceSlot, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"The freshly prepared stock plan changed the source provenance for slot '{entry.Key}'.");
            }

            bool isCurrentSlot = string.Equals(entry.Key, expected.CurrentSlot, StringComparison.Ordinal);
            if (expectedSlot.SourceKind == BootMaintenanceSourceKind.Empty && isCurrentSlot)
            {
                throw new InvalidOperationException(
                    $"The freshly prepared stock plan has an empty active source for current slot '{entry.Key}'.");
            }
        }
    }

    private static Dictionary<(string Role, string? Slot), BootMaintenanceRegionSummary> IndexRegions(
        BootMaintenancePrepared plan,
        string label)
    {
        var map = new Dictionary<(string Role, string? Slot), BootMaintenanceRegionSummary>(
            plan.Regions.Count);

        foreach (BootMaintenanceRegionSummary region in plan.Regions)
        {
            if (region is null)
            {
                throw new InvalidOperationException(
                    $"The {label} stock plan contains a null region entry.");
            }

            var key = (region.Role, region.Slot);
            if (map.ContainsKey(key))
            {
                throw new InvalidOperationException(
                    $"The {label} stock plan contains a duplicate region key {FormatKey(key)}.");
            }

            map.Add(key, region);
        }

        return map;
    }

    private static Dictionary<string, BootMaintenanceSlotSummary> IndexSlots(
        BootMaintenancePrepared plan,
        string label)
    {
        var map = new Dictionary<string, BootMaintenanceSlotSummary>(plan.Slots.Count, StringComparer.Ordinal);

        foreach (BootMaintenanceSlotSummary slot in plan.Slots)
        {
            if (slot is null)
            {
                throw new InvalidOperationException(
                    $"The {label} stock plan contains a null slot summary entry.");
            }

            if (map.ContainsKey(slot.Slot))
            {
                throw new InvalidOperationException(
                    $"The {label} stock plan contains a duplicate slot summary for '{slot.Slot}'.");
            }

            map.Add(slot.Slot, slot);
        }

        return map;
    }

    private static string DesiredFinalSha(BootMaintenanceRegionSummary region) =>
        region.CandidateSha256 ?? region.OriginalSha256;

    private static string FormatKey((string Role, string? Slot) key) =>
        key.Slot is null ? key.Role : $"{key.Role}@{key.Slot}";
}
