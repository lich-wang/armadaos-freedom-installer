using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace FreedomInstaller.Core.Tests;

// exactly the two real public cross-epoch initialized-B integration facts.
// The same-epoch full A/B repair is already covered green by BootMaintenanceAfterUpdateTests and is
// NOT re-claimed here. Both facts drive the public Check -> Backup -> CreatePreparedAsync path over
// the frozen EdlUninstallCurrentMenuTests harness, and Fact 1 continues into Execute. No constructed
// proof types, no reflection witnesses, no method-existence probes — only real files and typed returns.
public sealed class BootMaintenanceAfterEpochTests :
    IClassFixture<EdlClientToolchainFixture>,
    IClassFixture<EdlRawGblEnvelopeTests.SharedFixture>
{
    private readonly EdlClientToolchainFixture Toolchain;
    private readonly EdlRawGblEnvelopeTests.SharedFixture Shared;

    public BootMaintenanceAfterEpochTests(
        EdlClientToolchainFixture toolchain,
        EdlRawGblEnvelopeTests.SharedFixture shared)
    {
        Toolchain = toolchain;
        Shared = shared;
    }

    // Independent hard-coded allowed write roles for an AfterUpdate execution; never derived from
    // the prepared plan. Every observed write must additionally match exactly one WillWrite region.
    private static readonly string[] AllowedWriteRoles =
    {
        "boot_a", "boot_b",
        "recovery_a", "recovery_b",
        "vbmeta_system_a", "vbmeta_system_b",
        "vbmeta_a", "vbmeta_b",
        "efisp",
    };

    [Fact]
    public async Task After_CrossEpoch_OldTemplateB_NewStockA_WitnessesAndExecutesVerified()
    {
        using EpochCase run = await PrepareEpochCaseAsync();
        Assert.Equal(0, run.Harness.Ib.Writes.Count);
        Assert.Equal(0, run.Harness.Ib.ResetCount);

        string evidenceParent = Path.Combine(run.Harness.CaseDirectory, "evidence");
        Directory.CreateDirectory(evidenceParent);
        var sources = new BootMaintenanceSources(
            BootTools: Shared.Tools, OriginalBackupDirectory: run.OldDirectory);
        BootMaintenanceBackend backend = await BootMaintenanceBackend.CreatePreparedAsync(
            MaintenanceMode.AfterUpdate, run.Check, run.Harness.Client, run.Fresh, sources,
            Shared.Runner, evidenceParent, progress: null, cancellationToken: default);

        try
        {
            BootMaintenancePrepared prepared = backend.Prepared;
            Assert.Equal(MaintenanceMode.AfterUpdate, prepared.Mode);
            Assert.Equal("a", prepared.CurrentSlot);
            Assert.Equal(2, prepared.Slots.Count);
            Assert.Equal(new[] { "a", "b" }, prepared.Slots.Select(s => s.Slot).OrderBy(x => x).ToArray());
            foreach (BootMaintenanceSlotSummary slot in prepared.Slots)
            {
                Assert.Equal("a", slot.SourceSlot);
            }

            BootMaintenanceRegionSummary bootB = prepared.Regions.Single(r => r.Role == "boot_b");
            BootMaintenanceRegionSummary bootA = prepared.Regions.Single(r => r.Role == "boot_a");
            Assert.True(bootB.WillWrite);
            Assert.True(bootA.WillWrite);
            Assert.False(string.Equals(bootB.OriginalSha256, bootB.CandidateSha256, StringComparison.OrdinalIgnoreCase));
            Assert.False(string.Equals(bootA.OriginalSha256, bootA.CandidateSha256, StringComparison.OrdinalIgnoreCase));

            // ---- cross-epoch witness proof: this exact branch ran, not the full same-epoch A/B. ----
            string witnessPath = Path.Combine(prepared.EvidenceDirectory, "after-epoch-witness.json");
            string reportPath = Path.Combine(prepared.EvidenceDirectory, "after-epoch-witness.report.json");
            Assert.True(File.Exists(witnessPath));
            Assert.True(File.Exists(reportPath));
            Assert.False(string.Equals(Sha256File(witnessPath), Sha256File(reportPath), StringComparison.OrdinalIgnoreCase));

            using (JsonDocument witness = JsonDocument.Parse(File.ReadAllText(witnessPath)))
            {
                JsonElement root = witness.RootElement;
                Assert.Equal("after-epoch-witness", root.GetProperty("kind").GetString());
                Assert.Equal("a", root.GetProperty("sourceSlot").GetString());
                Assert.Equal("b", root.GetProperty("targetSlot").GetString());
                Assert.Equal(run.OldBaseSha, root.GetProperty("templateBasisBaseSha256").GetString(), ignoreCase: true);
                Assert.Equal(run.FreshBaseSha, root.GetProperty("freshBaseSha256").GetString(), ignoreCase: true);
                Assert.Equal("a", root.GetProperty("androidSourceSlot").GetString());
                Assert.Equal("b", root.GetProperty("templateTargetSlot").GetString());
                Assert.False(root.GetProperty("isSameEpoch").GetBoolean());
                Assert.Equal(run.OldDirectory, root.GetProperty("originalBackupDirectory").GetString());
                Assert.Equal(Sha256File(reportPath), root.GetProperty("verificationReportSha256").GetString(), ignoreCase: true);
            }

            using (JsonDocument report = JsonDocument.Parse(File.ReadAllText(reportPath)))
            {
                JsonElement root = report.RootElement;
                Assert.Equal(run.OldBaseSha, root.GetProperty("templateBasisBaseSha256").GetString(), ignoreCase: true);
                Assert.Equal(run.FreshBaseSha, root.GetProperty("freshABaseSha256").GetString(), ignoreCase: true);
                Assert.Equal("a", root.GetProperty("actualCurrentSlot").GetString());
                Assert.Equal("b", root.GetProperty("targetSlot").GetString());
                Assert.False(root.GetProperty("isSameEpoch").GetBoolean());
            }

            Assert.NotEqual(run.OldBaseSha, run.FreshBaseSha);

            int writesBefore = run.Harness.Ib.Writes.Count;
            int readsBefore = run.Harness.Ib.Reads.Count;
            int resetsBefore = run.Harness.Ib.ResetCount;

            BootMaintenanceResult result = await backend.ExecuteAsync(
                prepared.ConfirmationId, progress: null, cancellationToken: default);

            Assert.Equal(BootMaintenanceOutcome.Completed, result.Outcome);
            Assert.Equal(InternalInstallWriteState.AllVerified, result.WriteState);
            Assert.Null(result.Error);
            Assert.True(result.AwaitingAndroidAcceptance);
            Assert.Equal(resetsBefore + 1, run.Harness.Ib.ResetCount);

            List<IB001Write> newWrites = run.Harness.Ib.Writes.Skip(writesBefore).ToList();
            Assert.Equal(prepared.Regions.Count(r => r.WillWrite), newWrites.Count);
            var bootOrder = new List<string>();
            foreach (IB001Write write in newWrites)
            {
                BootMaintenanceRegionSummary region = Assert.Single(prepared.Regions.Where(r =>
                    r.WillWrite &&
                    r.Lun == write.Lun &&
                    r.StartSector == write.StartSector &&
                    r.SectorCount == write.SectorCount));
                Assert.Contains(region.Role, AllowedWriteRoles);
                Assert.Equal(region.Length, new FileInfo(write.FilePath).Length);
                Assert.Equal(region.CandidateSha256, write.Sha256, ignoreCase: true);
                IB001Read readBack = run.Harness.Ib.Reads.Skip(readsBefore).Last(r =>
                    r.Lun == region.Lun &&
                    r.StartSector == region.StartSector &&
                    r.SectorCount == region.SectorCount);
                Assert.Equal(region.CandidateSha256, Sha256File(readBack.FilePath), ignoreCase: true);
                if (region.Role is "boot_a" or "boot_b")
                {
                    bootOrder.Add(region.Role);
                    Assert.Contains(region.Role, result.VerifiedRegions);
                }
            }

            Assert.Equal(new[] { "boot_b", "boot_a" }, bootOrder.ToArray());
        }
        finally
        {
            BestEffortDispose(backend);
        }
    }

    [Fact]
    public async Task After_CrossEpoch_MissingOriginalBackupDirectory_RejectsWithoutWrites()
    {
        using EpochCase run = await PrepareEpochCaseAsync();
        int writesBefore = run.Harness.Ib.Writes.Count;
        int resetsBefore = run.Harness.Ib.ResetCount;

        string evidenceParent = Path.Combine(run.Harness.CaseDirectory, "evidence");
        Directory.CreateDirectory(evidenceParent);
        var sources = new BootMaintenanceSources(BootTools: Shared.Tools);

        InvalidOperationException failure = await Assert.ThrowsAsync<InvalidOperationException>(
            () => BootMaintenanceBackend.CreatePreparedAsync(
                MaintenanceMode.AfterUpdate, run.Check, run.Harness.Client, run.Fresh, sources,
                Shared.Runner, evidenceParent, progress: null, cancellationToken: default));

        Assert.StartsWith("boot-maintenance-template-epoch-unproven:", failure.Message);
        Assert.Equal(writesBefore, run.Harness.Ib.Writes.Count);
        Assert.Equal(resetsBefore, run.Harness.Ib.ResetCount);
    }

    // ------------------------------------------------------------------

    private async Task<EpochCase> PrepareEpochCaseAsync()
    {
        var frozen = new EdlUninstallCurrentMenuTests(Toolchain, Shared);
        EdlUninstallCurrentMenuTests.Harness h = await frozen.PrepareAsync();

        EdlRawBootBuilderTests.Workspace? oldWorkspace = null;
        EdlRawBootBuilderTests.Workspace? freshWorkspace = null;
        DirectAvbSourceTestFixture? aosp = null;
        InternalBackupSet? fresh = null;
        try
        {
            // Two DIFFERENT workspaces: both CreateSlot(..., "a", ...) write the same fixed slot-a
            // filenames with CreateNew, so a single shared workspace would collide.
            oldWorkspace = new();
            EdlRawBootBuilderTests.SlotFixture oldSlot = EdlRawBootBuilderTests.CreateSlot(oldWorkspace, "a", 0x31);
            freshWorkspace = new();
            EdlRawBootBuilderTests.SlotFixture freshSlot = EdlRawBootBuilderTests.CreateSlot(freshWorkspace, "a", 0x91);
            aosp = new(DirectAvbSourceKind.Aosp);

            string oldBaseSha = oldSlot.BaseSha256;
            string freshBaseSha = freshSlot.BaseSha256;
            Assert.Equal(Shared.NormalBuilt.BaseImage.Sha256, oldBaseSha, ignoreCase: true);
            Assert.NotEqual(oldBaseSha, freshBaseSha);

            // ---- FIRST capture (original epoch): old stock A on boot_a, while physical boot_b and
            //      its four aux roles are still raw zeros. Every other role stays untouched. ----
            VerifiedEdlFile oldStockA = aosp.A.RewriteBootLeaf(oldSlot.CurrentBoot.Path);
            EdlCapturedRegion bootA = h.Current.Files["boot_a"];
            h.Device.AddWriteOverlay(bootA.Lun, bootA.StartSector, bootA.SectorCount, oldStockA.Path);

            foreach (string role in new[] { "boot_b", "vendor_boot_b", "init_boot_b", "abl_b", "xbl_config_b" })
            {
                EdlCapturedRegion region = h.Current.Files[role];
                string zeroPath = Path.Combine(h.CaseDirectory, "zero-" + role + ".bin");
                using (FileStream zeros = new FileStream(zeroPath, FileMode.CreateNew, FileAccess.Write))
                {
                    zeros.SetLength(region.Length);
                }
                h.Device.AddWriteOverlay(region.Lun, region.StartSector, region.SectorCount, zeroPath);
            }

            string oldParent = Path.Combine(h.CaseDirectory, "old-epoch");
            Directory.CreateDirectory(oldParent);
            InternalBackupSet oldBackup = await InternalInstallBackup.CreateAsync(h.Client, oldParent);
            string oldDirectory = oldBackup.DirectoryPath;
            oldBackup.Dispose(); // the genuine captured files remain available after the lease is released

            // ---- SECOND capture: initialized B over old A, then the OTA changed A to new stock
            //      (seed 91). The B aux roles stay zeros; valid misc and the completed modern VAB
            //      on current A stay unchanged; no Before sidecar is added. ----
            EdlCapturedRegion bootB = h.Current.Files["boot_b"];
            h.Device.AddWriteOverlay(bootB.Lun, bootB.StartSector, bootB.SectorCount, bootB.FilePath);
            VerifiedEdlFile newStockA = aosp.A.RewriteBootLeaf(freshSlot.CurrentBoot.Path);
            h.Device.AddWriteOverlay(bootA.Lun, bootA.StartSector, bootA.SectorCount, newStockA.Path);

            string freshParent = Path.Combine(h.CaseDirectory, "fresh-epoch");
            Directory.CreateDirectory(freshParent);
            fresh = await InternalInstallBackup.CreateAsync(h.Client, freshParent);

            InternalDeviceCheckResult check = await RunRealCheckAsync(h);

            return new EpochCase(
                h, fresh, check, oldDirectory, oldBaseSha, freshBaseSha, aosp, oldWorkspace, freshWorkspace);
        }
        catch
        {
            // Reverse-order best-effort cleanup of whatever was actually allocated; the original
            // exception is preserved and never replaced by disposal failures.
            BestEffortDispose(fresh);
            BestEffortDispose(h);
            BestEffortDispose(aosp);
            BestEffortDispose(freshWorkspace);
            BestEffortDispose(oldWorkspace);
            throw;
        }
    }

    private static async Task<InternalDeviceCheckResult> RunRealCheckAsync(EdlUninstallCurrentMenuTests.Harness h)
    {
        string serial = h.Client.Binding.AndroidIdentity.Identity.Serial;
        var checkRunner = new DeviceCheckRunner(serial, new DeviceCheckClock())
        {
            FastbootCurrentSlot = "a",
            ReturnSlotSuffix = "_a",
            BootImmediatelyCompleteOnReturn = true,
            UnlockedReportValue = "yes",
        };
        InternalDeviceCheckResult check = await new InternalInstallDeviceCheck(
            AdbOrFastboot.AdbPath, AdbOrFastboot.FastbootPath, checkRunner, checkRunner.Clock)
            .CheckAsync(serial);
        Assert.True(check.Succeeded);
        Assert.Equal(BootloaderState.Unlocked, check.Android!.Identity.BootloaderState);
        return check;
    }

    private static void BestEffortDispose(IDisposable? resource)
    {
        if (resource is null)
        {
            return;
        }

        try
        {
            resource.Dispose();
        }
        catch
        {
            // Best effort only; the caller's original exception takes precedence.
        }
    }

    private static string Sha256File(string path)
    {
        using FileStream stream = new(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private sealed class EpochCase : IDisposable
    {
        public EpochCase(
            EdlUninstallCurrentMenuTests.Harness harness,
            InternalBackupSet fresh,
            InternalDeviceCheckResult check,
            string oldDirectory,
            string oldBaseSha,
            string freshBaseSha,
            DirectAvbSourceTestFixture aosp,
            EdlRawBootBuilderTests.Workspace oldWorkspace,
            EdlRawBootBuilderTests.Workspace freshWorkspace)
        {
            Harness = harness;
            Fresh = fresh;
            Check = check;
            OldDirectory = oldDirectory;
            OldBaseSha = oldBaseSha;
            FreshBaseSha = freshBaseSha;
            Aosp = aosp;
            OldWorkspace = oldWorkspace;
            FreshWorkspace = freshWorkspace;
        }

        public EdlUninstallCurrentMenuTests.Harness Harness { get; }
        public InternalBackupSet Fresh { get; }
        public InternalDeviceCheckResult Check { get; }
        public string OldDirectory { get; }
        public string OldBaseSha { get; }
        public string FreshBaseSha { get; }
        public DirectAvbSourceTestFixture Aosp { get; }
        public EdlRawBootBuilderTests.Workspace OldWorkspace { get; }
        public EdlRawBootBuilderTests.Workspace FreshWorkspace { get; }

        public void Dispose()
        {
            // Reverse-order best-effort disposal; any case backend is already disposed first by the
            // fact itself, before this owner runs.
            BestEffortDispose(Fresh);
            BestEffortDispose(Harness);
            BestEffortDispose(Aosp);
            BestEffortDispose(FreshWorkspace);
            BestEffortDispose(OldWorkspace);
        }
    }
}
