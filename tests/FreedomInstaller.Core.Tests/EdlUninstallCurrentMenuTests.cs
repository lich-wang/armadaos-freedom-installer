#nullable enable
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// U4-TEST1: actual public menu uninstall integration over the existing IB001 synthetic direct device.
/// The GPT planning boundary is the already-validated fake (TailGptInterceptRunner over the EB oracle);
/// this suite is NOT the portable Python acceptance. No reflection builds plans/Prepared/Ready; the only
/// reflection is the narrow private static pure ControlBlock/BuildMisc reuse from BootSlotControlTests.
/// </summary>
public sealed class EdlUninstallCurrentMenuTests
    : IClassFixture<EdlClientToolchainFixture>, IClassFixture<EdlRawGblEnvelopeTests.SharedFixture>
{
    private const long GibSectors = 1024L * 1024 * 1024 / 4096;
    private const long SectorBytes = 4096;
    private const string LinuxTypeGuid = "0fc63daf-8483-4772-8e79-3d69d8477de4";
    private const string CheckSerial = "u4-check-serial-01";

    private readonly EdlClientToolchainFixture _toolchain;
    private readonly EdlRawGblEnvelopeTests.SharedFixture _fx;

    public EdlUninstallCurrentMenuTests(
        EdlClientToolchainFixture toolchain,
        EdlRawGblEnvelopeTests.SharedFixture fx)
    {
        _toolchain = toolchain;
        _fx = fx;
    }

    [Fact]
    public async Task MenuUninstallSuccess_ExactWriteOrder_Readback_AndBackupRetentionAsync()
    {
        using Harness h = await PrepareAsync();

        AssertMenuPlan(h.Menu);

        int readsBeforeRun = h.Ib.Reads.Count;
        UninstallResult result = await RunWorkflowAsync(h);

        Assert.True(result.Success);
        Assert.Equal(UninstallStage.AwaitingFactoryReset, result.Stage);
        Assert.Null(result.Error);

        // ---- exact 7 writes in order (typed evidence, no argument parsing) ----
        var writes = h.Ib.Writes;
        Assert.Equal(7, writes.Count);
        Assert.Equal(0, h.Ib.ResetCount);

        (int bootBLun, long bootBStart, _, _) = h.Device.Expectation("boot_b");
        (int bootALun, long bootAStart, _, _) = h.Device.Expectation("boot_a");
        (int miscLun, long miscStart, _, _) = h.Device.Expectation("misc");

        VerifiedEdlFile candidateA = h.Menu.Slots.Single(s => s.Slot == "a").Candidate!;
        VerifiedEdlFile candidateB = h.Menu.Slots.Single(s => s.Slot == "b").Candidate!;
        long bootSectorsA = candidateA.Length / SectorBytes;
        long bootSectorsB = candidateB.Length / SectorBytes;

        long total = h.Device.TotalSectors(0);

        // First B then A; each carries the full candidate payload (hash + extent from the public menu).
        Assert.Equal((bootBLun, bootBStart, bootSectorsB), (writes[0].Lun, writes[0].StartSector, writes[0].SectorCount));
        Assert.Equal(candidateB.Sha256, writes[0].Sha256, StringComparer.OrdinalIgnoreCase);
        Assert.Equal((bootALun, bootAStart, bootSectorsA), (writes[1].Lun, writes[1].StartSector, writes[1].SectorCount));
        Assert.Equal(candidateA.Sha256, writes[1].Sha256, StringComparer.OrdinalIgnoreCase);

        // Last 5: GPT bounds (32-entry fixture) then misc start, one sector each.
        Assert.Equal((0, total - 2, 1), (writes[2].Lun, writes[2].StartSector, writes[2].SectorCount));
        Assert.Equal((0, total - 1, 1), (writes[3].Lun, writes[3].StartSector, writes[3].SectorCount));
        Assert.Equal((0, 2, 1), (writes[4].Lun, writes[4].StartSector, writes[4].SectorCount));
        Assert.Equal((0, 1, 1), (writes[5].Lun, writes[5].StartSector, writes[5].SectorCount));
        Assert.Equal((miscLun, miscStart, 1), (writes[6].Lun, writes[6].StartSector, writes[6].SectorCount));

        // ---- write/read chronology: after each menu write and before the next write there is a full
        //      matching candidate-SHA read of the written slot. ----
        var timeline = h.Ib.Commands
            .Select((command, index) => (Index: index, Item: Describe(command)))
            .Where(t => t.Item.Verb is "write-sector" or "read-sector")
            .ToList();
        var writeTimeline = timeline.Where(t => t.Item.Verb == "write-sector").ToList();

        foreach ((int writeIndex, string slot, int bootLun, long bootStart, VerifiedEdlFile candidate) in new[]
                 {
                     (0, "b", bootBLun, bootBStart, candidateB),
                     (1, "a", bootALun, bootAStart, candidateA),
                 })
        {
            long bootSectors = candidate.Length / SectorBytes;
            int w = writeTimeline[writeIndex].Index;
            int next = writeTimeline[writeIndex + 1].Index;
            var fullReads = timeline
                .Where(t => t.Index > w && t.Index < next &&
                            t.Item.Verb == "read-sector" &&
                            t.Item.Lun == bootLun &&
                            t.Item.Start == bootStart &&
                            t.Item.Count == bootSectors)
                .ToList();
            var read = Assert.Single(fullReads);
            Assert.Equal(candidate.Sha256, ShaFile(read.Item.Path), StringComparer.OrdinalIgnoreCase);
        }

        // ---- first preflight read of each physical slot shows the verified original boot; the last
        //      shows the candidate. Proven over h.Ib.Reads captured after the pre-run snapshot. ----
        foreach ((string role, int bootLun, long bootStart, VerifiedEdlFile candidate) in new[]
                 {
                     ("boot_a", bootALun, bootAStart, candidateA),
                     ("boot_b", bootBLun, bootBStart, candidateB),
                 })
        {
            long bootSectors = h.Current.Files[role].Length / SectorBytes;
            var slotReads = h.Ib.Reads
                .Skip(readsBeforeRun)
                .Where(r => r.Lun == bootLun && r.StartSector == bootStart && r.SectorCount == bootSectors)
                .ToList();
            Assert.NotEmpty(slotReads);
            Assert.NotEqual(slotReads.First().FilePath, slotReads.Last().FilePath);
            Assert.False(string.Equals(h.Current.Files[role].Sha256, candidate.Sha256, StringComparison.OrdinalIgnoreCase));
            Assert.Equal(h.Current.Files[role].Sha256, ShaFile(slotReads.First().FilePath), StringComparer.OrdinalIgnoreCase);
            Assert.Equal(candidate.Sha256, ShaFile(slotReads.Last().FilePath), StringComparer.OrdinalIgnoreCase);
        }

        // ---- no write touches the BACKUP range; no writes outside LUN0 + the two boot LUNs ----
        foreach (var w in writes)
        {
            Assert.True(w.Lun == 0 || w.Lun == bootALun || w.Lun == bootBLun);
            if (w.Lun == 0)
            {
                bool below = w.StartSector + w.SectorCount <= h.BackupSpec.StartSector;
                bool above = w.StartSector >= h.BackupSpec.StartSector + h.BackupSpec.SectorCount;
                Assert.True(below || above, "a write overlapped the BACKUP range.");
            }
        }

        // ---- boundary markers inside BACKUP are still readable and unchanged (public client reads) ----
        Assert.Equal(h.MarkerStartSha, await ReadSectorShaAsync(h, 0, h.BackupSpec.StartSector, 1), StringComparer.OrdinalIgnoreCase);
        Assert.Equal(h.MarkerEndSha, await ReadSectorShaAsync(h, 0, h.BackupSpec.StartSector + h.BackupSpec.SectorCount - 1, 1), StringComparer.OrdinalIgnoreCase);

        // ---- parse the actual post GPT pair ----
        IReadOnlyList<GptPartition> post = await ReadPostTableAsync(h);
        AssertPostTable(h, post);
    }

    [Fact]
    public async Task MenuReadbackFailure_AbortsAllGptAndMisc_AndPoisonsRetryAsync()
    {
        using Harness h = await PrepareAsync();

        (int bootBLun, long bootBStart, long bootBCount, _) = h.Device.Expectation("boot_b");

        // Armed BEFORE RunAsync; it fires only after the exact write has been acknowledged, so the
        // injected failure is the readback of the first menu write, never a preflight read failure.
        h.Ib.InjectReadbackFailureOnce(bootBLun, bootBStart, bootBCount);

        UninstallResult result = await RunWorkflowAsync(h);

        Assert.False(result.Success);
        Assert.Equal(UninstallStage.ReclaimAndroidSpace, result.Stage);
        Assert.False(string.IsNullOrEmpty(result.Error));
        Assert.Equal(1, h.Ib.Writes.Count);
        Assert.Equal(bootBLun, h.Ib.Writes[0].Lun);
        Assert.Equal(bootBStart, h.Ib.Writes[0].StartSector);
        Assert.Equal(0, h.Ib.ResetCount);

        // The poison guard, proven by behavior: restore physical boot_b to its pre-workflow bytes so an
        // ordinary preflight mismatch could no longer block, then a direct reclaim retry must still
        // throw the poisoned error without any further writes.
        h.Device.AddWriteOverlay(bootBLun, bootBStart, bootBCount, h.Current.Files["boot_b"].FilePath);
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => h.Backend.ReclaimAndroidSpaceAsync(CancellationToken.None));
        Assert.Equal(1, h.Ib.Writes.Count);
        Assert.Equal(0, h.Ib.ResetCount);
    }

    [Fact]
    public async Task PhysicalPreflightBootMismatch_AbortsWithZeroWritesAsync()
    {
        // PrepareAsync succeeding is itself the proof that setup works before the injection.
        using Harness h = await PrepareAsync();

        // A distinct 1-sector overlay at the very start of physical boot_a makes the whole physical
        // slot differ from the verified original while the backup files stay untouched.
        (int bootALun, long bootAStart, _, _) = h.Device.Expectation("boot_a");
        byte[] distinct = new byte[IB001SyntheticDevice.SectorSize];
        new Random(7).NextBytes(distinct);
        string overlay = Path.Combine(h.CaseDirectory, "preflight-mismatch.bin");
        File.WriteAllBytes(overlay, distinct);
        h.Device.AddWriteOverlay(bootALun, bootAStart, 1, overlay);

        UninstallResult result = await RunWorkflowAsync(h);

        Assert.False(result.Success);
        Assert.False(string.IsNullOrEmpty(result.Error));
        Assert.Equal(0, h.Ib.Writes.Count);
        Assert.Equal(0, h.Ib.ResetCount);
    }

    // ------------------------------------------------------------------

    private async Task<UninstallResult> RunWorkflowAsync(Harness h)
    {
        var body = new UserdataUninstallRequest(
            h.Backend.Snapshot, h.Backend.PlanFingerprint, string.Empty, true);
        body = body with { ConfirmationId = UninstallWorkflow.ConfirmationFor(body) };
        return await UninstallWorkflow.RunAsync(body, h.Backend);
    }

    internal async Task<Harness> PrepareAsync()
    {
        string caseDirectory = _toolchain.NewCaseDirectory(
            nameof(EdlUninstallCurrentMenuTests) + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(caseDirectory, "historical"));
        Directory.CreateDirectory(Path.Combine(caseDirectory, "current"));
        Directory.CreateDirectory(Path.Combine(caseDirectory, "menu"));
        var owned = new List<IDisposable>();

        try
        {
            DirectAvbSourceTestFixture avb = new(DirectAvbSourceKind.Aosp);
            owned.Add(avb);

            EdlRawBootBuilderTests.Workspace aux = new();
            owned.Add(aux);
            EdlRawBootBuilderTests.SlotFixture auxSlot = EdlRawBootBuilderTests.CreateSlot(aux, "a", 0x31);

            // The exact ten direct source roles; both physical slots legally contain identical bytes
            // (boot_a/b both start from the verified original) and the public planner still reads its
            // own physical slot.
            var sources = new Dictionary<string, VerifiedEdlFile>(StringComparer.Ordinal)
            {
                ["boot_a"] = _fx.NormalOriginal,
                ["boot_b"] = _fx.NormalOriginal,
                ["vendor_boot_a"] = auxSlot.VendorBoot,
                ["vendor_boot_b"] = auxSlot.VendorBoot,
                ["init_boot_a"] = auxSlot.InitBoot,
                ["init_boot_b"] = auxSlot.InitBoot,
                ["abl_a"] = auxSlot.Abl,
                ["abl_b"] = auxSlot.Abl,
                ["xbl_config_a"] = auxSlot.XblConfig,
                ["xbl_config_b"] = auxSlot.XblConfig,
            };

            // The synthetic device is shared fixture state for the case: never disposed here and never
            // added to the owned list.
            IB001SyntheticDevice device = IB001SyntheticDevice.CreateDirect(caseDirectory, sources, avb.Sources);

            // A valid misc overlay exists BEFORE the historical capture, so both captures see one.
            (int miscLun, long miscStart, long miscCount, _) = device.Expectation("misc");
            byte[] miscPage = BuildValidMiscBytes();
            Assert.Equal(miscCount * SectorBytes, miscPage.Length);
            string miscPath = Path.Combine(caseDirectory, "misc-overlay.bin");
            File.WriteAllBytes(miscPath, miscPage);
            device.AddWriteOverlay(miscLun, miscStart, miscCount, miscPath);

            var discovery = new E003ScriptedEndpointDiscovery
            {
                Endpoints = new[] { E003EdlTestData.Endpoint() },
            };

            // ---- real public device check #1 (verified unlocked, slot a) feeds the historical client ----
            InternalDeviceCheckResult check1 = await RunDeviceCheckAsync();
            EdlEntryResult historicalEntry = new(
                check1.Android!, E003EdlTestData.Endpoint(), E003EdlTestData.BusSerialHex);

            // ---- historical GPT-only factory backup (original full userdata, no ARMADA) ----
            var historicalReader = new IB001FakeEdlRunner(device);
            EdlClient historicalClient = new(
                _toolchain.Toolchain, historicalEntry, historicalReader, discovery);
            InternalBackupSet historical = await InternalInstallBackup.CreateAsync(
                historicalClient, Path.Combine(caseDirectory, "historical"));
            owned.Add(historical);

            // The set's metadata is immutable and its files stay after Dispose, so capture every fact
            // the later phases need and release the read leases immediately.
            string historicalDirectory = historical.DirectoryPath;
            GptTable originalTable = historical.Tables[0];
            GptPartition originalUserdata = originalTable.Partitions.Single(p => p.Name == "userdata");
            var originalVendorSpecs = originalTable.Partitions
                .Where(p => p.Name != "userdata")
                .Select(p => new GptPartitionSpec(
                    p.Number, p.Name, p.TypeGuid, p.PartUuid, p.StartSector, p.SectorCount, p.Attributes))
                .ToList();
            historical.Dispose();
            owned.Remove(historical);

            long lastUsable = originalTable.LastUsableSector;
            Assert.Equal(lastUsable + 1, originalUserdata.StartSector + originalUserdata.SectorCount);

            long backupStart = originalUserdata.StartSector + originalUserdata.SectorCount - 2 * GibSectors;
            string backupUuid = Guid.NewGuid().ToString();
            string bootUuid = Guid.NewGuid().ToString();
            string rootUuid = Guid.NewGuid().ToString();

            // ---- modern current-project GPT fixture (vendors cloned, ARMADA_BOOT/ROOT inserted,
            //      ARMADA_BACKUP carved from the tail of the original userdata) ----
            List<GptPartitionSpec> currentPartitions = new(originalVendorSpecs);
            int maxNumber = originalTable.Partitions.Max(p => p.Number);

            var currentTable = new List<GptPartitionSpec>(currentPartitions);
            currentTable.Add(new GptPartitionSpec(
                originalUserdata.Number, originalUserdata.Name, originalUserdata.TypeGuid,
                originalUserdata.PartUuid, originalUserdata.StartSector, 32 * GibSectors,
                originalUserdata.Attributes));
            long bootStart = originalUserdata.StartSector + 32 * GibSectors;
            currentTable.Add(new GptPartitionSpec(
                maxNumber + 1, "ARMADA_BOOT", LinuxTypeGuid, bootUuid, bootStart, GibSectors, 0UL));
            long rootStart = bootStart + GibSectors;
            long rootCount = backupStart - rootStart;
            Assert.True(rootCount >= 64 * GibSectors, "ARMADA_ROOT must be at least 64 GiB for this fixture.");
            currentTable.Add(new GptPartitionSpec(
                maxNumber + 2, "ARMADA_ROOT", LinuxTypeGuid, rootUuid, rootStart, rootCount, 0UL));
            var backupSpec = new GptPartitionSpec(
                maxNumber + 3, "ARMADA_BACKUP", LinuxTypeGuid, backupUuid, backupStart, 2 * GibSectors, 1UL << 60);
            currentTable.Add(backupSpec);

            // ---- expected post-uninstall table: vendors + shrunk userdata + the EXACT same BACKUP;
            //      no ARMADA_BOOT, no ARMADA_ROOT. Built and padded separately from the current image. ----
            var expectedPostPartitions = new List<GptPartitionSpec>(currentPartitions);
            expectedPostPartitions.Add(new GptPartitionSpec(
                originalUserdata.Number, originalUserdata.Name, originalUserdata.TypeGuid,
                originalUserdata.PartUuid, originalUserdata.StartSector,
                originalUserdata.SectorCount - 2 * GibSectors, originalUserdata.Attributes));
            expectedPostPartitions.Add(backupSpec);

            GptImage currentImage = new(
                originalTable.SectorSize,
                originalTable.DiskBytes,
                originalTable.DiskGuid,
                originalTable.FirstUsableSector,
                lastUsable,
                currentTable.ToArray());
            GptImage expectedPostImage = new(
                originalTable.SectorSize,
                originalTable.DiskBytes,
                originalTable.DiskGuid,
                originalTable.FirstUsableSector,
                lastUsable,
                expectedPostPartitions.ToArray());

            // 64-sector capture windows: the actual GptImage primary header lives at LBA 1, so the
            // primary fragment is placed at offset 0 of the 262144-byte window; the backup header is
            // at the last LBA, so the backup fragment is placed at the END of the window.
            // Current files overlay the device; expected-post paths go only to the
            // TailGptInterceptRunner oracle. Current and expected are always distinct.
            byte[] currentPrimary = BuildWindow(currentImage.BuildPrimaryFragment(), atEnd: false);
            byte[] currentBackup = BuildWindow(currentImage.BuildBackupFragment(), atEnd: true);
            string currentPrimaryPath = Path.Combine(caseDirectory, "current-primary.bin");
            string currentBackupPath = Path.Combine(caseDirectory, "current-backup.bin");
            File.WriteAllBytes(currentPrimaryPath, currentPrimary);
            File.WriteAllBytes(currentBackupPath, currentBackup);

            byte[] expectedPostPrimary = BuildWindow(expectedPostImage.BuildPrimaryFragment(), atEnd: false);
            byte[] expectedPostBackup = BuildWindow(expectedPostImage.BuildBackupFragment(), atEnd: true);
            string expectedPostPrimaryPath = Path.Combine(caseDirectory, "expected-post-primary.bin");
            string expectedPostBackupPath = Path.Combine(caseDirectory, "expected-post-backup.bin");
            File.WriteAllBytes(expectedPostPrimaryPath, expectedPostPrimary);
            File.WriteAllBytes(expectedPostBackupPath, expectedPostBackup);

            // ---- overlays: each physical boot slot gets its own start, both physically carry the
            //      project candidate; the modern GPT pair covers both 64-sector capture ranges. ----
            (int bootALun, long bootAStart, long bootACount, _) = device.Expectation("boot_a");
            (int bootBLun, long bootBStart, long bootBCount, _) = device.Expectation("boot_b");
            device.AddWriteOverlay(bootALun, bootAStart, bootACount, _fx.NormalBuilt.CandidateBoot.Path);
            device.AddWriteOverlay(bootBLun, bootBStart, bootBCount, _fx.NormalBuilt.CandidateBoot.Path);

            device.AddWriteOverlay(0, 0, 64, currentPrimaryPath);
            device.AddWriteOverlay(0, device.TotalSectors(0) - 64, 64, currentBackupPath);

            // ---- board markers: one 4 KiB sector each at the BACKUP start and end-1, distinct known
            //      hashes, so any write into the preserved range is provable. ----
            byte[] markerStartBytes = new byte[IB001SyntheticDevice.SectorSize];
            byte[] markerEndBytes = new byte[IB001SyntheticDevice.SectorSize];
            new Random(11).NextBytes(markerStartBytes);
            new Random(13).NextBytes(markerEndBytes);
            string markerStartPath = Path.Combine(caseDirectory, "marker-start.bin");
            string markerEndPath = Path.Combine(caseDirectory, "marker-end.bin");
            File.WriteAllBytes(markerStartPath, markerStartBytes);
            File.WriteAllBytes(markerEndPath, markerEndBytes);
            device.AddWriteOverlay(0, backupStart, 1, markerStartPath);
            device.AddWriteOverlay(0, backupStart + 2 * GibSectors - 1, 1, markerEndPath);
            string markerStartSha = Convert.ToHexString(SHA256.HashData(markerStartBytes));
            string markerEndSha = Convert.ToHexString(SHA256.HashData(markerEndBytes));
            Assert.NotEqual(markerStartSha, markerEndSha);

            // ---- real public device check #2 (verified unlocked, slot a) feeds the current client ----
            InternalDeviceCheckResult check2 = await RunDeviceCheckAsync();
            EdlEntryResult currentEntry = new(
                check2.Android!, E003EdlTestData.Endpoint(), E003EdlTestData.BusSerialHex);

            // ---- composite runner: python+gpt goes to the EB tail wrapper, everything else to IB001 ----
            var ib = new IB001FakeEdlRunner(device, enableWrites: true);
            EbScenario scenario = EbScenario.Create(_toolchain.Toolchain);
            var innerEb = new EbRunner(_toolchain.Toolchain, scenario.Content);
            var tail = new TailGptInterceptRunner(
                _toolchain.Toolchain, innerEb, caseDirectory, expectedPostPrimaryPath, expectedPostBackupPath,
                counterfeitScalars: false);
            var composite = new CompositeRunner(tail, ib, _toolchain.Toolchain);

            // ---- current backup, original lease, slot facts, public menu, prepared backend ----
            EdlClient currentClient = new(
                _toolchain.Toolchain, currentEntry, composite, discovery);
            InternalBackupSet current = await InternalInstallBackup.CreateAsync(
                currentClient, Path.Combine(caseDirectory, "current"));
            owned.Add(current);

            EdlCapturedRegion miscRegion = current.Files["misc"];
            BootSlotControlFacts slotFacts = await BootSlotControl.ReadAsync(new VerifiedEdlFile(
                miscRegion.FilePath, miscRegion.Length, miscRegion.Sha256));

            CurrentBootMenuPlan menu = await CurrentBootMenuPlanner.PrepareAndroidDefaultAsync(
                current, slotFacts.CurrentSlot, check2.Android.Identity.BootloaderState,
                _fx.Tools, _fx.Runner, Path.Combine(caseDirectory, "menu"), CancellationToken.None);
            owned.Add(menu);

            UninstallOriginalGptBackup original = await InternalInstallBackup.OpenOriginalGptForUninstallAsync(
                currentClient, historicalDirectory);
            owned.Add(original);

            EdlUninstallBackend backend = await EdlUninstallBackend.CreatePreparedAsync(
                currentClient, _toolchain.Toolchain, currentClient.Binding,
                UninstallGptAssets.FromVerifiedBackup(original),
                current, menu, slotFacts.CurrentSlot,
                Path.Combine(caseDirectory, "evidence"), composite,
                progress: null, token: CancellationToken.None);
            owned.Add(backend);

            return new Harness(
                device, ib, currentClient, current, original, menu, backend,
                caseDirectory, originalTable, backupSpec, markerStartSha, markerEndSha, owned);
        }
        catch
        {
            for (int i = owned.Count - 1; i >= 0; i--)
            {
                owned[i].Dispose();
            }

            throw;
        }
    }

    private static async Task<InternalDeviceCheckResult> RunDeviceCheckAsync()
    {
        var checkRunner = new DeviceCheckRunner(CheckSerial, new DeviceCheckClock())
        {
            FastbootCurrentSlot = "a",
            ReturnSlotSuffix = "_a",
            BootImmediatelyCompleteOnReturn = true,
            UnlockedReportValue = "yes",
        };
        InternalDeviceCheckResult check = await new InternalInstallDeviceCheck(
            AdbOrFastboot.AdbPath, AdbOrFastboot.FastbootPath, checkRunner, checkRunner.Clock)
            .CheckAsync(CheckSerial);
        Assert.True(check.Succeeded);
        Assert.Equal(BootloaderState.Unlocked, check.Android!.Identity.BootloaderState);
        return check;
    }

    private static void AssertMenuPlan(CurrentBootMenuPlan menu)
    {
        // The public menu is strongly typed: two real slots, each self-sourced, project-kind,
        // AOSP-resigned, with a candidate and no companions. No SlotA/SlotB reflection exists.
        Assert.Empty(menu.Companions);
        Assert.Equal(2, menu.Slots.Count);
        foreach (CurrentBootMenuSlot slot in menu.Slots)
        {
            Assert.True(slot.Slot is "a" or "b");
            Assert.Equal(slot.Slot, slot.SourceSlot);
            Assert.Equal(BootMaintenanceSourceKind.Project, slot.SourceKind);
            Assert.Equal(BootMaintenanceBootTrust.AospResigned, slot.BootTrustMode);
            Assert.NotNull(slot.Original);
            Assert.NotNull(slot.Candidate);
        }
    }

    private static byte[] BuildValidMiscBytes()
    {
        // Narrow reflection ONLY into the private static pure helpers of BootSlotControlTests,
        // exactly as BootMaintenanceBackendTests already does. No plan/Prepared/Ready reflection.
        Type type = typeof(BootSlotControlTests);
        object? control = type.GetMethod("ControlBlock", BindingFlags.NonPublic | BindingFlags.Static)!
            .Invoke(null, new object?[] { "_a", (byte)0, null, null });
        var controlBytes = (byte[])type.GetMethod("BuildMisc", BindingFlags.NonPublic | BindingFlags.Static)!
            .Invoke(null, new[] { control })!;

        var page = new byte[16 * 4096];
        Assert.True(controlBytes.Length <= page.Length);
        Buffer.BlockCopy(controlBytes, 0, page, 0, controlBytes.Length);

        // VAB64 note at byte 32768: byte 0 = 2, LE u32 at +1 = 0x56740AB0, +5 = 0 (completed),
        // +6 = 1 (inactive slot hint only - never slot authority). The rest stays zero.
        page[32768] = 2;
        BinaryPrimitives.WriteUInt32LittleEndian(page.AsSpan(32769), 0x56740AB0u);
        page[32768 + 5] = 0;
        page[32768 + 6] = 1;
        return page;
    }

    private static byte[] BuildWindow(byte[] fragment, bool atEnd)
    {
        // One 64-sector capture window (64 * 4096 = 262144 bytes). The primary fragment is padded to
        // the END of the window, the backup fragment to the START.
        var window = new byte[64 * SectorBytes];
        int offset = atEnd ? window.Length - fragment.Length : 0;
        Buffer.BlockCopy(fragment, 0, window, offset, fragment.Length);
        return window;
    }

    private static async Task<string> ReadSectorShaAsync(Harness h, int lun, long start, long count)
    {
        string path = Path.Combine(h.CaseDirectory, $"post-read-{lun}-{start}-{count}.bin");
        EdlReadEvidence evidence = await h.Client.ReadAsync(lun, start, count, path);
        return evidence.Sha256;
    }

    private static async Task<IReadOnlyList<GptPartition>> ReadPostTableAsync(Harness h)
    {
        long total = h.Device.TotalSectors(0);
        string primaryPath = Path.Combine(h.CaseDirectory, "post-primary.bin");
        string backupPath = Path.Combine(h.CaseDirectory, "post-backup.bin");
        EdlReadEvidence primary = await h.Client.ReadAsync(0, 0, 64, primaryPath);
        EdlReadEvidence backup = await h.Client.ReadAsync(0, total - 64, 64, backupPath);

        GptTable post = OriginalGptImporter.Parse(
            File.ReadAllBytes(primary.FilePath),
            File.ReadAllBytes(backup.FilePath),
            h.OriginalTable.SectorSize,
            h.OriginalTable.DiskBytes);
        return post.Partitions;
    }

    private static void AssertPostTable(Harness h, IReadOnlyList<GptPartition> post)
    {
        // All original vendor partitions keep every fact; the ARMADA boot/root entries are gone.
        foreach (GptPartition vendor in h.OriginalTable.Partitions.Where(p => p.Name != "userdata"))
        {
            GptPartition actual = post.Single(p => p.Name == vendor.Name);
            Assert.Equal(vendor.Number, actual.Number);
            Assert.Equal(vendor.TypeGuid, actual.TypeGuid);
            Assert.Equal(vendor.PartUuid, actual.PartUuid);
            Assert.Equal(vendor.StartSector, actual.StartSector);
            Assert.Equal(vendor.SectorCount, actual.SectorCount);
            Assert.Equal(vendor.Attributes, actual.Attributes);
        }

        Assert.Equal(0, post.Count(s => s.Name is "ARMADA_BOOT" or "ARMADA_ROOT"));

        GptPartition postUserdata = post.Single(s => s.Name == "userdata");
        GptPartition postBackup = post.Single(s => s.Name == "ARMADA_BACKUP");

        // userdata shrinks by exactly the 2 GiB ARMADA_BACKUP and ends where BACKUP starts.
        GptPartition originalUserdata = h.OriginalTable.Partitions.Single(p => p.Name == "userdata");
        Assert.Equal(originalUserdata.StartSector, postUserdata.StartSector);
        Assert.Equal(originalUserdata.SectorCount - 2 * GibSectors, postUserdata.SectorCount);
        Assert.Equal(postUserdata.StartSector + postUserdata.SectorCount, postBackup.StartSector);

        // ARMADA_BACKUP: all seven facts unchanged.
        Assert.Equal(h.BackupSpec.Number, postBackup.Number);
        Assert.Equal("ARMADA_BACKUP", postBackup.Name);
        Assert.Equal(Guid.Parse(h.BackupSpec.TypeGuid), Guid.Parse(postBackup.TypeGuid));
        Assert.Equal(Guid.Parse(h.BackupSpec.PartUuid), Guid.Parse(postBackup.PartUuid));
        Assert.Equal(h.BackupSpec.StartSector, postBackup.StartSector);
        Assert.Equal(h.BackupSpec.SectorCount, postBackup.SectorCount);
        Assert.Equal(h.BackupSpec.Attributes, postBackup.Attributes);
    }

    private static string ShaFile(string path)
    {
        using FileStream stream = new(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static (string Verb, int Lun, long Start, long Count, string Path) Describe(ProcessCommand command)
    {
        string[] args = command.Arguments.ToArray();
        string verb = args.Length == 0 ? string.Empty : args[0];
        if (verb is not ("read-sector" or "write-sector"))
        {
            return (verb, -1, 0, 0, string.Empty);
        }

        int lun = 0;
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == "--lun")
            {
                lun = int.Parse(args[i + 1], CultureInfo.InvariantCulture);
            }
        }

        long start = long.Parse(args[1], CultureInfo.InvariantCulture);
        if (verb == "read-sector")
        {
            long count = long.Parse(args[2], CultureInfo.InvariantCulture);
            return (verb, lun, start, count, args[3]);
        }

        string path = args[2];
        long writeCount = new FileInfo(path).Length / SectorBytes;
        Assert.Equal(0, new FileInfo(path).Length % SectorBytes);
        return (verb, lun, start, writeCount, path);
    }

    private sealed class CompositeRunner : ICommandRunner
    {
        private readonly TailGptInterceptRunner _gpt;
        private readonly IB001FakeEdlRunner _edl;
        private readonly EdlToolchain _tools;

        internal CompositeRunner(TailGptInterceptRunner gpt, IB001FakeEdlRunner edl, EdlToolchain tools)
        {
            _gpt = gpt;
            _edl = edl;
            _tools = tools;
        }

        public Task<ProcessResult> RunAsync(ProcessCommand command, CancellationToken cancellationToken = default)
        {
            bool isGpt = string.Equals(command.Executable, _tools.PythonPath, StringComparison.OrdinalIgnoreCase) &&
                command.Arguments.Any(a => string.Equals(a, _tools.GptCliPath, StringComparison.OrdinalIgnoreCase));
            return isGpt
                ? _gpt.RunAsync(command, cancellationToken)
                : _edl.RunAsync(command, cancellationToken);
        }
    }

    internal sealed class Harness : IDisposable
    {
        internal Harness(
            IB001SyntheticDevice device,
            IB001FakeEdlRunner ib,
            EdlClient client,
            InternalBackupSet current,
            UninstallOriginalGptBackup original,
            CurrentBootMenuPlan menu,
            EdlUninstallBackend backend,
            string caseDirectory,
            GptTable originalTable,
            GptPartitionSpec backupSpec,
            string markerStartSha,
            string markerEndSha,
            List<IDisposable> owned)
        {
            Device = device;
            Ib = ib;
            Client = client;
            Current = current;
            Original = original;
            Menu = menu;
            Backend = backend;
            CaseDirectory = caseDirectory;
            OriginalTable = originalTable;
            BackupSpec = backupSpec;
            MarkerStartSha = markerStartSha;
            MarkerEndSha = markerEndSha;
            Owned = owned;
        }

        internal IB001SyntheticDevice Device { get; }
        internal IB001FakeEdlRunner Ib { get; }
        internal EdlClient Client { get; }
        internal InternalBackupSet Current { get; }
        internal UninstallOriginalGptBackup Original { get; }
        internal CurrentBootMenuPlan Menu { get; }
        internal EdlUninstallBackend Backend { get; }
        internal string CaseDirectory { get; }
        internal GptTable OriginalTable { get; }
        internal GptPartitionSpec BackupSpec { get; }
        internal string MarkerStartSha { get; }
        internal string MarkerEndSha { get; }
        internal List<IDisposable> Owned { get; }

        public void Dispose()
        {
            // Reverse owned disposal only: backend, menu, original lease, current set, then the
            // case-local AVB/aux fixtures. The device is shared fixture state and the case directory
            // retention belongs to the toolchain fixture, so neither is touched here.
            for (int i = Owned.Count - 1; i >= 0; i--)
            {
                Owned[i].Dispose();
            }
        }
    }
}
