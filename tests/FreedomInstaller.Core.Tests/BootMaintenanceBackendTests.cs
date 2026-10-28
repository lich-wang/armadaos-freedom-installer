using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// five real public runtime facts of the BeforeUpdate/RestoreStock boot-maintenance
/// backend over the stock synthetic device. Fact 1 proves the preparation smoke (current slot a, the
/// whole 8-region plan, nothing written or reset). Fact 2 proves one execution: exactly eight
/// whole-region writes in the frozen order, each carrying the historical stock bytes, each read back
/// whole to the original source SHA, and exactly one accepted normal reset. Fact 3 proves the same
/// execution reality for RestoreStock on a current-slot-b device across the independent slot-major
/// restore order. Fact 4 proves a confirmation-id mismatch is rejected before any device IO without
/// consuming the prepared backend, which then completes with its own id. Fact 5 proves that a readback
/// failure after the first ACKed write surfaces the real unknown-outcome result and stops all further
/// roles and the reset. Every device operation runs through the real <see cref="EdlClient"/>
/// over the real toolchain with the IB001 fake transport; only existing private pure synthetic data writers
/// are reached by narrow reflection, and nothing readiness-shaped is ever forged through it.
/// </summary>
public sealed class BootMaintenanceBackendTests : IClassFixture<EdlClientToolchainFixture>
{
    private const string Serial = "BM-SYNTHETIC-A";

    /// <summary>One payload byte inside the kernel body is flipped for the damaged current boot images.</summary>
    private const int PayloadFlipOffset = 4096 + 128;

    /// <summary>The frozen expected write order: inactive slot b first, then current slot a.</summary>
    private static readonly string[] PlanRoles =
    {
        "boot_b", "recovery_b", "vbmeta_system_b", "vbmeta_b",
        "boot_a", "recovery_a", "vbmeta_system_a", "vbmeta_a",
    };

    private static readonly string[] AuxRoles =
    {
        "vendor_boot_a", "vendor_boot_b", "init_boot_a", "init_boot_b",
        "abl_a", "abl_b", "xbl_config_a", "xbl_config_b",
    };

    // Narrow reflection to existing PRIVATE PURE synthetic data writers only.
    private static readonly MethodInfo PlainKernelMethod = typeof(BootMaintenanceStockOriginalTests).GetMethod(
            "PlainKernel", BindingFlags.NonPublic | BindingFlags.Static)
        ?? throw new InvalidOperationException("BootMaintenanceStockOriginalTests.PlainKernel was not found.");

    private static readonly MethodInfo WriteBootMethod = typeof(BootMaintenanceStockOriginalTests).GetMethod(
            "WriteBoot", BindingFlags.NonPublic | BindingFlags.Static)
        ?? throw new InvalidOperationException("BootMaintenanceStockOriginalTests.WriteBoot was not found.");

    private static readonly MethodInfo ControlBlockMethod = typeof(BootSlotControlTests).GetMethod(
            "ControlBlock", BindingFlags.NonPublic | BindingFlags.Static)
        ?? throw new InvalidOperationException("BootSlotControlTests.ControlBlock was not found.");

    private static readonly MethodInfo BuildMiscMethod = typeof(BootSlotControlTests).GetMethod(
            "BuildMisc", BindingFlags.NonPublic | BindingFlags.Static)
        ?? throw new InvalidOperationException("BootSlotControlTests.BuildMisc was not found.");

    private readonly EdlClientToolchainFixture _fixture;

    public BootMaintenanceBackendTests(EdlClientToolchainFixture fixture)
    {
        _fixture = fixture;
    }

    // ------------------------------------------------------------------ the two facts

    [Fact]
    public async Task Fact1_Prepare_BeforeUpdate_currentSlotA_plans_all_eight_regions_and_never_writes()
    {
        StockCase stock = await SetUpStockCaseAsync(
            nameof(Fact1_Prepare_BeforeUpdate_currentSlotA_plans_all_eight_regions_and_never_writes));
        try
        {
            (InternalDeviceCheckResult check, EdlClient client, IB001FakeEdlRunner runner) =
                await OpenCurrentSessionAsync(stock.Device);

            using InternalBackupSet current = await InternalInstallBackup.CreateAsync(client, stock.CurrentParent);

            using BootMaintenanceBackend backend = await BootMaintenanceBackend.CreatePreparedAsync(
                MaintenanceMode.BeforeUpdate,
                check,
                client,
                current,
                new BootMaintenanceSources(OriginalBackupDirectory: stock.HistoricalDirectory),
                runner,
                stock.EvidenceParent);

            Assert.Equal(MaintenanceMode.BeforeUpdate, backend.Prepared.Mode);
            Assert.Equal("a", backend.Prepared.CurrentSlot);
            Assert.Equal(8, backend.Prepared.Regions.Count);
            Assert.Equal(PlanRoles, backend.Prepared.Regions.Select(region => region.Role).ToArray());
            Assert.All(backend.Prepared.Regions, region => Assert.True(region.WillWrite));

            // Preparation never writes and never resets.
            Assert.Empty(runner.Writes);
            Assert.Equal(0, runner.ResetCount);
        }
        finally
        {
            stock.Graph.Dispose();
        }
    }

    [Fact]
    public async Task Fact2_Execute_BeforeUpdate_writes_source_ranges_reads_them_back_and_resets_once()
    {
        StockCase stock = await SetUpStockCaseAsync(
            nameof(Fact2_Execute_BeforeUpdate_writes_source_ranges_reads_them_back_and_resets_once));
        try
        {
            (InternalDeviceCheckResult check, EdlClient client, IB001FakeEdlRunner runner) =
                await OpenCurrentSessionAsync(stock.Device);

            using InternalBackupSet current = await InternalInstallBackup.CreateAsync(client, stock.CurrentParent);

            using BootMaintenanceBackend backend = await BootMaintenanceBackend.CreatePreparedAsync(
                MaintenanceMode.BeforeUpdate,
                check,
                client,
                current,
                new BootMaintenanceSources(OriginalBackupDirectory: stock.HistoricalDirectory),
                runner,
                stock.EvidenceParent);

            // Independent expectations: whole ranges from the actual fresh current capture, candidate bytes
            // from the historical stock capture. Nothing is derived from the backend's plan.
            var expected = new (int Lun, long Start, long Count, long Length, string SourceSha)[PlanRoles.Length];
            for (int index = 0; index < PlanRoles.Length; index++)
            {
                EdlCapturedRegion region = current.Files[PlanRoles[index]];
                expected[index] = (
                    region.Lun, region.StartSector, region.SectorCount, region.Length,
                    stock.OriginalSha256[PlanRoles[index]]);
            }

            int readsBeforeExecute = runner.Reads.Count;

            BootMaintenanceResult result = await backend.ExecuteAsync(backend.Prepared.ConfirmationId);

            Assert.Equal(BootMaintenanceOutcome.Completed, result.Outcome);
            Assert.Equal(InternalInstallWriteState.AllVerified, result.WriteState);
            Assert.Null(result.Error);
            Assert.True(result.AwaitingAndroidAcceptance);
            Assert.Equal(PlanRoles, result.VerifiedRegions);

            // Exactly eight whole-range writes in the frozen order, each carrying the exact historical stock
            // bytes; exactly one accepted normal reset and nothing else (no GPT or misc write exists).
            Assert.Equal(1, runner.ResetCount);
            Assert.Equal(8, runner.Writes.Count);
            for (int index = 0; index < expected.Length; index++)
            {
                IB001Write write = runner.Writes[index];
                Assert.Equal(expected[index].Lun, write.Lun);
                Assert.Equal(expected[index].Start, write.StartSector);
                Assert.Equal(expected[index].Count, write.SectorCount);
                Assert.Equal(expected[index].Length, write.SectorCount * IB001SyntheticDevice.SectorSize);
                Assert.Equal(expected[index].SourceSha, write.Sha256, ignoreCase: true);
            }

            // Complete readback proof: inside the execute phase every expected range is first re-read whole
            // with the damaged current bytes and finally re-read whole with the stock bytes, hashed from the
            // actual readback files. The initial current SHAs all differ from the source SHAs, so a matching
            // final readback cannot come from any pre-write capture.
            for (int index = 0; index < expected.Length; index++)
            {
                IB001Read? first = null;
                IB001Read? last = null;
                for (int r = readsBeforeExecute; r < runner.Reads.Count; r++)
                {
                    IB001Read read = runner.Reads[r];
                    if (read.Lun != expected[index].Lun
                        || read.StartSector != expected[index].Start
                        || read.SectorCount != expected[index].Count)
                    {
                        continue;
                    }

                    first ??= read;
                    last = read;
                }

                Assert.NotNull(first);
                Assert.NotNull(last);
                Assert.NotSame(first!, last!);
                Assert.Equal(
                    current.Files[PlanRoles[index]].Sha256,
                    Sha256File(first!.FilePath),
                    ignoreCase: true);
                Assert.Equal(expected[index].SourceSha, Sha256File(last!.FilePath), ignoreCase: true);
            }
        }
        finally
        {
            stock.Graph.Dispose();
        }
    }

    [Fact]
    public async Task Fact3_Execute_RestoreStock_currentSlotB_restores_all_eight_roles_to_stock_bytes()
    {
        StockCase stock = await SetUpStockCaseAsync(
            nameof(Fact3_Execute_RestoreStock_currentSlotB_restores_all_eight_roles_to_stock_bytes), "b");
        try
        {
            (InternalDeviceCheckResult check, EdlClient client, IB001FakeEdlRunner runner) =
                await OpenCurrentSessionAsync(stock.Device, "b");

            using InternalBackupSet current = await InternalInstallBackup.CreateAsync(client, stock.CurrentParent);

            using BootMaintenanceBackend backend = await BootMaintenanceBackend.CreatePreparedAsync(
                MaintenanceMode.RestoreStock,
                check,
                client,
                current,
                new BootMaintenanceSources(OriginalBackupDirectory: stock.HistoricalDirectory),
                runner,
                stock.EvidenceParent);

            Assert.Equal(MaintenanceMode.RestoreStock, backend.Prepared.Mode);
            Assert.Equal("b", backend.Prepared.CurrentSlot);

            // The independent expected order for RestoreStock on current slot b: slot-major, a first.
            var expectedRoles = new[]
            {
                "boot_a", "recovery_a", "vbmeta_system_a", "vbmeta_a",
                "boot_b", "recovery_b", "vbmeta_system_b", "vbmeta_b",
            };
            Assert.Equal(expectedRoles, backend.Prepared.Regions.Select(region => region.Role).ToArray());
            Assert.All(backend.Prepared.Regions, region => Assert.True(region.WillWrite));

            var expected = new (int Lun, long Start, long Count, long Length, string SourceSha)[expectedRoles.Length];
            for (int index = 0; index < expectedRoles.Length; index++)
            {
                EdlCapturedRegion region = current.Files[expectedRoles[index]];
                expected[index] = (
                    region.Lun, region.StartSector, region.SectorCount, region.Length,
                    stock.OriginalSha256[expectedRoles[index]]);
            }

            int readsBeforeExecute = runner.Reads.Count;

            BootMaintenanceResult result = await backend.ExecuteAsync(backend.Prepared.ConfirmationId);

            Assert.Equal(BootMaintenanceOutcome.Completed, result.Outcome);
            Assert.Equal(InternalInstallWriteState.AllVerified, result.WriteState);
            Assert.Null(result.Error);
            Assert.True(result.AwaitingAndroidAcceptance);
            Assert.Equal(expectedRoles, result.VerifiedRegions);
            Assert.Equal(8, runner.Writes.Count);
            Assert.Equal(1, runner.ResetCount);

            for (int index = 0; index < expected.Length; index++)
            {
                IB001Write write = runner.Writes[index];
                Assert.Equal(expected[index].Lun, write.Lun);
                Assert.Equal(expected[index].Start, write.StartSector);
                Assert.Equal(expected[index].Count, write.SectorCount);
                Assert.Equal(expected[index].Length, write.SectorCount * IB001SyntheticDevice.SectorSize);
                Assert.Equal(expected[index].SourceSha, write.Sha256, ignoreCase: true);
            }

            for (int index = 0; index < expected.Length; index++)
            {
                IB001Read? first = null;
                IB001Read? last = null;
                for (int r = readsBeforeExecute; r < runner.Reads.Count; r++)
                {
                    IB001Read read = runner.Reads[r];
                    if (read.Lun != expected[index].Lun
                        || read.StartSector != expected[index].Start
                        || read.SectorCount != expected[index].Count)
                    {
                        continue;
                    }

                    first ??= read;
                    last = read;
                }

                Assert.NotNull(first);
                Assert.NotNull(last);
                Assert.NotSame(first!, last!);
                Assert.Equal(
                    current.Files[expectedRoles[index]].Sha256,
                    Sha256File(first!.FilePath),
                    ignoreCase: true);
                Assert.Equal(expected[index].SourceSha, Sha256File(last!.FilePath), ignoreCase: true);
            }
        }
        finally
        {
            stock.Graph.Dispose();
        }
    }

    [Fact]
    public async Task Fact4_WrongConfirmationId_is_rejected_without_device_io_and_does_not_consume_the_backend()
    {
        StockCase stock = await SetUpStockCaseAsync(
            nameof(Fact4_WrongConfirmationId_is_rejected_without_device_io_and_does_not_consume_the_backend));
        try
        {
            (InternalDeviceCheckResult check, EdlClient client, IB001FakeEdlRunner runner) =
                await OpenCurrentSessionAsync(stock.Device);

            using InternalBackupSet current = await InternalInstallBackup.CreateAsync(client, stock.CurrentParent);

            BootMaintenanceBackend first = await BootMaintenanceBackend.CreatePreparedAsync(
                MaintenanceMode.BeforeUpdate,
                check,
                client,
                current,
                new BootMaintenanceSources(OriginalBackupDirectory: stock.HistoricalDirectory),
                runner,
                stock.EvidenceParent);
            BootMaintenanceBackend second = await BootMaintenanceBackend.CreatePreparedAsync(
                MaintenanceMode.BeforeUpdate,
                check,
                client,
                current,
                new BootMaintenanceSources(OriginalBackupDirectory: stock.HistoricalDirectory),
                runner,
                stock.EvidenceParent);

            try
            {
                Assert.NotEqual(
                    first.Prepared.ConfirmationId,
                    second.Prepared.ConfirmationId);
                string firstId = first.Prepared.ConfirmationId;

                int writesBefore = runner.Writes.Count;
                int resetsBefore = runner.ResetCount;
                int readsBefore = runner.Reads.Count;

                InvalidOperationException mismatch = await Assert.ThrowsAsync<InvalidOperationException>(
                    () => second.ExecuteAsync(firstId));
                Assert.StartsWith("boot-maintenance-confirmation-mismatch:", mismatch.Message);

                // Rejected before any device IO, and the backend is not consumed.
                Assert.Equal(writesBefore, runner.Writes.Count);
                Assert.Equal(resetsBefore, runner.ResetCount);
                Assert.Equal(readsBefore, runner.Reads.Count);
                Assert.False(second.Snapshot.ExecutionStarted);
                Assert.Equal(InternalInstallWriteState.NoneIssued, second.Snapshot.WriteState);

                BootMaintenanceResult result = await second.ExecuteAsync(second.Prepared.ConfirmationId);

                Assert.Equal(BootMaintenanceOutcome.Completed, result.Outcome);
                Assert.Equal(InternalInstallWriteState.AllVerified, result.WriteState);
                Assert.Null(result.Error);
                Assert.Equal(PlanRoles, result.VerifiedRegions);
                Assert.Equal(8, runner.Writes.Count - writesBefore);
                Assert.Equal(1, runner.ResetCount - resetsBefore);
            }
            finally
            {
                first.Dispose();
                second.Dispose();
            }
        }
        finally
        {
            stock.Graph.Dispose();
        }
    }

    [Fact]
    public async Task Fact5_Readback_failure_after_first_ACKed_write_yields_unknown_outcome_and_stops()
    {
        StockCase stock = await SetUpStockCaseAsync(
            nameof(Fact5_Readback_failure_after_first_ACKed_write_yields_unknown_outcome_and_stops));
        try
        {
            (InternalDeviceCheckResult check, EdlClient client, IB001FakeEdlRunner runner) =
                await OpenCurrentSessionAsync(stock.Device);

            using InternalBackupSet current = await InternalInstallBackup.CreateAsync(client, stock.CurrentParent);

            using BootMaintenanceBackend backend = await BootMaintenanceBackend.CreatePreparedAsync(
                MaintenanceMode.BeforeUpdate,
                check,
                client,
                current,
                new BootMaintenanceSources(OriginalBackupDirectory: stock.HistoricalDirectory),
                runner,
                stock.EvidenceParent);

            EdlCapturedRegion firstRole = current.Files["boot_b"];
            Assert.Empty(runner.Writes);
            Assert.Equal(0, runner.ResetCount);

            // Arm the real injection helper before executing: the first read of this exact range after the
            // matching write has been ACKed throws, so every earlier setup/integrity read is unaffected.
            runner.InjectReadbackFailureOnce(firstRole.Lun, firstRole.StartSector, firstRole.SectorCount);

            BootMaintenanceResult result = await backend.ExecuteAsync(backend.Prepared.ConfirmationId);

            Assert.Equal(BootMaintenanceOutcome.UnknownWriteOutcome, result.Outcome);
            Assert.Equal(InternalInstallWriteState.Unknown, result.WriteState);
            Assert.NotNull(result.Error);
            Assert.StartsWith("execution-write-outcome-unknown", result.Error!);
            Assert.False(result.AwaitingAndroidAcceptance);
            Assert.Empty(result.VerifiedRegions);
            Assert.True(backend.Snapshot.ExecutionStarted);
            Assert.Equal(InternalInstallWriteState.Unknown, backend.Snapshot.WriteState);

            // Only the first role was written; no later role, no reset, no retry.
            Assert.Equal(1, runner.Writes.Count);
            IB001Write write = runner.Writes[0];
            Assert.Equal(firstRole.Lun, write.Lun);
            Assert.Equal(firstRole.StartSector, write.StartSector);
            Assert.Equal(firstRole.SectorCount, write.SectorCount);
            Assert.Equal(firstRole.Length, write.SectorCount * IB001SyntheticDevice.SectorSize);
            Assert.Equal(stock.OriginalSha256["boot_b"], write.Sha256, ignoreCase: true);
            Assert.Equal(0, runner.ResetCount);
        }
        finally
        {
            stock.Graph.Dispose();
        }
    }

    // ------------------------------------------------------------------ shared stock case

    private sealed record StockCase(
        BootMaintenanceStockChainTests.ChainRun Graph,
        IB001SyntheticDevice Device,
        string HistoricalDirectory,
        string CurrentParent,
        string EvidenceParent,
        IReadOnlyDictionary<string, string> OriginalSha256);

    /// <summary>
    /// Builds the stock device and the historical capture: the real signed OEM graph supplies the six source
    /// AVB metadata roles and the boot signing key; two genuine signed boots are grown to 96 MiB by pure
    /// FileStream surgery; the eight aux roles come from the existing legacy fixture payloads; a valid misc
    /// control selecting slot _a is installed before any capture. The damaged current state (tampered boot
    /// payloads plus the genuine six-role rekey) is overlaid after the historical capture.
    /// </summary>
    private async Task<StockCase> SetUpStockCaseAsync(string name, string currentSlot = "a")
    {
        string caseDirectory = _fixture.NewCaseDirectory(name);
        string inputs = Directory.CreateDirectory(Path.Combine(caseDirectory, "inputs")).FullName;
        string backing = Directory.CreateDirectory(Path.Combine(caseDirectory, "backing")).FullName;
        string originalParent = Directory.CreateDirectory(Path.Combine(caseDirectory, "original")).FullName;
        string currentParent = Directory.CreateDirectory(Path.Combine(caseDirectory, "current")).FullName;
        string evidenceParent = Directory.CreateDirectory(Path.Combine(caseDirectory, "evidence")).FullName;

        BootMaintenanceStockChainTests.ChainRun graph =
            BootMaintenanceStockChainTests.CreateChain(new BootMaintenanceStockChainTests.ChainSpec());
        try
        {
            byte[] kernelA = (byte[])PlainKernelMethod.Invoke(null, new object?[] { 4096, null })!;
            byte[] kernelB = (byte[])kernelA.Clone();
            kernelB[^1] ^= 0xFF;
            string smallA = (string)WriteBootMethod.Invoke(
                null, new object?[] { graph.SourceBootKeyOwner, inputs, kernelA, "boot_a.img" })!;
            string smallB = (string)WriteBootMethod.Invoke(
                null, new object?[] { graph.SourceBootKeyOwner, inputs, kernelB, "boot_b.img" })!;
            string bootA = ExpandToBootPartition(smallA, Path.Combine(inputs, "boot_a-full.img"));
            string bootB = ExpandToBootPartition(smallB, Path.Combine(inputs, "boot_b-full.img"));

            var sources = new Dictionary<string, VerifiedEdlFile>(StringComparer.Ordinal)
            {
                ["boot_a"] = FileClaim(bootA),
                ["boot_b"] = FileClaim(bootB),
            };

            IB001SyntheticDevice legacy = IB001SyntheticDevice.Create();
            foreach (string role in AuxRoles)
            {
                (int lun, long start, long count, string? _) = legacy.Expectation(role);
                byte[] payload = legacy.PayloadFor(lun, start, count)
                    ?? throw new InvalidOperationException("the legacy fixture has no payload for " + role + ".");
                string path = Path.Combine(inputs, role + ".img");
                File.WriteAllBytes(path, payload);
                sources[role] = FileClaim(path);
            }

            var avb = new Dictionary<string, VerifiedEdlFile>(StringComparer.Ordinal)
            {
                ["recovery_a"] = graph.SourceRecoveryClaim,
                ["recovery_b"] = graph.SourceRecoveryClaim,
                ["vbmeta_system_a"] = graph.SourceVbmetaSystemClaim,
                ["vbmeta_system_b"] = graph.SourceVbmetaSystemClaim,
                ["vbmeta_a"] = graph.SourceRootClaim,
                ["vbmeta_b"] = graph.SourceRootClaim,
            };

            IB001SyntheticDevice device = IB001SyntheticDevice.CreateDirect(backing, sources, avb);

            (int miscLun, long miscStart, long miscCount, string? _) = device.Expectation("misc");
            device.AddWriteOverlay(miscLun, miscStart, miscCount, WriteMiscOverlay(inputs, currentSlot));

            // Historical stock capture over a real check and a read-only EDL session.
            DeviceCheckRunner firstRunner = NewDeviceCheckRunner(currentSlot);
            var firstCheck = new InternalInstallDeviceCheck(
                AdbOrFastboot.AdbPath, AdbOrFastboot.FastbootPath, firstRunner, firstRunner.Clock);
            InternalDeviceCheckResult first = await firstCheck.CheckAsync(Serial);
            Assert.True(first.Succeeded);

            IB001FakeEdlRunner historicalRunner = new(device);
            EdlClient historicalClient = NewClient(
                new EdlEntryResult(first.Android!, E003EdlTestData.Endpoint(), E003EdlTestData.BusSerialHex),
                historicalRunner);

            using InternalBackupSet historical =
                await InternalInstallBackup.CreateAsync(historicalClient, originalParent);
            var original = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (string role in PlanRoles)
            {
                original[role] = Sha256File(historical.Files[role].FilePath);
            }

            string historicalDirectory = historical.DirectoryPath;
            historical.Dispose();

            // The damaged current state: everything else (misc, GPT, xbl, abl, vendor, init) stays untouched.
            InstallCurrentOverlay(
                device, "boot_a", CopyWithFlippedPayloadByte(bootA, Path.Combine(inputs, "current-boot_a.img")));
            InstallCurrentOverlay(
                device, "boot_b", CopyWithFlippedPayloadByte(bootB, Path.Combine(inputs, "current-boot_b.img")));
            InstallCurrentOverlay(device, "vbmeta_a", graph.CurrentRootPath);
            InstallCurrentOverlay(device, "vbmeta_b", graph.CurrentRootPath);
            InstallCurrentOverlay(device, "recovery_a", graph.CurrentRecoveryPath);
            InstallCurrentOverlay(device, "recovery_b", graph.CurrentRecoveryPath);
            InstallCurrentOverlay(device, "vbmeta_system_a", graph.CurrentSystemPath);
            InstallCurrentOverlay(device, "vbmeta_system_b", graph.CurrentSystemPath);

            return new StockCase(graph, device, historicalDirectory, currentParent, evidenceParent, original);
        }
        catch
        {
            graph.Dispose();
            throw;
        }
    }

    private void InstallCurrentOverlay(IB001SyntheticDevice device, string role, string path)
    {
        (int lun, long start, long count, string? _) = device.Expectation(role);
        device.AddWriteOverlay(lun, start, count, path);
    }

    private async Task<(InternalDeviceCheckResult Check, EdlClient Client, IB001FakeEdlRunner Runner)>
        OpenCurrentSessionAsync(IB001SyntheticDevice device, string currentSlot = "a")
    {
        DeviceCheckRunner checkRunner = NewDeviceCheckRunner(currentSlot);
        var deviceCheck = new InternalInstallDeviceCheck(
            AdbOrFastboot.AdbPath, AdbOrFastboot.FastbootPath, checkRunner, checkRunner.Clock);
        InternalDeviceCheckResult result = await deviceCheck.CheckAsync(Serial);
        Assert.True(result.Succeeded);

        IB001FakeEdlRunner runner = new(device, enableWrites: true);
        EdlClient client = NewClient(
            new EdlEntryResult(result.Android!, E003EdlTestData.Endpoint(), E003EdlTestData.BusSerialHex),
            runner);

        return (result, client, runner);
    }

    // ------------------------------------------------------------------ small helpers

    private EdlClient NewClient(EdlEntryResult binding, ICommandRunner runner) => new(
        _fixture.Toolchain,
        binding,
        runner,
        new E003ScriptedEndpointDiscovery { Endpoints = new[] { E003EdlTestData.Endpoint() } });

    private static DeviceCheckRunner NewDeviceCheckRunner(string currentSlot = "a") => new(Serial, new DeviceCheckClock())
    {
        FastbootCurrentSlot = currentSlot,
        ReturnSlotSuffix = "_" + currentSlot,
        BootImmediatelyCompleteOnReturn = true,
    };

    /// <summary>
    /// Grows a small signed boot image to the real 96 MiB partition with FileStream calls only: the 64-byte
    /// AVB footer is saved, the copied body ends before the old footer, the length is extended (zero fill),
    /// and the same footer is rewritten at the new end. The signed vbmeta offsets stay valid.
    /// </summary>
    private static string ExpandToBootPartition(string smallImagePath, string expandedPath)
    {
        const int FooterBytes = 64;
        const int BufferBytes = 64 * 1024;
        var footer = new byte[FooterBytes];

        using (FileStream reader = new(smallImagePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            reader.Seek(-FooterBytes, SeekOrigin.End);
            int total = 0;
            while (total < FooterBytes)
            {
                int read = reader.Read(footer, total, FooterBytes - total);
                if (read <= 0)
                {
                    throw new EndOfStreamException("the small boot image ended inside its AVB footer.");
                }

                total += read;
            }
        }

        using (FileStream source = new(
                   smallImagePath, FileMode.Open, FileAccess.Read, FileShare.Read, BufferBytes,
                   FileOptions.SequentialScan))
        using (FileStream target = new(
                   expandedPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, BufferBytes))
        {
            long remaining = source.Length - FooterBytes;
            var buffer = new byte[BufferBytes];
            while (remaining > 0)
            {
                int read = source.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
                if (read <= 0)
                {
                    throw new EndOfStreamException("the small boot image ended before its footer.");
                }

                target.Write(buffer, 0, read);
                remaining -= read;
            }

            target.SetLength(IB001SyntheticDevice.BootPartitionBytes);
            target.Seek(-FooterBytes, SeekOrigin.End);
            target.Write(footer, 0, FooterBytes);
        }

        return expandedPath;
    }

    private static string CopyWithFlippedPayloadByte(string sourcePath, string targetPath)
    {
        File.Copy(sourcePath, targetPath);
        using FileStream stream = new(targetPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        stream.Seek(PayloadFlipOffset, SeekOrigin.Begin);
        int original = stream.ReadByte();
        stream.Seek(PayloadFlipOffset, SeekOrigin.Begin);
        stream.WriteByte((byte)(original ^ 0xFF));
        return targetPath;
    }

    /// <summary>
    /// Writes the real 16-sector misc overlay: the existing CRC32-valid boot_control block selecting _a
    /// (via the existing pure helpers) inside a 64 KiB image, plus the 64-byte modern virtual-ab note at
    /// byte 32768 (version 2, magic 0x56740AB0, completed status, source hint 0). The hint is never the
    /// slot authority; the current slot stays the AB/device fact.
    /// </summary>
    private static string WriteMiscOverlay(string directory, string currentSlot = "a")
    {
        byte[] control = (byte[])ControlBlockMethod.Invoke(
            null, new object?[] { "_" + currentSlot, (byte)0, null, null })!;
        byte[] controlPage = (byte[])BuildMiscMethod.Invoke(null, new object?[] { control })!;
        var overlay = new byte[16 * IB001SyntheticDevice.SectorSize];
        Buffer.BlockCopy(controlPage, 0, overlay, 0, controlPage.Length);

        overlay[32768] = 2;
        BinaryPrimitives.WriteUInt32LittleEndian(overlay.AsSpan(32768 + 1), 0x56740AB0);
        overlay[32768 + 5] = 0;
        overlay[32768 + 6] = currentSlot == "b" ? (byte)1 : (byte)0;

        string path = Path.Combine(directory, "misc-overlay.img");
        File.WriteAllBytes(path, overlay);
        return path;
    }

    private static VerifiedEdlFile FileClaim(string path) =>
        new(Path.GetFullPath(path), new FileInfo(path).Length, Sha256File(path));

    private static string Sha256File(string path)
    {
        using FileStream stream = new(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.SequentialScan);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }
}
