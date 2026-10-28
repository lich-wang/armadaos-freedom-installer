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
/// TF-BOOT-ROUNDTRIP-TEST-01: one real positive G5 temporary/final TF public-factory roundtrip over the
/// independently signed OEM synthetic graph, the pinned public loader inputs, the REAL built TF native
/// package (real packer runtime) and the IB001 fake EDL transport. It never touches an actual device or
/// backup data and does not claim RAM OS boot, SD card write or hardware verification; "Completed" means
/// physical fake-transport writes plus whole readback plus one accepted reset only. Missing required
/// environment variables hard-fail; nothing is skipped and nothing is caught to pass.
/// </summary>
public sealed class TfBootRoundTripTests : IClassFixture<Gen5EdlToolchainFixture>
{
    private const string Serial = "SN0123456789";
    private const string Model = "TB323FU";
    private const string CurrentSlot = "a";

    /// <summary>Roles that must never carry a planned write in any phase of this case.</summary>
    private static readonly string[] ForbiddenWriteRoles =
    {
        "recovery_a", "recovery_b", "vbmeta_a", "vbmeta_b",
        "vbmeta_system_a", "vbmeta_system_b", "misc", "abl_a", "abl_b",
        "gpt", "userdata", "metadata",
    };

    // Narrow reflection to the two existing PRIVATE PURE synthetic byte writers only (root-approved
    // exception); their validated CRC/AB layout is reused verbatim, no second parser is implemented.
    private static readonly MethodInfo ControlBlockMethod = typeof(BootSlotControlTests).GetMethod(
            "ControlBlock", BindingFlags.NonPublic | BindingFlags.Static)
        ?? throw new InvalidOperationException("BootSlotControlTests.ControlBlock was not found.");

    private static readonly MethodInfo BuildMiscMethod = typeof(BootSlotControlTests).GetMethod(
            "BuildMisc", BindingFlags.NonPublic | BindingFlags.Static)
        ?? throw new InvalidOperationException("BootSlotControlTests.BuildMisc was not found.");

    private readonly Gen5EdlToolchainFixture _g5;

    public TfBootRoundTripTests(Gen5EdlToolchainFixture g5)
    {
        _g5 = g5;
    }

    [Fact]
    public async Task Tf_temporary_then_final_roundtrip_over_real_public_factories()
    {
        RequiredEnv("EDL_TOOLCHAIN_G5_TEST_BUNDLE_PATH");
        RequiredEnv("EDL_CLIENT_TEST_WORK_ROOT");
        string packagePath = RequiredEnv("TF_NATIVE_PACKAGE_PATH");
        string packerPath = RequiredEnv("EDL_RAW_LINUX_PACKER_PATH");
        string unpackerPath = RequiredEnv("EDL_RAW_LINUX_UNPACKER_PATH");

        string caseDirectory = _g5.NewCaseDirectory(
            nameof(Tf_temporary_then_final_roundtrip_over_real_public_factories));
        string backing = Directory.CreateDirectory(Path.Combine(caseDirectory, "backing")).FullName;
        string initialParent = Directory.CreateDirectory(Path.Combine(caseDirectory, "capture-initial")).FullName;
        string freshParent = Directory.CreateDirectory(Path.Combine(caseDirectory, "capture-fresh")).FullName;
        string thirdParent = Directory.CreateDirectory(Path.Combine(caseDirectory, "capture-third")).FullName;
        string evidenceParent = Directory.CreateDirectory(Path.Combine(caseDirectory, "evidence")).FullName;
        string planParent1 = Directory.CreateDirectory(Path.Combine(caseDirectory, "plans-1")).FullName;
        string planParent2 = Directory.CreateDirectory(Path.Combine(caseDirectory, "plans-2")).FullName;

        // Owned resources, disposed in natural reverse order at the end.
        InternalBackupSet? initialBackup = null;
        InternalBackupSet? freshBackup = null;
        InternalBackupSet? thirdBackup = null;
        ImportedPackage? imported = null;
        TfPreparedCardImages? images = null;
        TfBootPlan? ramPlan = null;
        TfBootPlan? finalPlan = null;
        TfBootPlan? thirdRamPlan = null;
        TfBootBackend? temporaryBackend = null;
        TfBootBackend? finalBackend = null;
        TfBootBackend? thirdPreparedBackend = null;
        EdlRawBootTools? tools = null;
        // Opt-in text_offset 0 matches the independently pinned Gen5 public C77 ABI; the old
        // helper default (0x80000) stays unchanged for all other callers.
        using var source = new GblDirectSourceFixture("PRC", mismatchParentBootChild: false, androidTextOffset: 0UL);

        try
        {
            // ---- Step 1: the real modeled G5 device with a valid misc control installed before any capture.
            IB001SyntheticDevice device = IB001SyntheticDevice.CreateDirect(
                backing, source.Sources, source.AvbSources, source.EfispSource, gen5: true);

            (int miscLun, long miscStart, long miscCount, string? _) = device.Expectation("misc");
            device.AddWriteOverlay(
                miscLun, miscStart, miscCount,
                WriteMiscOverlay(Path.Combine(caseDirectory, "inputs"), miscCount));

            // ---- Step 2: session 1, initial capture, real native tools/package, BOTH plans up front.
            (InternalDeviceCheckResult initialCheck, EdlClient initialClient, IB001FakeEdlRunner initialRunner) =
                await NewSessionAsync(device);

            initialBackup = await InternalInstallBackup.CreateAsync(initialClient, initialParent);
            string initialDirectory = initialBackup.DirectoryPath;
            string initialManifest = initialBackup.ManifestSha256;

            tools = await EdlRawBootBuilderTests.LoadToolsAsync();
            var nativeRunner = new EdlRawBootBuilderTests.LinuxOracleRunner(tools, packerPath, unpackerPath);
            int callsBefore = nativeRunner.Calls;

            imported = await PackageImporter.ImportAsync(
                packagePath, Model, InstallationTarget.TfCard,
                Directory.CreateDirectory(Path.Combine(caseDirectory, "package-work")).FullName);
            Assert.True(imported.Validation.IsValid);
            Assert.False(imported.Validation.TestOnly);
            Assert.Equal("tf-raw-v1", imported.Validation.DeploymentKind, ignoreCase: false);
            images = await TfPreparedCardImages.CaptureAsync(imported);
            Assert.NotNull(images.Contract.MaintenanceInitramfs);

            ramPlan = await CurrentBootMenuPlanner.PrepareTfAsync(
                initialBackup, CurrentSlot, BootloaderState.Locked, images,
                TfBootPurpose.RamMaintenance, tools, nativeRunner, planParent1);
            finalPlan = await CurrentBootMenuPlanner.PrepareTfAsync(
                initialBackup, CurrentSlot, BootloaderState.Locked, images,
                TfBootPurpose.FinalTf, tools, nativeRunner, planParent2);

            Assert.True(nativeRunner.Calls > callsBefore);
            Assert.Equal(TfBootPurpose.RamMaintenance, ramPlan.Purpose);
            Assert.Equal(TfBootPurpose.FinalTf, finalPlan.Purpose);
            Assert.Equal(Model, ramPlan.Model);
            Assert.Equal(Model, finalPlan.Model);

            // ---- Step 3: real temporary backend from the RAM plan; execute once; one reset; full proof.
            temporaryBackend = await BootMaintenanceBackend.CreateTfPreparedAsync(
                initialCheck, initialClient, initialBackup, ramPlan, initialRunner, evidenceParent,
                progress: null, cancellationToken: default);

            Assert.Equal(TfBootOperation.Temporary, temporaryBackend.Prepared.Operation);
            Assert.Equal(TfBootPurpose.RamMaintenance, temporaryBackend.Prepared.RawPurpose);
            List<BootMaintenanceRegionSummary> planned =
                temporaryBackend.Prepared.Regions.Where(region => region.WillWrite).ToList();
            var plannedRoles = planned.Select(region => region.Role).ToHashSet(StringComparer.Ordinal);
            Assert.All(plannedRoles, role => Assert.True(
                role == "efisp" || role == "boot_a",
                "unexpected temporary will-write role " + role + "."));
            Assert.Contains("boot_a", plannedRoles);
            Assert.All(ForbiddenWriteRoles, role => Assert.DoesNotContain(role, plannedRoles));

            Assert.True(File.Exists(temporaryBackend.Prepared.RollbackJournalPath));
            int readsBeforeTemporary = initialRunner.Reads.Count;

            TfBootResult temporaryResult =
                await temporaryBackend.ExecuteAsync(temporaryBackend.Prepared.ConfirmationId);

            Assert.Equal(TfBootOperation.Temporary, temporaryResult.Operation);
            Assert.Equal(BootMaintenanceOutcome.Completed, temporaryResult.Outcome);
            Assert.Equal(InternalInstallWriteState.AllVerified, temporaryResult.WriteState);
            Assert.Null(temporaryResult.Error);
            Assert.True(temporaryResult.ResetAccepted == true);
            Assert.Equal(1, initialRunner.ResetCount);
            Assert.Equal(
                plannedRoles.OrderBy(role => role, StringComparer.Ordinal).ToArray(),
                temporaryResult.VerifiedRegions.OrderBy(role => role, StringComparer.Ordinal).ToArray());
            AssertPlannedWritesAndReadback(initialRunner, planned, readsBeforeTemporary);

            // ---- Step 4: fresh session after the temporary write; real final factory binds both captures.
            (InternalDeviceCheckResult freshCheck, EdlClient freshClient, IB001FakeEdlRunner freshRunner) =
                await NewSessionAsync(device);

            freshBackup = await InternalInstallBackup.CreateAsync(freshClient, freshParent);
            Assert.Equal(initialManifest, initialBackup.ManifestSha256); // the initial manifest is unchanged
            Assert.NotEqual(initialDirectory, freshBackup.DirectoryPath);
            Assert.NotEqual(initialManifest, freshBackup.ManifestSha256); // physical boot bytes really changed
            Assert.False(string.Equals(
                initialBackup.Files["boot_a"].Sha256, freshBackup.Files["boot_a"].Sha256,
                StringComparison.OrdinalIgnoreCase));
            Assert.Equal(
                planned.Single(region => region.Role == "boot_a").CandidateSha256,
                freshBackup.Files["boot_a"].Sha256,
                ignoreCase: true);

            var history = await BootMaintenanceBackend.ReadHistoricalIdentityAsync(initialDirectory);

            finalBackend = await BootMaintenanceBackend.CreateTfFinalFromEdlAsync(
                history, freshClient, freshBackup, temporaryBackend, temporaryResult, finalPlan,
                freshRunner, evidenceParent, progress: null, cancellationToken: default);

            Assert.Equal(initialDirectory, finalBackend.Prepared.SourceBackupDirectory);
            Assert.Equal(initialManifest, finalBackend.Prepared.SourceBackupManifestSha256);
            Assert.Equal(freshBackup.DirectoryPath, finalBackend.Prepared.TargetBackupDirectory);
            Assert.Equal(freshBackup.ManifestSha256, finalBackend.Prepared.TargetBackupManifestSha256);

            // Journal provenance: the final and temporary factories produced two distinct actual rollback journals.
            string finalJournalPath = finalBackend.Prepared.RollbackJournalPath;
            string temporaryJournalPath = temporaryBackend.Prepared.RollbackJournalPath;
            Assert.NotEqual(
                Path.GetFullPath(finalJournalPath),
                Path.GetFullPath(temporaryJournalPath),
                StringComparer.OrdinalIgnoreCase);

            // The actual Final journal's possibleWrites array contains the boot_b role entry (lowercase "role").
            using (System.Text.Json.JsonDocument journal = System.Text.Json.JsonDocument.Parse(
                File.ReadAllText(finalJournalPath)))
            {
                Assert.Contains(
                    journal.RootElement.GetProperty("possibleWrites").EnumerateArray(),
                    entry => entry.GetProperty("role").GetString() == "boot_b");
            }

            // ---- Step 5: final execute; boot_b then boot_a; no forced EFI or forbidden writes; one reset.
            List<BootMaintenanceRegionSummary> finalPlanned =
                finalBackend.Prepared.Regions.Where(region => region.WillWrite).ToList();
            var finalRoles = finalPlanned.Select(region => region.Role).ToHashSet(StringComparer.Ordinal);
            Assert.Contains("boot_b", finalRoles);
            Assert.Contains("boot_a", finalRoles);
            Assert.All(ForbiddenWriteRoles, role => Assert.DoesNotContain(role, finalRoles));

            int readsBeforeFinal = freshRunner.Reads.Count;
            TfBootResult finalResult =
                await finalBackend.ExecuteAsync(finalBackend.Prepared.ConfirmationId);

            Assert.Equal(TfBootOperation.Final, finalResult.Operation);
            Assert.Equal(BootMaintenanceOutcome.Completed, finalResult.Outcome);
            Assert.Equal(InternalInstallWriteState.AllVerified, finalResult.WriteState);
            Assert.Null(finalResult.Error);
            Assert.True(finalResult.ResetAccepted == true);
            Assert.Equal(1, freshRunner.ResetCount);
            Assert.Equal(
                finalRoles.OrderBy(role => role, StringComparer.Ordinal).ToArray(),
                finalResult.VerifiedRegions.OrderBy(role => role, StringComparer.Ordinal).ToArray());

            // Plan order: inactive slot b first, then current slot a.
            Assert.Equal(2, freshRunner.Writes.Count);
            Assert.Equal("boot_b", MatchRole(freshRunner.Writes[0], finalPlanned));
            Assert.Equal("boot_a", MatchRole(freshRunner.Writes[1], finalPlanned));
            AssertPlannedWritesAndReadback(freshRunner, finalPlanned, readsBeforeFinal);

            // ---- Step 6: third fresh session; a new RAM plan against the CURRENT capture must plan no
            // efisp write (the identical EFI runtime is already on disk) while still planning boot_a.
            // The prepared backend is proven constructible and accepted, then disposed WITHOUT executing
            // (no extra reset) — the original "identical EFI 0-companion" bug route stays construct-only.
            (InternalDeviceCheckResult thirdCheck, EdlClient thirdClient, IB001FakeEdlRunner thirdRunner) =
                await NewSessionAsync(device);

            thirdBackup = await InternalInstallBackup.CreateAsync(thirdClient, thirdParent);

            thirdRamPlan = await CurrentBootMenuPlanner.PrepareTfAsync(
                thirdBackup, CurrentSlot, BootloaderState.Locked, images,
                TfBootPurpose.RamMaintenance, tools, nativeRunner,
                Directory.CreateDirectory(Path.Combine(caseDirectory, "plans-3")).FullName);
            Assert.Equal(TfBootPurpose.RamMaintenance, thirdRamPlan.Purpose);

            thirdPreparedBackend = await BootMaintenanceBackend.CreateTfPreparedAsync(
                thirdCheck, thirdClient, thirdBackup, thirdRamPlan, thirdRunner, evidenceParent,
                progress: null, cancellationToken: default);

            var thirdRoles = thirdPreparedBackend.Prepared.Regions
                .Where(region => region.WillWrite)
                .Select(region => region.Role)
                .ToHashSet(StringComparer.Ordinal);
            Assert.DoesNotContain("efisp", thirdRoles);
            Assert.Contains("boot_a", thirdRoles);
            Assert.All(ForbiddenWriteRoles, role => Assert.DoesNotContain(role, thirdRoles));
            Assert.Equal(0, thirdRunner.ResetCount); // never executed: nothing was written or reset
        }
        finally
        {
            thirdPreparedBackend?.Dispose();
            thirdRamPlan?.Dispose();
            finalBackend?.Dispose();
            temporaryBackend?.Dispose();
            finalPlan?.Dispose();
            ramPlan?.Dispose();
            images?.Dispose();
            imported?.Dispose();
            thirdBackup?.Dispose();
            freshBackup?.Dispose();
            initialBackup?.Dispose();
            tools?.Dispose();
        }
    }

    // ------------------------------------------------------------------ session + fixture helpers

    /// <summary>One real session: an actual device check plus a real EdlClient over the fake EDL transport.</summary>
    private async Task<(InternalDeviceCheckResult Check, EdlClient Client, IB001FakeEdlRunner Runner)>
        NewSessionAsync(IB001SyntheticDevice device)
    {
        DeviceCheckRunner checkRunner = new(Serial, new DeviceCheckClock(), model: Model,
            displayId: _g5.Toolchain.AndroidBuild, soc: E003EdlTestData.SocSerialDecimal)
        {
            FastbootProductValue = "baldur",
            UnlockedReportValue = "no",
            FastbootCurrentSlot = CurrentSlot,
            ReturnSlotSuffix = "_a",
            BootImmediatelyCompleteOnReturn = true,
        };
        var deviceCheck = new InternalInstallDeviceCheck(
            AdbOrFastboot.AdbPath, AdbOrFastboot.FastbootPath, checkRunner, checkRunner.Clock);
        InternalDeviceCheckResult result = await deviceCheck.CheckAsync(Serial);
        Assert.True(result.Succeeded);

        IB001FakeEdlRunner runner = new(device, enableWrites: true, hardwareId: _g5.Toolchain.HardwareId);
        EdlClient client = new(
            _g5.Toolchain,
            new EdlEntryResult(result.Android!, E003EdlTestData.Endpoint(), E003EdlTestData.BusSerialHex),
            runner,
            new E003ScriptedEndpointDiscovery { Endpoints = new[] { E003EdlTestData.Endpoint() } });

        return (result, client, runner);
    }

    /// <summary>
    /// Installs the synthetic misc overlay sized to the REAL misc partition: the existing CRC32-valid
    /// boot_control block selecting _a (via the two approved pure helpers, priorities 15/14, default
    /// successful state) plus the 64-byte modern virtual-ab note at byte 32768. Pure fixture bytes; no
    /// wipe command, no device-side writes beyond the overlay registration.
    /// </summary>
    private static string WriteMiscOverlay(string directory, long miscCountSectors)
    {
        byte[] control = (byte[])ControlBlockMethod.Invoke(null, new object?[] { "_a", (byte)0, 15, 14 })!;
        byte[] controlPage = (byte[])BuildMiscMethod.Invoke(null, new object?[] { control })!;

        var overlay = new byte[miscCountSectors * IB001SyntheticDevice.SectorSize];
        Assert.True(controlPage.Length <= overlay.Length, "the built misc control page exceeds the real misc partition.");

        Buffer.BlockCopy(controlPage, 0, overlay, 0, controlPage.Length);

        overlay[32768] = 2;
        BinaryPrimitives.WriteUInt32LittleEndian(overlay.AsSpan(32768 + 1), 0x56740AB0);
        overlay[32768 + 5] = 0; // status: completed
        overlay[32768 + 6] = 0; // source hint

        string path = Path.Combine(directory, "misc-overlay.img");
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(path, overlay);
        return path;
    }

    /// <summary>
    /// Independent write proof: every actual IB001Write matches exactly one planned region's geometry and
    /// candidate SHA, in plan order; then every written range is re-read whole after the writes and the
    /// readback file hashes to the planned candidate bytes.
    /// </summary>
    private static void AssertPlannedWritesAndReadback(
        IB001FakeEdlRunner runner,
        IReadOnlyList<BootMaintenanceRegionSummary> planned,
        int readsFrom)
    {
        Assert.Equal(planned.Count, runner.Writes.Count);

        // Execution order rank: efisp first, then inactive slot boot_b, then current slot boot_a.
        // Prepared.Regions enumeration order is not guaranteed to be the execution order, so build an
        // explicit ordered view of the same planned rows before any index-based geometry comparison.
        static int Rank(string role) => role switch
        {
            "efisp" => 0,
            "boot_b" => 1,
            "boot_a" => 2,
            _ => throw new InvalidOperationException("unexpected will-write role " + role + "."),
        };
        var ordered = planned.OrderBy(region => Rank(region.Role)).ToArray();

        for (int index = 0; index < ordered.Length; index++)
        {
            BootMaintenanceRegionSummary region = ordered[index];
            IB001Write write = runner.Writes[index];
            Assert.Equal(region.Lun, write.Lun);
            Assert.Equal(region.StartSector, write.StartSector);
            Assert.Equal(region.SectorCount, write.SectorCount);
            Assert.Equal(region.Length, write.SectorCount * IB001SyntheticDevice.SectorSize);
            Assert.Equal(region.CandidateSha256, write.Sha256, ignoreCase: true);
        }

        foreach (IB001Write write in runner.Writes)
        {
            IB001Read? last = null;
            for (int r = readsFrom; r < runner.Reads.Count; r++)
            {
                IB001Read read = runner.Reads[r];
                if (read.Lun == write.Lun
                    && read.StartSector == write.StartSector
                    && read.SectorCount == write.SectorCount)
                {
                    last = read;
                }
            }

            Assert.NotNull(last);
            Assert.Equal(write.Sha256, Sha256File(last!.FilePath), ignoreCase: true);
        }
    }

    /// <summary>Matches one actual write record to its planned region by exact geometry.</summary>
    private static string MatchRole(IB001Write write, IReadOnlyList<BootMaintenanceRegionSummary> planned) =>
        planned.Single(region =>
            region.Lun == write.Lun
            && region.StartSector == write.StartSector
            && region.SectorCount == write.SectorCount).Role;

    private static string RequiredEnv(string name) =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
            ? value
            : throw new InvalidOperationException("required environment variable " + name + " is not set.");

    private static string Sha256File(string path)
    {
        using FileStream stream = new(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.SequentialScan);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }
}
