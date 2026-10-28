using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// TF-BOOT-RECOVERY-TEST1: the public persisted-journal recovery genuinely survives a process restart.
/// A historical stock capture plus an externally written rollback journal (the real JSON schema, built
/// from the actual captured 52-region facts) let a fresh session restore a partially written boot_a,
/// while changed non-intent regions and unsafe misc transitions are refused before any write or reset.
/// Everything runs through the real <see cref="EdlClient"/> over the real toolchain with the IB001 fake
/// transport; only already-existing pure synthetic data writers are reached by narrow reflection, exactly
/// like the stock backend tests, and nothing readiness-shaped is ever forged through it. The journal is a
/// plain locator document written with System.Text.Json; the hint reader is never an execution authority.
/// </summary>
public sealed class TfBootRecoveryTests : IClassFixture<EdlClientToolchainFixture>
{
    private const string Serial = "TF-SYNTHETIC-R";

    /// <summary>Payload flip inside the intended (journal candidate) boot_a image.</summary>
    private const int CandidateFlipOffset = 4096 + 128;

    /// <summary>Different payload flip inside the damaged current boot_a on the device.</summary>
    private const int CurrentFlipOffset = 8192 + 64;

    private const string RecoveryRole = "boot_a";

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

    private static readonly string[] AuxRoles =
    {
        "vendor_boot_a", "vendor_boot_b", "init_boot_a", "init_boot_b",
        "abl_a", "abl_b", "xbl_config_a", "xbl_config_b",
    };

    private static readonly JsonSerializerOptions JournalJsonOptions = new()
    {
        WriteIndented = true,
    };

    private readonly EdlClientToolchainFixture _fixture;

    public TfBootRecoveryTests(EdlClientToolchainFixture fixture)
    {
        _fixture = fixture;
    }

    // ------------------------------------------------------------ journal documents

    private sealed record JournalGeometry(
        [property: JsonPropertyName("lun")] int Lun,
        [property: JsonPropertyName("sectorSize")] int SectorSize,
        [property: JsonPropertyName("totalSectors")] long TotalSectors);

    private sealed record JournalCapture(
        [property: JsonPropertyName("role")] string Role,
        [property: JsonPropertyName("lun")] int Lun,
        [property: JsonPropertyName("startSector")] long StartSector,
        [property: JsonPropertyName("sectorCount")] long SectorCount,
        [property: JsonPropertyName("length")] long Length,
        [property: JsonPropertyName("partUuid")] string? PartUuid,
        [property: JsonPropertyName("sha256")] string Sha256);

    private sealed record JournalPossibleWrite(
        [property: JsonPropertyName("role")] string Role,
        [property: JsonPropertyName("slot")] string Slot,
        [property: JsonPropertyName("stagedCandidateSha256")] string StagedCandidateSha256);

    private sealed record JournalDocument(
        [property: JsonPropertyName("schema")] int Schema,
        [property: JsonPropertyName("operation")] string Operation,
        [property: JsonPropertyName("nonce")] string Nonce,
        [property: JsonPropertyName("confirmationSha256")] string ConfirmationSha256,
        [property: JsonPropertyName("originalBackupDirectory")] string OriginalBackupDirectory,
        [property: JsonPropertyName("originalBackupManifestSha256")] string OriginalBackupManifestSha256,
        [property: JsonPropertyName("profileId")] string ProfileId,
        [property: JsonPropertyName("model")] string Model,
        [property: JsonPropertyName("hardwareId")] string HardwareId,
        [property: JsonPropertyName("androidSerial")] string AndroidSerial,
        [property: JsonPropertyName("socSerial")] string SocSerial,
        [property: JsonPropertyName("currentSlot")] string CurrentSlot,
        [property: JsonPropertyName("geometries")] List<JournalGeometry> Geometries,
        [property: JsonPropertyName("originalCaptures")] List<JournalCapture> OriginalCaptures,
        [property: JsonPropertyName("possibleWrites")] List<JournalPossibleWrite> PossibleWrites);

    // ------------------------------------------------------------ shared recovery case

    private sealed record RecoveryCase(
        BootMaintenanceStockChainTests.ChainRun Graph,
        IB001SyntheticDevice Device,
        string Inputs,
        string CaseDirectory,
        string OriginalDirectory,
        string EvidenceParent,
        EdlClient Client,
        IB001FakeEdlRunner Runner,
        InternalBackupSet FreshBackup,
        string DamagedBootASha,
        IReadOnlyDictionary<string, string> OriginalSha256,
        IReadOnlyDictionary<string, string> OriginalFilePaths,
        List<JournalGeometry> Geometries,
        List<JournalCapture> Captures,
        string HistoricalManifestSha256,
        string ProfileId,
        string Model,
        string HardwareId,
        string AndroidSerial,
        string SocSerial);

    /// <summary>
    /// Builds the whole restart scenario: the stock synthetic device with signed boots grown to 96 MiB,
    /// the aux roles from the legacy fixture, one valid misc overlay selecting slot a; then the real
    /// historical capture (whose original directory keeps its files), the journal facts, the fresh
    /// mutations (a damaged current boot_a only, plus optional per-test extras) and a completely new
    /// DeviceCheck/EdlClient/fresh backup. The old session's client and backend never participate again.
    /// </summary>
    private async Task<RecoveryCase> SetUpRecoveryCaseAsync(
        string name,
        byte baselineTries = 7,
        byte? freshTries = null,
        bool flipUnrelatedMiscByte = false,
        bool damageBootB = false,
        bool damageVendorBootA = false)
    {
        string caseDirectory = _fixture.NewCaseDirectory(name);
        string inputs = Directory.CreateDirectory(Path.Combine(caseDirectory, "inputs")).FullName;
        string backing = Directory.CreateDirectory(Path.Combine(caseDirectory, "backing")).FullName;
        string originalParent = Directory.CreateDirectory(Path.Combine(caseDirectory, "original")).FullName;
        string freshParent = Directory.CreateDirectory(Path.Combine(caseDirectory, "fresh")).FullName;
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

            // Historical misc: valid boot_control selecting _a with the requested baseline tries.
            string baselineMiscPath = Path.Combine(inputs, "misc-baseline.img");
            File.WriteAllBytes(baselineMiscPath, BuildMiscOverlay(baselineTries, null));
            (int miscLun, long miscStart, long miscCount, string? _) = device.Expectation("misc");
            device.AddWriteOverlay(miscLun, miscStart, miscCount, baselineMiscPath);

            // Historical stock capture over a real check and a read-only EDL session.
            DeviceCheckRunner firstRunner = NewDeviceCheckRunner();
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

            var originalSha = new Dictionary<string, string>(StringComparer.Ordinal);
            var captures = new List<JournalCapture>();
            foreach ((string role, EdlCapturedRegion region) in historical.Files)
            {
                originalSha[role] = region.Sha256;
                captures.Add(new JournalCapture(
                    role, region.Lun, region.StartSector, region.SectorCount, region.Length,
                    region.PartUuid, region.Sha256));
            }

            var geometries = historical.Geometries.Values
                .Select(g => new JournalGeometry(g.Lun, g.SectorSize, g.TotalSectors))
                .ToList();
            string historicalManifestSha = historical.ManifestSha256;

            // Identity facts captured from the historical capture and the first session, plus the
            // actual original backup file paths (metadata only, no own file leases), before disposal.
            string profileId = historical.ProfileId;
            string model = historical.Model;
            string hardwareId = historical.HardwareId;
            string androidSerial = first.Android!.Identity.Serial;
            string socSerial = first.Android.SocSerial;
            var originalFilePaths = historical.Files.ToDictionary(
                pair => pair.Key, pair => pair.Value.FilePath, StringComparer.Ordinal);

            string originalDirectory = historical.DirectoryPath;
            historical.Dispose();

            // Fresh mutations: the current boot_a is a whole-partition candidate damaged at a DIFFERENT
            // byte than the journal's intended candidate; nothing else on the device is touched unless a
            // specific test asks for it.
            string damagedA = CopyWithFlippedByte(
                bootA, CurrentFlipOffset, Path.Combine(inputs, "current-boot_a.img"));
            InstallOverlay(device, RecoveryRole, damagedA);

            if (damageBootB)
            {
                string damagedB = CopyWithFlippedByte(
                    bootB, CurrentFlipOffset, Path.Combine(inputs, "current-boot_b.img"));
                InstallOverlay(device, "boot_b", damagedB);
            }

            if (damageVendorBootA)
            {
                string damagedVendor = CopyWithFlippedByte(
                    sources["vendor_boot_a"].Path, 0,
                    Path.Combine(inputs, "current-vendor_boot_a.img"));
                InstallOverlay(device, "vendor_boot_a", damagedVendor);
            }

            if (freshTries is byte tries)
            {
                string freshMiscPath = Path.Combine(inputs, "misc-fresh.img");
                File.WriteAllBytes(freshMiscPath, BuildMiscOverlay(baselineTries, tries));
                device.AddWriteOverlay(miscLun, miscStart, miscCount, freshMiscPath);
            }
            else if (flipUnrelatedMiscByte)
            {
                string flippedMiscPath = Path.Combine(inputs, "misc-flipped.img");
                byte[] overlay = File.ReadAllBytes(baselineMiscPath);
                overlay[64] ^= 0xFF;
                File.WriteAllBytes(flippedMiscPath, overlay);
                device.AddWriteOverlay(miscLun, miscStart, miscCount, flippedMiscPath);
            }

            // Completely fresh session: new check, new write-enabled runner, new client, new backup.
            DeviceCheckRunner freshRunner = NewDeviceCheckRunner();
            var freshCheck = new InternalInstallDeviceCheck(
                AdbOrFastboot.AdbPath, AdbOrFastboot.FastbootPath, freshRunner, freshRunner.Clock);
            InternalDeviceCheckResult fresh = await freshCheck.CheckAsync(Serial);
            Assert.True(fresh.Succeeded);

            IB001FakeEdlRunner runner = new(device, enableWrites: true);
            EdlClient client = NewClient(
                new EdlEntryResult(fresh.Android!, E003EdlTestData.Endpoint(), E003EdlTestData.BusSerialHex),
                runner);

            InternalBackupSet freshBackup = await InternalInstallBackup.CreateAsync(client, freshParent);

            return new RecoveryCase(
                graph, device, inputs, caseDirectory, originalDirectory, evidenceParent,
                client, runner, freshBackup,
                Sha256File(damagedA), originalSha, originalFilePaths, geometries, captures,
                historicalManifestSha,
                profileId, model, hardwareId, androidSerial, socSerial);
        }
        catch
        {
            graph.Dispose();
            throw;
        }
    }

    private static void InstallOverlay(IB001SyntheticDevice device, string role, string path)
    {
        (int lun, long start, long count, string? _) = device.Expectation(role);
        device.AddWriteOverlay(lun, start, count, path);
    }

    // ------------------------------------------------------------ journal writing

    private static string NewNonce()
    {
        Span<byte> bytes = stackalloc byte[16];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string NewConfirmationId()
    {
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string Sha256String(string value) =>
        Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static JournalDocument BuildJournalDocument(
        RecoveryCase scenario,
        string journalPath,
        string confirmationId,
        string candidateSha,
        string? hardwareIdOverride = null,
        bool duplicatePossibleWrite = false,
        bool dropOneCapture = false)
    {
        var possibleWrites = new List<JournalPossibleWrite>
        {
            new(RecoveryRole, "a", candidateSha),
        };
        if (duplicatePossibleWrite)
        {
            possibleWrites.Add(new JournalPossibleWrite(RecoveryRole, "a", candidateSha));
        }

        var captures = scenario.Captures;
        if (dropOneCapture)
        {
            captures = scenario.Captures
                .Where(capture => capture.Role != RecoveryRole)
                .ToList();
        }

        return new JournalDocument(
            Schema: 1,
            Operation: "Temporary",
            Nonce: NewNonce(),
            ConfirmationSha256: Sha256String(confirmationId),
            OriginalBackupDirectory: scenario.OriginalDirectory,
            OriginalBackupManifestSha256: scenario.HistoricalManifestSha256,
            ProfileId: scenario.ProfileId,
            Model: scenario.Model,
            HardwareId: hardwareIdOverride ?? scenario.HardwareId,
            AndroidSerial: scenario.AndroidSerial,
            SocSerial: scenario.SocSerial,
            CurrentSlot: "a",
            Geometries: scenario.Geometries,
            OriginalCaptures: captures,
            PossibleWrites: possibleWrites);
    }

    private static string WriteJournal(JournalDocument document, string journalPath)
    {
        File.WriteAllText(journalPath, JsonSerializer.Serialize(document, JournalJsonOptions));
        return journalPath;
    }

    // ------------------------------------------------------------ focused facts

    [Fact]
    public async Task Recovery_PrepareAndExecute_RestoresPartialBootA_WholeVerified_OnceReset()
    {
        RecoveryCase scenario = await SetUpRecoveryCaseAsync(
            nameof(Recovery_PrepareAndExecute_RestoresPartialBootA_WholeVerified_OnceReset));
        try
        {
            // The intended (interrupted) candidate differs from both the original stock image and the
            // damaged current device bytes: a genuinely partial boot write.
            string intended = CopyWithFlippedByte(
                Path.Combine(scenario.Inputs, "boot_a-full.img"), CandidateFlipOffset,
                Path.Combine(scenario.Inputs, "intended-boot_a.img"));
            string candidateSha = Sha256File(intended);
            string originalSha = scenario.OriginalSha256[RecoveryRole];
            Assert.NotEqual(originalSha, candidateSha);
            Assert.NotEqual(originalSha, scenario.DamagedBootASha);
            Assert.NotEqual(candidateSha, scenario.DamagedBootASha);

            string confirmationId = NewConfirmationId();
            string journalPath = WriteJournal(
                BuildJournalDocument(scenario, Path.Combine(scenario.CaseDirectory, "tf-rollback.json"),
                    confirmationId, candidateSha),
                Path.Combine(scenario.CaseDirectory, "tf-rollback.json"));

            // Format-only hint: readable on its own, never an execution authority (no backend yet).
            _ = await BootMaintenanceBackend.ReadTfRecoveryHintAsync(journalPath);
            Assert.Empty(scenario.Runner.Writes);
            Assert.Equal(0, scenario.Runner.ResetCount);

            var history = await BootMaintenanceBackend.ReadHistoricalIdentityAsync(scenario.OriginalDirectory);

            using TfBootBackend backend = await BootMaintenanceBackend.CreateTfRestorePreviousFromEdlAsync(
                history,
                scenario.Client,
                scenario.FreshBackup,
                journalPath,
                scenario.Runner,
                scenario.EvidenceParent,
                progress: null,
                cancellationToken: CancellationToken.None);

            Assert.Equal("RestorePrevious", backend.Prepared.Operation.ToString());
            // Restoration requires a NEW confirmation minted by the backend, never the journal's id
            // (nor the journal's confirmation sha of that id).
            Assert.NotEqual(confirmationId, backend.Prepared.ConfirmationId);
            Assert.NotEqual(Sha256String(confirmationId), backend.Prepared.ConfirmationId);
            Assert.Equal(scenario.HistoricalManifestSha256, backend.Prepared.SourceBackupManifestSha256, ignoreCase: true);
            Assert.Equal(scenario.FreshBackup.ManifestSha256, backend.Prepared.TargetBackupManifestSha256, ignoreCase: true);

            var willWrite = backend.Prepared.Regions.Where(region => region.WillWrite).ToList();
            var entry = Assert.Single(willWrite);
            Assert.Equal(RecoveryRole, entry.Role);
            Assert.Equal(originalSha, entry.CandidateSha256, ignoreCase: true);
            Assert.Equal(scenario.DamagedBootASha, entry.OriginalSha256, ignoreCase: true);

            // A wrong confirmation never writes and never resets; the backend-minted id must be sent
            // for the real execution.
            int writesBeforeWrong = scenario.Runner.Writes.Count;
            await Assert.ThrowsAnyAsync<Exception>(
                () => backend.ExecuteAsync(backend.Prepared.ConfirmationId + "00"));
            Assert.Equal(writesBeforeWrong, scenario.Runner.Writes.Count);
            Assert.Equal(0, scenario.Runner.ResetCount);

            (int lun, long start, long count, string? _) = scenario.Device.Expectation(RecoveryRole);
            int readsBeforeExecute = scenario.Runner.Reads.Count;

            TfBootResult result = await backend.ExecuteAsync(backend.Prepared.ConfirmationId);

            Assert.Equal(BootMaintenanceOutcome.Completed, result.Outcome);
            Assert.Equal(InternalInstallWriteState.AllVerified, result.WriteState);
            Assert.Null(result.Error);
            Assert.True(result.ResetAccepted);
            Assert.False(result.NeedsBootloaderAttention);
            Assert.Equal(new[] { RecoveryRole }, result.VerifiedRegions);

            // Exactly one whole-region write carrying the original stock bytes, and exactly one reset.
            IB001Write write = Assert.Single(scenario.Runner.Writes);
            Assert.Equal(lun, write.Lun);
            Assert.Equal(start, write.StartSector);
            Assert.Equal(count, write.SectorCount);
            Assert.Equal(count * IB001SyntheticDevice.SectorSize, new FileInfo(write.FilePath).Length);
            Assert.Equal(originalSha, write.Sha256, ignoreCase: true);
            Assert.Equal(1, scenario.Runner.ResetCount);

            // Complete readback proof: first whole re-read sees the damaged current bytes, the final whole
            // re-read sees the restored original bytes.
            IB001Read? first = null;
            IB001Read? last = null;
            foreach (IB001Read read in scenario.Runner.Reads.Skip(readsBeforeExecute))
            {
                if (read.Lun != lun || read.StartSector != start || read.SectorCount != count)
                {
                    continue;
                }

                first ??= read;
                last = read;
            }

            Assert.NotNull(first);
            Assert.NotNull(last);
            Assert.Equal(scenario.DamagedBootASha, Sha256File(first!.FilePath), ignoreCase: true);
            Assert.Equal(originalSha, Sha256File(last!.FilePath), ignoreCase: true);
        }
        finally
        {
            scenario.FreshBackup.Dispose();
            scenario.Graph.Dispose();
        }
    }

    [Fact]
    public async Task Recovery_FinalJournal_PartialInactiveBootB_RestoresOriginalBothSlots_AfterRestart()
    {
        RecoveryCase scenario = await SetUpRecoveryCaseAsync(
            nameof(Recovery_FinalJournal_PartialInactiveBootB_RestoresOriginalBothSlots_AfterRestart),
            damageBootB: true);
        try
        {
            // Intended (interrupted) candidates for both slots differ from the stock originals and
            // from the damaged current device bytes on both slots.
            string intendedA = CopyWithFlippedByte(
                Path.Combine(scenario.Inputs, "boot_a-full.img"), CandidateFlipOffset,
                Path.Combine(scenario.Inputs, "intended-boot_a.img"));
            string intendedB = CopyWithFlippedByte(
                Path.Combine(scenario.Inputs, "boot_b-full.img"), CandidateFlipOffset,
                Path.Combine(scenario.Inputs, "intended-boot_b.img"));
            string intendedASha = Sha256File(intendedA);
            string intendedBSha = Sha256File(intendedB);
            string originalASha = scenario.OriginalSha256[RecoveryRole];
            string originalBSha = scenario.OriginalSha256["boot_b"];
            string currentASha = scenario.DamagedBootASha;
            string currentBSha = scenario.FreshBackup.Files["boot_b"].Sha256;

            Assert.NotEqual(originalASha, intendedASha);
            Assert.NotEqual(originalASha, currentASha);
            Assert.NotEqual(intendedASha, currentASha);
            Assert.NotEqual(originalBSha, intendedBSha);
            Assert.NotEqual(originalBSha, currentBSha);
            Assert.NotEqual(intendedBSha, currentBSha);

            // Persisted Final journal with exactly the two listed intents (A and B).
            string confirmationId = NewConfirmationId();
            var possibleWrites = new List<JournalPossibleWrite>
            {
                new(RecoveryRole, "a", intendedASha),
                new("boot_b", "b", intendedBSha),
            };
            string journalPath = Path.Combine(scenario.CaseDirectory, "tf-rollback.json");
            WriteJournal(
                BuildJournalDocument(scenario, journalPath, confirmationId, intendedASha) with
                {
                    Operation = "Final",
                    PossibleWrites = possibleWrites,
                },
                journalPath);

            // Format-only hint, then the true historical identity; still no backend/result yet.
            _ = await BootMaintenanceBackend.ReadTfRecoveryHintAsync(journalPath);
            var history = await BootMaintenanceBackend.ReadHistoricalIdentityAsync(scenario.OriginalDirectory);

            using TfBootBackend backend = await BootMaintenanceBackend.CreateTfRestorePreviousFromEdlAsync(
                history,
                scenario.Client,
                scenario.FreshBackup,
                journalPath,
                scenario.Runner,
                scenario.EvidenceParent,
                progress: null,
                cancellationToken: CancellationToken.None);

            // Nothing touched at prepare; a new confirmation was minted.
            Assert.Empty(scenario.Runner.Writes);
            Assert.Equal(0, scenario.Runner.ResetCount);
            Assert.Equal("RestorePrevious", backend.Prepared.Operation.ToString());
            Assert.NotEqual(confirmationId, backend.Prepared.ConfirmationId);
            Assert.NotEqual(Sha256String(confirmationId), backend.Prepared.ConfirmationId);
            Assert.Equal(scenario.HistoricalManifestSha256, backend.Prepared.SourceBackupManifestSha256, ignoreCase: true);
            Assert.Equal(scenario.FreshBackup.ManifestSha256, backend.Prepared.TargetBackupManifestSha256, ignoreCase: true);

            // Both slots restore to ORIGINAL stock bytes over their damaged fresh captures, B first.
            var willWrite = backend.Prepared.Regions.Where(region => region.WillWrite).ToList();
            Assert.Equal(2, willWrite.Count);
            Assert.Equal(new[] { "boot_b", RecoveryRole }, willWrite.Select(region => region.Role).ToArray());
            foreach (var entry in willWrite)
            {
                Assert.Equal(scenario.OriginalSha256[entry.Role], entry.CandidateSha256, ignoreCase: true);
                Assert.Equal(scenario.FreshBackup.Files[entry.Role].Sha256, entry.OriginalSha256, ignoreCase: true);
            }

            int readsBeforeExecute = scenario.Runner.Reads.Count;
            TfBootResult result = await backend.ExecuteAsync(backend.Prepared.ConfirmationId);

            Assert.Equal(BootMaintenanceOutcome.Completed, result.Outcome);
            Assert.Equal(InternalInstallWriteState.AllVerified, result.WriteState);
            Assert.Null(result.Error);
            Assert.True(result.ResetAccepted);
            Assert.False(result.NeedsBootloaderAttention);
            Assert.Equal(new[] { "boot_b", RecoveryRole }, result.VerifiedRegions);
            Assert.Equal(2, scenario.Runner.Writes.Count);
            Assert.Equal(1, scenario.Runner.ResetCount);

            // Each whole-region write carries the original stock bytes at the exact device extent,
            // with whole preflight/readback reads proving the damaged bytes before and original after.
            for (int index = 0; index < scenario.Runner.Writes.Count; index++)
            {
                IB001Write write = scenario.Runner.Writes[index];
                string role = willWrite[index].Role;
                (int lun, long start, long count, string? _) = scenario.Device.Expectation(role);
                Assert.Equal(lun, write.Lun);
                Assert.Equal(start, write.StartSector);
                Assert.Equal(count, write.SectorCount);
                Assert.Equal(scenario.OriginalSha256[role], write.Sha256, ignoreCase: true);
                Assert.Equal(count * IB001SyntheticDevice.SectorSize, new FileInfo(write.FilePath).Length);

                IB001Read? first = null;
                IB001Read? last = null;
                foreach (IB001Read read in scenario.Runner.Reads.Skip(readsBeforeExecute))
                {
                    if (read.Lun != lun || read.StartSector != start || read.SectorCount != count)
                    {
                        continue;
                    }

                    first ??= read;
                    last = read;
                }

                Assert.NotNull(first);
                Assert.NotNull(last);
                Assert.Equal(scenario.FreshBackup.Files[role].Sha256, Sha256File(first!.FilePath), ignoreCase: true);
                Assert.Equal(scenario.OriginalSha256[role], Sha256File(last!.FilePath), ignoreCase: true);
            }
        }
        finally
        {
            scenario.FreshBackup.Dispose();
            scenario.Graph.Dispose();
        }
    }

    [Theory]
    [InlineData((byte)6, false)] // legit selected-tries decrement 7 -> 6: recovery still allowed
    [InlineData((byte)0, true)]  // tries exhausted 7 -> 0: recovery runs but needs bootloader attention
    public async Task Recovery_SelectedTriesTransition_OnlyTriesByteChanges_AttentionMatches(byte freshTries, bool expectAttention)
    {
        RecoveryCase scenario = await SetUpRecoveryCaseAsync(
            nameof(Recovery_SelectedTriesTransition_OnlyTriesByteChanges_AttentionMatches) + "_" + freshTries,
            freshTries: freshTries);
        try
        {
            string intended = CopyWithFlippedByte(
                Path.Combine(scenario.Inputs, "boot_a-full.img"), CandidateFlipOffset,
                Path.Combine(scenario.Inputs, "intended-boot_a.img"));
            string confirmationId = NewConfirmationId();
            string journalPath = WriteJournal(
                BuildJournalDocument(scenario, Path.Combine(scenario.CaseDirectory, "tf-rollback.json"),
                    confirmationId, Sha256File(intended)),
                Path.Combine(scenario.CaseDirectory, "tf-rollback.json"));

            var history = await BootMaintenanceBackend.ReadHistoricalIdentityAsync(scenario.OriginalDirectory);

            using TfBootBackend backend = await BootMaintenanceBackend.CreateTfRestorePreviousFromEdlAsync(
                history,
                scenario.Client,
                scenario.FreshBackup,
                journalPath,
                scenario.Runner,
                scenario.EvidenceParent,
                progress: null,
                cancellationToken: CancellationToken.None);

            Assert.Equal(RecoveryRole, Assert.Single(
                backend.Prepared.Regions.Where(region => region.WillWrite)).Role);

            TfBootResult result = await backend.ExecuteAsync(backend.Prepared.ConfirmationId);

            Assert.Equal(BootMaintenanceOutcome.Completed, result.Outcome);
            Assert.Equal(InternalInstallWriteState.AllVerified, result.WriteState);
            Assert.True(result.ResetAccepted);
            Assert.Equal(expectAttention, result.NeedsBootloaderAttention);
            Assert.Equal(1, scenario.Runner.ResetCount);

            // The misc transition changed only the packed slot-a control byte (tries field) and possibly
            // a subset of the CRC bytes; slot priority, the other slot, and every other misc byte are
            // unchanged across the whole image.
            string baselinePath = Path.Combine(scenario.Inputs, "misc-baseline.img");
            string freshPath = Path.Combine(scenario.Inputs, "misc-fresh.img");
            var diffs = DiffByteOffsets(baselinePath, freshPath).ToList();
            Assert.Contains(2060, diffs);
            Assert.All(diffs, offset => Assert.True(
                offset == 2060 || (offset >= 2076 && offset <= 2079),
                "unexpected misc diff at " + offset + "."));

            if (freshTries == 0)
            {
                // With tries exhausted, reading the fresh control via the real parser throws before
                // or after recovery (the exhausted slot is not bootable), yet recovery still ran with
                // attention requested, as asserted above.
                await Assert.ThrowsAnyAsync<Exception>(
                    () => BootSlotControl.ReadAsync(FileClaim(freshPath)));
            }
        }
        finally
        {
            scenario.FreshBackup.Dispose();
            scenario.Graph.Dispose();
        }
    }

    [Fact]
    public async Task Recovery_SelectedTriesIncrease_RefusesBeforeAnyWriteOrReset()
    {
        RecoveryCase scenario = await SetUpRecoveryCaseAsync(
            nameof(Recovery_SelectedTriesIncrease_RefusesBeforeAnyWriteOrReset),
            baselineTries: 6,
            freshTries: 7);
        try
        {
            string intended = CopyWithFlippedByte(
                Path.Combine(scenario.Inputs, "boot_a-full.img"), CandidateFlipOffset,
                Path.Combine(scenario.Inputs, "intended-boot_a.img"));
            string journalPath = WriteJournal(
                BuildJournalDocument(scenario, Path.Combine(scenario.CaseDirectory, "tf-rollback.json"),
                    NewConfirmationId(), Sha256File(intended)),
                Path.Combine(scenario.CaseDirectory, "tf-rollback.json"));

            var history = await BootMaintenanceBackend.ReadHistoricalIdentityAsync(scenario.OriginalDirectory);

            Exception failure = await Assert.ThrowsAnyAsync<Exception>(
                () => BootMaintenanceBackend.CreateTfRestorePreviousFromEdlAsync(
                    history,
                    scenario.Client,
                    scenario.FreshBackup,
                    journalPath,
                    scenario.Runner,
                    scenario.EvidenceParent,
                    progress: null,
                    cancellationToken: CancellationToken.None));
            Assert.Contains("tries increased", failure.Message);

            Assert.Empty(scenario.Runner.Writes);
            Assert.Equal(0, scenario.Runner.ResetCount);
        }
        finally
        {
            scenario.FreshBackup.Dispose();
            scenario.Graph.Dispose();
        }
    }

    [Fact]
    public async Task Recovery_UnrelatedMiscByteChange_RefusesBeforeAnyWriteOrReset()
    {
        RecoveryCase scenario = await SetUpRecoveryCaseAsync(
            nameof(Recovery_UnrelatedMiscByteChange_RefusesBeforeAnyWriteOrReset),
            flipUnrelatedMiscByte: true);
        try
        {
            string intended = CopyWithFlippedByte(
                Path.Combine(scenario.Inputs, "boot_a-full.img"), CandidateFlipOffset,
                Path.Combine(scenario.Inputs, "intended-boot_a.img"));
            string journalPath = WriteJournal(
                BuildJournalDocument(scenario, Path.Combine(scenario.CaseDirectory, "tf-rollback.json"),
                    NewConfirmationId(), Sha256File(intended)),
                Path.Combine(scenario.CaseDirectory, "tf-rollback.json"));

            var history = await BootMaintenanceBackend.ReadHistoricalIdentityAsync(scenario.OriginalDirectory);

            Exception failure = await Assert.ThrowsAnyAsync<Exception>(
                () => BootMaintenanceBackend.CreateTfRestorePreviousFromEdlAsync(
                    history,
                    scenario.Client,
                    scenario.FreshBackup,
                    journalPath,
                    scenario.Runner,
                    scenario.EvidenceParent,
                    progress: null,
                    cancellationToken: CancellationToken.None));
            Assert.Contains("outside the permitted", failure.Message);

            Assert.Empty(scenario.Runner.Writes);
            Assert.Equal(0, scenario.Runner.ResetCount);
        }
        finally
        {
            scenario.FreshBackup.Dispose();
            scenario.Graph.Dispose();
        }
    }

    [Theory]
    [InlineData("boot_b")]
    [InlineData("vendor_boot_a")]
    public async Task Recovery_ChangedNonIntentRegion_RefusesBeforeAnyWriteOrReset(string damagedRole)
    {
        RecoveryCase scenario = await SetUpRecoveryCaseAsync(
            nameof(Recovery_ChangedNonIntentRegion_RefusesBeforeAnyWriteOrReset) + "_" + damagedRole,
            damageBootB: damagedRole == "boot_b",
            damageVendorBootA: damagedRole == "vendor_boot_a");
        try
        {
            string intended = CopyWithFlippedByte(
                Path.Combine(scenario.Inputs, "boot_a-full.img"), CandidateFlipOffset,
                Path.Combine(scenario.Inputs, "intended-boot_a.img"));
            string journalPath = WriteJournal(
                BuildJournalDocument(scenario, Path.Combine(scenario.CaseDirectory, "tf-rollback.json"),
                    NewConfirmationId(), Sha256File(intended)),
                Path.Combine(scenario.CaseDirectory, "tf-rollback.json"));

            var history = await BootMaintenanceBackend.ReadHistoricalIdentityAsync(scenario.OriginalDirectory);

            Exception failure = await Assert.ThrowsAnyAsync<Exception>(
                () => BootMaintenanceBackend.CreateTfRestorePreviousFromEdlAsync(
                    history,
                    scenario.Client,
                    scenario.FreshBackup,
                    journalPath,
                    scenario.Runner,
                    scenario.EvidenceParent,
                    progress: null,
                    cancellationToken: CancellationToken.None));
            Assert.Contains("not an allowed write intent", failure.Message);

            Assert.Empty(scenario.Runner.Writes);
            Assert.Equal(0, scenario.Runner.ResetCount);
        }
        finally
        {
            scenario.FreshBackup.Dispose();
            scenario.Graph.Dispose();
        }
    }

    [Theory]
    [InlineData(true, false, false)]  // duplicate possibleWrite role
    [InlineData(false, true, false)]  // wrong hardware id
    [InlineData(false, false, true)]  // missing original capture
    public async Task Recovery_MalformedJournal_RefusesBeforeAnyWriteOrReset(
        bool duplicatePossibleWrite,
        bool wrongHardware,
        bool dropCapture)
    {
        RecoveryCase scenario = await SetUpRecoveryCaseAsync(
            nameof(Recovery_MalformedJournal_RefusesBeforeAnyWriteOrReset)
            + "_" + Convert.ToInt32(duplicatePossibleWrite)
            + Convert.ToInt32(wrongHardware)
            + Convert.ToInt32(dropCapture));
        try
        {
            string intended = CopyWithFlippedByte(
                Path.Combine(scenario.Inputs, "boot_a-full.img"), CandidateFlipOffset,
                Path.Combine(scenario.Inputs, "intended-boot_a.img"));
            string journalPath = WriteJournal(
                BuildJournalDocument(scenario, Path.Combine(scenario.CaseDirectory, "tf-rollback.json"),
                    NewConfirmationId(), Sha256File(intended),
                    hardwareIdOverride: wrongHardware ? "TF-WRONG-HW" : null,
                    duplicatePossibleWrite: duplicatePossibleWrite,
                    dropOneCapture: dropCapture),
                Path.Combine(scenario.CaseDirectory, "tf-rollback.json"));

            var history = await BootMaintenanceBackend.ReadHistoricalIdentityAsync(scenario.OriginalDirectory);

            Exception failure = await Assert.ThrowsAnyAsync<Exception>(
                () => BootMaintenanceBackend.CreateTfRestorePreviousFromEdlAsync(
                    history,
                    scenario.Client,
                    scenario.FreshBackup,
                    journalPath,
                    scenario.Runner,
                    scenario.EvidenceParent,
                    progress: null,
                    cancellationToken: CancellationToken.None));
            Assert.Contains(
                duplicatePossibleWrite ? "unique non-blank roles"
                : wrongHardware ? "identity facts differ"
                : "has no matching original capture",
                failure.Message);

            Assert.Empty(scenario.Runner.Writes);
            Assert.Equal(0, scenario.Runner.ResetCount);
        }
        finally
        {
            scenario.FreshBackup.Dispose();
            scenario.Graph.Dispose();
        }
    }

    [Fact]
    public async Task Recovery_ChangedOriginalFile_RefusesBeforeAnyWriteOrReset()
    {
        RecoveryCase scenario = await SetUpRecoveryCaseAsync(
            nameof(Recovery_ChangedOriginalFile_RefusesBeforeAnyWriteOrReset));
        try
        {
            // Load the history BEFORE mutating anything on disk; the identity check must then reject
            // the changed original file by its capture-time hash.
            var history = await BootMaintenanceBackend.ReadHistoricalIdentityAsync(scenario.OriginalDirectory);

            // Mutate the actual captured original boot_a file (path from the real backup file map, not
            // an invented name): the journal still carries the capture-time SHA, so the on-disk hash
            // no longer matches.
            string originalBootA = scenario.OriginalFilePaths[RecoveryRole];
            Assert.True(File.Exists(originalBootA));
            string hashBeforeMutation = Sha256File(originalBootA);
            using (FileStream stream = new(originalBootA, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                stream.Seek(CandidateFlipOffset, SeekOrigin.Begin);
                int value = stream.ReadByte();
                stream.Seek(CandidateFlipOffset, SeekOrigin.Begin);
                stream.WriteByte((byte)(value ^ 0xFF));
            }

            Assert.NotEqual(hashBeforeMutation, Sha256File(originalBootA));

            string intended = CopyWithFlippedByte(
                Path.Combine(scenario.Inputs, "boot_a-full.img"), CandidateFlipOffset,
                Path.Combine(scenario.Inputs, "intended-boot_a.img"));
            string journalPath = WriteJournal(
                BuildJournalDocument(scenario, Path.Combine(scenario.CaseDirectory, "tf-rollback.json"),
                    NewConfirmationId(), Sha256File(intended)),
                Path.Combine(scenario.CaseDirectory, "tf-rollback.json"));

            Exception failure = await Assert.ThrowsAnyAsync<Exception>(
                () => BootMaintenanceBackend.CreateTfRestorePreviousFromEdlAsync(
                    history,
                    scenario.Client,
                    scenario.FreshBackup,
                    journalPath,
                    scenario.Runner,
                    scenario.EvidenceParent,
                    progress: null,
                    cancellationToken: CancellationToken.None));
            Assert.False(string.IsNullOrWhiteSpace(failure.Message));

            Assert.Empty(scenario.Runner.Writes);
            Assert.Equal(0, scenario.Runner.ResetCount);
        }
        finally
        {
            scenario.FreshBackup.Dispose();
            scenario.Graph.Dispose();
        }
    }

    [Fact]
    public async Task Recovery_HintAlone_IsNeverAnExecutionAuthority()
    {
        RecoveryCase scenario = await SetUpRecoveryCaseAsync(
            nameof(Recovery_HintAlone_IsNeverAnExecutionAuthority));
        try
        {
            string intended = CopyWithFlippedByte(
                Path.Combine(scenario.Inputs, "boot_a-full.img"), CandidateFlipOffset,
                Path.Combine(scenario.Inputs, "intended-boot_a.img"));
            string journalPath = WriteJournal(
                BuildJournalDocument(scenario, Path.Combine(scenario.CaseDirectory, "tf-rollback.json"),
                    NewConfirmationId(), Sha256File(intended)),
                Path.Combine(scenario.CaseDirectory, "tf-rollback.json"));

            // Reading the hint never touches the device: no new reads, no writes, no resets, ever.
            // (The fresh capture during setup already performed reads, so assert against the count
            // recorded immediately before the hint read.)
            int readsBeforeHint = scenario.Runner.Reads.Count;
            _ = await BootMaintenanceBackend.ReadTfRecoveryHintAsync(journalPath);

            Assert.Empty(scenario.Runner.Writes);
            Assert.Equal(0, scenario.Runner.ResetCount);
            Assert.Equal(readsBeforeHint, scenario.Runner.Reads.Count);
        }
        finally
        {
            scenario.FreshBackup.Dispose();
            scenario.Graph.Dispose();
        }
    }

    // ------------------------------------------------------------ small helpers

    private EdlClient NewClient(EdlEntryResult binding, ICommandRunner runner) => new(
        _fixture.Toolchain,
        binding,
        runner,
        new E003ScriptedEndpointDiscovery { Endpoints = new[] { E003EdlTestData.Endpoint() } });

    private static DeviceCheckRunner NewDeviceCheckRunner() => new(Serial, new DeviceCheckClock())
    {
        FastbootCurrentSlot = "a",
        ReturnSlotSuffix = "_a",
        BootImmediatelyCompleteOnReturn = true,
    };

    /// <summary>
    /// Grows a small signed boot image to the real 96 MiB partition with FileStream calls only, keeping
    /// the 64-byte AVB footer valid, exactly like the stock backend fixture.
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

    private static string CopyWithFlippedByte(string sourcePath, int offset, string targetPath)
    {
        File.Copy(sourcePath, targetPath, overwrite: true);
        using FileStream stream = new(targetPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        stream.Seek(offset, SeekOrigin.Begin);
        int original = stream.ReadByte();
        stream.Seek(offset, SeekOrigin.Begin);
        stream.WriteByte((byte)(original ^ 0xFF));
        return targetPath;
    }

    /// <summary>
    /// Builds the 16-sector misc overlay from the existing pure helpers: the CRC32-valid boot_control
    /// page (packed layout — control[12] is slot a with bits 0..3 priority, 4..6 tries, 7 successful;
    /// control[14] is slot b; each followed by a verity byte; CRC32 at bytes 28..31) plus the valid
    /// modern virtual-ab note at byte 32768. The baseline selects slot a at priority 15. When
    /// <paramref name="freshTries"/> differs from the baseline, only the packed slot-a byte is rebuilt
    /// (successful cleared) and the CRC is recomputed, so the production parser owns the read proof of
    /// a legit single-field transition.
    /// </summary>
    private static byte[] BuildMiscOverlay(byte baselineTries, byte? freshTries)
    {
        byte selectedTries = freshTries ?? baselineTries;
        if (selectedTries is < 0 or > 7)
        {
            throw new ArgumentOutOfRangeException(nameof(freshTries), "tries must fit the 3-bit field.");
        }

        byte[] control = (byte[])ControlBlockMethod.Invoke(null, new object?[] { "_a", (byte)0, null, null })!;
        control[12] = (byte)(15 | (selectedTries << 4)); // slot a: priority 15, selected tries, unsuccessful
        control[13] = 0;                                 // slot a verity
        control[14] = (byte)(14 | (7 << 4));             // slot b: priority 14, tries 7, unsuccessful
        control[15] = 0;                                 // slot b verity
        BinaryPrimitives.WriteUInt32LittleEndian(control.AsSpan(28), Crc32(control, 28));

        byte[] controlPage = (byte[])BuildMiscMethod.Invoke(null, new object?[] { control })!;

        var overlay = new byte[16 * IB001SyntheticDevice.SectorSize];
        Buffer.BlockCopy(controlPage, 0, overlay, 0, controlPage.Length);

        overlay[32768] = 2;
        BinaryPrimitives.WriteUInt32LittleEndian(overlay.AsSpan(32768 + 1), 0x56740AB0);
        overlay[32768 + 5] = 0;
        overlay[32768 + 6] = 0;
        return overlay;
    }

    private static readonly uint[] Crc32Table = BuildCrc32Table();

    private static uint[] BuildCrc32Table()
    {
        var table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint value = i;
            for (int bit = 0; bit < 8; bit++)
            {
                value = (value & 1) != 0 ? 0xEDB88320u ^ (value >> 1) : value >> 1;
            }

            table[i] = value;
        }

        return table;
    }

    private static uint Crc32(byte[] data, int length)
    {
        uint crc = 0xFFFFFFFFu;
        for (int i = 0; i < length; i++)
        {
            crc = Crc32Table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
        }

        return crc ^ 0xFFFFFFFFu;
    }

    private static IEnumerable<int> DiffByteOffsets(string leftPath, string rightPath)
    {
        byte[] left = File.ReadAllBytes(leftPath);
        byte[] right = File.ReadAllBytes(rightPath);
        Assert.Equal(left.Length, right.Length);
        var differences = new List<int>();
        for (int i = 0; i < left.Length; i++)
        {
            if (left[i] != right[i])
            {
                differences.Add(i);
            }
        }

        return differences;
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
