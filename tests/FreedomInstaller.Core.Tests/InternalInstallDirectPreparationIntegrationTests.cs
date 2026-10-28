// the direct-preparation positive bound to the actual .120 firmware snapshot.
// one thin shared direct-preparation session over the real production factory.
// The session composes the existing fixtures (BM slot/package/tools/oracle, the snapshot raw package, the
// IB synthetic device/runner) instead of copying any of their framework. Only this file is authored here;
// no other test or production file is written by this ticket.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// The single positive direct EDL raw preparation: the actual <see cref="InternalInstallBackend"/>
/// factory, the actual 52-file backup and 2 GiB artifact preparation, the actual builder for both slots
/// and the actual original-device capture. No write, reset or execution is issued and no operating-system
/// acceptance is claimed. FW01 binds the session to the actual .120 firmware snapshot while the loaded
/// toolchain keeps its reviewed .259 profile build.
/// <para>
/// The fixture is deliberately thin: every input helper is reused from <see cref="EdlRawBootBuilderTests"/>
/// and <see cref="InternalInstallEdlRawSnapshotTests"/>, and the device/runner pair comes from the IB
/// fixture. Only the composition lives here.
/// </para>
/// </summary>
public sealed class InternalInstallDirectPreparationIntegrationTests
    : IClassFixture<EdlClientToolchainFixture>, IClassFixture<EdlRawSharedInput>
{
    // FW01: the actual firmware under test. The loaded toolchain stays the reviewed .259 profile.
    private const string Actual120DisplayId =
        "TB322FC_CN_OPEN_USER_Q00041.1_V_ZUXOS_1.1.11.120_ST_250727";
    private const string Actual120BuildFingerprint = "Lenovo/TB322FC/TB322FC:15/TEST/120:user/release-keys";
    private const string Actual120AndroidRelease = "15";
    private const string Actual120SecurityPatch = "2026-06-01";
    private const string Profile259AndroidBuild =
        "TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.259_ST_260611";
    private const string ExpectedProfileId = "g4-9008-259";

    private readonly EdlClientToolchainFixture _toolchain;
    private readonly EdlRawSharedInput _rawShared;

    public InternalInstallDirectPreparationIntegrationTests(
        EdlClientToolchainFixture toolchain,
        EdlRawSharedInput rawShared)
    {
        _toolchain = toolchain;
        _rawShared = rawShared;
    }

    [Fact]
    public async Task FW01_CreatePrepared_CurrentSlotB_ProducesTheFullDirectConfirmationForBothSlots()
    {
        var actual120 = new FirmwareSnapshot(
            Actual120DisplayId,
            Actual120BuildFingerprint,
            Actual120AndroidRelease,
            Actual120SecurityPatch,
            BootloaderState.Locked);

        using DirectInstallReadyTestSession session =
            await DirectInstallReadyTestSession.CreateAsync(
                _toolchain, _rawShared, currentSlot: "b", observedFirmware: actual120);

        InternalInstallPrepared prepared = session.Backend.Prepared;

        // The factory returned the observed slot, and nothing was written, reset or executed.
        Assert.Equal("b", prepared.CurrentSlot);
        Assert.Equal(new[] { "b", "a" }, prepared.SlotOrder);
        Assert.False(session.Backend.Snapshot.ExecutionStarted);
        Assert.Equal(InternalInstallStage.Prepared, session.Backend.Snapshot.Stage);
        Assert.Equal(InternalInstallWriteState.NoneIssued, session.Backend.Snapshot.WriteState);
        Assert.Null(session.Backend.Snapshot.Outcome);
        Assert.Null(session.Backend.LastResult);
        Assert.Equal(0, session.EdlRunner.Writes.Count);
        Assert.Equal(0, session.EdlRunner.ResetCount);

        // Full confirmation: every claim is a non-empty fact bound to the same real inputs.
        Assert.False(string.IsNullOrWhiteSpace(prepared.ConfirmationId));
        Assert.Equal(64, prepared.ConfirmationId.Length);
        Assert.Equal(session.Backup.ManifestSha256, prepared.BackupManifestSha256, ignoreCase: true);
        Assert.Equal(session.Artifacts.PlanSha256, prepared.ArtifactPlanSha256, ignoreCase: true);
        Assert.Equal(session.Package.Validation.ManifestFingerprint, prepared.PackageFingerprint, ignoreCase: true);
        Assert.False(string.IsNullOrWhiteSpace(prepared.ProfileId));
        Assert.Equal(ExpectedProfileId, prepared.ProfileId);
        Assert.False(string.IsNullOrWhiteSpace(prepared.PackageBindingSha256));
        Assert.False(string.IsNullOrWhiteSpace(prepared.CurrentMiscSha256));
        Assert.Equal("SN0123456789", prepared.AndroidSerial);
        Assert.Equal(E003EdlTestData.SocSerialDecimal, prepared.SocSerial);

        // FW01: the prepared provenance is the actual device build, not the loaded toolchain's profile build.
        Assert.Equal(Actual120DisplayId, prepared.AndroidBuild);
        Assert.Equal(Actual120DisplayId, prepared.Firmware.DisplayId);
        Assert.Equal(Actual120BuildFingerprint, prepared.Firmware.BuildFingerprint);
        Assert.Equal(Actual120AndroidRelease, prepared.Firmware.AndroidRelease);
        Assert.Equal(Actual120SecurityPatch, prepared.Firmware.SecurityPatch);
        Assert.Equal(BootloaderState.Locked, prepared.Firmware.AndroidReportedBootloaderState);
        Assert.Equal(Profile259AndroidBuild, session.Toolchain.AndroidBuild);
        Assert.NotEqual(actual120.DisplayId, session.Toolchain.AndroidBuild);

        Assert.Equal(BootloaderState.Locked, prepared.FastbootLockState);
        Assert.Equal(16L, prepared.AndroidGiB);
        Assert.Equal(6, prepared.Geometries.Count);
        Assert.Equal(6, prepared.OriginalGptFingerprints.Count);
        Assert.Equal(
            128L * 1024 * 1024 * 1024,
            prepared.Geometries[0].TotalSectors * prepared.Geometries[0].SectorSize);
        Assert.Equal(2, prepared.CurrentBootSha256.Count);
        Assert.False(string.Equals(prepared.CurrentBootSha256["a"], prepared.CurrentBootSha256["b"], StringComparison.OrdinalIgnoreCase));

        // No legacy asset semantic may survive on the direct route.
        Assert.Empty(prepared.MaintenanceBootSha256);
        Assert.Empty(prepared.SupportSha256);
        Assert.Empty(prepared.ToolboxSha256);

        // Both slots carry their own recovered material, and the two origins are really different bytes.
        Assert.Equal(2, prepared.SlotMaterials.Count);
        Assert.True(prepared.SlotMaterials.ContainsKey("a"));
        Assert.True(prepared.SlotMaterials.ContainsKey("b"));
        Assert.Equal(2, prepared.RawUpperBoundBytes.Count);
        foreach (string slot in new[] { "a", "b" })
        {
            InternalSlotMaterial material = prepared.SlotMaterials[slot];
            Assert.Equal(slot, material.Slot);
            Assert.Equal(5, material.SourceSha256.Count);
            Assert.Equal(5, material.SourceLengths.Count);
            Assert.Equal(100_663_296L, material.SourceLengths["current_boot"]);
            Assert.False(string.IsNullOrWhiteSpace(material.BaseImageSha256));
        }

        InternalSlotMaterial slotA = prepared.SlotMaterials["a"];
        InternalSlotMaterial slotB = prepared.SlotMaterials["b"];
        Assert.False(string.Equals(slotA.BaseImageSha256, slotB.BaseImageSha256, StringComparison.OrdinalIgnoreCase));
        foreach (string role in new[] { "current_boot", "vendor_boot", "init_boot", "abl", "xbl_config" })
        {
            Assert.False(string.Equals(slotA.SourceSha256[role], slotB.SourceSha256[role], StringComparison.OrdinalIgnoreCase));
        }

        // The backup is the complete actual capture; the builders really called the native oracle six times.
        Assert.Equal(51, session.Backup.Files.Count);
        Assert.Equal(6, session.NativeCommandCount);

        // FW01: the saved real backup manifest records the actual observed snapshot.
        Assert.Equal(Actual120DisplayId, session.Backup.AndroidBuild);
        using (JsonDocument manifest = JsonDocument.Parse(File.ReadAllBytes(session.Backup.ManifestPath)))
        {
            JsonElement manifestRoot = manifest.RootElement;
            Assert.Equal(
                Actual120DisplayId,
                manifestRoot.GetProperty("profile").GetProperty("androidBuild").GetString());
            Assert.Equal(
                Actual120DisplayId,
                manifestRoot.GetProperty("identity").GetProperty("firmware").GetProperty("displayId").GetString());
        }

        // Evidence exists as files, and the confirmation record is the factual direct shape.
        Assert.True(Directory.Exists(prepared.EvidenceDirectory));
        string confirmationPath = Path.Combine(prepared.EvidenceDirectory, "prepared-confirmation.json");
        Assert.True(File.Exists(confirmationPath));
        Assert.True(File.Exists(Path.Combine(prepared.EvidenceDirectory, "direct-slot-a-verification.json")));
        Assert.True(File.Exists(Path.Combine(prepared.EvidenceDirectory, "direct-slot-b-verification.json")));

        using JsonDocument confirmation = JsonDocument.Parse(File.ReadAllBytes(confirmationPath));
        JsonElement root = confirmation.RootElement;

        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("armada-internal-install-confirmation", root.GetProperty("kind").GetString());
        Assert.Equal("b", root.GetProperty("device").GetProperty("currentSlot").GetString());
        Assert.Equal("TB322FC", root.GetProperty("device").GetProperty("model").GetString());
        Assert.Equal(2, root.GetProperty("slotOrder").GetArrayLength());
        Assert.Equal("b", root.GetProperty("slotOrder")[0].GetString());
        Assert.Equal("a", root.GetProperty("slotOrder")[1].GetString());

        // FW01: the confirmation record names the actual build and the full observed snapshot.
        JsonElement deviceNode = root.GetProperty("device");
        Assert.Equal(ExpectedProfileId, deviceNode.GetProperty("profileId").GetString());
        Assert.Equal(Actual120DisplayId, deviceNode.GetProperty("androidBuild").GetString());
        JsonElement firmwareNode = deviceNode.GetProperty("firmware");
        Assert.Equal(Actual120DisplayId, firmwareNode.GetProperty("displayId").GetString());
        Assert.Equal(Actual120BuildFingerprint, firmwareNode.GetProperty("buildFingerprint").GetString());
        Assert.Equal(Actual120AndroidRelease, firmwareNode.GetProperty("androidRelease").GetString());
        Assert.Equal(Actual120SecurityPatch, firmwareNode.GetProperty("securityPatch").GetString());

        // The direct route never writes a legacy seed or the maintenance/support/toolbox asset block.
        JsonElement package = root.GetProperty("package");
        Assert.False(package.TryGetProperty("seed", out _));
        Assert.Equal(7, package.GetProperty("payloads").GetArrayLength());
        Assert.False(root.TryGetProperty("assets", out _));

        JsonElement direct = root.GetProperty("direct");
        Assert.Equal("TB322FC", direct.GetProperty("deviceModel").GetString());
        Assert.False(direct.GetProperty("testOnly").GetBoolean());
        Assert.True(direct.GetProperty("requiredExecutionBytes").GetInt64() > 0);

        // Real filesystem and raw facts, not legacy boot/seed semantics.
        JsonElement bootImage = direct.GetProperty("bootImage");
        Assert.Equal("ext4", bootImage.GetProperty("fsType").GetString());
        Assert.Equal(4096, bootImage.GetProperty("sectorSize").GetInt32());
        Assert.Equal(1L * 1024 * 1024 * 1024, bootImage.GetProperty("expandedBytes").GetInt64());
        JsonElement rootImageNode = direct.GetProperty("rootImage");
        Assert.Equal("btrfs", rootImageNode.GetProperty("fsType").GetString());
        Assert.Equal(17L * 4096, rootImageNode.GetProperty("expandedBytes").GetInt64());
        Assert.NotEqual(
            bootImage.GetProperty("fsUuid").GetString(),
            rootImageNode.GetProperty("fsUuid").GetString(),
            StringComparer.OrdinalIgnoreCase);

        JsonElement tools = direct.GetProperty("tools");
        Assert.False(string.IsNullOrWhiteSpace(tools.GetProperty("packerSha256").GetString()));
        Assert.False(string.IsNullOrWhiteSpace(tools.GetProperty("unpackerSha256").GetString()));

        JsonElement slots = direct.GetProperty("slots");
        Assert.Equal(2, slots.GetArrayLength());
        Assert.Equal("b", slots[0].GetProperty("slot").GetString());
        Assert.Equal("a", slots[1].GetProperty("slot").GetString());
        foreach (JsonElement slot in slots.EnumerateArray())
        {
            Assert.Equal(100_663_296L, slot.GetProperty("candidateBoot").GetProperty("length").GetInt64());
            Assert.True(slot.GetProperty("packedRaw").GetProperty("length").GetInt64() > 0);
            Assert.False(string.IsNullOrWhiteSpace(slot.GetProperty("roundTripRawSha256").GetString()));
            Assert.Equal(6, slot.GetProperty("payloadSha256").EnumerateObject().Count());

            // The real builder emits each slot's own ordered metadata: slot a carries two duplicate
            // fingerprint properties, slot b only one. Their counts are per-slot facts, not one shared shape.
            int expectedEnvelopeProperties =
                slot.GetProperty("slot").GetString() == "a" ? 2 : 1;
            Assert.Equal(
                expectedEnvelopeProperties,
                slot.GetProperty("envelope").GetProperty("properties").GetArrayLength());
        }

        Assert.NotEqual(
            slots[0].GetProperty("candidateBoot").GetProperty("sha256").GetString(),
            slots[1].GetProperty("candidateBoot").GetProperty("sha256").GetString(),
            StringComparer.OrdinalIgnoreCase);

        Assert.Equal(2, root.GetProperty("slotMaterials").GetArrayLength());
        Assert.Equal(51, root.GetProperty("backup").GetProperty("files").GetArrayLength());
    }
}

/// <summary>
/// One real direct-preparation session: the caller's class fixtures stay the caller's, while the workspace,
/// raw package, slot sources, the owned AVB source fixture, tool leases, backup, artifacts, imported package,
/// device/runner and backend are disposed here in reverse creation order (backend first).
/// <para>
/// A setup failure closes only the leases this session already opened; it never disposes the caller's
/// toolchain fixture or the caller's shared raw input, and never deletes a file it does not own.
/// </para>
/// </summary>
internal sealed class DirectInstallReadyTestSession : IDisposable
{
    internal const string TestAdbPath = "test-adb";

    private readonly EdlRawBootBuilderTests.Workspace _workspace;
    private readonly EdlRawBootBuilderTests.SyntheticPackage _kernelPackage;
    private readonly InternalInstallEdlRawSnapshotTests.RawPackage _rawPackage;
    private readonly EdlRawBootBuilderTests.LinuxOracleRunner _oracle;
    private readonly EdlRawBootTools _tools;
    private readonly InternalInstallDirectAssets _assets;
    private readonly IB001SyntheticDevice _device;
    private readonly InternalBackupSet _backup;
    private readonly InternalArtifactSet _artifacts;
    private readonly ImportedPackage _package;
    private readonly InternalInstallBackend _backend;
    private readonly DirectAvbSourceTestFixture? _avbSources;
    private readonly IReadOnlyDictionary<string, VerifiedEdlFile> _originalAvbSources;
    private readonly string _originalRootKeySha256;
    private int _disposed;

    /// <summary>The one model whose package identity and DTB pair this session substitutes.</summary>
    private const string G5Model = "TB323FU";

    private DirectInstallReadyTestSession(
        EdlRawBootBuilderTests.Workspace workspace,
        EdlRawBootBuilderTests.SyntheticPackage kernelPackage,
        InternalInstallEdlRawSnapshotTests.RawPackage rawPackage,
        EdlRawBootTools tools,
        InternalInstallDirectAssets assets,
        IB001SyntheticDevice device,
        IB001FakeEdlRunner edlRunner,
        InternalBackupSet backup,
        InternalArtifactSet artifacts,
        ImportedPackage package,
        InternalInstallBackend backend,
        DirectAvbSourceTestFixture? avbSources,
        IReadOnlyDictionary<string, VerifiedEdlFile> originalAvbSources,
        string originalRootKey,
        DirectAvbSourceKind avbSourceKind,
        EdlToolchain toolchain,
        EdlRawBootBuilderTests.LinuxOracleRunner oracle)
    {
        _workspace = workspace;
        _kernelPackage = kernelPackage;
        _rawPackage = rawPackage;
        _oracle = oracle;
        _tools = tools;
        _assets = assets;
        _device = device;
        _backup = backup;
        _artifacts = artifacts;
        _package = package;
        _backend = backend;
        _avbSources = avbSources;
        _originalAvbSources = originalAvbSources;
        _originalRootKeySha256 = originalRootKey;
        AvbSourceKind = avbSourceKind;
        Toolchain = toolchain;
        EdlRunner = edlRunner;
    }

    internal InternalInstallBackend Backend => _backend;

    internal IB001FakeEdlRunner EdlRunner { get; }

    internal InternalBackupSet Backup => _backup;

    internal InternalArtifactSet Artifacts => _artifacts;

    internal ImportedPackage Package => _package;

    internal IB001SyntheticDevice Device => _device;

    internal EdlToolchain Toolchain { get; }

    internal string RootDirectory => _workspace.Root;

    internal int NativeCommandCount => _oracle.Calls;

    /// <summary>The real AVB metadata origin this session was composed with.</summary>
    internal DirectAvbSourceKind AvbSourceKind { get; }

    /// <summary>The six measured AVB metadata claims handed to the device assembly, unmodified.</summary>
    internal IReadOnlyDictionary<string, VerifiedEdlFile> OriginalAvbSources => _originalAvbSources;

    /// <summary>The lowercase root key hash of the original slot A AVB metadata.</summary>
    internal string OriginalRootKeySha256 => _originalRootKeySha256;

    /// <summary>
    /// Composes one real direct preparation. Every step is the actual production path; a missing native
    /// Linux oracle variable is a hard configuration failure, never a skip. <paramref name="observedFirmware"/>
    /// lets the caller supply the actual device snapshot; when it is null the Step 1 fact keeps the loaded
    /// toolchain's build, so every existing call is unchanged.
    /// <para>
    /// <paramref name="zeroSlot"/> optionally names the one factory-uninitialized target slot, whose five
    /// source claims are replaced by the existing all-zero fixture. <paramref name="corruptZeroBoot"/> then
    /// writes one non-zero byte after that zero v4 header, so a header-only emptiness check cannot pass.
    /// Both stay null by default and every existing call keeps its real two-slot material.
    /// </para>
    /// <para>
    /// <paramref name="avbSourceKind"/> and <paramref name="slotBAvbSourceKind"/> choose the real measured AVB
    /// metadata origin of each slot; the default AOSP fixture keeps every existing call on a legal original
    /// root, while an OEM transition is requested explicitly. <paramref name="observedFastbootLockState"/> is
    /// the confirmed fastboot lock fact of Step 1 and stays independent of the Android-reported bootloader
    /// state, so one can be Locked while the other is Unlocked. <paramref name="poisonExpandedRoot"/> rewrites
    /// only the compressed root artifact with a corrupted expansion, keeping the import valid while a snapshot
    /// expansion must fail. <paramref name="onPreparationFailure"/> observes the backend failure counts without
    /// turning it into a success. All four are test-only inputs and never reach production code.
    /// </para>
    /// </summary>
    internal static Task<DirectInstallReadyTestSession> CreateAsync(
        EdlClientToolchainFixture toolchainFixture,
        EdlRawSharedInput rawShared,
        string currentSlot = "a",
        ICommandRunner? androidRunner = null,
        FirmwareSnapshot? observedFirmware = null,
        string? zeroSlot = null,
        bool corruptZeroBoot = false,
        DirectAvbSourceKind avbSourceKind = DirectAvbSourceKind.Aosp,
        BootloaderState observedFastbootLockState = BootloaderState.Locked,
        bool poisonExpandedRoot = false,
        Action<int, int, int>? onPreparationFailure = null,
        DirectAvbSourceKind? slotBAvbSourceKind = null)
    {
        ArgumentNullException.ThrowIfNull(toolchainFixture);

        return CreateAsync(
            toolchainFixture.Toolchain,
            rawShared,
            currentSlot,
            androidRunner,
            observedFirmware,
            zeroSlot,
            corruptZeroBoot,
            avbSourceKind,
            observedFastbootLockState,
            poisonExpandedRoot,
            onPreparationFailure,
            slotBAvbSourceKind);
    }

    /// <summary>
    /// The resolved-toolchain form of the fixture overload; it composes exactly the same real session.
    /// <paramref name="gblSources"/> is an optional caller-owned source set: when it is present its ten boot
    /// claims, its six AVB claims and its EFISP claim replace the generated slot and AOSP AVB fixtures, and
    /// the caller keeps ownership of it. It is never disposed here and it never supplies the Step 1 check,
    /// the confirmed fastboot lock fact or any bypass flag.
    /// <para>
    /// <paramref name="omitEfispBackup"/> turns the real capture into a truthful legacy set: after the actual
    /// capture it removes exactly that one EFISP claim from the session's own manifest and disk, then reopens
    /// the set through production, while the device's GPT keeps the claim. It is test-only and refused
    /// without <paramref name="gblSources"/>.
    /// </para>
    /// </summary>
    internal static async Task<DirectInstallReadyTestSession> CreateAsync(
        EdlToolchain toolchain,
        EdlRawSharedInput rawShared,
        string currentSlot = "a",
        ICommandRunner? androidRunner = null,
        FirmwareSnapshot? observedFirmware = null,
        string? zeroSlot = null,
        bool corruptZeroBoot = false,
        DirectAvbSourceKind avbSourceKind = DirectAvbSourceKind.Aosp,
        BootloaderState observedFastbootLockState = BootloaderState.Locked,
        bool poisonExpandedRoot = false,
        Action<int, int, int>? onPreparationFailure = null,
        DirectAvbSourceKind? slotBAvbSourceKind = null,
        GblDirectSourceFixture? gblSources = null,
        bool omitEfispBackup = false)
    {
        ArgumentNullException.ThrowIfNull(toolchain);
        ArgumentNullException.ThrowIfNull(rawShared);

        if (omitEfispBackup && gblSources is null)
        {
            throw new ArgumentException(
                "Omitting the EFISP backup claim requires the caller's GBL source set.",
                nameof(omitEfispBackup));
        }

        if (zeroSlot is not (null or "a" or "b"))
        {
            throw new ArgumentException(
                "The optional inactive target slot must be null, 'a' or 'b', not '" + zeroSlot + "'.",
                nameof(zeroSlot));
        }

        string linuxPacker = RequireNativeTool("EDL_RAW_LINUX_PACKER_PATH");
        string linuxUnpacker = RequireNativeTool("EDL_RAW_LINUX_UNPACKER_PATH");

        EdlRawBootBuilderTests.Workspace? workspace = null;
        EdlRawBootBuilderTests.SyntheticPackage? kernelPackage = null;
        InternalInstallEdlRawSnapshotTests.RawPackage? rawPackage = null;
        EdlRawBootTools? tools = null;
        InternalInstallDirectAssets? assets = null;
        InternalBackupSet? backup = null;
        InternalArtifactSet? artifacts = null;
        ImportedPackage? imported = null;
        InternalInstallBackend? backend = null;
        DirectAvbSourceTestFixture? avbSources = null;
        bool transferred = false;

        try
        {
            workspace = new EdlRawBootBuilderTests.Workspace();
            string root = workspace.Root;

            // The raw package keeps its real 1 GiB streaming ext4 gzip, tiny Btrfs superblock, UUIDs, DTB
            // pair and truthful metadata; only the kernel payload is replaced by the BM ARM64 kernel.
            rawPackage = InternalInstallEdlRawSnapshotTests.RawPackage.Create(rawShared);
            kernelPackage = new EdlRawBootBuilderTests.SyntheticPackage(deviceModel: toolchain.Model);
            rawPackage.RewriteArtifact("kernel", kernelPackage.Kernel);

            // The final common package may omit the optional Android FW/HWID constraint groups entirely;
            // the trusted production toolchain profile is still supplied by the caller.
            rawPackage.EditManifest(metadata =>
            {
                metadata.Remove("edlProfile");
                var compatibility = metadata["bootCompatibility"]!.AsObject();
                compatibility.Remove("firmwareVersions");

                // Only the G5 model declares its own package identity and compatibility pair; every other
                // model keeps the snapshot's original metadata and default constraint groups byte for byte.
                if (IsG5Model(toolchain.Model))
                {
                    metadata["deviceModel"] = toolchain.Model;
                    var compatible = metadata["compatible"]!.AsObject();
                    compatible["soc"] = "SM8850";
                    compatible["device"] = "baldur";
                }
            });

            if (IsG5Model(toolchain.Model))
            {
                // The G5 DTB pair must carry the raw package's own boot arguments, because that is what the
                // manifest and the real images bind. The kernel payload stays the shared one and the G4
                // payloads keep the synthetic package's original DTB bytes.
                rawPackage.RewriteArtifact(
                    "dtb-normal", CreateG5RawDtb(RawFacts.NormalBootArgs, "os"));
                rawPackage.RewriteArtifact(
                    "dtb-diagnostic", CreateG5RawDtb(RawFacts.DiagnosticBootArgs, "maintenance"));
            }

            if (poisonExpandedRoot)
            {
                // Only the expanded payload is corrupted: the compressed declaration and its sha256 stay
                // truthful, so the import still validates while a snapshot root expansion must fail.
                byte[] poisoned = (byte[])rawShared.RootImage.Clone();
                poisoned[0] ^= 0xFF;
                rawPackage.RewriteArtifact(
                    "linux-root-raw", SyntheticRawImages.Gzip(poisoned));
            }

            Dictionary<string, VerifiedEdlFile> sources;

            if (gblSources is null)
            {
                EdlRawBootBuilderTests.SlotFixture slotA =
                    EdlRawBootBuilderTests.CreateSlot(workspace, "a", 0x31);
                EdlRawBootBuilderTests.SlotFixture slotB =
                    EdlRawBootBuilderTests.CreateSlot(workspace, "b", 0x71);

                sources = new(StringComparer.Ordinal)
                {
                    ["boot_a"] = slotA.CurrentBoot,
                    ["vendor_boot_a"] = slotA.VendorBoot,
                    ["init_boot_a"] = slotA.InitBoot,
                    ["abl_a"] = slotA.Abl,
                    ["xbl_config_a"] = slotA.XblConfig,
                    ["boot_b"] = slotB.CurrentBoot,
                    ["vendor_boot_b"] = slotB.VendorBoot,
                    ["init_boot_b"] = slotB.InitBoot,
                    ["abl_b"] = slotB.Abl,
                    ["xbl_config_b"] = slotB.XblConfig,
                };

                // The AVB metadata is a separate set of real measured claims per slot; slot B keeps its own
                // original metadata even when its boot set is the all-zero fixture, and nothing is cloned from A.
                avbSources = new DirectAvbSourceTestFixture(avbSourceKind, slotBAvbSourceKind);
            }
            else
            {
                // The caller's ten boot claims are copied because the optional zero-slot substitution below
                // rewrites this map; the AVB claims and the EFISP claim stay the caller's own objects and the
                // caller's fixture is never disposed by this session.
                sources = new(gblSources.Sources, StringComparer.Ordinal);
            }

            if (zeroSlot is not null)
            {
                // The factory-uninitialized target is the existing all-zero fixture; the device still pads
                // every one of its five claims to the real partition, so the backup captures padded zeros.
                InactiveSlotBackupFixture inactiveTarget = InactiveSlotBackupFixture.Create(workspace);

                if (corruptZeroBoot)
                {
                    // One non-zero byte well past the zero v4 header: a header-only probe must not accept it.
                    inactiveTarget.WriteByteAt(0, 4096 + 17, 0x01);
                }

                sources["boot_" + zeroSlot] = inactiveTarget.Boot;
                sources["vendor_boot_" + zeroSlot] = inactiveTarget.VendorBoot;
                sources["init_boot_" + zeroSlot] = inactiveTarget.InitBoot;
                sources["abl_" + zeroSlot] = inactiveTarget.Abl;
                sources["xbl_config_" + zeroSlot] = inactiveTarget.XblConfig;
            }

            // The factual AVB origin handed to the device assembly and reported by the session: the local
            // fixture on the default route, the caller's real claims and root key on the GBL route.
            IReadOnlyDictionary<string, VerifiedEdlFile> originalAvbSources = gblSources is null
                ? avbSources!.Sources
                : gblSources.AvbSources;
            string originalRootKey = gblSources is null
                ? avbSources!.OriginalRootKeySha256
                : gblSources.ParentPublicKeySha256;

            string deviceDirectory = Path.Combine(root, "device");
            Directory.CreateDirectory(deviceDirectory);
            IB001SyntheticDevice device = IB001SyntheticDevice.CreateDirect(
                deviceDirectory,
                sources,
                gblSources is null ? avbSources!.Sources : gblSources.AvbSources,
                gblSources?.EfispSource,
                gen5: IsG5Model(toolchain.Model));

            // The source five of each slot are not mutated by the copy/pad into the device's own child.
            foreach (VerifiedEdlFile claim in sources.Values)
            {
                Assert.True(File.Exists(claim.Path));
                Assert.Equal(claim.Length, new FileInfo(claim.Path).Length);
            }

            tools = await EdlRawBootBuilderTests.LoadToolsAsync();
            assets = await InternalInstallDirectAssets.LoadAsync(tools!);

            EdlRawBootBuilderTests.LinuxOracleRunner oracle =
                new(tools!, linuxPacker, linuxUnpacker);
            IB001FakeEdlRunner edlRunner = new(device, enableWrites: true, hardwareId: toolchain.HardwareId);
            DirectSessionCommandRunner router = new(
                tools!.Packer.Path,
                tools.Unpacker.Path,
                oracle,
                TestAdbPath,
                androidRunner ?? new DirectAdbRunner(),
                toolchain.ClientPath,
                edlRunner);

            var discovery = new E003ScriptedEndpointDiscovery
            {
                Endpoints = new[] { E003EdlTestData.Endpoint() },
            };

            // The Step 1 fact and the EDL binding are the same real identity and firmware snapshot.
            FirmwareSnapshot firmware = observedFirmware ?? (IsG5Model(toolchain.Model)
                ? new FirmwareSnapshot(
                    toolchain.AndroidBuild,
                    "Lenovo/baldur/baldur:16/test:user/release-keys",
                    "16",
                    "2026-06-01",
                    BootloaderState.Locked)
                : new FirmwareSnapshot(
                    toolchain.AndroidBuild,
                    "Lenovo/elden_prc_wifi/elden:15/AP3A.240905.015/259:user/release-keys",
                    "15",
                    "2026-06-01",
                    BootloaderState.Locked));

            var android = new AndroidMaintenanceIdentity(
                new DeviceIdentity("SN0123456789", toolchain.Model, firmware.AndroidReportedBootloaderState)
                {
                    Firmware = firmware,
                },
                E003EdlTestData.SocSerialDecimal);

            InternalDeviceCheckResult step1 = CreateStep1(
                android,
                currentSlot,
                observedFastbootLockState,
                IsG5Model(toolchain.Model) ? "baldur" : "elden_prc_wifi");
            EdlEntryResult binding = new(android, E003EdlTestData.Endpoint(), E003EdlTestData.BusSerialHex);

            EdlClient client = new(toolchain, binding, router, discovery);

            string backupParent = Path.Combine(root, "backup");
            Directory.CreateDirectory(backupParent);
            backup = await InternalInstallBackup.CreateAsync(client, backupParent);

            if (omitEfispBackup)
            {
                // The freshly captured set owns exactly one EFISP claim. Its own paths are captured first,
                // then its lease is released so the manifest and that claim can be rewritten on disk. The
                // device's own GPT still carries the claim; only this synthetic backup set becomes legacy.
                string backupDirectory = backup.DirectoryPath;
                string manifestPath = backup.ManifestPath;
                string efispClaimPath = backup.Files["efisp"].FilePath;

                backup.Dispose();
                backup = null;

                System.Text.Json.Nodes.JsonNode manifestRoot =
                    System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(manifestPath))
                    ?? throw new InvalidOperationException("the captured backup manifest must be a JSON object.");

                System.Text.Json.Nodes.JsonArray manifestFiles =
                    manifestRoot["files"] as System.Text.Json.Nodes.JsonArray
                    ?? throw new InvalidOperationException("the captured backup manifest must list its files.");

                // Exactly one entry carries the EFISP role; every other claim and every GPT/identity fact
                // stays byte for byte as the real capture wrote it.
                int removedClaims = 0;
                for (int index = manifestFiles.Count - 1; index >= 0; index--)
                {
                    System.Text.Json.Nodes.JsonNode? manifestEntry = manifestFiles[index];
                    if (manifestEntry is not null
                        && string.Equals(
                            manifestEntry["role"]?.GetValue<string>(),
                            "efisp",
                            StringComparison.OrdinalIgnoreCase))
                    {
                        manifestFiles.RemoveAt(index);
                        removedClaims++;
                    }
                }

                Assert.Equal(1, removedClaims);

                byte[] manifestBytes = System.Text.Encoding.UTF8.GetBytes(manifestRoot.ToJsonString());
                File.WriteAllBytes(manifestPath, manifestBytes);
                File.WriteAllText(
                    manifestPath + ".sha256",
                    System.Convert.ToHexString(
                        System.Security.Cryptography.SHA256.HashData(manifestBytes)) + "\n");

                // Only this session's own claim file is deleted, and only after proving it lives inside the
                // backup directory this session just captured; nothing is deleted recursively.
                string ownedPrefix = Path.GetFullPath(backupDirectory) + Path.DirectorySeparatorChar;
                string claimPath = Path.GetFullPath(efispClaimPath);
                Assert.True(
                    claimPath.StartsWith(ownedPrefix, StringComparison.OrdinalIgnoreCase),
                    "the omitted EFISP claim must stay inside this session's own backup directory.");
                File.Delete(claimPath);

                backup = await InternalInstallBackup.OpenExistingAsync(client, backupDirectory);
            }

            // The real capture is the model's own claim count; a supplied EFISP claim adds exactly one file
            // unless this call deliberately reopened the set without it.
            int expectedBackupFiles = IsG5Model(toolchain.Model) ? 47 : 51;
            if (gblSources?.EfispSource is not null && !omitEfispBackup)
            {
                expectedBackupFiles++;
            }

            Assert.Equal(expectedBackupFiles, backup.Files.Count);
            Assert.True(client.HasInitialSaharaProof);

            string importRoot = Path.Combine(root, "import");
            Directory.CreateDirectory(importRoot);
            imported = await PackageImporter.ImportAsync(
                rawPackage.Directory, toolchain.Model, InstallationTarget.Internal, importRoot);
            Assert.True(imported.Validation.IsValid, string.Join("; ", imported.Validation.Reasons));

            EdlRawPackageContract contract =
                PackageReader.ReadEdlRawContract(imported.PackageDirectory, toolchain.Model);

            // Both optional Android FW/HWID constraint groups are omitted and read back as absent.
            Assert.Null(contract.EdlProfileId);
            Assert.Null(contract.HardwareId);
            Assert.Null(contract.AndroidBuild);
            Assert.Empty(contract.FirmwareVersions);

            string artifactsParent = Path.Combine(root, "artifacts");
            Directory.CreateDirectory(artifactsParent);
            artifacts = await InternalInstallArtifacts.PrepareAsync(
                backup!, 16, contract.Storage, artifactsParent);

            EdlEntry entry = new(TestAdbPath, router, discovery);
            var services = new InternalInstallServices(entry, router, discovery, TestAdbPath);

            string evidenceParent = Path.Combine(root, "evidence");
            Directory.CreateDirectory(evidenceParent);
            try
            {
                backend = await InternalInstallBackend.CreatePreparedAsync(
                    step1, client, backup!, artifacts!, imported!, assets!, services, evidenceParent);
            }
            catch (Exception preparationError)
            {
                // Production cleanup has already run here and the test workspace is still alive, so the
                // shared GBL sources, the real backup and the evidence tree can still be observed.
                if (gblSources?.MismatchParentBootChild == true
                    && preparationError is InvalidOperationException
                    && preparationError.Message.StartsWith(
                        "gbl-boot-chain-key-mismatch:", StringComparison.Ordinal))
                {
                    string preparationDirectory = Assert.Single(Directory.GetDirectories(evidenceParent));
                    Assert.False(File.Exists(Path.Combine(preparationDirectory, "generic_superfastboot_prc.efi")));
                    Assert.False(File.Exists(Path.Combine(preparationDirectory, "gbl-efisp-candidate.img")));

                    Assert.True(File.Exists(gblSources.EfispSource.Path));
                    foreach (var original in gblSources.Sources.Values)
                    {
                        Assert.True(File.Exists(original.Path));
                    }

                    foreach (var originalBackup in backup!.Files.Values)
                    {
                        Assert.True(File.Exists(originalBackup.FilePath));
                    }
                }

                // The oracle sees the real counts while every lease is still open; the failure itself is
                // never converted into a success and the cleanup below still runs.
                onPreparationFailure?.Invoke(oracle.Calls, edlRunner.Writes.Count, edlRunner.ResetCount);
                throw;
            }

            Assert.Equal(currentSlot, backend.Prepared.CurrentSlot);
            Assert.Equal(6, oracle.Calls);

            transferred = true;
            return new DirectInstallReadyTestSession(
                workspace,
                kernelPackage,
                rawPackage,
                tools!,
                assets!,
                device,
                edlRunner,
                backup!,
                artifacts!,
                imported!,
                backend,
                avbSources,
                originalAvbSources,
                originalRootKey,
                avbSourceKind,
                toolchain,
                oracle);
        }
        finally
        {
            if (!transferred)
            {
                backend?.Dispose();
                imported?.Dispose();
                artifacts?.Dispose();
                backup?.Dispose();
                assets?.Dispose();
                tools?.Dispose();
                rawPackage?.Dispose();
                kernelPackage?.Dispose();
                avbSources?.Dispose();
                workspace?.Dispose();
            }
        }
    }

    /// <summary>Release order is the reverse of construction; the backend goes first.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _backend.Dispose();
        _package.Dispose();
        _artifacts.Dispose();
        _backup.Dispose();
        _assets.Dispose();
        _tools.Dispose();
        _rawPackage.Dispose();
        _kernelPackage.Dispose();

        // The session owns the AVB fixture only when it created one, so it closes here after every lease
        // above and before the workspace that contains its files; a caller's GBL source set is not closed.
        _avbSources?.Dispose();

        // The workspace owns exactly its own generated root; the device has no disposable state and its
        // files live below that root, after every lease above has been released.
        _workspace.Dispose();
    }

    /// <summary>True only for the one model whose package identity and DTB pair this session substitutes.</summary>
    private static bool IsG5Model(string model) =>
        string.Equals(model, G5Model, StringComparison.Ordinal);

    /// <summary>
    /// One G5 raw DTB blob bound to the raw package's own boot arguments, produced by the existing private
    /// writer of the raw DTB validator tests and bound on the compatible pair the G5 manifest declares. No
    /// writer is added or modified here; a missing or empty writer result fails loudly.
    /// </summary>
    private static byte[] CreateG5RawDtb(string bootArgs, string stage)
    {
        System.Reflection.MethodInfo? writer = typeof(EdlRawDtbValidatorTests).GetMethod(
            "CreateValidBlob",
            System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);

        if (writer is null)
        {
            throw new InvalidOperationException(
                "EdlRawDtbValidatorTests no longer exposes the private static CreateValidBlob writer.");
        }

        object? created = writer.Invoke(
            null,
            new object?[]
            {
                new[] { "lenovo,baldur", "qcom,kaanapali" },
                bootArgs,
                stage,
                new[] { 5u },
            });

        return created as byte[]
            ?? throw new InvalidOperationException(
                "the raw DTB writer returned no blob for the G5 package.");
    }

    private static string RequireNativeTool(string name)
    {
        string? value = Environment.GetEnvironmentVariable(name);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException(name + " must name the required native Linux oracle binary.");
        }

        string full = Path.GetFullPath(value);
        if (!File.Exists(full))
        {
            throw new InvalidOperationException(name + " does not exist: " + full);
        }

        return full;
    }

    private static InternalDeviceCheckResult CreateStep1(
        AndroidMaintenanceIdentity android,
        string currentSlot,
        BootloaderState fastbootLockState,
        string product)
    {
        var constructor = typeof(InternalDeviceCheckResult).GetConstructor(
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic,
            binder: null,
            new[]
            {
                typeof(AndroidMaintenanceIdentity),
                typeof(string),
                typeof(string),
                typeof(BootloaderState),
                typeof(OtaUpdateState),
                typeof(AndroidReturnState),
                typeof(bool),
                typeof(InternalDeviceCheckStage?),
                typeof(string),
                typeof(string),
            },
            modifiers: null)
            ?? throw new InvalidOperationException(
                "InternalDeviceCheckResult no longer exposes the ten-parameter internal constructor.");

        return (InternalDeviceCheckResult)constructor.Invoke(new object?[]
        {
            android,
            android.Identity.Serial,
            product,
            fastbootLockState,
            OtaUpdateState.Completed,
            AndroidReturnState.Verified,
            false,
            null,
            null,
            currentSlot,
        });
    }

    /// <summary>
    /// Routes exactly three executables: the two loaded Windows pins to the existing Linux oracle adapter,
    /// the literal test adb to the Android runner, and the staged toolchain client to the IB fake. Anything
    /// else is refused; there is no RAM or network fallback.
    /// </summary>
    private sealed class DirectSessionCommandRunner : ICommandRunner
    {
        private readonly string _packer;
        private readonly string _unpacker;
        private readonly ICommandRunner _native;
        private readonly string _adbPath;
        private readonly ICommandRunner _android;
        private readonly string _toolchainExecutable;
        private readonly ICommandRunner _edl;

        internal DirectSessionCommandRunner(
            string packer,
            string unpacker,
            ICommandRunner native,
            string adbPath,
            ICommandRunner android,
            string toolchainExecutable,
            ICommandRunner edl)
        {
            _packer = Path.GetFullPath(packer);
            _unpacker = Path.GetFullPath(unpacker);
            _native = native;
            _adbPath = adbPath;
            _android = android;
            _toolchainExecutable = Path.GetFullPath(toolchainExecutable);
            _edl = edl;
        }

        public Task<ProcessResult> RunAsync(
            ProcessCommand command,
            CancellationToken cancellationToken = default)
        {
            string requested = Path.GetFullPath(command.Executable);

            if (string.Equals(requested, _packer, StringComparison.OrdinalIgnoreCase)
                || string.Equals(requested, _unpacker, StringComparison.OrdinalIgnoreCase))
            {
                return _native.RunAsync(command, cancellationToken);
            }

            if (string.Equals(requested, Path.GetFullPath(_adbPath), StringComparison.OrdinalIgnoreCase))
            {
                return _android.RunAsync(command, cancellationToken);
            }

            if (string.Equals(requested, _toolchainExecutable, StringComparison.OrdinalIgnoreCase))
            {
                return _edl.RunAsync(command, cancellationToken);
            }

            throw new InvalidOperationException(
                "the direct session requested an executable that is not a loaded tool: " + command.Executable);
        }
    }

    /// <summary>
    /// The default Android boundary of this session: it only answers <c>adb devices</c> with the literal
    /// unauthorized serial. Every other argv is refused, so no preparation step can silently start adb work.
    /// </summary>
    private sealed class DirectAdbRunner : ICommandRunner
    {
        public Task<ProcessResult> RunAsync(
            ProcessCommand command,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (command.Arguments.Count == 1
                && string.Equals(command.Arguments[0], "devices", StringComparison.Ordinal))
            {
                return Task.FromResult(new ProcessResult(
                    0,
                    "List of devices attached\nSN0123456789\tunauthorized\n",
                    string.Empty));
            }

            throw new InvalidOperationException(
                "the direct session adb boundary only answers 'adb devices'.");
        }
    }
}
