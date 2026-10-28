using System;
using System.IO;
using System.Linq;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Discovery-level gate for the single test in this file that needs the REAL tablet captures. Everything else
/// in the suite runs from in-repo fixtures; this one is meaningless without the actual bytes, so xunit must
/// report it as skipped (not as a pass) while the evidence directory is not mounted. The decision is made at
/// discovery time from the environment so no runtime skip exception is inferred or faked.
/// </summary>
public sealed class OriginalGptDeviceEvidenceFactAttribute : FactAttribute
{
    public OriginalGptDeviceEvidenceFactAttribute()
    {
        if (string.IsNullOrWhiteSpace(
                Environment.GetEnvironmentVariable(OriginalGptDeviceEvidenceTests.EvidenceRootVariable)))
        {
            Skip = OriginalGptDeviceEvidenceTests.EvidenceRootVariable
                + " is not set, so the real tablet captures ("
                + OriginalGptDeviceEvidenceTests.PrimaryFileName + ", "
                + OriginalGptDeviceEvidenceTests.BackupFileName + ", "
                + OriginalGptDeviceEvidenceTests.CurrentJsonFileName
                + ") are not mounted for this run.";
        }
    }
}

/// <summary>
/// Regression over the actual original handset evidence: the raw primary + backup GPT captured from the
/// factory 4Kn disk, plus the sfdisk JSON the device tooling printed afterwards. The three files are mounted
/// out of tree by the release run (no binary assets are committed), and the whole production path —
/// <see cref="OriginalGptImporter.Parse"/>, <see cref="UninstallEvidenceValidator.ReadCurrentSfdisk"/>,
/// <see cref="UninstallEvidenceValidator.Validate"/> and the resulting plan — is exercised on those bytes
/// instead of on a synthetic layout.
/// </summary>
public sealed class OriginalGptDeviceEvidenceTests
{
    /// <summary>Directory holding the three mounted evidence files.</summary>
    public const string EvidenceRootVariable = "UNINSTALL_DEVICE_EVIDENCE_ROOT";

    public const string PrimaryFileName = "before-main.bin";
    public const string BackupFileName = "before-backup.bin";
    public const string CurrentJsonFileName = "current-sfdisk.json";

    // The real disk is a 4Kn tablet: 507,376,566,272 bytes reported in 4096-byte sectors.
    private const long DiskBytes = 507_376_566_272L;
    private const int SectorSize = 4096;

    private const long OriginalUserdataStart = 5_972_392L;
    private const long OriginalUserdataEndExclusive = 123_871_227L;
    private const long CurrentUserdataSectorCount = 33_554_432L;
    private const long ArmadaBootStart = 39_526_912L;
    private const long ArmadaBootSectorCount = 262_144L;
    private const long ArmadaRootStart = 39_789_056L;
    private const long ArmadaRootSectorCount = 84_082_171L;

    // Primary header+entries and backup header+entries, as the device actually reports them.
    private const int PrimaryFragmentLength = 24_576;
    private const int BackupFragmentLength = 20_480;

    /// <summary>
    /// The real capture has to survive the full path and still describe a restorable legacy layout: userdata
    /// at its factory start, the ARMADA partitions sitting exactly 88 sectors past userdata's end, and the
    /// Linux root ending on the original userdata boundary. Slots 17/18 (not the synthetic 3/4) are the ones
    /// the plan is allowed to drop.
    /// </summary>
    [OriginalGptDeviceEvidenceFact]
    public void RealTabletCapture_OldUserdataAndEightyEightSectorGap_ValidateAndPlanRestore()
    {
        // The attribute already gated discovery; execution must still fail loudly if the variable vanished.
        var evidenceRoot = Environment.GetEnvironmentVariable(EvidenceRootVariable);
        Assert.False(
            string.IsNullOrWhiteSpace(evidenceRoot),
            EvidenceRootVariable + " must name the directory with the real tablet evidence while this test runs.");

        // No search, no fallback name, no device node: exactly the three mounted files or a test failure.
        var primaryFragment = File.ReadAllBytes(Path.Combine(evidenceRoot!, PrimaryFileName));
        var backupFragment = File.ReadAllBytes(Path.Combine(evidenceRoot!, BackupFileName));
        var currentJson = File.ReadAllText(Path.Combine(evidenceRoot!, CurrentJsonFileName));

        // The captures are raw GPT fragments of the sizes the tablet really produced; a truncated or
        // re-wrapped file must fail before the parser is asked to interpret it.
        Assert.Equal(PrimaryFragmentLength, primaryFragment.Length);
        Assert.Equal(BackupFragmentLength, backupFragment.Length);

        var original = OriginalGptImporter.Parse(primaryFragment, backupFragment, SectorSize, DiskBytes);
        var current = UninstallEvidenceValidator.ReadCurrentSfdisk(currentJson, DiskBytes);

        // ---- the original capture is a factory 4Kn tablet with a single full-size userdata partition.

        Assert.Null(original.DeviceId); // raw capture names no device at all
        Assert.Equal(DiskBytes, original.DiskBytes);
        Assert.Equal(SectorSize, original.SectorSize);

        var originalUserdata = original.Partitions.Where(p => p.Name == "userdata").ToList();
        Assert.Single(originalUserdata);
        Assert.Equal(OriginalUserdataStart, originalUserdata[0].StartSector);
        Assert.Equal(OriginalUserdataEndExclusive, originalUserdata[0].StartSector + originalUserdata[0].SectorCount);

        // ---- the current table is the same disk, reported live, with the two owned ARMADA partitions.

        Assert.Equal(DiskBytes, current.DiskBytes);
        Assert.Equal(SectorSize, current.SectorSize);
        Assert.False(string.IsNullOrWhiteSpace(current.DeviceId)); // kept as reported, never hardcoded

        var currentUserdata = current.Partitions.Where(p => p.Name == "userdata").ToList();
        Assert.Single(currentUserdata);
        Assert.Equal(OriginalUserdataStart, currentUserdata[0].StartSector);
        Assert.Equal(CurrentUserdataSectorCount, currentUserdata[0].SectorCount);

        var armadaBoot = current.Partitions.Where(p => p.Name == "ARMADA_BOOT").ToList();
        Assert.Single(armadaBoot);
        Assert.Equal(ArmadaBootStart, armadaBoot[0].StartSector);
        Assert.Equal(ArmadaBootSectorCount, armadaBoot[0].SectorCount);

        var armadaRoot = current.Partitions.Where(p => p.Name == "ARMADA_ROOT").ToList();
        Assert.Single(armadaRoot);
        Assert.Equal(ArmadaRootStart, armadaRoot[0].StartSector);
        Assert.Equal(ArmadaRootSectorCount, armadaRoot[0].SectorCount);

        // The real tablet put these in slots 17/18, unlike every synthetic fixture in the suite.
        Assert.Equal(17L, (long)armadaBoot[0].Number);
        Assert.Equal(18L, (long)armadaRoot[0].Number);

        // The legitimate gap the installer must tolerate: 88 sectors of padding between userdata's end and
        // ARMADA_BOOT, with ARMADA_ROOT ending exactly where the original userdata ended.
        Assert.Equal(
            88L,
            armadaBoot[0].StartSector - (currentUserdata[0].StartSector + currentUserdata[0].SectorCount));
        Assert.Equal(
            OriginalUserdataEndExclusive,
            armadaRoot[0].StartSector + armadaRoot[0].SectorCount);

        // The raw-GPT digest is supplied by the inspector out of band, so it is deliberately unrelated to the
        // JSON's own SourceFingerprint; validation binds both independently.
        var rawTableFingerprint = new string('A', 64);
        Assert.NotEqual(current.SourceFingerprint, rawTableFingerprint);

        var identity = new DeviceIdentity("DEVICE-EVIDENCE-TEST", "TB322FC", BootloaderState.Unlocked);

        var validated = UninstallEvidenceValidator.Validate(identity, original, current, rawTableFingerprint);

        // Provenance: the external digest is retained verbatim, and the original snapshot stays the raw one.
        Assert.Equal(rawTableFingerprint, validated.CurrentTableFingerprint);
        Assert.Equal(original.SourceFingerprint, validated.OriginalGptFingerprint);

        // ---- the plan restores the original userdata extent and removes only the owned Linux pair.

        Assert.Equal(current.DeviceId, validated.Record.DeviceId);
        Assert.Equal(OriginalUserdataEndExclusive, validated.Record.OriginalUserdataEndSector);

        Assert.Equal(OriginalUserdataStart, validated.Plan.UserdataStartSector);
        Assert.Equal(OriginalUserdataEndExclusive, validated.Plan.UserdataEndSectorExclusive);
        Assert.Equal(482_913_628_160L, validated.Plan.RestoredAndroidBytes); // 117,898,835 sectors of 4096
        Assert.Equal(new long[] { 17L, 18L }, validated.Plan.RemovedPartitionNumbers);
    }
}
