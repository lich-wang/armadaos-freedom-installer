// ES3: the direct factory source-slot selection over one factory-uninitialized target slot.
// The session is the existing real direct composition (actual backup, artifacts, package, IB synthetic
// device and Linux oracle); only the optional zeroSlot input of the session is exercised here. No write,
// reset or execution is claimed, no physical boot or switch of the active slot is claimed, and no whole
// partition array is ever allocated by this file.
using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// The direct EDL raw preparation when exactly one target slot is factory-uninitialized: the built target
/// takes the trusted current slot's real material while the original all-zero target claims stay preserved
/// as evidence. The two negative cases refuse a partially corrupted zero target and a zero current slot.
/// </summary>
public sealed class InternalInstallInactiveSlotPreparationTests
    : IClassFixture<EdlClientToolchainFixture>, IClassFixture<EdlRawSharedInput>
{
    /// <summary>The fixed five source roles, in the fixture's own order.</summary>
    private static readonly string[] InactiveRoles =
    {
        "current_boot",
        "vendor_boot",
        "init_boot",
        "abl",
        "xbl_config",
    };

    private readonly EdlClientToolchainFixture _toolchain;
    private readonly EdlRawSharedInput _rawShared;

    public InternalInstallInactiveSlotPreparationTests(
        EdlClientToolchainFixture toolchain,
        EdlRawSharedInput rawShared)
    {
        _toolchain = toolchain;
        _rawShared = rawShared;
    }

    [Fact]
    public async Task ES3_CreatePrepared_CurrentAEmptyB_UsesCurrentSourceAndPreservesOriginalTarget()
    {
        using DirectInstallReadyTestSession session =
            await DirectInstallReadyTestSession.CreateAsync(
                _toolchain, _rawShared, currentSlot: "a", zeroSlot: "b");

        InternalInstallPrepared prepared = session.Backend.Prepared;

        // The observed current slot is unchanged and the fixed candidate order stays b before a.
        Assert.Equal("a", prepared.CurrentSlot);
        Assert.Equal(new[] { "b", "a" }, prepared.SlotOrder);

        // Both built slots really name the trusted A material and carry A's five actual claim hashes.
        Assert.Equal(2, prepared.SlotMaterials.Count);
        foreach (string targetSlot in new[] { "a", "b" })
        {
            InternalSlotMaterial material = prepared.SlotMaterials[targetSlot];
            Assert.Equal("a", material.Slot);
            Assert.Equal(5, material.SourceSha256.Count);
            Assert.Equal(5, material.SourceLengths.Count);

            for (int index = 0; index < InactiveRoles.Length; index++)
            {
                EdlCapturedRegion sourceClaim = session.Backup.Files[BackupRole("a", index)];
                Assert.Equal(
                    sourceClaim.Sha256,
                    material.SourceSha256[InactiveRoles[index]],
                    ignoreCase: true);
                Assert.Equal(sourceClaim.Length, material.SourceLengths[InactiveRoles[index]]);
            }
        }

        // The device capture of the zero target is the real original B backup, not A's boot bytes.
        Assert.Equal(2, prepared.CurrentBootSha256.Count);
        Assert.Equal(
            session.Backup.Files["boot_b"].Sha256,
            prepared.CurrentBootSha256["b"],
            ignoreCase: true);
        Assert.NotEqual(
            prepared.CurrentBootSha256["a"],
            prepared.CurrentBootSha256["b"],
            StringComparer.OrdinalIgnoreCase);

        // The original B capture survives as evidence, and none of it is one of A's source hashes.
        for (int index = 0; index < InactiveRoles.Length; index++)
        {
            string backupRole = BackupRole("b", index);
            Assert.True(session.Backup.Files.ContainsKey(backupRole), backupRole);
            Assert.False(
                string.Equals(
                    session.Backup.Files[backupRole].Sha256,
                    prepared.SlotMaterials["b"].SourceSha256[InactiveRoles[index]],
                    StringComparison.OrdinalIgnoreCase),
                backupRole + " was replaced by the trusted source claim");
        }

        // The two builders alone ran; nothing was written, reset or executed.
        Assert.Equal(6, session.NativeCommandCount);
        Assert.Equal(0, session.EdlRunner.Writes.Count);
        Assert.Equal(0, session.EdlRunner.ResetCount);
        Assert.False(session.Backend.Snapshot.ExecutionStarted);

        // The saved confirmation names the source of each target and flags only the zero target slot.
        string confirmationPath = Path.Combine(prepared.EvidenceDirectory, "prepared-confirmation.json");
        Assert.True(File.Exists(confirmationPath), confirmationPath);

        using (JsonDocument confirmation = JsonDocument.Parse(File.ReadAllBytes(confirmationPath)))
        {
            JsonElement root = confirmation.RootElement;
            Assert.Equal("a", root.GetProperty("device").GetProperty("currentSlot").GetString());

            JsonElement slots = root.GetProperty("direct").GetProperty("slots");
            Assert.Equal(2, slots.GetArrayLength());

            Assert.Equal("b", slots[0].GetProperty("slot").GetString());
            Assert.Equal("a", slots[0].GetProperty("sourceSlot").GetString());
            Assert.True(slots[0].GetProperty("inactiveTargetUninitialized").GetBoolean());

            Assert.Equal("a", slots[1].GetProperty("slot").GetString());
            Assert.Equal("a", slots[1].GetProperty("sourceSlot").GetString());
            Assert.False(slots[1].GetProperty("inactiveTargetUninitialized").GetBoolean());

            JsonElement materials = root.GetProperty("slotMaterials");
            Assert.Equal(2, materials.GetArrayLength());
            foreach (JsonElement entry in materials.EnumerateArray())
            {
                Assert.Equal("a", entry.GetProperty("sourceSlot").GetString());
            }
        }

        // The copied builder report of the zero target keeps its source/target binding and B's zero bytes.
        string reportPath = Path.Combine(prepared.EvidenceDirectory, "direct-slot-b-verification.json");
        Assert.True(File.Exists(reportPath), reportPath);

        using (JsonDocument report = JsonDocument.Parse(File.ReadAllBytes(reportPath)))
        {
            JsonElement root = report.RootElement;
            Assert.Equal("a", root.GetProperty("sourceSlot").GetString());
            Assert.Equal("b", root.GetProperty("targetSlot").GetString());
            Assert.True(root.GetProperty("inactiveTargetUninitialized").GetBoolean());

            JsonElement targetBackup = root.GetProperty("targetBackup");
            for (int index = 0; index < InactiveRoles.Length; index++)
            {
                EdlCapturedRegion original = session.Backup.Files[BackupRole("b", index)];
                JsonElement role = targetBackup.GetProperty(InactiveRoles[index]);
                Assert.Equal(original.Length, role.GetProperty("bytes").GetInt64());
                Assert.Equal(original.Sha256, role.GetProperty("sha256").GetString(), ignoreCase: true);
            }
        }
    }

    [Fact]
    public async Task ES3_CreatePrepared_NonZeroInactiveBootTail_IsRejected()
    {
        // A zero header alone is not an uninitialized target: one byte after the first 4 KiB refuses it
        // before any candidate exists.
        await Assert.ThrowsAsync<InvalidDataException>(
            () => DirectInstallReadyTestSession.CreateAsync(
                _toolchain, _rawShared, currentSlot: "a", zeroSlot: "b", corruptZeroBoot: true));
    }

    [Fact]
    public async Task ES3_CreatePrepared_ZeroCurrentSlot_IsRejected()
    {
        // The trusted source itself can never be the uninitialized target.
        await Assert.ThrowsAsync<InvalidDataException>(
            () => DirectInstallReadyTestSession.CreateAsync(
                _toolchain, _rawShared, currentSlot: "a", zeroSlot: "a"));
    }

    /// <summary>The backup role of one of the five fixed source roles for a slot.</summary>
    private static string BackupRole(string slot, int index) =>
        index == 0 ? "boot_" + slot : InactiveRoles[index] + "_" + slot;
}
