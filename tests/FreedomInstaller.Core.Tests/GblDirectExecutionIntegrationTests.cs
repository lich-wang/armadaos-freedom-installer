using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Real (non-simulated) GBL direct-execution tests. They encode the required EFI/boot_a/boot_b/misc
/// behavior and do not imply success against an actual device.
/// </summary>
public sealed class GblDirectExecutionIntegrationTests
    : IClassFixture<Gen5EdlToolchainFixture>,
      IClassFixture<EdlRawSharedInput>
{
    private const string ConfirmationFileName = "prepared-confirmation.json";
    private const int BcbUnitSize = 2048;

    private static readonly string[] MetadataRoles =
    {
        "recovery_a", "vbmeta_system_a", "vbmeta_a",
        "recovery_b", "vbmeta_system_b", "vbmeta_b",
    };

    private readonly Gen5EdlToolchainFixture _g5;
    private readonly EdlRawSharedInput _raw;

    public GblDirectExecutionIntegrationTests(Gen5EdlToolchainFixture g5, EdlRawSharedInput raw)
    {
        _g5 = g5;
        _raw = raw;
    }

    // ---------------------------------------------------------------------------------------
    // A. Empty slot B — EFI + both effective boots, no slot-B metadata (1)
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Execute_Empty_B_WritesEfiThenBothEffectiveBootsWithoutMetadata()
    {
        using var source = new GblDirectSourceFixture("PRC");
        using var session = await OpenAsync(source, zeroSlot: "b");

        var result = await session.Backend.ExecuteAsync(
            session.Backend.Prepared.ConfirmationId,
            userdataEraseConfirmed: true);

        var writes = session.EdlRunner.Writes;
        Assert.Equal(11, writes.Count);

        Assert.Equal(InternalInstallOutcome.InstallationCompleted, result.Outcome);
        Assert.Equal(InternalInstallWriteState.AllVerified, result.WriteState);
        Assert.Equal("b,a", string.Join(",", result.VerifiedSlots));
        Assert.Equal(1, session.EdlRunner.ResetCount);

        var slotB = session.Backend.Prepared.AvbSlots["b"];
        Assert.True(slotB.NonbootableSystem, "empty slot b must be flagged non-bootable");
        Assert.Equal("a", slotB.SourceSlot);

        var efisp = session.Backup.Files["efisp"];
        var bootB = session.Backup.Files["boot_b"];
        var bootA = session.Backup.Files["boot_a"];
        var misc = session.Backup.Files["misc"];

        // Frozen order: 0..6 existing pipeline, 7 efisp, 8 boot_b, 9 boot_a, 10 misc BCB.
        AssertFullWrite(writes[7], efisp);
        AssertFullWrite(writes[8], bootB);
        AssertFullWrite(writes[9], bootA);
        AssertBcbWrite(writes[10], misc);

        // Prior seven partition/artifact writes are untouched.
        var firstSeven = writes.Take(7).ToArray();
        Assert.Equal(
            7,
            firstSeven
                .Select(w => $"{Convert.ToInt64(w.Lun)}:{Convert.ToInt64(w.StartSector)}:{Convert.ToInt64(w.SectorCount)}")
                .Distinct(StringComparer.Ordinal)
                .Count());
        foreach (var write in firstSeven)
        {
            Assert.False(string.IsNullOrWhiteSpace(write.Sha256), "prior pipeline writes must carry a SHA-256");
            Assert.Equal(write.Sha256, Sha256OfFile(write.FilePath), ignoreCase: true);
            Assert.DoesNotContain(
                new[] { "efisp", "boot_a", "boot_b", "misc" },
                role => SameRegion(write, session.Backup.Files[role]));
        }

        using var confirmation = ReadPreparedConfirmation(session);

        var efispCandidate = RequireString(confirmation.RootElement, "direct.gbl.efisp.candidate.sha256");
        Assert.True(
            string.Equals(efispCandidate, writes[7].Sha256, StringComparison.OrdinalIgnoreCase),
            "efisp write must carry direct.gbl.efisp.candidate.sha256");

        AssertBootWrite(session, confirmation.RootElement, "b", writes[8]);
        AssertBootWrite(session, confirmation.RootElement, "a", writes[9]);

        // Neither slot's own metadata may be written for the empty-B case.
        foreach (var role in MetadataRoles)
        {
            var region = session.Backup.Files[role];
            Assert.DoesNotContain(writes, write => SameRegion(write, region));
        }

        // No other partition, and in particular no system / systemclone write.
        foreach (var pair in session.Backup.Files)
        {
            if (pair.Key.Contains("system", StringComparison.OrdinalIgnoreCase))
            {
                Assert.DoesNotContain(writes, write => SameRegion(write, pair.Value));
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // B. EFI fresh-target tamper: fail closed before any write (1)
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Execute_EfispFreshTargetTamperFailsBeforeAnyWrite()
    {
        using var source = new GblDirectSourceFixture("PRC");
        using var session = await OpenAsync(source, zeroSlot: null);

        var efi = session.Backup.Files["efisp"];
        var original = File.ReadAllBytes(efi.FilePath);
        Assert.True(original.Length > 17, "efisp backup is too small to tamper at byte 17");

        var tampered = (byte[])original.Clone();
        tampered[17] ^= 0xFF;

        session.EdlRunner.PayloadOverride = read =>
            session.EdlRunner.Writes.Count == 0 && SameRegion(read, efi)
                ? (byte[])tampered.Clone()
                : null;

        var result = await session.Backend.ExecuteAsync(
            session.Backend.Prepared.ConfirmationId,
            userdataEraseConfirmed: true);

        Assert.Equal(InternalInstallOutcome.Failed, result.Outcome);
        Assert.Equal(InternalInstallWriteState.NoneIssued, result.WriteState);
        Assert.Equal(0, session.EdlRunner.Writes.Count);
        Assert.Equal(0, session.EdlRunner.ResetCount);
    }

    // ---------------------------------------------------------------------------------------
    // C. EFI readback failure: unknown outcome, nothing after EFI (1)
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Execute_EfispReadbackFailureStopsBeforeBootAndMisc()
    {
        using var source = new GblDirectSourceFixture("PRC");
        using var session = await OpenAsync(source, zeroSlot: null);

        var efi = session.Backup.Files["efisp"];
        session.EdlRunner.InjectReadbackFailureOnce(efi.Lun, efi.StartSector, efi.SectorCount);

        var result = await session.Backend.ExecuteAsync(
            session.Backend.Prepared.ConfirmationId,
            userdataEraseConfirmed: true);

        Assert.Equal(InternalInstallOutcome.UnknownWriteOutcome, result.Outcome);
        Assert.Equal(InternalInstallWriteState.Unknown, result.WriteState);
        Assert.Equal(0, session.EdlRunner.ResetCount);

        var writes = session.EdlRunner.Writes;
        Assert.Equal(8, writes.Count);
        AssertFullWrite(writes[7], efi);

        // The first seven are legitimate; nothing at or after boot may be issued.
        var bootA = session.Backup.Files["boot_a"];
        var bootB = session.Backup.Files["boot_b"];
        Assert.DoesNotContain(writes, write => SameRegion(write, bootA));
        Assert.DoesNotContain(writes, write => SameRegion(write, bootB));

        foreach (var role in MetadataRoles)
        {
            var region = session.Backup.Files[role];
            Assert.DoesNotContain(writes, write => SameRegion(write, region));
        }

        // The BCB write is a single unit, so compare only LUN/start.
        var misc = session.Backup.Files["misc"];
        Assert.DoesNotContain(
            writes,
            write => Convert.ToInt64(write.Lun) == Convert.ToInt64(misc.Lun)
                     && Convert.ToInt64(write.StartSector) == Convert.ToInt64(misc.StartSector));
    }

    // ---------------------------------------------------------------------------------------
    // Session / evidence helpers
    // ---------------------------------------------------------------------------------------

    private Task<DirectInstallReadyTestSession> OpenAsync(GblDirectSourceFixture source, string? zeroSlot)
        => DirectInstallReadyTestSession.CreateAsync(
            _g5.Toolchain,
            _raw,
            avbSourceKind: DirectAvbSourceKind.Oem,
            observedFastbootLockState: BootloaderState.Locked,
            gblSources: source,
            zeroSlot: zeroSlot);

    private static JsonDocument ReadPreparedConfirmation(DirectInstallReadyTestSession session)
    {
        var directory = session.Backend.Prepared.EvidenceDirectory;
        Assert.False(string.IsNullOrWhiteSpace(directory), "prepared evidence directory must be known");

        var path = Path.Combine(directory, ConfirmationFileName);
        Assert.True(File.Exists(path), $"{ConfirmationFileName} was not produced at {path}");

        var bytes = File.ReadAllBytes(path);
        Assert.NotEmpty(bytes);
        return JsonDocument.Parse(bytes);
    }

    private static void AssertBootWrite(
        DirectInstallReadyTestSession session,
        JsonElement confirmation,
        string slot,
        IB001Write write)
    {
        AssertFullWrite(write, session.Backup.Files["boot_" + slot]);

        var entry = RequireSlot(confirmation, slot);
        Assert.Equal("a", RequireString(entry, "sourceSlot"));
        var candidate = RequireString(entry, "candidateBoot.sha256");
        var intermediate = RequireString(entry, "buildIntermediate.candidateBoot.sha256");

        Assert.True(
            string.Equals(candidate, write.Sha256, StringComparison.OrdinalIgnoreCase),
            $"boot_{slot} write must carry direct.slots[{slot}].candidateBoot.sha256");
        Assert.False(
            string.Equals(intermediate, write.Sha256, StringComparison.OrdinalIgnoreCase),
            $"boot_{slot} write must not carry the build-intermediate boot image");
    }

    private static void AssertFullWrite(IB001Write write, EdlCapturedRegion region)
    {
        Assert.Equal(Convert.ToInt64(region.Lun), Convert.ToInt64(write.Lun));
        Assert.Equal(Convert.ToInt64(region.StartSector), Convert.ToInt64(write.StartSector));
        Assert.Equal(Convert.ToInt64(region.SectorCount), Convert.ToInt64(write.SectorCount));
        Assert.False(string.IsNullOrWhiteSpace(write.FilePath), "write payload path must be known");
        Assert.True(File.Exists(write.FilePath), $"write payload was not produced at {write.FilePath}");

        Assert.Equal(region.Length, new FileInfo(write.FilePath).Length);
        Assert.True(
            string.Equals(write.Sha256, Sha256OfFile(write.FilePath), StringComparison.OrdinalIgnoreCase),
            "streamed SHA-256 of the write payload must equal the recorded write SHA-256");
    }

    private static void AssertBcbWrite(IB001Write write, EdlCapturedRegion misc)
    {
        var sectorSize = Convert.ToInt64(misc.SectorSize);
        Assert.True(sectorSize > 0, "misc sector size must be known");

        var expectedUnits = (BcbUnitSize + sectorSize - 1) / sectorSize;

        Assert.Equal(Convert.ToInt64(misc.Lun), Convert.ToInt64(write.Lun));
        Assert.Equal(Convert.ToInt64(misc.StartSector), Convert.ToInt64(write.StartSector));
        Assert.Equal(expectedUnits, Convert.ToInt64(write.SectorCount));

        var length = new FileInfo(write.FilePath).Length;
        Assert.Equal(expectedUnits * sectorSize, length);
    }

    private static bool SameRegion(IB001Read read, EdlCapturedRegion region)
        => Convert.ToInt64(read.Lun) == Convert.ToInt64(region.Lun)
           && Convert.ToInt64(read.StartSector) == Convert.ToInt64(region.StartSector)
           && Convert.ToInt64(read.SectorCount) == Convert.ToInt64(region.SectorCount);

    private static bool SameRegion(IB001Write write, EdlCapturedRegion region)
        => Convert.ToInt64(write.Lun) == Convert.ToInt64(region.Lun)
           && Convert.ToInt64(write.StartSector) == Convert.ToInt64(region.StartSector)
           && Convert.ToInt64(write.SectorCount) == Convert.ToInt64(region.SectorCount);

    private static string Sha256OfFile(string path)
    {
        using var stream = File.OpenRead(path);
        using var sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
    }

    private static JsonElement Require(JsonElement parent, string path)
    {
        var current = parent;
        foreach (var part in path.Split('.'))
        {
            Assert.True(
                current.ValueKind == JsonValueKind.Object,
                $"{ConfirmationFileName}: expected an object while resolving '{path}'");
            Assert.True(
                current.TryGetProperty(part, out var next),
                $"{ConfirmationFileName}: missing field '{path}'");
            current = next;
        }

        return current;
    }

    private static string RequireString(JsonElement parent, string path)
    {
        var value = Require(parent, path);
        Assert.True(
            value.ValueKind == JsonValueKind.String,
            $"{ConfirmationFileName}: field '{path}' must be a string");

        var text = value.GetString();
        Assert.False(string.IsNullOrWhiteSpace(text), $"{ConfirmationFileName}: field '{path}' must not be empty");
        return text!;
    }

    private static JsonElement RequireSlot(JsonElement confirmation, string slot)
    {
        var slots = Require(confirmation, "direct.slots");
        Assert.True(
            slots.ValueKind == JsonValueKind.Array,
            $"{ConfirmationFileName}: direct.slots must be an array");

        foreach (var entry in slots.EnumerateArray())
        {
            if (entry.ValueKind == JsonValueKind.Object
                && entry.TryGetProperty("slot", out var label)
                && label.ValueKind == JsonValueKind.String
                && string.Equals(label.GetString(), slot, StringComparison.OrdinalIgnoreCase))
            {
                return entry;
            }
        }

        Assert.True(false, $"{ConfirmationFileName}: direct.slots must describe slot '{slot}'");
        return default;
    }
}
