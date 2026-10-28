using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Session = FreedomInstaller.Core.Tests.DirectInstallReadyTestSession;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// P2 / F3B — AVB chain graph + real metadata write/verify coverage.
///
/// Every case in this file is expected to FAIL until P2 lands, and the failure must be one of:
///   * direct.avbChain missing from prepared-confirmation.json,
///   * the six metadata writes (recovery_*/vbmeta_system_*/vbmeta_* per slot) not being emitted,
///   * the pre-write warm-target readback tamper check not existing.
/// A failure caused by the environment, an invalid source payload, or a signing problem is NOT an
/// acceptable red and must not be reported as one.
///
/// No bootability claim is made anywhere here: these tests pin the metadata chain plan
/// (original/candidate/target) and the physical writes, nothing more.
/// </summary>
public sealed class InternalInstallAvbChainExecutionTests
    : IClassFixture<EdlClientToolchainFixture>
    , IClassFixture<EdlRawSharedInput>
{
    private const string ConfirmationFileName = "prepared-confirmation.json";

    private static readonly string[] MetadataPrefixes = { "recovery", "vbmeta_system", "vbmeta" };
    private static readonly string[] ChainPinKeys = { "boot", "recovery", "vbmeta_system" };

    private static readonly string[] FullMetadataOrder =
    {
        "recovery_b", "vbmeta_system_b", "vbmeta_b",
        "recovery_a", "vbmeta_system_a", "vbmeta_a",
    };

    private static readonly string[] EmptyBMetadataOrder =
    {
        "recovery_a", "vbmeta_system_a", "vbmeta_a",
    };

    private readonly EdlClientToolchainFixture _toolchain;
    private readonly EdlRawSharedInput _rawShared;

    public InternalInstallAvbChainExecutionTests(
        EdlClientToolchainFixture toolchain,
        EdlRawSharedInput rawShared)
    {
        _toolchain = toolchain;
        _rawShared = rawShared;
    }

    // ---------------------------------------------------------------------------------------
    // A. Prepared confirmation graph (2)
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(null)]
    [InlineData("b")]
    public async Task PreparedConfirmation_DescribesAvbChainGraph(string? zeroSlot)
    {
        using var session = await OpenAsync(zeroSlot);
        using var document = ReadPreparedConfirmation(session);
        var root = document.RootElement;

        var direct = RequireObject(root, "direct", "prepared-confirmation");
        var chain = RequireObject(direct, "avbChain", "prepared-confirmation.direct");

        var pin = RequireString(chain, "signingPublicKeySha256", "direct.avbChain");
        AssertValidSha(pin, "direct.avbChain.signingPublicKeySha256");

        var slots = RequireArray(chain, "slots", "direct.avbChain");
        Assert.Equal(2, slots.GetArrayLength());

        var ordered = slots.EnumerateArray().ToArray();
        Assert.Equal("b", RequireString(ordered[0], "slot", "direct.avbChain.slots[0]"));
        Assert.Equal("a", RequireString(ordered[1], "slot", "direct.avbChain.slots[1]"));

        // Slot b: real source unless the run explicitly emptied it.
        VerifySlotDetail(
            session,
            ordered[0],
            slot: "b",
            sourceSlot: zeroSlot is null ? "b" : "a",
            nonbootableSystem: zeroSlot is not null,
            metadataNodeCount: zeroSlot is null ? 3 : 0,
            preservedMetadataCount: zeroSlot is null ? 0 : 3,
            pin: pin);

        // Slot a is always a real source and always carries the full three-node chain.
        VerifySlotDetail(
            session,
            ordered[1],
            slot: "a",
            sourceSlot: "a",
            nonbootableSystem: false,
            metadataNodeCount: 3,
            preservedMetadataCount: 0,
            pin: pin);

        // The pre-P2 direct.slots boot facts must be preserved untouched.
        var bootSlots = RequireArray(direct, "slots", "prepared-confirmation.direct");
        Assert.Equal(2, bootSlots.GetArrayLength());
        var bootSlotNames = bootSlots.EnumerateArray()
            .Select(slot => RequireString(slot, "slot", "direct.slots[]"))
            .ToArray();
        Assert.Contains("a", bootSlotNames);
        Assert.Contains("b", bootSlotNames);

        // P2D2 — budget regression: the declared future byte total must equal an independently
        // derived canonical total, so a dropped metadata budget or a double count fails here
        // for both slot shapes.
        AssertRequiredExecutionBudget(session, direct, zeroSlot);
    }

    // ---------------------------------------------------------------------------------------
    // B. Actual execution: metadata writes really happen (2)
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(null, 16)]
    [InlineData("b", 13)]
    public async Task Execute_EmitsMetadataWritesInFrozenOrder(string? zeroSlot, int expectedWriteCount)
    {
        using var session = await OpenAsync(zeroSlot);
        var result = await session.Backend.ExecuteAsync(
            session.Backend.Prepared.ConfirmationId,
            userdataEraseConfirmed: true);

        // Asserted first on purpose: the pre-P2 baseline emits 10 writes and silently completes.
        var writes = session.EdlRunner.Writes;
        Assert.Equal(expectedWriteCount, writes.Count);

        Assert.Equal(InternalInstallOutcome.InstallationCompleted, result.Outcome);
        Assert.Equal(InternalInstallWriteState.AllVerified, result.WriteState);
        Assert.Null(result.AndroidAcceptance);
        Assert.False(result.LinuxAcceptanceVerified);
        Assert.Equal("b,a", string.Join(",", result.VerifiedSlots));
        Assert.Equal(1, session.EdlRunner.ResetCount);
        Assert.NotNull(session.Backend.Prepared.EvidenceDirectory);

        AssertBootBaselineWrites(session, writes);

        var expectedRoles = zeroSlot is null ? FullMetadataOrder : EmptyBMetadataOrder;

        Assert.Equal(9 + expectedRoles.Length + 1, writes.Count);

        var candidateShas = ReadCandidateShas(session);
        for (var i = 0; i < expectedRoles.Length; i++)
        {
            var role = expectedRoles[i];
            Assert.True(candidateShas.ContainsKey(role), $"direct.avbChain must describe {role}");
            VerifyMetadataWrite(session, writes[9 + i], role, candidateShas[role]);
        }

        AssertFinalMiscWrite(session, writes[writes.Count - 1]);

        if (zeroSlot is not null)
        {
            // Non-bootable slot b: its metadata partitions must not be written at all.
            foreach (var prefix in MetadataPrefixes)
            {
                var untouched = session.Backup.Files[Role(prefix, "b")];
                Assert.DoesNotContain(writes, write => SameRegion(write, untouched));
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // C. Warm-target tamper: modify the on-device target before the write (3)
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("recovery_a")]
    [InlineData("vbmeta_system_a")]
    [InlineData("vbmeta_a")]
    public async Task Execute_FailsClosed_WhenWarmTargetRegionIsTamperedBeforeWrite(string role)
    {
        using var session = await OpenAsync(zeroSlot: null);

        var backup = session.Backup.Files[role];
        var original = File.ReadAllBytes(backup.FilePath);
        Assert.True(original.Length > 17, $"{role} backup is too small to tamper at byte 17");

        var tampered = (byte[])original.Clone();
        tampered[17] ^= 0xFF;

        session.EdlRunner.PayloadOverride = read =>
            session.EdlRunner.Writes.Count == 0 && SameRegion(read, backup)
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
    // D. Post-write readback failure: unknown write outcome, no reset (3)
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("recovery_a", 12, 13)]
    [InlineData("vbmeta_system_a", 13, 14)]
    [InlineData("vbmeta_a", 14, 15)]
    public async Task Execute_ReportsUnknownWriteOutcome_WhenReadbackFails(
        string role,
        int failingIndex,
        int expectedIssuedWrites)
    {
        using var session = await OpenAsync(zeroSlot: null);

        var backup = session.Backup.Files[role];
        session.EdlRunner.InjectReadbackFailureOnce(backup.Lun, backup.StartSector, backup.SectorCount);

        var result = await session.Backend.ExecuteAsync(
            session.Backend.Prepared.ConfirmationId,
            userdataEraseConfirmed: true);

        Assert.Equal(InternalInstallOutcome.UnknownWriteOutcome, result.Outcome);
        Assert.Equal(InternalInstallWriteState.Unknown, result.WriteState);
        Assert.Equal(0, session.EdlRunner.ResetCount);

        var writes = session.EdlRunner.Writes;
        Assert.Equal(expectedIssuedWrites, writes.Count);
        Assert.Equal(failingIndex, expectedIssuedWrites - 1);
        Assert.True(
            SameRegion(writes[failingIndex], backup),
            $"write #{failingIndex} must be the {role} full-partition write");

        // Only roles ordered after the failing one may be absent; earlier legitimate writes stay legal.
        var failingOrderIndex = Array.IndexOf(FullMetadataOrder, role);
        Assert.True(failingOrderIndex >= 0, $"{role} must be part of the frozen metadata order");

        for (var i = failingOrderIndex + 1; i < FullMetadataOrder.Length; i++)
        {
            var laterRegion = session.Backup.Files[FullMetadataOrder[i]];
            Assert.DoesNotContain(writes, write => SameRegion(write, laterRegion));
        }

        // The final misc unit follows every metadata write, so it can never appear here. The BCB
        // write is one unit, not the full captured misc partition: compare LUN/start only.
        var misc = session.Backup.Files["misc"];
        Assert.DoesNotContain(
            writes,
            write => Convert.ToInt64(write.Lun) == Convert.ToInt64(misc.Lun)
                     && Convert.ToInt64(write.StartSector) == Convert.ToInt64(misc.StartSector));
    }

    // ---------------------------------------------------------------------------------------
    // Session / evidence helpers
    // ---------------------------------------------------------------------------------------

    private Task<Session> OpenAsync(string? zeroSlot)
        => Session.CreateAsync(
            _toolchain,
            _rawShared,
            zeroSlot: zeroSlot,
            avbSourceKind: DirectAvbSourceKind.Oem,
            observedFastbootLockState: BootloaderState.Unlocked);

    private static JsonDocument ReadPreparedConfirmation(Session session)
    {
        var path = Path.Combine(session.Backend.Prepared.EvidenceDirectory, ConfirmationFileName);
        Assert.True(File.Exists(path), $"{ConfirmationFileName} was not produced at {path}");
        var bytes = File.ReadAllBytes(path);
        Assert.NotEmpty(bytes);
        return JsonDocument.Parse(bytes);
    }

    // P2D2 — re-derive the canonical future byte total from the actual session facts. This is a
    // second, independent computation on purpose: it must not call the production budget helper,
    // and it needs no SourceKey or signing oracle. All arithmetic is checked so a silent wrap
    // fails the test rather than producing a plausible-looking total.
    private static void AssertRequiredExecutionBudget(
        Session session,
        JsonElement direct,
        string? zeroSlot)
    {
        // Captured GPT: two 64-sector windows per LUN, i.e. 128 sectors of geometry per LUN.
        long gptCaptured = 0;
        foreach (var geometry in session.Backup.Geometries.Values)
        {
            gptCaptured = checked(gptCaptured + checked(128L * Convert.ToInt64(geometry.SectorSize)));
        }

        var bootA = Convert.ToInt64(session.Backup.Files[Role("boot", "a")].Length);
        var bootB = Convert.ToInt64(session.Backup.Files[Role("boot", "b")].Length);
        var misc = session.Backup.Files["misc"];
        var miscLength = Convert.ToInt64(misc.Length);

        // GPT readback + board summary actually retained in this run's evidence artifacts.
        long gptReadback = 0;
        foreach (var region in session.Artifacts.GptWriteRegions)
        {
            gptReadback = checked(gptReadback + Convert.ToInt64(region.Length));
        }

        var boardSummary = Convert.ToInt64(session.Artifacts.BoardSummary.Length);

        // Package contract: the expanded Linux payload sizes actually scheduled by this run.
        var contract = PackageReader.ReadEdlRawContract(
            session.Package.PackageDirectory,
            session.Package.DeviceModel);
        var linuxBootExpanded = Convert.ToInt64(contract.BootImage.ExpandedBytes);
        var linuxRootExpanded = Convert.ToInt64(contract.RootImage.ExpandedBytes);

        // The trailing BCB unit is a whole-sector-rounded 2 KiB write, not the misc capture.
        var miscSectorSize = Convert.ToInt64(misc.SectorSize);
        var bcbUnit = checked((2048L + miscSectorSize - 1) / miscSectorSize * miscSectorSize);

        // Capture + readback for boot/misc, expanded Linux payloads, and the BCB unit.
        var baseFuture = checked(
            gptCaptured
            + bootA + bootB + miscLength
            + gptReadback + boardSummary
            + linuxBootExpanded + linuxRootExpanded
            + bootB + bootA
            + miscLength
            + checked(2L * bcbUnit));

        // One warm-target capture plus one whole-metadata readback per written metadata
        // partition: both slots, or slot a only when slot b is emptied by the run.
        long metadataSum = 0;
        foreach (var prefix in MetadataPrefixes)
        {
            metadataSum = checked(metadataSum + Convert.ToInt64(session.Backup.Files[Role(prefix, "a")].Length));
            if (zeroSlot is null)
            {
                metadataSum = checked(metadataSum + Convert.ToInt64(session.Backup.Files[Role(prefix, "b")].Length));
            }
        }

        var expectedFuture = checked(baseFuture + checked(2L * metadataSum));

        Assert.Equal(
            expectedFuture,
            RequireInt64(direct, "requiredExecutionBytes", "direct"));
    }

    // ---------------------------------------------------------------------------------------
    // Graph assertions
    // ---------------------------------------------------------------------------------------

    private static void VerifySlotDetail(
        Session session,
        JsonElement slotElement,
        string slot,
        string sourceSlot,
        bool nonbootableSystem,
        int metadataNodeCount,
        int preservedMetadataCount,
        string pin)
    {
        var context = $"direct.avbChain.slots[{slot}]";

        Assert.Equal(slot, RequireString(slotElement, "slot", context));
        Assert.Equal(sourceSlot, RequireString(slotElement, "sourceSlot", context));
        Assert.Equal(nonbootableSystem, RequireBool(slotElement, "nonbootableSystem", context));

        var nodes = RequireArray(slotElement, "metadataNodes", context);
        Assert.Equal(metadataNodeCount, nodes.GetArrayLength());

        var nodeRoles = nodes.EnumerateArray()
            .Select(node => RequireString(node, "role", context + ".metadataNodes[]"))
            .ToArray();

        Assert.Equal(nodeRoles.Length, nodeRoles.Distinct(StringComparer.Ordinal).Count());
        if (metadataNodeCount > 0)
        {
            Assert.Equal(
                MetadataRoles(slot).OrderBy(entry => entry, StringComparer.Ordinal),
                nodeRoles.OrderBy(entry => entry, StringComparer.Ordinal));
        }

        foreach (var node in nodes.EnumerateArray())
        {
            VerifyMetadataNode(session, node, slot, pin);
        }

        var preserved = RequireArray(slotElement, "preservedMetadata", context);
        Assert.Equal(preservedMetadataCount, preserved.GetArrayLength());

        var preservedRoles = preserved.EnumerateArray()
            .Select(entry => RequireString(entry, "role", context + ".preservedMetadata[]"))
            .ToArray();

        Assert.Equal(preservedRoles.Length, preservedRoles.Distinct(StringComparer.Ordinal).Count());
        if (preservedMetadataCount > 0)
        {
            Assert.Equal(
                MetadataRoles(slot).OrderBy(entry => entry, StringComparer.Ordinal),
                preservedRoles.OrderBy(entry => entry, StringComparer.Ordinal));
        }

        foreach (var entry in preserved.EnumerateArray())
        {
            VerifyPreservedMetadata(session, entry, slot);
        }
    }

    private static void VerifyMetadataNode(Session session, JsonElement node, string slot, string pin)
    {
        var role = RequireString(node, "role", $"direct.avbChain.slots[{slot}].metadataNodes[]");
        Assert.Contains(role, MetadataRoles(slot));

        var backup = session.Backup.Files[role];
        var context = $"direct.avbChain.slots[{slot}].metadataNodes[{role}]";

        var original = RequireObject(node, "original", context);
        Assert.Equal(Convert.ToInt64(backup.Length), RequireInt64(original, "length", context + ".original"));
        Assert.Equal(backup.Sha256, RequireString(original, "sha256", context + ".original"), ignoreCase: true);

        var candidate = RequireObject(node, "candidate", context);
        Assert.Equal(
            Convert.ToInt64(backup.SectorCount) * Convert.ToInt64(backup.SectorSize),
            RequireInt64(candidate, "length", context + ".candidate"));
        AssertValidSha(RequireString(candidate, "sha256", context + ".candidate"), context + ".candidate.sha256");
        Assert.Equal(pin, RequireString(candidate, "publicKeySha256", context + ".candidate"), ignoreCase: true);

        var target = RequireObject(node, "target", context);
        Assert.Equal(Convert.ToInt64(backup.Lun), RequireInt64(target, "lun", context + ".target"));
        Assert.Equal(Convert.ToInt64(backup.StartSector), RequireInt64(target, "startSector", context + ".target"));
        Assert.Equal(Convert.ToInt64(backup.SectorCount), RequireInt64(target, "sectorCount", context + ".target"));
        Assert.Equal(Convert.ToInt64(backup.SectorSize), RequireInt64(target, "sectorSize", context + ".target"));

        if (string.Equals(role, Role("vbmeta", slot), StringComparison.Ordinal))
        {
            // Root node of the slot chain: exactly the three expected roles, all pinned to the signing key.
            var chainPin = RequireObject(node, "chainPublicKeySha256", context);
            Assert.Equal(ChainPinKeys.Length, chainPin.EnumerateObject().Count());
            foreach (var key in ChainPinKeys)
            {
                Assert.Equal(pin, RequireString(chainPin, key, context + ".chainPublicKeySha256"), ignoreCase: true);
            }
        }
    }

    private static void VerifyPreservedMetadata(Session session, JsonElement entry, string slot)
    {
        var role = RequireString(entry, "role", $"direct.avbChain.slots[{slot}].preservedMetadata[]");
        Assert.Contains(role, MetadataRoles(slot));

        var backup = session.Backup.Files[role];
        var context = $"direct.avbChain.slots[{slot}].preservedMetadata[{role}]";
        var original = RequireObject(entry, "original", context);

        Assert.Equal(Convert.ToInt64(backup.Length), RequireInt64(original, "length", context + ".original"));
        Assert.Equal(backup.Sha256, RequireString(original, "sha256", context + ".original"), ignoreCase: true);
    }

    private static IEnumerable<string> MetadataRoles(string slot)
        => MetadataPrefixes.Select(prefix => Role(prefix, slot));

    private static string Role(string prefix, string slot) => prefix + "_" + slot;

    // ---------------------------------------------------------------------------------------
    // Write assertions
    // ---------------------------------------------------------------------------------------

    private static void AssertBootBaselineWrites(Session session, IReadOnlyList<IB001Write> writes)
    {
        Assert.True(writes.Count >= 9, "the nine baseline writes must still precede the metadata writes");

        var bootB = session.Backup.Files[Role("boot", "b")];
        var bootA = session.Backup.Files[Role("boot", "a")];

        Assert.True(SameRegion(writes[7], bootB), "write #7 must remain the boot_b write");
        Assert.True(SameRegion(writes[8], bootA), "write #8 must remain the boot_a write");
    }

    private static void AssertFinalMiscWrite(Session session, IB001Write write)
    {
        var misc = session.Backup.Files["misc"];
        var miscSectorSize = Convert.ToInt64(misc.SectorSize);
        var expectedSectorCount = (2048L + miscSectorSize - 1) / miscSectorSize;

        // The trailing unit is a one-unit BCB write, not the whole captured misc partition,
        // so the full-partition region check does not apply here.
        Assert.Equal(Convert.ToInt64(misc.Lun), Convert.ToInt64(write.Lun));
        Assert.Equal(Convert.ToInt64(misc.StartSector), Convert.ToInt64(write.StartSector));
        Assert.Equal(expectedSectorCount, Convert.ToInt64(write.SectorCount));
        Assert.Equal(4096L, Convert.ToInt64(write.SectorCount) * miscSectorSize);

        Assert.True(File.Exists(write.FilePath), $"misc write payload not found: {write.FilePath}");
        Assert.Equal(4096L, new FileInfo(write.FilePath).Length);
    }

    private static void VerifyMetadataWrite(
        Session session,
        IB001Write write,
        string role,
        string confirmationCandidateSha)
    {
        var backup = session.Backup.Files[role];
        var fullPartitionLength = Convert.ToInt64(backup.SectorCount) * Convert.ToInt64(backup.SectorSize);

        Assert.True(SameRegion(write, backup), $"{role} write must target the full partition region");
        Assert.Equal(Convert.ToInt64(backup.Lun), Convert.ToInt64(write.Lun));
        Assert.Equal(Convert.ToInt64(backup.StartSector), Convert.ToInt64(write.StartSector));
        Assert.Equal(Convert.ToInt64(backup.SectorCount), Convert.ToInt64(write.SectorCount));

        Assert.True(File.Exists(write.FilePath), $"{role} write payload not found: {write.FilePath}");
        Assert.Equal(fullPartitionLength, new FileInfo(write.FilePath).Length);

        var actualSha = Sha256OfFile(write.FilePath);
        Assert.Equal(actualSha, write.Sha256, ignoreCase: true);
        Assert.Equal(confirmationCandidateSha, write.Sha256, ignoreCase: true);
    }

    private static Dictionary<string, string> ReadCandidateShas(Session session)
    {
        using var document = ReadPreparedConfirmation(session);

        var direct = RequireObject(document.RootElement, "direct", "prepared-confirmation");
        var chain = RequireObject(direct, "avbChain", "prepared-confirmation.direct");

        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var slot in RequireArray(chain, "slots", "direct.avbChain").EnumerateArray())
        {
            foreach (var node in RequireArray(slot, "metadataNodes", "direct.avbChain.slots[]").EnumerateArray())
            {
                var role = RequireString(node, "role", "direct.avbChain.slots[].metadataNodes[]");
                var candidate = RequireObject(node, "candidate", "direct.avbChain.slots[].metadataNodes[]");
                map[role] = RequireString(candidate, "sha256", "direct.avbChain.slots[].metadataNodes[].candidate");
            }
        }

        return map;
    }

    // ---------------------------------------------------------------------------------------
    // Primitives
    // ---------------------------------------------------------------------------------------

    private static bool SameRegion(IB001Write write, EdlCapturedRegion region)
        => Convert.ToInt64(write.Lun) == Convert.ToInt64(region.Lun)
           && Convert.ToInt64(write.StartSector) == Convert.ToInt64(region.StartSector)
           && Convert.ToInt64(write.SectorCount) == Convert.ToInt64(region.SectorCount);

    private static bool SameRegion(IB001Read read, EdlCapturedRegion region)
        => Convert.ToInt64(read.Lun) == Convert.ToInt64(region.Lun)
           && Convert.ToInt64(read.StartSector) == Convert.ToInt64(region.StartSector)
           && Convert.ToInt64(read.SectorCount) == Convert.ToInt64(region.SectorCount);

    private static string Sha256OfFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static void AssertValidSha(string value, string context)
    {
        Assert.False(string.IsNullOrWhiteSpace(value), $"{context} must be a sha256 hex digest");
        Assert.Equal(64, value.Length);
        Assert.All(value, c => Assert.True(Uri.IsHexDigit(c), $"{context} must be hex, got '{value}'"));
    }

    private static JsonElement RequireObject(JsonElement parent, string name, string context)
    {
        Assert.True(parent.TryGetProperty(name, out var value), $"{context}.{name} is missing");
        Assert.Equal(JsonValueKind.Object, value.ValueKind);
        return value;
    }

    private static JsonElement RequireArray(JsonElement parent, string name, string context)
    {
        Assert.True(parent.TryGetProperty(name, out var value), $"{context}.{name} is missing");
        Assert.Equal(JsonValueKind.Array, value.ValueKind);
        return value;
    }

    private static string RequireString(JsonElement parent, string name, string context)
    {
        Assert.True(parent.TryGetProperty(name, out var value), $"{context}.{name} is missing");
        Assert.Equal(JsonValueKind.String, value.ValueKind);
        var text = value.GetString();
        Assert.False(string.IsNullOrWhiteSpace(text), $"{context}.{name} must not be empty");
        return text!;
    }

    private static bool RequireBool(JsonElement parent, string name, string context)
    {
        Assert.True(parent.TryGetProperty(name, out var value), $"{context}.{name} is missing");
        Assert.True(
            value.ValueKind is JsonValueKind.True or JsonValueKind.False,
            $"{context}.{name} must be a boolean");
        return value.GetBoolean();
    }

    private static long RequireInt64(JsonElement parent, string name, string context)
    {
        Assert.True(parent.TryGetProperty(name, out var value), $"{context}.{name} is missing");
        Assert.Equal(JsonValueKind.Number, value.ValueKind);
        Assert.True(value.TryGetInt64(out var number), $"{context}.{name} must be an integer");
        return number;
    }
}
