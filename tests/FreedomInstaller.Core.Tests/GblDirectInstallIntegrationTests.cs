using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace FreedomInstaller.Core.Tests;

// ---------------------------------------------------------------------------------------------
// F4a.a2 -- test-only. Both classes drive the real production session; nothing here fabricates a
// check, a "ready" verdict, a plan, or a prepared set. The only reflection used is the public
// BootTrustMode read, which is written so this file compiles before that member lands.
// ---------------------------------------------------------------------------------------------

/// <summary>
/// Proves the shared session factory still composes the real G5 material inside the GBL integration
/// file: the actual capture, the real toolchain identity, and a truthful (not simulated) backup.
/// This class must be green before any GBL assertion in this file is trusted.
/// </summary>
public sealed class GblFixtureFactorySmokeTests
    : IClassFixture<Gen5EdlToolchainFixture>, IClassFixture<EdlRawSharedInput>
{
    private const string G5Model = "TB323FU";

    /// <summary>The confirmed fastboot lock fact: unlocked, independent of any bootloader read.</summary>
    private const BootloaderState ConfirmedUnlocked = BootloaderState.Unlocked;

    private readonly Gen5EdlToolchainFixture _g5;

    private readonly EdlRawSharedInput _raw;

    public GblFixtureFactorySmokeTests(Gen5EdlToolchainFixture g5, EdlRawSharedInput raw)
    {
        _g5 = g5;
        _raw = raw;
    }

    [Theory]
    [InlineData(false, 49)]
    [InlineData(true, 48)]
    public async Task UnlockedG5_UsesRealFactoryAndTruthfulBackup(bool omitEfispBackup, int expectedBackupFiles)
    {
        // Source first, session second: the session is disposed first, the source last.
        using GblDirectSourceFixture source = new(region: "PRC");
        using DirectInstallReadyTestSession session = await DirectInstallReadyTestSession.CreateAsync(
            _g5.Toolchain,
            _raw,
            avbSourceKind: DirectAvbSourceKind.Oem,
            observedFastbootLockState: ConfirmedUnlocked,
            gblSources: source,
            omitEfispBackup: omitEfispBackup);

        Assert.NotNull(session.Backend.Prepared);
        Assert.Equal(G5Model, session.Toolchain.Model);
        Assert.Equal(expectedBackupFiles, session.Backup.Files.Count);

        // The capture is the real one: its EFISP claim tracks the truth of this call, not the device.
        Assert.Equal(!omitEfispBackup, session.Backup.Files.ContainsKey("efisp"));

        // The device's own GPT keeps exactly one EFISP partition even when the backup went legacy.
        var specs = session.Device.Specs(4);
        Assert.Single(specs.Where(spec => spec.Name == "efisp"));

        Assert.Equal(6, session.NativeCommandCount);
        Assert.Empty(session.EdlRunner.Writes);
        Assert.Equal(0, session.EdlRunner.ResetCount);

        // The two principals are genuinely independent, so a later parent/child mix-up shows up.
        Assert.False(
            string.Equals(
                source.ParentPublicKeySha256,
                source.BootChildPublicKeySha256,
                StringComparison.OrdinalIgnoreCase),
            "the fixture's parent and boot-child principals must differ");
    }
}

/// <summary>
/// F4a.a2 -- the real Locked/OEM direct preparation: one typed GBL-preserving plan, distinct
/// parent and boot-child principals, and the measured EFISP/vbmeta evidence the plan is built on.
/// </summary>
public sealed class GblDirectInstallIntegrationTests
    : IClassFixture<Gen5EdlToolchainFixture>, IClassFixture<EdlRawSharedInput>
{
    private const string G5Model = "TB323FU";

    /// <summary>The confirmed fastboot lock fact: locked, independent of any bootloader read.</summary>
    private const BootloaderState ConfirmedLocked = BootloaderState.Locked;

    /// <summary>The one boot-trust mode this file asserts; never a "complete" or hardware claim.</summary>
    private const string PreserveOemBootTrustMode = "GblPreserveOem";

    private const long EfispRuntimeAssetLength = 282624;

    private const string PrcEfispRuntimeAssetSha256 =
        "B91DB7974DA80976BC73ADD671F4ADFB833AEA4FD0D9D7604B75CB63415FED84";

    private const string RowEfispRuntimeAssetSha256 =
        "E21F6D5FFE29113943092AC4A2A75E4FA03960831CC8855316C784B472999ABD";

    private readonly Gen5EdlToolchainFixture _g5;

    private readonly EdlRawSharedInput _raw;

    public GblDirectInstallIntegrationTests(Gen5EdlToolchainFixture g5, EdlRawSharedInput raw)
    {
        _g5 = g5;
        _raw = raw;
    }

    [Theory]
    [InlineData("PRC", "Prc", PrcEfispRuntimeAssetSha256)]
    [InlineData("ROW", "Row", RowEfispRuntimeAssetSha256)]
    public async Task LockedOem_UsesTypedGblPlanAndDistinctParentChildKeys(
        string region,
        string expectedRuntimeRegion,
        string expectedEfispRuntimeAssetSha256)
    {
        using GblDirectSourceFixture source = new(region: region);
        using DirectInstallReadyTestSession session = await DirectInstallReadyTestSession.CreateAsync(
            _g5.Toolchain,
            _raw,
            avbSourceKind: DirectAvbSourceKind.Oem,
            observedFastbootLockState: ConfirmedLocked,
            gblSources: source);

        var prepared = session.Backend.Prepared;
        Assert.NotNull(prepared);
        Assert.Equal(G5Model, session.Toolchain.Model);

        // Public, typed boot-trust mode -- read by reflection so this file compiles today.
        PropertyInfo bootTrustMode = prepared!.GetType().GetProperty(
                "BootTrustMode",
                BindingFlags.Public | BindingFlags.Instance)
            ?? throw new Xunit.Sdk.XunitException("the prepared set must expose a public BootTrustMode");
        Assert.True(bootTrustMode.PropertyType.IsEnum, "BootTrustMode must be an enum");
        Assert.Equal(PreserveOemBootTrustMode, bootTrustMode.GetValue(prepared)?.ToString());

        using JsonDocument confirmation = ReadConfirmation(session);
        var direct = RequireObject(confirmation.RootElement, "direct", "prepared-confirmation");

        Assert.Equal(
            PreserveOemBootTrustMode,
            RequireString(direct, "bootTrustMode", "direct"));
        Assert.Equal(
            expectedRuntimeRegion,
            RequireString(RequireObject(direct, "gbl", "direct"), "runtimeRegion", "direct.gbl"));

        AssertEfispEvidence(direct, session, expectedEfispRuntimeAssetSha256);
        AssertSlots(direct, session, source);

        // The plan never executed anything: one native composition, no device write, no reset.
        Assert.Equal(6, session.NativeCommandCount);
        Assert.Empty(session.EdlRunner.Writes);
        Assert.Equal(0, session.EdlRunner.ResetCount);
    }

    // -----------------------------------------------------------------------------------------
    // Claims
    // -----------------------------------------------------------------------------------------

    private static void AssertEfispEvidence(
        JsonElement direct,
        DirectInstallReadyTestSession session,
        string expectedRuntimeAssetSha256)
    {
        Assert.True(
            session.Backup.Files.TryGetValue("efisp", out var liveEfisp),
            "the real capture must carry its EFISP claim");

        var efisp = RequireObject(
            RequireObject(direct, "gbl", "direct"),
            "efisp",
            "direct.gbl");

        var candidate = RequireObject(efisp, "candidate", "direct.gbl.efisp");
        Assert.Equal((long)liveEfisp.Length, RequireInt(candidate, "length", "direct.gbl.efisp.candidate"));

        var runtimeAsset = RequireObject(efisp, "runtimeAsset", "direct.gbl.efisp");
        Assert.Equal(
            EfispRuntimeAssetLength,
            RequireInt(runtimeAsset, "length", "direct.gbl.efisp.runtimeAsset"));
        AssertSame(
            expectedRuntimeAssetSha256,
            RequireString(runtimeAsset, "sha256", "direct.gbl.efisp.runtimeAsset"),
            "direct.gbl.efisp.runtimeAsset.sha256");

        var targetBefore = RequireObject(efisp, "targetBefore", "direct.gbl.efisp");
        AssertSame(
            liveEfisp.Sha256,
            RequireString(targetBefore, "sha256", "direct.gbl.efisp.targetBefore"),
            "direct.gbl.efisp.targetBefore.sha256");
    }

    private static void AssertSlots(
        JsonElement direct,
        DirectInstallReadyTestSession session,
        GblDirectSourceFixture source)
    {
        var slots = RequireArray(direct, "slots", "direct");
        Assert.Equal(2, slots.GetArrayLength());

        var seen = new List<string>();
        foreach (JsonElement slotElement in slots.EnumerateArray())
        {
            string slot = RequireString(slotElement, "slot", "direct.slots[]");
            Assert.True(slot is "a" or "b", $"unexpected slot '{slot}'");
            Assert.True(
                string.Equals(
                    slot,
                    RequireString(slotElement, "sourceSlot", "direct.slots[]"),
                    StringComparison.Ordinal),
                "slot and sourceSlot must name the same factory slot");
            Assert.DoesNotContain(seen, existing => string.Equals(existing, slot, StringComparison.Ordinal));
            seen.Add(slot);

            AssertSlotSignature(slotElement, slot, session, source);
            AssertSlotBoot(slotElement, slot, session);
            AssertSlotMetadata(slotElement, slot, session);
        }

        Assert.Equal(2, seen.Count);
        Assert.Contains("a", seen);
        Assert.Contains("b", seen);
    }

    private static void AssertSlotSignature(
        JsonElement slotElement,
        string slot,
        DirectInstallReadyTestSession session,
        GblDirectSourceFixture source)
    {
        var originalSignature = RequireObject(slotElement, "originalSignature", "direct.slots[]");

        Assert.True(RequireBool(
            originalSignature,
            "originalSignatureValid",
            "direct.slots[].originalSignature"));
        Assert.False(RequireBool(
            originalSignature,
            "contentDigestMatches",
            "direct.slots[].originalSignature"));

        // The original root really is signed by the parent; its boot leaf is the child.
        AssertSame(
            source.BootChildPublicKeySha256,
            RequireString(originalSignature, "publicKeySha256", "direct.slots[].originalSignature"),
            "direct.slots[].originalSignature.publicKeySha256");

        string signedVbmeta = RequireString(
            originalSignature,
            "signedVbmetaSha256",
            "direct.slots[].originalSignature");
        Assert.Equal(64, signedVbmeta.Length);
        Assert.All(signedVbmeta, c => Assert.True(Uri.IsHexDigit(c), "signedVbmetaSha256 must be hex"));

        var parentBootChain = RequireObject(slotElement, "parentBootChain", "direct.slots[]");
        string parentKey = RequireString(parentBootChain, "publicKeySha256", "direct.slots[].parentBootChain");
        AssertSame(source.ParentPublicKeySha256, parentKey, "direct.slots[].parentBootChain.publicKeySha256");
        Assert.False(
            string.Equals(
                parentKey,
                RequireString(originalSignature, "publicKeySha256", "direct.slots[].originalSignature"),
                StringComparison.OrdinalIgnoreCase),
            "the parent principal must differ from the boot child");

        AssertSame(
            source.BootChildPublicKeySha256,
            RequireString(
                parentBootChain,
                "bootChainPublicKeySha256",
                "direct.slots[].parentBootChain"),
            "direct.slots[].parentBootChain.bootChainPublicKeySha256");

        var vbmeta = session.Backup.Files[$"vbmeta_{slot}"];
        AssertSame(
            vbmeta.Sha256,
            RequireString(
                RequireObject(parentBootChain, "original", "direct.slots[].parentBootChain"),
                "sha256",
                "direct.slots[].parentBootChain.original"),
            "direct.slots[].parentBootChain.original.sha256");
    }

    private static void AssertSlotBoot(
        JsonElement slotElement,
        string slot,
        DirectInstallReadyTestSession session)
    {
        var candidateBoot = RequireObject(slotElement, "candidateBoot", "direct.slots[]");
        var intermediate = RequireObject(
            RequireObject(slotElement, "buildIntermediate", "direct.slots[]"),
            "candidateBoot",
            "direct.slots[].buildIntermediate");

        string candidateSha = RequireString(candidateBoot, "sha256", "direct.slots[].candidateBoot");
        string intermediateSha = RequireString(
            intermediate,
            "sha256",
            "direct.slots[].buildIntermediate.candidateBoot");
        Assert.False(
            string.Equals(candidateSha, intermediateSha, StringComparison.OrdinalIgnoreCase),
            "the signed candidate boot must not equal the AOSP build intermediate");

        var targetBoot = session.Backup.Files[$"boot_{slot}"];
        Assert.Equal(
            (long)targetBoot.Length,
            RequireInt(candidateBoot, "length", "direct.slots[].candidateBoot"));
    }

    private static void AssertSlotMetadata(
        JsonElement slotElement,
        string slot,
        DirectInstallReadyTestSession session)
    {
        var preserved = RequireArray(slotElement, "preservedMetadata", "direct.slots[]");
        Assert.Equal(3, preserved.GetArrayLength());

        var claimed = new List<string>();
        foreach (JsonElement entry in preserved.EnumerateArray())
        {
            string role = RequireString(entry, "role", "direct.slots[].preservedMetadata[]");
            claimed.Add(role);

            var original = session.Backup.Files[role];
            var ownOriginal = RequireObject(entry, "original", "direct.slots[].preservedMetadata[]");
            Assert.Equal(
                (long)original.Length,
                RequireInt(ownOriginal, "length", "direct.slots[].preservedMetadata[].original"));
            AssertSame(
                original.Sha256,
                RequireString(ownOriginal, "sha256", "direct.slots[].preservedMetadata[].original"),
                "direct.slots[].preservedMetadata[].original.sha256");
        }

        Assert.Equal(3, claimed.Distinct(StringComparer.Ordinal).Count());
        Assert.Contains($"recovery_{slot}", claimed);
        Assert.Contains($"vbmeta_system_{slot}", claimed);
        Assert.Contains($"vbmeta_{slot}", claimed);
    }

    // -----------------------------------------------------------------------------------------
    // Shared JSON primitives (reusable by the cases added later in this same file)
    // -----------------------------------------------------------------------------------------

    /// <summary>Reads the confirmation file the real preparation wrote into its own evidence directory.</summary>
    internal static JsonDocument ReadConfirmation(DirectInstallReadyTestSession session)
    {
        string path = Path.Combine(session.Backend.Prepared.EvidenceDirectory, "prepared-confirmation.json");
        Assert.True(File.Exists(path), $"{path} must exist");
        return JsonDocument.Parse(File.ReadAllBytes(path));
    }

    private static JsonElement RequireObject(JsonElement parent, string name, string context)
        => RequireKind(parent, name, context, JsonValueKind.Object);

    private static JsonElement RequireArray(JsonElement parent, string name, string context)
        => RequireKind(parent, name, context, JsonValueKind.Array);

    private static JsonElement RequireKind(
        JsonElement parent,
        string name,
        string context,
        JsonValueKind kind)
    {
        Assert.True(parent.TryGetProperty(name, out JsonElement value), $"{context}.{name} is missing");
        Assert.Equal(kind, value.ValueKind);
        return value;
    }

    private static string RequireString(JsonElement parent, string name, string context)
    {
        Assert.True(parent.TryGetProperty(name, out JsonElement value), $"{context}.{name} is missing");
        Assert.Equal(JsonValueKind.String, value.ValueKind);
        string? text = value.GetString();
        Assert.False(string.IsNullOrWhiteSpace(text), $"{context}.{name} must not be empty");
        return text!;
    }

    private static bool RequireBool(JsonElement parent, string name, string context)
    {
        Assert.True(parent.TryGetProperty(name, out JsonElement value), $"{context}.{name} is missing");
        Assert.True(
            value.ValueKind is JsonValueKind.True or JsonValueKind.False,
            $"{context}.{name} must be a boolean");
        return value.GetBoolean();
    }

    private static long RequireInt(JsonElement parent, string name, string context)
    {
        Assert.True(parent.TryGetProperty(name, out JsonElement value), $"{context}.{name} is missing");
        Assert.Equal(JsonValueKind.Number, value.ValueKind);
        Assert.True(value.TryGetInt64(out long number), $"{context}.{name} must be an integer");
        return number;
    }

    /// <summary>Digest equality is case-insensitive: the backup is lowercase, the plan may not be.</summary>
    private static void AssertSame(string expected, string actual, string context)
    {
        Assert.True(
            string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase),
            $"{context}: expected '{expected}', got '{actual}'");
    }
}
