using System.Collections.Generic;
using System.Text.Json;
using FreedomInstaller.Core.Gbl;

namespace FreedomInstaller.Core;

internal sealed partial class InternalInstallPreparationContext
{
    private void WriteDirectGblConfirmation(Utf8JsonWriter json)
    {
        var plan = RequireDirectGblPlan();
        var inputs = plan.Inputs;
        var selected = inputs.RuntimeSelectedSourceSlot;

        json.WriteString("bootTrustMode", "GblPreserveOem");

        json.WriteStartObject("gbl");
        json.WriteString("runtimeRegion", inputs.RuntimeRegion.ToString());

        json.WriteStartObject("runtimeSelectedAbl");
        WriteGblAblFacts(json, "abl_" + selected, inputs.Sources[selected]);
        json.WriteEndObject();

        json.WriteStartArray("sources");
        foreach (var sourceSlot in SortedKeys(inputs.Sources))
        {
            var evidence = inputs.Sources[sourceSlot];
            json.WriteStartObject();
            WriteGblAblFacts(json, "abl_" + sourceSlot, evidence);
            WriteVerifiedFile(json, "vendorBoot", Claim(BackupFiles, "vendor_boot_" + sourceSlot));
            WriteGblParent(json, "parentBootChain", evidence.ParentBootChain, sourceSlot);
            json.WriteEndObject();
        }
        json.WriteEndArray();

        json.WriteStartObject("efisp");
        WriteVerifiedFile(json, "runtimeAsset", inputs.RuntimeAsset);
        WriteVerifiedFile(json, "candidate", inputs.EfispCandidate);
        WriteVerifiedFile(json, "targetBefore", Claim(BackupFiles, "efisp"));
        WriteGblTarget(json, "target", inputs.EfispTarget);
        json.WriteEndObject();

        json.WriteStartObject("currentXbl");
        json.WriteString("role", plan.CurrentXblRole);
        WriteVerifiedFile(json, "original", plan.CurrentXbl);
        json.WriteString("commonLoaderEvidence", plan.CommonLoaderEvidence);
        json.WriteEndObject();

        json.WriteStartArray("runtimeRawBounds");
        foreach (var target in SlotOrder)
        {
            var wrapper = plan.Boots[target];
            json.WriteStartObject();
            json.WriteString("slot", target);
            json.WriteString("sourceSlot", wrapper.SourceBuiltBoot.SourceSlot);
            json.WriteNumber("packedRawBytes", wrapper.SourceBuiltBoot.PackedRaw.Length);
            json.WriteNumber("maxRawBytes", plan.RuntimeRawBounds[target]);
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteEndObject();

        json.WriteStartArray("slots");
        foreach (var target in SlotOrder)
        {
            var wrapper = plan.Boots[target];
            var built = wrapper.SourceBuiltBoot;
            var sourceSlot = built.SourceSlot;
            var signature = wrapper.OriginalSignatureFacts;

            json.WriteStartObject();
            json.WriteString("slot", target);
            json.WriteString("sourceSlot", sourceSlot);
            json.WriteBoolean("inactiveTargetUninitialized", sourceSlot != target);
            json.WriteBoolean("nonbootableSystem", sourceSlot != target);
            WriteVerifiedFile(json, "candidateBoot", wrapper.EffectiveCandidate);
            WriteVerifiedFile(json, "targetBefore", Claim(BackupFiles, "boot_" + target));
            WriteVerifiedFile(json, "originalBoot", wrapper.OriginalBoot);
            json.WriteNumber("payloadBytes", wrapper.PayloadBytes);
            json.WriteString("payloadSha256", wrapper.PayloadSha256);
            json.WriteNumber("vbmetaOffset", wrapper.VbmetaOffset);
            json.WriteNumber("vbmetaBytes", wrapper.VbmetaBytes);

            json.WriteStartObject("buildIntermediate");
            json.WriteString("bootTrustMode", "AospResigned");
            WriteVerifiedFile(json, "candidateBoot", built.CandidateBoot);
            WriteVerifiedFile(json, "packedRaw", built.PackedRaw);
            WriteVerifiedFile(json, "verificationReport", built.VerificationReport);
            json.WritePropertyName("facts");
            WriteDirectSlot(json, built);
            json.WriteEndObject();

            json.WriteStartObject("originalSignature");
            json.WriteString("signedVbmetaSha256", signature.SignedVbmetaSha256);
            json.WriteString("publicKeySha256", signature.PublicKeySha256);
            json.WriteNumber("algorithmType", signature.AlgorithmType);
            json.WriteNumber("rollbackIndex", signature.RollbackIndex);
            json.WriteNumber("rollbackIndexLocation", signature.RollbackIndexLocation);
            json.WriteNumber("flags", signature.Flags);
            json.WriteNumber("requiredMajor", signature.RequiredMajor);
            json.WriteNumber("requiredMinor", signature.RequiredMinor);
            json.WriteNumber("signedContentBytes", signature.SignedContentBytes);
            json.WriteString("signedContentDigestHex", signature.SignedContentDigestHex);
            json.WriteString("effectiveContentDigestHex", signature.EffectiveContentDigestHex);
            json.WriteBoolean("originalSignatureValid", signature.OriginalSignatureValid);
            json.WriteBoolean("contentDigestMatches", signature.ContentDigestMatches);
            json.WriteEndObject();

            WriteGblParent(json, "parentBootChain", inputs.Sources[sourceSlot].ParentBootChain, sourceSlot);

            json.WriteStartArray("preservedMetadata");
            foreach (var prefix in new[] { "recovery", "vbmeta_system", "vbmeta" })
            {
                var role = prefix + "_" + target;
                json.WriteStartObject();
                json.WriteString("role", role);
                WriteVerifiedFile(json, "original", Claim(BackupFiles, role));
                json.WriteEndObject();
            }
            json.WriteEndArray();

            json.WriteEndObject();
        }
        json.WriteEndArray();
    }

    private static void WriteGblAblFacts(Utf8JsonWriter json, string role, GblSourceEvidence evidence)
    {
        json.WriteString("role", role);
        json.WriteString("sourceSlot", evidence.SourceSlot);
        WriteVerifiedFile(json, "original", evidence.Abl);
        json.WriteString("decodedPeSha256", evidence.PeSha256);
        WriteGblDetector(json, "detector", evidence.Entry);
    }

    private static void WriteGblDetector(Utf8JsonWriter json, string name, DetectionResult entry)
    {
        json.WriteStartObject(name);
        json.WriteString("status", entry.Status.ToString());
        json.WriteString("reason", entry.Reason);
        WriteGblRvas(json, "efispMarkerRvas", entry.EfispMarkerRvas);
        WriteGblRvas(json, "loadMarkerRvas", entry.LoadMarkerRvas);
        WriteGblRvas(json, "startMarkerRvas", entry.StartMarkerRvas);
        WriteGblRvas(json, "secureBootMarkerRvas", entry.SecureBootMarkerRvas);
        WriteGblRvas(json, "efispXrefRvas", entry.EfispXrefRvas);
        WriteGblRvas(json, "loadXrefRvas", entry.LoadXrefRvas);
        WriteGblRvas(json, "startXrefRvas", entry.StartXrefRvas);
        WriteGblRvas(json, "secureBootXrefRvas", entry.SecureBootXrefRvas);
        if (entry.SelectedChain is { } chain)
        {
            json.WriteStartObject("selectedChain");
            json.WriteNumber("firstRva", chain.FirstRva);
            json.WriteNumber("lastRva", chain.LastRva);
            json.WriteNumber("span", chain.Span);
            json.WriteEndObject();
        }
        json.WriteEndObject();
    }

    private static void WriteGblRvas(Utf8JsonWriter json, string name, IReadOnlyList<long> values)
    {
        json.WriteStartArray(name);
        foreach (long value in values)
        {
            json.WriteNumberValue(value);
        }
        json.WriteEndArray();
    }

    private static void WriteGblParent(
        Utf8JsonWriter json,
        string name,
        EdlRawOriginalBootChainFacts parent,
        string sourceSlot)
    {
        json.WriteStartObject(name);
        WriteVerifiedFile(json, "original", parent.Original);
        json.WriteString("sourceSlot", sourceSlot);
        json.WriteString("signedVbmetaSha256", parent.SignedVbmetaSha256);
        json.WriteString("publicKeySha256", parent.PublicKeySha256);
        json.WriteString("bootChainPublicKeySha256", parent.BootChainPublicKeySha256);
        json.WriteEndObject();
    }

    private static void WriteGblTarget(Utf8JsonWriter json, string name, EdlCapturedRegion region)
    {
        json.WriteStartObject(name);
        json.WriteString("role", region.Role);
        json.WriteNumber("lun", region.Lun);
        json.WriteNumber("startSector", region.StartSector);
        json.WriteNumber("sectorCount", region.SectorCount);
        json.WriteNumber("sectorSize", region.SectorSize);
        json.WriteString("partUuid", region.PartUuid);
        json.WriteEndObject();
    }
}
