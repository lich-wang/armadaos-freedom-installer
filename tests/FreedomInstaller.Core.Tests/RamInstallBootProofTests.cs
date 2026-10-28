using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Focused coverage for RH004A: the read-only inspect source catalog and the cross-validated build
/// proof. All fixtures are synthetic metadata; no device, sysfs or partition byte is read. Tests are
/// authored, not run here.
/// </summary>
public sealed class RamInstallBootProofTests
{
    private const long MaterialLength = Rh003TestData.DefaultMaterialLength;

    private const string ExactLoaderProfile = "tb322fc-abl259-xbl-config-ramdisk-derived";
    private const string StructuralLoaderProfile = "tb322fc-abl-kernel-region-derived";

    [Fact]
    public async Task GetBuiltBoots_ReturnsFourImmutableRolesAndRetainsTheFullReport()
    {
        RamInstallRequest request = Rh004TestData.CreateRequest();
        Rh004Proof proof = Rh004TestData.CreateProof(request);
        var console = Rh004TestData.CreateConsole(request, proof);
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        await client.InitializeAsync();
        Assert.NotNull(client.BootSourceCatalog);

        RamInstallBuiltBoots built = await client.GetBuiltBootsAsync();

        Assert.Equal(Rh002TestData.SeedCommit, built.DeploymentChecksum);
        Assert.Equal(Rh004TestData.PrepareBootFs, built.BootFilesystemUuid);
        Assert.Equal(Rh004TestData.PrepareRootFs, built.RootFilesystemUuid);

        Assert.Equal("a", built.Slots.A.Slot);
        Assert.Equal(RamInstallExportRole.BootA, built.Slots.A.Candidate.Role);
        Assert.Equal(MaterialLength, built.Slots.A.Candidate.Length);
        Assert.Equal(Rh004TestData.CandidateShaA, built.Slots.A.Candidate.Sha256);
        Assert.Equal(RamInstallExportRole.ReportA, built.Slots.A.Report.Role);
        Assert.Equal(Rh004TestData.ReportShaA, built.Slots.A.Report.Sha256);

        Assert.Equal("b", built.Slots.B.Slot);
        Assert.Equal(RamInstallExportRole.BootB, built.Slots.B.Candidate.Role);
        Assert.Equal(Rh004TestData.CandidateShaB, built.Slots.B.Candidate.Sha256);
        Assert.Equal(RamInstallExportRole.ReportB, built.Slots.B.Report.Role);
        Assert.Equal(Rh004TestData.ReportShaB, built.Slots.B.Report.Sha256);

        Assert.Same(built.Slots.A.Candidate, built.GetArtifact(RamInstallExportRole.BootA));
        Assert.Same(built.Slots.B.Candidate, built.GetArtifact(RamInstallExportRole.BootB));
        Assert.Same(built.Slots.A.Report, built.GetArtifact(RamInstallExportRole.ReportA));
        Assert.Same(built.Slots.B.Report, built.GetArtifact(RamInstallExportRole.ReportB));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => built.GetArtifact((RamInstallExportRole)99));

        JsonElement report = built.Slots.A.BuilderReport;
        Assert.Equal(JsonValueKind.Object, report.ValueKind);
        Assert.True(report.GetProperty("offline_verified").GetBoolean());
        Assert.Equal("installed", report.GetProperty("layout_mode").GetString());
        Assert.Equal("android", report.GetProperty("default_entry").GetString());
        Assert.Equal(0, report.GetProperty("default_index").GetInt32());
        Assert.Equal(JsonValueKind.Object, report.GetProperty("slot_material").ValueKind);
        Assert.Equal(JsonValueKind.Object, report.GetProperty("loader_budget").ValueKind);

        Assert.Equal(1, Rh004TestData.Count(console, "status --action prepare"));
        Assert.Equal(1, Rh004TestData.Count(console, "status --action deploy"));
        Assert.Equal(1, Rh004TestData.Count(console, "status --action build-boots"));
        Assert.Equal(0, Rh004TestData.Count(console, "armada_install.py build-boots --token"));

        RamInstallBuiltBoots again = await client.GetBuiltBootsAsync();
        Assert.Same(built, again);
        Assert.Equal(1, Rh004TestData.Count(console, "status --action build-boots"));
    }

    [Fact]
    public async Task WrongDeploymentChecksum_IsRejected()
    {
        RamInstallRequest request = Rh004TestData.CreateRequest();
        Rh004Proof proof = Rh004TestData.CreateProof(request);
        proof.Build["deploymentChecksum"] = new string('d', 64);

        await AssertRejectedAsync(request, proof);
    }

    [Fact]
    public async Task FilesystemUuidConfusedWithPartUuid_IsRejected()
    {
        RamInstallRequest request = Rh004TestData.CreateRequest();
        Rh004Proof proof = Rh004TestData.CreateProof(request);
        proof.Deploy["filesystem_uuids"]!.AsObject()["boot"] = Rh002TestData.BootUuid;

        await AssertRejectedAsync(request, proof);

        Rh004Proof buildSide = Rh004TestData.CreateProof(request);
        buildSide.Build["filesystemUuids"]!.AsObject()["root"] = Rh002TestData.RootUuid;
        await AssertRejectedAsync(request, buildSide);
    }

    [Fact]
    public async Task SlotBSourceUsingSlotAMaterial_IsRejected()
    {
        var boot = new RamInstallBootConfig(
            Rh003TestData.CreateSlot("a", MaterialLength, new string('a', 64)),
            Rh003TestData.CreateSlot("b", MaterialLength, new string('b', 64)),
            Rh003TestData.RuntimeIdentity(),
            Rh003TestData.LinuxArtifacts());
        RamInstallRequest request = Rh003TestData.CreateRequest(boot);
        Rh004Proof proof = Rh004TestData.CreateProof(request);
        proof.BuildSlotMaterial("b")["source_sha256"]!.AsObject()["current_boot"] = new string('a', 64);

        await AssertRejectedAsync(request, proof);
    }

    [Fact]
    public async Task SourceLengthMismatch_IsRejected()
    {
        RamInstallRequest request = Rh004TestData.CreateRequest();
        Rh004Proof proof = Rh004TestData.CreateProof(request);
        proof.BuildSlotMaterial("b")["source_lengths"]!.AsObject()["abl"] = MaterialLength - 1;

        await AssertRejectedAsync(request, proof);
    }

    [Fact]
    public async Task BaseImageMustEqualTheStockImage()
    {
        RamInstallRequest request = Rh004TestData.CreateRequest();
        Rh004Proof proof = Rh004TestData.CreateProof(request);
        proof.BuildSlotMaterial("a")["base_image"]!.AsObject()["sha256"] = new string('8', 64);

        await AssertRejectedAsync(request, proof);
    }

    [Fact]
    public async Task TopLoaderBudgetMustEqualTheSlotMaterialBudget()
    {
        RamInstallRequest request = Rh004TestData.CreateRequest();
        Rh004Proof proof = Rh004TestData.CreateProof(request);
        proof.BuildReport("a")["loader_budget"]!.AsObject()["page_size"] = 8192L;

        await AssertRejectedAsync(request, proof);
    }

    [Fact]
    public async Task UnknownLoaderMustUseTheConservative128MiBLimit()
    {
        RamInstallRequest request = Rh004TestData.CreateRequest();
        Rh004Proof proof = Rh004TestData.CreateProof(request);
        proof.BuildBudget("a")["max_raw_bytes"] = 134217729L;

        await AssertRejectedAsync(request, proof);
    }

    [Theory]
    [InlineData(ExactLoaderProfile)]
    [InlineData(StructuralLoaderProfile)]
    public async Task KnownLoaderBudgetMustBeTheExactDerivedRawLimit(string profile)
    {
        RamInstallRequest request = Rh004TestData.CreateRequest();

        Rh004Proof accepted = ConfigureKnownLoaderA(Rh004TestData.CreateProof(request), profile);
        var acceptedConsole = Rh004TestData.CreateConsole(request, accepted);
        var acceptedClient = new RamInstallClient(
            Rh002TestData.CreateSession(acceptedConsole),
            request);
        await acceptedClient.InitializeAsync();
        RamInstallBuiltBoots built = await acceptedClient.GetBuiltBootsAsync();
        Assert.Equal(
            265801728L,
            built.Slots.A.BuilderReport.GetProperty("loader_budget")
                .GetProperty("max_raw_bytes").GetInt64());

        // The one-byte change is applied identically to the module and the top-level budget, so the
        // rejection below can only come from the known-profile formula, not from a budget inequality.
        Rh004Proof tampered = ConfigureKnownLoaderA(Rh004TestData.CreateProof(request), profile);
        tampered.BuildBudget("a")["max_raw_bytes"] = 265801729L;
        tampered.BuildReport("a")["loader_budget"]!.AsObject()["max_raw_bytes"] = 265801729L;

        var tamperedConsole = Rh004TestData.CreateConsole(request, tampered);
        var tamperedClient = new RamInstallClient(
            Rh002TestData.CreateSession(tamperedConsole),
            request);
        await tamperedClient.InitializeAsync();
        await Assert.ThrowsAsync<MaintenanceException>(() => tamperedClient.GetBuiltBootsAsync());
    }

    [Theory]
    [InlineData(ExactLoaderProfile)]
    [InlineData(StructuralLoaderProfile)]
    public async Task KnownLoaderProfileAndBooleanMustAgree(string profile)
    {
        RamInstallRequest request = Rh004TestData.CreateRequest();

        Rh004Proof knownFalseProfile = Rh004TestData.CreateProof(request);
        knownFalseProfile.BuildBudget("a")["profile"] = profile;
        await AssertRejectedAsync(request, knownFalseProfile);

        Rh004Proof knownTrueConservative = Rh004TestData.CreateProof(request);
        knownTrueConservative.BuildBudget("a")["known_loader_match"] = true;
        await AssertRejectedAsync(request, knownTrueConservative);

        // known=true is never sufficient on its own: the profile still has to be one of the two
        // reviewed identities, even with the exact derived budget attached.
        Rh004Proof knownTrueUnreviewed = ConfigureKnownLoaderA(
            Rh004TestData.CreateProof(request), profile + "-not-reviewed");
        await AssertRejectedAsync(request, knownTrueUnreviewed);
    }

    [Theory]
    [InlineData("abl_sha256", "0000000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("xbl_config_sha256", "5555555555555555555555555555555555555555555555555555555555555555")]
    [InlineData("abl_bytes", 4097L)]
    [InlineData("xbl_config_bytes", 4097L)]
    public async Task StructuralLoaderProfileStillBindsTheFrozenMaterialIdentity(
        string field, object value)
    {
        RamInstallRequest request = Rh004TestData.CreateRequest();
        Rh004Proof proof = ConfigureKnownLoaderA(
            Rh004TestData.CreateProof(request), StructuralLoaderProfile);

        JsonObject slotMaterial = proof.BuildSlotMaterial("a");
        JsonObject frozenSha = slotMaterial["source_sha256"]!.AsObject();
        JsonObject frozenLengths = slotMaterial["source_lengths"]!.AsObject();
        string frozenAblSha = frozenSha["abl"]!.GetValue<string>();
        long frozenAblLength = frozenLengths["abl"]!.GetValue<long>();

        JsonObject module = proof.BuildBudget("a");
        JsonObject top = proof.BuildReport("a")["loader_budget"]!.AsObject();
        Assert.NotSame(module, top);
        module[field] = ToNode(value);
        top[field] = ToNode(value);

        // The frozen same-slot material is deliberately untouched: only the two budget objects move.
        Assert.Equal(frozenAblSha, frozenSha["abl"]!.GetValue<string>());
        Assert.Equal(frozenAblLength, frozenLengths["abl"]!.GetValue<long>());

        await AssertRejectedAsync(request, proof);

        static JsonNode? ToNode(object candidate) => candidate switch
        {
            string text => JsonValue.Create(text),
            long number => JsonValue.Create(number),
            _ => throw new ArgumentOutOfRangeException(nameof(candidate)),
        };
    }

    private static Rh004Proof ConfigureKnownLoaderA(Rh004Proof proof, string profile)
    {
        JsonObject ramdisks = proof.BuildSlotMaterial("a")["ramdisks"]!.AsObject();
        ramdisks["boot_ramdisk_size"] = 1L;
        ramdisks["total_ramdisk_size"] = 1L;

        JsonObject budget = proof.BuildBudget("a");
        budget["profile"] = profile;
        budget["known_loader_match"] = true;
        budget["total_ramdisk_bytes"] = 1L;

        // 268435456 - 524288 - align_up(1, 4096) - 8192 - 2097152: the external expected number is
        // written out literally and is not recomputed from the implementation under test.
        budget["max_raw_bytes"] = 265801728L;

        proof.BuildReport("a")["loader_budget"] = budget.DeepClone();
        return proof;
    }

    [Fact]
    public async Task CandidateLengthMustMatchTheFrozenPartitionLength()
    {
        RamInstallRequest request = Rh004TestData.CreateRequest();
        Rh004Proof proof = Rh004TestData.CreateProof(request);
        proof.Build["slots"]!.AsObject()["a"]!.AsObject()["candidate"]!.AsObject()["length"] =
            MaterialLength - 1;

        await AssertRejectedAsync(request, proof);
    }

    [Fact]
    public async Task ReportFlagsScopeAndOutputAreEachEnforced()
    {
        RamInstallRequest request = Rh004TestData.CreateRequest();

        await AssertReportMutationRejectedAsync(request, report => report["offline_verified"] = false);
        await AssertReportMutationRejectedAsync(request, report => report["layout_mode"] = "partition");
        await AssertReportMutationRejectedAsync(request, report => report["default_entry"] = "linux");
        await AssertReportMutationRejectedAsync(
            request,
            report => report["slot_material"]!.AsObject()["oem_signed_restored"] = true);
        await AssertReportMutationRejectedAsync(
            request,
            report => report["slot_material"]!.AsObject()["signature_verification_performed"] = true);
        await AssertReportMutationRejectedAsync(
            request,
            report => report["slot_material"]!.AsObject()["recovery_scope"] = "android-arm64");
        await AssertReportMutationRejectedAsync(
            request,
            report => report["outputs"]!.AsObject()["final_boot"]!.AsObject()["sha256"] =
                new string('5', 64));
        await AssertReportMutationRejectedAsync(
            request,
            report => report["outputs"]!.AsObject()["final_boot"]!.AsObject()["length"] =
                MaterialLength - 1);
        await AssertReportMutationRejectedAsync(
            request,
            report => report["slot_material"]!.AsObject()["slot"] = "b");
        await AssertReportMutationRejectedAsync(
            request,
            report => report["slot_material"]!.AsObject()["source_sha256"]!.AsObject()["extra"] =
                new string('5', 64));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("null")]
    [InlineData("string")]
    [InlineData("fractional")]
    [InlineData("otherinteger")]
    public async Task DefaultIndexMustBeTheIntegerZero(string kind)
    {
        RamInstallRequest request = Rh004TestData.CreateRequest();

        await AssertReportMutationRejectedAsync(request, report =>
        {
            switch (kind)
            {
                case "missing":
                    report.Remove("default_index");
                    break;
                case "null":
                    report["default_index"] = null;
                    break;
                case "string":
                    report["default_index"] = "0";
                    break;
                case "fractional":
                    report["default_index"] = 0.5;
                    break;
                case "otherinteger":
                    report["default_index"] = 1;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(kind));
            }
        });
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("duplicate")]
    [InlineData("extra")]
    [InlineData("role")]
    [InlineData("slot")]
    [InlineData("parent")]
    [InlineData("parentid")]
    [InlineData("rdev")]
    [InlineData("length")]
    [InlineData("extent")]
    [InlineData("contentRead")]
    [InlineData("label")]
    [InlineData("lun0")]
    public async Task Initialize_RejectsMalformedSourceCatalog(string kind)
    {
        RamInstallRequest request = Rh004TestData.CreateRequest();
        JsonObject inspect = Rh004TestData.InspectEnvelope(request);
        var result = inspect["result"]!.AsObject();

        if (string.Equals(kind, "missing", StringComparison.Ordinal))
        {
            result.Remove("bootSourceCatalog");
        }
        else
        {
            var catalog = result["bootSourceCatalog"]!.AsObject();
            JsonArray bindings = catalog["bindings"]!.AsArray();
            JsonObject first = bindings[0]!.AsObject();

            switch (kind)
            {
                case "duplicate":
                    bindings[1]!.AsObject()["partUuid"] = first["partUuid"]!.GetValue<string>();
                    break;
                case "extra":
                    bindings.Add(first.DeepClone());
                    break;
                case "role":
                    first["role"] = "boot_a";
                    break;
                case "slot":
                    first["slot"] = "c";
                    break;
                case "parent":
                    first["parentDevice"] = "/dev/sdz";
                    break;
                case "parentid":
                    first["parentDeviceId"] = "8:99";
                    break;
                case "rdev":
                    first["deviceId"] = first["parentDeviceId"]!.GetValue<string>();
                    break;
                case "length":
                    first["length"] = first["length"]!.GetValue<long>() + 1L;
                    break;
                case "extent":
                    first["startSector"] = Rh004TestData.SdbDiskBytes / Rh004TestData.SdbSectorSize;
                    break;
                case "contentRead":
                    first["contentRead"] = true;
                    break;
                case "label":
                    first["label"] = "boot_b";
                    break;
                case "lun0":
                    first["parentDevice"] = "/dev/sda";
                    first["parentDeviceId"] = "8:0";
                    first["number"] = 9L;
                    first["device"] = "/dev/sda9";
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(kind));
            }
        }

        await AssertInspectRejectedAsync(request, inspect);
    }

    [Fact]
    public async Task OptionalBoot_NoBootInspectStaysValidWithoutAnyCatalog()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        JsonObject inspect = Rh004TestData.InspectEnvelope(request);
        Assert.False(inspect["result"]!.AsObject().ContainsKey("bootSourceCatalog"));

        var console = new Rh004Console(inspect, new Dictionary<string, string>());
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        await client.InitializeAsync();
        Assert.Null(client.BootSourceCatalog);
        Assert.Null(request.Boot);

        RamInstallRequest bootRequest = Rh004TestData.CreateRequest();
        Rh004Proof proof = Rh004TestData.CreateProof(bootRequest);
        var bootConsole = Rh004TestData.CreateConsole(bootRequest, proof);
        var bootClient = new RamInstallClient(
            Rh002TestData.CreateSession(bootConsole),
            bootRequest);
        await bootClient.InitializeAsync();
        Assert.NotNull(bootClient.BootSourceCatalog);
    }

    private static async Task AssertRejectedAsync(RamInstallRequest request, Rh004Proof proof)
    {
        var console = Rh004TestData.CreateConsole(request, proof);
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);
        await client.InitializeAsync();

        await Assert.ThrowsAsync<MaintenanceException>(() => client.GetBuiltBootsAsync());
    }

    private static async Task AssertReportMutationRejectedAsync(
        RamInstallRequest request,
        Action<JsonObject> mutate)
    {
        Rh004Proof proof = Rh004TestData.CreateProof(request);
        mutate(proof.BuildReport("a"));
        await AssertRejectedAsync(request, proof);
    }

    private static async Task AssertInspectRejectedAsync(
        RamInstallRequest request,
        JsonObject inspect)
    {
        var console = new Rh004Console(inspect, new Dictionary<string, string>());
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        await Assert.ThrowsAsync<MaintenanceException>(() => client.InitializeAsync());
        Assert.Null(client.BootSourceCatalog);
    }
}

/// <summary>Shared RH004 synthetic proof fixtures. No real partition, path or byte is involved.</summary>
internal static class Rh004TestData
{
    public const string PrepareBootFs = "66666666-6666-4666-8666-666666666666";
    public const string PrepareRootFs = "77777777-7777-4777-8777-777777777777";
    public const string BaseImageSha = "9999999999999999999999999999999999999999999999999999999999999999";
    public const string CandidateShaA = "1111111111111111111111111111111111111111111111111111111111111111";
    public const string CandidateShaB = "2222222222222222222222222222222222222222222222222222222222222222";
    public const string ReportShaA = "3333333333333333333333333333333333333333333333333333333333333333";
    public const string ReportShaB = "4444444444444444444444444444444444444444444444444444444444444444";

    public const string SdbParentId = "8:16";
    public const int SdbSectorSize = 512;
    public const long SdbDiskBytes = 64L * 1024L * 1024L * 1024L;

    private static readonly string[] Roles =
    {
        "currentBoot",
        "vendorBoot",
        "initBoot",
        "abl",
        "xblConfig",
    };

    public static RamInstallRequest CreateRequest()
    {
        return Rh003TestData.CreateRequest(Rh003TestData.CreateBoot());
    }

    public static JsonObject InspectEnvelope(RamInstallRequest request)
    {
        JsonObject envelope = Rh002TestData.InspectEnvelope(request);
        if (request.Boot is not null)
        {
            envelope["result"]!.AsObject()["bootSourceCatalog"] = CreateCatalog(request);
        }

        return envelope;
    }

    public static JsonObject CreateCatalog(RamInstallRequest request)
    {
        RamInstallBootConfig boot = request.Boot
            ?? throw new InvalidOperationException("A boot request is required for a catalog.");

        ExpectedTable table = request.ExpectedTable;
        var parents = new JsonArray
        {
            new JsonObject
            {
                ["device"] = "/dev/sda",
                ["deviceId"] = "8:0",
                ["sectorSize"] = table.SectorSize,
                ["diskBytes"] = table.DiskBytes,
                ["sysfsDevice"] =
                    "/sys/devices/pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0/block/sda",
                ["linuxTableFingerprint"] = new string('f', 64),
            },
            new JsonObject
            {
                ["device"] = "/dev/sdb",
                ["deviceId"] = SdbParentId,
                ["sectorSize"] = SdbSectorSize,
                ["diskBytes"] = SdbDiskBytes,
                ["sysfsDevice"] =
                    "/sys/devices/pci0000:00/0000:00:1d.0/host1/target1:0:0/1:0:0:0/block/sdb",
                ["linuxTableFingerprint"] = new string('e', 64),
            },
        };

        var bindings = new JsonArray();
        var number = 1L;
        foreach (string slotName in new[] { "a", "b" })
        {
            RamInstallBootSlot slot = string.Equals(slotName, "a", StringComparison.Ordinal)
                ? boot.Slots.A
                : boot.Slots.B;

            foreach (string role in Roles)
            {
                RamInstallPartitionMaterial descriptor = Select(slot, role);
                long sectorCount = descriptor.Length / SdbSectorSize;
                if (descriptor.Length % SdbSectorSize != 0)
                {
                    throw new InvalidOperationException("The synthetic material must be sector aligned.");
                }

                bindings.Add(new JsonObject
                {
                    ["slot"] = slotName,
                    ["role"] = role,
                    ["label"] = Label(slotName, role),
                    ["partUuid"] = descriptor.PartUuid,
                    ["device"] = "/dev/sdb" + number,
                    ["parentDevice"] = "/dev/sdb",
                    ["number"] = number,
                    ["startSector"] = 2048L + (number - 1L) * 8L,
                    ["sectorCount"] = sectorCount,
                    ["sectorSize"] = SdbSectorSize,
                    ["length"] = descriptor.Length,
                    ["deviceId"] = "8:" + (16L + number),
                    ["parentDeviceId"] = SdbParentId,
                    ["contentRead"] = false,
                });
                number++;
            }
        }

        return new JsonObject
        {
            ["parents"] = parents,
            ["bindings"] = bindings,
        };
    }

    public static Rh004Proof CreateProof(RamInstallRequest request)
    {
        return new Rh004Proof(request);
    }

    public static Rh004Console CreateConsole(RamInstallRequest request, Rh004Proof proof)
    {
        return new Rh004Console(
            InspectEnvelope(request),
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["prepare"] = Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                    request,
                    "prepare",
                    "succeeded",
                    result: proof.Prepare,
                    exitCode: 0)),
                ["deploy"] = Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                    request,
                    "deploy",
                    "succeeded",
                    result: proof.Deploy,
                    exitCode: 0)),
                ["build-boots"] = Rh002TestData.Transcript(Rh002TestData.JobEnvelope(
                    request,
                    "build-boots",
                    "succeeded",
                    result: proof.Build,
                    exitCode: 0)),
            });
    }

    public static int Count(Rh004Console console, string fragment)
    {
        return console.Calls.Count(call => call.Contains(fragment, StringComparison.Ordinal));
    }

    private static RamInstallPartitionMaterial Select(RamInstallBootSlot slot, string role) => role switch
    {
        "currentBoot" => slot.CurrentBoot,
        "vendorBoot" => slot.VendorBoot,
        "initBoot" => slot.InitBoot,
        "abl" => slot.Abl,
        "xblConfig" => slot.XblConfig,
        _ => throw new ArgumentOutOfRangeException(nameof(role)),
    };

    private static string Label(string slot, string role) => role switch
    {
        "currentBoot" => "boot_" + slot,
        "vendorBoot" => "vendor_boot_" + slot,
        "initBoot" => "init_boot_" + slot,
        "abl" => "abl_" + slot,
        "xblConfig" => "xbl_config_" + slot,
        _ => throw new ArgumentOutOfRangeException(nameof(role)),
    };
}

/// <summary>One mutable synthetic proof used to build a good result and then corrupt one field.</summary>
internal sealed class Rh004Proof
{
    public Rh004Proof(RamInstallRequest request)
    {
        Request = request;
        RamInstallBootConfig boot = request.Boot
            ?? throw new InvalidOperationException("A boot request is required.");
        Prepare = CreatePrepare(request);
        Deploy = CreateDeploy(request);
        Build = CreateBuild(request, boot);
    }

    public RamInstallRequest Request { get; }

    public JsonObject Prepare { get; }

    public JsonObject Deploy { get; }

    public JsonObject Build { get; }

    public JsonObject BuildReport(string slot)
    {
        return Build["slots"]!.AsObject()[slot]!.AsObject()["builderReport"]!.AsObject();
    }

    public JsonObject BuildSlotMaterial(string slot)
    {
        return BuildReport(slot)["slot_material"]!.AsObject();
    }

    public JsonObject BuildBudget(string slot)
    {
        return BuildSlotMaterial(slot)["loader_budget"]!.AsObject();
    }

    private static JsonObject CreatePrepare(RamInstallRequest request)
    {
        long sectorSize = request.ExpectedTable.SectorSize;
        ExpectedPartition boot = Find(request, RamInstallRequest.BootLabel);
        ExpectedPartition root = Find(request, RamInstallRequest.RootLabel);

        return new JsonObject
        {
            ["boot"] = new JsonObject
            {
                ["partuuid"] = request.BootPartUuid,
                ["filesystem_uuid"] = Rh004TestData.PrepareBootFs,
                ["start"] = boot.StartSector,
                ["end"] = boot.StartSector + boot.SectorCount,
                ["size_bytes"] = boot.SectorCount * sectorSize,
            },
            ["root"] = new JsonObject
            {
                ["partuuid"] = request.RootPartUuid,
                ["filesystem_uuid"] = Rh004TestData.PrepareRootFs,
                ["start"] = root.StartSector,
                ["end"] = root.StartSector + root.SectorCount,
                ["size_bytes"] = root.SectorCount * sectorSize,
            },
            ["table_fingerprint"] = new string('f', 64),
            ["device"] = "/dev/sda",
            ["sector_size"] = sectorSize,
            ["subvolumes"] = new JsonArray(),
            ["seed_directory"] = "/.armada-install-seed/repo",
        };
    }

    private static JsonObject CreateDeploy(RamInstallRequest request)
    {
        return new JsonObject
        {
            ["deployment_checksum"] = request.Seed.Commit,
            ["filesystem_uuids"] = new JsonObject
            {
                ["boot"] = Rh004TestData.PrepareBootFs,
                ["root"] = Rh004TestData.PrepareRootFs,
            },
            ["bls"] = "freedom",
            ["image"] = "image",
            ["initrd"] = "initrd",
            ["fdtdir"] = "fdtdir",
            ["options"] = "options",
        };
    }

    private static JsonObject CreateBuild(RamInstallRequest request, RamInstallBootConfig boot)
    {
        return new JsonObject
        {
            ["deploymentChecksum"] = request.Seed.Commit,
            ["filesystemUuids"] = new JsonObject
            {
                ["boot"] = Rh004TestData.PrepareBootFs,
                ["root"] = Rh004TestData.PrepareRootFs,
            },
            ["slots"] = new JsonObject
            {
                ["a"] = Slot(
                    "a",
                    "boot_a",
                    "report_a",
                    boot.Slots.A,
                    Rh004TestData.CandidateShaA,
                    Rh004TestData.ReportShaA),
                ["b"] = Slot(
                    "b",
                    "boot_b",
                    "report_b",
                    boot.Slots.B,
                    Rh004TestData.CandidateShaB,
                    Rh004TestData.ReportShaB),
            },
        };
    }

    private static JsonObject Slot(
        string slot,
        string candidateRole,
        string reportRole,
        RamInstallBootSlot materials,
        string candidateSha,
        string reportSha)
    {
        return new JsonObject
        {
            ["slot"] = slot,
            ["candidate"] = new JsonObject
            {
                ["role"] = candidateRole,
                ["length"] = materials.CurrentBoot.Length,
                ["sha256"] = candidateSha,
            },
            ["report"] = new JsonObject
            {
                ["role"] = reportRole,
                ["length"] = 1024L,
                ["sha256"] = reportSha,
            },
            ["builderReport"] = CreateReport(slot, materials, candidateSha),
        };
    }

    private static JsonObject CreateReport(
        string slot,
        RamInstallBootSlot materials,
        string candidateSha)
    {
        JsonObject budget = CreateBudget(materials);

        return new JsonObject
        {
            ["offline_verified"] = true,
            ["layout_mode"] = "installed",
            ["default_entry"] = "android",
            ["default_index"] = 0,
            ["stock_image"] = new JsonObject
            {
                ["length"] = Rh003TestData.DefaultMaterialLength,
                ["sha256"] = Rh004TestData.BaseImageSha,
            },
            ["outputs"] = new JsonObject
            {
                ["final_boot"] = new JsonObject
                {
                    ["length"] = materials.CurrentBoot.Length,
                    ["sha256"] = candidateSha,
                },
            },
            ["slot_material"] = new JsonObject
            {
                ["schemaVersion"] = 1,
                ["slot"] = slot,
                ["is_kshim"] = true,
                ["source_sha256"] = new JsonObject
                {
                    ["current_boot"] = materials.CurrentBoot.Sha256,
                    ["vendor_boot"] = materials.VendorBoot.Sha256,
                    ["init_boot"] = materials.InitBoot.Sha256,
                    ["abl"] = materials.Abl.Sha256,
                    ["xbl_config"] = materials.XblConfig.Sha256,
                },
                ["source_lengths"] = new JsonObject
                {
                    ["current_boot"] = materials.CurrentBoot.Length,
                    ["vendor_boot"] = materials.VendorBoot.Length,
                    ["init_boot"] = materials.InitBoot.Length,
                    ["abl"] = materials.Abl.Length,
                    ["xbl_config"] = materials.XblConfig.Length,
                },
                ["base_image"] = new JsonObject
                {
                    ["length"] = Rh003TestData.DefaultMaterialLength,
                    ["sha256"] = Rh004TestData.BaseImageSha,
                },
                ["ramdisks"] = new JsonObject
                {
                    ["boot_ramdisk_size"] = 0L,
                    ["vendor_ramdisk_size"] = 0L,
                    ["init_ramdisk_size"] = 0L,
                    ["total_ramdisk_size"] = 0L,
                    ["page_size"] = 4096L,
                },
                ["loader_budget"] = budget.DeepClone(),
                ["oem_signed_restored"] = false,
                ["recovery_scope"] = "android-arm64-kernel-only",
                ["signature_verification_performed"] = false,
            },
            ["loader_budget"] = budget,
        };
    }

    private static JsonObject CreateBudget(RamInstallBootSlot materials)
    {
        return new JsonObject
        {
            ["profile"] = "conservative-default",
            ["evidence"] = "synthetic-rh004",
            ["formula"] = "fixed-unknown-loader-limit",
            ["max_raw_bytes"] = 134217728L,
            ["known_loader_match"] = false,
            ["abl_sha256"] = materials.Abl.Sha256,
            ["xbl_config_sha256"] = materials.XblConfig.Sha256,
            ["abl_bytes"] = materials.Abl.Length,
            ["xbl_config_bytes"] = materials.XblConfig.Length,
            ["total_ramdisk_bytes"] = 0L,
            ["page_size"] = 4096L,
        };
    }

    private static ExpectedPartition Find(RamInstallRequest request, string label)
    {
        ExpectedPartition? found = request.ExpectedTable.Partitions
            .FirstOrDefault(partition => string.Equals(
                partition.Name,
                label,
                StringComparison.Ordinal));
        return found ?? throw new InvalidOperationException("A required fixture partition is missing.");
    }
}

/// <summary>A console that serves one inspect envelope and fixed status transcripts.</summary>
internal sealed class Rh004Console : IMaintenanceConsole
{
    private readonly JsonObject _inspect;
    private readonly Dictionary<string, string> _statuses;

    public Rh004Console(JsonObject inspect, Dictionary<string, string> statuses)
    {
        _inspect = inspect ?? throw new ArgumentNullException(nameof(inspect));
        _statuses = statuses ?? throw new ArgumentNullException(nameof(statuses));
    }

    public List<string> Calls { get; } = new();

    public Task<string> RunCommandAsync(
        string script,
        string expectedMarker,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        Calls.Add(script);

        if (cancellationToken.IsCancellationRequested)
        {
            return Task.FromCanceled<string>(cancellationToken);
        }

        if (string.Equals(expectedMarker, Rh002TestData.InitMarker, StringComparison.Ordinal))
        {
            return Task.FromResult(Rh002TestData.InitMarker + "\n");
        }

        if (script.Contains("armada_install.py inspect", StringComparison.Ordinal))
        {
            return Task.FromResult(Rh002TestData.Transcript(_inspect));
        }

        foreach (KeyValuePair<string, string> pair in _statuses)
        {
            if (script.Contains("status --action " + pair.Key, StringComparison.Ordinal))
            {
                return Task.FromResult(pair.Value);
            }
        }

        throw new InvalidOperationException("Unexpected console command: " + script);
    }
}
