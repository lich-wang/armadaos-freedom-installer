using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class UpdatePackageDescriptorTests
{
    private const string H = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string H2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    [Fact]
    public void ValidThreeModelInstall_ClonesRootAndChecksLifetime()
    {
        UpdatePackageDescriptor descriptor = Parse(Base());
        Assert.Equal("release-1", descriptor.ReleaseId);
        Assert.Equal("1.0.0", descriptor.Version);
        Assert.Equal(1, descriptor.Root.GetProperty("schemaVersion").GetInt64());
        descriptor.RequireOperation("TB710FU", "install", "1.2.3");
    }

    [Fact]
    public void PublicVerifyAndParse_RejectsSyntheticSignature()
    {
        byte[] json = Encoding.UTF8.GetBytes(Base().ToJsonString());
        Assert.Throws<InvalidDataException>(() =>
            UpdatePackageDescriptor.VerifyAndParse(json, Encoding.UTF8.GetBytes("AA==")));
    }

    [Fact]
    public void InstallOnly_RejectsOfflineUpgradeAndUnsupportedModel()
    {
        UpdatePackageDescriptor descriptor = Parse(Base());
        Assert.Throws<InvalidDataException>(() => descriptor.RequireOperation("TB322FC", "offline-upgrade", "2.0.0"));
        Assert.Throws<InvalidDataException>(() => descriptor.RequireOperation("other", "install", "2.0.0"));
    }

    [Theory]
    [InlineData("1.2.2", false)]
    [InlineData("1.2.3", true)]
    [InlineData("1.2.4", true)]
    [InlineData("999999999999999999999999999999.0.0", true)]
    [InlineData("01.2.3", false)]
    [InlineData("1.2", false)]
    public void InstallerVersionGate_IsCanonicalAndArbitraryPrecision(string version, bool accepted)
    {
        UpdatePackageDescriptor descriptor = Parse(Base());
        if (accepted)
            descriptor.RequireOperation("TB322FC", "install", version);
        else
            Assert.Throws<InvalidDataException>(() => descriptor.RequireOperation("TB322FC", "install", version));
    }

    [Fact]
    public void HugeMinimumVersion_IsSupported()
    {
        JsonObject json = Base();
        const string version = "999999999999999999999999999999.0.0";
        json["minimumInstallerVersion"] = version;
        Parse(json).RequireOperation("TB322FC", "install", version);
        json["minimumInstallerVersion"] = "1.02.3";
        AssertInvalid(_ => { }, json);
    }

    [Theory]
    [InlineData("extra")]
    [InlineData("missing")]
    public void TopLevelKeys_MustBeExact(string mode)
    {
        AssertInvalid(json =>
        {
            if (mode == "extra") json["unexpected"] = true;
            else json.Remove("parts");
        });
    }

    [Theory]
    [InlineData("true")]
    [InlineData("1.0")]
    [InlineData("1e0")]
    public void IntegerFields_RejectBooleanFractionAndExponent(string raw)
    {
        InvalidRaw(Base().ToJsonString().Replace("\"schemaVersion\":1", $"\"schemaVersion\":{raw}"));
    }

    [Theory]
    [InlineData("model")]
    [InlineData("duplicate-model")]
    [InlineData("operation")]
    [InlineData("duplicate-operation")]
    public void ModelAndOperationSets_RejectUnknownAndDuplicates(string mode)
    {
        AssertInvalid(json => json[mode.Contains("model") ? "supportedModels" : "operations"] = mode switch
        {
            "model" => new JsonArray("unknown"),
            "duplicate-model" => new JsonArray("TB322FC", "TB322FC"),
            "operation" => new JsonArray("unknown"),
            _ => new JsonArray("install", "install")
        });
    }

    [Theory]
    [InlineData("releaseId")]
    [InlineData("version")]
    [InlineData("sourceRevision")]
    [InlineData("ociDigest")]
    [InlineData("ostreeCommit")]
    public void IdentityAndHashFields_AreCanonical(string field)
    {
        AssertInvalid(json => json[field] = field switch
        {
            "releaseId" => "latest",
            "version" => "../bad",
            "sourceRevision" => new string('A', 40),
            "ociDigest" => "sha256:" + new string('A', 64),
            _ => new string('A', 64)
        });
    }

    [Theory]
    [InlineData("sequence")]
    [InlineData("sum")]
    [InlineData("limit")]
    public void SplitParts_EnforceSequenceSumAndTwoGiBLIMIT(string mode)
    {
        AssertInvalid(json =>
        {
            JsonArray parts = json["parts"]!.AsArray();
            if (mode == "sequence") parts[0]!["fileName"] = "bundle.zip.002";
            else if (mode == "sum") parts[0]!["bytes"] = 2;
            else parts[0]!["bytes"] = 2147483648L;
        });
    }

    [Fact]
    public void SplitPart_AtLimitIsAccepted()
    {
        JsonObject json = Base();
        json["archive"]!["bytes"] = 2147483647L;
        json["parts"] = new JsonArray(Archive("bundle.zip.001", 2147483647L));
        Parse(json);
    }

    [Theory]
    [InlineData("/absolute")]
    [InlineData("../escape")]
    [InlineData("a\\b")]
    [InlineData("dir/CON.txt")]
    [InlineData("dir/trailing.")]
    [InlineData("dir/trailing ")]
    public void Paths_RejectTraversalBackslashReservedAndNonPortableNames(string path)
    {
        AssertInvalid(json => json["files"]!.AsArray()[0]!["path"] = path);
    }

    [Fact]
    public void Paths_RejectWindowsCaseDuplicateAndParentFileCollision()
    {
        AssertInvalid(json => json["files"]!.AsArray().Add(File("IMAGES/ROOT.IMG", "metadata")));
        AssertInvalid(json => json["files"]!.AsArray().Add(File("images/root.img/child", "metadata")));
    }

    [Theory]
    [InlineData("linux-root")]
    [InlineData("linux-boot")]
    public void RootAndBoot_MustHaveSingleRecords(string role)
    {
        AssertInvalid(json => json["files"]!.AsArray().Add(File($"images/second-{role}", role)));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("role")]
    [InlineData("duplicate")]
    [InlineData("overlap")]
    public void ManifestReferences_AreIndexedManifestsAndDistinct(string mode)
    {
        AssertInvalid(json =>
        {
            if (mode == "missing") json["modelManifests"]!["TB322FC"] = "missing.json";
            if (mode == "role") json["files"]!.AsArray()[1]!["role"] = "kernel";
            if (mode == "duplicate") json["modelManifests"]!["TB323FU"] = "manifests/TB322FC.json";
            if (mode == "overlap") json["recoveryManifests"] = new JsonObject { ["TB322FC"] = "manifests/TB322FC.json" };
        });
    }

    [Fact]
    public void OfflineUpgrade_WithGzipImagesAndPerModelRecovery_IsValid()
    {
        UpdatePackageDescriptor descriptor = Parse(OfflineBase());
        descriptor.RequireOperation("TB323FU", "offline-upgrade", "1.2.3");
    }

    [Fact]
    public void OfflineUpgrade_WithoutRecoveryManifests_IsValid()
    {
        JsonObject json = OfflineBase();
        json["recoveryManifests"] = new JsonObject();
        UpdatePackageDescriptor descriptor = Parse(json);
        descriptor.RequireOperation("TB323FU", "offline-upgrade", "1.2.3");
        descriptor.RequireOperation("TB710FU", "offline-upgrade", "1.2.3");
    }

    [Fact]
    public void MixedDescriptor_InstallsAndUpgradesEveryModel()
    {
        JsonObject json = OfflineBase();
        json["operations"] = new JsonArray("install", "offline-upgrade");
        UpdatePackageDescriptor descriptor = Parse(json);

        foreach (string model in new[] { "TB322FC", "TB323FU", "TB710FU" })
            descriptor.RequireOperation(model, "install", "1.2.3");
        // TB710FU has the native dual-slot backend now, like the two Y700 generations.
        foreach (string model in new[] { "TB322FC", "TB323FU", "TB710FU" })
            descriptor.RequireOperation(model, "offline-upgrade", "1.2.3");
    }

    [Theory]
    [InlineData("TB322FC", true)]
    [InlineData("tb323fu", true)]
    [InlineData("TB710FU", true)]
    [InlineData("TB320FC", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void SupportsOfflineUpgrade_IsTheSingleModelList(string? model, bool expected) =>
        Assert.Equal(expected, UpdatePackageDescriptor.SupportsOfflineUpgrade(model));

    [Fact]
    public void OfflineUpgrade_WithSubsetRecoveryManifests_IsValid()
    {
        JsonObject json = OfflineBase();
        json["recoveryManifests"]!.AsObject().Remove("TB710FU");
        Parse(json).RequireOperation("TB322FC", "offline-upgrade", "1.2.3");
    }

    [Theory]
    [InlineData("unknown-model")]
    [InlineData("missing-file")]
    [InlineData("wrong-role")]
    [InlineData("duplicate-path")]
    public void OfflineUpgrade_OptionalRecoveryEntries_RemainStrictlyValidated(string mode)
    {
        AssertInvalid(json =>
        {
            JsonObject recovery = json["recoveryManifests"]!.AsObject();
            if (mode == "unknown-model")
            {
                recovery["TB999XX"] = "recovery/TB322FC.json";
            }
            else if (mode == "missing-file")
            {
                recovery["TB322FC"] = "recovery/missing.json";
            }
            else if (mode == "wrong-role")
            {
                foreach (JsonNode? node in json["files"]!.AsArray())
                {
                    JsonObject file = node!.AsObject();
                    if (file["path"]!.GetValue<string>() == "recovery/TB322FC.json")
                        file["role"] = "kernel";
                }
            }
            else
            {
                recovery["TB323FU"] = "recovery/TB322FC.json";
            }
        }, OfflineBase());
    }

    [Theory]
    [InlineData("size")]
    [InlineData("hash")]
    public void NoneCompression_RequiresMatchingExpandedIdentity(string mode)
    {
        AssertInvalid(json =>
        {
            JsonObject root = json["files"]!.AsArray()[4]!.AsObject();
            if (mode == "size") root["expandedBytes"] = 2;
            else root["expandedSha256"] = H2;
        });
    }

    [Fact]
    public void DeckyRepair_RequiresSnapshot()
    {
        AssertInvalid(json => json["operations"] = new JsonArray("decky-repair"));
    }

    [Theory]
    [InlineData("releaseId")]
    [InlineData("assetId")]
    [InlineData("size")]
    [InlineData("tag")]
    [InlineData("sha256")]
    public void DeckySnapshot_HasTypedFields(string field)
    {
        AssertInvalid(json =>
        {
            json["deckySnapshot"] = Decky();
            json["deckySnapshot"]![field] = field is "tag" ? "" : field is "sha256" ? "bad" : true;
        });
    }

    [Fact]
    public void DeckySnapshot_ValidTypedMetadataIsAccepted()
    {
        JsonObject json = Base();
        json["operations"] = new JsonArray("decky-repair");
        json["deckySnapshot"] = Decky();
        Parse(json);
    }

    [Fact]
    public void NestedDuplicateJsonNames_AreRejectedFromRawDocument()
    {
        InvalidRaw(Base().ToJsonString().Replace(
            "\"fileName\":\"bundle.zip\",\"bytes\":3",
            "\"fileName\":\"bundle.zip\",\"fileName\":\"bundle.zip\",\"bytes\":3"));
    }

    private static JsonObject Base()
    {
        JsonObject json = new()
        {
            ["schemaVersion"] = 1, ["kind"] = "freedom-universal-package",
            ["product"] = "armadaos-freedom", ["architecture"] = "aarch64",
            ["releaseId"] = "release-1", ["version"] = "1.0.0",
            ["sourceRevision"] = new string('a', 40), ["ociDigest"] = "sha256:" + H,
            ["ostreeCommit"] = H, ["minimumInstallerVersion"] = "1.2.3",
            ["minimumUpdaterVersion"] = "1.0.0",
            ["supportedModels"] = new JsonArray("TB322FC", "TB323FU", "TB710FU"),
            ["operations"] = new JsonArray("install"),
            ["archive"] = Archive("bundle.zip", 3),
            ["parts"] = new JsonArray(Archive("bundle.zip.001", 1), Archive("bundle.zip.002", 2)),
            ["files"] = new JsonArray(
                File("bundle.json", "manifest"), File("manifests/TB322FC.json", "manifest"),
                File("manifests/TB323FU.json", "manifest"), File("manifests/TB710FU.json", "manifest"),
                File("images/root.img", "linux-root"), File("images/boot.img", "linux-boot")),
            ["modelManifests"] = new JsonObject
            {
                ["TB322FC"] = "manifests/TB322FC.json", ["TB323FU"] = "manifests/TB323FU.json",
                ["TB710FU"] = "manifests/TB710FU.json"
            },
            ["recoveryManifests"] = new JsonObject(), ["deckySnapshot"] = null
        };
        return json;
    }

    private static JsonObject OfflineBase()
    {
        JsonObject json = Base();
        json["operations"] = new JsonArray("offline-upgrade");
        JsonArray files = json["files"]!.AsArray();
        foreach (int index in new[] { 4, 5 })
        {
            files[index]!["compression"] = "gzip";
            files[index]!["expandedBytes"] = 2;
            files[index]!["expandedSha256"] = H2;
        }
        JsonObject recovery = new();
        foreach (string model in new[] { "TB322FC", "TB323FU", "TB710FU" })
        {
            string path = $"recovery/{model}.json";
            files.Add(File(path, "manifest"));
            recovery[model] = path;
        }
        json["recoveryManifests"] = recovery;
        return json;
    }

    private static JsonObject Archive(string name, long bytes) =>
        new() { ["fileName"] = name, ["bytes"] = bytes, ["sha256"] = H };

    private static JsonObject File(string path, string role) => new()
    {
        ["path"] = path, ["bytes"] = 1, ["sha256"] = H, ["expandedBytes"] = 1,
        ["expandedSha256"] = H, ["compression"] = "none", ["role"] = role
    };

    private static JsonObject Decky() => new()
    {
        ["releaseId"] = 1, ["tag"] = "v1", ["publishedAt"] = "2025-01-01T00:00:00Z",
        ["assetId"] = 2, ["url"] = "https://example.invalid/asset", ["size"] = 3, ["sha256"] = H
    };

    private static UpdatePackageDescriptor ParseRoot(JsonElement root)
    {
        try
        {
            return (UpdatePackageDescriptor)typeof(UpdatePackageDescriptor)
                .GetMethod("ParseVerifiedRoot", BindingFlags.Static | BindingFlags.NonPublic)!
                .Invoke(null, new object[] { root })!;
        }
        catch (TargetInvocationException ex) when (ex.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
            throw;
        }
    }

    private static UpdatePackageDescriptor Parse(JsonNode json)
    {
        using JsonDocument document = JsonDocument.Parse(json.ToJsonString());
        return ParseRoot(document.RootElement);
    }

    private static void AssertInvalid(Action<JsonObject> mutate, JsonObject? fixture = null)
    {
        JsonObject json = fixture ?? Base();
        mutate(json);
        Assert.Throws<InvalidDataException>(() => Parse(json));
    }

    private static void InvalidRaw(string raw)
    {
        using JsonDocument document = JsonDocument.Parse(raw);
        Assert.Throws<InvalidDataException>(() => ParseRoot(document.RootElement));
    }
}
