using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>Formal skip when the manager has not exported the real MB006 packaged ZIP.</summary>
sealed class MaintenancePackageFactAttribute : FactAttribute
{
    public MaintenancePackageFactAttribute()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("MAINTENANCE_TEST_BUNDLE_PATH")))
            Skip = "MAINTENANCE_TEST_BUNDLE_PATH not set; requires the real MB006 packaged ZIP.";
    }
}

public sealed class MaintenancePackageIntegrationTests
{
    const string ProfileId = "g4-198-259-acmncm";
    const string Model = "TB322FC";
    const string Build = "TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.259_ST_260611";
    static readonly (string Role, string Arc, long Bytes, string Sha)[] Expected =
    {
        ("boot", "payload/boot.img", 100663296L, "81e7da2e2d3910d80dee80e1d6f774db294c8e9aa633d4aca7db9ccd7a50c358"),
        ("toolbox", "payload/toolbox.tar.gz", 171162924L, "79a2d937f2cf566591fde9bb8fc1b594fb9e949176fbde0364e9f09976af14a2"),
        ("bootstrap", "scripts/maintenance_bootstrap.sh", -1, ""),
        ("helper", "scripts/armada_uninstall.py", -1, ""),
        ("avb", "scripts/avb_stock.py", -1, ""),
    };

    [MaintenancePackageFact]
    public async Task LoadAsync_RealBundle_ExposesFivePinnedRoles()
    {
        var zipPath = Environment.GetEnvironmentVariable("MAINTENANCE_TEST_BUNDLE_PATH")!;
        var artifactRoot = Environment.GetEnvironmentVariable("TEST_ARTIFACT_ROOT");
        Assert.False(string.IsNullOrWhiteSpace(artifactRoot), "TEST_ARTIFACT_ROOT is required once the real-bundle case runs.");
        var testRoot = Path.Combine(artifactRoot!, "mb006-" + Guid.NewGuid().ToString("N"));
        var sentinel = Path.Combine(testRoot, "sentinel.txt");
        try
        {
            var workRoot = Directory.CreateDirectory(Path.Combine(testRoot, "work")).FullName;
            File.WriteAllText(sentinel, "sibling sentinel");

            var sourceLength = new FileInfo(zipPath).Length;
            var manifest = ReadManifest(zipPath);
            using var stream = new FileStream(zipPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var bundle = await MaintenanceBundle.LoadAsync(stream, Model, Build, workRoot);
            var staging = bundle.StagingDirectory;
            try
            {
                Assert.Equal(ProfileId, bundle.Profile.ProfileId);
                Assert.Equal(Model, bundle.Profile.Model);
                Assert.Equal(Build, bundle.Profile.AndroidBuild);
                Assert.Equal("SM8750", bundle.Profile.Soc);
                Assert.Equal(5, manifest.Count);
                foreach (var (role, arc, bytes, sha) in Expected)
                {
                    var asset = bundle.GetAsset(role);
                    Assert.Equal(role, asset.Role);
                    Assert.Equal(arc, manifest[role].Arc);
                    Assert.Equal(arc, asset.Path);
                    Assert.Equal(manifest[role].Bytes, asset.Bytes);
                    Assert.Equal(manifest[role].Sha, asset.Sha256);
                    if (bytes >= 0)
                    {
                        Assert.Equal(bytes, asset.Bytes);
                        Assert.Equal(sha, asset.Sha256);
                    }
                    using var content = bundle.OpenAsset(role);
                    Assert.Equal(asset.Bytes, content.Length);
                }
                Assert.True(Directory.Exists(staging));
            }
            finally { bundle.Dispose(); }

            Assert.False(Directory.Exists(staging), "Dispose must remove only its own staging directory.");
            Assert.True(Directory.Exists(workRoot));
            Assert.Equal("sibling sentinel", File.ReadAllText(sentinel));
            Assert.Equal(sourceLength, new FileInfo(zipPath).Length);
            Assert.True(stream.CanRead);
            stream.Position = 0;
            Assert.True(stream.ReadByte() >= 0);
        }
        finally
        {
            if (Directory.Exists(testRoot)) Directory.Delete(testRoot, true);
        }
    }

    static Dictionary<string, (string Arc, long Bytes, string Sha)> ReadManifest(string zipPath)
    {
        using var stream = new FileStream(zipPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        var entry = zip.GetEntry("manifest.json");
        Assert.NotNull(entry);
        using var reader = new StreamReader(entry!.Open(), Encoding.UTF8);
        using var doc = JsonDocument.Parse(reader.ReadToEnd());
        var root = doc.RootElement;
        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(ProfileId, root.GetProperty("profileId").GetString());
        Assert.Equal(Model, root.GetProperty("model").GetString());
        Assert.Equal(Build, root.GetProperty("androidBuild").GetString());
        var map = new Dictionary<string, (string, long, string)>(StringComparer.Ordinal);
        foreach (var e in root.GetProperty("entries").EnumerateArray())
            map.Add(e.GetProperty("role").GetString()!,
                (e.GetProperty("path").GetString()!, e.GetProperty("bytes").GetInt64(), e.GetProperty("sha256").GetString()!));
        return map;
    }
}
