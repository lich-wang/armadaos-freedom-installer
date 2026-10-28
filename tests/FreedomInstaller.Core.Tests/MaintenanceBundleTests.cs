using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Reviewed evidence pins restated as independent literals. The tests never read the
/// production pin constants, so corrupting those constants cannot make this suite pass.
/// </summary>
internal static class TestPins
{
    internal const int SchemaVersion = 1;
    internal const string ProfileId = "g4-198-259-acmncm";
    internal const string Model = "TB322FC";
    internal const string Soc = "SM8750";
    internal const string AndroidBuild = "TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.259_ST_260611";

    internal const long BootBytes = 100663296L;
    internal const string BootSha256 = "81e7da2e2d3910d80dee80e1d6f774db294c8e9aa633d4aca7db9ccd7a50c358";

    internal const long ToolboxBytes = 171162924L;
    internal const string ToolboxSha256 = "79a2d937f2cf566591fde9bb8fc1b594fb9e949176fbde0364e9f09976af14a2";

    internal const string WrongModel = "TB323FU";
    internal const string UnknownProfileId = "g5-198-259-acmncm";
    internal const string WrongAndroidBuild = "TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.258_ST_260601";
}

/// <summary>
/// Required environment roots. There is deliberately no local or system-temp fallback:
/// every artifact this suite writes must land under TEST_ARTIFACT_ROOT, and the only
/// real-pin inputs may come from MAINTENANCE_TEST_ASSET_ROOT.
/// </summary>
internal static class TestPaths
{
    internal static string ArtifactRoot => Require("TEST_ARTIFACT_ROOT");

    internal static string AssetRoot => Require("MAINTENANCE_TEST_ASSET_ROOT");

    private static string Require(string variable)
    {
        var value = Environment.GetEnvironmentVariable(variable);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException(
                $"{variable} must be set to an existing directory; MB002 never falls back to a local or system temp path.");
        }

        return value;
    }
}

/// <summary>
/// One planned manifest entry plus the bytes actually written into the archive under
/// <see cref="Path"/>. Keeping declaration and payload separate is what lets the suite
/// declare the real production pins while shipping tiny placeholders.
/// </summary>
internal sealed record PlannedEntry
{
    internal string Role { get; init; } = string.Empty;

    internal string Path { get; init; } = string.Empty;

    internal long Bytes { get; init; }

    internal string Sha256 { get; init; } = string.Empty;

    internal byte[]? InlinePayload { get; init; }

    internal string? FilePayload { get; init; }

    internal bool IncludeInArchive { get; init; } = true;
}

/// <summary>
/// Isolated per-test directory: the archive, the loader's work root, and a sentinel file
/// that must survive every failure path.
/// </summary>
internal sealed class BundleWorkspace : IDisposable
{
    private BundleWorkspace(string root, string workRoot, string archivePath, string sentinelPath)
    {
        Root = root;
        WorkRoot = workRoot;
        ArchivePath = archivePath;
        SentinelPath = sentinelPath;
    }

    internal string Root { get; }

    internal string WorkRoot { get; }

    internal string ArchivePath { get; }

    internal string SentinelPath { get; }

    internal static BundleWorkspace Create()
    {
        var root = Path.Combine(TestPaths.ArtifactRoot, "mb002-" + Guid.NewGuid().ToString("N"));
        var workRoot = Path.Combine(root, "work");
        Directory.CreateDirectory(workRoot);

        var sentinel = Path.Combine(root, "sentinel.txt");
        File.WriteAllText(sentinel, "sentinel");

        return new BundleWorkspace(root, workRoot, Path.Combine(root, "bundle.zip"), sentinel);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
        catch (IOException)
        {
            // Artifact cleanup is best effort; assertions already ran against the live tree.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}

/// <summary>
/// Test-only ZIP fixture construction. Real archives are always written through
/// FileStream; nothing here materialises a multi-hundred-megabyte MemoryStream.
/// </summary>
internal static class BundleFixture
{
    internal static byte[] BootstrapScript { get; } =
        Encoding.UTF8.GetBytes("#!/bin/sh\nset -eu\n# MB002 fixture bootstrap\necho bootstrap\n");

    internal static byte[] HelperScript { get; } =
        Encoding.UTF8.GetBytes("#!/bin/sh\nset -eu\n# MB002 fixture helper\necho helper\n");

    internal static byte[] AvbStockScript { get; } =
        Encoding.UTF8.GetBytes("#!/usr/bin/env python3\n# MB002 fixture avb_stock\nprint(\"avb-stock\")\n");

    private static byte[] BootPlaceholder { get; } = Encoding.ASCII.GetBytes("mb002-boot-placeholder");

    private static byte[] ToolboxPlaceholder { get; } = Encoding.ASCII.GetBytes("mb002-toolbox-placeholder");

    internal static string Sha256Hex(byte[] data) =>
        Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    /// <summary>
    /// Well-formed manifest with the four required roles in a fixed order: the two tiny
    /// scripts first so that script validation can complete before the large payloads
    /// are ever streamed.
    /// </summary>
    internal static List<PlannedEntry> DefaultEntries() => new()
    {
        new PlannedEntry
        {
            Role = "bootstrap",
            Path = "scripts/bootstrap.sh",
            Bytes = BootstrapScript.Length,
            Sha256 = Sha256Hex(BootstrapScript),
            InlinePayload = BootstrapScript
        },
        new PlannedEntry
        {
            Role = "helper",
            Path = "scripts/helper.sh",
            Bytes = HelperScript.Length,
            Sha256 = Sha256Hex(HelperScript),
            InlinePayload = HelperScript
        },
        new PlannedEntry
        {
            Role = "avb",
            Path = "scripts/avb_stock.py",
            Bytes = AvbStockScript.Length,
            Sha256 = Sha256Hex(AvbStockScript),
            InlinePayload = AvbStockScript
        },
        new PlannedEntry
        {
            Role = "boot",
            Path = "payload/boot.img",
            Bytes = TestPins.BootBytes,
            Sha256 = TestPins.BootSha256,
            InlinePayload = BootPlaceholder
        },
        new PlannedEntry
        {
            Role = "toolbox",
            Path = "payload/toolbox.tar.gz",
            Bytes = TestPins.ToolboxBytes,
            Sha256 = TestPins.ToolboxSha256,
            InlinePayload = ToolboxPlaceholder
        }
    };

    /// <summary>Entries whose payloads are the real pinned assets supplied by the manager mount.</summary>
    internal static List<PlannedEntry> RealAssetEntries(string bootPath, string toolboxPath) => new()
    {
        new PlannedEntry
        {
            Role = "bootstrap",
            Path = "scripts/bootstrap.sh",
            Bytes = BootstrapScript.Length,
            Sha256 = Sha256Hex(BootstrapScript),
            InlinePayload = BootstrapScript
        },
        new PlannedEntry
        {
            Role = "helper",
            Path = "scripts/helper.sh",
            Bytes = HelperScript.Length,
            Sha256 = Sha256Hex(HelperScript),
            InlinePayload = HelperScript
        },
        new PlannedEntry
        {
            Role = "avb",
            Path = "scripts/avb_stock.py",
            Bytes = AvbStockScript.Length,
            Sha256 = Sha256Hex(AvbStockScript),
            InlinePayload = AvbStockScript
        },
        new PlannedEntry
        {
            Role = "boot",
            Path = "payload/boot.img",
            Bytes = TestPins.BootBytes,
            Sha256 = TestPins.BootSha256,
            FilePayload = bootPath
        },
        new PlannedEntry
        {
            Role = "toolbox",
            Path = "payload/toolbox.tar.gz",
            Bytes = TestPins.ToolboxBytes,
            Sha256 = TestPins.ToolboxSha256,
            FilePayload = toolboxPath
        }
    };

    internal static void WriteArchive(
        BundleWorkspace workspace,
        string profileId,
        string model,
        string androidBuild,
        IReadOnlyList<PlannedEntry> entries,
        int schemaVersion = TestPins.SchemaVersion)
    {
        var manifest = BuildManifest(schemaVersion, profileId, model, androidBuild, entries);

        using var file = new FileStream(workspace.ArchivePath, FileMode.Create, FileAccess.ReadWrite, FileShare.None);
        using var archive = new ZipArchive(file, ZipArchiveMode.Create, leaveOpen: true);

        var manifestEntry = archive.CreateEntry("manifest.json", CompressionLevel.NoCompression);
        using (var manifestStream = manifestEntry.Open())
        {
            manifestStream.Write(manifest, 0, manifest.Length);
        }

        foreach (var entry in entries)
        {
            if (!entry.IncludeInArchive)
            {
                continue;
            }

            var zipEntry = archive.CreateEntry(entry.Path, CompressionLevel.NoCompression);
            using var target = zipEntry.Open();
            if (entry.FilePayload is { } filePath)
            {
                using var source = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                source.CopyTo(target);
                continue;
            }

            var payload = entry.InlinePayload ?? Array.Empty<byte>();
            target.Write(payload, 0, payload.Length);
        }
    }

    private static byte[] BuildManifest(
        int schemaVersion,
        string profileId,
        string model,
        string androidBuild,
        IReadOnlyList<PlannedEntry> entries)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", schemaVersion);
            writer.WriteString("profileId", profileId);
            writer.WriteString("model", model);
            writer.WriteString("androidBuild", androidBuild);
            writer.WriteStartArray("entries");
            foreach (var entry in entries)
            {
                writer.WriteStartObject();
                writer.WriteString("role", entry.Role);
                writer.WriteString("path", entry.Path);
                writer.WriteNumber("bytes", entry.Bytes);
                writer.WriteString("sha256", entry.Sha256);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return buffer.ToArray();
    }
}

public sealed class MaintenanceBundleTests
{
    /// <summary>
    /// Catches a loader that never verifies digests, returns a profile other than the one
    /// declared, writes into the work root instead of a fresh unique child, or whose
    /// Dispose deletes the source archive, the work root, or sibling files such as the
    /// sentinel. Uses the real mounted pins; it is never skipped.
    /// </summary>
    [Fact]
    public async Task LoadAsync_WithRealPinnedAssets_ReturnsProfileAndAssets_AndDisposeRemovesOnlyStaging()
    {
        var assetRoot = TestPaths.AssetRoot;
        var bootPath = Path.Combine(assetRoot, "boot.img");
        var toolboxPath = Path.Combine(assetRoot, "installer-toolbox198.tar.gz");
        Assert.True(File.Exists(bootPath), "Manager mount is missing the real boot pin image: " + bootPath);
        Assert.True(File.Exists(toolboxPath), "Manager mount is missing the real toolbox pin archive: " + toolboxPath);

        using var workspace = BundleWorkspace.Create();
        BundleFixture.WriteArchive(
            workspace,
            TestPins.ProfileId,
            TestPins.Model,
            TestPins.AndroidBuild,
            BundleFixture.RealAssetEntries(bootPath, toolboxPath));

        Assert.Empty(Directory.GetDirectories(workspace.WorkRoot));
        var archiveLength = new FileInfo(workspace.ArchivePath).Length;

        using var archiveStream = new FileStream(workspace.ArchivePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var bundle = await MaintenanceBundle.LoadAsync(
            archiveStream,
            TestPins.Model,
            TestPins.AndroidBuild,
            workspace.WorkRoot,
            CancellationToken.None);

        var staging = bundle.StagingDirectory;
        Assert.False(string.IsNullOrWhiteSpace(staging));
        try
        {
            Assert.Equal(
                new MaintenanceProfile(TestPins.ProfileId, TestPins.Model, TestPins.AndroidBuild, TestPins.Soc),
                bundle.Profile);

            Assert.True(Directory.Exists(staging));
            Assert.Equal(
                Path.GetFullPath(workspace.WorkRoot),
                Path.GetFullPath(Path.GetDirectoryName(staging)!));
            Assert.Single(Directory.GetDirectories(workspace.WorkRoot));

            Assert.Equal(TestPins.BootBytes, bundle.GetAsset("boot").Bytes);
            Assert.Equal(TestPins.BootSha256, bundle.GetAsset("boot").Sha256);
            Assert.Equal(TestPins.ToolboxBytes, bundle.GetAsset("toolbox").Bytes);
            Assert.Equal(TestPins.ToolboxSha256, bundle.GetAsset("toolbox").Sha256);

            using (var boot = bundle.OpenAsset("boot"))
            {
                Assert.Equal(TestPins.BootBytes, boot.Length);
                Assert.True(boot.CanRead);
            }

            using (var toolbox = bundle.OpenAsset("toolbox"))
            {
                Assert.Equal(TestPins.ToolboxBytes, toolbox.Length);
                Assert.True(toolbox.CanRead);
            }

            Assert.Equal("scripts/avb_stock.py", bundle.GetAsset("avb").Path);
            Assert.Equal((long)BundleFixture.AvbStockScript.Length, bundle.GetAsset("avb").Bytes);
            Assert.Equal(BundleFixture.Sha256Hex(BundleFixture.AvbStockScript), bundle.GetAsset("avb").Sha256);

            using (var avb = bundle.OpenAsset("avb"))
            {
                Assert.Equal((long)BundleFixture.AvbStockScript.Length, avb.Length);
                Assert.True(avb.CanRead);
            }
        }
        finally
        {
            bundle.Dispose();
        }

        Assert.False(Directory.Exists(staging));
        Assert.Empty(Directory.GetDirectories(workspace.WorkRoot));
        Assert.True(File.Exists(workspace.ArchivePath));
        Assert.Equal(archiveLength, new FileInfo(workspace.ArchivePath).Length);
        Assert.True(archiveStream.CanRead);
        Assert.True(File.Exists(workspace.SentinelPath));
        Assert.Equal("sentinel", File.ReadAllText(workspace.SentinelPath));
    }

    /// <summary>
    /// Catches a loader that trusts the manifest profile or accepts a requested model that
    /// is merely nearby: the caller asks for TB323FU while the archive is TB322FC.
    /// </summary>
    [Fact]
    public async Task LoadAsync_WithDifferentRequestedModel_ThrowsModelMismatch()
    {
        using var workspace = BundleWorkspace.Create();
        BundleFixture.WriteArchive(
            workspace, TestPins.ProfileId, TestPins.Model, TestPins.AndroidBuild, BundleFixture.DefaultEntries());

        Assert.Equal(
            MaintenanceErrorCode.ModelMismatch,
            await LoadExpectingFailureAsync(workspace, TestPins.WrongModel, TestPins.AndroidBuild));
    }

    /// <summary>
    /// Catches a loader that resolves any self-consistent manifest: a G5 profile id with
    /// G4 asset pins must never be accepted.
    /// </summary>
    [Fact]
    public async Task LoadAsync_WithUnknownG5Profile_ThrowsUnsupportedProfile()
    {
        using var workspace = BundleWorkspace.Create();
        BundleFixture.WriteArchive(
            workspace, TestPins.UnknownProfileId, TestPins.Model, TestPins.AndroidBuild, BundleFixture.DefaultEntries());

        Assert.Equal(
            MaintenanceErrorCode.UnsupportedProfile,
            await LoadExpectingFailureAsync(workspace, TestPins.Model, TestPins.AndroidBuild));
    }

    /// <summary>Catches a loader that compares only the model and ignores the Android build string.</summary>
    [Fact]
    public async Task LoadAsync_WithDifferentRequestedBuild_ThrowsBuildMismatch()
    {
        using var workspace = BundleWorkspace.Create();
        BundleFixture.WriteArchive(
            workspace, TestPins.ProfileId, TestPins.Model, TestPins.AndroidBuild, BundleFixture.DefaultEntries());

        Assert.Equal(
            MaintenanceErrorCode.BuildMismatch,
            await LoadExpectingFailureAsync(workspace, TestPins.Model, TestPins.WrongAndroidBuild));
    }

    /// <summary>
    /// Catches a loader that joins manifest paths onto the staging root and only rejects
    /// traversal after something has already been written outside it.
    /// </summary>
    [Theory]
    [InlineData("../outside/helper.sh")]
    [InlineData("/etc/helper.sh")]
    [InlineData("scripts\\helper.sh")]
    [InlineData("./scripts/helper.sh")]
    public async Task LoadAsync_WithUnsafeEntryPath_ThrowsUnsafeEntry(string unsafePath)
    {
        using var workspace = BundleWorkspace.Create();
        var entries = BundleFixture.DefaultEntries();
        var index = entries.FindIndex(e => e.Role == "helper");
        entries[index] = entries[index] with { Path = unsafePath };
        BundleFixture.WriteArchive(workspace, TestPins.ProfileId, TestPins.Model, TestPins.AndroidBuild, entries);

        Assert.Equal(
            MaintenanceErrorCode.UnsafeEntry,
            await LoadExpectingFailureAsync(workspace, TestPins.Model, TestPins.AndroidBuild));
    }

    /// <summary>
    /// Catches a loader that indexes entries into a dictionary and silently keeps the last
    /// writer, or that compares paths case-sensitively on a case-insensitive filesystem.
    /// </summary>
    [Theory]
    [InlineData("role")]
    [InlineData("path")]
    [InlineData("path-case")]
    public async Task LoadAsync_WithDuplicateEntry_ThrowsDuplicateEntry(string mode)
    {
        using var workspace = BundleWorkspace.Create();
        var entries = BundleFixture.DefaultEntries();
        var bootIndex = entries.FindIndex(e => e.Role == "boot");
        var bootstrapIndex = entries.FindIndex(e => e.Role == "bootstrap");

        switch (mode)
        {
            case "role":
                entries.Add(entries[bootIndex] with { Path = "payload/boot-copy.img" });
                break;
            case "path":
                entries[bootstrapIndex] = entries[bootstrapIndex] with { Path = "scripts/helper.sh" };
                break;
            default:
                entries[bootstrapIndex] = entries[bootstrapIndex] with { Path = "Scripts/HELPER.sh" };
                break;
        }

        BundleFixture.WriteArchive(workspace, TestPins.ProfileId, TestPins.Model, TestPins.AndroidBuild, entries);

        Assert.Equal(
            MaintenanceErrorCode.DuplicateEntry,
            await LoadExpectingFailureAsync(workspace, TestPins.Model, TestPins.AndroidBuild));
    }

    /// <summary>
    /// Catches a loader that only validates the roles it happens to look up, so a manifest
    /// that omits helper or avb (or references a file the archive never stores) still succeeds.
    /// </summary>
    [Theory]
    [InlineData("role")]
    [InlineData("file")]
    [InlineData("avb-role")]
    [InlineData("avb-file")]
    public async Task LoadAsync_WithMissingAsset_ThrowsMissingAsset(string mode)
    {
        using var workspace = BundleWorkspace.Create();
        var entries = BundleFixture.DefaultEntries();
        var targetRole = mode.StartsWith("avb", StringComparison.Ordinal) ? "avb" : "helper";
        var targetIndex = entries.FindIndex(e => e.Role == targetRole);

        if (mode.EndsWith("role", StringComparison.Ordinal))
        {
            entries.RemoveAt(targetIndex);
        }
        else
        {
            entries[targetIndex] = entries[targetIndex] with { IncludeInArchive = false };
        }

        BundleFixture.WriteArchive(workspace, TestPins.ProfileId, TestPins.Model, TestPins.AndroidBuild, entries);

        Assert.Equal(
            MaintenanceErrorCode.MissingAsset,
            await LoadExpectingFailureAsync(workspace, TestPins.Model, TestPins.AndroidBuild));
    }

    /// <summary>
    /// Catches a loader that accepts whatever digest the manifest declares instead of
    /// comparing boot against the reviewed pin for the fixed production profile.
    /// </summary>
    [Fact]
    public async Task LoadAsync_WithWrongDeclaredBootPin_ThrowsUnsupportedProfile()
    {
        using var workspace = BundleWorkspace.Create();
        var entries = BundleFixture.DefaultEntries();
        var bootIndex = entries.FindIndex(e => e.Role == "boot");
        entries[bootIndex] = entries[bootIndex] with { Sha256 = new string('0', 64) };
        BundleFixture.WriteArchive(workspace, TestPins.ProfileId, TestPins.Model, TestPins.AndroidBuild, entries);

        Assert.Equal(
            MaintenanceErrorCode.UnsupportedProfile,
            await LoadExpectingFailureAsync(workspace, TestPins.Model, TestPins.AndroidBuild));
    }

    /// <summary>
    /// Catches a loader that hashes the bytes it read without comparing the read length to
    /// the declared length, so a truncated script is accepted and later fails at runtime.
    /// Validates the tiny scripts before the large payloads, leaving no staging residue.
    /// </summary>
    [Fact]
    public async Task LoadAsync_WithWrongDeclaredScriptLength_ThrowsAssetSizeMismatch()
    {
        using var workspace = BundleWorkspace.Create();
        var entries = BundleFixture.DefaultEntries();
        var bootstrapIndex = entries.FindIndex(e => e.Role == "bootstrap");
        entries[bootstrapIndex] = entries[bootstrapIndex] with
        {
            Bytes = BundleFixture.BootstrapScript.Length + 7
        };
        BundleFixture.WriteArchive(workspace, TestPins.ProfileId, TestPins.Model, TestPins.AndroidBuild, entries);

        Assert.Equal(
            MaintenanceErrorCode.AssetSizeMismatch,
            await LoadExpectingFailureAsync(workspace, TestPins.Model, TestPins.AndroidBuild));
        AssertNoStagingResidue(workspace);
    }

    /// <summary>
    /// Catches a loader that trusts the manifest for content after checking size only, or
    /// that never hashes anything smaller than boot/toolbox. Validates small scripts first
    /// and leaves no staging residue behind.
    /// </summary>
    [Fact]
    public async Task LoadAsync_WithWrongDeclaredScriptHash_ThrowsAssetHashMismatch()
    {
        using var workspace = BundleWorkspace.Create();
        var entries = BundleFixture.DefaultEntries();
        var bootstrapIndex = entries.FindIndex(e => e.Role == "bootstrap");
        entries[bootstrapIndex] = entries[bootstrapIndex] with { Sha256 = new string('b', 64) };
        BundleFixture.WriteArchive(workspace, TestPins.ProfileId, TestPins.Model, TestPins.AndroidBuild, entries);

        Assert.Equal(
            MaintenanceErrorCode.AssetHashMismatch,
            await LoadExpectingFailureAsync(workspace, TestPins.Model, TestPins.AndroidBuild));
        AssertNoStagingResidue(workspace);
    }

    private static async Task<MaintenanceErrorCode> LoadExpectingFailureAsync(
        BundleWorkspace workspace,
        string expectedModel,
        string expectedBuild)
    {
        using var archiveStream = new FileStream(
            workspace.ArchivePath, FileMode.Open, FileAccess.Read, FileShare.Read);

        var exception = await Assert.ThrowsAsync<MaintenanceException>(() => MaintenanceBundle.LoadAsync(
            archiveStream,
            expectedModel,
            expectedBuild,
            workspace.WorkRoot,
            CancellationToken.None));

        return exception.Code;
    }

    private static void AssertNoStagingResidue(BundleWorkspace workspace)
    {
        Assert.Empty(Directory.GetDirectories(workspace.WorkRoot));
        Assert.True(Directory.Exists(workspace.Root));
        Assert.True(File.Exists(workspace.SentinelPath));
        Assert.Equal("sentinel", File.ReadAllText(workspace.SentinelPath));
    }
}
