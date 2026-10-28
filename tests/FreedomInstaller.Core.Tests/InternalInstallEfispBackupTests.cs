using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// EFISP-A2: RED behaviour tests for the optional <c>efisp</c> capture role.
/// The toolchains, reader and capture pipeline are the production ones; only the external process boundary
/// and the USB endpoint enumeration are faked and every device table is synthetic (IB001 fixture).
/// No real device dump, serial, backup image or partition table is involved.
/// </summary>
public sealed class InternalInstallEfispBackupTests : IClassFixture<EdlClientToolchainFixture>, IClassFixture<Gen5EdlToolchainFixture>
{
    private const string EfispRole = "efisp";
    private const string UnknownRole = "efisp_unknown";
    private const string BootPartitionRole = "boot_b";
    private const string GptLun4Role = "gpt_lun4_primary";
    private const long EfispLength = 3145728;
    private const string SidecarSuffix = ".sha256";
    private const long TwoGiB = 2L * 1024 * 1024 * 1024;

    private readonly EdlClientToolchainFixture _g4;
    private readonly Gen5EdlToolchainFixture _g5;

    public InternalInstallEfispBackupTests(EdlClientToolchainFixture g4, Gen5EdlToolchainFixture g5)
    {
        _g4 = g4;
        _g5 = g5;
    }

    // 1. Fresh capture of the optional efisp role, then reopen reuses it without touching the device.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Create_CapturesOptionalEfisp_AndOpenExistingReusesIt(bool gen5)
    {
        int expectedBase = BaseRoleCount(gen5);
        (EdlToolchain toolchain, string root) = Chosen(gen5, nameof(Create_CapturesOptionalEfisp_AndOpenExistingReusesIt));
        IB001SyntheticDevice device = IB001SyntheticDevice.Create(gen5: gen5, includeEfisp: true, efispLun: 4);
        (EdlClient createClient, IB001FakeEdlRunner createRunner) = NewClient(toolchain, device);

        (int lun, long start, long count, string partUuid) = device.Expectation(EfispRole);
        ProgressCollector progress = new();
        string backupDirectory = Path.Combine(root, "backup");
        Directory.CreateDirectory(backupDirectory);

        string efispSha;
        string directoryPath;
        using (InternalBackupSet set = await InternalInstallBackup.CreateAsync(
                   createClient, backupDirectory, progress, CancellationToken.None))
        {
            Assert.True(set.Files.Count == expectedBase + 1,
                $"Expected {expectedBase + 1} captured roles (base {expectedBase} plus efisp), got {set.Files.Count}.");
            Assert.True(set.Files.ContainsKey(EfispRole), "The freshly captured set must expose the efisp role.");

            EdlCapturedRegion efisp = set.Files[EfispRole];
            Assert.Equal(EfispRole, efisp.Role);
            Assert.Equal(4, efisp.Lun);
            Assert.Equal(lun, efisp.Lun);
            Assert.Equal(start, efisp.StartSector);
            Assert.Equal(count, efisp.SectorCount);
            Assert.Equal(partUuid, efisp.PartUuid);
            Assert.Equal(EfispLength, efisp.Length);
            Assert.Equal(EfispLength, new FileInfo(efisp.FilePath).Length);
            Assert.Equal(efisp.Sha256, Sha256File(efisp.FilePath), ignoreCase: true);

            Assert.True(progress.Items.Count > 0, "Capture must report progress.");
            InternalBackupProgress last = progress.Items[progress.Items.Count - 1];
            Assert.Equal(expectedBase + 1, last.CompletedFiles);
            Assert.Equal(expectedBase + 1, last.TotalFiles);

            efispSha = efisp.Sha256;
            directoryPath = set.DirectoryPath;
        }

        (EdlClient openClient, IB001FakeEdlRunner openRunner) = NewClient(toolchain, device);
        using InternalBackupSet reopened = await InternalInstallBackup.OpenExistingAsync(
            openClient, directoryPath, null, CancellationToken.None);

        Assert.Equal(expectedBase + 1, reopened.Files.Count);
        Assert.True(reopened.Files.ContainsKey(EfispRole),
            "OpenExisting must expose the previously captured efisp role.");
        Assert.Equal(efispSha, reopened.Files[EfispRole].Sha256, ignoreCase: true);
        Assert.Equal(6, openRunner.ProbedLuns.Distinct().Count());
        Assert.Empty(openRunner.Reads);
        Assert.Equal(0, openRunner.WriteOrResetCount);
    }

    // 2. Without the optional role the capture stays at the base count and still reopens cleanly.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Create_WithoutEfisp_StaysAtBaseAndReopens(bool gen5)
    {
        int expectedBase = BaseRoleCount(gen5);
        (EdlToolchain toolchain, string root) = Chosen(gen5, nameof(Create_WithoutEfisp_StaysAtBaseAndReopens));
        IB001SyntheticDevice device = IB001SyntheticDevice.Create(gen5: gen5, includeEfisp: false);
        (EdlClient createClient, _) = NewClient(toolchain, device);

        string backupDirectory = Path.Combine(root, "backup");
        Directory.CreateDirectory(backupDirectory);

        string directoryPath;
        using (InternalBackupSet set = await InternalInstallBackup.CreateAsync(
                   createClient, backupDirectory, null, CancellationToken.None))
        {
            Assert.Equal(expectedBase, set.Files.Count);
            Assert.False(set.Files.ContainsKey(EfispRole), "No efisp role may be invented when the device has none.");
            directoryPath = set.DirectoryPath;
        }

        (EdlClient openClient, IB001FakeEdlRunner openRunner) = NewClient(toolchain, device);
        using InternalBackupSet reopened = await InternalInstallBackup.OpenExistingAsync(
            openClient, directoryPath, null, CancellationToken.None);

        Assert.Equal(expectedBase, reopened.Files.Count);
        Assert.False(reopened.Files.ContainsKey(EfispRole));
        Assert.Equal(0, openRunner.WriteOrResetCount);
    }

    // 3. Legacy (non-GBL) shape: a manifest that predates the optional role is still reusable.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OpenExisting_WithoutEfispEntry_AcceptsLegacyShape(bool gen5)
    {
        int expectedBase = BaseRoleCount(gen5);
        (EdlToolchain toolchain, string root) = Chosen(gen5, nameof(OpenExisting_WithoutEfispEntry_AcceptsLegacyShape));
        IB001SyntheticDevice device = IB001SyntheticDevice.Create(gen5: gen5, includeEfisp: true, efispLun: 4);
        (EdlClient createClient, _) = NewClient(toolchain, device);

        string backupDirectory = Path.Combine(root, "backup");
        Directory.CreateDirectory(backupDirectory);

        string directoryPath;
        string manifestPath;
        string sidecarPath;
        string? efispPath = null;
        long efispFileLength = 0;
        bool gptStillNamesEfisp;

        using (InternalBackupSet set = await InternalInstallBackup.CreateAsync(
                   createClient, backupDirectory, null, CancellationToken.None))
        {
            // Old production may ignore efisp, so its presence is optional here; the saved GPT is not.
            if (set.Files.TryGetValue(EfispRole, out EdlCapturedRegion captured))
            {
                efispPath = captured.FilePath;
                efispFileLength = captured.Length;
            }

            Assert.True(set.Files.ContainsKey(GptLun4Role), "The synthetic device must capture the LUN4 GPT.");
            byte[] gptBytes = File.ReadAllBytes(set.Files[GptLun4Role].FilePath);
            gptStillNamesEfisp = gptBytes.AsSpan().IndexOf(Encoding.Unicode.GetBytes(EfispRole)) >= 0;

            directoryPath = set.DirectoryPath;
            manifestPath = set.ManifestPath;
            sidecarPath = manifestPath + SidecarSuffix;
        }

        // Remove efisp only when this production recorded it; never require its removal.
        RewriteManifest(manifestPath, manifest => RemoveRoleEntries(manifest, EfispRole));

        if (efispPath is not null)
        {
            Assert.True(File.Exists(efispPath), "Trimming the manifest must not delete captured user files.");
            Assert.Equal(efispFileLength, new FileInfo(efispPath).Length);
        }

        Assert.True(gptStillNamesEfisp, "The saved GPT of the synthetic device must keep naming the efisp partition.");

        string manifestHashBefore = Sha256File(manifestPath);
        string sidecarHashBefore = Sha256File(sidecarPath);

        (EdlClient openClient, IB001FakeEdlRunner openRunner) = NewClient(toolchain, device);
        using InternalBackupSet reopened = await InternalInstallBackup.OpenExistingAsync(
            openClient, directoryPath, null, CancellationToken.None);

        Assert.Equal(expectedBase, reopened.Files.Count);
        Assert.False(reopened.Files.ContainsKey(EfispRole),
            "A legacy manifest without efisp must reopen at the base count.");
        Assert.Equal(0, openRunner.WriteOrResetCount);
        Assert.Equal(manifestHashBefore, Sha256File(manifestPath), ignoreCase: true);
        Assert.Equal(sidecarHashBefore, Sha256File(sidecarPath), ignoreCase: true);
    }

    // 4. Duplicate or misplaced efisp partitions are rejected before any partition read.
    [Theory]
    [InlineData("duplicate")]
    [InlineData("wrong-lun")]
    public async Task Create_RejectsDuplicateOrWrongLunEfisp(string shape)
    {
        (EdlToolchain toolchain, string root) = Chosen(true, nameof(Create_RejectsDuplicateOrWrongLunEfisp));
        IB001SyntheticDevice device = string.Equals(shape, "duplicate", StringComparison.Ordinal)
            ? IB001SyntheticDevice.Create(gen5: true, includeEfisp: true, duplicateRole: EfispRole)
            : IB001SyntheticDevice.Create(gen5: true, includeEfisp: true, efispLun: 0);
        (EdlClient client, IB001FakeEdlRunner runner) = NewClient(toolchain, device);

        string backupDirectory = Path.Combine(root, shape);
        Directory.CreateDirectory(backupDirectory);
        Exception failure = await CaptureFailure(() => InternalInstallBackup.CreateAsync(
            client, backupDirectory, null, CancellationToken.None));

        Assert.True(failure is InvalidDataException || failure is InvalidOperationException,
            $"Duplicate or misplaced efisp must be a business rejection, got {failure.GetType().Name}: {failure.Message}");
        Assert.Equal(12, runner.Reads.Count);
        Assert.Equal(0, runner.WriteOrResetCount);
    }

    // 5. Tampered extent, tampered payload or an unknown role is rejected on reuse.
    [Theory]
    [InlineData("extent")]
    [InlineData("hash")]
    [InlineData("role")]
    public async Task OpenExisting_RejectsTamperedEfisp(string tamper)
    {
        (EdlToolchain toolchain, string root) = Chosen(true, nameof(OpenExisting_RejectsTamperedEfisp));
        IB001SyntheticDevice device = IB001SyntheticDevice.Create(gen5: true, includeEfisp: true, efispLun: 4);
        (EdlClient createClient, _) = NewClient(toolchain, device);

        string backupDirectory = Path.Combine(root, tamper);
        Directory.CreateDirectory(backupDirectory);

        string directoryPath;
        string manifestPath;
        string efispPath;
        long efispLength;

        using (InternalBackupSet set = await InternalInstallBackup.CreateAsync(
                   createClient, backupDirectory, null, CancellationToken.None))
        {
            Assert.True(set.Files.ContainsKey(EfispRole), "The tamper cases require a captured efisp role first.");

            EdlCapturedRegion efisp = set.Files[EfispRole];
            efispPath = efisp.FilePath;
            efispLength = efisp.Length;
            directoryPath = set.DirectoryPath;
            manifestPath = set.ManifestPath;
        }

        bool mutated = tamper switch
        {
            "extent" => RewriteManifest(manifestPath, manifest => MutateEfispEntry(manifest, entry =>
            {
                long start = entry["startSector"]!.GetValue<long>();
                entry["startSector"] = start + 1;
            })),
            "role" => RewriteManifest(manifestPath, manifest => MutateEfispEntry(manifest, entry =>
            {
                entry["role"] = UnknownRole;
            })),
            _ => false,
        };

        if (string.Equals(tamper, "hash", StringComparison.Ordinal))
        {
            FlipLastByte(efispPath);
        }
        else
        {
            Assert.True(mutated, "The self-owned synthetic manifest must contain an efisp entry to mutate.");
        }

        (EdlClient openClient, IB001FakeEdlRunner openRunner) = NewClient(toolchain, device);
        Exception failure = await CaptureFailure(() => InternalInstallBackup.OpenExistingAsync(
            openClient, directoryPath, null, CancellationToken.None));

        Assert.True(failure is InvalidDataException || failure is InvalidOperationException,
            $"Tampered efisp ({tamper}) must be a business rejection, got {failure.GetType().Name}: {failure.Message}");
        Assert.Equal(0, openRunner.WriteOrResetCount);
        Assert.Equal(efispLength, new FileInfo(efispPath).Length);
    }

    // 6. A missing required role can never be excused by a matching file count.
    [Fact]
    public async Task OpenExisting_RejectsMissingRequiredRole_EvenWhenCountMatches()
    {
        (EdlToolchain toolchain, string root) = Chosen(true, nameof(OpenExisting_RejectsMissingRequiredRole_EvenWhenCountMatches));
        IB001SyntheticDevice device = IB001SyntheticDevice.Create(gen5: true, includeEfisp: true, efispLun: 4);
        (EdlClient createClient, _) = NewClient(toolchain, device);

        string backupDirectory = Path.Combine(root, "backup");
        Directory.CreateDirectory(backupDirectory);

        string directoryPath;
        string manifestPath;
        using (InternalBackupSet set = await InternalInstallBackup.CreateAsync(
                   createClient, backupDirectory, null, CancellationToken.None))
        {
            Assert.True(set.Files.ContainsKey(EfispRole), "The device captures efisp, so the base set is complete plus efisp.");
            Assert.Equal(BaseRoleCount(true) + 1, set.Files.Count);

            directoryPath = set.DirectoryPath;
            manifestPath = set.ManifestPath;
        }

        bool removed = RewriteManifest(manifestPath, manifest => RemoveRoleEntries(manifest, BootPartitionRole));
        Assert.True(removed, "The self-owned synthetic manifest must contain the boot_b entry to remove.");

        (EdlClient openClient, IB001FakeEdlRunner openRunner) = NewClient(toolchain, device);
        Exception failure = await CaptureFailure(() => InternalInstallBackup.OpenExistingAsync(
            openClient, directoryPath, null, CancellationToken.None));

        Assert.True(failure is InvalidDataException || failure is InvalidOperationException,
            $"A missing required role must be a business rejection, got {failure.GetType().Name}: {failure.Message}");
        Assert.Equal(0, openRunner.WriteOrResetCount);
    }

    // 7. Gen5 archive layout: efisp appears exactly once in the board archive, without inflating usage.
    [Fact]
    public async Task Archive_PlacesEfispExactlyOnce_AndKeepsUsageBounded()
    {
        (EdlToolchain toolchain, string root) = Chosen(true, nameof(Archive_PlacesEfispExactlyOnce_AndKeepsUsageBounded));
        IB001SyntheticDevice device = IB001SyntheticDevice.Create(
            gen5: true, includeEfisp: true, efispLun: 4, archiveLayout: true);
        (EdlClient createClient, _) = NewClient(toolchain, device);

        string backupDirectory = Path.Combine(root, "backup");
        Directory.CreateDirectory(backupDirectory);
        string artifactRoot = Path.Combine(root, "artifacts");
        Directory.CreateDirectory(artifactRoot);

        using InternalBackupSet set = await InternalInstallBackup.CreateAsync(
            createClient, backupDirectory, null, CancellationToken.None);

        Assert.True(set.Files.ContainsKey(EfispRole), "The archive case requires a captured efisp role.");
        Assert.Equal(48, set.Files.Count);

        string efispSha = set.Files[EfispRole].Sha256;
        string model = set.Model;

        using InternalArtifactSet artifacts = await InternalInstallArtifacts.PrepareAsync(
            set, 16, new PackageStorage(1L << 30, 8L << 30, 4L << 30, 1L << 30), artifactRoot, CancellationToken.None);

        Assert.True(artifacts.SummaryUsedBytes < TwoGiB,
            $"Summary used bytes must stay below 2 GiB, got {artifacts.SummaryUsedBytes}.");
        Assert.Equal(TwoGiB, artifacts.BoardSummary.Length);

        using FileStream board = new(artifacts.BoardSummary.FilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        JsonElement boardJson = VerifyBoardArchive(board, model, CancellationToken.None);

        Assert.True(boardJson.TryGetProperty("entries", out JsonElement entries),
            "The board archive must expose an 'entries' array.");
        Assert.Equal(52, entries.GetArrayLength());

        JsonElement? efispEntry = null;
        foreach (JsonElement entry in entries.EnumerateArray())
        {
            if (!entry.TryGetProperty("role", out JsonElement role) || role.ValueKind != JsonValueKind.String)
            {
                continue;
            }

            if (!string.Equals(role.GetString(), EfispRole, StringComparison.Ordinal))
            {
                continue;
            }

            Assert.True(efispEntry is null, "efisp must appear exactly once in the board archive.");
            efispEntry = entry;
        }

        Assert.True(efispEntry is not null, "efisp must appear in the board archive.");
        JsonElement efispJson = efispEntry!.Value;
        Assert.Equal(EfispRole, efispJson.GetProperty("role").GetString());
        Assert.Equal("efisp.bin", efispJson.GetProperty("path").GetString());
        Assert.Equal(EfispLength, efispJson.GetProperty("length").GetInt64());
        Assert.Equal(efispSha, efispJson.GetProperty("sha256").GetString(), ignoreCase: true);
    }

    // ---- helpers -------------------------------------------------------

    private static int BaseRoleCount(bool gen5) => gen5 ? 47 : 51;

    private (EdlToolchain Toolchain, string Root) Chosen(bool gen5, string testName) => gen5
        ? (_g5.Toolchain, _g5.NewCaseDirectory(testName))
        : (_g4.Toolchain, _g4.NewCaseDirectory(testName));

    private static (EdlClient Client, IB001FakeEdlRunner Runner) NewClient(
        EdlToolchain toolchain, IB001SyntheticDevice device)
    {
        IB001FakeEdlRunner runner = new(device, hardwareId: toolchain.HardwareId);
        EdlClient client = new(
            toolchain,
            NewBinding(toolchain),
            runner,
            new E003ScriptedEndpointDiscovery { Endpoints = new[] { E003EdlTestData.Endpoint() } });
        return (client, runner);
    }

    /// <summary>Synthetic identity: no real serial, endpoint or dump is used.</summary>
    private static EdlEntryResult NewBinding(EdlToolchain toolchain)
    {
        bool gen5 = string.Equals(toolchain.Model, "TB323FU", StringComparison.Ordinal);

        return new(
            new AndroidMaintenanceIdentity(
                new DeviceIdentity(E003EdlTestData.SocSerialDecimal, toolchain.Model, BootloaderState.Unknown)
                {
                    Firmware = new FirmwareSnapshot(
                        gen5
                            ? "TB323FU_CN_OPEN_USER_Q00020.0_A16_ZUXOS_2.0.11.043_ST_260309"
                            : MaintenanceProfiles.AndroidBuild,
                        BuildFingerprint: "synthetic/efisp-backup-test/" + toolchain.Model,
                        AndroidRelease: gen5 ? "16" : "15",
                        SecurityPatch: "2026-01-01",
                        AndroidReportedBootloaderState: BootloaderState.Locked),
                },
                E003EdlTestData.SocSerialDecimal),
            E003EdlTestData.Endpoint(),
            E003EdlTestData.BusSerialHex);
    }

    private static async Task<Exception> CaptureFailure(Func<Task> action)
    {
        Exception? failure = await Record.ExceptionAsync(action);
        Assert.True(failure is not null, "Expected a business rejection but the operation succeeded.");
        return failure!;
    }

    private static string Sha256File(string path)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void FlipLastByte(string path)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        Assert.True(stream.Length > 0, "The captured efisp file must not be empty.");
        stream.Seek(-1, SeekOrigin.End);
        int value = stream.ReadByte();
        Assert.True(value >= 0, "The captured efisp file must be readable.");
        stream.Seek(-1, SeekOrigin.End);
        stream.WriteByte((byte)(value ^ 0xFF));
        stream.Flush(true);
    }

    private static bool RewriteManifest(string manifestPath, Func<JsonObject, bool> mutate)
    {
        JsonObject root = JsonNode.Parse(File.ReadAllText(manifestPath))!.AsObject();
        bool result = mutate(root);

        byte[] bytes = Encoding.UTF8.GetBytes(root.ToJsonString());
        using (FileStream stream = new(manifestPath, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            stream.Write(bytes, 0, bytes.Length);
            stream.Flush(true);
        }

        File.WriteAllBytes(
            manifestPath + SidecarSuffix,
            Encoding.ASCII.GetBytes(Convert.ToHexString(SHA256.HashData(bytes)) + "\n"));
        return result;
    }

    private static bool RemoveRoleEntries(JsonObject root, string role)
    {
        if (root["files"] is not JsonArray files)
        {
            return false;
        }

        int removed = 0;
        for (int i = files.Count - 1; i >= 0; i--)
        {
            if (TryReadRole(files[i], role))
            {
                files.RemoveAt(i);
                removed++;
            }
        }

        return removed > 0;
    }

    private static bool MutateEfispEntry(JsonObject root, Action<JsonObject> mutate)
    {
        if (root["files"] is not JsonArray files)
        {
            return false;
        }

        foreach (JsonNode? node in files)
        {
            if (!TryReadRole(node, EfispRole) || node is not JsonObject entry)
            {
                continue;
            }

            mutate(entry);
            return true;
        }

        return false;
    }

    // Exact case: the manifest schema is files -> { role, ... }.
    private static bool TryReadRole(JsonNode? node, string role) =>
        node is JsonObject entry &&
        entry["role"] is JsonValue value &&
        value.TryGetValue(out string? text) &&
        string.Equals(text, role, StringComparison.Ordinal);

    private static JsonElement VerifyBoardArchive(Stream stream, string model, CancellationToken token)
    {
        MethodInfo? method = typeof(InternalInstallArtifacts).GetMethod(
            "VerifyBoardArchive",
            BindingFlags.Static | BindingFlags.NonPublic,
            binder: null,
            types: new[] { typeof(Stream), typeof(string), typeof(CancellationToken) },
            modifiers: null);

        Assert.True(method is not null, "VerifyBoardArchive(Stream,string,CancellationToken) must exist.");

        try
        {
            object? result = method!.Invoke(null, new object?[] { stream, model, token });
            return Assert.IsType<JsonElement>(result);
        }
        catch (TargetInvocationException ex) when (ex.InnerException is not null)
        {
            throw ex.InnerException!;
        }
    }

    private sealed class ProgressCollector : IProgress<InternalBackupProgress>
    {
        private readonly List<InternalBackupProgress> _items = new();

        public IReadOnlyList<InternalBackupProgress> Items
        {
            get
            {
                lock (_items)
                {
                    return _items.ToArray();
                }
            }
        }

        public void Report(InternalBackupProgress value)
        {
            lock (_items)
            {
                _items.Add(value);
            }
        }
    }
}
