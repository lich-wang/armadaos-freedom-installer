// real-native tests for the template Android-base replacement primitive. Reuses the
// existing EdlRawGblEnvelopeTests.SharedFixture (loaded pins, Linux oracle runner, one genuine built
// project 7-entry menu). Every case drives the internal method through a narrow reflection adapter;
// no mock packer, no stub assertions and no new trust interface. Nothing here is an OEM, loader,
// hardware or TF acceptance statement: the extra eighth blob in case B is synthetic test material.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class BootMaintenanceMenuTemplateTests : IClassFixture<EdlRawGblEnvelopeTests.SharedFixture>
{
    private const string BaseImageName = "BaseImage";

    private const string ConfigName = "config.cfg";

    private const string RepackedName = "RepackedKernel";

    private static readonly TimeSpan NativeTimeout = TimeSpan.FromMinutes(3);

    private static readonly UTF8Encoding ConfigUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private static readonly MethodInfo ReplaceTemplateMethod = typeof(EdlRawBootBuilder).GetMethod(
        "ReplaceTemplateAndroidBaseAsync", BindingFlags.NonPublic | BindingFlags.Static)
        ?? throw new InvalidOperationException("ReplaceTemplateAndroidBaseAsync was not found");

    private static readonly MethodInfo RepackEnvelopeMethod = typeof(EdlRawBootBuilder).GetMethod(
        "RepackEnvelopeAsync", BindingFlags.NonPublic | BindingFlags.Static)
        ?? throw new InvalidOperationException("RepackEnvelopeAsync was not found");

    private static readonly MethodInfo ExportBaseMethod = typeof(InternalSlotMaterialReader).GetMethod(
        "AnalyzeAndExportBaseAsync", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static)
        ?? throw new InvalidOperationException("AnalyzeAndExportBaseAsync was not found");

    private readonly EdlRawGblEnvelopeTests.SharedFixture fx;

    public BootMaintenanceMenuTemplateTests(EdlRawGblEnvelopeTests.SharedFixture fixture) => fx = fixture;

    // ------------------------------------------------------------------ case A

    [Fact]
    public async Task ReplaceTemplate_StandardSevenMenu_PreservesMenuAndSwapsOnlyBase()
    {
        using var workspace = new EdlRawBootBuilderTests.Workspace();
        VerifiedEdlFile replacement = await ExportSlotBaseAsync(workspace, "a", 0x52);

        int callsBefore = fx.Runner.Calls;
        object result = await InvokeReplaceAsync(
            fx.NormalBuilt.CandidateBoot, replacement,
            fx.NormalBuilt.SlotMaterial.LoaderBudget.MaxRawBytes, workspace.Root);
        // Guarantees owned child disposal even if a later assertion fails; the explicit
        // idempotence assertions below stay and the final using dispose is a safe no-op.
        using IDisposable resultOwner = (IDisposable)result;
        int primitiveCalls = fx.Runner.Calls - callsBefore;
        Assert.Equal(3, primitiveCalls);

        string templateSha = Sha256OfFile(fx.NormalBuilt.CandidateBoot.Path);
        Assert.Equal(templateSha, GetString(result, "TemplateBootSha256"));
        Assert.Equal(replacement.Sha256, GetString(result, "ReplacementBaseSha256"));
        Assert.Equal(7u, GetUInt(result, "EntryCount"));
        Assert.Equal(1u, GetUInt(result, "DefaultIndex"));

        var packed = (VerifiedEdlFile)Get(result, "PackedRaw");
        Assert.True(File.Exists(packed.Path));
        Assert.Equal(replacement.Sha256, GetString(result, "ReplacementBaseSha256"));

        // Independent native unpack of the original template raw for the comparison baseline.
        string originalDir = Path.Combine(workspace.Root, "baseline-unpack");
        Directory.CreateDirectory(originalDir);
        await UnpackNativeAsync(fx.NormalBuilt.PackedRaw.Path, originalDir);

        // Independent native unpack of the returned packed raw in a separate owned directory.
        string unpackDir = Path.Combine(workspace.Root, "result-unpack");
        Directory.CreateDirectory(unpackDir);
        string rawCopy = Path.Combine(workspace.Root, "result.raw");
        File.Copy(packed.Path, rawCopy, overwrite: true);
        await UnpackNativeAsync(rawCopy, unpackDir);
        Assert.True(fx.Runner.Calls > callsBefore, "the unpack ran through the real native runner");

        string[] originalConfig = ReadConfigLines(Path.Combine(originalDir, ConfigName));
        string[] newConfig = ReadConfigLines(Path.Combine(unpackDir, ConfigName));
        Assert.Equal(originalConfig.Length, newConfig.Length);
        for (int index = 0; index < originalConfig.Length; index++)
        {
            Assert.Equal(originalConfig[index], newConfig[index]);
        }

        var baseline = HashPayloads(originalDir);
        var actual = HashPayloads(unpackDir);
        Assert.Equal(baseline.Count, actual.Count);
        foreach (KeyValuePair<string, (long Length, string Sha256)> entry in baseline)
        {
            Assert.True(actual.ContainsKey(entry.Key), entry.Key);
            if (string.Equals(entry.Key, BaseImageName, StringComparison.Ordinal))
            {
                Assert.Equal(replacement.Length, actual[entry.Key].Length);
                Assert.Equal(replacement.Sha256, actual[entry.Key].Sha256);
            }
            else
            {
                Assert.Equal(entry.Value.Length, actual[entry.Key].Length);
                Assert.Equal(entry.Value.Sha256, actual[entry.Key].Sha256);
            }
        }

        Assert.Equal(baseline[BaseImageName].Sha256, GetString(result, "OriginalBaseSha256"));

        var preserved = (IReadOnlyDictionary<string, string>)Get(result, "PreservedPayloadSha256");
        Assert.Equal(baseline.Count - 1, preserved.Count);
        Assert.False(preserved.ContainsKey(BaseImageName));
        foreach (KeyValuePair<string, string> entry in preserved)
        {
            Assert.Equal(baseline[entry.Key].Sha256, entry.Value);
        }

        var report = (VerifiedEdlFile)Get(result, "VerificationReport");
        Assert.True(File.Exists(report.Path));

        // Dispose removes exactly its own child; inputs, the parent and shared fixtures stay.
        string directoryPath = GetString(result, "DirectoryPath");
        Assert.True(Directory.Exists(directoryPath));
        ((IDisposable)result).Dispose();
        ((IDisposable)result).Dispose();
        Assert.False(Directory.Exists(directoryPath));
        Assert.True(Directory.Exists(workspace.Root));
        Assert.True(File.Exists(fx.NormalBuilt.CandidateBoot.Path));
        Assert.Equal(templateSha, Sha256OfFile(fx.NormalBuilt.CandidateBoot.Path));
        Assert.Equal(replacement.Sha256, Sha256OfFile(replacement.Path));
    }

    // ------------------------------------------------------------------ case B

    [Fact]
    public async Task ReplaceTemplate_ExtraEighthBlobEntry_PreservesAllEight()
    {
        using var workspace = new EdlRawBootBuilderTests.Workspace();

        // Genuine native unpack of the built raw, then one extra Blob payload + config entry
        // in the native style, inserted before [Manifest].
        string sourceDir = Path.Combine(workspace.Root, "eight-src");
        Directory.CreateDirectory(sourceDir);
        string rawCopy = Path.Combine(workspace.Root, "seven.raw");
        File.Copy(fx.NormalBuilt.PackedRaw.Path, rawCopy, overwrite: true);
        await UnpackNativeAsync(rawCopy, sourceDir);

        string configPath = Path.Combine(sourceDir, ConfigName);
        string[] lines = ReadConfigLines(configPath);
        byte[] extraBytes = new byte[96];
        for (int index = 0; index < extraBytes.Length; index++)
        {
            extraBytes[index] = (byte)(0x52 + index);
        }

        string extraPayloadName = "Image-07-Extra";
        string utf8Label = "额外-Image-07";
        string extraSha = Sha256Of(extraBytes);
        File.WriteAllBytes(Path.Combine(sourceDir, extraPayloadName), extraBytes);
        string[] eightConfig = BuildEightEntryConfig(lines, extraPayloadName, utf8Label);
        File.WriteAllBytes(configPath, ConfigUtf8.GetBytes(string.Join("\n", eightConfig)));

        var packCommand = new ProcessCommand(
            fx.Tools.Packer.Path, new[] { ConfigName }, NativeTimeout) { WorkingDirectory = sourceDir };
        var packResult = await fx.Runner.RunAsync(packCommand, CancellationToken.None);
        Assert.Equal(0, packResult.ExitCode);

        string raw8Path = Path.Combine(sourceDir, RepackedName);
        Assert.True(File.Exists(raw8Path));
        var raw8 = new VerifiedEdlFile(raw8Path, new FileInfo(raw8Path).Length, Sha256OfFile(raw8Path));

        string wrappedDirectory = Path.Combine(workspace.Root, "wrapped8");
        Directory.CreateDirectory(wrappedDirectory);
        string wrappedPath = Path.Combine(wrappedDirectory, "candidate-boot.img");
        object envelopeTask = RepackEnvelopeMethod.Invoke(null, new object?[]
        {
            fx.NormalOriginal, raw8, fx.NormalBuilt.SlotMaterial.LoaderBudget.MaxRawBytes, wrappedPath, CancellationToken.None,
        })!;
        await (Task)envelopeTask;
        var envelope = (EdlRawBootEnvelope)envelopeTask.GetType().GetProperty("Result")!.GetValue(envelopeTask)!;
        VerifiedEdlFile template8 = envelope.CandidateBoot;

        // Independent native baseline of the 8-entry raw: its config and physical payload facts
        // are what the primitive's own self-unpack must reproduce, plus the base swap.
        string baselineDir = Path.Combine(workspace.Root, "eight-baseline");
        Directory.CreateDirectory(baselineDir);
        string baselineRaw = Path.Combine(workspace.Root, "eight-baseline.raw");
        File.Copy(raw8Path, baselineRaw, overwrite: true);
        await UnpackNativeAsync(baselineRaw, baselineDir);
        string[] baselineConfig = ReadConfigLines(Path.Combine(baselineDir, ConfigName));
        var baselinePayloads = HashPayloads(baselineDir);
        int imageSections = baselineConfig.Count(line => line.Trim().StartsWith("[Image-", StringComparison.Ordinal));
        int manifestSections = baselineConfig.Count(line => line.Trim() == "[Manifest]");
        Assert.Equal(8, imageSections + manifestSections);
        Assert.True(baselinePayloads.Values.Any(entry => entry.Sha256 == extraSha), "the baseline carries the extra blob");

        VerifiedEdlFile replacement = await ExportSlotBaseAsync(workspace, "b", 0x53);
        object result = await InvokeReplaceAsync(
            template8, replacement, fx.NormalBuilt.SlotMaterial.LoaderBudget.MaxRawBytes, workspace.Root);
        // Guarantees owned child disposal even if a later assertion fails; the explicit
        // dispose below stays and the final using dispose is a safe idempotent no-op.
        using IDisposable resultOwner = (IDisposable)result;

        Assert.Equal(8u, GetUInt(result, "EntryCount"));
        var preserved = (IReadOnlyDictionary<string, string>)Get(result, "PreservedPayloadSha256");
        Assert.Equal(baselinePayloads.Count - 1, preserved.Count);
        Assert.True(preserved.Values.Contains(extraSha), "the extra blob hash must survive the replacement");
        Assert.False(preserved.ContainsKey(BaseImageName));

        string unpackDir = Path.Combine(workspace.Root, "eight-result-unpack");
        Directory.CreateDirectory(unpackDir);
        string resultRaw = Path.Combine(workspace.Root, "eight-result.raw");
        File.Copy(((VerifiedEdlFile)Get(result, "PackedRaw")).Path, resultRaw, overwrite: true);
        await UnpackNativeAsync(resultRaw, unpackDir);

        string[] resultConfig = ReadConfigLines(Path.Combine(unpackDir, ConfigName));
        Assert.Equal(baselineConfig.Length, resultConfig.Length);
        for (int index = 0; index < baselineConfig.Length; index++)
        {
            Assert.Equal(baselineConfig[index], resultConfig[index]);
        }

        var actual = HashPayloads(unpackDir);
        Assert.Equal(baselinePayloads.Count, actual.Count);
        foreach (KeyValuePair<string, (long Length, string Sha256)> entry in baselinePayloads)
        {
            Assert.True(actual.ContainsKey(entry.Key), entry.Key);
            if (string.Equals(entry.Key, BaseImageName, StringComparison.Ordinal))
            {
                Assert.Equal(replacement.Length, actual[entry.Key].Length);
                Assert.Equal(replacement.Sha256, actual[entry.Key].Sha256);
            }
            else
            {
                Assert.Equal(entry.Value.Length, actual[entry.Key].Length);
                Assert.Equal(entry.Value.Sha256, actual[entry.Key].Sha256);
            }
        }

        ((IDisposable)result).Dispose();
        Assert.True(File.Exists(template8.Path));
        Assert.True(File.Exists(fx.NormalOriginal.Path));
    }

    // ------------------------------------------------------------------ case C

    [Fact]
    public async Task ReplaceTemplate_WrongReplacementSha_FailsBeforeAnyNativeCall()
    {
        using var workspace = new EdlRawBootBuilderTests.Workspace();
        VerifiedEdlFile exported = await ExportSlotBaseAsync(workspace, "a", 0x54);

        string sentinelPath = Path.Combine(workspace.Root, "sentinel.txt");
        const string sentinelText = "template-parent-sentinel";
        File.WriteAllText(sentinelPath, sentinelText);

        var wrongClaim = new VerifiedEdlFile(exported.Path, exported.Length, new string('f', 64));
        int callsBefore = fx.Runner.Calls;
        string templateShaBefore = Sha256OfFile(fx.NormalBuilt.CandidateBoot.Path);

        Exception failure = await CaptureAsync(() => InvokeReplaceAsync(
            fx.NormalBuilt.CandidateBoot, wrongClaim,
            fx.NormalBuilt.SlotMaterial.LoaderBudget.MaxRawBytes, workspace.Root));
        Assert.IsType<InvalidDataException>(failure);

        Assert.Equal(callsBefore, fx.Runner.Calls);
        Assert.Equal(sentinelText, File.ReadAllText(sentinelPath));
        Assert.Equal(templateShaBefore, Sha256OfFile(fx.NormalBuilt.CandidateBoot.Path));
        Assert.Equal(0, Directory.GetDirectories(workspace.Root, "edl-boot-menu-template-*").Length);
    }

    // ------------------------------------------------------------------ case D

    [Fact]
    public async Task ReplaceTemplate_Precancelled_MakesNoCallsAndLeavesParentUntouched()
    {
        using var workspace = new EdlRawBootBuilderTests.Workspace();
        string sentinelPath = Path.Combine(workspace.Root, "sentinel.txt");
        const string sentinelText = "template-precancel-sentinel";
        File.WriteAllText(sentinelPath, sentinelText);

        // No-I/O claims only: values are never hashed or opened before the invocation.
        var template = new VerifiedEdlFile(
            Path.Combine(workspace.Root, "absent-template.img"), 1, new string('a', 64));
        var replacement = new VerifiedEdlFile(
            Path.Combine(workspace.Root, "absent-base.img"), 1, new string('b', 64));

        int callsBefore = fx.Runner.Calls;
        Exception failure = await CaptureAsync(() => InvokeReplaceAsync(
            template, replacement, fx.NormalBuilt.SlotMaterial.LoaderBudget.MaxRawBytes, workspace.Root,
            new CancellationToken(canceled: true)));
        Assert.IsType<OperationCanceledException>(failure);

        Assert.Equal(callsBefore, fx.Runner.Calls);
        Assert.Equal(sentinelText, File.ReadAllText(sentinelPath));
        Assert.Equal(0, Directory.GetDirectories(workspace.Root, "edl-boot-menu-template-*").Length);
    }

    // ------------------------------------------------------- reflection adapters

    private Task<object> InvokeReplaceAsync(
        VerifiedEdlFile template,
        VerifiedEdlFile replacement,
        long budget,
        string parent,
        CancellationToken cancellationToken = default)
    {
        object? invocation;
        try
        {
            invocation = ReplaceTemplateMethod.Invoke(null, new object?[]
            {
                template, replacement, budget, fx.Tools, fx.Runner, parent, cancellationToken,
            });
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }

        var task = (Task)(invocation ?? throw new InvalidOperationException("the template method returned null"));
        return AwaitResultAsync(task);
    }

    private static async Task<object> AwaitResultAsync(Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }

        return task.GetType().GetProperty("Result")!.GetValue(task)!;
    }

    private static async Task<VerifiedEdlFile> ExportSlotBaseAsync(
        EdlRawBootBuilderTests.Workspace workspace, string slot, byte seed)
    {
        EdlRawBootBuilderTests.SlotFixture fixture =
            EdlRawBootBuilderTests.CreateSlot(workspace, slot, seed);
        string basePath = Path.Combine(workspace.Root, "replacement-" + slot + "-" + seed + ".img");

        object? invocation = ExportBaseMethod.Invoke(null, new object?[]
        {
            slot, fixture.CurrentBoot, fixture.VendorBoot, fixture.InitBoot, fixture.Abl, fixture.XblConfig,
            basePath, CancellationToken.None,
        });
        var task = (Task)(invocation ?? throw new InvalidOperationException("the export method returned null"));
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }

        var material = (InternalSlotMaterial)task.GetType().GetProperty("Result")!.GetValue(task)!;
        return new VerifiedEdlFile(basePath, material.BaseImageLength, material.BaseImageSha256);
    }

    private static async Task<Exception> CaptureAsync(Func<Task> action)
    {
        try
        {
            await action();
        }
        catch (Exception exception)
        {
            return exception;
        }

        throw new InvalidOperationException("the expected failure did not occur");
    }

    // -------------------------------------------------------------- native helper

    private async Task UnpackNativeAsync(string rawPath, string outputDirectory)
    {
        string working = Path.GetDirectoryName(outputDirectory)!;
        string rawName = "unpack-" + Path.GetFileName(Path.TrimEndingDirectorySeparator(outputDirectory)) + ".raw";
        string localRaw = Path.Combine(working, rawName);
        File.Copy(rawPath, localRaw, overwrite: true);

        var command = new ProcessCommand(
            fx.Tools.Unpacker.Path,
            new[] { rawName, Path.GetFileName(Path.TrimEndingDirectorySeparator(outputDirectory)) },
            NativeTimeout) { WorkingDirectory = working };
        var result = await fx.Runner.RunAsync(command, CancellationToken.None);
        Assert.Equal(0, result.ExitCode);
        Assert.True(Directory.Exists(outputDirectory), outputDirectory);
    }

    // ----------------------------------------------------------------- helpers

    private static string[] BuildEightEntryConfig(
        string[] lines, string extraPayloadName, string utf8Name)
    {
        int blobStart = -1;
        for (int index = 0; index < lines.Length; index++)
        {
            if (!lines[index].StartsWith("[", StringComparison.Ordinal))
            {
                continue;
            }

            int cursor = index + 1;
            while (cursor < lines.Length && !lines[cursor].StartsWith("[", StringComparison.Ordinal))
            {
                if (lines[cursor].Trim() == "Type=Blob")
                {
                    blobStart = index;
                    break;
                }

                cursor++;
            }

            if (blobStart >= 0)
            {
                break;
            }
        }

        Assert.True(blobStart >= 0, "the template config carries no Blob section to clone");

        int blobEnd = lines.Length;
        for (int index = blobStart + 1; index < lines.Length; index++)
        {
            if (lines[index].StartsWith("[", StringComparison.Ordinal))
            {
                blobEnd = index;
                break;
            }
        }

        var section = new List<string>();
        for (int index = blobStart; index < blobEnd; index++)
        {
            string line = lines[index];
            if (line.StartsWith("Path=", StringComparison.Ordinal))
            {
                line = "Path=" + extraPayloadName;
            }
            else if (line.StartsWith("Name=", StringComparison.Ordinal))
            {
                line = "Name=" + utf8Name;
            }

            section.Add(line);
        }

        Assert.True(section[0].StartsWith("[Image-", StringComparison.Ordinal), section[0]);
        section[0] = "[Image-07]";
        // A cloned alias section must lose the alias reference: the new entry owns its Path file only.
        section.RemoveAll(line => line.StartsWith("PayloadFrom=", StringComparison.Ordinal));
        if (!section.Exists(line => line.StartsWith("Name=", StringComparison.Ordinal)))
        {
            int pathIndex = section.FindIndex(line => line.StartsWith("Path=", StringComparison.Ordinal));
            Assert.True(pathIndex >= 0, "the cloned Blob section has no Path line");
            section.Insert(pathIndex + 1, "Name=" + utf8Name);
        }

        int manifest = Array.FindIndex(lines, line => line.Trim() == "[Manifest]");
        Assert.True(manifest >= 0, "the template config has no [Manifest] section");

        var combined = new List<string>(lines.Length + section.Count);
        combined.AddRange(lines);
        combined.InsertRange(manifest, section);
        return combined.ToArray();
    }

    private static string[] ReadConfigLines(string path)
    {
        string text = ConfigUtf8.GetString(File.ReadAllBytes(path));
        if (text.Length > 0 && text[0] == '\uFEFF')
        {
            text = text.Substring(1);
        }

        return text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
    }

    private static Dictionary<string, (long Length, string Sha256)> HashPayloads(string directory)
    {
        var files = new Dictionary<string, (long, string)>(StringComparer.Ordinal);
        foreach (string path in Directory.EnumerateFiles(directory))
        {
            string name = Path.GetFileName(path);
            if (string.Equals(name, ConfigName, StringComparison.Ordinal))
            {
                continue;
            }

            using FileStream stream = new(
                path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.SequentialScan);
            files.Add(name, (stream.Length, Sha256OfFile(path)));
        }

        return files;
    }

    private static object Get(object instance, string property) =>
        instance.GetType().GetProperty(property, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!.GetValue(instance)
        ?? throw new InvalidOperationException(property + " was null");

    private static string GetString(object instance, string property) => (string)Get(instance, property);

    private static uint GetUInt(object instance, string property) => (uint)Get(instance, property);

    private static string Sha256Of(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static string Sha256OfFile(string path)
    {
        using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.SequentialScan);
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[81920];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            hash.AppendData(buffer, 0, read);
        }

        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }
}
