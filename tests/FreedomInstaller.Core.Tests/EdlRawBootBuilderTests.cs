// BM001: focused specification of the one-slot Windows native build orchestration.
// The positive case drives the real pinned tools through a test-only adapter that maps the Windows
// executables to an existing Linux oracle build; production has no such mapping and no bypass.
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Real-native tests for <see cref="EdlRawBootBuilder"/>. Four environment variables are mandatory and
/// never skipped: the two fixed Windows PE pins (<c>EDL_RAW_PACKER_PATH</c>, <c>EDL_RAW_UNPACKER_PATH</c>)
/// for the real <see cref="EdlRawBootTools"/> loader, and the two existing static Linux oracle binaries
/// (<c>EDL_RAW_LINUX_PACKER_PATH</c>, <c>EDL_RAW_LINUX_UNPACKER_PATH</c>) that the test-only adapter runs.
/// <para>
/// The two 96 MiB candidates are only ever hashed or probed by range: no test materialises a whole boot
/// partition array. Every fixture child lives under <see cref="TestArtifactRoot"/> and is cleaned by its
/// own test.
/// </para>
/// </summary>
public sealed class EdlRawBootBuilderTests
{
    private const long BootPartitionBytes = 100_663_296L;

    private const int V4HeaderBytes = 4096;

    private const int FooterBytes = 64;

    private const int SmallSourcePartitionBytes = 262144;

    private const string WindowsPackerVariable = "EDL_RAW_PACKER_PATH";

    private const string WindowsUnpackerVariable = "EDL_RAW_UNPACKER_PATH";

    private const string LinuxPackerVariable = "EDL_RAW_LINUX_PACKER_PATH";

    private const string LinuxUnpackerVariable = "EDL_RAW_LINUX_UNPACKER_PATH";

    private const string InactiveProfileId = "g5-9008-y7005";

    private const string G5Model = "TB323FU";

    private const string G5Build = "TB323FU_CN_OPEN_USER_Q00042.1_W_ZUXOS_1.6.0.300_ST_260701";

    private static readonly string[] PayloadKeys =
    {
        "base",
        "linux-padded",
        "runtime",
        "dtb-normal",
        "dtb-diagnostic",
        "initramfs",
    };

    private static readonly string[] G4Compatible = { "lenovo,elden", "qcom,sm8750" };

    private static readonly string[] G5Compatible = { "lenovo,baldur", "qcom,kaanapali" };

    /// <summary>Fixed five role keys of the source and target-backup report objects.</summary>
    private static readonly string[] InactiveTargetRoles =
    {
        "current_boot",
        "vendor_boot",
        "init_boot",
        "abl",
        "xbl_config",
    };

    private static readonly MethodInfo MakeArm64Method =
        RequireMethod(typeof(InternalSlotMaterialReaderTests), "MakeArm64");

    private static readonly MethodInfo MakeBootMethod =
        RequireMethod(typeof(InternalSlotMaterialReaderTests), "MakeBoot");

    private static readonly MethodInfo MakeVendorMethod =
        RequireMethod(typeof(InternalSlotMaterialReaderTests), "MakeVendor");

    private static readonly MethodInfo CreateValidBlobMethod =
        RequireMethod(typeof(EdlRawDtbValidatorTests), "CreateValidBlob");

    private static readonly MethodInfo WriteSourceMethod =
        RequireMethod(typeof(EdlRawBootEnvelopeTests), "WriteSource");

    private static readonly Type SourceSpecType =
        typeof(EdlRawBootEnvelopeTests).GetNestedType("SourceSpec", BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("EdlRawBootEnvelopeTests.SourceSpec was not found");

    /// <summary>Narrow bridge to the internal result revalidation; the test assembly has no friend access.</summary>
    private static readonly MethodInfo RevalidateMethod = typeof(EdlRawBuiltBoot).GetMethod(
        "RevalidateAsync", BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("EdlRawBuiltBoot.RevalidateAsync was not found");

    // ---------------------------------------------------------------- positive integration

    [Fact]
    public async Task BuildAsync_TwoSlots_StagesThreeNativeCommandsAndBindsPerSlotFacts()
    {
        string linuxPacker = RequireEnvironment(LinuxPackerVariable);
        string linuxUnpacker = RequireEnvironment(LinuxUnpackerVariable);
        using EdlRawBootTools tools = await LoadToolsAsync();
        using var package = new SyntheticPackage();
        using var workspace = new Workspace();

        var runner = new LinuxOracleRunner(tools, linuxPacker, linuxUnpacker);
        SlotFixture slotA = CreateSlot(workspace, "a", 0x31);
        SlotFixture slotB = CreateSlot(workspace, "b", 0x71);

        // The selected ZIP recipe is unchanged: old packages still say "android", only the produced
        // candidate is expected to default to the internal Linux entry.
        Assert.Equal("android", package.Contract.BootRecipe.DefaultEntry);

        var built = new List<EdlRawBuiltBoot>();
        try
        {
            foreach (SlotFixture slot in new[] { slotA, slotB })
            {
                string currentBefore = Sha256OfFile(slot.CurrentBoot.Path);
                string vendorBefore = Sha256OfFile(slot.VendorBoot.Path);
                int callsBefore = runner.Calls;

                EdlRawBuiltBoot result = await EdlRawBootBuilder.BuildAsync(
                    new EdlRawBootBuildRequest(
                        slot.Slot,
                        slot.CurrentBoot,
                        slot.VendorBoot,
                        slot.InitBoot,
                        slot.Abl,
                        slot.XblConfig,
                        package.Contract,
                        tools,
                        workspace.Root),
                    runner);

                built.Add(result);
                AssertUnpackedConfigDefaultsToImage01(result);
                AssertSlotResult(slot, package, result);
                await AssertPackIsTheOracleAsync(slot, package, result, linuxPacker);

                Assert.Equal(currentBefore, Sha256OfFile(slot.CurrentBoot.Path));
                Assert.Equal(vendorBefore, Sha256OfFile(slot.VendorBoot.Path));
                Assert.Equal(callsBefore + 3, runner.Calls);

                // Usable while held, then Dispose removes exactly its own generated child.
                await RevalidateAsync(result);
                Assert.True(File.Exists(result.CandidateBoot.Path));
                Assert.True(File.Exists(result.PackedRaw.Path));
                Assert.True(File.Exists(result.BaseImage.Path));
                Assert.True(File.Exists(result.VerificationReport.Path));

                result.Dispose();
                Assert.True(result.IsDisposed);
                Assert.False(Directory.Exists(result.DirectoryPath));
                result.Dispose();
                ObjectDisposedException disposed = await Assert.ThrowsAsync<ObjectDisposedException>(
                    () => RevalidateAsync(result));
                Assert.False(string.IsNullOrEmpty(disposed.Message));

                Assert.True(Directory.Exists(workspace.Root));
                Assert.True(Directory.Exists(slot.Directory));
                Assert.True(File.Exists(slot.CurrentBoot.Path));
                Assert.True(File.Exists(package.Contract.Artifacts["runtime"].FullPath));
                Assert.False(tools.IsDisposed);
            }

            Assert.NotEqual(slotA.BaseSha256, slotB.BaseSha256);
            Assert.NotEqual(built[0].CandidateBoot.Sha256, built[1].CandidateBoot.Sha256);
            Assert.NotEqual(built[0].Envelope.SaltHex, built[1].Envelope.SaltHex);
            Assert.Equal(built[0].Envelope.RollbackIndex, 11UL);
            Assert.Equal(built[1].Envelope.RollbackIndex, 12UL);
        }
        finally
        {
            foreach (EdlRawBuiltBoot item in built)
            {
                item.Dispose();
            }
        }
    }

    /// <summary>
    /// Reads the configuration the real native unpacker itself emitted, not the builder's input build.cfg,
    /// and requires exactly one standalone <c>Default=Image-01</c> line.
    /// </summary>
    private static void AssertUnpackedConfigDefaultsToImage01(EdlRawBuiltBoot result)
    {
        string path = Path.Combine(result.DirectoryPath, "unpacked", "config.cfg");
        Assert.True(File.Exists(path), path);

        string text = File.ReadAllText(path).Replace("\r\n", "\n").Replace('\r', '\n');
        int defaults = 0;
        foreach (string rawLine in text.Split('\n'))
        {
            string line = rawLine.TrimEnd();
            if (!line.StartsWith("Default=", StringComparison.Ordinal))
            {
                continue;
            }

            defaults++;
            Assert.Equal("Default=Image-01", line);
        }

        Assert.Equal(1, defaults);
    }

    // ---------------------------------------------------------------- negatives before any native call

    [Fact]
    public async Task BuildAsync_ChangedPackageKernelClaim_RefusesBeforeAnyNativeCommand()
    {
        using EdlRawBootTools tools = await LoadToolsAsync();
        using var package = new SyntheticPackage();
        using var workspace = new Workspace();
        SlotFixture slot = CreateSlot(workspace, "a", 0x11);

        var request = CreateRequest(slot, package, tools, workspace);
        File.AppendAllText(package.Contract.Artifacts["kernel"].FullPath, "X");

        int calls = 0;
        var runner = new DelegateRunner((_, _) =>
        {
            calls++;
            return Task.FromResult(new ProcessResult(0, string.Empty, string.Empty));
        });

        await Assert.ThrowsAsync<InvalidDataException>(
            () => EdlRawBootBuilder.BuildAsync(request, runner));
        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task BuildAsync_ChangedSourceClaim_RefusesBeforeAnyNativeCommand()
    {
        using EdlRawBootTools tools = await LoadToolsAsync();
        using var package = new SyntheticPackage();
        using var workspace = new Workspace();
        SlotFixture slot = CreateSlot(workspace, "a", 0x21);

        var request = CreateRequest(slot, package, tools, workspace);

        using (var stream = new FileStream(slot.CurrentBoot.Path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            stream.Position = V4HeaderBytes + 5;
            int value = stream.ReadByte();
            stream.Position = V4HeaderBytes + 5;
            stream.WriteByte((byte)(value ^ 0x5A));
        }

        var runner = new DelegateRunner((_, _) => Task.FromResult(new ProcessResult(0, string.Empty, string.Empty)));

        await Assert.ThrowsAsync<InvalidDataException>(
            () => EdlRawBootBuilder.BuildAsync(request, runner));
        Assert.Equal(0, runner.Calls);
    }

    [Fact]
    public async Task BuildAsync_PreCancelledToken_RunsNothing()
    {
        using EdlRawBootTools tools = await LoadToolsAsync();
        using var package = new SyntheticPackage();
        using var workspace = new Workspace();
        SlotFixture slot = CreateSlot(workspace, "a", 0x31);
        var request = CreateRequest(slot, package, tools, workspace);

        var runner = new DelegateRunner((_, _) => Task.FromResult(new ProcessResult(0, string.Empty, string.Empty)));

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => EdlRawBootBuilder.BuildAsync(request, runner, cancellation.Token));
        Assert.Equal(0, runner.Calls);
        Assert.Empty(Directory.GetDirectories(workspace.Root, "edl-boot-a-*"));
    }

    // ---------------------------------------------------------------- negatives after native commands

    [Fact]
    public async Task BuildAsync_NativePackerFailure_RefusesAndRemovesTheOwnedBuildChild()
    {
        using EdlRawBootTools tools = await LoadToolsAsync();
        using var package = new SyntheticPackage();
        using var workspace = new Workspace();
        SlotFixture slot = CreateSlot(workspace, "a", 0x41);
        var request = CreateRequest(slot, package, tools, workspace);

        var runner = new DelegateRunner(
            (_, _) => Task.FromResult(new ProcessResult(9, "packer stdout", "synthetic packer refusal")));

        IOException failure = await Assert.ThrowsAsync<IOException>(
            () => EdlRawBootBuilder.BuildAsync(request, runner));

        Assert.Contains("9", failure.Message, StringComparison.Ordinal);
        Assert.Contains("synthetic packer refusal", failure.Message, StringComparison.Ordinal);
        Assert.Equal(1, runner.Calls);

        // The failed child is this build's own output: it is removed, every caller path stays.
        Assert.Empty(Directory.GetDirectories(workspace.Root, "edl-boot-a-*"));
        Assert.True(Directory.Exists(workspace.Root));
        Assert.True(Directory.Exists(slot.Directory));
        Assert.True(File.Exists(slot.CurrentBoot.Path));
        Assert.True(File.Exists(package.Contract.Artifacts["kernel"].FullPath));
        Assert.False(tools.IsDisposed);
    }

    [Fact]
    public async Task BuildAsync_TamperedUnpackedPayload_ReturnsNoCandidate()
    {
        await AssertTamperRefusedAsync("unpacked", "Image-01-Linux");
    }

    [Fact]
    public async Task BuildAsync_TamperedRepackedRaw_ReturnsNoCandidate()
    {
        await AssertTamperRefusedAsync("unpacked", "RepackedKernel");
    }

    private static async Task AssertTamperRefusedAsync(string relativeDirectory, string fileName)
    {
        string linuxPacker = RequireEnvironment(LinuxPackerVariable);
        string linuxUnpacker = RequireEnvironment(LinuxUnpackerVariable);
        using EdlRawBootTools tools = await LoadToolsAsync();
        using var package = new SyntheticPackage();
        using var workspace = new Workspace();
        SlotFixture slot = CreateSlot(workspace, "a", 0x51);
        var request = CreateRequest(slot, package, tools, workspace);

        int target = string.Equals(fileName, "RepackedKernel", StringComparison.Ordinal) ? 3 : 2;
        var runner = new LinuxOracleRunner(
            tools,
            linuxPacker,
            linuxUnpacker,
            (call, command) =>
            {
                if (call != target)
                {
                    return;
                }

                // The repack command already runs inside "unpacked"; the unpacker runs one level above it.
                string path = target == 3
                    ? Path.Combine(command.WorkingDirectory!, fileName)
                    : Path.Combine(command.WorkingDirectory!, relativeDirectory, fileName);
                using var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                stream.Position = 0;
                int value = stream.ReadByte();
                stream.Position = 0;
                stream.WriteByte((byte)(value ^ 0xFF));
            });

        await Assert.ThrowsAsync<InvalidDataException>(
            () => EdlRawBootBuilder.BuildAsync(request, runner));

        Assert.Equal(target, runner.Calls);
        Assert.Empty(Directory.GetDirectories(workspace.Root, "edl-boot-a-*"));
        Assert.True(File.Exists(slot.CurrentBoot.Path));
        Assert.False(tools.IsDisposed);
    }

    [Fact]
    public async Task BuildAsync_KernelTextOffsetLowBitsMismatch_RefusesBeforeAnyNativeCommand()
    {
        using EdlRawBootTools tools = await LoadToolsAsync();
        // Stock base text_offset is 0x80000; this package kernel declares 0x81000, a different low 21 bits.
        using var package = new SyntheticPackage(0x81000UL);
        using var workspace = new Workspace();
        SlotFixture slot = CreateSlot(workspace, "a", 0x61);
        var request = CreateRequest(slot, package, tools, workspace);

        var runner = new DelegateRunner(
            (_, _) => throw new InvalidOperationException("no native command may run before the staging gates"));

        InvalidDataException failure = await Assert.ThrowsAsync<InvalidDataException>(
            () => EdlRawBootBuilder.BuildAsync(request, runner));

        Assert.Contains("text_offset", failure.Message, StringComparison.Ordinal);
        Assert.Equal(0, runner.Calls);
        Assert.Empty(Directory.GetDirectories(workspace.Root, "edl-boot-a-*"));
        Assert.True(Directory.Exists(workspace.Root));
        Assert.True(File.Exists(slot.CurrentBoot.Path));
        Assert.True(File.Exists(package.Contract.Artifacts["kernel"].FullPath));
        Assert.False(tools.IsDisposed);
    }

    [Fact]
    public async Task BuildAsync_CancelledAfterChildCreated_RemovesOwnChildAndStopsNativeCalls()
    {
        using EdlRawBootTools tools = await LoadToolsAsync();
        using var package = new SyntheticPackage();
        using var workspace = new Workspace();
        SlotFixture slot = CreateSlot(workspace, "a", 0x43);
        var request = CreateRequest(slot, package, tools, workspace);

        using var cancellation = new CancellationTokenSource();
        var runner = new DelegateRunner((_, _) =>
        {
            // The build must already own exactly one child, staged up to the first native command.
            string[] children = Directory.GetDirectories(workspace.Root, "edl-boot-a-*");
            Assert.Single(children);
            Assert.True(File.Exists(Path.Combine(children[0], "build.cfg")));
            cancellation.Cancel();
            return Task.FromCanceled<ProcessResult>(cancellation.Token);
        });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => EdlRawBootBuilder.BuildAsync(request, runner, cancellation.Token));

        Assert.Equal(1, runner.Calls);
        Assert.Empty(Directory.GetDirectories(workspace.Root, "edl-boot-a-*"));
        Assert.True(Directory.Exists(workspace.Root));
        Assert.True(Directory.Exists(slot.Directory));
        Assert.True(File.Exists(slot.CurrentBoot.Path));
        Assert.True(File.Exists(slot.VendorBoot.Path));
        Assert.True(File.Exists(slot.InitBoot.Path));
        Assert.True(File.Exists(slot.Abl.Path));
        Assert.True(File.Exists(slot.XblConfig.Path));
        Assert.True(File.Exists(package.Contract.Artifacts["runtime"].FullPath));
        Assert.False(tools.IsDisposed);
    }

    // ---------------------------------------------------------------- inactive target slot

    /// <summary>
    /// The target B is factory-uninitialized: its five files are all zero, so the build must take the
    /// source material from A while keeping the result slot bound to B and retaining B's zero evidence.
    /// </summary>
    [Fact]
    public async Task BuildAsync_InactiveTargetB_UsesSourceAAndRetainsZeroTargetEvidence()
    {
        string linuxPacker = RequireEnvironment(LinuxPackerVariable);
        string linuxUnpacker = RequireEnvironment(LinuxUnpackerVariable);
        using EdlRawBootTools tools = await LoadToolsAsync();
        using var package = new SyntheticPackage(deviceModel: G5Model);
        using var workspace = new Workspace();
        SlotFixture source = CreateSlot(workspace, "a", 0x31);
        InactiveSlotBackupFixture target = InactiveSlotBackupFixture.Create(workspace);

        Assert.Equal(G5Model, package.Contract.DeviceModel);
        string[] sourceBefore = Snapshot(source);
        string[] targetBefore = EdlRawInactiveSlotBackupTests.Snapshot(target.Five);

        object proof = await VerifyInactiveTargetAsync(target);
        using IDisposable proofLease = (IDisposable)proof;

        var runner = new LinuxOracleRunner(tools, linuxPacker, linuxUnpacker);

        EdlRawBootBuildRequest request = CreateInactiveRequest(source, proof, package, tools, workspace);
        Assert.Equal("a", InactiveSlotBackupReflection.Read<string>(request, "SourceSlot"));

        EdlRawBuiltBoot result = await EdlRawBootBuilder.BuildAsync(request, runner);

        try
        {
            Assert.Equal("b", result.Slot);
            Assert.Equal("a", InactiveSlotBackupReflection.Read<string>(result, "SourceSlot"));
            Assert.True(InactiveSlotBackupReflection.Read<bool>(result, "UsesInactiveSlotBackup"));

            // The reader material stays bound to A and its recovered base.
            Assert.Equal("a", result.SlotMaterial.Slot);
            Assert.Equal(source.BaseSha256, result.SlotMaterial.BaseImageSha256);
            Assert.Equal(source.CurrentBoot.Sha256, result.SlotMaterial.SourceSha256["current_boot"]);
            Assert.Equal(source.VendorBoot.Sha256, result.SlotMaterial.SourceSha256["vendor_boot"]);
            Assert.Equal(source.InitBoot.Sha256, result.SlotMaterial.SourceSha256["init_boot"]);
            Assert.Equal(source.Abl.Sha256, result.SlotMaterial.SourceSha256["abl"]);
            Assert.Equal(source.XblConfig.Sha256, result.SlotMaterial.SourceSha256["xbl_config"]);
            Assert.Equal(BootPartitionBytes, result.SlotMaterial.SourceLengths["current_boot"]);

            // AVB envelope, salt, rollback and properties are A's, never the zero target's.
            Assert.Equal(source.SaltHex, result.Envelope.SaltHex);
            Assert.Equal(source.RollbackIndex, result.Envelope.RollbackIndex);
            Assert.Equal(source.RollbackLocation, result.Envelope.RollbackIndexLocation);
            Assert.Equal(source.Properties.Count, result.Envelope.Properties.Count);
            for (int index = 0; index < source.Properties.Count; index++)
            {
                Assert.Equal(source.Properties[index].Key, result.Envelope.Properties[index].Key);
                Assert.Equal(source.Properties[index].Value, result.Envelope.Properties[index].Value);
            }

            Assert.Equal(3, runner.Calls);
            AssertInactiveTargetReport(result, target);
            AssertSameFiles(source, sourceBefore);
            AssertSameFiles(target.Five, targetBefore);
        }
        finally
        {
            result.Dispose();
        }

        Assert.True(result.IsDisposed);
        Assert.False(Directory.Exists(result.DirectoryPath));
        AssertSameFiles(source, sourceBefore);
        AssertSameFiles(target.Five, targetBefore);
    }

    [Fact]
    public async Task BuildAsync_InactiveProofWithMismatchedTargetBootLength_RefusesBeforeAnyNativeCommand()
    {
        using EdlRawBootTools tools = await LoadToolsAsync();
        using var package = new SyntheticPackage(deviceModel: G5Model);
        using var workspace = new Workspace();
        SlotFixture source = CreateSlot(workspace, "a", 0x41);
        InactiveSlotBackupFixture target = InactiveSlotBackupFixture.Create(workspace, bootLength: 8192);
        object proof = await VerifyInactiveTargetAsync(target);
        using IDisposable proofLease = (IDisposable)proof;

        var runner = new DelegateRunner(
            (_, _) => throw new InvalidOperationException("no native command may run before the proof gates"));

        await AssertInactiveRefusedAsync(
            () => EdlRawBootBuilder.BuildAsync(
                CreateInactiveRequest(source, proof, package, tools, workspace), runner),
            runner);

        Assert.Empty(Directory.GetDirectories(workspace.Root, "edl-boot-b-*"));
        Assert.True(File.Exists(target.Boot.Path));
        Assert.False(tools.IsDisposed);
    }

    [Fact]
    public async Task BuildAsync_DisposedInactiveProof_RefusesBeforeAnyNativeCommand()
    {
        using EdlRawBootTools tools = await LoadToolsAsync();
        using var package = new SyntheticPackage(deviceModel: G5Model);
        using var workspace = new Workspace();
        SlotFixture source = CreateSlot(workspace, "a", 0x43);
        InactiveSlotBackupFixture target = InactiveSlotBackupFixture.Create(workspace);
        object proof = await VerifyInactiveTargetAsync(target);
        InactiveSlotBackupReflection.DisposeProof(proof);
        Assert.True(InactiveSlotBackupReflection.Read<bool>(proof, "IsDisposed"));

        var runner = new DelegateRunner(
            (_, _) => throw new InvalidOperationException("no native command may run before the proof gates"));

        await AssertInactiveRefusedAsync(
            () => EdlRawBootBuilder.BuildAsync(
                CreateInactiveRequest(source, proof, package, tools, workspace), runner),
            runner);

        Assert.Empty(Directory.GetDirectories(workspace.Root, "edl-boot-b-*"));
        Assert.True(File.Exists(source.CurrentBoot.Path));
        Assert.True(File.Exists(target.Boot.Path));
        Assert.False(tools.IsDisposed);
    }

    /// <summary>
    /// Builds the ten-argument request by reflection: the baseline has only the nine-argument
    /// constructor, so a missing capability fails the test instead of the compilation.
    /// </summary>
    private static EdlRawBootBuildRequest CreateInactiveRequest(
        SlotFixture source,
        object proof,
        SyntheticPackage package,
        EdlRawBootTools tools,
        Workspace workspace)
    {
        ConstructorInfo? constructor = null;
        foreach (ConstructorInfo candidate in typeof(EdlRawBootBuildRequest).GetConstructors(
                     BindingFlags.Public | BindingFlags.Instance))
        {
            ParameterInfo[] parameters = candidate.GetParameters();
            if (parameters.Length == 10
                && parameters[9].ParameterType.FullName == InactiveSlotBackupReflection.TypeName)
            {
                constructor = candidate;
                break;
            }
        }

        Assert.True(
            constructor is not null,
            "EdlRawBootBuildRequest has no tenth EdlRawInactiveSlotBackup parameter");
        Assert.True(
            constructor!.GetParameters()[9].IsOptional,
            "the inactive backup parameter must be optional");

        var arguments = new object?[]
        {
            "b",
            source.CurrentBoot,
            source.VendorBoot,
            source.InitBoot,
            source.Abl,
            source.XblConfig,
            package.Contract,
            tools,
            workspace.Root,
            proof,
        };

        try
        {
            return (EdlRawBootBuildRequest)(constructor.Invoke(arguments)
                ?? throw new InvalidOperationException("the request constructor returned null"));
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }
    }

    private static async Task<object> VerifyInactiveTargetAsync(InactiveSlotBackupFixture target)
    {
        MethodInfo verify = InactiveSlotBackupReflection.RequireVerifyAsync(
            InactiveSlotBackupReflection.RequireType());
        return await InactiveSlotBackupReflection.InvokeVerifyAsync(
            verify,
            InactiveProfileId,
            "a",
            "b",
            target.Boot,
            target.VendorBoot,
            target.InitBoot,
            target.Abl,
            target.XblConfig);
    }

    private static async Task AssertInactiveRefusedAsync(Func<Task> action, DelegateRunner runner)
    {
        Exception? failure = null;
        try
        {
            await action();
        }
        catch (Exception exception)
        {
            failure = exception;
        }

        Assert.True(failure is not null, "the build accepted an invalid inactive-slot proof");
        Assert.True(
            failure is ObjectDisposedException or ArgumentException or InvalidDataException
                or InvalidOperationException,
            "unexpected refusal: " + failure);
        Assert.Equal(0, runner.Calls);
    }

    private static void AssertInactiveTargetReport(
        EdlRawBuiltBoot result,
        InactiveSlotBackupFixture target)
    {
        using JsonDocument report = JsonDocument.Parse(File.ReadAllBytes(result.VerificationReport.Path));
        JsonElement root = report.RootElement;
        Assert.Equal("a", root.GetProperty("sourceSlot").GetString());
        Assert.Equal("b", root.GetProperty("targetSlot").GetString());
        Assert.True(root.GetProperty("inactiveTargetUninitialized").GetBoolean());

        JsonElement backup = root.GetProperty("targetBackup");
        Assert.Equal(InactiveTargetRoles.Length, CountProperties(backup));

        VerifiedEdlFile[] files = target.Five;
        for (int index = 0; index < InactiveTargetRoles.Length; index++)
        {
            JsonElement role = backup.GetProperty(InactiveTargetRoles[index]);
            Assert.Equal(files[index].Length, role.GetProperty("bytes").GetInt64());
            Assert.Equal(files[index].Sha256, role.GetProperty("sha256").GetString());
        }

        // The source object still carries A's five real inputs.
        Assert.Equal(5, CountProperties(root.GetProperty("source")));
    }

    private static string[] Snapshot(SlotFixture source) => new[]
    {
        source.CurrentBoot.Sha256,
        source.VendorBoot.Sha256,
        source.InitBoot.Sha256,
        source.Abl.Sha256,
        source.XblConfig.Sha256,
    };

    private static void AssertSameFiles(SlotFixture source, string[] hashes)
    {
        VerifiedEdlFile[] files =
        {
            source.CurrentBoot, source.VendorBoot, source.InitBoot, source.Abl, source.XblConfig,
        };
        AssertSameFiles(files, hashes);
    }

    private static void AssertSameFiles(VerifiedEdlFile[] files, string[] hashes)
    {
        for (int index = 0; index < files.Length; index++)
        {
            Assert.True(File.Exists(files[index].Path), files[index].Path);
            Assert.Equal(files[index].Length, new FileInfo(files[index].Path).Length);
            Assert.Equal(hashes[index], Sha256OfFile(files[index].Path));
        }
    }

    // ---------------------------------------------------------------- result facts

    private static void AssertSlotResult(SlotFixture slot, SyntheticPackage package, EdlRawBuiltBoot result)
    {
        Assert.Equal(slot.Slot, result.Slot);
        Assert.Equal(slot.Slot, result.SourceSlot);
        Assert.False(result.UsesInactiveSlotBackup);
        Assert.True(Directory.Exists(result.DirectoryPath));
        Assert.Equal(BootPartitionBytes, result.CandidateBoot.Length);
        Assert.Equal(BootPartitionBytes, new FileInfo(result.CandidateBoot.Path).Length);
        Assert.Equal(result.PackedRaw.Sha256, result.RoundTripRawSha256);
        Assert.Same(result.CandidateBoot, result.Envelope.CandidateBoot);
        Assert.Equal(package.Contract.ManifestFingerprint, result.PackageManifestFingerprint);

        // Fixed payload map: six cloned role hashes, no extra key.
        Assert.Equal(PayloadKeys.Length, result.UnpackedPayloadSha256.Count);
        foreach (string key in PayloadKeys)
        {
            Assert.True(result.UnpackedPayloadSha256.ContainsKey(key), key);
        }

        Assert.Equal(slot.BaseSha256, result.UnpackedPayloadSha256["base"]);
        Assert.Equal(slot.BaseSha256, result.BaseImage.Sha256);
        Assert.Equal((long)slot.BaseImage.Length, result.BaseImage.Length);
        Assert.Equal(Sha256OfFile(package.Contract.Artifacts["runtime"].FullPath),
            result.UnpackedPayloadSha256["runtime"]);
        Assert.Equal(Sha256OfFile(package.Contract.Artifacts["initramfs"].FullPath),
            result.UnpackedPayloadSha256["initramfs"]);
        Assert.Equal(Sha256OfFile(package.Contract.Artifacts["dtb-normal"].FullPath),
            result.UnpackedPayloadSha256["dtb-normal"]);
        Assert.Equal(Sha256OfFile(package.Contract.Artifacts["dtb-diagnostic"].FullPath),
            result.UnpackedPayloadSha256["dtb-diagnostic"]);

        // Source five binding.
        Assert.Equal(5, result.SlotMaterial.SourceSha256.Count);
        Assert.Equal(slot.CurrentBoot.Sha256, result.SlotMaterial.SourceSha256["current_boot"]);
        Assert.Equal(slot.VendorBoot.Sha256, result.SlotMaterial.SourceSha256["vendor_boot"]);
        Assert.Equal(slot.InitBoot.Sha256, result.SlotMaterial.SourceSha256["init_boot"]);
        Assert.Equal(slot.Abl.Sha256, result.SlotMaterial.SourceSha256["abl"]);
        Assert.Equal(slot.XblConfig.Sha256, result.SlotMaterial.SourceSha256["xbl_config"]);
        Assert.Equal(BootPartitionBytes, result.SlotMaterial.SourceLengths["current_boot"]);
        Assert.Equal(slot.BaseSha256, result.SlotMaterial.BaseImageSha256);
        Assert.Equal(slot.BaseImageSize, result.SlotMaterial.BaseImageSize);
        Assert.False(result.SlotMaterial.IsKshim);

        // The Linux payload is the package kernel plus its own BSS zeros, never the exported Android base.
        byte[] expectedLinux = ExpectedLinuxPayload(package.Kernel, package.KernelImageSize);
        byte[] stagedLinux = File.ReadAllBytes(Path.Combine(result.DirectoryPath, "linux-padded"));
        Assert.Equal(expectedLinux, stagedLinux);
        Assert.Equal(package.KernelImageSize, stagedLinux.LongLength);
        Assert.True(stagedLinux.Length > package.Kernel.Length);
        for (int index = 0; index < package.Kernel.Length; index++)
        {
            Assert.Equal(package.Kernel[index], stagedLinux[index]);
        }

        for (int index = package.Kernel.Length; index < stagedLinux.Length; index++)
        {
            Assert.Equal((byte)0, stagedLinux[index]);
        }

        Assert.Equal(Sha256Of(expectedLinux), result.UnpackedPayloadSha256["linux-padded"]);

        // Fixture distinctness: the Android base and the package Linux kernel are really different inputs.
        Assert.NotEqual(package.Kernel.Length, slot.BaseImage.Length);
        Assert.NotEqual(package.KernelImageSize, slot.BaseImageSize);
        Assert.NotEqual(Sha256Of(package.Kernel), slot.BaseSha256);

        // A successful native unpack must hand back both payloads byte for byte.
        byte[] unpackedBase = File.ReadAllBytes(Path.Combine(result.DirectoryPath, "unpacked", "BaseImage"));
        byte[] unpackedLinux = File.ReadAllBytes(Path.Combine(result.DirectoryPath, "unpacked", "Image-01-Linux"));
        Assert.Equal(slot.BaseImage, unpackedBase);
        Assert.Equal(expectedLinux, unpackedLinux);
        Assert.NotEqual(Sha256Of(unpackedLinux), slot.BaseSha256);

        // DTB evidence of both blobs.
        Assert.Equal(EdlRawDtbKind.Normal, result.NormalDtb.Kind);
        Assert.Equal(EdlRawDtbKind.Diagnostic, result.DiagnosticDtb.Kind);
        Assert.Equal("TB322FC", result.NormalDtb.DeviceModel);
        Assert.Equal(package.Contract.BootRecipe.NormalBootArgs, result.NormalDtb.BootArgs);
        Assert.Equal(package.Contract.BootRecipe.DiagnosticBootArgs, result.DiagnosticDtb.BootArgs);
        Assert.Equal("os", result.NormalDtb.BootStage);
        Assert.Equal("maintenance", result.DiagnosticDtb.BootStage);
        Assert.Equal("internal", result.NormalDtb.RootMedium);
        Assert.Equal(5u, result.NormalDtb.InitrdEntryIndex);
        Assert.Equal(new FileInfo(package.Contract.Artifacts["dtb-normal"].FullPath).Length, result.NormalDtb.Length);
        Assert.Equal(
            new FileInfo(package.Contract.Artifacts["dtb-diagnostic"].FullPath).Length, result.DiagnosticDtb.Length);
        Assert.Equal(2, result.NormalDtb.Compatible.Count);

        // Envelope facts preserved from this slot's own source boot.
        Assert.Equal(slot.RollbackIndex, result.Envelope.RollbackIndex);
        Assert.Equal(slot.RollbackLocation, result.Envelope.RollbackIndexLocation);
        Assert.Equal(slot.SaltHex, result.Envelope.SaltHex);
        Assert.Equal(slot.Properties.Count, result.Envelope.Properties.Count);
        Assert.Equal(slot.Properties[0].Key, result.Envelope.Properties[0].Key);
        Assert.Equal(2, result.Envelope.AlgorithmType);
        Assert.False(result.Envelope.OemSigned);
        Assert.True(result.Envelope.SignatureVerificationPerformed);
        Assert.False(result.Envelope.HardwareRollbackVerified);

        // Candidate v4 header and AVB footer, read by range only.
        long partition = new FileInfo(result.CandidateBoot.Path).Length;
        byte[] sourceHeader = ReadRange(slot.CurrentBoot.Path, 0, V4HeaderBytes);
        byte[] candidateHeader = ReadRange(result.CandidateBoot.Path, 0, V4HeaderBytes);
        Assert.Equal("ANDROID!", Encoding.ASCII.GetString(candidateHeader, 0, 8));
        Assert.Equal(4u, LeU32(candidateHeader, 40));
        Assert.Equal(0u, LeU32(candidateHeader, 12));
        Assert.Equal(0u, LeU32(candidateHeader, 1580));
        Assert.Equal((uint)result.Envelope.CompressedKernelBytes, LeU32(candidateHeader, 8));
        for (int index = 0; index < V4HeaderBytes; index++)
        {
            if (index < 8 || index >= 12)
            {
                Assert.Equal(sourceHeader[index], candidateHeader[index]);
            }
        }

        byte[] footer = ReadRange(result.CandidateBoot.Path, partition - FooterBytes, FooterBytes);
        Assert.Equal("AVBf", Encoding.ASCII.GetString(footer, 0, 4));
        Assert.Equal(1u, BeU32(footer, 4));
        Assert.Equal((ulong)result.Envelope.OriginalImageSize, BeU64(footer, 12));
        Assert.Equal((ulong)result.Envelope.VbmetaOffset, BeU64(footer, 20));
        Assert.True(result.Envelope.VbmetaBytes > 0);
        Assert.Equal((ulong)result.Envelope.VbmetaBytes, BeU64(footer, 28));

        // Single kshim manifest at the end of the packed raw: no nested second manifest.
        long rawLength = new FileInfo(result.PackedRaw.Path).Length;
        byte[] rawHead = ReadRange(result.PackedRaw.Path, 0, 64);
        Assert.Equal("ARMd", Encoding.ASCII.GetString(rawHead, 56, 4));
        Assert.Equal((ulong)rawLength, LeU64(rawHead, 16));
        ulong manifestOffset = LeU64(rawHead, 32);
        ulong manifestSize = LeU64(rawHead, 40);
        Assert.Equal((ulong)rawLength, manifestOffset + manifestSize);
        Assert.True(LeU64(rawHead, 48) > 0);
        byte[] manifestHeader = ReadRange(result.PackedRaw.Path, (long)manifestOffset, 60);
        Assert.Equal(7u, LeU32(manifestHeader, 8));
        Assert.Equal(1u, LeU32(manifestHeader, 12));
        Assert.Equal(8000u, LeU32(manifestHeader, 16));

        // Report is factual JSON with the same binding.
        using JsonDocument report = JsonDocument.Parse(File.ReadAllBytes(result.VerificationReport.Path));
        JsonElement root = report.RootElement;
        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(slot.Slot, root.GetProperty("slot").GetString());
        Assert.Equal(package.Contract.ManifestFingerprint, root.GetProperty("packageManifestFingerprint").GetString());
        Assert.Equal(5, CountProperties(root.GetProperty("source")));
        Assert.Equal(result.PackedRaw.Sha256, root.GetProperty("roundTripRawSha256").GetString());
        Assert.Equal(1, root.GetProperty("packedRaw").GetProperty("defaultIndex").GetInt32());
        Assert.Equal(6, CountProperties(root.GetProperty("unpackedPayloadSha256")));
        foreach (string key in PayloadKeys)
        {
            Assert.Equal(
                result.UnpackedPayloadSha256[key],
                root.GetProperty("unpackedPayloadSha256").GetProperty(key).GetString());
        }
    }

    // ---------------------------------------------------------------- independent raw oracle

    private static async Task AssertPackIsTheOracleAsync(
        SlotFixture slot,
        SyntheticPackage package,
        EdlRawBuiltBoot result,
        string linuxPacker)
    {
        string directory = Path.Combine(slot.Directory, "oracle");
        Directory.CreateDirectory(directory);

        File.WriteAllBytes(Path.Combine(directory, "BaseImage"), slot.BaseImage);
        File.WriteAllBytes(
            Path.Combine(directory, "linux-padded"),
            ExpectedLinuxPayload(package.Kernel, package.KernelImageSize));
        File.Copy(package.Contract.Artifacts["runtime"].FullPath, Path.Combine(directory, "runtime.bin"), true);
        File.Copy(package.Contract.Artifacts["dtb-normal"].FullPath, Path.Combine(directory, "dtb-normal.dtb"), true);
        File.Copy(package.Contract.Artifacts["dtb-diagnostic"].FullPath, Path.Combine(directory, "dtb-diagnostic.dtb"), true);
        File.Copy(package.Contract.Artifacts["initramfs"].FullPath, Path.Combine(directory, "initramfs"), true);

        File.WriteAllText(
            Path.Combine(directory, "build.cfg"),
            OracleConfig(package.Contract.DeviceModel),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

        var runner = new ProcessRunner();
        ProcessResult packed = await runner.RunAsync(
            new ProcessCommand(linuxPacker, new[] { "build.cfg" }, TimeSpan.FromMinutes(3))
            {
                WorkingDirectory = directory,
            });

        Assert.Equal(0, packed.ExitCode);
        Assert.Equal(result.PackedRaw.Sha256, Sha256OfFile(Path.Combine(directory, "PackedKernel")));
    }

    /// <summary>The protocol 1 recipe written independently of the builder output, as the raw oracle.</summary>
    private static string OracleConfig(string model) =>
        "[Pack]\n" +
        "Shim=runtime.bin\n" +
        "Output=PackedKernel\n" +
        "Default=Image-01\n" +
        "Timeout=8000\n" +
        "\n" +
        "[Image-00]\n" +
        "Name=原厂 Android\n" +
        "Path=BaseImage\n" +
        "Type=Linux\n" +
        "BaseImage=true\n" +
        "Align=21\n" +
        "\n" +
        "[Image-01]\n" +
        "Name=机身 Linux\n" +
        "Path=linux-padded\n" +
        "Type=Linux\n" +
        "BaseImage=false\n" +
        "Align=21\n" +
        "EntryOffset=0\n" +
        "DeviceTreeBlob=Image-03\n" +
        "\n" +
        "[Image-02]\n" +
        "Name=Linux 诊断模式\n" +
        "Type=Linux\n" +
        "PayloadFrom=Image-01\n" +
        "Align=21\n" +
        "EntryOffset=0\n" +
        "DeviceTreeBlob=Image-04\n" +
        "\n" +
        "[Image-03]\n" +
        "Name=" + model + " Internal DTB\n" +
        "Path=dtb-normal.dtb\n" +
        "Type=DTB\n" +
        "BaseImage=false\n" +
        "Align=3\n" +
        "\n" +
        "[Image-04]\n" +
        "Name=" + model + " Diagnostic DTB\n" +
        "Path=dtb-diagnostic.dtb\n" +
        "Type=DTB\n" +
        "BaseImage=false\n" +
        "Align=3\n" +
        "\n" +
        "[Image-05]\n" +
        "Name=Installed initramfs\n" +
        "Path=initramfs\n" +
        "Type=Blob\n" +
        "BaseImage=false\n" +
        "Align=16\n" +
        "\n" +
        "[Manifest]\n" +
        "Type=Manifest\n";

    // ---------------------------------------------------------------- fixtures

    internal static EdlRawBootBuildRequest CreateRequest(
        SlotFixture slot,
        SyntheticPackage package,
        EdlRawBootTools tools,
        Workspace workspace) =>
        new(
            slot.Slot,
            slot.CurrentBoot,
            slot.VendorBoot,
            slot.InitBoot,
            slot.Abl,
            slot.XblConfig,
            package.Contract,
            tools,
            workspace.Root);

    internal static SlotFixture CreateSlot(Workspace workspace, string slot, byte seed)
    {
        string directory = Path.Combine(workspace.Root, "slot-" + slot);
        Directory.CreateDirectory(directory);

        byte[] baseImage = MakeArm64(320 + (seed % 7) * 8, 0x11110000u + seed, 1024 + (seed % 7) * 16);
        byte[] salt = new byte[16];
        for (int index = 0; index < salt.Length; index++)
        {
            salt[index] = (byte)(seed + index);
        }

        var properties = new List<(string Key, string Value)>
        {
            ("com.android.build.boot.fingerprint", "synthetic/" + slot),
        };

        if (string.Equals(slot, "a", StringComparison.Ordinal))
        {
            properties.Add(("com.android.build.boot.fingerprint", "synthetic/duplicate"));
        }

        var fixture = new SlotFixture
        {
            Slot = slot,
            Directory = directory,
            BaseImage = baseImage,
            BaseImageSize = 1024 + (seed % 7) * 16,
            RollbackIndex = string.Equals(slot, "a", StringComparison.Ordinal) ? 11UL : 12UL,
            RollbackLocation = 2u,
            SaltHex = ToHex(salt),
            Properties = properties,
        };

        string currentPath = CreateSparseBoot(directory, slot, baseImage, salt, fixture.RollbackIndex, properties);
        fixture.CurrentBoot = Claim(currentPath);

        string vendorPath = Path.Combine(directory, "vendor-" + slot + ".img");
        File.WriteAllBytes(vendorPath, MakeVendor(Repeat((byte)(0x40 + seed), 96)));
        fixture.VendorBoot = Claim(vendorPath);

        string initPath = Path.Combine(directory, "init-" + slot + ".img");
        File.WriteAllBytes(
            initPath,
            MakeBoot(Array.Empty<byte>(), Array.Empty<byte>(), Encoding.ASCII.GetBytes("initsig-" + slot)));
        fixture.InitBoot = Claim(initPath);

        string ablPath = Path.Combine(directory, "abl-" + slot + ".bin");
        File.WriteAllBytes(ablPath, Encoding.ASCII.GetBytes("abl-synthetic-" + slot));
        fixture.Abl = Claim(ablPath);

        string xblPath = Path.Combine(directory, "xbl-" + slot + ".bin");
        File.WriteAllBytes(xblPath, Encoding.ASCII.GetBytes("xbl-synthetic-" + slot));
        fixture.XblConfig = Claim(xblPath);

        return fixture;
    }

    /// <summary>
    /// Writes the real small AVB source image, expands it to the fixed 96 MiB partition by sparse length,
    /// moves the 64-byte footer and drops the real ARM64 base at offset 4096. No 96 MiB array is created.
    /// </summary>
    private static string CreateSparseBoot(
        string directory,
        string slot,
        byte[] baseImage,
        byte[] salt,
        ulong rollbackIndex,
        List<(string Key, string Value)> properties)
    {
        object spec = Activator.CreateInstance(SourceSpecType)
            ?? throw new InvalidOperationException("SourceSpec could not be constructed");
        SetProperty(spec, "PartitionSize", SmallSourcePartitionBytes);
        SetProperty(spec, "KernelSize", baseImage.Length);
        SetProperty(spec, "RamdiskSize", 0u);
        SetProperty(spec, "SignatureSize", 0u);
        SetProperty(spec, "Salt", salt);
        SetProperty(spec, "RollbackIndex", rollbackIndex);
        SetProperty(spec, "RollbackLocation", 2u);

        var propertyList = (List<(string Key, string Value)>)SourceSpecType
            .GetProperty("Properties")!.GetValue(spec)!;
        foreach ((string key, string value) in properties)
        {
            propertyList.Add((key, value));
        }

        string smallPath = Path.Combine(directory, "source-" + slot + ".small.img");
        Invoke(WriteSourceMethod, smallPath, spec);

        byte[] footer = ReadRange(smallPath, SmallSourcePartitionBytes - FooterBytes, FooterBytes);
        string finalPath = Path.Combine(directory, "current-" + slot + ".img");
        File.Move(smallPath, finalPath);

        using (var stream = new FileStream(finalPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            stream.Position = SmallSourcePartitionBytes - FooterBytes;
            stream.Write(new byte[FooterBytes]);
            stream.SetLength(BootPartitionBytes);
            stream.Position = BootPartitionBytes - FooterBytes;
            stream.Write(footer);
            stream.Position = V4HeaderBytes;
            stream.Write(baseImage);
            stream.Position = 8;
            byte[] kernelSizeField = new byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(kernelSizeField, (uint)baseImage.Length);
            stream.Write(kernelSizeField);
            stream.Flush(true);
        }

        return finalPath;
    }

    internal sealed class SyntheticPackage : IDisposable
    {
        private readonly EdlRawFixture _fixture;

        private readonly string _model;

        internal SyntheticPackage(ulong? kernelTextOffset = null, string? deviceModel = null)
        {
            _fixture = EdlRawFixture.Create();
            _model = deviceModel ?? EdlRawFixture.Model;
            Kernel = MakeArm64(256, 0x22220000u, 4096);
            if (kernelTextOffset is ulong textOffset)
            {
                // Mutated before hashing, so the real package contract tracks the new header.
                BinaryPrimitives.WriteUInt64LittleEndian(Kernel.AsSpan(8, 8), textOffset);
            }

            if (deviceModel is not null)
            {
                ApplyDeviceModel(_fixture, deviceModel);
            }

            string[] compatible = string.Equals(_model, G5Model, StringComparison.Ordinal)
                ? G5Compatible
                : G4Compatible;
            NormalDtb = CreateValidBlob(EdlRawFixture.NormalBootArgs, "os", compatible);
            DiagnosticDtb = CreateValidBlob(
                EdlRawFixture.NormalBootArgs + EdlRawFixture.DiagnosticSuffix,
                "maintenance",
                compatible);

            _fixture.WriteFile(EdlRawFixture.KernelFile, Kernel);
            _fixture.WriteFile(EdlRawFixture.DtbNormalFile, NormalDtb);
            _fixture.WriteFile(EdlRawFixture.DtbDiagnosticFile, DiagnosticDtb);

            UpdateArtifacts(
                ("kernel", EdlRawFixture.KernelFile),
                ("dtb-normal", EdlRawFixture.DtbNormalFile),
                ("dtb-diagnostic", EdlRawFixture.DtbDiagnosticFile));
        }

        internal EdlRawPackageContract Contract { get; private set; } = null!;

        internal byte[] Kernel { get; private set; }

        internal byte[] NormalDtb { get; }

        internal byte[] DiagnosticDtb { get; }

        /// <summary>The package kernel's own declared image_size, decoded independently of the builder.</summary>
        internal long KernelImageSize => (long)LeU64(Kernel, 16);

        internal void ReplaceKernel(byte[] kernel)
        {
            Kernel = kernel;
            _fixture.WriteFile(EdlRawFixture.KernelFile, kernel);
            UpdateArtifacts(("kernel", EdlRawFixture.KernelFile));
        }

        public void Dispose() => _fixture.Dispose();

        private void UpdateArtifacts(params (string Role, string File)[] changed)
        {
            JsonObject metadata = _fixture.ReadMetadata();
            JsonArray artifacts = metadata["artifacts"]!.AsArray();
            for (int index = 0; index < artifacts.Count; index++)
            {
                JsonObject artifact = artifacts[index]!.AsObject();
                string role = artifact["role"]!.GetValue<string>();
                foreach ((string changedRole, string file) in changed)
                {
                    if (string.Equals(role, changedRole, StringComparison.Ordinal))
                    {
                        artifacts[index] = _fixture.Describe(role, file);
                        break;
                    }
                }
            }

            _fixture.WriteMetadata(metadata);
            Contract = PackageReader.ReadEdlRawContract(_fixture.Path, _model);
        }

        /// <summary>
        /// Retargets the synthetic package declarations to another model (schema shape only). This is
        /// not a device-support, loader, Complete or physical-test statement.
        /// </summary>
        private static void ApplyDeviceModel(EdlRawFixture fixture, string deviceModel)
        {
            JsonObject metadata = fixture.ReadMetadata();
            metadata["deviceModel"] = deviceModel;

            if (string.Equals(deviceModel, G5Model, StringComparison.Ordinal))
            {
                JsonObject compatible = metadata["compatible"]!.AsObject();
                compatible["soc"] = "SM8850";
                compatible["device"] = "baldur";

                JsonObject profile = metadata["edlProfile"]!.AsObject();
                profile["id"] = InactiveProfileId;
                profile["hardwareId"] = "a1b2c3d4e5f60718";
                profile["androidBuild"] = G5Build;

                metadata["bootCompatibility"]!.AsObject()["firmwareVersions"] = new JsonArray(G5Build);
            }

            fixture.WriteMetadata(metadata);
        }
    }

    internal sealed class SlotFixture
    {
        internal string Slot = string.Empty;

        internal string Directory = string.Empty;

        internal byte[] BaseImage = Array.Empty<byte>();

        internal long BaseImageSize;

        internal string BaseSha256 => Sha256Of(BaseImage);

        internal VerifiedEdlFile CurrentBoot = null!;

        internal VerifiedEdlFile VendorBoot = null!;

        internal VerifiedEdlFile InitBoot = null!;

        internal VerifiedEdlFile Abl = null!;

        internal VerifiedEdlFile XblConfig = null!;

        internal ulong RollbackIndex;

        internal uint RollbackLocation;

        internal string SaltHex = string.Empty;

        internal List<(string Key, string Value)> Properties = new();
    }

    internal sealed class Workspace : IDisposable
    {
        internal Workspace()
        {
            Root = Path.Combine(TestArtifactRoot.Resolve(), "bm001-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        internal string Root { get; }

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
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    // ---------------------------------------------------------------- process boundary

    /// <summary>
    /// Test-only adapter: asserts the builder asked for the exact loaded Windows pins and runs the existing
    /// Linux oracle executable with the same argv vector, working directory, timeout and token.
    /// </summary>
    internal sealed class LinuxOracleRunner : ICommandRunner
    {
        private readonly string _windowsPacker;

        private readonly string _windowsUnpacker;

        private readonly string _linuxPacker;

        private readonly string _linuxUnpacker;

        private readonly Action<int, ProcessCommand>? _after;

        private readonly ProcessRunner _inner = new();

        private int _calls;

        internal LinuxOracleRunner(
            EdlRawBootTools tools,
            string linuxPacker,
            string linuxUnpacker,
            Action<int, ProcessCommand>? after = null)
        {
            _windowsPacker = tools.Packer.Path;
            _windowsUnpacker = tools.Unpacker.Path;
            _linuxPacker = linuxPacker;
            _linuxUnpacker = linuxUnpacker;
            _after = after;
        }

        internal int Calls => Volatile.Read(ref _calls);

        public async Task<ProcessResult> RunAsync(
            ProcessCommand command,
            CancellationToken cancellationToken = default)
        {
            int call = Interlocked.Increment(ref _calls);
            string requested = Path.GetFullPath(command.Executable);

            string mapped;
            if (string.Equals(requested, _windowsPacker, StringComparison.OrdinalIgnoreCase))
            {
                mapped = _linuxPacker;
            }
            else if (string.Equals(requested, _windowsUnpacker, StringComparison.OrdinalIgnoreCase))
            {
                mapped = _linuxUnpacker;
            }
            else
            {
                throw new InvalidOperationException(
                    "the build requested an executable that is not a loaded pin: " + command.Executable);
            }

            ProcessResult result = await _inner
                .RunAsync(command with { Executable = mapped }, cancellationToken)
                .ConfigureAwait(false);
            _after?.Invoke(call, command);
            return result;
        }
    }

    private sealed class DelegateRunner : ICommandRunner
    {
        private readonly Func<ProcessCommand, CancellationToken, Task<ProcessResult>> _handler;

        private int _calls;

        internal DelegateRunner(Func<ProcessCommand, CancellationToken, Task<ProcessResult>> handler) =>
            _handler = handler;

        internal int Calls => Volatile.Read(ref _calls);

        public Task<ProcessResult> RunAsync(
            ProcessCommand command,
            CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _calls);
            return _handler(command, cancellationToken);
        }
    }

    // ---------------------------------------------------------------- environment and tiny helpers

    private static string RequireEnvironment(string name)
    {
        string? value = Environment.GetEnvironmentVariable(name);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException(name + " must name the required native test fixture.");
        }

        string full = Path.GetFullPath(value);
        if (!File.Exists(full))
        {
            throw new InvalidOperationException(name + " does not exist: " + full);
        }

        return full;
    }

    internal static async Task<EdlRawBootTools> LoadToolsAsync()
    {
        string packer = RequireEnvironment(WindowsPackerVariable);
        string unpacker = RequireEnvironment(WindowsUnpackerVariable);
        return await EdlRawBootTools.LoadAsync(Claim(packer), Claim(unpacker));
    }

    private static VerifiedEdlFile Claim(string path)
    {
        string full = Path.GetFullPath(path);
        return new VerifiedEdlFile(full, new FileInfo(full).Length, Sha256OfFile(full));
    }

    private static byte[] MakeArm64(int size, uint code1, long imageSize, ulong textOffset = 0x80000UL) =>
        (byte[])Invoke(
            MakeArm64Method,
            size,
            0x14000100u,
            code1,
            (long?)imageSize,
            textOffset,
            0x0A000000UL,
            null,
            0UL,
            0UL,
            0UL);

    private static byte[] MakeBoot(byte[] kernel, byte[] ramdisk, byte[] signature) =>
        (byte[])Invoke(MakeBootMethod, kernel, ramdisk, signature, null, 4u, 1584, null, 4096, null, null, null);

    private static byte[] MakeVendor(byte[] ramdisk) =>
        (byte[])Invoke(
            MakeVendorMethod, ramdisk, null, null, null, 4096, 2128, null, 4u, 0u, 0u, null, null, null);

    private static byte[] CreateValidBlob(string bootArgs, string stage, string[]? compatible = null) =>
        (byte[])Invoke(
            CreateValidBlobMethod,
            compatible ?? G4Compatible,
            bootArgs,
            stage,
            new[] { 5u });

    private static object Invoke(MethodInfo method, params object?[] arguments)
    {
        try
        {
            return method.Invoke(null, arguments)
                ?? throw new InvalidOperationException(method.Name + " returned null");
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }
    }

    private static Task RevalidateAsync(EdlRawBuiltBoot result)
    {
        object? invocation;
        try
        {
            invocation = RevalidateMethod.Invoke(result, new object?[] { CancellationToken.None });
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }

        return (Task)(invocation ?? throw new InvalidOperationException("RevalidateAsync returned no task"));
    }

    private static void SetProperty(object target, string name, object? value)
    {
        PropertyInfo? property = target.GetType().GetProperty(name, BindingFlags.Public | BindingFlags.Instance);
        if (property is null)
        {
            throw new InvalidOperationException("SourceSpec." + name + " was not found");
        }

        property.SetValue(target, value);
    }

    private static MethodInfo RequireMethod(Type type, string name) =>
        type.GetMethod(name, BindingFlags.NonPublic | BindingFlags.Static)
        ?? throw new InvalidOperationException(type.Name + "." + name + " was not found");

    private static byte[] Repeat(byte value, int count)
    {
        byte[] result = new byte[count];
        Array.Fill(result, value);
        return result;
    }

    /// <summary>
    /// The expected Image-01 payload, derived from the fixture kernel and its own decoded image_size:
    /// the kernel bytes followed by an independently counted zero BSS. Never read from builder output.
    /// </summary>
    private static byte[] ExpectedLinuxPayload(byte[] kernel, long imageSize)
    {
        var padded = new byte[(int)imageSize];
        Buffer.BlockCopy(kernel, 0, padded, 0, kernel.Length);
        return padded;
    }

    private static byte[] ReadRange(string path, long offset, int count)
    {
        byte[] buffer = new byte[count];
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920);
        stream.Position = offset;
        int read = 0;
        while (read < count)
        {
            int chunk = stream.Read(buffer, read, count - read);
            if (chunk == 0)
            {
                throw new InvalidDataException("unexpected end of file while reading a range");
            }

            read += chunk;
        }

        return buffer;
    }

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

    private static string ToHex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    private static int CountProperties(JsonElement element)
    {
        int count = 0;
        foreach (JsonProperty property in element.EnumerateObject())
        {
            _ = property.Name;
            count++;
        }

        return count;
    }

    private static uint LeU32(byte[] buffer, int offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offset, 4));

    private static ulong LeU64(byte[] buffer, int offset) =>
        BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(offset, 8));

    private static uint BeU32(byte[] buffer, int offset) =>
        BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(offset, 4));

    private static ulong BeU64(byte[] buffer, int offset) =>
        BinaryPrimitives.ReadUInt64BigEndian(buffer.AsSpan(offset, 8));
}
