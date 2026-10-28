// TF-NATIVE-POSITIVE-FIX02: one actual native-oracle fact with FOUR explicit sequential subcases —
// stock Android source -> FinalTf / RamMaintenance, and an actually built internal native candidate
// -> FinalTf / RamMaintenance. All four use the independently pinned PUBLIC Android kernel as the
// Android base (never the internal package's Linux kernel). Offline payload/partition-budget
// verification only: no OEM-source signature, parent-chain trust, verified Ready, device write,
// A/B authority or hardware boot is asserted.
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Real-native TF payload oracle. Skip applies ONLY when both TF_NATIVE_PACKAGE_PATH and
/// TF_NATIVE_INTERNAL_PACKAGE_PATH are unset/whitespace; once either is set, every required input
/// must exist and match or the fact FAILS. Dedicated CI sets both and expects 1 executed fact
/// containing the four sequential subcases.
/// </summary>
public sealed class TfNativePackageOracleTests
{
    private const string TfPackageVariable = "TF_NATIVE_PACKAGE_PATH";
    private const string TfInternalPackageVariable = "TF_NATIVE_INTERNAL_PACKAGE_PATH";
    private const string EvidenceRootVariable = "TF_NATIVE_EVIDENCE_ROOT";
    private const string PublicBootVariable = "TF_NATIVE_PUBLIC_BOOT_PATH";
    private const string LoaderFixtureVariable = "G5_LOADER_FIXTURE_ROOT";
    private const string LinuxPackerVariable = "EDL_RAW_LINUX_PACKER_PATH";
    private const string LinuxUnpackerVariable = "EDL_RAW_LINUX_UNPACKER_PATH";

    private const string G5Model = "TB323FU";

    // Independently pinned PUBLIC identities: whole .092 stock boot, then its kernel range.
    private const long PublicBootBytes = 100_663_296L;
    private const string PublicBootSha256 =
        "88DC5792AEBAC2DA5BE4A419F3EBC268D39FF4FBBB43B1A1F3C810AEA0BD25FB";
    private const long PublicKernelOffset = 4096;
    private const int PublicKernelBytes = 39_954_944;
    private const string PublicKernelSha256 =
        "C77D542D1620DC3D2FB94E1EAECC7384FB1884615E6D03F5A7B6A9C525FE335D";

    // Public official .092 loader pair (public fixtures only; never G5_ACTUAL_LOADER_FIXTURE_ROOT).
    private const string AblFileName = "abl.elf";
    private const long AblBytes = 270_136;
    private const string AblSha256 =
        "A7B278E11E6C7AA2A930C69E0811F3C0C3DADFE066F5753A7C975B4BACF991BA";
    private const string XblConfigFileName = "xbl_config.elf";
    private const long XblConfigBytes = 381_708;
    private const string XblConfigSha256 =
        "737E87430B19A0D83D885DE207584A77711B5F26F1852FFD381DAEEE2A8893F9";

    private const long BootPartitionBytes = 100_663_296L;
    private const string TfDeployment = "tf-raw-v1";
    private const string InternalDeployment = "edl-raw-v1";
    private const string MaintenanceInitramfsRole = "tf-maintenance-initramfs";

    [TfNativeOracleFact]
    public async Task Native_oracle_covers_stock_and_built_sources_over_both_tf_purposes()
    {
        // 1. Resolve required inputs; any missing/invalid one FAILS once either package var is set.
        string tfPackagePath = RequireVariable(TfPackageVariable);
        string internalPackagePath = RequireVariable(TfInternalPackageVariable);
        string evidenceRoot = RequireDirectory(EvidenceRootVariable, "evidence root");
        string publicBootPath = RequireFile(PublicBootVariable, "public stock boot");
        string loaderRoot = RequireDirectory(LoaderFixtureVariable, "public loader fixture root");
        string linuxPacker = RequireFile(LinuxPackerVariable, "linux packer ELF");
        string linuxUnpacker = RequireFile(LinuxUnpackerVariable, "linux unpacker ELF");

        // Stream-hash the whole public boot first, then ONLY its pinned kernel range.
        AssertHash("public stock boot", publicBootPath, PublicBootBytes, PublicBootSha256);
        byte[] publicKernel = ReadRange(publicBootPath, PublicKernelOffset, PublicKernelBytes);
        AssertHashBytes("public stock kernel range",
            Convert.ToHexString(SHA256.HashData(publicKernel)), PublicKernelSha256);

        // Public loader pair identity.
        string ablPath = Path.Combine(loaderRoot, AblFileName);
        string xblConfigPath = Path.Combine(loaderRoot, XblConfigFileName);
        AssertHash("public abl.elf", ablPath, AblBytes, AblSha256);
        AssertHash("public xbl_config.elf", xblConfigPath, XblConfigBytes, XblConfigSha256);

        // One real tools instance, one instantiated sealed Workspace, one shared real runner.
        using var tools = await EdlRawBootBuilderTests.LoadToolsAsync();
        using var workspace = new EdlRawBootBuilderTests.Workspace();
        var runner = new EdlRawBootBuilderTests.LinuxOracleRunner(tools, linuxPacker, linuxUnpacker);

        string evidence = CreateChild(evidenceRoot, "tf-native-oracle-" + Guid.NewGuid().ToString("N"));
        var expectedReports = new List<string>();

        // 2. Internal import ONCE (Internal target), then TF import ONCE (TfCard target).
        string internalWork = CreateChild(workspace.Root, "import-internal");
        string tfWork = CreateChild(workspace.Root, "import-tf");
        using var internalPackage = await PackageImporter.ImportAsync(
            internalPackagePath, G5Model, InstallationTarget.Internal, internalWork);
        using var tfPackage = await PackageImporter.ImportAsync(
            tfPackagePath, G5Model, InstallationTarget.TfCard, tfWork);
        AssertImport(internalPackage.Validation, InternalDeployment, "internal");
        AssertImport(tfPackage.Validation, TfDeployment, "tf");
        var internalContract = PackageReader.ReadEdlRawContract(internalPackage.PackageDirectory, G5Model);

        // Capture images ONCE through the real API; require the real maintenance role.
        TfPreparedCardImages images = await TfPreparedCardImages.CaptureAsync(tfPackage);
        try
        {
            Assert.True(images.Contract.MaintenanceInitramfs is not null,
                $"TF contract must carry the real '{MaintenanceInitramfsRole}' role.");
            CompareCommonRoles(internalContract, images.Contract);
            VerifiedEdlFile abl = await ClaimFileAsync(ablPath);
            VerifiedEdlFile xblConfig = await ClaimFileAsync(xblConfigPath);

            // 3. Slot A (stock oracle source) and slot B (internal-build source), both carrying
            // the SAME pinned public kernel over synthetic unsigned AVB NONE metadata.
            var fixtureA = EdlRawBootBuilderTests.CreateSlot(workspace, "a", 0x31);
            var fixtureB = EdlRawBootBuilderTests.CreateSlot(workspace, "b", 0x71);
            PrepareStockSource(fixtureA, publicKernel, abl, xblConfig);
            PrepareStockSource(fixtureB, publicKernel, abl, xblConfig);

            // 4. One real internal candidate from slot B + real internal contract/tools/runner.
            long callsBeforeBuild = runner.Calls;
            string buildWork = CreateChild(workspace.Root, "internal-build");
            var buildRequest = new EdlRawBootBuildRequest(
                fixtureB.Slot,
                fixtureB.CurrentBoot!,
                fixtureB.VendorBoot!,
                fixtureB.InitBoot!,
                fixtureB.Abl!,
                fixtureB.XblConfig!,
                internalContract,
                tools,
                buildWork,
                null);
            using var built = await EdlRawBootBuilder.BuildAsync(buildRequest, runner);
            Assert.True(runner.Calls > callsBeforeBuild,
                "internal candidate build must execute the real native oracle.");
            Assert.Equal(BootPartitionBytes, built.CandidateBoot!.Length);
            AssertHashClaim("built internal candidate", built.CandidateBoot);
            // Base expectation is the INDEPENDENT pinned public kernel, not a self-derived readback.
            AssertHash("internal candidate base image", built.BaseImage!.Path,
                PublicKernelBytes, PublicKernelSha256);

            // 5. Four explicit sequential typed subcases with explicit parameters, no hidden state.
            await RunSubcaseAsync("stock-a-final-tf", fixtureA, tools, runner, images, publicKernel,
                built.CandidateBoot, fixtureA.CurrentBoot!, workspace.Root, evidence, expectedReports,
                TfBootPurpose.FinalTf, internalSource: false);
            await RunSubcaseAsync("stock-a-ram-maintenance", fixtureA, tools, runner, images, publicKernel,
                built.CandidateBoot, fixtureA.CurrentBoot!, workspace.Root, evidence, expectedReports,
                TfBootPurpose.RamMaintenance, internalSource: false);
            await RunSubcaseAsync("built-b-final-tf", fixtureB, tools, runner, images, publicKernel,
                built.CandidateBoot, built.CandidateBoot!, workspace.Root, evidence, expectedReports,
                TfBootPurpose.FinalTf, internalSource: true);
            await RunSubcaseAsync("built-b-ram-maintenance", fixtureB, tools, runner, images, publicKernel,
                built.CandidateBoot, built.CandidateBoot!, workspace.Root, evidence, expectedReports,
                TfBootPurpose.RamMaintenance, internalSource: true);

            // After all four subcases, while built remains alive: prove operations did not
            // change stock/build sources. Expectations captured BEFORE operations (above).
            AssertHashClaim("stock source A current boot unchanged", fixtureA.CurrentBoot!);
            AssertHashClaim("stock source B current boot unchanged", fixtureB.CurrentBoot!);
            AssertHashClaim("built candidate boot unchanged", built.CandidateBoot!);
        }
        finally
        {
            images.Dispose();
        }

        // 9. All four explicit subcases must produce their small evidence reports; no
        // empty-directory success claim.
        Assert.True(expectedReports.Count == 4,
            $"expected exactly 4 evidence reports, got {expectedReports.Count}.");
        foreach (string report in expectedReports)
            Assert.True(File.Exists(report), $"missing evidence report: {report}");
    }

    private static async Task RunSubcaseAsync(
        string name,
        EdlRawBootBuilderTests.SlotFixture fixture,
        EdlRawBootTools tools,
        EdlRawBootBuilderTests.LinuxOracleRunner runner,
        TfPreparedCardImages images,
        byte[] publicKernel,
        VerifiedEdlFile builtCandidate,
        VerifiedEdlFile sourceBoot,
        string workspaceRoot,
        string evidenceDir,
        List<string> expectedReports,
        TfBootPurpose purpose,
        bool internalSource)
    {
        // Vbmeta=null! and Efisp=null are explicit UNUSED raw-payload arguments here; the boot stays
        // a boot, never a vbmeta, and no parent-chain trust is claimed.
        // CurrentBootSlotInputs is an INTERNAL record; build it through a narrow reflection boundary
        // with the same 17 raw-input values plus FOUR literal nulls for optional slots 18–21.
        object inputs = CreateCurrentBootSlotInputs(
            fixture.Slot,
            sourceBoot,
            fixture.VendorBoot!,
            fixture.InitBoot!,
            fixture.Abl!,
            fixture.XblConfig!,
            null!,
            null,
            tools,
            runner,
            CreateChild(workspaceRoot, name),
            WriteBaseImage(workspaceRoot, name, publicKernel),
            Path.Combine(workspaceRoot, name, "original-raw.img"),
            Path.Combine(workspaceRoot, name, "changed-raw.img"),
            "unpacked-original",
            "unpacked-changed",
            Path.Combine(workspaceRoot, name, "candidate-payload.img"));

        long callsBefore = runner.Calls;
        IDisposable? payload = null;
        try
        {
            // 6. Typed await of the actual internal API; real native execution required.
            payload = await InvokeTfBuildPayloadAsync(inputs, images, purpose, CancellationToken.None);
            Assert.True(runner.Calls > callsBefore, $"{name}: native oracle must run.");

            // Real internal instance getters, read once into typed locals for all assertions.
            VerifiedEdlFile packedRaw = GetRequired<VerifiedEdlFile>(payload, "PackedRaw");
            VerifiedEdlFile baseImage = GetRequired<VerifiedEdlFile>(payload, "BaseImage");
            VerifiedEdlFile verificationReport = GetRequired<VerifiedEdlFile>(payload, "VerificationReport");
            uint defaultIndex = GetRequired<uint>(payload, "DefaultIndex");
            string runtimeSha256 = GetRequired<string>(payload, "RuntimeSha256");
            var payloadSha256 = GetRequired<IReadOnlyDictionary<string, string>>(payload, "PayloadSha256");
            var originalPayloadSha256 = GetRequired<IReadOnlyDictionary<string, string>>(payload, "OriginalPayloadSha256");
            object material = GetRequired<object>(payload, "Material");
            object loaderBudget = GetRequired<object>(material, "LoaderBudget");
            bool knownLoaderMatch = GetRequired<bool>(loaderBudget, "KnownLoaderMatch");
            long maxRaw = GetRequired<long>(loaderBudget, "MaxRawBytes");

            AssertHashClaim($"{name} packed raw", packedRaw);
            Assert.True(knownLoaderMatch,
                $"{name}: loader budget must report a real known-loader match.");
            Assert.True(maxRaw > 128L * 1024 * 1024, $"{name}: MaxRawBytes must exceed 128 MiB.");
            Assert.True(packedRaw.Length <= maxRaw,
                $"{name}: packed raw exceeds the real loader budget.");
            // Independent public-kernel base expectation in ALL cases; never a self-derived oracle.
            AssertHash($"{name} base image", baseImage.Path, PublicKernelBytes, PublicKernelSha256);

            // 7. Real on-disk report hash and the exact oracle fields.
            AssertHashClaim($"{name} report", verificationReport);
            string reportPath = verificationReport.Path;
            using var doc = JsonDocument.Parse(File.ReadAllText(reportPath));
            JsonElement r = doc.RootElement;

            ExpectString(r, "schema", "TF-NATIVE-PAYLOAD-01", ignoreCase: false);
            ExpectString(r, "purpose", purpose.ToString(), ignoreCase: false);
            ExpectString(r, "sourceSlot", fixture.Slot, ignoreCase: false);
            ExpectString(r, "deviceModel", G5Model, ignoreCase: false);
            ExpectString(r, "sourceKind", internalSource ? "kshim" : "android", ignoreCase: false);
            Assert.Equal(maxRaw, r.GetProperty("loaderBudgetMaxRawBytes").GetInt64());
            Assert.Equal(packedRaw.Length, r.GetProperty("packedRaw").GetProperty("length").GetInt64());
            ExpectString(r.GetProperty("packedRaw"), "sha256", packedRaw.Sha256, ignoreCase: true);
            Assert.Equal(baseImage.Length, r.GetProperty("baseImage").GetProperty("length").GetInt64());
            ExpectString(r.GetProperty("baseImage"), "sha256", PublicKernelSha256, ignoreCase: true);
            Assert.True(r.GetProperty("sourceCompositeSha256").ValueKind
                is JsonValueKind.String or JsonValueKind.Null, $"{name}: sourceCompositeSha256 wrong type.");
            ExpectString(r, "runtimeShimSha256", runtimeSha256, ignoreCase: true);
            Assert.True(r.GetProperty("linuxPaddedSha256").GetString() is not null,
                $"{name}: linuxPaddedSha256 missing.");
            Assert.True(r.GetProperty("initrdSha256").GetString() is not null, $"{name}: initrdSha256 missing.");
            Assert.True(r.GetProperty("templateSourceSlot").ValueKind
                is JsonValueKind.String or JsonValueKind.Null, $"{name}: templateSourceSlot wrong type.");
            Assert.True(r.GetProperty("templateBootSha256").ValueKind
                is JsonValueKind.String or JsonValueKind.Null, $"{name}: templateBootSha256 wrong type.");
            Assert.Equal(defaultIndex, r.GetProperty("defaultIndex").GetUInt32());
            Assert.True(r.GetProperty("timeoutMs").GetInt64() > 0, $"{name}: timeoutMs must be positive.");
            Assert.True(r.GetProperty("entryCount").GetInt32() > 0, $"{name}: entryCount must be positive.");
            Assert.True(r.GetProperty("preservedEntryCount").GetInt32() >= 0,
                $"{name}: preservedEntryCount wrong type.");
            Assert.True(r.GetProperty("appendedEntryCount").GetInt32() >= 0,
                $"{name}: appendedEntryCount wrong type.");
            Assert.Equal(purpose == TfBootPurpose.RamMaintenance,
                r.GetProperty("maintenanceInitramfsValidated").GetBoolean());

            if (internalSource && purpose == TfBootPurpose.FinalTf)
            {
                // Internal FINAL ONLY: the original internal candidate has NO prior TF pair.
                Assert.False(r.GetProperty("reusedExistingTfPair").GetBoolean(),
                    $"{name}: no prior TF pair exists, so reuse must be false.");
                Assert.True(r.GetProperty("preservedEntryCount").GetInt32() > 0,
                    $"{name}: Final must preserve original entries.");
                Assert.True(r.GetProperty("appendedEntryCount").GetInt32() > 0,
                    $"{name}: Final must append TF content.");
                Assert.Equal(JsonValueKind.Number, r.GetProperty("reusedKernelIndex").ValueKind);
                var original = originalPayloadSha256;
                var final = payloadSha256;
                Assert.NotEmpty(original);
                foreach (var pair in original)
                {
                    Assert.True(final.ContainsKey(pair.Key),
                        $"{name}: original payload '{pair.Key}' must survive Final.");
                    Assert.True(string.Equals(final[pair.Key], pair.Value, StringComparison.OrdinalIgnoreCase),
                        $"{name}: hash drift for original payload '{pair.Key}'.");
                }
            }
            else
            {
                Assert.True(r.GetProperty("reusedKernelIndex").ValueKind
                    is JsonValueKind.Number or JsonValueKind.Null, $"{name}: reusedKernelIndex wrong type.");
            }

            // 8. Evidence copy under the owned evidence child with a distinct name.
            string evidenceReport = Path.Combine(evidenceDir, $"{name}-report.json");
            File.Copy(reportPath, evidenceReport, overwrite: true);
            expectedReports.Add(evidenceReport);

            // Real typed envelope repack over the 96 MiB source geometry with the REAL MaxRawBytes.
            string envelopePath = Path.Combine(workspaceRoot, name, "envelope-boot.img");
            EdlRawBootEnvelope envelope = await InvokeRepackEnvelopeAsync(
                sourceBoot, packedRaw, maxRaw, envelopePath, CancellationToken.None);
            try
            {
                Assert.Equal(BootPartitionBytes, envelope.CandidateBoot!.Length);
                AssertHashClaim($"{name} envelope candidate", envelope.CandidateBoot!);
            }
            finally
            {
                // Delete only this extra owned envelope path after checking it.
                if (File.Exists(envelopePath))
                    File.Delete(envelopePath);
            }
        }
        catch (Exception ex)
        {
            // Real errors name the subcase and preserve inner/native diagnostics; never swallow.
            throw new InvalidOperationException($"subcase '{name}' failed.", ex);
        }
        finally
        {
            payload?.Dispose();
        }
    }

    // --- Narrow reflection boundary over INTERNAL Core APIs -----------------------------

    private const string CurrentBootSlotInputsTypeName = "FreedomInstaller.Core.CurrentBootSlotInputs";
    private const string TfBuildPayloadAsyncMethodName = "TfBuildPayloadAsync";
    private const string RepackEnvelopeAsyncMethodName = "RepackEnvelopeAsync";

    // ONE exact input-construction helper: resolve the internal record by exact assembly type
    // name, pick its primary constructor (exact 21 parameters, excluding the copy constructor),
    // and invoke with the caller's 17 raw values plus FOUR literal nulls for slots 18–21.
    private static object CreateCurrentBootSlotInputs(
        string slot,
        VerifiedEdlFile boot,
        VerifiedEdlFile vendorBoot,
        VerifiedEdlFile initBoot,
        VerifiedEdlFile abl,
        VerifiedEdlFile xblConfig,
        VerifiedEdlFile vbmeta,
        object? efisp,
        object tools,
        object runner,
        string workDirectory,
        string baseImagePath,
        string originalRawPath,
        string changedRawPath,
        string unpackedOriginalDirectoryName,
        string unpackedChangedDirectoryName,
        string candidatePath)
    {
        Type inputsType = typeof(EdlRawBootBuilder).Assembly.GetType(CurrentBootSlotInputsTypeName, throwOnError: true)!;
        ConstructorInfo primary = inputsType.GetConstructors(
                BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
            .SingleOrDefault(c => c.GetParameters().Length == 21)
            ?? throw new InvalidOperationException(
                $"{CurrentBootSlotInputsTypeName}: primary constructor with 21 parameters not found.");
        var arguments = new object?[]
        {
            slot, boot, vendorBoot, initBoot, abl, xblConfig, vbmeta, efisp, tools, runner,
            workDirectory, baseImagePath, originalRawPath, changedRawPath,
            unpackedOriginalDirectoryName, unpackedChangedDirectoryName, candidatePath,
            null, null, null, null,
        };
        return primary.Invoke(arguments);
    }

    // Actual internal static TfBuildPayloadAsync; cast to the PUBLIC non-generic Task (never
    // Task<object>), await it, then read the real inherited Result property reflectively.
    private static async Task<IDisposable> InvokeTfBuildPayloadAsync(
        object inputs, TfPreparedCardImages images, TfBootPurpose purpose, CancellationToken token)
    {
        Type builderType = typeof(EdlRawBootBuilder);
        MethodInfo build = builderType.GetMethod(
                TfBuildPayloadAsyncMethodName,
                BindingFlags.NonPublic | BindingFlags.Static,
                binder: null,
                new[] { inputs.GetType(), typeof(TfPreparedCardImages), typeof(TfBootPurpose), typeof(CancellationToken) },
                modifiers: null)
            ?? throw new InvalidOperationException(
                $"{TfBuildPayloadAsyncMethodName}: internal static method with the exact signature not found.");
        Task task = (Task)build.Invoke(null, new[] { inputs, (object)images, (object)purpose, (object)token })!;
        try
        {
            await task;
        }
        catch (Exception ex)
        {
            // Never reaches here from Invoke; kept for the await path only.
            ExceptionDispatchInfo.Capture(ex).Throw();
            throw;
        }
        PropertyInfo result = task.GetType().GetProperty("Result")
            ?? throw new InvalidOperationException("TF build task Result property not found.");
        return (IDisposable)(result.GetValue(task)
            ?? throw new InvalidOperationException("TF build task produced a null payload."));
    }

    // Actual internal static RepackEnvelopeAsync with the exact 5-parameter signature,
    // returning Task<EdlRawBootEnvelope>; a VALID generic cast, awaited directly.
    private static async Task<EdlRawBootEnvelope> InvokeRepackEnvelopeAsync(
        VerifiedEdlFile sourceBoot, VerifiedEdlFile packedRaw, long maxRaw, string envelopePath, CancellationToken token)
    {
        Type builderType = typeof(EdlRawBootBuilder);
        MethodInfo repack = builderType.GetMethod(
                RepackEnvelopeAsyncMethodName,
                BindingFlags.NonPublic | BindingFlags.Static,
                binder: null,
                new[]
                {
                    typeof(VerifiedEdlFile), typeof(VerifiedEdlFile), typeof(long),
                    typeof(string), typeof(CancellationToken),
                },
                modifiers: null)
            ?? throw new InvalidOperationException(
                $"{RepackEnvelopeAsyncMethodName}: internal static method with the exact signature not found.");
        var task = (Task<EdlRawBootEnvelope>)repack.Invoke(
            null, new object?[] { sourceBoot, packedRaw, maxRaw, envelopePath, token })!;
        return await task;
    }

    // Required read-only instance property reader: non-public/public instance getters only,
    // exact required value, no fabricated defaults.
    private static T GetRequired<T>(object instance, string propertyName)
    {
        PropertyInfo property = instance.GetType().GetProperty(
                propertyName, BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance)
            ?? throw new InvalidOperationException(
                $"{instance.GetType().Name}: required property '{propertyName}' not found.");
        object? value = property.GetValue(instance);
        if (value is not T typed)
            throw new InvalidOperationException(
                $"{instance.GetType().Name}.{propertyName}: value is not {typeof(T).Name}.");
        return typed;
    }

    // ------------------------------------------------------------------------------------

    private static string WriteBaseImage(string workspaceRoot, string name, byte[] publicKernel)
    {
        string path = Path.Combine(workspaceRoot, name, "base-image.img");
        File.WriteAllBytes(path, publicKernel);
        return path;
    }

    private static void PrepareStockSource(
        EdlRawBootBuilderTests.SlotFixture fixture,
        byte[] publicKernel,
        VerifiedEdlFile abl,
        VerifiedEdlFile xblConfig)
    {
        string sourcePath = Path.Combine(fixture.Directory!, "stock-source.img");
        WriteSyntheticSource(sourcePath);

        // Overwrite exactly the pinned kernel range with the public kernel, then a FRESH claim.
        using (var stream = new FileStream(sourcePath, FileMode.Open, FileAccess.Write, FileShare.None))
        {
            stream.Seek(PublicKernelOffset, SeekOrigin.Begin);
            stream.Write(publicKernel, 0, publicKernel.Length);
        }

        fixture.CurrentBoot = ClaimFileSync(sourcePath);
        // Independent expectation: the pinned public kernel, not a claim read back from the file.
        fixture.BaseImage = publicKernel;
        fixture.BaseImageSize = publicKernel.Length;
        fixture.Abl = abl;
        fixture.XblConfig = xblConfig;
    }

    // Narrow reflection reuse of the existing PRIVATE independent AVB NONE synthetic fixture.
    private static void WriteSyntheticSource(string path)
    {
        var specType = typeof(EdlRawBootEnvelopeTests).GetNestedType("SourceSpec", BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("EdlRawBootEnvelopeTests.SourceSpec not found.");
        var spec = Activator.CreateInstance(specType)!;
        specType.GetProperty(nameof(SourceSpecShim.PartitionSize))!.SetValue(spec, (int)100_663_296);
        specType.GetProperty(nameof(SourceSpecShim.KernelSize))!.SetValue(spec, (int)39_954_944);
        specType.GetProperty(nameof(SourceSpecShim.RamdiskSize))!.SetValue(spec, 0u);
        specType.GetProperty(nameof(SourceSpecShim.SignatureSize))!.SetValue(spec, 0u);

        var writeSource = typeof(EdlRawBootEnvelopeTests).GetMethod(
                "WriteSource", BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException("EdlRawBootEnvelopeTests.WriteSource not found.");
        try
        {
            writeSource.Invoke(null, new[] { path, (object)spec });
        }
        catch (TargetInvocationException tie) when (tie.InnerException is not null)
        {
            // Unwrap reflection TargetInvocationException preserving the inner exception.
            ExceptionDispatchInfo.Capture(tie.InnerException).Throw();
        }
    }

    // Compile-time name shim only (never instantiated): keeps the reflected property names checked.
    private sealed class SourceSpecShim
    {
        public int PartitionSize { get; set; }
        public int KernelSize { get; set; }
        public uint RamdiskSize { get; set; }
        public uint SignatureSize { get; set; }
    }

    private static void CompareCommonRoles(EdlRawPackageContract internalContract, TfRawPackageContract tfContract)
    {
        // Internal and TF raw files/DTBs intentionally differ (different filesystem UUID/target
        // arguments); compare exactly kernel, initramfs and runtime, each required in both.
        foreach (string role in new[] { "kernel", "initramfs", "runtime" })
        {
            Assert.True(internalContract.Artifacts.TryGetValue(role, out var internalArtifact),
                $"internal contract is missing required role '{role}'.");
            Assert.True(tfContract.Artifacts.TryGetValue(role, out var tfArtifact),
                $"TF images contract is missing required role '{role}'.");
            Assert.True(
                string.Equals(internalArtifact.Sha256, tfArtifact.Sha256, StringComparison.OrdinalIgnoreCase),
                $"common role '{role}' hash differs between internal contract and TF images contract.");
        }
    }

    private static void AssertImport(PackageValidationResult validation, string deployment, string kind)
    {
        Assert.True(validation.IsValid,
            $"{kind} package validation failed: {string.Join("; ", validation.Reasons)}");
        Assert.False(validation.TestOnly, $"{kind} package must not be test-only.");
        Assert.True(string.Equals(
                validation.DeploymentKind?.ToString(), deployment, StringComparison.Ordinal),
            $"{kind} package deployment must be '{deployment}'.");
    }

    private static string RequireVariable(string name)
    {
        string? value = Environment.GetEnvironmentVariable(name);
        Assert.True(!string.IsNullOrWhiteSpace(value),
            $"required environment variable '{name}' is unset or whitespace.");
        return value!;
    }

    private static string RequireFile(string name, string description)
    {
        string value = RequireVariable(name);
        Assert.True(File.Exists(value), $"{description} '{value}' does not exist.");
        return value;
    }

    private static string RequireDirectory(string name, string description)
    {
        string value = RequireVariable(name);
        Assert.True(Directory.Exists(value), $"{description} '{value}' does not exist.");
        return value;
    }

    private static string CreateChild(string root, string name)
    {
        string path = Path.Combine(root, name);
        Directory.CreateDirectory(path);
        return path;
    }

    private static void AssertHash(string label, string path, long expectedLength, string expectedSha256)
    {
        long length = new FileInfo(path).Length;
        Assert.True(length == expectedLength, $"{label}: length {length} != {expectedLength}.");
        AssertHashBytes(label, HashFile(path), expectedSha256);
    }

    private static string HashFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void AssertHashBytes(string label, string actualSha256, string expectedSha256) =>
        Assert.True(string.Equals(actualSha256, expectedSha256, StringComparison.OrdinalIgnoreCase),
            $"{label}: SHA256 mismatch.");

    private static void AssertHashClaim(string label, VerifiedEdlFile claim)
    {
        long length = new FileInfo(claim.Path).Length;
        Assert.True(length == claim.Length, $"{label}: on-disk length {length} != claim {claim.Length}.");
        AssertHashBytes(label, HashFile(claim.Path), claim.Sha256);
    }

    private static Task<VerifiedEdlFile> ClaimFileAsync(string path) =>
        Task.Run(() => ClaimFileSync(path));

    private static VerifiedEdlFile ClaimFileSync(string path) =>
        new(path, new FileInfo(path).Length, HashFile(path));

    private static byte[] ReadRange(string path, long offset, int count)
    {
        using var stream = File.OpenRead(path);
        stream.Seek(offset, SeekOrigin.Begin);
        var buffer = new byte[count];
        int read = 0;
        while (read < count)
        {
            int chunk = stream.Read(buffer, read, count - read);
            Assert.True(chunk > 0, $"unexpected end of file while reading {count} bytes at offset {offset}.");
            read += chunk;
        }
        return buffer;
    }

    private static void ExpectString(JsonElement element, string name, string expected, bool ignoreCase) =>
        Assert.True(string.Equals(element.GetProperty(name).GetString(), expected,
                ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal),
            $"{name}: expected '{expected}', got '{element.GetProperty(name).GetString()}'.");

    /// <summary>Skip ONLY when both package variables are unset/whitespace; otherwise execute.</summary>
    private sealed class TfNativeOracleFactAttribute : FactAttribute
    {
        public TfNativeOracleFactAttribute()
        {
            if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(TfPackageVariable)) &&
                string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(TfInternalPackageVariable)))
            {
                Skip = $"{TfPackageVariable} and {TfInternalPackageVariable} are both unconfigured.";
            }
        }
    }
}
