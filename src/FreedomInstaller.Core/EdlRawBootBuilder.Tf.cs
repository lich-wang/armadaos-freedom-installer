// TF-NATIVE-PAYLOAD-01: actual native TF/RAM payload construction.
//
// Builds the real packed native payload for the TF final menu or the RAM maintenance boot at
// product runtime through the injected pinned kshim packer/unpacker. Every staged byte lives in
// one unique generated child below the caller work directory; caller files are never overwritten
// or deleted. This file performs no device IO, writes no partition, and creates no authenticated
// envelope: the next thin finisher applies the existing sealed AOSP/GBL route and the 96 MiB
// partition envelope budget on top of TfPackedPayload.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>What the finished native payload is for.</summary>
public enum TfBootPurpose
{
    /// <summary>Permanent TF menu payload preserved alongside the internal boot graph.</summary>
    FinalTf,

    /// <summary>Temporary RAM maintenance payload; the original full source backup stays external.</summary>
    RamMaintenance,
}

/// <summary>
/// A finished, verified packed payload plus the read leases and the unique generated child
/// directory it owns. Data facts only: this is not a boot-ready or written object.
/// </summary>
internal sealed class TfPackedPayload : IDisposable
{
    private readonly List<FileStream> _leases;
    private bool _disposed;

    internal TfPackedPayload(
        string directoryPath,
        string sourceSlot,
        TfBootPurpose purpose,
        InternalSlotMaterial material,
        VerifiedEdlFile packedRaw,
        VerifiedEdlFile baseImage,
        VerifiedEdlFile verificationReport,
        uint defaultIndex,
        IReadOnlyDictionary<string, string> payloadSha256,
        IReadOnlyDictionary<string, string> originalPayloadSha256,
        string runtimeSha256,
        List<FileStream> leases)
    {
        DirectoryPath = directoryPath;
        SourceSlot = sourceSlot;
        Purpose = purpose;
        Material = material;
        PackedRaw = packedRaw;
        BaseImage = baseImage;
        VerificationReport = verificationReport;
        DefaultIndex = defaultIndex;
        PayloadSha256 = payloadSha256;
        OriginalPayloadSha256 = originalPayloadSha256;
        RuntimeSha256 = runtimeSha256;
        _leases = leases;
    }

    internal string DirectoryPath { get; }

    internal string SourceSlot { get; }

    internal TfBootPurpose Purpose { get; }

    internal InternalSlotMaterial Material { get; }

    internal VerifiedEdlFile PackedRaw { get; }

    internal VerifiedEdlFile BaseImage { get; }

    internal VerifiedEdlFile VerificationReport { get; }

    internal uint DefaultIndex { get; }

    internal IReadOnlyDictionary<string, string> PayloadSha256 { get; }

    internal IReadOnlyDictionary<string, string> OriginalPayloadSha256 { get; }

    internal string RuntimeSha256 { get; }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        var cleanupErrors = new List<Exception>();
        foreach (FileStream stream in _leases)
        {
            try
            {
                stream.Close();
            }
            catch (Exception exception)
                when (exception is IOException or UnauthorizedAccessException or ObjectDisposedException)
            {
                cleanupErrors.Add(exception);
            }
        }

        _leases.Clear();
        try
        {
            if (Directory.Exists(DirectoryPath))
            {
                Directory.Delete(DirectoryPath, recursive: true);
            }
        }
        catch (Exception exception)
            when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            // The staged child is reclaimed best-effort; the closed leases are the hard guarantee.
            cleanupErrors.Add(exception);
        }

        if (cleanupErrors.Count > 0)
        {
            throw new AggregateException("the TF payload disposal did not fully succeed", cleanupErrors);
        }
    }
}

public static partial class EdlRawBootBuilder
{
    private const string TfTypeAndroid = "Linux";
    private const string TfTypeLinux = "Linux";
    private const string TfTypeDtb = "DTB";
    private const string TfTypeBlob = "Blob";
    private const string TfTypeShim = "Shim";
    private const string TfNativeOutputFileName = "RepackedKernel";
    private const string TfBaseImageFileName = "BaseImage";
    private const string TfPackageShimFileName = "Shim.bin";
    private const string TfInitrdStagedFileName = "Initrd.bin";
    private const string TfSourceRawStagedFileName = "SourceComposite.bin";
    private const string TfDtbNormalStagedFileName = "TfNormal.dtb";
    private const string TfDtbDiagnosticStagedFileName = "TfDiagnostic.dtb";
    private const string TfVerificationReportFileName = "TfVerificationReport.json";
    private const uint TfNativeTimeoutMs = 8000;
    private const int TfReportBytesLimit = 64 * 1024;

    private static readonly UTF8Encoding TfReportUtf8 =
        new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    internal static Task<TfPackedPayload> TfBuildPayloadAsync(
        CurrentBootSlotInputs inputs,
        TfPreparedCardImages images,
        TfBootPurpose purpose,
        CancellationToken ct)
    {
        return TfBuildPayloadCoreAsync(inputs, images, purpose, null, ct);
    }

    internal static Task<TfPackedPayload> TfBuildPayloadFromInitializedInactiveAsync(
        CurrentBootSlotInputs inputs,
        TfPreparedCardImages images,
        TfBootPurpose purpose,
        CurrentBootInitializedInactiveProof templateProof,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(templateProof);
        if (purpose != TfBootPurpose.FinalTf)
        {
            throw new InvalidDataException(
                "the initialized inactive template payload requires the final TF purpose");
        }

        return TfBuildPayloadCoreAsync(inputs, images, purpose, templateProof, ct);
    }

    private static async Task<TfPackedPayload> TfBuildPayloadCoreAsync(
        CurrentBootSlotInputs inputs,
        TfPreparedCardImages images,
        TfBootPurpose purpose,
        CurrentBootInitializedInactiveProof? templateProof,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        ArgumentNullException.ThrowIfNull(images);
        if (purpose is not (TfBootPurpose.FinalTf or TfBootPurpose.RamMaintenance))
        {
            throw new InvalidDataException("the TF payload purpose is not a supported boot purpose");
        }

        await images.RevalidateAsync(ct).ConfigureAwait(false);
        if (templateProof is not null)
        {
            if (!string.Equals(inputs.Slot, templateProof.SourceSlot, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "the TF payload inputs must target the template proof source slot a");
            }

            templateProof.RequireUsable();
            await templateProof.RevalidateAsync(ct).ConfigureAwait(false);
        }

        TfRawPackageContract contract = images.Contract;

        string model = contract.DeviceModel;
        if (string.IsNullOrWhiteSpace(model))
        {
            throw new InvalidDataException("the TF package does not declare a device model");
        }

        var leases = new List<HeldLease>();
        string? child = null;
        EdlRawBootTools tools = await inputs.Tools.AcquireAsync(ct).ConfigureAwait(false);
        try
        {
            try
            {
                string workRoot = Path.GetFullPath(inputs.WorkDirectory)
                    ?? throw new InvalidDataException("the TF payload work directory is not usable");
                if (!Path.IsPathFullyQualified(workRoot) || !Directory.Exists(workRoot))
                {
                    throw new InvalidDataException("the TF payload work directory must be an existing full path");
                }

                string rootPrefix = workRoot.EndsWith(Path.DirectorySeparatorChar)
                    || workRoot.EndsWith(Path.AltDirectorySeparatorChar)
                    ? workRoot
                    : workRoot + Path.DirectorySeparatorChar;
                child = Path.Combine(workRoot, "tf-payload-" + Guid.NewGuid().ToString("N"));
                string childFull = Path.GetFullPath(child);
                if (!childFull.StartsWith(rootPrefix, StringComparison.Ordinal)
                    || string.Equals(childFull, workRoot, StringComparison.OrdinalIgnoreCase)
                    || Directory.Exists(childFull))
                {
                    throw new InvalidDataException(
                        "the TF payload child directory must be a new unique path inside the work directory");
                }

                child = childFull;
                Directory.CreateDirectory(child);

                HeldLease bootLease = OpenClaimLease("source boot", inputs.Boot, ct);
                leases.Add(bootLease);
                leases.Add(OpenClaimLease("source vendor_boot", inputs.VendorBoot, ct));
                leases.Add(OpenClaimLease("source init_boot", inputs.InitBoot, ct));
                leases.Add(OpenClaimLease("source abl", inputs.Abl, ct));
                leases.Add(OpenClaimLease("source xbl_config", inputs.XblConfig, ct));

                HeldLease? templateRawLease = null;
                if (templateProof is not null)
                {
                    RequireTemplateProofMatch(templateProof, inputs);
                    leases.Add(OpenClaimLease("template project raw", templateProof.ProjectRaw, ct));
                    templateRawLease = leases[^1];
                }

                leases.Add(OpenPackageLease(contract.Raw, "kernel", ct));
                HeldLease kernelLease = leases[^1];

                HeldLease initrdLease;
                if (purpose == TfBootPurpose.RamMaintenance)
                {
                    EdlRawArtifact maintenance = contract.MaintenanceInitramfs
                        ?? throw new InvalidDataException(
                            "the RAM maintenance payload requires the package maintenance initramfs artifact");
                    initrdLease = OpenHeldLease(
                        "package maintenance initramfs",
                        maintenance.FullPath,
                        maintenance.Bytes,
                        maintenance.Sha256,
                        ct);
                }
                else
                {
                    initrdLease = OpenPackageLease(contract.Raw, "initramfs", ct);
                }

                leases.Add(initrdLease);

                leases.Add(OpenPackageLease(contract.Raw, "dtb-normal", ct));
                HeldLease dtbNormalLease = leases[^1];
                leases.Add(OpenPackageLease(contract.Raw, "dtb-diagnostic", ct));
                HeldLease dtbDiagnosticLease = leases[^1];

                // Actual Android kernel facts and the real loader budget come from the analyzed
                // slot material; nothing is fabricated from UI state.
                string baseImagePath = Path.Combine(child, TfBaseImageFileName);
                InternalSlotMaterial material = await InternalSlotMaterialReader.AnalyzeAndExportBaseAsync(
                    inputs.Slot,
                    inputs.Boot,
                    inputs.VendorBoot,
                    inputs.InitBoot,
                    inputs.Abl,
                    inputs.XblConfig,
                    baseImagePath,
                    ct).ConfigureAwait(false);
                long budget = material.LoaderBudget.MaxRawBytes;
                if (budget <= Arm64HeaderProbeBytes)
                {
                    throw new InvalidDataException("the analyzed slot material reports an unusable loader budget");
                }

                HeldLease? shimLease = null;
                string? shimStagedPath = null;
                string? shimShaClaim = null;
                if (!material.IsKshim)
                {
                    shimLease = OpenPackageLease(contract.Raw, "runtime", ct);
                    leases.Add(shimLease);
                    shimStagedPath = Path.Combine(child, TfPackageShimFileName);
                    (_, shimShaClaim) = CopyHeldToNewFile(
                        shimLease.Stream, shimStagedPath, "package runtime shim", ct);
                }

                (long baseBytes, string baseSha256) = TfHashFile(baseImagePath, "exported base image", ct);
                if (templateProof is not null
                    && (baseBytes != templateProof.ReconstructedBase.Length
                        || !string.Equals(baseSha256, templateProof.ReconstructedBase.Sha256, StringComparison.OrdinalIgnoreCase)))
                {
                    throw new InvalidDataException(
                        "the exported base image does not match the template proof reconstructed base");
                }
                HeldLease baseLease = OpenHeldLease(
                    "exported base image", baseImagePath, baseBytes, baseSha256, ct);
                leases.Add(baseLease);
                byte[] baseHeader = new byte[Arm64HeaderProbeBytes];
                ReadExactly(baseLease.Stream, baseHeader, 0, baseHeader.Length);
                RequireArm64Header(baseHeader, "exported base image");

                (string linuxPaddedPath, long _, string linuxPaddedSha256) =
                    TfStagePaddedKernel(kernelLease, baseHeader, child, budget, ct);

                string initrdPath = Path.Combine(child, TfInitrdStagedFileName);
                (long _, string initrdSha256) = CopyHeldToNewFile(
                    initrdLease.Stream, initrdPath, "TF initrd payload", ct);
                if (purpose == TfBootPurpose.RamMaintenance)
                {
                    // Actual gzip/newc and marker verification before RAM use; the validator's own
                    // evidence is authoritative here, none is invented locally.
                    await TfMaintenanceInitramfsValidator.ValidateAsync(
                        initrdLease.Claim,
                        model,
                        kernelLease.Claim.Sha256,
                        budget,
                        ct).ConfigureAwait(false);
                }

                string dtbNormalStagedPath = Path.Combine(child, TfDtbNormalStagedFileName);
                string dtbDiagnosticStagedPath = Path.Combine(child, TfDtbDiagnosticStagedFileName);
                _ = CopyHeldToNewFile(dtbNormalLease.Stream, dtbNormalStagedPath, "TF normal DTB artifact", ct);
                _ = CopyHeldToNewFile(
                    dtbDiagnosticLease.Stream, dtbDiagnosticStagedPath, "TF diagnostic DTB artifact", ct);
                byte[] dtbNormalStaged = await File.ReadAllBytesAsync(dtbNormalStagedPath, ct).ConfigureAwait(false);
                byte[] dtbDiagnosticStaged =
                    await File.ReadAllBytesAsync(dtbDiagnosticStagedPath, ct).ConfigureAwait(false);

                string normalArgs = contract.BootRecipe.NormalBootArgs;
                string diagnosticArgs = contract.BootRecipe.DiagnosticBootArgs;
                if (normalArgs.Length == 0 || diagnosticArgs.Length == 0)
                {
                    throw new InvalidDataException("the TF boot recipe does not carry both TF kernel command lines");
                }

                TfNativeConfig? sourceConfig = null;
                Dictionary<string, (long Length, string Sha256)>? originalFiles = null;
                string? unpackDir = null;
                string? sourceSha256 = null;
                bool useTemplate = material.IsKshim || templateProof is not null;
                if (templateProof is not null)
                {
                    if (templateRawLease is null
                        || templateRawLease.Stream.Length <= 0
                        || templateRawLease.Stream.Length > budget
                        || templateRawLease.Stream.Length > int.MaxValue)
                    {
                        throw new InvalidDataException(
                            "the template project raw length is outside the actual A loader budget");
                    }

                    byte[] templateRaw = new byte[(int)templateRawLease.Stream.Length];
                    ReadExactly(templateRawLease.Stream, templateRaw, 0, templateRaw.Length);
                    string templateSha256 = ToHex(SHA256.HashData(templateRaw));
                    if (!string.Equals(templateSha256, templateProof.ProjectRaw.Sha256, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidDataException("the template project raw does not match its claimed hash");
                    }

                    sourceSha256 = templateSha256;
                    CurrentBootMenuFacts templateMenu = CurrentBootParseMenu(templateRaw, ct);

                    string templateRawPath = Path.Combine(child, TfSourceRawStagedFileName);
                    WriteNewFile(templateRawPath, templateRaw, "template composite raw", ct);
                    unpackDir = Path.Combine(child, "original");
                    Directory.CreateDirectory(unpackDir);
                    await RunNativeAsync(
                        inputs.Runner,
                        tools.Unpacker.Path,
                        new[] { TfSourceRawStagedFileName, unpackDir },
                        child,
                        "template composite unpack",
                        ct).ConfigureAwait(false);

                    string[] templateLines =
                        CurrentBootReadConfigLines(Path.Combine(unpackDir, UnpackedConfigFileName), ct);
                    sourceConfig = TfParseNativeConfig(templateLines, "template composite config");
                    if ((uint)sourceConfig.Entries.Count + 1u != templateMenu.EntryCount)
                    {
                        throw new InvalidDataException(
                            "the template composite config and manifest disagree on the entry count");
                    }

                    if (sourceConfig.DefaultIndex != templateMenu.DefaultBefore)
                    {
                        throw new InvalidDataException(
                            "the template composite config and manifest disagree on the default entry");
                    }

                    originalFiles = CurrentBootHashUnpacked(unpackDir, ct);
                    foreach (TfNativeEntry entry in sourceConfig.Entries)
                    {
                        string resolved = TfResolvePayloadFile(sourceConfig, entry, "template composite config");
                        if (!originalFiles.ContainsKey(resolved))
                        {
                            throw new InvalidDataException(
                                "the template composite config references missing payload file '" + resolved + "'");
                        }
                    }
                }
                else if (material.IsKshim)
                {
                    (byte[] sourceRaw, sourceSha256) = CurrentBootDecodeComposite(bootLease.Stream, budget, ct);
                    CurrentBootMenuFacts menu = CurrentBootParseMenu(sourceRaw, ct);

                    string sourceRawPath = Path.Combine(child, TfSourceRawStagedFileName);
                    WriteNewFile(sourceRawPath, sourceRaw, "source composite raw", ct);
                    unpackDir = Path.Combine(child, "original");
                    Directory.CreateDirectory(unpackDir);
                    await RunNativeAsync(
                        inputs.Runner,
                        tools.Unpacker.Path,
                        new[] { TfSourceRawStagedFileName, unpackDir },
                        child,
                        "source composite unpack",
                        ct).ConfigureAwait(false);

                    string[] sourceLines =
                        CurrentBootReadConfigLines(Path.Combine(unpackDir, UnpackedConfigFileName), ct);
                    sourceConfig = TfParseNativeConfig(sourceLines, "source composite config");
                    if ((uint)sourceConfig.Entries.Count + 1u != menu.EntryCount)
                    {
                        throw new InvalidDataException(
                            "the source composite config and manifest disagree on the entry count");
                    }

                    if (sourceConfig.DefaultIndex != menu.DefaultBefore)
                    {
                        throw new InvalidDataException(
                            "the source composite config and manifest disagree on the default entry");
                    }

                    originalFiles = CurrentBootHashUnpacked(unpackDir, ct);
                    foreach (TfNativeEntry entry in sourceConfig.Entries)
                    {
                        string resolved = TfResolvePayloadFile(sourceConfig, entry, "source composite config");
                        if (!originalFiles.ContainsKey(resolved))
                        {
                            throw new InvalidDataException(
                                "the source composite config references missing payload file '" + resolved + "'");
                        }
                    }
                }

                var staged = new TfStagedInputs
                {
                    IsKshim = useTemplate,
                    BaseImagePath = baseImagePath,
                    LinuxPaddedPath = linuxPaddedPath,
                    InitrdPath = initrdPath,
                    UnpackDirectory = unpackDir,
                    DtbNormalStaged = dtbNormalStaged,
                    DtbDiagnosticStaged = dtbDiagnosticStaged,
                    ShimStagedPath = shimStagedPath,
                    ShimSha256 = shimShaClaim,
                };

                TfPlannedBody plan = purpose == TfBootPurpose.FinalTf
                    ? TfPlanFinalBody(
                        staged, sourceConfig, originalFiles, contract, model, normalArgs, diagnosticArgs,
                        linuxPaddedSha256, initrdSha256, baseSha256)
                    : TfPlanRamBody(
                        staged, sourceConfig, originalFiles, contract, model, normalArgs, diagnosticArgs,
                        linuxPaddedSha256, initrdSha256, baseSha256);

                string packDir = Path.Combine(child, "pack");
                Directory.CreateDirectory(packDir);
                foreach (TfPlannedFile file in plan.Files)
                {
                    string destination = Path.Combine(packDir, file.PackFileName);
                    if (file.StagedPath is not null)
                    {
                        _ = TfCopyFile(
                            file.StagedPath, destination, "TF staged payload '" + file.PackFileName + "'", ct);
                    }
                    else if (file.Bytes is not null)
                    {
                        WriteNewFile(destination, file.Bytes, "TF staged payload '" + file.PackFileName + "'", ct);
                    }
                    else
                    {
                        throw new InvalidDataException(
                            "TF staged payload '" + file.PackFileName + "' carries neither staged nor inline bytes");
                    }
                }

                byte[] configBytes = TfSerializeNativeConfig(plan.Config);
                WriteNewFile(Path.Combine(packDir, UnpackedConfigFileName), configBytes, "TF native config", ct);

                await RunNativeAsync(
                    inputs.Runner,
                    tools.Packer.Path,
                    new[] { UnpackedConfigFileName },
                    packDir,
                    "TF native pack",
                    ct).ConfigureAwait(false);

                string packedPath = Path.Combine(packDir, TfNativeOutputFileName);
                var packedInfo = new FileInfo(packedPath);
                if (!packedInfo.Exists || packedInfo.Length <= 0)
                {
                    throw new InvalidDataException("the pinned packer produced no TF payload output");
                }

                if (packedInfo.Length > budget)
                {
                    throw new InvalidDataException(
                        "the packed TF payload " + packedInfo.Length.ToString(CultureInfo.InvariantCulture)
                        + " exceeds the slot loader budget " + budget.ToString(CultureInfo.InvariantCulture));
                }

                byte[] packed = File.ReadAllBytes(packedPath);
                RequireArm64Header(packed, "packed TF payload");
                ulong manifestOffset = ReadLeU64(packed, Arm64ManifestOffsetField);
                ulong manifestSize = ReadLeU64(packed, Arm64ManifestSizeField);
                if (manifestOffset < (ulong)Arm64HeaderProbeBytes
                    || manifestSize < (ulong)ManifestHeaderBytes
                    || manifestOffset > (ulong)packed.LongLength
                    || manifestSize > (ulong)packed.LongLength - manifestOffset
                    || manifestOffset + manifestSize != (ulong)packed.LongLength)
                {
                    throw new InvalidDataException("the packed TF payload manifest does not end exactly at the image end");
                }

                CurrentBootMenuFacts packedMenu = CurrentBootParseMenu(packed, ct);
                if (packedMenu.EntryCount != (uint)plan.Config.Entries.Count + 1u)
                {
                    throw new InvalidDataException(
                        "the packed TF payload manifest count disagrees with the generated config");
                }

                if (packedMenu.DefaultBefore != plan.Config.DefaultIndex)
                {
                    throw new InvalidDataException(
                        "the packed TF payload default entry disagrees with the generated config");
                }

                string packedRawSha256 = ToHex(SHA256.HashData(packed));

                string verifyDir = Path.Combine(child, "verify");
                Directory.CreateDirectory(verifyDir);
                await RunNativeAsync(
                    inputs.Runner,
                    tools.Unpacker.Path,
                    new[] { TfNativeOutputFileName, verifyDir },
                    packDir,
                    "packed TF payload verification unpack",
                    ct).ConfigureAwait(false);

                Dictionary<string, (long Length, string Sha256)> verifyFiles =
                    TfVerifyPacked(plan, verifyDir, originalFiles, model, ct);
                var payloadSha = TfShaMap(verifyFiles);
                Dictionary<string, string> originalSha = originalFiles is null
                    ? new Dictionary<string, string>(StringComparer.Ordinal) { [TfBaseImageFileName] = baseSha256 }
                    : TfShaMap(originalFiles);

                string runtimeSha256 = verifyFiles[plan.Config.ShimFileName].Sha256;
                byte[] reportBytes = TfBuildVerificationReport(
                    purpose,
                    inputs.Slot,
                    model,
                    material.IsKshim,
                    budget,
                    packed.LongLength,
                    packedRawSha256,
                    runtimeSha256,
                    sourceSha256,
                    baseBytes,
                    baseSha256,
                    linuxPaddedSha256,
                    initrdSha256,
                    plan,
                    payloadSha,
                    originalSha,
                    templateProof?.TargetSlot,
                    templateProof?.TargetBoot.Sha256);
                string reportPath = Path.Combine(child, TfVerificationReportFileName);
                WriteNewFile(reportPath, reportBytes, "TF verification report", ct);

                var packedClaim = new VerifiedEdlFile(packedPath, packed.LongLength, packedRawSha256);
                var baseClaim = new VerifiedEdlFile(baseImagePath, baseBytes, baseSha256);
                string reportSha256 = ToHex(SHA256.HashData(reportBytes));
                var reportClaim = new VerifiedEdlFile(reportPath, reportBytes.LongLength, reportSha256);
                leases.Add(OpenHeldLease("packed TF payload", packedPath, packed.LongLength, packedRawSha256, ct));
                leases.Add(OpenHeldLease("TF verification report", reportPath, reportBytes.LongLength, reportSha256, ct));

                return new TfPackedPayload(
                    child,
                    inputs.Slot,
                    purpose,
                    material,
                    packedClaim,
                    baseClaim,
                    reportClaim,
                    plan.Config.DefaultIndex,
                    payloadSha,
                    originalSha,
                    runtimeSha256,
                    leases.ConvertAll(lease => lease.Stream));
            }
            catch
            {
                TfCleanupOnFailure(child, leases);
                throw;
            }
        }
        finally
        {
            tools.Dispose();
        }
    }

    // ------------------------------------------------------------- planning bodies

    private sealed class TfStagedInputs
    {
        internal bool IsKshim { get; set; }

        internal string BaseImagePath { get; set; } = string.Empty;

        internal string LinuxPaddedPath { get; set; } = string.Empty;

        internal string InitrdPath { get; set; } = string.Empty;

        internal string? UnpackDirectory { get; set; }

        internal byte[] DtbNormalStaged { get; set; } = Array.Empty<byte>();

        internal byte[] DtbDiagnosticStaged { get; set; } = Array.Empty<byte>();

        internal string? ShimStagedPath { get; set; }

        internal string? ShimSha256 { get; set; }
    }

    private sealed class TfPlannedFile
    {
        internal TfPlannedFile(string packFileName, string? stagedPath, byte[]? bytes)
        {
            PackFileName = packFileName;
            StagedPath = stagedPath;
            Bytes = bytes;
        }

        internal string PackFileName { get; }

        internal string? StagedPath { get; }

        internal byte[]? Bytes { get; }
    }

    private sealed class TfBootChain
    {
        internal uint LinuxIndex { get; set; }

        internal uint DtbIndex { get; set; }

        internal uint BlobIndex { get; set; }

        internal string Args { get; set; } = string.Empty;

        internal EdlRawDtbKind Kind { get; set; } = EdlRawDtbKind.Normal;

        internal bool RequireBlobType { get; set; }
    }

    private sealed class TfPlannedBody
    {
        internal TfNativeConfig Config { get; } = new();

        internal Dictionary<uint, string> ExpectedShaByIndex { get; } = new();

        internal List<TfPlannedFile> Files { get; } = new();

        internal List<TfBootChain> Chains { get; } = new();

        internal int PreservedEntryCount { get; set; }

        internal int AppendedEntryCount { get; set; }

        internal bool ReusedExistingPair { get; set; }

        internal uint? ReusedKernelIndex { get; set; }

        internal string? PackageShimSha256 { get; set; }
    }

    private static TfPlannedBody TfPlanFinalBody(
        TfStagedInputs staged,
        TfNativeConfig? sourceConfig,
        Dictionary<string, (long Length, string Sha256)>? originalFiles,
        TfRawPackageContract contract,
        string model,
        string normalArgs,
        string diagnosticArgs,
        string linuxPaddedSha256,
        string initrdSha256,
        string baseSha256)
    {
        if (staged.IsKshim && (sourceConfig is null || originalFiles is null || staged.UnpackDirectory is null))
        {
            throw new InvalidDataException("kshim source material is missing its unpacked composite");
        }

        var recipe = contract.BootRecipe;
        var plan = new TfPlannedBody();
        TfNativeConfig config = plan.Config;
        config.GeneratedByKshimSource = staged.IsKshim;
        if (!staged.IsKshim)
        {
            plan.PackageShimSha256 = staged.ShimSha256;
        }

        uint? reuseNormalIndex = null;
        uint? reuseDiagnosticIndex = null;
        uint? reuseNormalBlob = null;
        uint? reuseDiagnosticBlob = null;

        if (staged.IsKshim)
        {
            // Scan every actually installed internal boot/root UUID pair from the existing Linux
            // DTB routes; the recipe's sourceInternal pair alone is insufficient.
            var installedPairs = new List<(string Boot, string Root)>();
            var routeByLinuxIndex = new Dictionary<uint, (string RootMedium, string Args, uint InitrdIndex)>();
            foreach (TfNativeEntry entry in sourceConfig!.Entries)
            {
                if (!string.Equals(entry.Type, TfTypeLinux, StringComparison.Ordinal)
                    || entry.DeviceTreeBlob is not uint dtbIndex)
                {
                    continue;
                }

                if (dtbIndex >= (uint)sourceConfig.Entries.Count)
                {
                    throw new InvalidDataException(
                        "a source composite Linux entry references a DTB section outside the config");
                }

                string dtbFile = TfRequireSafeRelativeName(
                    TfResolvePayloadFile(sourceConfig, sourceConfig.Entries[(int)dtbIndex], "source composite config"),
                    "source composite config");
                byte[] dtbBytes = File.ReadAllBytes(Path.Combine(staged.UnpackDirectory!, dtbFile));
                (string rootMedium, string bootArgs, uint initrdIndex) =
                    EdlRawDtbValidator.ReadInstalledRoute(dtbBytes, model);
                if (initrdIndex >= (uint)sourceConfig.Entries.Count)
                {
                    throw new InvalidDataException(
                        "an installed DTB route references an initrd section outside the config");
                }

                routeByLinuxIndex[entry.Index] = (rootMedium, bootArgs, initrdIndex);
                if (!string.Equals(rootMedium, "internal", StringComparison.Ordinal))
                {
                    continue;
                }

                if (TfExtractUuidPair(bootArgs) is (string bootUuid, string rootUuid))
                {
                    installedPairs.Add((bootUuid, rootUuid));
                }
            }

            string tfBootUuid = recipe.BootUuid.ToString("D");
            string tfRootUuid = recipe.RootUuid.ToString("D");
            foreach ((string bootUuid, string rootUuid) in installedPairs)
            {
                bool bootCollides = string.Equals(bootUuid, tfBootUuid, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(bootUuid, tfRootUuid, StringComparison.OrdinalIgnoreCase);
                bool rootCollides = string.Equals(rootUuid, tfBootUuid, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(rootUuid, tfRootUuid, StringComparison.OrdinalIgnoreCase);
                if (bootCollides || rootCollides)
                {
                    throw new InvalidDataException(
                        "the TF boot/root UUID pair collides with an actually installed internal boot/root UUID pair");
                }
            }

            // Exact existing TF normal+diagnostic pair: full args + kernel + initrd hash equality
            // on actual TF-routed entries only.
            foreach (TfNativeEntry entry in sourceConfig.Entries)
            {
                if (!string.Equals(entry.Type, TfTypeLinux, StringComparison.Ordinal)
                    || !routeByLinuxIndex.TryGetValue(entry.Index, out (string RootMedium, string Args, uint InitrdIndex) route)
                    || !string.Equals(route.RootMedium, "tf", StringComparison.Ordinal))
                {
                    continue;
                }

                string kernelFile = TfResolvePayloadFile(sourceConfig, entry, "source composite config");
                if (!string.Equals(originalFiles![kernelFile].Sha256, linuxPaddedSha256, StringComparison.Ordinal))
                {
                    continue;
                }

                TfNativeEntry initrdEntry = sourceConfig.Entries[(int)route.InitrdIndex];
                if (!string.Equals(initrdEntry.Type, TfTypeBlob, StringComparison.Ordinal))
                {
                    continue;
                }

                string blobFile = TfResolvePayloadFile(sourceConfig, initrdEntry, "source composite config");
                if (!string.Equals(originalFiles[blobFile].Sha256, initrdSha256, StringComparison.Ordinal))
                {
                    continue;
                }

                if (string.Equals(route.Args, normalArgs, StringComparison.Ordinal))
                {
                    if (reuseNormalIndex is not null)
                    {
                        throw new InvalidDataException("the source composite carries duplicate TF normal boot entries");
                    }

                    reuseNormalIndex = entry.Index;
                    reuseNormalBlob = route.InitrdIndex;
                }
                else if (string.Equals(route.Args, diagnosticArgs, StringComparison.Ordinal))
                {
                    if (reuseDiagnosticIndex is not null)
                    {
                        throw new InvalidDataException(
                            "the source composite carries duplicate TF diagnostic boot entries");
                    }

                    reuseDiagnosticIndex = entry.Index;
                    reuseDiagnosticBlob = route.InitrdIndex;
                }
            }
        }

        uint preservedCount;
        if (staged.IsKshim)
        {
            config.ShimFileName = sourceConfig!.ShimFileName;
            config.OutputFileName = sourceConfig.OutputFileName;
            config.TimeoutMs = sourceConfig.TimeoutMs;
            foreach (TfNativeEntry entry in sourceConfig.Entries)
            {
                config.Entries.Add(TfCloneEntry(entry));
                plan.ExpectedShaByIndex[entry.Index] =
                    originalFiles![TfResolvePayloadFile(sourceConfig, entry, "source composite config")].Sha256;
            }

            if (!string.Equals(plan.ExpectedShaByIndex[0], baseSha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "the unpacked source Android base does not match the exported base image");
            }

            preservedCount = (uint)config.Entries.Count;
            var added = new HashSet<string>(StringComparer.Ordinal);
            foreach (TfNativeEntry entry in config.Entries)
            {
                string resolved = TfResolvePayloadFile(config, entry, "source composite config");
                if (added.Add(resolved))
                {
                    plan.Files.Add(new TfPlannedFile(resolved, Path.Combine(staged.UnpackDirectory!, resolved), null));
                }
            }
        }
        else
        {
            config.ShimFileName = TfPackageShimFileName;
            config.OutputFileName = TfNativeOutputFileName;
            config.TimeoutMs = TfNativeTimeoutMs;
            config.Entries.Add(new TfNativeEntry
            {
                Index = 0,
                Name = "android",
                Path = TfBaseImageFileName,
                Type = TfTypeAndroid,
                BaseImage = true,
                HasAlign = true,
                Align = 21,
            });
            plan.ExpectedShaByIndex[0] = baseSha256;
            preservedCount = 1;
            plan.Files.Add(new TfPlannedFile(TfBaseImageFileName, staged.BaseImagePath, null));
        }

        if (reuseNormalIndex is uint normalFound && reuseDiagnosticIndex is uint diagnosticFound)
        {
            // Reuse the existing TF menu indices and default instead of adding duplicates.
            TfNativeEntry normalEntry = config.Entries[(int)normalFound];
            TfNativeEntry diagnosticEntry = config.Entries[(int)diagnosticFound];
            uint normalDtbIndex = normalEntry.DeviceTreeBlob!.Value;
            uint diagnosticDtbIndex = diagnosticEntry.DeviceTreeBlob!.Value;
            TfValidateReusedDtb(
                staged.UnpackDirectory!, config, normalDtbIndex, normalArgs,
                TfDtbKind(TfBootPurpose.FinalTf, false), model, reuseNormalBlob!.Value);
            TfValidateReusedDtb(
                staged.UnpackDirectory!, config, diagnosticDtbIndex, diagnosticArgs,
                TfDtbKind(TfBootPurpose.FinalTf, true), model, reuseDiagnosticBlob!.Value);

            config.GeneratedByKshimSource = staged.IsKshim;
            if (!staged.IsKshim)
            {
                plan.PackageShimSha256 = staged.ShimSha256;
            }

            config.DefaultIndex = normalFound;
            plan.ReusedExistingPair = true;
            plan.PreservedEntryCount = (int)preservedCount;
            plan.AppendedEntryCount = 0;
            plan.Chains.Add(new TfBootChain
            {
                LinuxIndex = normalFound,
                DtbIndex = normalDtbIndex,
                BlobIndex = reuseNormalBlob.Value,
                Args = normalArgs,
                Kind = TfDtbKind(TfBootPurpose.FinalTf, false),
                RequireBlobType = true,
            });
            plan.Chains.Add(new TfBootChain
            {
                LinuxIndex = diagnosticFound,
                DtbIndex = diagnosticDtbIndex,
                BlobIndex = reuseDiagnosticBlob.Value,
                Args = diagnosticArgs,
                Kind = TfDtbKind(TfBootPurpose.FinalTf, true),
                RequireBlobType = true,
            });
            return plan;
        }

        // Reuse a source kernel only on actual staged BSS-padded whole-SHA equality with a Linux
        // typed section; otherwise a new payload is staged for the TF items.
        uint? kernelFrom = null;
        if (staged.IsKshim)
        {
            foreach (TfNativeEntry entry in config.Entries)
            {
                if (!string.Equals(entry.Type, TfTypeLinux, StringComparison.Ordinal)
                    || entry.Path is null
                    || entry.PayloadFrom is not null)
                {
                    continue;
                }

                if (string.Equals(
                        plan.ExpectedShaByIndex[entry.Index], linuxPaddedSha256, StringComparison.Ordinal))
                {
                    kernelFrom = entry.Index;
                    break;
                }
            }
        }

        // Reuse a source blob entry only on actual whole-length+whole-SHA equality with the
        // staged initrd; otherwise a new payload is staged for the TF items.
        uint? blobFrom = null;
        if (staged.IsKshim)
        {
            long initrdLength = new FileInfo(staged.InitrdPath).Length;
            foreach (TfNativeEntry entry in config.Entries)
            {
                if (!string.Equals(entry.Type, TfTypeBlob, StringComparison.Ordinal)
                    || entry.Path is null
                    || entry.PayloadFrom is not null)
                {
                    continue;
                }

                string blobFileNameCandidate = TfResolvePayloadFile(config, entry, "source composite config");
                if (!originalFiles!.TryGetValue(
                        blobFileNameCandidate, out (long Length, string Sha256) actual))
                {
                    continue;
                }

                if (actual.Length == initrdLength
                    && string.Equals(actual.Sha256, initrdSha256, StringComparison.OrdinalIgnoreCase))
                {
                    blobFrom = entry.Index;
                    break;
                }
            }
        }

        uint normalIndex = preservedCount;
        uint diagnosticIndex = preservedCount + 1;
        uint dtbNormalIndex = preservedCount + 2;
        uint dtbDiagnosticIndex = preservedCount + 3;
        uint blobIndex = blobFrom ?? (preservedCount + 4);

        byte[] relocatedNormal = TfRelocateTfDtb(
            staged.DtbNormalStaged, normalArgs, TfDtbKind(TfBootPurpose.FinalTf, false), model, blobIndex);
        byte[] relocatedDiagnostic = TfRelocateTfDtb(
            staged.DtbDiagnosticStaged, diagnosticArgs, TfDtbKind(TfBootPurpose.FinalTf, true), model, blobIndex);

        string linuxFileName = TfPayloadFileName(normalIndex, TfTypeLinux);
        string dtbNormalFileName = TfPayloadFileName(dtbNormalIndex, TfTypeDtb);
        string dtbDiagnosticFileName = TfPayloadFileName(dtbDiagnosticIndex, TfTypeDtb);
        string blobFileName = TfPayloadFileName(blobIndex, TfTypeBlob);

        config.Entries.Add(new TfNativeEntry
        {
            Index = normalIndex,
            Name = "tf-linux",
            Path = kernelFrom is null ? linuxFileName : null,
            PayloadFrom = kernelFrom,
            Type = TfTypeLinux,
            BaseImage = false,
            HasAlign = true,
            Align = 21,
            EntryOffset = 0,
            DeviceTreeBlob = dtbNormalIndex,
        });
        plan.ExpectedShaByIndex[normalIndex] = linuxPaddedSha256;

        config.Entries.Add(new TfNativeEntry
        {
            Index = diagnosticIndex,
            Name = "tf-diagnostic",
            PayloadFrom = kernelFrom ?? normalIndex,
            Type = TfTypeLinux,
            BaseImage = false,
            HasAlign = true,
            Align = 21,
            EntryOffset = 0,
            DeviceTreeBlob = dtbDiagnosticIndex,
        });
        plan.ExpectedShaByIndex[diagnosticIndex] = linuxPaddedSha256;

        config.Entries.Add(new TfNativeEntry
        {
            Index = dtbNormalIndex,
            Name = "tf-dtb",
            Path = dtbNormalFileName,
            Type = TfTypeDtb,
            BaseImage = false,
            HasAlign = true,
            Align = 3,
        });
        plan.ExpectedShaByIndex[dtbNormalIndex] = ToHex(SHA256.HashData(relocatedNormal));

        config.Entries.Add(new TfNativeEntry
        {
            Index = dtbDiagnosticIndex,
            Name = "tf-dtb-diagnostic",
            Path = dtbDiagnosticFileName,
            Type = TfTypeDtb,
            BaseImage = false,
            HasAlign = true,
            Align = 3,
        });
        plan.ExpectedShaByIndex[dtbDiagnosticIndex] = ToHex(SHA256.HashData(relocatedDiagnostic));

        if (blobFrom is null)
        {
            config.Entries.Add(new TfNativeEntry
            {
                Index = blobIndex,
                Name = "tf-initrd",
                Path = blobFileName,
                Type = TfTypeBlob,
                BaseImage = false,
                HasAlign = true,
                Align = 16,
            });
            plan.ExpectedShaByIndex[blobIndex] = initrdSha256;
        }

        if (kernelFrom is null)
        {
            plan.Files.Add(new TfPlannedFile(linuxFileName, staged.LinuxPaddedPath, null));
        }

        plan.Files.Add(new TfPlannedFile(dtbNormalFileName, null, relocatedNormal));
        plan.Files.Add(new TfPlannedFile(dtbDiagnosticFileName, null, relocatedDiagnostic));
        if (blobFrom is null)
        {
            plan.Files.Add(new TfPlannedFile(blobFileName, staged.InitrdPath, null));
        }
        TfEnsureShimFile(plan, staged, config);

        config.DefaultIndex = normalIndex;
        plan.PreservedEntryCount = (int)preservedCount;
        plan.AppendedEntryCount = config.Entries.Count - (int)preservedCount;
        plan.ReusedKernelIndex = kernelFrom;
        plan.Chains.Add(new TfBootChain
        {
            LinuxIndex = normalIndex,
            DtbIndex = dtbNormalIndex,
            BlobIndex = blobIndex,
            Args = normalArgs,
            Kind = TfDtbKind(TfBootPurpose.FinalTf, false),
            RequireBlobType = true,
        });
        plan.Chains.Add(new TfBootChain
        {
            LinuxIndex = diagnosticIndex,
            DtbIndex = dtbDiagnosticIndex,
            BlobIndex = blobIndex,
            Args = diagnosticArgs,
            Kind = TfDtbKind(TfBootPurpose.FinalTf, true),
            RequireBlobType = true,
        });
        return plan;
    }

    private static TfPlannedBody TfPlanRamBody(
        TfStagedInputs staged,
        TfNativeConfig? sourceConfig,
        Dictionary<string, (long Length, string Sha256)>? originalFiles,
        TfRawPackageContract contract,
        string model,
        string normalArgs,
        string diagnosticArgs,
        string linuxPaddedSha256,
        string initrdSha256,
        string baseSha256)
    {
        if (staged.IsKshim && (sourceConfig is null || originalFiles is null || staged.UnpackDirectory is null))
        {
            throw new InvalidDataException("kshim source material is missing its unpacked composite");
        }

        var recipe = contract.BootRecipe;
        var plan = new TfPlannedBody();
        TfNativeConfig config = plan.Config;
        config.GeneratedByKshimSource = staged.IsKshim;
        if (!staged.IsKshim)
        {
            plan.PackageShimSha256 = staged.ShimSha256;
        }

        config.OutputFileName = TfNativeOutputFileName;
        config.TimeoutMs = TfNativeTimeoutMs;
        config.ShimFileName = staged.IsKshim ? sourceConfig!.ShimFileName : TfPackageShimFileName;

        // Row 0: the Android base, preserving the current ABL/GBL trust chain through it.
        if (staged.IsKshim)
        {
            TfNativeEntry android = TfCloneEntry(sourceConfig!.Entries[0]);
            android.Index = 0;
            config.Entries.Add(android);
            string resolved = TfResolvePayloadFile(sourceConfig, sourceConfig.Entries[0], "source composite config");
            string androidSha = originalFiles![resolved].Sha256;
            if (!string.Equals(androidSha, baseSha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "the unpacked source Android base does not match the exported base image");
            }

            plan.ExpectedShaByIndex[0] = androidSha;
        }
        else
        {
            config.Entries.Add(new TfNativeEntry
            {
                Index = 0,
                Name = "android",
                Path = TfBaseImageFileName,
                Type = TfTypeAndroid,
                BaseImage = true,
                HasAlign = true,
                Align = 21,
            });
            plan.ExpectedShaByIndex[0] = baseSha256;
        }

        // Rows 1-5: RAM Linux plus alias diagnostic, their two maintenance-stage TF DTBs, and the
        // RAM initrd Blob at index 5. RAM normal and alias both use the diagnostic-stage artifact:
        // the RAM /init runs chosen-stage maintenance and never mounts storage.
        byte[] relocatedNormal = TfRelocateTfDtb(
            staged.DtbDiagnosticStaged, diagnosticArgs, TfDtbKind(TfBootPurpose.RamMaintenance, false), model, 5u);
        byte[] relocatedDiagnostic = TfRelocateTfDtb(
            staged.DtbDiagnosticStaged, diagnosticArgs, TfDtbKind(TfBootPurpose.RamMaintenance, true), model, 5u);

        config.Entries.Add(new TfNativeEntry
        {
            Index = 1,
            Name = "tf-ram-linux",
            Path = TfPayloadFileName(1, TfTypeLinux),
            Type = TfTypeLinux,
            BaseImage = false,
            HasAlign = true,
            Align = 21,
            EntryOffset = 0,
            DeviceTreeBlob = 3,
        });
        plan.ExpectedShaByIndex[1] = linuxPaddedSha256;

        config.Entries.Add(new TfNativeEntry
        {
            Index = 2,
            Name = "tf-ram-diagnostic",
            PayloadFrom = 1,
            Type = TfTypeLinux,
            BaseImage = false,
            HasAlign = true,
            Align = 21,
            EntryOffset = 0,
            DeviceTreeBlob = 4,
        });
        plan.ExpectedShaByIndex[2] = linuxPaddedSha256;

        config.Entries.Add(new TfNativeEntry
        {
            Index = 3,
            Name = "tf-ram-dtb",
            Path = TfPayloadFileName(3, TfTypeDtb),
            Type = TfTypeDtb,
            BaseImage = false,
            HasAlign = true,
            Align = 3,
        });
        plan.ExpectedShaByIndex[3] = ToHex(SHA256.HashData(relocatedNormal));

        config.Entries.Add(new TfNativeEntry
        {
            Index = 4,
            Name = "tf-ram-dtb-diagnostic",
            Path = TfPayloadFileName(4, TfTypeDtb),
            Type = TfTypeDtb,
            BaseImage = false,
            HasAlign = true,
            Align = 3,
        });
        plan.ExpectedShaByIndex[4] = ToHex(SHA256.HashData(relocatedDiagnostic));

        config.Entries.Add(new TfNativeEntry
        {
            Index = 5,
            Name = "tf-ram-initrd",
            Path = TfPayloadFileName(5, TfTypeBlob),
            Type = TfTypeBlob,
            BaseImage = false,
            HasAlign = true,
            Align = 16,
        });
        plan.ExpectedShaByIndex[5] = initrdSha256;

        if (config.Entries.Count != 6)
        {
            throw new InvalidDataException("the RAM maintenance body is not the standard 6-row shape");
        }

        config.DefaultIndex = 1;

        if (staged.IsKshim)
        {
            string androidFile = TfResolvePayloadFile(config, config.Entries[0], "RAM maintenance body");
            plan.Files.Add(new TfPlannedFile(androidFile, Path.Combine(staged.UnpackDirectory!, androidFile), null));
        }
        else
        {
            plan.Files.Add(new TfPlannedFile(TfBaseImageFileName, staged.BaseImagePath, null));
        }

        plan.Files.Add(new TfPlannedFile(TfPayloadFileName(1, TfTypeLinux), staged.LinuxPaddedPath, null));
        plan.Files.Add(new TfPlannedFile(TfPayloadFileName(3, TfTypeDtb), null, relocatedNormal));
        plan.Files.Add(new TfPlannedFile(TfPayloadFileName(4, TfTypeDtb), null, relocatedDiagnostic));
        plan.Files.Add(new TfPlannedFile(TfPayloadFileName(5, TfTypeBlob), staged.InitrdPath, null));
        TfEnsureShimFile(plan, staged, config);

        plan.PreservedEntryCount = 1;
        plan.AppendedEntryCount = 5;
        plan.Chains.Add(new TfBootChain
        {
            LinuxIndex = 1,
            DtbIndex = 3,
            BlobIndex = 5,
            Args = diagnosticArgs,
            Kind = TfDtbKind(TfBootPurpose.RamMaintenance, false),
            RequireBlobType = true,
        });
        plan.Chains.Add(new TfBootChain
        {
            LinuxIndex = 2,
            DtbIndex = 4,
            BlobIndex = 5,
            Args = diagnosticArgs,
            Kind = TfDtbKind(TfBootPurpose.RamMaintenance, true),
            RequireBlobType = true,
        });
        return plan;
    }

    private static void TfEnsureShimFile(TfPlannedBody plan, TfStagedInputs staged, TfNativeConfig config)
    {
        string shimName = config.ShimFileName;
        foreach (TfPlannedFile file in plan.Files)
        {
            if (string.Equals(file.PackFileName, shimName, StringComparison.Ordinal))
            {
                return;
            }
        }

        if (staged.IsKshim)
        {
            plan.Files.Add(new TfPlannedFile(shimName, Path.Combine(staged.UnpackDirectory!, shimName), null));
        }
        else
        {
            plan.Files.Add(new TfPlannedFile(
                TfPackageShimFileName,
                staged.ShimStagedPath
                    ?? throw new InvalidDataException("the package runtime shim payload is missing"),
                null));
        }
    }

    private static void TfValidateReusedDtb(
        string unpackDirectory,
        TfNativeConfig config,
        uint dtbIndex,
        string args,
        EdlRawDtbKind kind,
        string model,
        uint expectedBlobIndex)
    {
        string dtbFile = TfRequireSafeRelativeName(
            TfResolvePayloadFile(config, config.Entries[(int)dtbIndex], "source composite config"),
            "source composite config");
        byte[] dtbBytes = File.ReadAllBytes(Path.Combine(unpackDirectory, dtbFile));
        _ = EdlRawDtbValidator.ValidateTfPacked(dtbBytes, args, kind, model, expectedBlobIndex);
    }

    private static byte[] TfRelocateTfDtb(
        byte[] stagedDtb,
        string args,
        EdlRawDtbKind kind,
        string model,
        uint blobIndex)
    {
        // The validator enforces the strict artifact checks before the edit; only the new TF DTBs
        // are ever relocated, never an old one.
        (_, _, uint currentIndex) = EdlRawDtbValidator.ReadInstalledRoute(stagedDtb, model);
        _ = EdlRawDtbValidator.ValidateTfPacked(stagedDtb, args, kind, model, currentIndex);
        return EdlRawDtbValidator.RelocateTfInitrdEntry(stagedDtb, args, kind, model, blobIndex);
    }

    private static EdlRawDtbKind TfDtbKind(TfBootPurpose purpose, bool diagnostic) =>
        purpose == TfBootPurpose.FinalTf && !diagnostic
            ? EdlRawDtbKind.Normal
            : EdlRawDtbKind.Diagnostic;

    private static string TfPayloadFileName(uint index, string type) =>
        "Image-" + index.ToString("00", CultureInfo.InvariantCulture) + "-" + type;

    // ------------------------------------------------------------- verification

    private static Dictionary<string, (long Length, string Sha256)> TfVerifyPacked(
        TfPlannedBody plan,
        string verifyDirectory,
        Dictionary<string, (long Length, string Sha256)>? originalFiles,
        string model,
        CancellationToken ct)
    {
        string[] verifyLines =
            CurrentBootReadConfigLines(Path.Combine(verifyDirectory, UnpackedConfigFileName), ct);
        TfNativeConfig verifyConfig = TfParseNativeConfig(verifyLines, "verify config");
        if (verifyConfig.Entries.Count != plan.Config.Entries.Count)
        {
            throw new InvalidDataException("the restored TF payload carries a different entry count");
        }

        if (verifyConfig.DefaultIndex != plan.Config.DefaultIndex)
        {
            throw new InvalidDataException("the restored TF payload carries a different default entry");
        }

        if (verifyConfig.TimeoutMs != plan.Config.TimeoutMs)
        {
            throw new InvalidDataException("the restored TF payload carries a different menu timeout");
        }

        if (!string.Equals(verifyConfig.ShimFileName, plan.Config.ShimFileName, StringComparison.Ordinal)
            || !string.Equals(verifyConfig.OutputFileName, plan.Config.OutputFileName, StringComparison.Ordinal))
        {
            throw new InvalidDataException("the restored TF payload config header drifted from the generated one");
        }

        Dictionary<string, (long Length, string Sha256)> verifyFiles =
            CurrentBootHashUnpacked(verifyDirectory, ct);

        for (int i = 0; i < plan.Config.Entries.Count; i++)
        {
            TfNativeEntry plannedEntry = plan.Config.Entries[i];
            TfNativeEntry actualEntry = verifyConfig.Entries[i];
            if (actualEntry.Index != plannedEntry.Index)
            {
                throw new InvalidDataException(
                    "the restored TF payload reindexed section Image-"
                    + plannedEntry.Index.ToString("00", CultureInfo.InvariantCulture));
            }

            if (!TfEntryFieldsEqual(plannedEntry, actualEntry))
            {
                throw new InvalidDataException(
                    "the restored TF payload altered preserved fields of Image-"
                    + plannedEntry.Index.ToString("00", CultureInfo.InvariantCulture));
            }

            string actualFile = TfRequireSafeRelativeName(
                TfResolvePayloadFile(verifyConfig, actualEntry, "verify config"), "verify config");
            string plannedFile = TfResolvePayloadFile(plan.Config, plannedEntry, "generated config");
            if (!string.Equals(actualFile, plannedFile, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "the restored TF payload resolves Image-"
                    + plannedEntry.Index.ToString("00", CultureInfo.InvariantCulture) + " to a different payload file");
            }

            if (!verifyFiles.TryGetValue(actualFile, out (long Length, string Sha256) actualHash))
            {
                throw new InvalidDataException(
                    "the restored TF payload is missing payload file '" + actualFile + "'");
            }

            if (!plan.ExpectedShaByIndex.TryGetValue(plannedEntry.Index, out string? expectedSha)
                || !string.Equals(actualHash.Sha256, expectedSha, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "the restored TF payload hash for Image-"
                    + plannedEntry.Index.ToString("00", CultureInfo.InvariantCulture) + " does not match");
            }
        }

        foreach (TfBootChain chain in plan.Chains)
        {
            TfNativeEntry linuxEntry = verifyConfig.Entries[(int)chain.LinuxIndex];
            if (linuxEntry.DeviceTreeBlob != chain.DtbIndex)
            {
                throw new InvalidDataException(
                    "the restored TF Linux entry at Image-"
                    + chain.LinuxIndex.ToString("00", CultureInfo.InvariantCulture)
                    + " does not reference its expected DTB section");
            }

            string dtbFile = TfRequireSafeRelativeName(
                TfResolvePayloadFile(verifyConfig, verifyConfig.Entries[(int)chain.DtbIndex], "verify config"),
                "verify config");
            byte[] dtbBytes = File.ReadAllBytes(Path.Combine(verifyDirectory, dtbFile));
            _ = EdlRawDtbValidator.ValidateTfPacked(dtbBytes, chain.Args, chain.Kind, model, chain.BlobIndex);

            TfNativeEntry blobEntry = verifyConfig.Entries[(int)chain.BlobIndex];
            if (chain.RequireBlobType && !string.Equals(blobEntry.Type, TfTypeBlob, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "the restored TF initrd Blob at Image-"
                    + chain.BlobIndex.ToString("00", CultureInfo.InvariantCulture) + " does not carry the Blob type");
            }
        }

        string shimName = plan.Config.ShimFileName;
        if (plan.Config.GeneratedByKshimSource)
        {
            if (originalFiles is null
                || !originalFiles.TryGetValue(shimName, out (long Length, string Sha256) sourceShim)
                || !verifyFiles.TryGetValue(shimName, out (long Length, string Sha256) verifyShim)
                || !string.Equals(verifyShim.Sha256, sourceShim.Sha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException("the current Shim.bin did not survive the pack/unpack round trip");
            }
        }
        else
        {
            if (!verifyFiles.TryGetValue(TfPackageShimFileName, out (long Length, string Sha256) verifyShim)
                || plan.PackageShimSha256 is null
                || !string.Equals(verifyShim.Sha256, plan.PackageShimSha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException("the package runtime shim did not survive the pack/unpack round trip");
            }
        }

        return verifyFiles;
    }

    private static bool TfEntryFieldsEqual(TfNativeEntry left, TfNativeEntry right) =>
        left.Name == right.Name
        && left.Type == right.Type
        && left.BaseImage == right.BaseImage
        && left.HasAlign == right.HasAlign
        && left.Align == right.Align
        && left.Path == right.Path
        && left.PayloadFrom == right.PayloadFrom
        && left.CopyTo == right.CopyTo
        && left.CopySizeMax == right.CopySizeMax
        && left.EntryOffset == right.EntryOffset
        && left.DeviceTreeBlob == right.DeviceTreeBlob;

    // ------------------------------------------------------------- native config model

    private sealed class TfNativeConfig
    {
        internal string ShimFileName { get; set; } = string.Empty;

        internal string OutputFileName { get; set; } = string.Empty;

        internal uint DefaultIndex { get; set; }

        internal uint TimeoutMs { get; set; }

        internal List<TfNativeEntry> Entries { get; } = new();

        internal bool GeneratedByKshimSource { get; set; }
    }

    private sealed class TfNativeEntry
    {
        internal uint Index { get; set; }

        internal string Name { get; set; } = string.Empty;

        internal string? Path { get; set; }

        internal uint? PayloadFrom { get; set; }

        internal string Type { get; set; } = string.Empty;

        internal bool BaseImage { get; set; }

        internal bool HasAlign { get; set; }

        internal ulong Align { get; set; }

        internal ulong? CopyTo { get; set; }

        internal ulong? CopySizeMax { get; set; }

        internal ulong? EntryOffset { get; set; }

        internal uint? DeviceTreeBlob { get; set; }
    }

    private static TfNativeEntry TfCloneEntry(TfNativeEntry entry) => new()
    {
        Index = entry.Index,
        Name = entry.Name,
        Path = entry.Path,
        PayloadFrom = entry.PayloadFrom,
        Type = entry.Type,
        BaseImage = entry.BaseImage,
        HasAlign = entry.HasAlign,
        Align = entry.Align,
        CopyTo = entry.CopyTo,
        CopySizeMax = entry.CopySizeMax,
        EntryOffset = entry.EntryOffset,
        DeviceTreeBlob = entry.DeviceTreeBlob,
    };

    private static TfNativeConfig TfParseNativeConfig(string[] lines, string subject)
    {
        var config = new TfNativeConfig();
        TfNativeEntry? current = null;
        bool packSeen = false;
        bool manifestSeen = false;
        bool manifestTypeSeen = false;
        bool shimSeen = false;
        bool outputSeen = false;
        bool defaultSeen = false;
        bool timeoutSeen = false;
        uint nextIndex = 0;

        foreach (string rawLine in lines)
        {
            string line = rawLine.Trim();
            if (line.Length == 0)
            {
                continue;
            }

            if (line[0] == '[')
            {
                if (!line.EndsWith(']'))
                {
                    throw new InvalidDataException(subject + ": section line '" + line + "' is not bracketed");
                }

                if (manifestSeen)
                {
                    throw new InvalidDataException(subject + ": a section follows the [Manifest] section");
                }

                string section = line[1..^1];
                if (string.Equals(section, "Pack", StringComparison.Ordinal))
                {
                    if (packSeen)
                    {
                        throw new InvalidDataException(subject + ": duplicate [Pack] section");
                    }

                    packSeen = true;
                    current = null;
                    continue;
                }

                if (string.Equals(section, "Manifest", StringComparison.Ordinal))
                {
                    if (!packSeen)
                    {
                        throw new InvalidDataException(subject + ": [Manifest] appears before [Pack]");
                    }

                    manifestSeen = true;
                    current = null;
                    continue;
                }

                if (section.StartsWith("Image-", StringComparison.Ordinal)
                    && section.Length >= "Image-NN".Length
                    && uint.TryParse(section.AsSpan("Image-".Length), NumberStyles.None,
                        CultureInfo.InvariantCulture, out uint sectionIndex)
                    && sectionIndex == nextIndex)
                {
                    current = new TfNativeEntry { Index = sectionIndex };
                    config.Entries.Add(current);
                    nextIndex = sectionIndex + 1;
                    continue;
                }

                throw new InvalidDataException(subject + ": unsupported config section '" + line + "'");
            }

            int separator = line.IndexOf('=');
            if (separator <= 0)
            {
                throw new InvalidDataException(subject + ": config line '" + line + "' is not a key=value pair");
            }

            string key = line[..separator].Trim();
            string value = line[(separator + 1)..].Trim();
            if (manifestSeen)
            {
                if (!string.Equals(key, "Type", StringComparison.Ordinal)
                    || !string.Equals(value, "Manifest", StringComparison.Ordinal))
                {
                    throw new InvalidDataException(subject + ": [Manifest] only accepts the required field Type=Manifest");
                }

                manifestTypeSeen = TfSetOnce(manifestTypeSeen, subject, "[Manifest] Type");
                continue;
            }

            if (current is null)
            {
                if (!packSeen)
                {
                    throw new InvalidDataException(subject + ": a field appears before [Pack]");
                }

                switch (key)
                {
                    case "Shim":
                        shimSeen = TfSetOnce(shimSeen, subject, key);
                        config.ShimFileName = TfRequireSafeRelativeName(value, subject);
                        break;
                    case "Output":
                        outputSeen = TfSetOnce(outputSeen, subject, key);
                        config.OutputFileName = TfRequireSafeRelativeName(value, subject);
                        break;
                    case "Default":
                        defaultSeen = TfSetOnce(defaultSeen, subject, key);
                        config.DefaultIndex = TfParseEntryRef(value, subject);
                        break;
                    case "Timeout":
                        timeoutSeen = TfSetOnce(timeoutSeen, subject, key);
                        if (!uint.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out uint timeoutMs))
                        {
                            throw new InvalidDataException(subject + ": Timeout value '" + value + "' is not a number");
                        }

                        config.TimeoutMs = timeoutMs;
                        break;
                    default:
                        throw new InvalidDataException(subject + ": unknown [Pack] key '" + key + "'");
                }

                continue;
            }

            switch (key)
            {
                case "Name":
                    if (current.Name.Length > 0)
                    {
                        throw new InvalidDataException(subject + ": duplicate Name in Image-"
                            + current.Index.ToString("00", CultureInfo.InvariantCulture));
                    }

                    current.Name = value;
                    break;
                case "Path":
                    if (current.Path is not null || current.PayloadFrom is not null)
                    {
                        throw new InvalidDataException(subject + ": duplicate payload reference in Image-"
                            + current.Index.ToString("00", CultureInfo.InvariantCulture));
                    }

                    current.Path = TfRequireSafeRelativeName(value, subject);
                    break;
                case "PayloadFrom":
                    if (current.Path is not null || current.PayloadFrom is not null)
                    {
                        throw new InvalidDataException(subject + ": duplicate payload reference in Image-"
                            + current.Index.ToString("00", CultureInfo.InvariantCulture));
                    }

                    current.PayloadFrom = TfParseEntryRef(value, subject);
                    break;
                case "Type":
                    if (current.Type.Length > 0)
                    {
                        throw new InvalidDataException(subject + ": duplicate Type in Image-"
                            + current.Index.ToString("00", CultureInfo.InvariantCulture));
                    }

                    current.Type = value;
                    break;
                case "BaseImage":
                    if (string.Equals(value, "true", StringComparison.Ordinal))
                    {
                        current.BaseImage = true;
                    }
                    else if (string.Equals(value, "false", StringComparison.Ordinal))
                    {
                        current.BaseImage = false;
                    }
                    else
                    {
                        throw new InvalidDataException(subject + ": BaseImage value '" + value + "' is not true/false");
                    }

                    break;
                case "Align":
                    if (current.HasAlign)
                    {
                        throw new InvalidDataException(subject + ": duplicate Align in Image-"
                            + current.Index.ToString("00", CultureInfo.InvariantCulture));
                    }

                    if (!ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out ulong align))
                    {
                        throw new InvalidDataException(subject + ": Align value '" + value + "' is not a number");
                    }

                    current.HasAlign = true;
                    current.Align = align;
                    break;
                case "CopyTo":
                case "CopySizeMax":
                case "EntryOffset":
                    ulong parsed = TfParseHexField(value, subject, key);
                    if (key == "CopyTo")
                    {
                        if (current.CopyTo is not null)
                        {
                            throw new InvalidDataException(subject + ": duplicate CopyTo field");
                        }

                        current.CopyTo = parsed;
                    }
                    else if (key == "CopySizeMax")
                    {
                        if (current.CopySizeMax is not null)
                        {
                            throw new InvalidDataException(subject + ": duplicate CopySizeMax field");
                        }

                        current.CopySizeMax = parsed;
                    }
                    else
                    {
                        if (current.EntryOffset is not null)
                        {
                            throw new InvalidDataException(subject + ": duplicate EntryOffset field");
                        }

                        current.EntryOffset = parsed;
                    }

                    break;
                case "DeviceTreeBlob":
                    if (current.DeviceTreeBlob is not null)
                    {
                        throw new InvalidDataException(subject + ": duplicate DeviceTreeBlob field");
                    }

                    current.DeviceTreeBlob = TfParseEntryRef(value, subject);
                    break;
                default:
                    throw new InvalidDataException(subject + ": unknown key '" + key + "' in Image-"
                        + current.Index.ToString("00", CultureInfo.InvariantCulture));
            }
        }

        if (!packSeen || !manifestSeen)
        {
            throw new InvalidDataException(subject + " is missing the [Pack] or [Manifest] section");
        }

        if (!manifestTypeSeen)
        {
            throw new InvalidDataException(subject + " is missing the required [Manifest] field Type=Manifest");
        }

        if (!shimSeen || !outputSeen || !defaultSeen || !timeoutSeen)
        {
            throw new InvalidDataException(subject + " is missing a required [Pack] field");
        }

        if (config.Entries.Count == 0)
        {
            throw new InvalidDataException(subject + " carries no image sections");
        }

        uint count = (uint)config.Entries.Count;
        for (int i = 0; i < config.Entries.Count; i++)
        {
            TfNativeEntry entry = config.Entries[i];
            if (entry.Name.Length == 0 || entry.Type.Length == 0 || !entry.HasAlign)
            {
                throw new InvalidDataException(subject + ": Image-"
                    + entry.Index.ToString("00", CultureInfo.InvariantCulture) + " is missing Name, Type or Align");
            }

            if ((entry.Path is null) == (entry.PayloadFrom is null))
            {
                throw new InvalidDataException(subject + ": Image-"
                    + entry.Index.ToString("00", CultureInfo.InvariantCulture)
                    + " must carry exactly one of Path or PayloadFrom");
            }

            if (entry.BaseImage != (i == 0))
            {
                throw new InvalidDataException(subject + ": only the first image section may be the BaseImage");
            }

            if (entry.PayloadFrom is uint aliasSource && aliasSource >= count)
            {
                throw new InvalidDataException(subject + ": PayloadFrom references a section outside the config");
            }

            if (entry.DeviceTreeBlob is uint blobSource && blobSource >= count)
            {
                throw new InvalidDataException(subject + ": DeviceTreeBlob references a section outside the config");
            }
        }

        return config;
    }

    private static bool TfSetOnce(bool seen, string subject, string key)
    {
        if (seen)
        {
            throw new InvalidDataException(subject + ": duplicate " + key + " field");
        }

        return true;
    }

    private static ulong TfParseHexField(string value, string subject, string key)
    {
        bool parsed;
        ulong number;
        if (value.StartsWith("0x", StringComparison.Ordinal))
        {
            parsed = ulong.TryParse(value.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out number);
        }
        else
        {
            parsed = ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out number);
        }

        if (!parsed)
        {
            throw new InvalidDataException(
                subject + ": " + key + " value '" + value + "' is not a 0x hex or decimal number");
        }

        return number;
    }

    private static uint TfParseEntryRef(string value, string subject)
    {
        if (!value.StartsWith("Image-", StringComparison.Ordinal))
        {
            throw new InvalidDataException(subject + ": entry reference '" + value + "' is not an Image-NN section");
        }

        string digits = value["Image-".Length..];
        if (digits.Length < 2
            || !uint.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out uint index))
        {
            throw new InvalidDataException(subject + ": entry reference '" + value + "' is not a valid index");
        }

        return index;
    }

    private static byte[] TfSerializeNativeConfig(TfNativeConfig config)
    {
        var text = new StringBuilder(1024);
        text.Append("[Pack]\nShim=").Append(config.ShimFileName)
            .Append("\nOutput=").Append(config.OutputFileName)
            .Append("\nDefault=Image-").Append(config.DefaultIndex.ToString("00", CultureInfo.InvariantCulture))
            .Append("\nTimeout=").Append(config.TimeoutMs.ToString(CultureInfo.InvariantCulture))
            .Append("\n\n");

        foreach (TfNativeEntry entry in config.Entries)
        {
            text.Append("[Image-").Append(entry.Index.ToString("00", CultureInfo.InvariantCulture)).Append("]\n");
            text.Append("Name=").Append(entry.Name).Append('\n');
            if (entry.Path is not null)
            {
                text.Append("Path=").Append(entry.Path).Append('\n');
            }
            else
            {
                text.Append("PayloadFrom=Image-")
                    .Append(entry.PayloadFrom!.Value.ToString("00", CultureInfo.InvariantCulture))
                    .Append('\n');
            }

            text.Append("Type=").Append(entry.Type).Append('\n');
            text.Append("BaseImage=").Append(entry.BaseImage ? "true" : "false").Append('\n');
            if (entry.HasAlign)
            {
                text.Append("Align=").Append(entry.Align.ToString(CultureInfo.InvariantCulture)).Append('\n');
            }
            if (entry.CopyTo is ulong copyTo)
            {
                text.Append("CopyTo=0x").Append(copyTo.ToString("x", CultureInfo.InvariantCulture)).Append('\n');
            }

            if (entry.CopySizeMax is ulong copySizeMax)
            {
                text.Append("CopySizeMax=0x").Append(copySizeMax.ToString("x", CultureInfo.InvariantCulture))
                    .Append('\n');
            }

            if (entry.EntryOffset is ulong entryOffset)
            {
                text.Append("EntryOffset=0x").Append(entryOffset.ToString("x", CultureInfo.InvariantCulture))
                    .Append('\n');
            }

            if (entry.DeviceTreeBlob is uint blob)
            {
                text.Append("DeviceTreeBlob=Image-").Append(blob.ToString("00", CultureInfo.InvariantCulture))
                    .Append('\n');
            }

            text.Append('\n');
        }

        text.Append("[Manifest]\nType=Manifest\n");
        byte[] bytes = ConfigUtf8.GetBytes(text.ToString());
        if (bytes.Length > ConfigBytesLimit)
        {
            throw new InvalidDataException("the generated TF native config exceeds the bounded config size");
        }

        return bytes;
    }

    private static string TfResolvePayloadFile(TfNativeConfig config, TfNativeEntry entry, string subject)
    {
        var visited = new HashSet<uint>();
        uint index = entry.Index;
        while (true)
        {
            if (!visited.Add(index))
            {
                throw new InvalidDataException(subject + ": the payload alias graph contains a cycle at Image-"
                    + index.ToString("00", CultureInfo.InvariantCulture));
            }

            TfNativeEntry node = config.Entries[(int)index];
            if (node.Path is string path)
            {
                return path;
            }

            if (node.PayloadFrom is uint from)
            {
                if (from >= (uint)config.Entries.Count)
                {
                    throw new InvalidDataException(subject + ": PayloadFrom references a section outside the config");
                }

                index = from;
                continue;
            }

            throw new InvalidDataException(subject + ": Image-"
                + index.ToString("00", CultureInfo.InvariantCulture) + " has no payload Path or PayloadFrom");
        }
    }

    private static string TfRequireSafeRelativeName(string name, string subject)
    {
        if (name.Length == 0 || name.Length > 96)
        {
            throw new InvalidDataException(subject + ": payload file name is empty or too long");
        }

        if (name.Contains('/') || name.Contains('\\') || name.Contains(':')
            || name.Contains("..", StringComparison.Ordinal) || name.StartsWith(".", StringComparison.Ordinal)
            || !string.Equals(name, Path.GetFileName(name), StringComparison.Ordinal))
        {
            throw new InvalidDataException(subject + ": payload file name '" + name + "' is not a safe relative name");
        }

        return name;
    }

    private static (string Boot, string Root)? TfExtractUuidPair(string bootArgs)
    {
        string? boot = null;
        string? root = null;
        foreach (string token in bootArgs.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            string trimmed = token.Trim();
            if (trimmed.StartsWith("boot=UUID=", StringComparison.OrdinalIgnoreCase))
            {
                boot = trimmed["boot=UUID=".Length..];
            }
            else if (trimmed.StartsWith("root=UUID=", StringComparison.OrdinalIgnoreCase))
            {
                root = trimmed["root=UUID=".Length..];
            }
        }

        if (boot is null || root is null || boot.Length == 0 || root.Length == 0)
        {
            return null;
        }

        return (boot.ToLowerInvariant(), root.ToLowerInvariant());
    }

    // ------------------------------------------------------------- staging and cleanup

    private static (string Path, long Bytes, string Sha256) TfStagePaddedKernel(
        HeldLease kernelLease,
        byte[] baseHeader,
        string childDirectory,
        long budget,
        CancellationToken ct)
    {
        byte[] linuxHeader = new byte[Arm64HeaderProbeBytes];
        ReadExactly(kernelLease.Stream, linuxHeader, 0, linuxHeader.Length);
        RequireArm64Header(linuxHeader, "package kernel payload");

        ulong linuxImageSize = ReadLeU64(linuxHeader, Arm64ImageSizeField);
        if (linuxImageSize > (ulong)long.MaxValue)
        {
            throw new InvalidDataException("the package kernel image_size does not fit a signed 64-bit length");
        }

        long linuxTarget = Math.Max(kernelLease.Claim.Length, (long)linuxImageSize);
        if (linuxTarget < Arm64HeaderProbeBytes)
        {
            throw new InvalidDataException("the package kernel target length is below the ARM64 header");
        }

        if (linuxTarget > budget)
        {
            throw new InvalidDataException(
                "the BSS-expanded Linux payload " + linuxTarget.ToString(CultureInfo.InvariantCulture)
                + " exceeds the slot loader budget " + budget.ToString(CultureInfo.InvariantCulture));
        }

        if ((ReadLeU64(baseHeader, Arm64TextOffsetField) & 0x1FFFFFUL)
            != (ReadLeU64(linuxHeader, Arm64TextOffsetField) & 0x1FFFFFUL))
        {
            throw new InvalidDataException("the base and package kernel text_offset disagree in the low 21 bits");
        }

        string linuxPaddedPath = Path.Combine(childDirectory, LinuxPaddedFileName);
        long linuxPaddedBytes;
        string linuxPaddedSha256;
        using (FileStream output = CreateNew(linuxPaddedPath, "BSS-expanded Linux payload"))
        {
            kernelLease.Stream.Position = 0;
            using (IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
            {
                CopyTo(kernelLease.Stream, output, hash, ct);
                WriteZeros(output, linuxTarget - kernelLease.Claim.Length, hash, ct);
                linuxPaddedSha256 = ToHex(hash.GetHashAndReset());
            }

            output.Flush(true);
            linuxPaddedBytes = output.Length;
        }

        if (linuxPaddedBytes != linuxTarget)
        {
            throw new InvalidDataException("the BSS-expanded Linux payload length changed on disk");
        }

        using (FileStream padded = OpenRead(linuxPaddedPath, "BSS-expanded Linux payload"))
        {
            byte[] writtenHeader = new byte[Arm64HeaderProbeBytes];
            ReadExactly(padded, writtenHeader, 0, writtenHeader.Length);
            if (ReadLeU64(writtenHeader, Arm64ImageSizeField) != (ulong)linuxPaddedBytes)
            {
                throw new InvalidDataException(
                    "the staged BSS-expanded Linux payload image_size does not equal its staged length");
            }
        }

        return (linuxPaddedPath, linuxPaddedBytes, linuxPaddedSha256);
    }

    private static (long Bytes, string Sha256) TfHashFile(string path, string subject, CancellationToken ct)
    {
        using FileStream stream = OpenRead(path, subject);
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long total = 0;
        var buffer = new byte[CopyChunkBytes];
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            int read = stream.Read(buffer, 0, buffer.Length);
            if (read <= 0)
            {
                break;
            }

            hash.AppendData(buffer, 0, read);
            total += read;
        }

        return (total, ToHex(hash.GetHashAndReset()));
    }

    private static (long Bytes, string Sha256) TfCopyFile(
        string sourcePath,
        string destinationPath,
        string subject,
        CancellationToken ct)
    {
        using FileStream source = OpenRead(sourcePath, subject);
        return CopyHeldToNewFile(source, destinationPath, subject, ct);
    }

    private static void TfCleanupOnFailure(string? child, List<HeldLease> leases)
    {
        var cleanupErrors = new List<Exception>();
        foreach (HeldLease lease in leases)
        {
            try
            {
                lease.Stream.Close();
            }
            catch (Exception exception)
                when (exception is IOException or UnauthorizedAccessException or ObjectDisposedException)
            {
                cleanupErrors.Add(exception);
            }
        }

        leases.Clear();
        if (child is not null)
        {
            try
            {
                if (Directory.Exists(child))
                {
                    Directory.Delete(child, recursive: true);
                }
            }
            catch (Exception exception)
                when (exception is IOException or UnauthorizedAccessException or ArgumentException)
            {
                // Only this newly created child is targeted; never the caller's paths or backups.
                cleanupErrors.Add(exception);
            }
        }

        if (cleanupErrors.Count > 0)
        {
            throw new AggregateException("the TF payload failure cleanup did not fully succeed", cleanupErrors);
        }
    }

    private static Dictionary<string, string> TfShaMap(Dictionary<string, (long Length, string Sha256)> files)
    {
        var map = new Dictionary<string, string>(files.Count, StringComparer.Ordinal);
        foreach (KeyValuePair<string, (long Length, string Sha256)> file in files)
        {
            map.Add(file.Key, file.Value.Sha256);
        }

        return map;
    }

    // ------------------------------------------------------------- verification report

    private static void RequireTemplateProofMatch(
        CurrentBootInitializedInactiveProof proof,
        CurrentBootSlotInputs inputs)
    {
        if (!string.Equals(proof.SourceSlot, "a", StringComparison.Ordinal)
            || !string.Equals(proof.TargetSlot, "b", StringComparison.Ordinal)
            || !string.Equals(inputs.Slot, "a", StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "the initialized inactive template proof requires source slot a targeting inactive slot b");
        }

        if (!string.Equals(inputs.Boot.Sha256, proof.SourceBoot.Sha256, StringComparison.OrdinalIgnoreCase)
            || inputs.Boot.Length != proof.SourceBoot.Length
            || !string.Equals(
                Path.GetFullPath(inputs.Boot.Path),
                Path.GetFullPath(proof.SourceBoot.Path),
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("the source inputs do not match the template proof source boot");
        }

        RequireTemplateClaimMatch("boot", inputs.Boot, proof.Claims["boot_a"]);
        RequireTemplateClaimMatch("vendor_boot", inputs.VendorBoot, proof.Claims["vendor_boot_a"]);
        RequireTemplateClaimMatch("init_boot", inputs.InitBoot, proof.Claims["init_boot_a"]);
        RequireTemplateClaimMatch("abl", inputs.Abl, proof.Claims["abl_a"]);
        RequireTemplateClaimMatch("xbl_config", inputs.XblConfig, proof.Claims["xbl_config_a"]);
        RequireTemplateClaimMatch("vbmeta", inputs.Vbmeta, proof.Claims["vbmeta_a"]);
    }

    private static void RequireTemplateClaimMatch(
        string subject,
        VerifiedEdlFile input,
        VerifiedEdlFile claim)
    {
        if (input.Length != claim.Length
            || !string.Equals(input.Sha256, claim.Sha256, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(
                Path.GetFullPath(input.Path),
                Path.GetFullPath(claim.Path),
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "the source input '" + subject + "' does not match the template proof claim");
        }
    }

    private static byte[] TfBuildVerificationReport(
        TfBootPurpose purpose,
        string sourceSlot,
        string deviceModel,
        bool isKshim,
        long loaderBudgetMaxRawBytes,
        long packedLength,
        string packedRawSha256,
        string runtimeSha256,
        string? sourceCompositeSha256,
        long baseImageLength,
        string baseImageSha256,
        string linuxPaddedSha256,
        string initrdSha256,
        TfPlannedBody plan,
        Dictionary<string, string> payloadSha256,
        Dictionary<string, string> originalPayloadSha256,
        string? templateSourceSlot,
        string? templateBootSha256)
    {
        var json = new StringBuilder(2048);
        json.Append("{\n");
        json.Append("  \"schema\": \"TF-NATIVE-PAYLOAD-01\",\n");
        json.Append("  \"purpose\": ").Append(TfJsonQuote(purpose.ToString())).Append(",\n");
        json.Append("  \"sourceSlot\": ").Append(TfJsonQuote(sourceSlot)).Append(",\n");
        json.Append("  \"deviceModel\": ").Append(TfJsonQuote(deviceModel)).Append(",\n");
        json.Append("  \"sourceKind\": ").Append(TfJsonQuote(isKshim ? "kshim" : "android")).Append(",\n");
        json.Append("  \"loaderBudgetMaxRawBytes\": ")
            .Append(loaderBudgetMaxRawBytes.ToString(CultureInfo.InvariantCulture)).Append(",\n");
        json.Append("  \"packedRaw\": {\"length\": ").Append(packedLength.ToString(CultureInfo.InvariantCulture))
            .Append(", \"sha256\": ").Append(TfJsonQuote(packedRawSha256)).Append("},\n");
        json.Append("  \"baseImage\": {\"length\": ").Append(baseImageLength.ToString(CultureInfo.InvariantCulture))
            .Append(", \"sha256\": ").Append(TfJsonQuote(baseImageSha256)).Append("},\n");
        json.Append("  \"sourceCompositeSha256\": ")
            .Append(sourceCompositeSha256 is null ? "null" : TfJsonQuote(sourceCompositeSha256)).Append(",\n");
        json.Append("  \"linuxPaddedSha256\": ").Append(TfJsonQuote(linuxPaddedSha256)).Append(",\n");
        json.Append("  \"initrdSha256\": ").Append(TfJsonQuote(initrdSha256)).Append(",\n");
        json.Append("  \"runtimeShimSha256\": ").Append(TfJsonQuote(runtimeSha256)).Append(",\n");
        json.Append("  \"templateSourceSlot\": ")
            .Append(templateSourceSlot is null ? "null" : TfJsonQuote(templateSourceSlot)).Append(",\n");
        json.Append("  \"templateBootSha256\": ")
            .Append(templateBootSha256 is null ? "null" : TfJsonQuote(templateBootSha256)).Append(",\n");
        json.Append("  \"defaultIndex\": ").Append(plan.Config.DefaultIndex.ToString(CultureInfo.InvariantCulture))
            .Append(",\n");
        json.Append("  \"timeoutMs\": ").Append(plan.Config.TimeoutMs.ToString(CultureInfo.InvariantCulture))
            .Append(",\n");
        json.Append("  \"entryCount\": ").Append(plan.Config.Entries.Count.ToString(CultureInfo.InvariantCulture))
            .Append(",\n");
        json.Append("  \"preservedEntryCount\": ")
            .Append(plan.PreservedEntryCount.ToString(CultureInfo.InvariantCulture)).Append(",\n");
        json.Append("  \"appendedEntryCount\": ")
            .Append(plan.AppendedEntryCount.ToString(CultureInfo.InvariantCulture)).Append(",\n");
        json.Append("  \"reusedExistingTfPair\": ").Append(plan.ReusedExistingPair ? "true" : "false").Append(",\n");
        json.Append("  \"reusedKernelIndex\": ")
            .Append(plan.ReusedKernelIndex is uint reused
                ? reused.ToString(CultureInfo.InvariantCulture)
                : "null")
            .Append(",\n");
        json.Append("  \"maintenanceInitramfsValidated\": ")
            .Append(purpose == TfBootPurpose.RamMaintenance ? "true" : "false").Append(",\n");
        TfAppendJsonMap(json, "payloadSha256", payloadSha256);
        json.Append(",\n");
        TfAppendJsonMap(json, "originalPayloadSha256", originalPayloadSha256);
        json.Append("\n}\n");
        byte[] bytes = TfReportUtf8.GetBytes(json.ToString());
        if (bytes.Length > TfReportBytesLimit)
        {
            throw new InvalidDataException("the TF verification report exceeds its bounded size");
        }

        return bytes;
    }

    private static void TfAppendJsonMap(
        StringBuilder json,
        string key,
        IReadOnlyDictionary<string, string> map)
    {
        json.Append("  ").Append(TfJsonQuote(key)).Append(": {");
        bool first = true;
        foreach (KeyValuePair<string, string> pair in map)
        {
            if (!first)
            {
                json.Append(", ");
            }

            first = false;
            json.Append(TfJsonQuote(pair.Key)).Append(": ").Append(TfJsonQuote(pair.Value));
        }

        json.Append('}');
    }

    private static string TfJsonQuote(string value)
    {
        var quoted = new StringBuilder(value.Length + 2);
        quoted.Append('"');
        foreach (char ch in value)
        {
            switch (ch)
            {
                case '"':
                    quoted.Append("\\\"");
                    break;
                case '\\':
                    quoted.Append("\\\\");
                    break;
                case '\n':
                    quoted.Append("\\n");
                    break;
                case '\r':
                    quoted.Append("\\r");
                    break;
                case '\t':
                    quoted.Append("\\t");
                    break;
                default:
                    if (ch < 0x20)
                    {
                        quoted.Append("\\u").Append(((int)ch).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        quoted.Append(ch);
                    }

                    break;
            }
        }

        quoted.Append('"');
        return quoted.ToString();
    }
}
