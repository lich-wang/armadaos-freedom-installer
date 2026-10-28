// BM001: one-slot staging plus three native commands for the EDL raw boot builder protocol 1.
// This file orchestrates only: base recovery, envelope repack, DTB validation, manifest policy and
// AVB field work stay with the existing owners. Nothing here reimplements packing, the manifest
// parser, the five-source recovery, the AVB-NONE envelope or the FDT reader.
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

public static partial class EdlRawBootBuilder
{
    /// <summary>Fixed boot partition length of the protocol 1 source slot, in bytes.</summary>
    private const long SourceBootPartitionBytes = 100_663_296L;

    private const int Arm64HeaderProbeBytes = 64;

    private const int Arm64MagicField = 0x38;

    private const int Arm64TextOffsetField = 8;

    private const int Arm64ImageSizeField = 16;

    private const int Arm64FlagsField = 24;

    private const int Arm64ManifestOffsetField = 32;

    private const int Arm64ManifestSizeField = 40;

    private const int Arm64ShimOffsetField = 48;

    private const uint BranchOpcodeMask = 0xFC000000u;

    private const uint BranchLinkOpcode = 0x94000000u;

    private const uint BranchImmediateMask = 0x03FFFFFFu;

    private const uint BranchImmediateSign = 0x02000000u;

    private const long BranchSignedRange = 0x08000000L;

    private const uint ManifestMagic = 0x464D504Bu;

    private const int ManifestHeaderBytes = 60;

    private const uint ManifestEntryCount = 7u;

    private const uint ManifestDefaultIndex = 1u;

    private const uint ManifestTimeoutMillis = 8000u;

    private const long RuntimePayloadBytes = 4_194_304L;

    private const long DtbPayloadLimitBytes = 8L * 1024 * 1024;

    private const long ConfigBytesLimit = 1024L * 1024;

    private const int DiagnosticTextLimit = 800;

    private const string BaseImageFileName = "BaseImage";

    private const string LinuxPaddedFileName = "linux-padded";

    private const string RuntimeFileName = "runtime.bin";

    private const string NormalDtbFileName = "dtb-normal.dtb";

    private const string DiagnosticDtbFileName = "dtb-diagnostic.dtb";

    private const string InitramfsFileName = "initramfs";

    private const string BuildConfigFileName = "build.cfg";

    private const string PackedRawFileName = "PackedKernel";

    private const string UnpackedDirectoryName = "unpacked";

    private const string UnpackedConfigFileName = "config.cfg";

    private const string RepackedRawFileName = "RepackedKernel";

    private const string CandidateBootFileName = "candidate-boot.img";

    private const string ReportFileName = "verification.json";

    private const string ShimPayloadFileName = "Shim.bin";

    private const string Image01PayloadFileName = "Image-01-Linux";

    private const string Image03PayloadFileName = "Image-03-DTB";

    private const string Image04PayloadFileName = "Image-04-DTB";

    private const string Image05PayloadFileName = "Image-05-Blob";

    private const string PayloadBase = "base";

    private const string PayloadLinuxPadded = "linux-padded";

    private const string PayloadRuntime = "runtime";

    private const string PayloadNormalDtb = "dtb-normal";

    private const string PayloadDiagnosticDtb = "dtb-diagnostic";

    private const string PayloadInitramfs = "initramfs";

    private static readonly TimeSpan NativeCommandTimeout = TimeSpan.FromMinutes(3);

    private static readonly UTF8Encoding ConfigUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private static readonly string[] SlotSourceRoles =
    {
        "current_boot",
        "vendor_boot",
        "init_boot",
        "abl",
        "xbl_config",
    };

    /// <summary>
    /// Builds one slot of the protocol 1 candidate boot. Only the two pinned native tools and the
    /// existing owners do the real format work; this method stages, commands, observes and refuses.
    /// </summary>
    /// <exception cref="ArgumentNullException">Request or runner is null.</exception>
    /// <exception cref="ArgumentException">The slot or the chosen parent is unusable.</exception>
    /// <exception cref="OperationCanceledException">The token is already cancelled.</exception>
    public static Task<EdlRawBuiltBoot> BuildAsync(
        EdlRawBootBuildRequest request,
        ICommandRunner runner,
        CancellationToken cancellationToken = default)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (runner is null)
        {
            throw new ArgumentNullException(nameof(runner));
        }

        cancellationToken.ThrowIfCancellationRequested();

        if (request.Slot is not ("a" or "b"))
        {
            throw new ArgumentException("slot must be exactly 'a' or 'b'.", nameof(request));
        }

        _ = RequireSourceSlot(request);

        string chosenParent = NormalizeParent(request.ChosenParent);

        return Task.Run(
            () => BuildCoreAsync(request, runner, chosenParent, cancellationToken),
            cancellationToken);
    }

    /// <summary>
    /// Rehashes one held output lease against its claim. Used only by the result's own
    /// <c>RevalidateAsync</c>, so the chunk hashing stays in this partial class.
    /// </summary>
    internal static void VerifyHeldOutput(
        FileStream stream,
        VerifiedEdlFile claim,
        string role,
        CancellationToken cancellationToken) =>
        VerifyClaim(stream, claim, role, cancellationToken);

    // ------------------------------------------------------------------ core

    private static async Task<EdlRawBuiltBoot> BuildCoreAsync(
        EdlRawBootBuildRequest request,
        ICommandRunner runner,
        string chosenParent,
        CancellationToken cancellationToken)
    {
        CancellationToken token = cancellationToken;
        token.ThrowIfCancellationRequested();

        // The source slot is the slot the five real inputs belong to. A verified inactive-target proof
        // keeps its own target slot as the build target and points at the opposite slot as the source.
        string sourceSlot = RequireSourceSlot(request);
        EdlRawInactiveSlotBackup? inactiveBackup = request.InactiveSlotBackup;

        string parent = RequirePlainDirectory(chosenParent, "chosen parent");
        string child = Path.GetFullPath(Path.Combine(
            parent,
            "edl-boot-" + request.Slot + "-" + Guid.NewGuid().ToString("N")));
        string parentPrefix = Path.EndsInDirectorySeparator(parent)
            ? parent
            : parent + Path.DirectorySeparatorChar;
        if (!child.StartsWith(parentPrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("owned build directory would escape the chosen parent");
        }

        // A GUID child is expected to be absent; a pre-existing directory is never adopted or deleted.
        if (Directory.Exists(child))
        {
            throw new IOException("owned build directory already exists: " + child);
        }

        Directory.CreateDirectory(child);
        bool childCreated = true;
        bool ownershipTransferred = false;

        var leases = new List<HeldLease>();
        EdlRawBootTools? tools = null;
        try
        {
            tools = await request.Tools.AcquireAsync(token).ConfigureAwait(false);

            HeldLease current = OpenClaimLease("current_boot", request.CurrentBoot, token);
            leases.Add(current);
            leases.Add(OpenClaimLease("vendor_boot", request.VendorBoot, token));
            leases.Add(OpenClaimLease("init_boot", request.InitBoot, token));
            leases.Add(OpenClaimLease("abl", request.Abl, token));
            leases.Add(OpenClaimLease("xbl_config", request.XblConfig, token));

            HeldLease kernel = OpenPackageLease(request.Package, "kernel", token);
            leases.Add(kernel);
            HeldLease runtime = OpenPackageLease(request.Package, "runtime", token);
            leases.Add(runtime);
            HeldLease initramfs = OpenPackageLease(request.Package, "initramfs", token);
            leases.Add(initramfs);
            HeldLease normalDtbLease = OpenPackageLease(request.Package, "dtb-normal", token);
            leases.Add(normalDtbLease);
            HeldLease diagnosticDtbLease = OpenPackageLease(request.Package, "dtb-diagnostic", token);
            leases.Add(diagnosticDtbLease);

            RequireProtocolOneSourceBoot(current, token);

            // Base export: the existing reader recovers the source-slot Android kernel and writes it once.
            string baseImagePath = Path.Combine(child, BaseImageFileName);
            InternalSlotMaterial material = await InternalSlotMaterialReader
                .AnalyzeAndExportBaseAsync(
                    sourceSlot,
                    request.CurrentBoot,
                    request.VendorBoot,
                    request.InitBoot,
                    request.Abl,
                    request.XblConfig,
                    baseImagePath,
                    token)
                .ConfigureAwait(false);

            var baseClaim = new VerifiedEdlFile(baseImagePath, material.BaseImageLength, material.BaseImageSha256);
            byte[] baseHeader;
            using (FileStream exported = OpenRead(baseImagePath, "exported base image"))
            {
                VerifyClaim(exported, baseClaim, "exported base image", token);
                baseHeader = new byte[Arm64HeaderProbeBytes];
                ReadExactly(exported, baseHeader, 0, baseHeader.Length);
            }

            RequireArm64Header(baseHeader, "exported base image");

            // Image-00 keeps the recovered Android base; Image-01 is the real package kernel lease with
            // its own image_size-driven BSS expansion. They are separate inputs and separate payloads.
            byte[] linuxHeader = new byte[Arm64HeaderProbeBytes];
            ReadExactly(kernel.Stream, linuxHeader, 0, linuxHeader.Length);
            RequireArm64Header(linuxHeader, "package kernel payload");

            ulong linuxImageSize = ReadLeU64(linuxHeader, Arm64ImageSizeField);
            if (linuxImageSize > long.MaxValue)
            {
                throw new InvalidDataException("package kernel image_size does not fit a signed 64-bit length");
            }

            long linuxTarget = Math.Max(kernel.Claim.Length, (long)linuxImageSize);
            if (linuxTarget < Arm64HeaderProbeBytes)
            {
                throw new InvalidDataException("package kernel target length is below the ARM64 header");
            }

            if (linuxTarget > material.LoaderBudget.MaxRawBytes)
            {
                throw new InvalidDataException(
                    "BSS-expanded Linux payload " + linuxTarget.ToString(CultureInfo.InvariantCulture)
                    + " exceeds the slot loader budget "
                    + material.LoaderBudget.MaxRawBytes.ToString(CultureInfo.InvariantCulture));
            }

            if ((ReadLeU64(baseHeader, Arm64TextOffsetField) & 0x1FFFFFUL)
                != (ReadLeU64(linuxHeader, Arm64TextOffsetField) & 0x1FFFFFUL))
            {
                throw new InvalidDataException(
                    "base and package kernel text_offset disagree in the low 21 bits");
            }

            string linuxPaddedPath = Path.Combine(child, LinuxPaddedFileName);
            long linuxPaddedBytes;
            string linuxPaddedSha256;
            using (FileStream output = CreateNew(linuxPaddedPath, "BSS-expanded Linux payload"))
            {
                kernel.Stream.Position = 0;
                using (IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
                {
                    CopyTo(kernel.Stream, output, hash, token);
                    WriteZeros(output, linuxTarget - kernel.Claim.Length, hash, token);
                    linuxPaddedSha256 = ToHex(hash.GetHashAndReset());
                }

                output.Flush(true);
                linuxPaddedBytes = output.Length;
            }

            if (linuxPaddedBytes != linuxTarget)
            {
                throw new InvalidDataException("BSS-expanded Linux payload length changed on disk");
            }

            using (FileStream padded = OpenRead(linuxPaddedPath, "BSS-expanded Linux payload"))
            {
                byte[] writtenLinuxHeader = new byte[Arm64HeaderProbeBytes];
                ReadExactly(padded, writtenLinuxHeader, 0, writtenLinuxHeader.Length);
                if (!writtenLinuxHeader.AsSpan().SequenceEqual(linuxHeader))
                {
                    throw new InvalidDataException("staged Linux payload header differs from the package kernel");
                }
            }

            EdlRawDtbEvidence normalDtb = StageDtb(
                normalDtbLease,
                request.Package.BootRecipe.NormalBootArgs,
                EdlRawDtbKind.Normal,
                request.Package.DeviceModel,
                Path.Combine(child, NormalDtbFileName),
                token);

            EdlRawDtbEvidence diagnosticDtb = StageDtb(
                diagnosticDtbLease,
                request.Package.BootRecipe.DiagnosticBootArgs,
                EdlRawDtbKind.Diagnostic,
                request.Package.DeviceModel,
                Path.Combine(child, DiagnosticDtbFileName),
                token);

            string runtimePath = Path.Combine(child, RuntimeFileName);
            runtime.Stream.Position = 0;
            (long runtimeBytes, string runtimeSha256) = CopyHeldToNewFile(
                runtime.Stream, runtimePath, "package runtime payload", token);
            if (runtimeBytes != RuntimePayloadBytes)
            {
                throw new InvalidDataException(
                    "package runtime payload is " + runtimeBytes.ToString(CultureInfo.InvariantCulture)
                    + " bytes, the protocol 1 contract fixes 4194304");
            }

            string initramfsPath = Path.Combine(child, InitramfsFileName);
            initramfs.Stream.Position = 0;
            (long initramfsBytes, string initramfsSha256) = CopyHeldToNewFile(
                initramfs.Stream, initramfsPath, "package initramfs payload", token);
            if (initramfsBytes <= 0)
            {
                throw new InvalidDataException("package initramfs payload is empty");
            }

            // The staged package kernel claim stays held and re-verified even though the same-slot base
            // is the recovery authority; nothing here substitutes one for the other.
            if (kernel.Stream.Length <= 0)
            {
                throw new InvalidDataException("package kernel payload is empty");
            }

            string configPath = Path.Combine(child, BuildConfigFileName);
            WriteNewFile(
                configPath,
                ConfigUtf8.GetBytes(BuildConfigText(request.Package.DeviceModel)),
                "build configuration",
                token);

            RequireInactiveBackupUsable(inactiveBackup);

            await RunNativeAsync(
                    runner,
                    tools.Packer.Path,
                    new[] { BuildConfigFileName },
                    child,
                    "native packer build.cfg step",
                    token)
                .ConfigureAwait(false);

            string packedPath = Path.Combine(child, PackedRawFileName);
            if (!File.Exists(packedPath))
            {
                throw new InvalidDataException("native packer did not produce PackedKernel");
            }

            PackedRawFacts packed;
            using (FileStream raw = OpenRead(packedPath, "packed raw image"))
            {
                packed = InspectPackedRaw(raw, baseHeader, material.LoaderBudget.MaxRawBytes, token);
            }

            string unpackedDirectory = Path.Combine(child, UnpackedDirectoryName);
            RequireInactiveBackupUsable(inactiveBackup);

            await RunNativeAsync(
                    runner,
                    tools.Unpacker.Path,
                    new[] { PackedRawFileName, UnpackedDirectoryName },
                    child,
                    "native unpacker step",
                    token)
                .ConfigureAwait(false);

            if (!Directory.Exists(unpackedDirectory))
            {
                throw new InvalidDataException("native unpacker did not create the unpacked directory");
            }

            var payloads = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [PayloadBase] = material.BaseImageSha256,
                [PayloadLinuxPadded] = linuxPaddedSha256,
                [PayloadRuntime] = runtimeSha256,
                [PayloadNormalDtb] = normalDtb.Sha256,
                [PayloadDiagnosticDtb] = diagnosticDtb.Sha256,
                [PayloadInitramfs] = initramfsSha256,
            };

            VerifyUnpackedOutput(
                unpackedDirectory,
                baseImagePath,
                linuxPaddedPath,
                runtimePath,
                Path.Combine(child, NormalDtbFileName),
                Path.Combine(child, DiagnosticDtbFileName),
                initramfsPath,
                request.Package.DeviceModel,
                token);

            RequireInactiveBackupUsable(inactiveBackup);

            await RunNativeAsync(
                    runner,
                    tools.Packer.Path,
                    new[] { UnpackedConfigFileName },
                    unpackedDirectory,
                    "native packer repack step",
                    token)
                .ConfigureAwait(false);

            string repackedPath = Path.Combine(unpackedDirectory, RepackedRawFileName);
            if (!File.Exists(repackedPath))
            {
                throw new InvalidDataException("native repack step did not produce RepackedKernel");
            }

            RequireIdenticalFile(packedPath, repackedPath, "repacked raw image", token);

            // Envelope: the existing owner rebuilds the candidate partition from this slot's own boot.
            var packedClaim = new VerifiedEdlFile(packedPath, packed.Bytes, packed.Sha256);
            string candidatePath = Path.Combine(child, CandidateBootFileName);
            EdlRawBootEnvelope envelope = await RepackEnvelopeAsync(
                    request.CurrentBoot,
                    packedClaim,
                    material.LoaderBudget.MaxRawBytes,
                    candidatePath,
                    token)
                .ConfigureAwait(false);

            // Whole-parser readback through the proven reader, never a second manifest implementation.
            InternalSlotMaterial candidateMaterial = await InternalSlotMaterialReader
                .AnalyzeAsync(
                    sourceSlot,
                    envelope.CandidateBoot,
                    request.VendorBoot,
                    request.InitBoot,
                    request.Abl,
                    request.XblConfig,
                    token)
                .ConfigureAwait(false);

            if (!candidateMaterial.IsKshim)
            {
                throw new InvalidDataException("candidate boot does not carry the kshim composite");
            }

            if (candidateMaterial.BaseImageLength != material.BaseImageLength
                || !string.Equals(candidateMaterial.BaseImageSha256, material.BaseImageSha256, StringComparison.Ordinal)
                || candidateMaterial.BaseImageSize != material.BaseImageSize
                || candidateMaterial.BaseTextOffset != material.BaseTextOffset)
            {
                throw new InvalidDataException("candidate boot recovered a different base image than the slot");
            }

            string reportPath = Path.Combine(child, ReportFileName);
            long reportBytes;
            string reportSha256;
            RequireInactiveBackupUsable(inactiveBackup);
            using (FileStream report = CreateNew(reportPath, "verification report"))
            {
                using (Utf8JsonWriter writer = new(report, new JsonWriterOptions { Indented = true }))
                {
                    WriteReport(
                        writer,
                        request,
                        sourceSlot,
                        inactiveBackup,
                        material,
                        tools,
                        envelope,
                        normalDtb,
                        diagnosticDtb,
                        packed,
                        linuxPaddedBytes,
                        linuxPaddedSha256,
                        payloads,
                        candidateMaterial);
                }

                report.Flush(true);
                reportBytes = report.Length;
            }

            reportSha256 = HashFileSha256(reportPath, token);

            // Final input and tool revalidation while every lease is still held.
            foreach (HeldLease lease in leases)
            {
                VerifyClaim(lease.Stream, lease.Claim, lease.Role, token);
            }

            await tools.RevalidateAsync(token).ConfigureAwait(false);

            // A proof disposed in the middle of the build never yields a candidate.
            RequireInactiveBackupUsable(inactiveBackup);

            // The four output leases are the only handles that outlive this method.
            var reportClaim = new VerifiedEdlFile(reportPath, reportBytes, reportSha256);
            FileStream? candidateStream = null;
            FileStream? packedStream = null;
            FileStream? baseStream = null;
            FileStream? reportStream = null;
            try
            {
                candidateStream = OpenHeldOutput(envelope.CandidateBoot, "candidate boot", token);
                packedStream = OpenHeldOutput(packedClaim, "packed raw image", token);
                baseStream = OpenHeldOutput(baseClaim, "exported base image", token);
                reportStream = OpenHeldOutput(reportClaim, "verification report", token);

                var result = new EdlRawBuiltBoot(
                    request.Slot,
                    sourceSlot,
                    inactiveBackup is not null,
                    child,
                    envelope.CandidateBoot,
                    packedClaim,
                    baseClaim,
                    material,
                    request.Package.ManifestFingerprint,
                    envelope,
                    normalDtb,
                    diagnosticDtb,
                    packed.Sha256,
                    payloads,
                    reportClaim,
                    candidateStream,
                    packedStream,
                    baseStream,
                    reportStream);

                // Ownership of the four handles and of the child directory transfers together, atomically,
                // at this exact point: after it the outer finally must not delete anything.
                candidateStream = null;
                packedStream = null;
                baseStream = null;
                reportStream = null;
                ownershipTransferred = true;
                return result;
            }
            finally
            {
                CloseQuietly(candidateStream);
                CloseQuietly(packedStream);
                CloseQuietly(baseStream);
                CloseQuietly(reportStream);
            }
        }
        finally
        {
            // Only this build's own leases and own child are released: caller files, the package, the
            // caller's tools owner and any sibling stay untouched. A single close failure never skips
            // the later closes or the child cleanup, and cleanup ignores cancellation on purpose.
            foreach (HeldLease lease in leases)
            {
                CloseQuietly(lease.Stream);
            }

            if (tools is not null)
            {
                try
                {
                    tools.Dispose();
                }
                catch (IOException)
                {
                }
                catch (ObjectDisposedException)
                {
                }
            }

            if (childCreated && !ownershipTransferred)
            {
                TryDeleteOwnedChild(child);
            }
        }
    }

    // ------------------------------------------------------------------ inactive target

    /// <summary>
    /// Returns the slot the five real inputs belong to and refuses a proof that does not fit this
    /// request. The target slot stays <see cref="EdlRawBootBuildRequest.Slot"/>; only the source moves.
    /// </summary>
    private static string RequireSourceSlot(EdlRawBootBuildRequest request)
    {
        EdlRawInactiveSlotBackup? inactiveBackup = request.InactiveSlotBackup;
        if (inactiveBackup is null)
        {
            return request.Slot;
        }

        inactiveBackup.RequireUsable();

        if (!string.Equals(inactiveBackup.Slot, request.Slot, StringComparison.Ordinal))
        {
            throw new InvalidDataException("inactive backup target slot does not match the requested slot");
        }

        if (request.CurrentBoot.Length != inactiveBackup.CurrentBoot.Length)
        {
            throw new InvalidDataException(
                "source current_boot length does not match the original inactive target boot partition");
        }

        if (!string.Equals(request.Package.DeviceModel, inactiveBackup.Profile.Model, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "package device model does not match the inactive backup profile model");
        }

        return inactiveBackup.SourceSlot;
    }

    /// <summary>Cheap disposal gate only: the proof owns its verified files, so nothing is rehashed here.</summary>
    private static void RequireInactiveBackupUsable(EdlRawInactiveSlotBackup? inactiveBackup) =>
        inactiveBackup?.RequireUsable();

    private static VerifiedEdlFile InactiveBackupClaim(EdlRawInactiveSlotBackup inactiveBackup, string role) =>
        role switch
        {
            "current_boot" => inactiveBackup.CurrentBoot,
            "vendor_boot" => inactiveBackup.VendorBoot,
            "init_boot" => inactiveBackup.InitBoot,
            "abl" => inactiveBackup.Abl,
            "xbl_config" => inactiveBackup.XblConfig,
            _ => throw new InvalidDataException("unknown inactive backup role: " + role),
        };

    // ------------------------------------------------------------------ staging

    private static void RequireProtocolOneSourceBoot(HeldLease current, CancellationToken cancellationToken)
    {
        if (current.Stream.Length != SourceBootPartitionBytes)
        {
            throw new InvalidDataException(
                "current_boot is " + current.Stream.Length.ToString(CultureInfo.InvariantCulture)
                + " bytes, the protocol 1 source partition is "
                + SourceBootPartitionBytes.ToString(CultureInfo.InvariantCulture));
        }

        byte[] header = new byte[BootHeaderBytes];
        ReadExactly(current.Stream, header, 0, header.Length);

        if (!header.AsSpan(0, 8).SequenceEqual(AndroidMagic))
        {
            throw new InvalidDataException("current_boot magic is not ANDROID!");
        }

        if (ReadLeU32(header, 40) != 4)
        {
            throw new InvalidDataException("current_boot header version is not 4");
        }

        if (ReadLeU32(header, 20) != HeaderSizeField)
        {
            throw new InvalidDataException("current_boot header_size is not 1584");
        }

        if (ReadLeU32(header, 12) != 0)
        {
            throw new InvalidDataException("current_boot ramdisk_size is nonzero");
        }

        if (ReadLeU32(header, 1580) != 0)
        {
            throw new InvalidDataException("current_boot signature_size is nonzero");
        }

        cancellationToken.ThrowIfCancellationRequested();
    }

    private static EdlRawDtbEvidence StageDtb(
        HeldLease lease,
        string expectedBootArgs,
        EdlRawDtbKind kind,
        string expectedModel,
        string outputPath,
        CancellationToken cancellationToken)
    {
        byte[] bytes = ReadBoundedBytes(lease.Stream, DtbPayloadLimitBytes, lease.Role, cancellationToken);

        EdlRawDtbEvidence evidence = EdlRawDtbValidator.Validate(
            bytes, expectedBootArgs, kind, expectedModel);

        if (evidence.Length != lease.Claim.Length
            || !string.Equals(evidence.Sha256, lease.Claim.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                lease.Role + ": validated DTB facts do not match the package claim");
        }

        WriteNewFile(outputPath, bytes, lease.Role, cancellationToken);

        if (!string.Equals(HashFileSha256(outputPath, cancellationToken), evidence.Sha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException(lease.Role + ": staged DTB bytes changed on disk");
        }

        return evidence;
    }

    private static byte[] ReadBoundedBytes(
        FileStream stream,
        long limit,
        string subject,
        CancellationToken cancellationToken)
    {
        if (stream.Length <= 0 || stream.Length > limit)
        {
            throw new InvalidDataException(
                subject + " length is outside the bounded staging range");
        }

        byte[] buffer = new byte[(int)stream.Length];
        ReadExactly(stream, buffer, 0, buffer.Length);
        cancellationToken.ThrowIfCancellationRequested();
        return buffer;
    }

    // ------------------------------------------------------------------ configuration

    /// <summary>
    /// The protocol 1 producer configuration: newline LF, UTF-8 without BOM, and only ASCII relative
    /// file names. No absolute drive, UNC or traversal path can appear here.
    /// </summary>
    private static string BuildConfigText(string model)
    {
        var text = new StringBuilder();
        text.Append("[Pack]\n");
        text.Append("Shim=").Append(RuntimeFileName).Append('\n');
        text.Append("Output=").Append(PackedRawFileName).Append('\n');
        text.Append("Default=Image-01\n");
        text.Append("Timeout=").Append(ManifestTimeoutMillis.ToString(CultureInfo.InvariantCulture)).Append('\n');

        text.Append('\n').Append("[Image-00]\n");
        text.Append("Name=原厂 Android\n");
        text.Append("Path=").Append(BaseImageFileName).Append('\n');
        text.Append("Type=Linux\n");
        text.Append("BaseImage=true\n");
        text.Append("Align=21\n");

        text.Append('\n').Append("[Image-01]\n");
        text.Append("Name=机身 Linux\n");
        text.Append("Path=").Append(LinuxPaddedFileName).Append('\n');
        text.Append("Type=Linux\n");
        text.Append("BaseImage=false\n");
        text.Append("Align=21\n");
        text.Append("EntryOffset=0\n");
        text.Append("DeviceTreeBlob=Image-03\n");

        text.Append('\n').Append("[Image-02]\n");
        text.Append("Name=Linux 诊断模式\n");
        text.Append("Type=Linux\n");
        text.Append("PayloadFrom=Image-01\n");
        text.Append("Align=21\n");
        text.Append("EntryOffset=0\n");
        text.Append("DeviceTreeBlob=Image-04\n");

        text.Append('\n').Append("[Image-03]\n");
        text.Append("Name=").Append(model).Append(" Internal DTB\n");
        text.Append("Path=").Append(NormalDtbFileName).Append('\n');
        text.Append("Type=DTB\n");
        text.Append("BaseImage=false\n");
        text.Append("Align=3\n");

        text.Append('\n').Append("[Image-04]\n");
        text.Append("Name=").Append(model).Append(" Diagnostic DTB\n");
        text.Append("Path=").Append(DiagnosticDtbFileName).Append('\n');
        text.Append("Type=DTB\n");
        text.Append("BaseImage=false\n");
        text.Append("Align=3\n");

        text.Append('\n').Append("[Image-05]\n");
        text.Append("Name=Installed initramfs\n");
        text.Append("Path=").Append(InitramfsFileName).Append('\n');
        text.Append("Type=Blob\n");
        text.Append("BaseImage=false\n");
        text.Append("Align=16\n");

        text.Append('\n').Append("[Manifest]\n");
        text.Append("Type=Manifest\n");
        return text.ToString();
    }

    /// <summary>Fixed header facts only; the whole-manifest parser stays with the package reader.</summary>
    private static PackedRawFacts InspectPackedRaw(
        FileStream raw,
        byte[] baseHeader,
        long maxRawBytes,
        CancellationToken cancellationToken)
    {
        long bytes = raw.Length;
        if (bytes < Arm64HeaderProbeBytes)
        {
            throw new InvalidDataException("packed raw image is shorter than the ARM64 header");
        }

        if (bytes > maxRawBytes)
        {
            throw new InvalidDataException("packed raw image exceeds the slot loader budget");
        }

        byte[] head = new byte[Arm64HeaderProbeBytes];
        ReadExactly(raw, head, 0, head.Length);

        RequireArm64Header(head, "packed raw image");

        ulong imageSize = ReadLeU64(head, Arm64ImageSizeField);
        if (imageSize != (ulong)bytes)
        {
            throw new InvalidDataException("packed raw image_size does not match its own length");
        }

        if (ReadLeU64(head, Arm64TextOffsetField) != ReadLeU64(baseHeader, Arm64TextOffsetField))
        {
            throw new InvalidDataException("packed raw text_offset differs from the base image");
        }

        if (ReadLeU64(head, Arm64FlagsField) != ReadLeU64(baseHeader, Arm64FlagsField))
        {
            throw new InvalidDataException("packed raw Image flags differ from the base image");
        }

        ulong shimOffset = ReadLeU64(head, Arm64ShimOffsetField);
        if (shimOffset == 0 || shimOffset % 4 != 0)
        {
            throw new InvalidDataException("packed raw shim offset is not a positive 4-aligned offset");
        }

        if (shimOffset >= (ulong)BranchSignedRange)
        {
            throw new InvalidDataException("packed raw shim offset is outside the BL signed range");
        }

        uint word0 = ReadLeU32(head, 0);
        if ((word0 & BranchOpcodeMask) != BranchLinkOpcode)
        {
            throw new InvalidDataException("packed raw first instruction is not a BL");
        }

        if (ResolveBranchTarget(word0) != (long)shimOffset)
        {
            throw new InvalidDataException("packed raw first BL does not resolve to the shim");
        }

        ulong manifestOffset = ReadLeU64(head, Arm64ManifestOffsetField);
        ulong manifestSize = ReadLeU64(head, Arm64ManifestSizeField);
        if (manifestOffset < Arm64HeaderProbeBytes || manifestSize < ManifestHeaderBytes)
        {
            throw new InvalidDataException("packed raw manifest offset or size is below the header");
        }

        if (manifestOffset > (ulong)bytes || manifestSize > (ulong)bytes - manifestOffset)
        {
            throw new InvalidDataException("packed raw manifest runs outside the image");
        }

        if (manifestOffset + manifestSize != (ulong)bytes)
        {
            throw new InvalidDataException("packed raw manifest does not end exactly at the image end");
        }

        byte[] manifestHeader = new byte[ManifestHeaderBytes];
        ReadExactly(raw, manifestHeader, (long)manifestOffset, manifestHeader.Length);

        if (ReadLeU32(manifestHeader, 0) != ManifestMagic)
        {
            throw new InvalidDataException("packed raw manifest magic is not the protocol 1 value");
        }

        if (BinaryPrimitives.ReadUInt16LittleEndian(manifestHeader.AsSpan(4, 2)) != 0
            || BinaryPrimitives.ReadUInt16LittleEndian(manifestHeader.AsSpan(6, 2)) != 1)
        {
            throw new InvalidDataException("packed raw manifest version is not 0.1");
        }

        if (ReadLeU32(manifestHeader, 8) != ManifestEntryCount)
        {
            throw new InvalidDataException("packed raw manifest does not declare seven entries");
        }

        if (ReadLeU32(manifestHeader, 12) != ManifestDefaultIndex)
        {
            throw new InvalidDataException("packed raw manifest default entry is not Image-01");
        }

        if (ReadLeU32(manifestHeader, 16) != ManifestTimeoutMillis)
        {
            throw new InvalidDataException("packed raw manifest timeout is not 8000 ms");
        }

        int[] backupOffsets = { 0, 16, 32, 40, 48 };
        for (int index = 0; index < backupOffsets.Length; index++)
        {
            if (ReadLeU64(manifestHeader, 20 + index * 8) != ReadLeU64(baseHeader, backupOffsets[index]))
            {
                throw new InvalidDataException(
                    "packed raw manifest backup word " + index.ToString(CultureInfo.InvariantCulture)
                    + " does not match the base image");
            }
        }

        cancellationToken.ThrowIfCancellationRequested();

        return new PackedRawFacts(
            bytes,
            HashStreamSha256(raw, cancellationToken),
            imageSize,
            ReadLeU64(head, Arm64TextOffsetField),
            ReadLeU64(head, Arm64FlagsField),
            shimOffset,
            manifestOffset,
            manifestSize);
    }

    private static long ResolveBranchTarget(uint word)
    {
        int immediate = (int)(word & BranchImmediateMask);
        if ((immediate & BranchImmediateSign) != 0)
        {
            immediate -= 0x04000000;
        }

        return (long)immediate * 4L;
    }

    private static void RequireArm64Header(byte[] header, string subject)
    {
        if (header.Length < Arm64HeaderProbeBytes)
        {
            throw new InvalidDataException(subject + " is shorter than the ARM64 header");
        }

        if (!header.AsSpan(Arm64MagicField, 4).SequenceEqual(Arm64ImageMagic))
        {
            throw new InvalidDataException(subject + " ARM64 magic is missing at 0x38");
        }
    }

    // ------------------------------------------------------------------ unpack verification

    private static void VerifyUnpackedOutput(
        string unpackedDirectory,
        string baseImagePath,
        string linuxPaddedPath,
        string runtimePath,
        string normalDtbPath,
        string diagnosticDtbPath,
        string initramfsPath,
        string model,
        CancellationToken cancellationToken)
    {
        var expected = new[]
        {
            UnpackedConfigFileName,
            BaseImageFileName,
            ShimPayloadFileName,
            Image01PayloadFileName,
            Image03PayloadFileName,
            Image04PayloadFileName,
            Image05PayloadFileName,
        };

        var actual = new List<string>();
        foreach (string entry in Directory.EnumerateFileSystemEntries(unpackedDirectory))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Directory.Exists(entry))
            {
                throw new InvalidDataException("native unpacker emitted an unexpected subdirectory");
            }

            actual.Add(Path.GetFileName(entry));
        }

        if (actual.Count != expected.Length)
        {
            throw new InvalidDataException("native unpacker did not emit exactly seven files");
        }

        foreach (string name in expected)
        {
            bool seen = false;
            foreach (string candidate in actual)
            {
                if (string.Equals(candidate, name, StringComparison.Ordinal))
                {
                    seen = true;
                    break;
                }
            }

            if (!seen)
            {
                throw new InvalidDataException("native unpacker did not emit " + name);
            }
        }

        RequireIdenticalFile(
            baseImagePath, Path.Combine(unpackedDirectory, BaseImageFileName), "unpacked base payload", cancellationToken);
        RequireIdenticalFile(
            runtimePath, Path.Combine(unpackedDirectory, ShimPayloadFileName), "unpacked shim payload", cancellationToken);
        RequireIdenticalFile(
            linuxPaddedPath, Path.Combine(unpackedDirectory, Image01PayloadFileName), "unpacked Linux payload", cancellationToken);
        RequireIdenticalFile(
            normalDtbPath, Path.Combine(unpackedDirectory, Image03PayloadFileName), "unpacked normal DTB", cancellationToken);
        RequireIdenticalFile(
            diagnosticDtbPath, Path.Combine(unpackedDirectory, Image04PayloadFileName), "unpacked diagnostic DTB", cancellationToken);
        RequireIdenticalFile(
            initramfsPath, Path.Combine(unpackedDirectory, Image05PayloadFileName), "unpacked initramfs", cancellationToken);

        VerifyUnpackedConfig(Path.Combine(unpackedDirectory, UnpackedConfigFileName), model, cancellationToken);
    }

    /// <summary>
    /// One deliberately small strict INI reader for the emitted configuration. It is not a general INI
    /// library: duplicate sections or keys, comments, a key outside a section and any unsafe path are refused.
    /// </summary>
    private static void VerifyUnpackedConfig(string path, string model, CancellationToken cancellationToken)
    {
        var file = new FileInfo(path);
        if (!file.Exists || file.Length <= 0 || file.Length > ConfigBytesLimit)
        {
            throw new InvalidDataException("unpacked config.cfg is missing or outside the bounded range");
        }

        byte[] bytes = File.ReadAllBytes(path);
        string text;
        try
        {
            text = ConfigUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            throw new InvalidDataException("unpacked config.cfg is not valid UTF-8");
        }

        if (text.Length > 0 && text[0] == '\uFEFF')
        {
            text = text.Substring(1);
        }

        var sections = new Dictionary<string, Dictionary<string, string>>(StringComparer.Ordinal);
        Dictionary<string, string>? current = null;
        foreach (string rawLine in text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
        {
            cancellationToken.ThrowIfCancellationRequested();
            string line = rawLine.Trim();
            if (line.Length == 0)
            {
                continue;
            }

            if (line[0] is '#' or ';')
            {
                throw new InvalidDataException("unpacked config.cfg carries an unexpected comment line");
            }

            if (line[0] == '[')
            {
                if (line[line.Length - 1] != ']' || line.Length < 3)
                {
                    throw new InvalidDataException("unpacked config.cfg has a malformed section header");
                }

                string name = line.Substring(1, line.Length - 2).Trim();
                if (name.Length == 0 || sections.ContainsKey(name))
                {
                    throw new InvalidDataException("unpacked config.cfg has an empty or duplicate section");
                }

                current = new Dictionary<string, string>(StringComparer.Ordinal);
                sections.Add(name, current);
                continue;
            }

            if (current is null)
            {
                throw new InvalidDataException("unpacked config.cfg has a key outside any section");
            }

            int separator = line.IndexOf('=');
            if (separator <= 0)
            {
                throw new InvalidDataException("unpacked config.cfg has a malformed key line");
            }

            string key = line.Substring(0, separator).Trim();
            string value = line.Substring(separator + 1).Trim();
            if (key.Length == 0 || current.ContainsKey(key))
            {
                throw new InvalidDataException("unpacked config.cfg has an empty or duplicate key");
            }

            current.Add(key, value);
        }

        RequireSections(sections, "Pack", "Image-00", "Image-01", "Image-02", "Image-03", "Image-04", "Image-05", "Manifest");

        Dictionary<string, string> pack = sections["Pack"];
        RequireValue(pack, "Shim", ShimPayloadFileName);
        RequireValue(pack, "Output", RepackedRawFileName);
        RequireValue(pack, "Default", "Image-01");
        RequireValue(pack, "Timeout", "8000");

        RequireValue(sections["Manifest"], "Type", "Manifest");

        RequireImage(
            sections["Image-00"], "原厂 Android", "Linux", "21", null, null, null,
            new[] { BaseImageFileName }, "Image-00");
        RequireImage(
            sections["Image-01"], "机身 Linux", "Linux", "21", "0x0", "Image-03", null,
            new[] { LinuxPaddedFileName, Image01PayloadFileName }, "Image-01");
        RequireImage(
            sections["Image-02"], "Linux 诊断模式", "Linux", "21", "0x0", "Image-04", "Image-01",
            null, "Image-02");
        RequireImage(
            sections["Image-03"], model + " Internal DTB", "DTB", "3", null, null, null,
            new[] { NormalDtbFileName, Image03PayloadFileName }, "Image-03");
        RequireImage(
            sections["Image-04"], model + " Diagnostic DTB", "DTB", "3", null, null, null,
            new[] { DiagnosticDtbFileName, Image04PayloadFileName }, "Image-04");
        RequireImage(
            sections["Image-05"], "Installed initramfs", "Blob", "16", null, null, null,
            new[] { InitramfsFileName, Image05PayloadFileName }, "Image-05");
    }

    private static void RequireSections(
        Dictionary<string, Dictionary<string, string>> sections,
        params string[] expected)
    {
        if (sections.Count != expected.Length)
        {
            throw new InvalidDataException("unpacked config.cfg does not carry exactly the expected sections");
        }

        foreach (string name in expected)
        {
            if (!sections.ContainsKey(name))
            {
                throw new InvalidDataException("unpacked config.cfg is missing section " + name);
            }
        }
    }

    private static void RequireValue(Dictionary<string, string> section, string key, string expected)
    {
        if (!section.TryGetValue(key, out string? actual)
            || !string.Equals(actual, expected, StringComparison.Ordinal))
        {
            throw new InvalidDataException("unpacked config.cfg key " + key + " is not the expected value");
        }
    }

    private static void RequireImage(
        Dictionary<string, string> section,
        string expectedName,
        string expectedType,
        string expectedAlign,
        string? expectedEntryOffset,
        string? expectedDtbReference,
        string? expectedPayloadFrom,
        string[]? allowedPaths,
        string subject)
    {
        RequireValue(section, "Name", expectedName);
        RequireValue(section, "Type", expectedType);
        RequireValue(section, "Align", expectedAlign);

        if (expectedEntryOffset is not null)
        {
            RequireValue(section, "EntryOffset", expectedEntryOffset);
        }

        if (expectedDtbReference is not null)
        {
            RequireValue(section, "DeviceTreeBlob", expectedDtbReference);
        }

        if (expectedPayloadFrom is not null)
        {
            RequireValue(section, "PayloadFrom", expectedPayloadFrom);
        }

        if (allowedPaths is null)
        {
            if (section.ContainsKey("Path"))
            {
                throw new InvalidDataException("unpacked " + subject + " must not carry a Path key");
            }

            return;
        }

        if (!section.TryGetValue("Path", out string? path))
        {
            throw new InvalidDataException("unpacked " + subject + " is missing its Path key");
        }

        RequireSafeRelativeName(path, subject);

        foreach (string allowed in allowedPaths)
        {
            if (string.Equals(path, allowed, StringComparison.Ordinal))
            {
                return;
            }
        }

        throw new InvalidDataException("unpacked " + subject + " names an unexpected payload path");
    }

    private static void RequireSafeRelativeName(string path, string subject)
    {
        if (path.Length == 0 || path.Length > 255)
        {
            throw new InvalidDataException("unpacked " + subject + " payload name has an invalid length");
        }

        if (path.IndexOfAny(new[] { '/', '\\', ':', '\0' }) >= 0 || Path.IsPathRooted(path))
        {
            throw new InvalidDataException("unpacked " + subject + " payload name is not a relative name");
        }

        if (path is "." or "..")
        {
            throw new InvalidDataException("unpacked " + subject + " payload name is not a file name");
        }

        foreach (char character in path)
        {
            if (character < 0x20 || character > 0x7E)
            {
                throw new InvalidDataException("unpacked " + subject + " payload name is not ASCII");
            }
        }
    }

    // ------------------------------------------------------------------ report

    private static void WriteReport(
        Utf8JsonWriter writer,
        EdlRawBootBuildRequest request,
        string sourceSlot,
        EdlRawInactiveSlotBackup? inactiveBackup,
        InternalSlotMaterial material,
        EdlRawBootTools tools,
        EdlRawBootEnvelope envelope,
        EdlRawDtbEvidence normalDtb,
        EdlRawDtbEvidence diagnosticDtb,
        PackedRawFacts packed,
        long linuxPaddedBytes,
        string linuxPaddedSha256,
        IReadOnlyDictionary<string, string> payloads,
        InternalSlotMaterial candidateMaterial)
    {
        writer.WriteStartObject();
        writer.WriteNumber("schemaVersion", 1);
        writer.WriteString("slot", request.Slot);
        writer.WriteString("sourceSlot", sourceSlot);
        writer.WriteString("targetSlot", request.Slot);
        writer.WriteBoolean("inactiveTargetUninitialized", inactiveBackup is not null);
        writer.WriteString("packageId", request.Package.PackageId);
        writer.WriteString("packageManifestFingerprint", request.Package.ManifestFingerprint);
        writer.WriteString("deviceModel", request.Package.DeviceModel);

        // Only a verified inactive proof contributes a target-backup object. Its five entries are the
        // original zero-filled target claims, never a rehash of anything this build produced.
        if (inactiveBackup is not null)
        {
            writer.WriteStartObject("targetBackup");
            foreach (string role in SlotSourceRoles)
            {
                VerifiedEdlFile claim = InactiveBackupClaim(inactiveBackup, role);
                writer.WriteStartObject(role);
                writer.WriteNumber("bytes", claim.Length);
                writer.WriteString("sha256", claim.Sha256);
                writer.WriteEndObject();
            }

            writer.WriteEndObject();
        }

        writer.WriteStartObject("source");
        foreach (string role in SlotSourceRoles)
        {
            writer.WriteStartObject(role);
            writer.WriteNumber("bytes", material.SourceLengths[role]);
            writer.WriteString("sha256", material.SourceSha256[role]);
            writer.WriteEndObject();
        }

        writer.WriteEndObject();

        writer.WriteStartObject("tools");
        writer.WriteStartObject("packer");
        writer.WriteNumber("bytes", tools.Packer.Length);
        writer.WriteString("sha256", tools.Packer.Sha256);
        writer.WriteEndObject();
        writer.WriteStartObject("unpacker");
        writer.WriteNumber("bytes", tools.Unpacker.Length);
        writer.WriteString("sha256", tools.Unpacker.Sha256);
        writer.WriteEndObject();
        writer.WriteEndObject();

        writer.WriteStartObject("material");
        writer.WriteBoolean("isKshim", material.IsKshim);
        writer.WriteNumber("baseImageLength", material.BaseImageLength);
        writer.WriteString("baseImageSha256", material.BaseImageSha256);
        writer.WriteNumber("baseImageSize", material.BaseImageSize);
        writer.WriteNumber("baseTextOffset", material.BaseTextOffset);
        writer.WriteNumber("pageSize", material.PageSize);
        writer.WriteNumber("bootRamdiskSize", material.BootRamdiskSize);
        writer.WriteNumber("vendorRamdiskSize", material.VendorRamdiskSize);
        writer.WriteNumber("initRamdiskSize", material.InitRamdiskSize);
        writer.WriteString("recoveryScope", material.RecoveryScope);
        writer.WriteBoolean("oemSignedRestored", material.OemSignedRestored);
        writer.WriteBoolean("signatureVerificationPerformed", material.SignatureVerificationPerformed);
        writer.WriteStartObject("loaderBudget");
        writer.WriteString("profile", material.LoaderBudget.Profile);
        writer.WriteNumber("maxRawBytes", material.LoaderBudget.MaxRawBytes);
        writer.WriteBoolean("knownLoaderMatch", material.LoaderBudget.KnownLoaderMatch);
        writer.WriteString("formula", material.LoaderBudget.Formula);
        writer.WriteString("evidence", material.LoaderBudget.Evidence);
        writer.WriteEndObject();
        writer.WriteEndObject();

        WriteDtbFacts(writer, "dtbNormal", normalDtb);
        WriteDtbFacts(writer, "dtbDiagnostic", diagnosticDtb);

        writer.WriteStartObject("packedRaw");
        writer.WriteNumber("bytes", packed.Bytes);
        writer.WriteString("sha256", packed.Sha256);
        writer.WriteNumber("imageSize", packed.ImageSize);
        writer.WriteNumber("textOffset", packed.TextOffset);
        writer.WriteNumber("flags", packed.Flags);
        writer.WriteNumber("shimOffset", packed.ShimOffset);
        writer.WriteNumber("manifestOffset", packed.ManifestOffset);
        writer.WriteNumber("manifestSize", packed.ManifestSize);
        writer.WriteNumber("entryCount", ManifestEntryCount);
        writer.WriteNumber("defaultIndex", ManifestDefaultIndex);
        writer.WriteNumber("timeoutMillis", ManifestTimeoutMillis);
        writer.WriteEndObject();

        writer.WriteStartObject("linuxPadded");
        writer.WriteNumber("bytes", linuxPaddedBytes);
        writer.WriteString("sha256", linuxPaddedSha256);
        writer.WriteEndObject();

        writer.WriteString("roundTripRawSha256", packed.Sha256);

        writer.WriteStartObject("unpackedPayloadSha256");
        foreach (string key in new[]
                 {
                     PayloadBase,
                     PayloadLinuxPadded,
                     PayloadRuntime,
                     PayloadNormalDtb,
                     PayloadDiagnosticDtb,
                     PayloadInitramfs,
                 })
        {
            writer.WriteString(key, payloads[key]);
        }

        writer.WriteEndObject();

        writer.WriteStartObject("envelope");
        writer.WriteString("candidatePath", envelope.CandidateBoot.Path);
        writer.WriteNumber("candidateBytes", envelope.CandidateBoot.Length);
        writer.WriteString("candidateSha256", envelope.CandidateBoot.Sha256);
        writer.WriteNumber("compressedKernelBytes", envelope.CompressedKernelBytes);
        writer.WriteString("compressedKernelSha256", envelope.CompressedKernelSha256);
        writer.WriteNumber("originalImageSize", envelope.OriginalImageSize);
        writer.WriteNumber("vbmetaOffset", envelope.VbmetaOffset);
        writer.WriteNumber("vbmetaBytes", envelope.VbmetaBytes);
        writer.WriteString("hashAlgorithm", envelope.HashAlgorithm);
        writer.WriteString("saltHex", envelope.SaltHex);
        writer.WriteNumber("hashDescriptorFlags", envelope.HashDescriptorFlags);
        writer.WriteNumber("rollbackIndex", envelope.RollbackIndex);
        writer.WriteNumber("rollbackIndexLocation", envelope.RollbackIndexLocation);
        writer.WriteString("digestHex", envelope.DigestHex);
        writer.WriteString("sourceEmbeddedVbmetaSha256", envelope.SourceEmbeddedVbmetaSha256);
        writer.WriteNumber("algorithmType", envelope.AlgorithmType);
        writer.WriteBoolean("oemSigned", envelope.OemSigned);
        writer.WriteBoolean("signatureVerificationPerformed", envelope.SignatureVerificationPerformed);
        writer.WriteBoolean("hardwareRollbackVerified", envelope.HardwareRollbackVerified);
        writer.WriteStartArray("properties");
        foreach (EdlRawAvbProperty property in envelope.Properties)
        {
            writer.WriteStartObject();
            writer.WriteString("key", property.Key);
            writer.WriteString("value", property.Value);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();

        writer.WriteStartObject("candidate");
        writer.WriteString("slot", candidateMaterial.Slot);
        writer.WriteBoolean("isKshim", candidateMaterial.IsKshim);
        writer.WriteNumber("baseImageLength", candidateMaterial.BaseImageLength);
        writer.WriteString("baseImageSha256", candidateMaterial.BaseImageSha256);
        writer.WriteNumber("baseImageSize", candidateMaterial.BaseImageSize);
        writer.WriteNumber("baseTextOffset", candidateMaterial.BaseTextOffset);
        writer.WriteEndObject();

        writer.WriteEndObject();
    }

    private static void WriteDtbFacts(Utf8JsonWriter writer, string name, EdlRawDtbEvidence evidence)
    {
        writer.WriteStartObject(name);
        writer.WriteString("kind", evidence.Kind == EdlRawDtbKind.Normal ? "Normal" : "Diagnostic");
        writer.WriteString("deviceModel", evidence.DeviceModel);
        writer.WriteNumber("length", evidence.Length);
        writer.WriteString("sha256", evidence.Sha256);
        writer.WriteStartArray("compatible");
        foreach (string token in evidence.Compatible)
        {
            writer.WriteStringValue(token);
        }

        writer.WriteEndArray();
        writer.WriteString("bootArgs", evidence.BootArgs);
        writer.WriteString("bootStage", evidence.BootStage);
        writer.WriteString("rootMedium", evidence.RootMedium);
        writer.WriteNumber("initrdEntryIndex", evidence.InitrdEntryIndex);
        writer.WriteEndObject();
    }

    // ------------------------------------------------------------------ native

    private static async Task RunNativeAsync(
        ICommandRunner runner,
        string executable,
        IReadOnlyList<string> arguments,
        string workingDirectory,
        string subject,
        CancellationToken cancellationToken)
    {
        var command = new ProcessCommand(executable, arguments, NativeCommandTimeout)
        {
            WorkingDirectory = workingDirectory,
        };

        ProcessResult result = await runner.RunAsync(command, cancellationToken).ConfigureAwait(false);
        if (result.ExitCode == 0)
        {
            return;
        }

        string diagnostic = result.StandardError.Trim();
        if (diagnostic.Length == 0)
        {
            diagnostic = result.StandardOutput.Trim();
        }

        if (diagnostic.Length > DiagnosticTextLimit)
        {
            diagnostic = diagnostic.Substring(0, DiagnosticTextLimit);
        }

        if (diagnostic.Length == 0)
        {
            diagnostic = "(no diagnostic output)";
        }

        throw new IOException(
            subject + " failed with exit code "
            + result.ExitCode.ToString(CultureInfo.InvariantCulture) + ": " + diagnostic);
    }

    // ------------------------------------------------------------------ leases and files

    private static string NormalizeParent(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Contains('\0'))
        {
            throw new ArgumentException("chosen parent must name an existing directory.", nameof(path));
        }

        try
        {
            return Path.GetFullPath(path);
        }
        catch (Exception exception)
            when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new ArgumentException("chosen parent cannot be normalized.", nameof(path), exception);
        }
    }

    private static string RequirePlainDirectory(string path, string subject)
    {
        var directory = new DirectoryInfo(path);
        if (!directory.Exists)
        {
            throw new InvalidDataException(subject + " does not exist as a directory");
        }

        if (IsLink(directory))
        {
            throw new InvalidDataException(subject + " is a reparse point");
        }

        return Path.TrimEndingDirectorySeparator(directory.FullName);
    }

    private static string RequirePlainFile(string? path, string subject)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Contains('\0'))
        {
            throw new InvalidDataException(subject + " path is empty");
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception exception)
            when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new InvalidDataException(subject + " path cannot be normalized", exception);
        }

        var file = new FileInfo(fullPath);
        if (!file.Exists || IsLink(file))
        {
            throw new InvalidDataException(subject + " is not a regular file");
        }

        DirectoryInfo? directory = file.Directory;
        if (directory is null || IsLink(directory))
        {
            throw new InvalidDataException(subject + " containing directory is a reparse point");
        }

        return fullPath;
    }

    private static bool IsLink(FileSystemInfo info) =>
        (info.Attributes & FileAttributes.ReparsePoint) != 0 || info.LinkTarget is not null;

    /// <summary>
    /// Closes one owned lease without letting a single close failure skip the remaining closes or the
    /// child cleanup. Only this class's own handles are ever passed here.
    /// </summary>
    private static void CloseQuietly(FileStream? stream)
    {
        if (stream is null)
        {
            return;
        }

        try
        {
            stream.Dispose();
        }
        catch (IOException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    /// <summary>
    /// Deletes exactly one generated build child. The name marker plus the parent check keep a caller
    /// directory, a chosen parent, a sibling or a backup path out of reach.
    /// </summary>
    internal static void TryDeleteOwnedChild(string? directory)
    {
        if (string.IsNullOrEmpty(directory))
        {
            return;
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(directory);
        }
        catch (Exception exception)
            when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return;
        }

        string trimmed = Path.TrimEndingDirectorySeparator(fullPath);
        if (string.IsNullOrEmpty(trimmed) || Path.GetDirectoryName(trimmed) is null)
        {
            return;
        }

        if (!Path.GetFileName(trimmed).StartsWith("edl-boot-", StringComparison.Ordinal))
        {
            return;
        }

        try
        {
            if (Directory.Exists(trimmed))
            {
                Directory.Delete(trimmed, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static HeldLease OpenClaimLease(
        string role,
        VerifiedEdlFile claim,
        CancellationToken cancellationToken) =>
        OpenHeldLease(role, claim.Path, claim.Length, claim.Sha256, cancellationToken);

    private static HeldLease OpenPackageLease(
        EdlRawPackageContract package,
        string role,
        CancellationToken cancellationToken)
    {
        if (!package.Artifacts.TryGetValue(role, out EdlRawArtifact? artifact) || artifact is null)
        {
            throw new InvalidDataException("package is missing the required '" + role + "' artifact");
        }

        return OpenHeldLease("package " + role, artifact.FullPath, artifact.Bytes, artifact.Sha256, cancellationToken);
    }

    private static HeldLease OpenHeldLease(
        string role,
        string? path,
        long bytes,
        string sha256,
        CancellationToken cancellationToken)
    {
        string fullPath = RequirePlainFile(path, role);
        FileStream stream;
        try
        {
            stream = new FileStream(
                fullPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                CopyChunkBytes,
                FileOptions.RandomAccess);
        }
        catch (Exception exception)
            when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new InvalidDataException(role + ": cannot open the claimed input", exception);
        }

        var claim = new VerifiedEdlFile(fullPath, bytes, sha256);
        try
        {
            VerifyClaim(stream, claim, role, cancellationToken);
        }
        catch
        {
            stream.Dispose();
            throw;
        }

        return new HeldLease(role, stream, claim);
    }

    private static FileStream OpenRead(string path, string subject)
    {
        try
        {
            return new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.Read, CopyChunkBytes, FileOptions.RandomAccess);
        }
        catch (Exception exception)
            when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new InvalidDataException(subject + ": cannot be opened for reading", exception);
        }
    }

    private static FileStream CreateNew(string path, string subject)
    {
        try
        {
            return new FileStream(
                path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, CopyChunkBytes);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new IOException(subject + ": cannot create the owned output file", exception);
        }
    }

    private static FileStream OpenHeldOutput(
        VerifiedEdlFile claim,
        string role,
        CancellationToken cancellationToken)
    {
        FileStream stream = OpenRead(claim.Path, role);
        try
        {
            VerifyClaim(stream, claim, role, cancellationToken);
        }
        catch
        {
            stream.Dispose();
            throw;
        }

        return stream;
    }

    private static void WriteNewFile(
        string path,
        byte[] bytes,
        string subject,
        CancellationToken cancellationToken)
    {
        using FileStream output = CreateNew(path, subject);
        output.Write(bytes, 0, bytes.Length);
        cancellationToken.ThrowIfCancellationRequested();
        output.Flush(true);
    }

    private static (long Bytes, string Sha256) CopyHeldToNewFile(
        FileStream source,
        string path,
        string subject,
        CancellationToken cancellationToken)
    {
        using FileStream output = CreateNew(path, subject);
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        source.Position = 0;
        CopyTo(source, output, hash, cancellationToken);
        output.Flush(true);
        return (output.Length, ToHex(hash.GetHashAndReset()));
    }

    private static void RequireIdenticalFile(
        string expectedPath,
        string actualPath,
        string subject,
        CancellationToken cancellationToken)
    {
        var expected = new FileInfo(expectedPath);
        var actual = new FileInfo(actualPath);
        if (!expected.Exists)
        {
            throw new InvalidDataException(subject + ": the staged expectation is missing");
        }

        if (!actual.Exists)
        {
            throw new InvalidDataException(subject + ": the observed file is missing");
        }

        if (expected.Length != actual.Length)
        {
            throw new InvalidDataException(subject + ": lengths differ");
        }

        if (!string.Equals(
                HashFileSha256(expectedPath, cancellationToken),
                HashFileSha256(actualPath, cancellationToken),
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(subject + ": SHA-256 differs");
        }
    }

    private sealed class HeldLease
    {
        internal HeldLease(string role, FileStream stream, VerifiedEdlFile claim)
        {
            Role = role;
            Stream = stream;
            Claim = claim;
        }

        internal string Role { get; }

        internal FileStream Stream { get; }

        internal VerifiedEdlFile Claim { get; }
    }

    private readonly record struct PackedRawFacts(
        long Bytes,
        string Sha256,
        ulong ImageSize,
        ulong TextOffset,
        ulong Flags,
        ulong ShimOffset,
        ulong ManifestOffset,
        ulong ManifestSize);
}
