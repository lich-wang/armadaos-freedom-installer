// BM001: public request/result surface for the one-slot EDL raw boot builder.
// The result is a disposable owner of exactly four read leases and makes no readiness claim.
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// Immutable inputs of one <see cref="EdlRawBootBuilder.BuildAsync"/> call.
/// <para>
/// The constructor performs only cheap argument checks: no file is opened, no directory is created and no
/// claim is trusted here. The five <see cref="VerifiedEdlFile"/> values and the package artifacts stay
/// claims that the build verifies against the bytes it actually reads.
/// </para>
/// </summary>
public sealed class EdlRawBootBuildRequest
{
    public EdlRawBootBuildRequest(
        string slot,
        VerifiedEdlFile currentBoot,
        VerifiedEdlFile vendorBoot,
        VerifiedEdlFile initBoot,
        VerifiedEdlFile abl,
        VerifiedEdlFile xblConfig,
        EdlRawPackageContract package,
        EdlRawBootTools tools,
        string chosenParent,
        EdlRawInactiveSlotBackup? inactiveSlotBackup = null)
    {
        if (slot is not ("a" or "b"))
        {
            throw new ArgumentException("slot must be exactly 'a' or 'b'.", nameof(slot));
        }

        Slot = slot;
        InactiveSlotBackup = inactiveSlotBackup;
        CurrentBoot = currentBoot ?? throw new ArgumentNullException(nameof(currentBoot));
        VendorBoot = vendorBoot ?? throw new ArgumentNullException(nameof(vendorBoot));
        InitBoot = initBoot ?? throw new ArgumentNullException(nameof(initBoot));
        Abl = abl ?? throw new ArgumentNullException(nameof(abl));
        XblConfig = xblConfig ?? throw new ArgumentNullException(nameof(xblConfig));
        Package = package ?? throw new ArgumentNullException(nameof(package));
        Tools = tools ?? throw new ArgumentNullException(nameof(tools));

        if (string.IsNullOrWhiteSpace(chosenParent) || chosenParent.Contains('\0'))
        {
            throw new ArgumentException(
                "chosen parent must name an existing directory path.", nameof(chosenParent));
        }

        ChosenParent = chosenParent;
    }

    /// <summary>The single TARGET slot this request builds: exactly <c>a</c> or <c>b</c>.</summary>
    public string Slot { get; }

    /// <summary>
    /// The slot the five real inputs belong to. Without a proof this is <see cref="Slot"/>; with one it is
    /// the proof's source slot, read from proof metadata so the value survives the proof's disposal.
    /// </summary>
    public string SourceSlot => InactiveSlotBackup?.SourceSlot ?? Slot;

    /// <summary>
    /// The verified factory-uninitialized target proof, or null when both slots hold real sources.
    /// When it is present, <see cref="Slot"/> is the inactive target and the five
    /// <see cref="VerifiedEdlFile"/> values below are the real source material of the proof's
    /// <see cref="EdlRawInactiveSlotBackup.SourceSlot"/>; the build keeps the target slot in its result and
    /// takes the source material from the proof.
    /// </summary>
    public EdlRawInactiveSlotBackup? InactiveSlotBackup { get; }

    public VerifiedEdlFile CurrentBoot { get; }

    public VerifiedEdlFile VendorBoot { get; }

    public VerifiedEdlFile InitBoot { get; }

    public VerifiedEdlFile Abl { get; }

    public VerifiedEdlFile XblConfig { get; }

    /// <summary>The already validated schema 2 package contract.</summary>
    public EdlRawPackageContract Package { get; }

    /// <summary>The caller's loaded pinned tools; the build acquires its own independent leases.</summary>
    public EdlRawBootTools Tools { get; }

    /// <summary>An existing caller directory that will receive one new unique build child.</summary>
    public string ChosenParent { get; }
}

/// <summary>
/// One finished slot build. Every value is a factual observation of the files this build produced; the
/// class carries no Ready, Verified, OEM-signed or device-write statement.
/// <para>
/// The instance owns four read leases (<see cref="CandidateBoot"/>, <see cref="PackedRaw"/>,
/// <see cref="BaseImage"/>, <see cref="VerificationReport"/>) and the generated build child named by
/// <see cref="DirectoryPath"/>. <see cref="Dispose"/> closes those handles and deletes exactly that one
/// generated child (raw, repacked, unpacked, candidate, base and report). It never deletes or disposes a
/// caller path, the chosen parent, a sibling, the original five slot inputs, the package, the caller's
/// tools owner or any backup.
/// </para>
/// </summary>
public sealed class EdlRawBuiltBoot : IDisposable
{
    private readonly FileStream _candidateBootStream;

    private readonly FileStream _packedRawStream;

    private readonly FileStream _baseImageStream;

    private readonly FileStream _verificationReportStream;

    private int _disposed;

    internal EdlRawBuiltBoot(
        string slot,
        string sourceSlot,
        bool usesInactiveSlotBackup,
        string directoryPath,
        VerifiedEdlFile candidateBoot,
        VerifiedEdlFile packedRaw,
        VerifiedEdlFile baseImage,
        InternalSlotMaterial slotMaterial,
        string packageManifestFingerprint,
        EdlRawBootEnvelope envelope,
        EdlRawDtbEvidence normalDtb,
        EdlRawDtbEvidence diagnosticDtb,
        string roundTripRawSha256,
        IReadOnlyDictionary<string, string> unpackedPayloadSha256,
        VerifiedEdlFile verificationReport,
        FileStream candidateBootStream,
        FileStream packedRawStream,
        FileStream baseImageStream,
        FileStream verificationReportStream)
    {
        if (sourceSlot is not ("a" or "b"))
        {
            throw new ArgumentException("source slot must be exactly 'a' or 'b'.", nameof(sourceSlot));
        }

        if (usesInactiveSlotBackup == string.Equals(sourceSlot, slot, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "an inactive-slot build takes its source from the opposite slot.", nameof(usesInactiveSlotBackup));
        }

        Slot = slot;
        SourceSlot = sourceSlot;
        UsesInactiveSlotBackup = usesInactiveSlotBackup;
        DirectoryPath = directoryPath;
        CandidateBoot = candidateBoot ?? throw new ArgumentNullException(nameof(candidateBoot));
        PackedRaw = packedRaw ?? throw new ArgumentNullException(nameof(packedRaw));
        BaseImage = baseImage ?? throw new ArgumentNullException(nameof(baseImage));
        SlotMaterial = slotMaterial ?? throw new ArgumentNullException(nameof(slotMaterial));
        PackageManifestFingerprint = packageManifestFingerprint
            ?? throw new ArgumentNullException(nameof(packageManifestFingerprint));
        Envelope = envelope ?? throw new ArgumentNullException(nameof(envelope));
        NormalDtb = normalDtb ?? throw new ArgumentNullException(nameof(normalDtb));
        DiagnosticDtb = diagnosticDtb ?? throw new ArgumentNullException(nameof(diagnosticDtb));
        RoundTripRawSha256 = roundTripRawSha256 ?? throw new ArgumentNullException(nameof(roundTripRawSha256));
        if (unpackedPayloadSha256 is null)
        {
            throw new ArgumentNullException(nameof(unpackedPayloadSha256));
        }

        UnpackedPayloadSha256 = new ReadOnlyDictionary<string, string>(
            new Dictionary<string, string>(unpackedPayloadSha256, StringComparer.Ordinal));
        VerificationReport = verificationReport ?? throw new ArgumentNullException(nameof(verificationReport));
        _candidateBootStream = candidateBootStream ?? throw new ArgumentNullException(nameof(candidateBootStream));
        _packedRawStream = packedRawStream ?? throw new ArgumentNullException(nameof(packedRawStream));
        _baseImageStream = baseImageStream ?? throw new ArgumentNullException(nameof(baseImageStream));
        _verificationReportStream = verificationReportStream
            ?? throw new ArgumentNullException(nameof(verificationReportStream));
    }

    public string Slot { get; }

    /// <summary>
    /// The slot the slot material was really read from: <see cref="Slot"/> itself for a normal build, or
    /// the opposite slot for a build of an original factory-uninitialized inactive target.
    /// </summary>
    public string SourceSlot { get; }

    /// <summary>
    /// True only when this build kept <see cref="Slot"/> as the target while taking every source input
    /// from <see cref="SourceSlot"/> through a verified <see cref="EdlRawInactiveSlotBackup"/>. The target
    /// slot's uninitialized state is a fact of the request's proof only.
    /// </summary>
    public bool UsesInactiveSlotBackup { get; }

    /// <summary>
    /// The unique generated build child this result owns. Valid while the result is held; <see cref="Dispose"/>
    /// removes exactly this directory and nothing around it.
    /// </summary>
    public string DirectoryPath { get; }

    public VerifiedEdlFile CandidateBoot { get; }

    public VerifiedEdlFile PackedRaw { get; }

    public VerifiedEdlFile BaseImage { get; }

    public InternalSlotMaterial SlotMaterial { get; }

    public string PackageManifestFingerprint { get; }

    public EdlRawBootEnvelope Envelope { get; }

    public EdlRawDtbEvidence NormalDtb { get; }

    public EdlRawDtbEvidence DiagnosticDtb { get; }

    /// <summary>SHA-256 of the raw image after the third native command equals <see cref="PackedRaw"/>.</summary>
    public string RoundTripRawSha256 { get; }

    /// <summary>Fixed role map: base, linux-padded, runtime, dtb-normal, dtb-diagnostic, initramfs.</summary>
    public IReadOnlyDictionary<string, string> UnpackedPayloadSha256 { get; }

    public VerifiedEdlFile VerificationReport { get; }

    public bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    /// <summary>Rehashes all four held output files against their observed length and SHA-256.</summary>
    /// <exception cref="ObjectDisposedException">This result has already released its leases.</exception>
    /// <exception cref="OperationCanceledException">The token was cancelled.</exception>
    /// <exception cref="InvalidDataException">A held output no longer matches its observation.</exception>
    internal Task RevalidateAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        cancellationToken.ThrowIfCancellationRequested();

        return Task.Run(
            () =>
            {
                ObjectDisposedException.ThrowIf(IsDisposed, this);
                cancellationToken.ThrowIfCancellationRequested();

                EdlRawBootBuilder.VerifyHeldOutput(
                    _candidateBootStream, CandidateBoot, "candidate boot", cancellationToken);
                EdlRawBootBuilder.VerifyHeldOutput(
                    _packedRawStream, PackedRaw, "packed raw image", cancellationToken);
                EdlRawBootBuilder.VerifyHeldOutput(
                    _baseImageStream, BaseImage, "exported base image", cancellationToken);
                EdlRawBootBuilder.VerifyHeldOutput(
                    _verificationReportStream, VerificationReport, "verification report", cancellationToken);

                cancellationToken.ThrowIfCancellationRequested();
            },
            cancellationToken);
    }

    /// <summary>
    /// Releases this result's four read leases and deletes only its own generated
    /// <see cref="DirectoryPath"/>. Idempotent: a repeated call is a no-op, a single close failure never
    /// skips the remaining closes or the directory cleanup, and no caller path is touched.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        CloseQuietly(_candidateBootStream);
        CloseQuietly(_packedRawStream);
        CloseQuietly(_baseImageStream);
        CloseQuietly(_verificationReportStream);
        EdlRawBootBuilder.TryDeleteOwnedChild(DirectoryPath);
    }

    private static void CloseQuietly(FileStream stream)
    {
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
}
