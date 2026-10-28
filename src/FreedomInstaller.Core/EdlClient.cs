using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// Geometry of one explicitly requested LUN, as reported inside the DEBUG-prefixed Firehose
/// <c>storage_info</c> payload. <see cref="TotalSectors"/> is <c>total_blocks</c> (sectors, not bytes) and
/// <see cref="SectorSize"/> is the reported logical <c>block_size</c> for that same LUN context.
/// <para>
/// Geometry belongs to the LUN it was probed for; it is evidence from one probe and is never reused as a
/// global device-wide sector size. A UFS product string, serial number or firmware version inside the same
/// payload is not a device identity and never substitutes for the bound bus identity.
/// </para>
/// </summary>
public sealed record EdlGeometry(int Lun, int SectorSize, long TotalSectors);

/// <summary>
/// Evidence of one successful probe. <see cref="BusSerialHex"/> is the 8-digit hex serial of the endpoint
/// the client actually selected; <see cref="SaharaSerialHex"/> and <see cref="HardwareId"/> are present only
/// when the initial loader upload proved them.
/// <para>
/// Success means the command exited 0 and the selected transport/probe markers were observed. A command
/// that merely "finished" is not success, and this record says nothing about Firehose write readiness.
/// </para>
/// </summary>
public sealed record EdlProbeEvidence(
    EdlGeometry Geometry,
    string BusSerialHex,
    string? SaharaSerialHex,
    string? HardwareId,
    ProcessResult Command);

/// <summary>
/// Evidence of one completed sector read. <see cref="Length"/> and <see cref="Sha256"/> are computed from the
/// file the client actually wrote and length-checked against <c>SectorCount * SectorSize</c>; the rounded size
/// printed in the tool log is not trusted. <see cref="FilePath"/> is the caller-supplied new path.
/// </summary>
public sealed record EdlReadEvidence(
    EdlGeometry Geometry,
    long StartSector,
    long SectorCount,
    string FilePath,
    long Length,
    string Sha256,
    ProcessResult Command);

/// <summary>
/// Caller-declared file evidence for a write. The client still reopens the path and rechecks length and
/// SHA-256 immediately before running the command, so this record is a claim to verify, not authority.
/// </summary>
public sealed record VerifiedEdlFile(string Path, long Length, string Sha256);

/// <summary>
/// Evidence of one acknowledged sector write. <see cref="Length"/> and <see cref="Sha256"/> describe the
/// bytes the client verified immediately before invoking the tool.
/// <para>
/// A successful write means the Firehose program operation was acknowledged ("final ACK received"). It is
/// never readback verification, and no implicit read-back or retry is performed.
/// </para>
/// </summary>
public sealed record EdlWriteEvidence(
    EdlGeometry Geometry,
    long StartSector,
    long SectorCount,
    long Length,
    string Sha256,
    ProcessResult Command);

/// <summary>
/// Evidence of one accepted reset. <see cref="CommandAccepted"/> means the Firehose power command was sent
/// and acknowledged; it does not mean Android booted or Recovery was entered.
/// </summary>
public sealed record EdlResetEvidence(bool CommandAccepted, ProcessResult Command);

/// <summary>
/// Thin EDL client over one staged <see cref="EdlToolchain"/> and one proven <see cref="EdlEntryResult"/>.
/// <para>
/// The constructor only null-checks and stores the exact references; every method revalidates the loaded
/// profile, the binding identity and the currently present endpoint before it builds a command. Once an
/// invocation has started, a write or reset whose outcome cannot be established surfaces as an
/// <see cref="IOException"/> that says the outcome is unknown; nothing is ever retried implicitly.
/// </para>
/// <para>
/// Before every operation the client re-enumerates the present USB endpoints and deduplicates interfaces by
/// their current <c>DeviceInstanceId</c> (case-insensitive), requiring exactly one currently present
/// physical <c>VID_05C6/PID_9008</c> instance. Every description serial number for that current instance
/// must be valid, unambiguous and agreed, and must match the binding's bus serial, the Android-derived SoC
/// serial and the initially proven Sahara serial.
/// </para>
/// <para>
/// The current PnP instance id may change after loader re-enumeration or when the USB port changes.
/// <see cref="EdlEntryResult.Endpoint"/> is original evidence and is never used as a permanent equality
/// gate. The CLI accepts VID/PID only, so hard serial selection is not promised; the actual selected bus
/// serial in the returned command logs is checked instead.
/// </para>
/// </summary>
public sealed class EdlClient
{
    private const string EdlVid = "VID_05C6";
    private const string EdlPid = "PID_9008";
    private const int SnHexLength = 8;
    private const int MinimumSectorSize = 512;
    private const int TimeoutFixedSeconds = 30;
    private const long TimeoutTransferBytesPerSecond = 8L * 1024 * 1024;

    private static readonly TimeSpan ProbeInitialTimeout = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan ProbeWarmTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(120);
    private static readonly TimeSpan WriteTimeout = TimeSpan.FromSeconds(180);
    private static readonly TimeSpan ResetTimeout = TimeSpan.FromSeconds(20);

    private static readonly Regex StorageInfoContextRegex =
        new(@"Getting Storage Info for LUN (?<lun>\d+)", RegexOptions.CultureInvariant);

    private static readonly Regex SectorSizeLineRegex =
        new(@"Using sector size: (?<size>\d+) bytes for LUN (?<lun>\d+)", RegexOptions.CultureInvariant);

    private static readonly Regex GptHeaderRegex =
        new(@"--- GPT Header LUN (?<lun>\d+) ---", RegexOptions.CultureInvariant);

    private static readonly Regex SaharaSerialRegex =
        new(@"(?:^|\]\s+)Serial Number:\s*(?<value>\S+)\s*$", RegexOptions.CultureInvariant);

    private static readonly Regex HardwareIdRegex =
        new(@"HWID:\s*(?<value>\S+)", RegexOptions.CultureInvariant);

    private static readonly Regex PreparingReadRegex =
        new(
            @"Preparing to read (?<count>\d+) sectors \(LBA (?<start>\d+) to (?<last>\d+), " +
            @"(?<bytes>\d+) bytes\) from LUN (?<lun>\d+) into '(?<path>.+)'",
            RegexOptions.CultureInvariant);

    private static readonly Regex ReadSuccessBytesRegex =
        new(@"Successfully read and wrote (?<bytes>\d+) bytes in", RegexOptions.CultureInvariant);

    private static readonly Regex WritingRegex =
        new(
            @"Writing (?<count>\d+) sectors \((?<bytes>\d+) bytes\) to LUN (?<lun>\d+), " +
            @"starting at sector (?<start>\d+)",
            RegexOptions.CultureInvariant);

    private static readonly Regex NakRegex =
        new(@"\bNAK\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex RawDataStreamRegex =
        new(@"Raw data stream \((?<bytes>\d+) bytes\) sent", RegexOptions.CultureInvariant);

    private readonly ICommandRunner _runner;
    private readonly IEdlEndpointDiscovery _discovery;
    private readonly Dictionary<int, EdlGeometry> _geometryByLun = new();
    private bool _initialProven;
    private string? _provenSaharaSerialHex;

    /// <summary>
    /// Creates the client. The toolchain and binding are stored by reference and are exposed unchanged;
    /// no property of either is read and no command is issued here.
    /// </summary>
    public EdlClient(
        EdlToolchain toolchain,
        EdlEntryResult binding,
        ICommandRunner runner,
        IEdlEndpointDiscovery discovery)
    {
        ArgumentNullException.ThrowIfNull(toolchain);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(runner);
        ArgumentNullException.ThrowIfNull(discovery);

        Toolchain = toolchain;
        Binding = binding;

        _runner = runner;
        _discovery = discovery;
    }

    /// <summary>Exact staged toolchain reference passed to the constructor.</summary>
    public EdlToolchain Toolchain { get; }

    /// <summary>Exact EDL entry binding passed to the constructor.</summary>
    public EdlEntryResult Binding { get; }

    /// <summary>
    /// True only after one complete initial Sahara probe proved the Sahara serial, the hardware id, the loader
    /// start marker, the selected bus serial and the requested LUN's storage_info geometry.
    /// <para>
    /// A warm probe, a read-only failure, or a failure before the runner was invoked leaves an already proven
    /// session intact. An accepted reset, or the unknown outcome of any started write or reset, invalidates
    /// the proof. This is always false on a freshly constructed client and has no setter.
    /// </para>
    /// </summary>
    public bool HasInitialSaharaProof => _initialProven;

    /// <summary>
    /// Probes one LUN with <c>printgpt</c>.
    /// <para>
    /// <paramref name="initialLoader"/> is true only for the first probe, which must prove the initial Sahara
    /// serial and hardware id and an explicit loader-started marker; a warm probe before that proof is
    /// rejected without running anything. Warm probes may omit the Sahara section and update only the
    /// requested LUN's geometry. The selected endpoint marker (not an earlier "found" line) carries the
    /// bound bus serial.
    /// </para>
    /// </summary>
    public async Task<EdlProbeEvidence> ProbeAsync(
        int lun,
        bool initialLoader,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        ValidateLun(lun);

        if (initialLoader && _initialProven)
        {
            throw new InvalidOperationException(
                "The initial loader probe has already been proven for this session; use a warm probe.");
        }

        if (!initialLoader && !_initialProven)
        {
            throw new InvalidOperationException(
                "A warm probe requires a successful initial loader probe in this session.");
        }

        string expectedSerial = EnsureCurrentEndpointIdentity();

        TimeSpan timeout = initialLoader ? ProbeInitialTimeout : ProbeWarmTimeout;
        ProcessCommand command = new(
            Toolchain.ClientPath,
            BuildArguments("printgpt", "--lun", Invariant(lun)),
            timeout);

        cancellationToken.ThrowIfCancellationRequested();

        ProcessResult result = await _runner.RunAsync(command, cancellationToken).ConfigureAwait(false);

        string[] lines = SplitLines(result);
        ThrowIfCommandFailed(result, lines);
        ThrowIfHardError(lines);
        string selectedSerial = ReadSelectedBusSerial(lines, expectedSerial);

        string? saharaSerial = null;
        string? hardwareId = null;

        if (initialLoader)
        {
            saharaSerial = ReadSaharaSerial(lines, expectedSerial);
            hardwareId = ReadHardwareId(lines);
            if (!string.Equals(hardwareId, Toolchain.HardwareId, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"Sahara HWID '{hardwareId}' does not match the loaded profile hardware id " +
                    $"'{Toolchain.HardwareId}'.");
            }

            if (!Contains(lines, "Loader uploaded and started successfully via Sahara."))
            {
                throw new InvalidOperationException(
                    "The initial probe did not report a successful Sahara loader upload.");
            }
        }
        else
        {
            // A warm probe may omit the Sahara section, but any value it does print must still agree.
            string? warmSahara = TryReadSaharaSerial(lines);
            if (warmSahara != null &&
                !string.Equals(warmSahara, expectedSerial, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"Warm probe Sahara serial '{warmSahara}' does not match the expected serial " +
                    $"'{expectedSerial}'.");
            }

            string? warmHardwareId = TryReadHardwareId(lines);
            if (warmHardwareId != null &&
                !string.Equals(warmHardwareId, Toolchain.HardwareId, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"Warm probe HWID '{warmHardwareId}' does not match the loaded profile hardware id " +
                    $"'{Toolchain.HardwareId}'.");
            }
        }

        if (!Contains(lines, "Read command ACKed, raw mode enabled."))
        {
            throw new InvalidOperationException("The probe did not report the initial read acknowledgement.");
        }

        if (!Contains(lines, "Final ACK received for Read operation."))
        {
            throw new InvalidOperationException("The probe did not report the final read acknowledgement.");
        }

        if (!lines.Any(line =>
            {
                Match header = GptHeaderRegex.Match(line);
                return header.Success &&
                       string.Equals(header.Groups["lun"].Value, Invariant(lun), StringComparison.Ordinal);
            }))
        {
            throw new InvalidOperationException(
                $"The probe did not report a GPT header for LUN {Invariant(lun)}.");
        }

        EdlGeometry geometry = ParseGeometry(lines, lun);

        // Everything above is validated before the session state changes.
        _geometryByLun[lun] = geometry;

        if (initialLoader)
        {
            _initialProven = true;
            _provenSaharaSerialHex = saharaSerial;
        }

        return new EdlProbeEvidence(
            geometry,
            selectedSerial,
            initialLoader ? saharaSerial : null,
            initialLoader ? hardwareId : null,
            result);
    }

    /// <summary>
    /// Probes one LUN's raw geometry by reading exactly LBA 0, count 1 with <c>read-sector</c>, for the global
    /// rescue route where the on-device GPT may be corrupt.
    /// <para>
    /// <c>printgpt</c> is never used and no GPT header is required: the evidence is the storage_info payload,
    /// the declared sector size (exactly 512 or 4096 bytes for a single sector), the single read plan, the
    /// read acknowledgements and the length/SHA-256 of the one-sector file the client actually wrote.
    /// </para>
    /// <para>
    /// <paramref name="initialLoader"/> follows the same rule as <see cref="ProbeAsync"/>: the first probe must
    /// prove the Sahara serial, the hardware id and the loader-started marker, and a warm probe before that
    /// proof is rejected without running anything. The output file must be a new, fully qualified path inside
    /// an existing caller-owned directory that is not a reparse point; it is never created implicitly,
    /// overwritten or deleted by this method. Session proof is updated only after every validation, including
    /// the file length and SHA-256, has passed.
    /// </para>
    /// </summary>
    public async Task<EdlProbeEvidence> ProbeRawGeometryAsync(
        int lun,
        bool initialLoader,
        string newOutputFile,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        ValidateLun(lun);

        if (initialLoader && _initialProven)
        {
            throw new InvalidOperationException(
                "The initial loader probe has already been proven for this session; use a warm probe.");
        }

        if (!initialLoader && !_initialProven)
        {
            throw new InvalidOperationException(
                "A warm probe requires a successful initial loader probe in this session.");
        }

        string canonicalOutput = ValidateRawGeometryOutputPath(newOutputFile);

        string expectedSerial = EnsureCurrentEndpointIdentity();

        TimeSpan timeout = initialLoader ? ProbeInitialTimeout : ProbeWarmTimeout;
        ProcessCommand command = new(
            Toolchain.ClientPath,
            BuildArguments("read-sector", "0", "1", canonicalOutput, "--lun", Invariant(lun)),
            timeout);

        cancellationToken.ThrowIfCancellationRequested();

        ProcessResult result = await _runner.RunAsync(command, cancellationToken).ConfigureAwait(false);

        string[] lines = SplitLines(result);
        ThrowIfCommandFailed(result, lines);
        ThrowIfHardError(lines);
        string selectedSerial = ReadSelectedBusSerial(lines, expectedSerial);

        string? saharaSerial = null;
        string? hardwareId = null;

        if (initialLoader)
        {
            saharaSerial = ReadSaharaSerial(lines, expectedSerial);
            hardwareId = ReadHardwareId(lines);
            if (!string.Equals(hardwareId, Toolchain.HardwareId, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"Sahara HWID '{hardwareId}' does not match the loaded profile hardware id " +
                    $"'{Toolchain.HardwareId}'.");
            }

            if (!Contains(lines, "Loader uploaded and started successfully via Sahara."))
            {
                throw new InvalidOperationException(
                    "The initial probe did not report a successful Sahara loader upload.");
            }
        }
        else
        {
            // A warm probe may omit the Sahara section, but any value it does print must still agree.
            string? warmSahara = TryReadSaharaSerial(lines);
            if (warmSahara != null &&
                !string.Equals(warmSahara, expectedSerial, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"Warm probe Sahara serial '{warmSahara}' does not match the expected serial " +
                    $"'{expectedSerial}'.");
            }

            string? warmHardwareId = TryReadHardwareId(lines);
            if (warmHardwareId != null &&
                !string.Equals(warmHardwareId, Toolchain.HardwareId, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"Warm probe HWID '{warmHardwareId}' does not match the loaded profile hardware id " +
                    $"'{Toolchain.HardwareId}'.");
            }
        }

        if (!Contains(lines, "Read command ACKed, raw mode enabled."))
        {
            throw new InvalidOperationException(
                "The raw geometry probe did not report the initial read acknowledgement.");
        }

        if (!Contains(lines, "Final ACK received for Read operation."))
        {
            throw new InvalidOperationException(
                "The raw geometry probe did not report the final read acknowledgement.");
        }

        EdlGeometry geometry = ParseGeometry(lines, lun);

        if (geometry.SectorSize != 512 && geometry.SectorSize != 4096)
        {
            throw new InvalidOperationException(
                $"LUN {lun} reports a {geometry.SectorSize}-byte sector size; a single-sector read requires " +
                "exactly 512 or 4096 bytes.");
        }

        ValidateRawGeometryReadPlan(lines, lun, geometry.SectorSize, canonicalOutput);

        ValidateReportedReadBytes(lines, geometry.SectorSize);

        if (!File.Exists(canonicalOutput))
        {
            throw new IOException(
                $"The raw geometry probe did not produce the expected output file '{canonicalOutput}'.");
        }

        RejectReparseTarget(canonicalOutput);

        // Real file length and SHA-256, not the size printed in the log; a truncated, oversized or missing
        // file fails here and leaves the session unproven.
        VerifyReadFile(geometry, 0, 1, geometry.SectorSize, canonicalOutput, result);

        // Everything above is validated before the session state changes.
        _geometryByLun[lun] = geometry;

        if (initialLoader)
        {
            _initialProven = true;
            _provenSaharaSerialHex = saharaSerial;
        }

        return new EdlProbeEvidence(
            geometry,
            selectedSerial,
            initialLoader ? saharaSerial : null,
            initialLoader ? hardwareId : null,
            result);
    }

    /// <summary>
    /// Reads a sector range into a caller-supplied path that must not exist yet.
    /// <para>
    /// Range arithmetic is checked before the runner; the exact read-sector argv includes start, count and
    /// output path. Success requires exit code 0, the final read ACK and a file whose length equals
    /// <c>sectorCount * geometrySectorSize</c>; the SHA-256 is then computed from that file.
    /// </para>
    /// </summary>
    public Task<EdlReadEvidence> ReadAsync(
        int lun,
        long startSector,
        long sectorCount,
        string newOutputPath,
        CancellationToken cancellationToken = default) =>
        ReadAsync(lun, startSector, sectorCount, newOutputPath, null, null, cancellationToken);

    /// <summary>
    /// Observed variant of <see cref="ReadAsync(int, long, long, string, CancellationToken)"/>: exactly the
    /// same range checks, argv, timeout, acknowledgements and file verification, plus an optional live
    /// observer and optional prefixed raw logs. A progress report never replaces the read ACK, the readback
    /// length or the SHA-256.
    /// </summary>
    public async Task<EdlReadEvidence> ReadAsync(
        int lun,
        long startSector,
        long sectorCount,
        string newOutputPath,
        IProgress<EdlTransferProgress>? progress,
        string? logPrefix,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        ValidateLun(lun);
        RequireSessionAndGeometry(lun);
        EdlGeometry geometry = _geometryByLun[lun];

        if (startSector < 0)
        {
            throw new InvalidOperationException("The read start sector must not be negative.");
        }

        if (sectorCount <= 0)
        {
            throw new InvalidOperationException("The read sector count must be positive.");
        }

        long endSector = CheckedAdd(startSector, sectorCount, "The read sector range overflows.");
        if (endSector > geometry.TotalSectors)
        {
            throw new InvalidOperationException(
                $"The read range ends at sector {endSector}, beyond LUN {lun}'s {geometry.TotalSectors} sectors.");
        }

        long byteCount = CheckedMultiply(sectorCount, geometry.SectorSize, "The read byte range overflows.");
        if (byteCount <= 0)
        {
            throw new InvalidOperationException("The read byte count must be positive.");
        }

        if (string.IsNullOrWhiteSpace(newOutputPath))
        {
            throw new ArgumentException("A non-blank new output path is required.", nameof(newOutputPath));
        }

        if (File.Exists(newOutputPath) || Directory.Exists(newOutputPath))
        {
            throw new IOException(
                $"The read output path '{newOutputPath}' already exists; an overwrite is not allowed.");
        }

        string? parent = Path.GetDirectoryName(newOutputPath);
        if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent))
        {
            throw new IOException(
                $"The read output path '{newOutputPath}' requires an existing explicit parent directory.");
        }

        string expectedSerial = EnsureCurrentEndpointIdentity();

        // Nothing is created when neither an observer nor a log prefix was requested.
        using EdlOperationObservation? observation = EdlOperationObservation.Start(
            EdlTransferDirection.Read,
            byteCount,
            progress,
            logPrefix);

        Action<ProcessOutputLine>? observer =
            observation is null ? (Action<ProcessOutputLine>?)null : observation.Observe;

        ProcessCommand command = new(
            Toolchain.ClientPath,
            BuildArguments(
                "read-sector",
                Invariant(startSector),
                Invariant(sectorCount),
                newOutputPath,
                "--lun",
                Invariant(lun)),
            ByteDependentTimeout(byteCount, ReadTimeout))
        {
            OutputReceived = observer,
        };

        observation?.ReportPhase(EdlTransferPhase.Transferring, 0);

        cancellationToken.ThrowIfCancellationRequested();

        ProcessResult result = await _runner.RunAsync(command, cancellationToken).ConfigureAwait(false);

        // Written before any validator can reject the result, so a failed command still leaves its full
        // captured output in the logs.
        observation?.Complete(result);

        string[] lines = SplitLines(result);
        ThrowIfCommandFailed(result, lines);
        ThrowIfHardError(lines);
        ReadSelectedBusSerial(lines, expectedSerial);

        if (!Contains(lines, "Read command ACKed, raw mode enabled."))
        {
            throw new InvalidOperationException("The read did not report the initial read acknowledgement.");
        }

        if (!Contains(lines, "Final ACK received for Read operation."))
        {
            throw new InvalidOperationException("The read did not report the final read acknowledgement.");
        }

        ValidatePreparingReadLine(lines, lun, startSector, sectorCount, byteCount);
        ValidateReportedReadBytes(lines, byteCount);

        observation?.ReportPhase(EdlTransferPhase.CheckingOutput, 0);

        EdlReadEvidence evidence = VerifyReadFile(
            geometry,
            startSector,
            sectorCount,
            byteCount,
            newOutputPath,
            result);

        // The end of the output phase is only reported once the real file length and SHA-256 exist.
        observation?.ReportPhase(EdlTransferPhase.CheckingOutput, byteCount);

        return evidence;
    }

    /// <summary>
    /// Writes a verified local file at a sector offset. The real CLI takes no count positional argument.
    /// <para>
    /// The file is opened read-only with <c>FileShare.Read</c>, its actual length and SHA-256 are verified on
    /// that same open handle, and the handle stays open across the awaited external command until it
    /// completes or fails. The external CLI can therefore read the file while Windows still refuses writes,
    /// replacement or deletion between hashing and the tool's read.
    /// </para>
    /// <para>
    /// Success is only the acknowledged program operation; it is never readback verification and nothing is
    /// retried. Once the invocation has started, a failure whose outcome cannot be established surfaces as
    /// an <see cref="IOException"/> stating that the outcome is unknown.
    /// </para>
    /// </summary>
    public Task<EdlWriteEvidence> WriteAsync(
        int lun,
        long startSector,
        VerifiedEdlFile file,
        CancellationToken cancellationToken = default) =>
        WriteAsync(lun, startSector, file, null, null, cancellationToken);

    /// <summary>
    /// Observed variant of <see cref="WriteAsync(int, long, VerifiedEdlFile, CancellationToken)"/>: exactly
    /// the same argv, timeout, acknowledged program operation and held source handle, plus an optional live
    /// observer and optional prefixed raw logs. A progress report never becomes write success.
    /// </summary>
    public async Task<EdlWriteEvidence> WriteAsync(
        int lun,
        long startSector,
        VerifiedEdlFile file,
        IProgress<EdlTransferProgress>? progress,
        string? logPrefix,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        ArgumentNullException.ThrowIfNull(file);

        ValidateLun(lun);
        RequireSessionAndGeometry(lun);
        EdlGeometry geometry = _geometryByLun[lun];

        if (string.IsNullOrWhiteSpace(file.Path))
        {
            throw new ArgumentException("A non-blank verified file path is required.", nameof(file));
        }

        if (file.Length <= 0)
        {
            throw new InvalidOperationException("The verified file length must be positive.");
        }

        if (!IsSha256Hex(file.Sha256))
        {
            throw new InvalidOperationException("The verified file SHA-256 must be 64 hexadecimal characters.");
        }

        if (startSector < 0)
        {
            throw new InvalidOperationException("The write start sector must not be negative.");
        }

        if (file.Length % geometry.SectorSize != 0)
        {
            throw new InvalidOperationException(
                $"The verified file length {file.Length} is not a multiple of LUN {lun}'s sector size " +
                $"{geometry.SectorSize}.");
        }

        long sectorCount = file.Length / geometry.SectorSize;
        long endSector = CheckedAdd(startSector, sectorCount, "The write sector range overflows.");
        if (endSector > geometry.TotalSectors)
        {
            throw new InvalidOperationException(
                $"The write range ends at sector {endSector}, beyond LUN {lun}'s {geometry.TotalSectors} sectors.");
        }

        string expectedSerial = EnsureCurrentEndpointIdentity();

        // Created before the input is touched and before the invocation: observer or log setup can only fail
        // as an ordinary pre-invocation failure that never clears the session proof.
        using EdlOperationObservation? observation = EdlOperationObservation.Start(
            EdlTransferDirection.Write,
            file.Length,
            progress,
            logPrefix);

        // Opened exactly once for the client's own verification and held across the awaited command so that
        // Windows refuses writer, replacement or delete sharing for the whole invocation.
        using FileStream source = new(file.Path, FileMode.Open, FileAccess.Read, FileShare.Read);

        observation?.ReportPhase(EdlTransferPhase.CheckingInput, 0);
        VerifySourceLengthAndHash(source, file);
        observation?.ReportPhase(EdlTransferPhase.CheckingInput, file.Length);

        Action<ProcessOutputLine>? observer =
            observation is null ? (Action<ProcessOutputLine>?)null : observation.Observe;

        ProcessCommand command = new(
            Toolchain.ClientPath,
            BuildArguments(
                "write-sector",
                Invariant(startSector),
                file.Path,
                "--lun",
                Invariant(lun)),
            ByteDependentTimeout(file.Length, WriteTimeout))
        {
            OutputReceived = observer,
        };

        observation?.ReportPhase(EdlTransferPhase.Transferring, 0);

        cancellationToken.ThrowIfCancellationRequested();

        ProcessResult result;
        try
        {
            result = await _runner.RunAsync(command, cancellationToken).ConfigureAwait(false);

            // Inside the same guard as the invocation: a log failure after the command started is still an
            // unknown outcome and still clears the session proof.
            observation?.Complete(result);
            ValidateWriteResult(result, lun, startSector, sectorCount, file.Length, expectedSerial);
        }
        catch (Exception exception)
        {
            ClearSessionProof();
            throw new IOException(
                $"write-sector outcome unknown: the command was invoked for LUN {lun} but its result could " +
                "not be established.",
                exception);
        }

        return new EdlWriteEvidence(
            geometry,
            startSector,
            sectorCount,
            file.Length,
            file.Sha256.ToUpperInvariant(),
            result);
    }

    /// <summary>
    /// Resets the device with <c>--mode Reset --delay 1</c>. There is no Recovery reset mode.
    /// <para>
    /// <see cref="EdlResetEvidence.CommandAccepted"/> only means the Firehose power command was accepted,
    /// never that Android booted or Recovery was entered. An invoked reset whose outcome is unknown surfaces
    /// as an <see cref="IOException"/> stating that the outcome is unknown.
    /// </para>
    /// </summary>
    public async Task<EdlResetEvidence> ResetAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!_initialProven)
        {
            throw new InvalidOperationException("A reset requires a successful initial loader probe.");
        }

        string expectedSerial = EnsureCurrentEndpointIdentity();

        ProcessCommand command = new(
            Toolchain.ClientPath,
            BuildArguments("reset", "--mode", "Reset", "--delay", "1"),
            ResetTimeout);

        cancellationToken.ThrowIfCancellationRequested();

        ProcessResult result;
        try
        {
            result = await _runner.RunAsync(command, cancellationToken).ConfigureAwait(false);
            ValidateResetResult(result, expectedSerial);
        }
        catch (Exception exception)
        {
            ClearSessionProof();
            throw new IOException(
                "reset outcome unknown: the command was invoked but its result could not be established.",
                exception);
        }

        // The accepted reset destroys the transport session; cached proof and geometry must not be reused.
        ClearSessionProof();

        return new EdlResetEvidence(true, result);
    }

    /// <summary>
    /// Drops all session proof: the initial-loader flag, the proven Sahara serial and every cached LUN
    /// geometry. Used when an accepted reset or an unknown started-write/reset outcome invalidates the
    /// session, never for read-only or pre-invocation failures.
    /// </summary>
    private void ClearSessionProof()
    {
        _initialProven = false;
        _provenSaharaSerialHex = null;
        _geometryByLun.Clear();
    }

    // ------------------------------------------------------------------ identity

    /// <summary>
    /// Revalidates the loaded profile and the bound Android identity, re-enumerates the currently present
    /// EDL endpoints and returns the expected 8-digit bus serial. The original binding endpoint is never
    /// used as an equality gate because the PnP instance may legitimately change between operations.
    /// </summary>
    private string EnsureCurrentEndpointIdentity()
    {
        string expectedSerial = ValidateProfileAndBinding();

        IReadOnlyList<EdlEndpoint> present = _discovery.ReadPresent() ?? Array.Empty<EdlEndpoint>();

        List<EdlEndpoint> candidates = present
            .Where(endpoint => endpoint is not null && IsEdlInstance(endpoint.DeviceInstanceId))
            .ToList();

        List<IGrouping<string, EdlEndpoint>> groups = candidates
            .GroupBy(endpoint => endpoint.DeviceInstanceId, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (groups.Count != 1)
        {
            throw new InvalidOperationException(
                $"Expected exactly one present EDL device instance, found {groups.Count}.");
        }

        foreach (EdlEndpoint endpoint in groups[0])
        {
            string serial = ParseEndpointBusSerial(endpoint.BusReportedDeviceDescription);
            if (!string.Equals(serial, expectedSerial, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"EDL endpoint {endpoint.DeviceInstanceId} reports bus serial {serial}, " +
                    $"expected {expectedSerial}.");
            }
        }

        if (_initialProven &&
            !string.Equals(_provenSaharaSerialHex, expectedSerial, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The current endpoint identity no longer agrees with the proven Sahara serial.");
        }

        return expectedSerial;
    }

    private string ValidateProfileAndBinding()
    {
        RequireNonBlank(Toolchain.ClientPath, "toolchain client path");
        RequireNonBlank(Toolchain.FirehosePath, "toolchain firehose path");
        RequireNonBlank(Toolchain.ProfileId, "toolchain profile id");
        RequireNonBlank(Toolchain.Model, "toolchain model");
        RequireNonBlank(Toolchain.AndroidBuild, "toolchain Android build");
        RequireNonBlank(Toolchain.HardwareId, "toolchain hardware id");

        // Offline 9008 binding: this route has no Android identity and no firmware to compare.
        if (Binding.OfflineIdentity is { } offline)
        {
            return ValidateOfflineBinding(offline);
        }

        AndroidMaintenanceIdentity android = Binding.AndroidIdentity
            ?? throw new InvalidOperationException("The EDL binding has no Android maintenance identity.");

        DeviceIdentity identity = android.Identity
            ?? throw new InvalidOperationException("The EDL binding has no Android device identity.");

        if (!string.Equals(identity.Model, Toolchain.Model, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The binding model '{identity.Model}' does not match the loaded profile model " +
                $"'{Toolchain.Model}'.");
        }

        string? displayId = identity.Firmware?.DisplayId;
        if (string.IsNullOrWhiteSpace(displayId))
        {
            throw new InvalidOperationException(
                "The binding has no current Android firmware display id; a non-blank actual build is required.");
        }

        string expectedSerial = ExpectedBusSerial(android.SocSerial);

        if (!IsBusSerialHex(Binding.BusSerialHex) ||
            !string.Equals(Binding.BusSerialHex, expectedSerial, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"The binding bus serial '{Binding.BusSerialHex}' does not match the serial derived from the " +
                $"SoC serial ('{expectedSerial}').");
        }

        return expectedSerial;
    }

    /// <summary>
    /// Validates the limited offline 9008 binding. It carries no Android proof, so an Android serial or
    /// firmware display id on the offline identity is rejected, and a binding that also carries an Android
    /// identity is rejected as mixed origin. The trusted profile must be the exact staged registry object,
    /// and the offline identity must restate that profile's id, model and hardware id exactly (hardware id
    /// case-insensitively). The bus serial is the only device-derived value and must agree with the binding.
    /// </summary>
    private string ValidateOfflineBinding(GlobalEdlIdentity offline)
    {
        if (Binding.AndroidIdentity != null)
        {
            throw new InvalidOperationException(
                "The EDL binding carries both an Android identity and an offline identity.");
        }

        EdlDeviceProfile trusted = Toolchain.Profile;

        if (!ReferenceEquals(EdlDeviceProfiles.FindById(Toolchain.ProfileId), trusted) ||
            !string.Equals(trusted.ProfileId, Toolchain.ProfileId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The loaded profile '{Toolchain.ProfileId}' is not a known built-in EDL profile.");
        }

        trusted.RequireComplete();

        if (!string.Equals(offline.ProfileId, Toolchain.ProfileId, StringComparison.Ordinal) ||
            !string.Equals(offline.ProfileId, trusted.ProfileId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The offline profile id '{offline.ProfileId}' does not match the loaded profile id " +
                $"'{Toolchain.ProfileId}'.");
        }

        if (!string.Equals(offline.Model, Toolchain.Model, StringComparison.Ordinal) ||
            !string.Equals(offline.Model, trusted.Model, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The offline model '{offline.Model}' does not match the loaded profile model " +
                $"'{Toolchain.Model}'.");
        }

        string? profileHardwareId = trusted.FullHardwareId;

        if (string.IsNullOrEmpty(profileHardwareId) ||
            !string.Equals(offline.HardwareId, Toolchain.HardwareId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(offline.HardwareId, profileHardwareId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"The offline hardware id '{offline.HardwareId}' does not match the loaded profile " +
                $"hardware id '{Toolchain.HardwareId}'.");
        }

        if (offline.AndroidSerial != null || offline.FirmwareDisplayId != null)
        {
            throw new InvalidOperationException(
                "The offline EDL binding cannot claim an Android serial or firmware display id.");
        }

        string offlineSerial = NormalizeBusSerial(offline.BusSerialHex, "offline bus serial");
        string bindingSerial = NormalizeBusSerial(Binding.BusSerialHex, "binding bus serial");

        if (!string.Equals(offlineSerial, bindingSerial, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The offline bus serial {offlineSerial} does not match the binding bus serial " +
                $"{bindingSerial}.");
        }

        return bindingSerial;
    }

    /// <summary>Strict 8-hex bus serial: no trimming, and zero or broadcast serials are unusable.</summary>
    private static string NormalizeBusSerial(string? value, string description)
    {
        if (!IsBusSerialHex(value))
        {
            throw new InvalidOperationException(
                $"The {description} '{value ?? "<none>"}' is not exactly {SnHexLength} hex digits.");
        }

        string normalized = value!.ToUpperInvariant();

        if (string.Equals(normalized, "00000000", StringComparison.Ordinal) ||
            string.Equals(normalized, "FFFFFFFF", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The {description} '{value}' is not a usable EDL bus serial (zero or broadcast).");
        }

        return normalized;
    }

    private static string ExpectedBusSerial(string? socSerial)
    {
        if (!uint.TryParse(socSerial, NumberStyles.None, CultureInfo.InvariantCulture, out uint value))
        {
            throw new InvalidOperationException(
                $"SoC serial '{socSerial ?? "<none>"}' is not an unsigned decimal 32-bit value.");
        }

        if (value == 0 || value == uint.MaxValue)
        {
            throw new InvalidOperationException(
                $"SoC serial '{socSerial}' is not a usable EDL bus serial (zero or broadcast).");
        }

        return value.ToString("X8", CultureInfo.InvariantCulture);
    }

    private static bool IsEdlInstance(string? deviceInstanceId) =>
        !string.IsNullOrEmpty(deviceInstanceId) &&
        deviceInstanceId.IndexOf(EdlVid, StringComparison.OrdinalIgnoreCase) >= 0 &&
        deviceInstanceId.IndexOf(EdlPid, StringComparison.OrdinalIgnoreCase) >= 0;

    /// <summary>
    /// Extracts the serial from a description such as <c>QUSB_BULK_CID:045A_SN:C1D2E3F4</c>. Exactly one
    /// <c>SN:</c> label must exist and its value must be exactly eight hex digits; a missing, duplicated,
    /// short, long or non-hex value is unusable.
    /// </summary>
    private static string ParseEndpointBusSerial(string? description)
    {
        if (string.IsNullOrEmpty(description))
        {
            throw new InvalidOperationException(
                "An EDL endpoint reports no bus description, so the SoC serial cannot be proven.");
        }

        string[] tokens = description.Split('_');
        int labels = 0;
        string? value = null;

        foreach (string token in tokens)
        {
            if (token.StartsWith("SN:", StringComparison.OrdinalIgnoreCase))
            {
                labels++;
                value = token.Substring(3);
            }
        }

        if (labels != 1)
        {
            throw new InvalidOperationException(
                $"The EDL bus description '{description}' must contain exactly one SN: label, found {labels}.");
        }

        if (!IsBusSerialHex(value))
        {
            throw new InvalidOperationException(
                $"The EDL bus description '{description}' does not carry an exactly eight-digit hex serial.");
        }

        return value!.ToUpperInvariant();
    }

    // ------------------------------------------------------------------ command construction

    private string[] BuildArguments(params string[] head)
    {
        string[] arguments = new string[head.Length + 10];
        Array.Copy(head, arguments, head.Length);

        arguments[head.Length] = "--loader";
        arguments[head.Length + 1] = Toolchain.FirehosePath;
        arguments[head.Length + 2] = "--vid";
        arguments[head.Length + 3] = "05c6";
        arguments[head.Length + 4] = "--pid";
        arguments[head.Length + 5] = "9008";
        arguments[head.Length + 6] = "--memory";
        arguments[head.Length + 7] = "Ufs";
        arguments[head.Length + 8] = "--loglevel";
        arguments[head.Length + 9] = "Debug";

        return arguments;
    }

    // ------------------------------------------------------------------ log parsing

    private static string[] SplitLines(ProcessResult result)
    {
        string combined = (result.StandardOutput ?? string.Empty) + "\n" + (result.StandardError ?? string.Empty);
        return combined
            .Split('\n')
            .Select(line => line.TrimEnd('\r'))
            .ToArray();
    }

    private static void ThrowIfCommandFailed(ProcessResult result, string[] lines)
    {
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"The EDL command exited with code {result.ExitCode}: {Describe(lines)}");
        }
    }

    private static void ThrowIfHardError(string[] lines)
    {
        foreach (string line in lines)
        {
            if (line.IndexOf("[ERROR]", StringComparison.OrdinalIgnoreCase) >= 0 ||
                line.IndexOf("[FATAL]", StringComparison.OrdinalIgnoreCase) >= 0 ||
                line.IndexOf("[ERR]", StringComparison.Ordinal) >= 0 ||
                NakRegex.IsMatch(line))
            {
                throw new InvalidOperationException("The EDL tool reported a hard error: " + line.Trim());
            }
        }
    }

    private static bool Contains(string[] lines, string marker) =>
        lines.Any(line => line.IndexOf(marker, StringComparison.Ordinal) >= 0);

    /// <summary>
    /// Reads the serial from every actual "Qualcomm EDL device selected" / "Bus Name" line and requires all
    /// of them to agree with the expected serial. An earlier "Found device" line is never trusted.
    /// </summary>
    private static string ReadSelectedBusSerial(string[] lines, string expectedSerial)
    {
        string? selected = null;

        foreach (string line in lines)
        {
            bool isSelection =
                line.IndexOf("Qualcomm EDL device selected:", StringComparison.Ordinal) >= 0;
            bool isBusName = line.IndexOf("Bus Name:", StringComparison.Ordinal) >= 0;

            if (!isSelection && !isBusName)
            {
                continue;
            }

            int index = line.LastIndexOf("SN:", StringComparison.OrdinalIgnoreCase);
            if (index < 0)
            {
                throw new InvalidOperationException(
                    "The EDL tool selected a device without reporting a bus serial: " + line.Trim());
            }

            string tail = line.Substring(index + 3).Trim();
            int length = 0;
            while (length < tail.Length && Uri.IsHexDigit(tail[length]))
            {
                length++;
            }

            string serial = tail.Substring(0, length);
            if (!IsBusSerialHex(serial))
            {
                throw new InvalidOperationException(
                    "The EDL tool reported an unusable selected bus serial: " + line.Trim());
            }

            if (!string.Equals(serial, expectedSerial, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"The EDL tool selected bus serial '{serial}', expected '{expectedSerial}'.");
            }

            selected ??= serial.ToUpperInvariant();
        }

        return selected ?? throw new InvalidOperationException(
            "The EDL tool did not report the device it actually selected.");
    }

    private static string ReadSaharaSerial(string[] lines, string expectedSerial)
    {
        string? sahara = TryReadSaharaSerial(lines);
        if (sahara is null)
        {
            throw new InvalidOperationException("The initial probe did not report a Sahara serial number.");
        }

        if (!string.Equals(sahara, expectedSerial, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"Sahara serial '{sahara}' does not match the expected serial '{expectedSerial}'.");
        }

        return sahara;
    }

    private static string? TryReadSaharaSerial(string[] lines)
    {
        string? serial = null;

        foreach (string line in lines)
        {
            Match match = SaharaSerialRegex.Match(line);
            if (!match.Success)
            {
                continue;
            }

            string value = match.Groups["value"].Value;
            if (!IsBusSerialHex(value))
            {
                throw new InvalidOperationException("The probe reported an unusable Sahara serial: " + value);
            }

            if (serial != null && !string.Equals(serial, value, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("The probe reported conflicting Sahara serial numbers.");
            }

            serial = value.ToUpperInvariant();
        }

        return serial;
    }

    private static string? ReadHardwareId(string[] lines)
    {
        string? hardwareId = TryReadHardwareId(lines);
        if (hardwareId is null)
        {
            throw new InvalidOperationException("The initial probe did not report a Sahara hardware id.");
        }

        return hardwareId;
    }

    private static string? TryReadHardwareId(string[] lines)
    {
        string? hardwareId = null;

        foreach (string line in lines)
        {
            Match match = HardwareIdRegex.Match(line);
            if (!match.Success)
            {
                continue;
            }

            string value = match.Groups["value"].Value;
            if (hardwareId != null && !string.Equals(hardwareId, value, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("The probe reported conflicting hardware ids.");
            }

            hardwareId = value;
        }

        return hardwareId;
    }

    // ------------------------------------------------------------------ probe geometry

    private static EdlGeometry ParseGeometry(string[] lines, int requestedLun)
    {
        Dictionary<int, EdlGeometry> geometries = new();
        Dictionary<int, int> declaredSectorSizes = new();
        int? contextLun = null;

        foreach (string line in lines)
        {
            Match context = StorageInfoContextRegex.Match(line);
            if (context.Success)
            {
                contextLun = int.Parse(context.Groups["lun"].Value, CultureInfo.InvariantCulture);
                continue;
            }

            Match sectorSize = SectorSizeLineRegex.Match(line);
            if (sectorSize.Success)
            {
                int size = int.Parse(sectorSize.Groups["size"].Value, CultureInfo.InvariantCulture);
                int declaredLun = int.Parse(sectorSize.Groups["lun"].Value, CultureInfo.InvariantCulture);

                if (declaredSectorSizes.TryGetValue(declaredLun, out int existing) && existing != size)
                {
                    throw new InvalidOperationException(
                        $"Conflicting sector size declarations for LUN {declaredLun}: {existing} and {size}.");
                }

                declaredSectorSizes[declaredLun] = size;
                continue;
            }

            if (line.IndexOf("DEVPRG LOG", StringComparison.OrdinalIgnoreCase) < 0)
            {
                continue;
            }

            // Only a line carrying the exact quoted JSON property token is a storage_info payload. Ordinary
            // DEVPRG log lines (build date, chip id, supported functions, ...) are unrelated and ignored.
            // A line that does carry the token but is malformed still fails below.
            if (line.IndexOf("\"storage_info\"", StringComparison.Ordinal) < 0)
            {
                continue;
            }

            if (contextLun is null)
            {
                throw new InvalidOperationException(
                    "The storage_info payload is not bound to a 'Getting Storage Info for LUN N' line.");
            }

            int open = line.IndexOf('{');
            int close = line.LastIndexOf('}');
            if (open < 0 || close <= open)
            {
                throw new InvalidOperationException("The storage_info payload is not a JSON object: " + line.Trim());
            }

            int lun = contextLun.Value;
            EdlGeometry geometry = ParseStorageInfo(line.Substring(open, close - open + 1), lun);

            if (geometries.TryGetValue(lun, out EdlGeometry existingGeometry))
            {
                if (existingGeometry.SectorSize != geometry.SectorSize ||
                    existingGeometry.TotalSectors != geometry.TotalSectors)
                {
                    throw new InvalidOperationException(
                        $"Conflicting repeated geometry for LUN {lun}.");
                }

                continue;
            }

            geometries.Add(lun, geometry);
        }

        if (!geometries.TryGetValue(requestedLun, out EdlGeometry requested))
        {
            throw new InvalidOperationException(
                $"The probe did not report storage_info geometry for LUN {requestedLun}.");
        }

        if (!declaredSectorSizes.TryGetValue(requestedLun, out int declared))
        {
            throw new InvalidOperationException(
                $"The probe did not report a sector size for LUN {requestedLun}.");
        }

        if (declared != requested.SectorSize)
        {
            throw new InvalidOperationException(
                $"The declared sector size {declared} disagrees with the storage_info block size " +
                $"{requested.SectorSize} for LUN {requestedLun}.");
        }

        return requested;
    }

    private static EdlGeometry ParseStorageInfo(string json, int lun)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException(
                $"The storage_info payload for LUN {lun} is not valid JSON.", exception);
        }

        using (document)
        {
            if (!document.RootElement.TryGetProperty("storage_info", out JsonElement info) ||
                info.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidOperationException(
                    $"The payload for LUN {lun} has no storage_info object.");
            }

            if (!info.TryGetProperty("total_blocks", out JsonElement totalElement) ||
                !totalElement.TryGetInt64(out long totalBlocks) ||
                totalBlocks <= 0)
            {
                throw new InvalidOperationException(
                    $"storage_info for LUN {lun} has an invalid total_blocks value.");
            }

            if (!info.TryGetProperty("block_size", out JsonElement blockElement) ||
                !blockElement.TryGetInt32(out int blockSize) ||
                blockSize < MinimumSectorSize ||
                (blockSize & (blockSize - 1)) != 0)
            {
                throw new InvalidOperationException(
                    $"storage_info for LUN {lun} has an invalid block_size value.");
            }

            if (!info.TryGetProperty("mem_type", out JsonElement memElement) ||
                memElement.ValueKind != JsonValueKind.String ||
                !string.Equals(memElement.GetString(), "UFS", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"storage_info for LUN {lun} does not describe UFS storage.");
            }

            return new EdlGeometry(lun, blockSize, totalBlocks);
        }
    }

    // ------------------------------------------------------------------ read helpers

    /// <summary>
    /// Preflight for <see cref="ProbeRawGeometryAsync"/>: the caller must hand over an owned evidence
    /// directory, so the new file must be fully qualified, absent, inside an existing explicit parent, and
    /// neither the target nor any containing directory may be a reparse point or symbolic link. Nothing is
    /// created, deleted or overwritten here and the caller's string is not modified; the canonical absolute
    /// path is the only value returned and later placed in the argv.
    /// </summary>
    private static string ValidateRawGeometryOutputPath(string? newOutputFile)
    {
        if (string.IsNullOrWhiteSpace(newOutputFile))
        {
            throw new ArgumentException(
                "A non-blank raw geometry output file path is required.", nameof(newOutputFile));
        }

        if (!Path.IsPathFullyQualified(newOutputFile))
        {
            throw new IOException(
                $"The raw geometry output file '{newOutputFile}' must be a fully qualified path.");
        }

        string canonical;
        try
        {
            canonical = Path.GetFullPath(newOutputFile);
        }
        catch (Exception exception)
            when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new IOException(
                $"The raw geometry output file '{newOutputFile}' is not a usable path.", exception);
        }

        if (File.Exists(canonical) || Directory.Exists(canonical))
        {
            throw new IOException(
                $"The raw geometry output file '{canonical}' already exists; an overwrite is not allowed.");
        }

        string? parent = Path.GetDirectoryName(canonical);
        if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent))
        {
            throw new IOException(
                $"The raw geometry output file '{canonical}' requires an existing explicit parent directory.");
        }

        RejectReparseTarget(canonical);
        RejectReparseDirectoryChain(parent);

        return canonical;
    }

    /// <summary>Rejects an existing file that is a reparse point or symbolic link, including a dangling one.</summary>
    private static void RejectReparseTarget(string canonicalPath)
    {
        FileAttributes attributes;
        try
        {
            attributes = File.GetAttributes(canonicalPath);
        }
        catch (Exception exception)
            when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            return;
        }

        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException(
                $"The raw geometry output file '{canonicalPath}' is a reparse point or symbolic link; " +
                "an owned evidence file is required.");
        }
    }

    /// <summary>
    /// Rejects any directory from the explicit parent up to the root that is a reparse point or symbolic
    /// link, so the one-sector artifact cannot land in a redirected location outside the owned directory.
    /// </summary>
    private static void RejectReparseDirectoryChain(string startDirectory)
    {
        string? directory = startDirectory;

        while (!string.IsNullOrEmpty(directory))
        {
            if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException(
                    $"The raw geometry output directory '{directory}' is a reparse point or symbolic link; " +
                    "an owned evidence directory is required.");
            }

            string? parent = Path.GetDirectoryName(directory);
            if (string.IsNullOrEmpty(parent) || string.Equals(parent, directory, StringComparison.Ordinal))
            {
                break;
            }

            directory = parent;
        }
    }

    /// <summary>
    /// Requires exactly one read plan line for LBA 0, count 1, one sector of <paramref name="sectorSize"/>
    /// bytes and the requested LUN, and requires the path in that line to name the canonical output file
    /// under the OS path comparison rules. Any additional plan line is a mismatch.
    /// </summary>
    private static void ValidateRawGeometryReadPlan(
        string[] lines,
        int lun,
        int sectorSize,
        string canonicalOutput)
    {
        StringComparison pathComparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

        int plans = 0;

        foreach (string line in lines)
        {
            Match match = PreparingReadRegex.Match(line);
            if (!match.Success)
            {
                continue;
            }

            plans++;
            if (plans > 1)
            {
                throw new InvalidOperationException(
                    "The raw geometry probe described more than one read plan: " + line.Trim());
            }

            string captured = match.Groups["path"].Value;

            if (!Path.IsPathFullyQualified(captured))
            {
                throw new InvalidOperationException(
                    $"The raw geometry probe used a relative output path '{captured}'.");
            }

            string capturedCanonical;
            try
            {
                capturedCanonical = Path.GetFullPath(captured);
            }
            catch (Exception exception)
                when (exception is ArgumentException or NotSupportedException or PathTooLongException)
            {
                throw new InvalidOperationException(
                    $"The raw geometry probe used an unusable output path '{captured}'.", exception);
            }

            if (!string.Equals(capturedCanonical, canonicalOutput, pathComparison))
            {
                throw new InvalidOperationException(
                    $"The raw geometry probe wrote to '{captured}' instead of the requested " +
                    $"'{canonicalOutput}'.");
            }
        }

        if (plans != 1)
        {
            throw new InvalidOperationException(
                "The raw geometry probe did not describe exactly one read plan.");
        }

        // Same range check as a normal read: count 1, start 0, last 0 and bytes equal to one sector.
        ValidatePreparingReadLine(lines, lun, 0, 1, sectorSize);
    }

    private static void ValidatePreparingReadLine(
        string[] lines,
        int lun,
        long startSector,
        long sectorCount,
        long byteCount)
    {
        long lastSector = startSector + sectorCount - 1;

        foreach (string line in lines)
        {
            Match match = PreparingReadRegex.Match(line);
            if (!match.Success)
            {
                continue;
            }

            bool agrees =
                MatchNumber(match, "count", sectorCount) &&
                MatchNumber(match, "start", startSector) &&
                MatchNumber(match, "last", lastSector) &&
                MatchNumber(match, "bytes", byteCount) &&
                MatchNumber(match, "lun", lun);

            if (!agrees)
            {
                throw new InvalidOperationException(
                    "The read command described a different range than the requested one: " + line.Trim());
            }
        }
    }

    private static void ValidateReportedReadBytes(string[] lines, long expectedBytes)
    {
        Match? success = lines
            .Select(line => ReadSuccessBytesRegex.Match(line))
            .FirstOrDefault(match => match.Success);

        if (success is null)
        {
            throw new InvalidOperationException("The read did not report the number of bytes written.");
        }

        long reported = ParseLong(success.Groups["bytes"].Value);
        if (reported != expectedBytes)
        {
            throw new InvalidOperationException(
                $"The read reported {reported} bytes, expected {expectedBytes}.");
        }
    }

    private static EdlReadEvidence VerifyReadFile(
        EdlGeometry geometry,
        long startSector,
        long sectorCount,
        long expectedBytes,
        string outputPath,
        ProcessResult result)
    {
        if (!File.Exists(outputPath))
        {
            throw new IOException($"The read did not produce the expected output file '{outputPath}'.");
        }

        using (FileStream flush = new(outputPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            if (flush.Length != expectedBytes)
            {
                throw new IOException(
                    $"The read output file '{outputPath}' is {flush.Length} bytes, expected {expectedBytes}.");
            }

            flush.Flush(flushToDisk: true);
        }

        using FileStream verify = new(outputPath, FileMode.Open, FileAccess.Read, FileShare.None);
        if (verify.Length != expectedBytes)
        {
            throw new IOException(
                $"The read output file '{outputPath}' changed length to {verify.Length} bytes, " +
                $"expected {expectedBytes}.");
        }

        string sha256 = Convert.ToHexString(SHA256.HashData(verify));

        return new EdlReadEvidence(
            geometry,
            startSector,
            sectorCount,
            outputPath,
            expectedBytes,
            sha256,
            result);
    }

    // ------------------------------------------------------------------ write/reset helpers

    private static void VerifySourceLengthAndHash(FileStream source, VerifiedEdlFile file)
    {
        if (source.Length != file.Length)
        {
            throw new InvalidOperationException(
                $"The verified file '{file.Path}' is {source.Length} bytes, but the claim says {file.Length}.");
        }

        string actual = Convert.ToHexString(SHA256.HashData(source));
        if (!string.Equals(actual, file.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"The verified file '{file.Path}' has SHA-256 {actual}, but the claim says {file.Sha256}.");
        }
    }

    private static void ValidateWriteResult(
        ProcessResult result,
        int lun,
        long startSector,
        long sectorCount,
        long byteCount,
        string expectedSerial)
    {
        string[] lines = SplitLines(result);
        ThrowIfCommandFailed(result, lines);
        ThrowIfHardError(lines);
        ReadSelectedBusSerial(lines, expectedSerial);

        Match? described = lines
            .Select(line => WritingRegex.Match(line))
            .FirstOrDefault(match => match.Success);

        if (described is null)
        {
            throw new InvalidOperationException("The write did not describe the sector range it programmed.");
        }

        bool agrees =
            MatchNumber(described, "count", sectorCount) &&
            MatchNumber(described, "bytes", byteCount) &&
            MatchNumber(described, "lun", lun) &&
            MatchNumber(described, "start", startSector);

        if (!agrees)
        {
            throw new InvalidOperationException(
                "The write command described a different range than the verified file and request.");
        }

        if (!Contains(lines, "Program command ACKed, raw mode enabled."))
        {
            throw new InvalidOperationException("The write did not report the initial program acknowledgement.");
        }

        if (!Contains(lines, "Program operation successful (final ACK received)."))
        {
            throw new InvalidOperationException("The write did not report the final program acknowledgement.");
        }

        bool sawRawStream = false;
        foreach (string line in lines)
        {
            Match sent = RawDataStreamRegex.Match(line);
            if (!sent.Success)
            {
                continue;
            }

            sawRawStream = true;
            long reported = ParseLong(sent.Groups["bytes"].Value);
            if (reported != byteCount)
            {
                throw new InvalidOperationException(
                    $"The write reported {reported} raw data bytes sent, expected {byteCount}.");
            }
        }

        if (!sawRawStream)
        {
            throw new InvalidOperationException("The write did not report the raw data stream it sent.");
        }
    }

    private static void ValidateResetResult(ProcessResult result, string expectedSerial)
    {
        string[] lines = SplitLines(result);
        ThrowIfCommandFailed(result, lines);
        ThrowIfHardError(lines);
        ReadSelectedBusSerial(lines, expectedSerial);

        if (!Contains(lines, "Power command 'Reset' sent successfully."))
        {
            throw new InvalidOperationException("The reset was not acknowledged.");
        }

        if (!Contains(lines, "Device should now be resetting."))
        {
            throw new InvalidOperationException("The reset did not report that the device is resetting.");
        }
    }

    // ------------------------------------------------------------------ small helpers

    private static void ValidateLun(int lun)
    {
        if (lun < 0 || lun > 5)
        {
            throw new ArgumentOutOfRangeException(nameof(lun), lun, "The EDL LUN must be between 0 and 5.");
        }
    }

    private void RequireSessionAndGeometry(int lun)
    {
        if (!_initialProven)
        {
            throw new InvalidOperationException(
                "The operation requires a successful initial loader probe in this session.");
        }

        if (!_geometryByLun.ContainsKey(lun))
        {
            throw new InvalidOperationException(
                $"LUN {lun} has not been probed in this session; its geometry is unknown.");
        }
    }

    private static void RequireNonBlank(string? value, string description)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"The loaded {description} is blank.");
        }
    }

    private static long CheckedAdd(long left, long right, string message)
    {
        try
        {
            return checked(left + right);
        }
        catch (OverflowException exception)
        {
            throw new InvalidOperationException(message, exception);
        }
    }

    private static long CheckedMultiply(long left, long right, string message)
    {
        try
        {
            return checked(left * right);
        }
        catch (OverflowException exception)
        {
            throw new InvalidOperationException(message, exception);
        }
    }

    /// <summary>
    /// Byte-dependent command timeout: the fixed <paramref name="minimum"/> (120 s read / 180 s write) or,
    /// above the floor, <see cref="TimeoutFixedSeconds"/> s plus one whole second per started
    /// <see cref="TimeoutTransferBytesPerSecond"/> block, i.e. a ceiling of
    /// <c>byteCount / 8 MiB</c> computed from quotient and remainder so no <c>byteCount + rate - 1</c>
    /// addition can overflow.
    /// <para>
    /// Pure and total: a non-positive count or a duration that cannot be represented as a
    /// <see cref="TimeSpan"/> is rejected with <see cref="InvalidOperationException"/> instead of being
    /// clamped, made infinite or silently truncated. Callers invoke this while building the command, so a
    /// rejected count never reaches the runner.
    /// </para>
    /// </summary>
    private static TimeSpan ByteDependentTimeout(long byteCount, TimeSpan minimum)
    {
        if (byteCount <= 0)
        {
            throw new InvalidOperationException("The command byte count must be positive.");
        }

        try
        {
            long blocks = byteCount / TimeoutTransferBytesPerSecond;
            long remainder = byteCount % TimeoutTransferBytesPerSecond;
            long transferSeconds = checked(blocks + (remainder == 0 ? 0 : 1));
            long seconds = checked(transferSeconds + TimeoutFixedSeconds);
            long ticks = checked(seconds * TimeSpan.TicksPerSecond);

            TimeSpan computed = TimeSpan.FromTicks(ticks);
            return computed > minimum ? computed : minimum;
        }
        catch (OverflowException exception)
        {
            throw new InvalidOperationException(
                $"The {byteCount}-byte command cannot be given a finite representable timeout.", exception);
        }
    }

    private static bool MatchNumber(Match match, string group, long expected) =>
        long.TryParse(
            match.Groups[group].Value,
            NumberStyles.None,
            CultureInfo.InvariantCulture,
            out long actual) && actual == expected;

    private static long ParseLong(string value) =>
        long.Parse(value, NumberStyles.None, CultureInfo.InvariantCulture);

    private static string Invariant(long value) => value.ToString(CultureInfo.InvariantCulture);

    private static string Invariant(int value) => value.ToString(CultureInfo.InvariantCulture);

    private static bool IsBusSerialHex(string? value)
    {
        if (value is null || value.Length != SnHexLength)
        {
            return false;
        }

        foreach (char character in value)
        {
            bool isHex = character is >= '0' and <= '9'
                or >= 'a' and <= 'f'
                or >= 'A' and <= 'F';

            if (!isHex)
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsSha256Hex(string? value)
    {
        if (value is null || value.Length != 64)
        {
            return false;
        }

        foreach (char character in value)
        {
            bool isHex = character is >= '0' and <= '9'
                or >= 'a' and <= 'f'
                or >= 'A' and <= 'F';

            if (!isHex)
            {
                return false;
            }
        }

        return true;
    }

    private static string Describe(string[] lines)
    {
        string text = string.Join("\n", lines).Trim();
        return text.Length > 0 ? text : "the command produced no diagnostic output";
    }
}
