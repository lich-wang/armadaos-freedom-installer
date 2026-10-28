using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

public static partial class InternalInstallBackup
{
    /// <summary>
    /// Opens one existing, verified internal-install backup and returns only the facts the uninstall needs:
    /// the original factory LUN0 table and the captured LUN0 GPT pair.
    /// <para>
    /// The directory validation, manifest and sidecar verification, payload leases, six-table parse, extent
    /// and whole-file SHA-256 verification and the six read-only geometry and bus-serial probes are exactly
    /// those of <see cref="OpenExistingAsync"/>. Only the requirement that the saved firmware is still the
    /// currently installed one is relaxed: the saved backup must still be internally consistent, its saved
    /// profile build equal to its own saved firmware display id and its saved firmware identity complete.
    /// </para>
    /// <para>
    /// The saved LUN0 table must be the original factory source, never a fresh installed GPT: no
    /// <c>ARMADA_</c> entries, exactly one <c>userdata</c> partition ending exactly at the last usable
    /// sector, and no other partition ending after <c>userdata</c> starts.
    /// </para>
    /// <para>
    /// No partition content is read or written, the device is never reset, and no backup file, manifest or
    /// sidecar is ever created, rewritten or deleted. A failure or cancellation after the first lease
    /// releases every lease again; lease ownership moves into the returned backup only on success.
    /// </para>
    /// </summary>
    /// <param name="client">The current EDL session; its exact <see cref="EdlClient.Binding"/> becomes the backup's binding.</param>
    /// <param name="backupDirectory">Absolute existing directory holding the manifest, sidecar and the model's payload files.</param>
    /// <param name="progress">Optional progress sink; null is allowed.</param>
    /// <param name="token">Cancellation; a cancelled open releases every lease it opened.</param>
    /// <returns>The narrow backup facts, holding read leases on the selected files until it is disposed.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="client"/> or <paramref name="backupDirectory"/> is null.</exception>
    /// <exception cref="ArgumentException">The directory is blank, not absolute or does not exist.</exception>
    /// <exception cref="IOException">The manifest, sidecar or a payload file is missing or unreadable.</exception>
    /// <exception cref="InvalidDataException">The backup is inconsistent with the manifest, its own bytes, this device or the original factory layout.</exception>
    /// <exception cref="InvalidOperationException">The profile or current binding is not the trusted, complete one, or the path is a reparse point.</exception>
    /// <exception cref="OperationCanceledException">The token was cancelled.</exception>
    public static async Task<UninstallOriginalGptBackup> OpenOriginalGptForUninstallAsync(
        EdlClient client,
        string backupDirectory,
        IProgress<InternalBackupProgress>? progress = null,
        CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();

        if (client is null)
        {
            throw new ArgumentNullException(nameof(client));
        }

        if (backupDirectory is null)
        {
            throw new ArgumentNullException(nameof(backupDirectory));
        }

        if (string.IsNullOrWhiteSpace(backupDirectory))
        {
            throw new ArgumentException(
                "An explicit backup directory is required; there is no parent or temporary fallback.",
                nameof(backupDirectory));
        }

        if (!Path.IsPathFullyQualified(backupDirectory))
        {
            throw new ArgumentException(
                "The backup directory must be an absolute path; no working-directory fallback is used.",
                nameof(backupDirectory));
        }

        string directory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(backupDirectory));

        if (File.Exists(directory))
        {
            throw new IOException("The selected backup path is a file, not a directory: '" + directory + "'.");
        }

        if (!Directory.Exists(directory))
        {
            throw new ArgumentException(
                "The selected backup directory does not exist: '" + directory + "'.", nameof(backupDirectory));
        }

        if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException(
                "The selected backup directory is a reparse point; a symlinked backup is not accepted.");
        }

        token.ThrowIfCancellationRequested();

        ExistingState state = await Task
            .Run(
                () => ExistingLoadAsync(client, directory, progress, token, requireCurrentFirmware: false),
                token)
            .ConfigureAwait(false);

        try
        {
            for (int lun = 0; lun < 6; lun++)
            {
                token.ThrowIfCancellationRequested();

                EdlProbeEvidence probe = await client
                    .ProbeAsync(lun, lun == 0 && !client.HasInitialSaharaProof, token)
                    .ConfigureAwait(false);

                EdlGeometry actual = RequireGeometry(probe, lun);
                EdlGeometry saved = state.Geometries[lun];

                if (actual.SectorSize != saved.SectorSize || actual.TotalSectors != saved.TotalSectors)
                {
                    throw new InvalidDataException(
                        "LUN" + lun + " now reports " + actual.SectorSize + " byte sectors and " +
                        actual.TotalSectors + " sectors, not the saved " + saved.SectorSize + " and " +
                        saved.TotalSectors + ".");
                }

                if (!string.Equals(probe.BusSerialHex, state.ExpectedBusSerialHex, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException(
                        "The probe of LUN" + lun + " selected bus serial '" + (probe.BusSerialHex ?? "<none>") +
                        "', not the expected '" + state.ExpectedBusSerialHex + "'.");
                }
            }

            GptTable originalTable = RequireOriginalFactoryLun0Table(state.Tables[0]);

            InternalInstallBackupRoles contract = InternalInstallBackupRoles
                .ForModel(client.Toolchain.Model)
                .ForCapturedRoles(state.Regions.Keys);

            UninstallOriginalGptBackup backup = new(
                client.Binding,
                directory,
                state.ManifestPath,
                state.ManifestSha256,
                client.Toolchain.Model,
                client.Toolchain.HardwareId,
                CopyGeometries(state.Geometries),
                originalTable,
                state.Regions["gpt_lun0_primary"],
                state.Regions["gpt_lun0_backup"],
                state.Locks);

            progress?.Report(new InternalBackupProgress(
                CompleteStage,
                null,
                state.TotalBytes,
                state.TotalBytes,
                contract.TotalFileCount,
                contract.TotalFileCount));

            return backup;
        }
        catch
        {
            state.DisposeLeases();
            throw;
        }
    }

    // ------------------------------------------------------------------ original factory layout

    /// <summary>
    /// Proves the saved LUN0 table is the original factory source, never a fresh installed GPT: no
    /// <c>ARMADA_</c> entries, exactly one <c>userdata</c> that ends exactly at the last usable sector, and
    /// no other partition ending after <c>userdata</c> starts.
    /// </summary>
    private static GptTable RequireOriginalFactoryLun0Table(GptTable table)
    {
        GptPartition? userdata = null;

        foreach (GptPartition partition in table.Partitions)
        {
            if (partition.Name is not null
                && partition.Name.StartsWith("ARMADA_", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "The saved LUN0 table contains an 'ARMADA_' partition; it is a fresh installed GPT, " +
                    "not the original factory backup.");
            }

            if (string.Equals(partition.Name, "userdata", StringComparison.Ordinal))
            {
                if (userdata is not null)
                {
                    throw new InvalidDataException(
                        "The saved LUN0 table contains more than one 'userdata' partition.");
                }

                userdata = partition;
            }
        }

        if (userdata is null)
        {
            throw new InvalidDataException("The saved LUN0 table contains no 'userdata' partition.");
        }

        long userdataEnd = CheckedAdd(
            userdata.StartSector,
            userdata.SectorCount,
            "The saved LUN0 'userdata' sector range overflows.");
        long lastUsableEnd = CheckedAdd(
            table.LastUsableSector,
            1,
            "The saved LUN0 last usable sector overflows.");

        if (userdataEnd != lastUsableEnd)
        {
            throw new InvalidDataException(
                "The saved LUN0 'userdata' partition does not end exactly at the last usable sector of the " +
                "original factory layout.");
        }

        foreach (GptPartition partition in table.Partitions)
        {
            if (ReferenceEquals(partition, userdata))
            {
                continue;
            }

            long end = CheckedAdd(
                partition.StartSector,
                partition.SectorCount,
                "The saved LUN0 partition '" + partition.Name + "' has an overflowing sector range.");

            if (end > userdata.StartSector)
            {
                throw new InvalidDataException(
                    "The saved LUN0 partition '" + partition.Name + "' ends after the start of 'userdata'; " +
                    "the saved table is not the original factory layout.");
            }
        }

        return table;
    }
}

/// <summary>
/// The narrow result of opening one existing internal-install backup for uninstall: the exact session
/// binding, the backup directory with its verified manifest, the saved geometry of all six LUNs, the
/// original factory LUN0 table and the captured LUN0 GPT pair.
/// <para>
/// This is deliberately not an <see cref="InternalBackupSet"/>: no full role set, no boot roles and no
/// planner layout are exposed. The metadata is immutable and stays readable after <see cref="Dispose"/>;
/// a live backup owns only the read leases on the selected files. It never deletes files, never disposes
/// the client or toolchain and never resets the device.
/// </para>
/// </summary>
public sealed class UninstallOriginalGptBackup : IDisposable
{
    private readonly EdlEntryResult _binding;
    private readonly string _directoryPath;
    private readonly string _manifestPath;
    private readonly string _manifestSha256;
    private readonly string _model;
    private readonly string _hardwareId;
    private readonly IReadOnlyDictionary<int, EdlGeometry> _geometries;
    private readonly GptTable _originalTable;
    private readonly EdlCapturedRegion _primaryGpt;
    private readonly EdlCapturedRegion _backupGpt;
    private readonly List<FileStream> _locks;
    private int _disposed;

    /// <summary>Factory-only constructor. Callers only ever receive a backup from <see cref="InternalInstallBackup.OpenOriginalGptForUninstallAsync"/>.</summary>
    internal UninstallOriginalGptBackup(
        EdlEntryResult binding,
        string directoryPath,
        string manifestPath,
        string manifestSha256,
        string model,
        string hardwareId,
        IReadOnlyDictionary<int, EdlGeometry> geometries,
        GptTable originalTable,
        EdlCapturedRegion primaryGpt,
        EdlCapturedRegion backupGpt,
        List<FileStream> locks)
    {
        _binding = binding;
        _directoryPath = directoryPath;
        _manifestPath = manifestPath;
        _manifestSha256 = manifestSha256;
        _model = model;
        _hardwareId = hardwareId;
        _geometries = geometries;
        _originalTable = originalTable;
        _primaryGpt = primaryGpt;
        _backupGpt = backupGpt;
        _locks = locks;
    }

    /// <summary>Exact <see cref="EdlClient.Binding"/> of the session the backup was opened from.</summary>
    public EdlEntryResult Binding => _binding;

    /// <summary>Absolute path of the selected backup directory.</summary>
    public string DirectoryPath => _directoryPath;

    /// <summary>Path of <c>backup-manifest.json</c> inside <see cref="DirectoryPath"/>.</summary>
    public string ManifestPath => _manifestPath;

    /// <summary>SHA-256 of the manifest file itself, verified against its sidecar.</summary>
    public string ManifestSha256 => _manifestSha256;

    /// <summary>Model of the loaded toolchain, for example <c>TB322FC</c>.</summary>
    public string Model => _model;

    /// <summary>Hardware id the initial loader proved.</summary>
    public string HardwareId => _hardwareId;

    /// <summary>Saved geometry of each of the six LUNs, verified equal to the fresh probes, keyed by LUN number.</summary>
    public IReadOnlyDictionary<int, EdlGeometry> Geometries => _geometries;

    /// <summary>The saved, re-verified original factory LUN0 table.</summary>
    public GptTable OriginalTable => _originalTable;

    /// <summary>The captured primary GPT of LUN0, role <c>gpt_lun0_primary</c>.</summary>
    public EdlCapturedRegion PrimaryGpt => _primaryGpt;

    /// <summary>The captured backup GPT of LUN0, role <c>gpt_lun0_backup</c>.</summary>
    public EdlCapturedRegion BackupGpt => _backupGpt;

    /// <summary>
    /// Releases only the read leases this backup owns. Idempotent, and it never deletes files or the
    /// metadata, never disposes the client/toolchain and never resets the device.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        foreach (FileStream stream in _locks)
        {
            stream.Dispose();
        }

        _locks.Clear();
    }
}
