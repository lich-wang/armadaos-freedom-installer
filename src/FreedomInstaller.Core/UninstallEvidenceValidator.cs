using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace FreedomInstaller.Core;

/// <summary>
/// Everything the uninstall path is allowed to act on, proven against the original table before any write:
/// the confirmed <see cref="Identity"/>, the two tables that were cross-checked, the installation
/// <see cref="Record"/> the validator derived from them, the <see cref="Plan"/> the
/// <see cref="UninstallPlanner"/> produced, and the fingerprints of the evidence.
/// <para>
/// There is deliberately no public constructor: an instance can only come out of
/// <see cref="UninstallEvidenceValidator.Validate"/>. Nothing that merely deserialised a JSON document can
/// hand the write backend a validated input set.
/// </para>
/// </summary>
public sealed class ValidatedUninstallInputs
{
    internal ValidatedUninstallInputs(
        DeviceIdentity identity,
        GptTable originalTable,
        GptTable currentTable,
        string originalGptFingerprint,
        string currentTableFingerprint,
        LinuxInstallationLayout record,
        AndroidRestorePlan plan,
        string evidenceFingerprint)
    {
        ArgumentNullException.ThrowIfNull(plan);

        Identity = identity;
        OriginalTable = originalTable;
        CurrentTable = currentTable;
        OriginalGptFingerprint = originalGptFingerprint;
        CurrentTableFingerprint = currentTableFingerprint;
        Record = record;

        // The plan is re-created around a read-only copy of its number list, so the validated token never
        // hands out a collection that can still be rewritten through the plan it came from.
        var removed = new List<long>();
        if (plan.RemovedPartitionNumbers is not null)
        {
            removed.AddRange(plan.RemovedPartitionNumbers);
        }

        Plan = plan with { RemovedPartitionNumbers = new ReadOnlyCollection<long>(removed) };

        EvidenceFingerprint = evidenceFingerprint;
    }

    /// <summary>Serial, model and lock state the user confirmed before any evidence was read.</summary>
    public DeviceIdentity Identity { get; }

    /// <summary>The original Android table decoded from the raw capture; its DeviceId is always null.</summary>
    public GptTable OriginalTable { get; }

    /// <summary>The table the live disk reports right now, including its device node.</summary>
    public GptTable CurrentTable { get; }

    /// <summary><see cref="GptTable.SourceFingerprint"/> of <see cref="OriginalTable"/>.</summary>
    public string OriginalGptFingerprint { get; }

    /// <summary>Fingerprint of the current table the caller presented as evidence.</summary>
    public string CurrentTableFingerprint { get; }

    /// <summary>Installation record rebuilt from the two tables; DeviceId comes from the current table.</summary>
    public LinuxInstallationLayout Record { get; }

    /// <summary>Restore plan for the two owned Linux partitions, produced by <see cref="UninstallPlanner"/>.</summary>
    public AndroidRestorePlan Plan { get; }

    /// <summary>Opaque fingerprint over all validated evidence, so a later write can name exactly this input set.</summary>
    public string EvidenceFingerprint { get; }
}

/// <summary>
/// Turns "the original table" plus "what the disk says now" into a validated input set for the uninstall
/// path. The two tables are compared literally - disk GUID, disk size, sector size and usable window - and
/// every original partition except <c>userdata</c> must still be present with the same number, name, UUID,
/// type, start and size. The current <c>userdata</c> must be the same partition (UUID, name, start, type)
/// only smaller, which is what the install carved up.
/// <para>
/// Attributes are the one field allowed to move: OTA state is written there, so the validator keeps the words
/// the CURRENT table carries and never restores the original ones.
/// </para>
/// <para>
/// Exactly two partitions may be new: <c>ARMADA_BOOT</c> (1 GiB) and <c>ARMADA_ROOT</c> (&gt;= 32 GiB),
/// both immediately usable by <see cref="UninstallPlanner"/>. A removed, moved or renamed vendor partition,
/// an unknown extra partition, or a table that claims another disk is refused rather than guessed at.
/// </para>
/// </summary>
public static class UninstallEvidenceValidator
{
    /// <summary>Upper bound on the accepted sfdisk text, so no document can drive an unbounded parse.</summary>
    private const int MaximumDocumentChars = 16 * 1024 * 1024;

    /// <summary>Largest entry array a GPT may declare.</summary>
    private const int MaximumPartitionSlots = 32768;

    private const string UserdataName = "userdata";
    private const string LinuxBootName = "ARMADA_BOOT";
    private const string LinuxRootName = "ARMADA_ROOT";

    /// <summary>
    /// Reads the sfdisk JSON of the live disk into a table. The document must report a GPT table in sectors
    /// with a 512 or 4096 byte sector size, a disk GUID, a usable window inside the disk and well formed
    /// partitions whose numbers match their device nodes; <c>attrs</c> is optional and defaults to 0.
    /// <para>
    /// Attribute names are parsed exactly: <c>RequiredPartition</c>, <c>NoBlockIOProtocol</c> and
    /// <c>LegacyBIOSBootable</c> set bits 0, 1 and 2; <c>GUID:&lt;n&gt;</c> starts a list of GUID attribute
    /// bits that the following decimal tokens continue. Names may appear in any order and must not repeat; an
    /// unknown name, a malformed one or a repeated bit rejects the table instead of being silently ignored.
    /// </para>
    /// <para>
    /// The device node is kept exactly as reported - it is a POSIX path, never a Windows path. The returned
    /// table's <see cref="GptTable.SourceFingerprint"/> hashes the raw text together with the sector size and
    /// disk length. No file, device or process is touched.
    /// </para>
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="json"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="diskBytes"/> is not positive, or is not a whole number of the reported sector size.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// The text is not valid JSON, is larger than 16 MiB, is not a GPT table in sectors, or carries metadata,
    /// a usable window or a partition that contradicts itself.
    /// </exception>
    public static GptTable ReadCurrentSfdisk(string json, long diskBytes)
    {
        if (json is null)
        {
            throw new ArgumentNullException(nameof(json));
        }

        if (diskBytes <= 0)
        {
            throw new ArgumentException("The disk length must be positive.", nameof(diskBytes));
        }

        if (json.Length > MaximumDocumentChars)
        {
            throw new InvalidDataException("The sfdisk document is larger than 16 MiB.");
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 32,
            });
        }
        catch (JsonException exception)
        {
            // A JsonException must never reach the caller as a parse artefact; the bytes are simply untrusted.
            throw new InvalidDataException("The current table document is not valid JSON.", exception);
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("partitiontable", out var table)
                || table.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException("The document carries no partitiontable object.");
            }

            if (!string.Equals(RequireString(table, "label"), "gpt", StringComparison.Ordinal))
            {
                throw new InvalidDataException("The reported table is not a GPT table.");
            }

            if (!string.Equals(RequireString(table, "unit"), "sectors", StringComparison.Ordinal))
            {
                throw new InvalidDataException("The reported table is not expressed in sectors.");
            }

            var diskGuid = RequireGuid(RequireString(table, "id"), "disk GUID");

            // The device node is a POSIX path reported by the device side; it is kept verbatim.
            var device = RequireString(table, "device");
            if (device.Length == 0)
            {
                throw new InvalidDataException("The reported table names no device node.");
            }

            var sectorSize = RequireInteger(table, "sectorsize");
            if (sectorSize != 512 && sectorSize != 4096)
            {
                throw new InvalidDataException("The reported sector size is neither 512 nor 4096 bytes.");
            }

            if (diskBytes % sectorSize != 0)
            {
                throw new ArgumentException(
                    "The disk length is not a whole number of the reported sector size.", nameof(diskBytes));
            }

            var firstUsableSector = RequireInteger(table, "firstlba");
            var lastUsableSector = RequireInteger(table, "lastlba");
            var totalSectors = diskBytes / sectorSize;

            // The usable range has to sit strictly between the two header sectors, exactly as in a GPT.
            if (firstUsableSector <= 1
                || lastUsableSector >= totalSectors - 1
                || firstUsableSector > lastUsableSector)
            {
                throw new InvalidDataException(
                    "The declared usable range is not inside the disk between the two headers.");
            }

            if (!table.TryGetProperty("partitions", out var nodes) || nodes.ValueKind != JsonValueKind.Array)
            {
                throw new InvalidDataException("The reported table carries no partitions array.");
            }

            if (nodes.GetArrayLength() > MaximumPartitionSlots)
            {
                throw new InvalidDataException("The table reports more partitions than a GPT can hold.");
            }

            long? declaredSlots = null;
            if (table.TryGetProperty("table-length", out var tableLength))
            {
                declaredSlots = ReadTableLength(tableLength);
            }

            var partitions = new List<GptPartition>();
            var numbers = new HashSet<int>();
            var partUuids = new HashSet<string>(StringComparer.Ordinal);
            var used = new List<(long Start, long End)>();

            foreach (var node in nodes.EnumerateArray())
            {
                if (node.ValueKind != JsonValueKind.Object)
                {
                    throw new InvalidDataException("A partition entry is not an object.");
                }

                var number = ReadNodeNumber(node, device);
                if (!numbers.Add(number))
                {
                    throw new InvalidDataException($"Partition number {number} is reported twice.");
                }

                if (declaredSlots.HasValue && number > declaredSlots.Value)
                {
                    throw new InvalidDataException(
                        $"Partition number {number} is outside the declared table length {declaredSlots.Value}.");
                }

                var start = RequireInteger(node, "start");
                if (start < 0)
                {
                    throw new InvalidDataException($"Partition {number} starts at a negative sector.");
                }

                var size = RequireInteger(node, "size");
                if (size <= 0)
                {
                    throw new InvalidDataException($"Partition {number} has no positive sector count.");
                }

                if (start > long.MaxValue - size)
                {
                    throw new InvalidDataException($"Partition {number} has a sector range that is not representable.");
                }

                var endExclusive = start + size;
                if (start < firstUsableSector || endExclusive - 1 > lastUsableSector)
                {
                    throw new InvalidDataException($"Partition {number} lies outside the declared usable range.");
                }

                var typeGuid = RequireGuid(RequireString(node, "type"), $"type GUID of partition {number}");
                var partUuid = RequireGuid(RequireString(node, "uuid"), $"partition GUID of partition {number}");
                if (!partUuids.Add(partUuid))
                {
                    throw new InvalidDataException($"Partition GUID {partUuid} is reported twice.");
                }

                // sfdisk omits the name of an unnamed GPT entry; that is an empty name, not a missing field.
                var name = string.Empty;
                if (node.TryGetProperty("name", out var nameElement))
                {
                    if (nameElement.ValueKind != JsonValueKind.String)
                    {
                        throw new InvalidDataException($"The name of partition {number} is not a string.");
                    }

                    name = nameElement.GetString() ?? string.Empty;
                }

                var attributes = 0UL;
                if (node.TryGetProperty("attrs", out var attrsElement))
                {
                    if (attrsElement.ValueKind != JsonValueKind.String)
                    {
                        throw new InvalidDataException($"The attributes of partition {number} are not a string.");
                    }

                    attributes = ParseAttributes(attrsElement.GetString() ?? string.Empty, number);
                }

                partitions.Add(new GptPartition(number, name, typeGuid, partUuid, start, size, attributes));
                used.Add((start, endExclusive - 1));
            }

            used.Sort((left, right) => left.Start.CompareTo(right.Start));
            for (var index = 1; index < used.Count; index++)
            {
                if (used[index].Start <= used[index - 1].End)
                {
                    throw new InvalidDataException("Two reported partitions claim overlapping sectors.");
                }
            }

            return new GptTable(
                device,
                (int)sectorSize,
                diskBytes,
                diskGuid,
                firstUsableSector,
                lastUsableSector,
                partitions,
                ComputeSourceFingerprint(json, (int)sectorSize, diskBytes));
        }
    }

    /// <summary>
    /// Cross-checks the raw original table against the table the disk reports now and, only if they agree,
    /// derives the <see cref="LinuxInstallationLayout"/> the uninstall step needs and asks
    /// <see cref="UninstallPlanner"/> for the restore plan.
    /// <para>
    /// The identity must name a supported unit; the bootloader state is not consulted here, because this
    /// layer only reads evidence and never grants a write. The original table must be one
    /// <see cref="OriginalGptImporter.Parse"/> produced (no device node) and the current one must be one
    /// <see cref="ReadCurrentSfdisk"/> produced (a device node), so two arbitrary JSON tables cannot mint
    /// original-GPT proof.
    /// </para>
    /// </summary>
    /// <param name="identity">Identity the user confirmed; it must name a concrete, supported unit.</param>
    /// <param name="original">Table decoded by <see cref="OriginalGptImporter.Parse"/>.</param>
    /// <param name="current">Table read by <see cref="ReadCurrentSfdisk"/>.</param>
    /// <param name="currentTableFingerprint">Fingerprint the caller captured for <paramref name="current"/>.</param>
    /// <exception cref="ArgumentNullException">One of the arguments is null.</exception>
    /// <exception cref="ArgumentException">
    /// The identity is incomplete or unsupported, a fingerprint is blank, or the original table was not
    /// produced by the raw importer (it names a device node) while the current one names none; also raised by
    /// <see cref="UninstallPlanner"/> when it refuses an incompatible size or argument.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// The two tables describe a different disk or geometry, or the current partitions are not exactly the
    /// original ones plus the two Linux partitions this install owns.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// <see cref="UninstallPlanner"/> refuses the Linux partition type or the layout it would produce.
    /// </exception>
    public static ValidatedUninstallInputs Validate(
        DeviceIdentity identity,
        GptTable original,
        GptTable current,
        string currentTableFingerprint)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(original);
        ArgumentNullException.ThrowIfNull(current);
        ArgumentException.ThrowIfNullOrWhiteSpace(currentTableFingerprint);

        if (string.IsNullOrWhiteSpace(identity.Serial))
        {
            throw new ArgumentException("The confirmed identity carries no serial.", nameof(identity));
        }

        if (!DeviceProbe.IsSupportedModel(identity.Model))
        {
            throw new ArgumentException(
                $"The confirmed identity names the unsupported model '{identity.Model}'.", nameof(identity));
        }

        // Provenance is carried by the tables themselves: raw original bytes name no device node, and only
        // ReadCurrentSfdisk attaches one. Swapping the two can therefore never be accepted.
        if (original.DeviceId is not null)
        {
            throw new ArgumentException(
                "The original table names a device node, so it is not a raw capture.", nameof(original));
        }

        if (string.IsNullOrWhiteSpace(current.DeviceId))
        {
            throw new ArgumentException("The current table names no device node.", nameof(current));
        }

        // The node the later write has to name: it comes from the current table and from nowhere else.
        var currentDeviceId = current.DeviceId!;

        RequireFingerprint(original.SourceFingerprint, nameof(original));
        RequireFingerprint(current.SourceFingerprint, nameof(current));

        if (original.SectorSize != 512 && original.SectorSize != 4096)
        {
            throw new InvalidDataException("The original table was not decoded at a supported sector size.");
        }

        if (!string.Equals(CanonicalUuid(original.DiskGuid), CanonicalUuid(current.DiskGuid), StringComparison.Ordinal))
        {
            throw new InvalidDataException("The two tables name different disks.");
        }

        if (original.DiskBytes != current.DiskBytes
            || original.SectorSize != current.SectorSize
            || original.FirstUsableSector != current.FirstUsableSector
            || original.LastUsableSector != current.LastUsableSector)
        {
            throw new InvalidDataException("The two tables describe a different disk geometry.");
        }

        // ---- the original table must name exactly one userdata ------------------------------

        GptPartition? originalUserdata = null;
        var originalVendor = new List<GptPartition>();

        foreach (var partition in original.Partitions)
        {
            if (string.Equals(partition.Name, UserdataName, StringComparison.Ordinal))
            {
                if (originalUserdata is not null)
                {
                    throw new InvalidDataException("The original table names more than one userdata partition.");
                }

                originalUserdata = partition;
            }
            else
            {
                originalVendor.Add(partition);
            }
        }

        if (originalUserdata is null)
        {
            throw new InvalidDataException("The original table carries no userdata partition.");
        }

        // A genuine factory table never carries ARMADA_* partitions: the installer owns that label prefix.
        foreach (var partition in original.Partitions)
        {
            if (partition.Name.StartsWith("ARMADA_", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    $"The original table already carries the ARMADA_* partition {Describe(partition)}.");
            }
        }

        // The factory userdata must run to the very end of the usable area, and every other original
        // partition must sit entirely before it: that is the tail the installer split from.
        long originalUserdataEndExclusive;
        try
        {
            originalUserdataEndExclusive = checked(originalUserdata.StartSector + originalUserdata.SectorCount);
        }
        catch (OverflowException exception)
        {
            throw new InvalidDataException("The original userdata extent is not representable.", exception);
        }

        if (originalUserdataEndExclusive - 1 != original.LastUsableSector)
        {
            throw new InvalidDataException("The original userdata does not end at the last usable sector.");
        }

        foreach (var vendor in originalVendor)
        {
            long vendorEnd;
            try
            {
                vendorEnd = checked(vendor.StartSector + vendor.SectorCount);
            }
            catch (OverflowException exception)
            {
                throw new InvalidDataException(
                    "The original table contains an unrepresentable partition extent.", exception);
            }

            if (vendorEnd > originalUserdata.StartSector)
            {
                throw new InvalidDataException(
                    $"The original partition {Describe(vendor)} does not sit entirely before userdata.");
            }
        }

        // ---- the current table must still carry every original partition -------------------

        var currentByUuid = new Dictionary<string, GptPartition>(StringComparer.Ordinal);
        foreach (var partition in current.Partitions)
        {
            if (!currentByUuid.TryAdd(CanonicalUuid(partition.PartUuid), partition))
            {
                throw new InvalidDataException($"The current table repeats partition GUID {partition.PartUuid}.");
            }
        }

        var currentUserdata = RequireMatch(currentByUuid, originalUserdata);

        if (currentUserdata.Number != originalUserdata.Number
            || !string.Equals(currentUserdata.Name, originalUserdata.Name, StringComparison.Ordinal)
            || !string.Equals(
                CanonicalUuid(currentUserdata.TypeGuid),
                CanonicalUuid(originalUserdata.TypeGuid),
                StringComparison.Ordinal)
            || currentUserdata.StartSector != originalUserdata.StartSector)
        {
            throw new InvalidDataException("The current userdata is not the original partition at the same place.");
        }

        if (currentUserdata.SectorCount <= 0 || currentUserdata.SectorCount >= originalUserdata.SectorCount)
        {
            throw new InvalidDataException("The current userdata is not a strictly smaller part of the original one.");
        }

        var originalUuids = new HashSet<string>(StringComparer.Ordinal)
        {
            CanonicalUuid(originalUserdata.PartUuid),
        };

        foreach (var vendor in originalVendor)
        {
            originalUuids.Add(CanonicalUuid(vendor.PartUuid));

            var match = RequireMatch(currentByUuid, vendor);
            if (match.Number != vendor.Number
                || !string.Equals(match.Name, vendor.Name, StringComparison.Ordinal)
                || !string.Equals(CanonicalUuid(match.TypeGuid), CanonicalUuid(vendor.TypeGuid), StringComparison.Ordinal)
                || match.StartSector != vendor.StartSector
                || match.SectorCount != vendor.SectorCount)
            {
                throw new InvalidDataException(
                    $"The current table no longer matches the original partition {Describe(vendor)}.");
            }
        }

        // ---- exactly the owned Linux partitions may be new ------------------------------
        //
        // Two additions are the legacy layout (boot + root only); three additions are the modern layout
        // with a retained board backup. Anything else - and any name outside the exact three - is refused.

        const string LinuxBackupName = "ARMADA_BACKUP";

        var additions = new List<GptPartition>();
        foreach (var partition in current.Partitions)
        {
            if (!originalUuids.Contains(CanonicalUuid(partition.PartUuid)))
            {
                additions.Add(partition);
            }
        }

        if (additions.Count is < 2 or > 3)
        {
            throw new InvalidDataException(
                $"The current table adds {additions.Count} partitions; only {LinuxBootName}, {LinuxRootName} and optionally {LinuxBackupName} may be new.");
        }

        GptPartition? boot = null;
        GptPartition? root = null;
        GptPartition? backup = null;

        foreach (var addition in additions)
        {
            if (string.Equals(addition.Name, LinuxBootName, StringComparison.Ordinal))
            {
                if (boot is not null)
                {
                    throw new InvalidDataException($"The current table carries more than one {LinuxBootName}.");
                }

                boot = addition;
            }
            else if (string.Equals(addition.Name, LinuxRootName, StringComparison.Ordinal))
            {
                if (root is not null)
                {
                    throw new InvalidDataException($"The current table carries more than one {LinuxRootName}.");
                }

                root = addition;
            }
            else if (string.Equals(addition.Name, LinuxBackupName, StringComparison.Ordinal))
            {
                if (backup is not null)
                {
                    throw new InvalidDataException($"The current table carries more than one {LinuxBackupName}.");
                }

                backup = addition;
            }
            else
            {
                throw new InvalidDataException(
                    $"The current table carries the unknown extra partition {Describe(addition)}.");
            }
        }

        if (boot is null || root is null)
        {
            throw new InvalidDataException(
                $"The current table does not add exactly {LinuxBootName} and {LinuxRootName}.");
        }

        if (backup is null && additions.Count == 3)
        {
            throw new InvalidDataException(
                $"The current table adds three partitions, but the third is not named {LinuxBackupName}.");
        }

        // ---- record and plan ---------------------------------------------------------------

        long originalUserdataEnd;
        try
        {
            originalUserdataEnd = checked(originalUserdata.StartSector + originalUserdata.SectorCount);
        }
        catch (OverflowException exception)
        {
            throw new InvalidDataException("The original userdata extent is not representable.", exception);
        }

        // The backup is named by its GUID from the freshly parsed table, never by its name alone: a record
        // without a retained backup (legacy layout) leaves BoardBackupPartUuid null.
        var record = new LinuxInstallationLayout(
            currentDeviceId,
            CanonicalUuid(currentUserdata.PartUuid),
            CanonicalUuid(boot.PartUuid),
            CanonicalUuid(root.PartUuid),
            originalUserdataEnd)
        {
            BoardBackupPartUuid = backup is null ? null : CanonicalUuid(backup.PartUuid),
        };

        // The planner owns the Linux type, the exact 1 GiB boot, the 32 GiB root, the alignment, the overlap
        // and the tail rules; this layer only hands it the geometry the disk reports right now.
        var diskPartitions = new List<DiskPartition>(current.Partitions.Count);
        foreach (var partition in current.Partitions)
        {
            diskPartitions.Add(new DiskPartition(
                partition.Number,
                partition.Name,
                partition.StartSector,
                partition.SectorCount,
                partition.TypeGuid,
                partition.PartUuid));
        }

        var plan = UninstallPlanner.Plan(new DiskLayout(currentDeviceId, current.SectorSize, diskPartitions), record);

        var evidenceFingerprint = ComputeEvidenceFingerprint(
            identity, original, current, currentTableFingerprint, record, plan);

        return new ValidatedUninstallInputs(
            identity,
            original,
            current,
            original.SourceFingerprint,
            currentTableFingerprint,
            record,
            plan,
            evidenceFingerprint);
    }

    /// <summary>
    /// Validates evidence captured over EDL, where BOTH tables are raw GPT bytes read from the UFS logical unit
    /// rather than one raw capture plus an sfdisk document: <paramref name="original"/> is the factory table and
    /// <paramref name="currentRaw"/> is the raw table captured from the installed disk.
    /// <para>
    /// Both tables must come from <see cref="OriginalGptImporter.Parse"/> and therefore name no device node. A
    /// table produced by <see cref="ReadCurrentSfdisk"/> is refused in either position: an sfdisk document
    /// reports a POSIX node and cannot stand in for captured raw bytes. Only LUN 0 is supported by this
    /// profile; every other value is refused rather than interpreted.
    /// </para>
    /// <para>
    /// The method builds the current snapshot itself: all geometry, partitions, current attribute words and
    /// the raw <see cref="GptTable.SourceFingerprint"/> are copied unchanged, and the snapshot is labelled
    /// <c>edl:ufs:lun:0</c>. That snapshot is then cross-checked with the same rules as
    /// <see cref="Validate"/>, so the disk identity, vendor partitions, ownership and planner constraints all
    /// still apply. The caller's tables are never mutated.
    /// </para>
    /// <para>
    /// The returned token keeps the raw fingerprints: <see cref="ValidatedUninstallInputs.CurrentTableFingerprint"/>
    /// and the snapshot's source fingerprint are <paramref name="currentRaw"/>'s fingerprint, while
    /// <see cref="ValidatedUninstallInputs.OriginalGptFingerprint"/> is <paramref name="original"/>'s.
    /// <see cref="LinuxInstallationLayout.DeviceId"/> and the snapshot's device id both name the EDL marker, so
    /// a later write can tell this evidence apart from anything read off a live device node. Attributes stay
    /// the ones the raw current table carries; they are never replaced by the original ones.
    /// </para>
    /// <para>
    /// This is a pure evidence check. It proves neither that the capture is fresh, nor that the device is still
    /// present, nor that a write is authorised; obtaining a fresh raw capture and deciding to write remain the
    /// transport caller's responsibility.
    /// </para>
    /// </summary>
    /// <param name="identity">Identity the user confirmed; it must name a concrete, supported unit.</param>
    /// <param name="original">Raw factory table decoded by <see cref="OriginalGptImporter.Parse"/>.</param>
    /// <param name="currentRaw">Raw table of the installed disk, also decoded by the importer.</param>
    /// <param name="lun">UFS logical unit the captures came from; only 0 is valid for this profile.</param>
    /// <returns>
    /// The validated input set, with both device identifiers set to <c>edl:ufs:lun:0</c> and both raw source
    /// fingerprints retained.
    /// </returns>
    /// <exception cref="ArgumentNullException">One of the arguments is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="lun"/> is not 0, either table names a device node (so it was not decoded from raw
    /// bytes), the identity is incomplete or unsupported, a source fingerprint is blank, or
    /// <see cref="UninstallPlanner"/> refuses a size or argument.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// The tables describe a different disk or geometry, or the current partitions are not exactly the original
    /// ones plus the two Linux partitions this install owns.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// <see cref="UninstallPlanner"/> refuses the Linux partition type or the layout it would produce.
    /// </exception>
    public static ValidatedUninstallInputs ValidateEdl(
        DeviceIdentity identity,
        GptTable original,
        GptTable currentRaw,
        int lun)
    {
        const string EdlDeviceId = "edl:ufs:lun:0";

        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(original);
        ArgumentNullException.ThrowIfNull(currentRaw);

        // Only LUN 0 belongs to this profile; any other value is refused, never reinterpreted or defaulted.
        if (lun != 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(lun), lun, "Only the UFS logical unit 0 is supported by this profile.");
        }

        // Provenance again: raw importer output names no device node, so an sfdisk-derived table is refused in
        // either position before anything is compared.
        if (original.DeviceId is not null)
        {
            throw new ArgumentException(
                "The original table names a device node, so it is not a raw capture.", nameof(original));
        }

        if (currentRaw.DeviceId is not null)
        {
            throw new ArgumentException(
                "The current table names a device node, so it is not a raw capture.", nameof(currentRaw));
        }

        // The EDL marker is the only device identity this path may hand on. Everything else - sector size, disk
        // length, disk GUID, usable window, partitions with their current attribute words and the raw source
        // fingerprint - is copied from the capture, so the caller's tables are never mutated.
        var attachedCurrent = new GptTable(
            EdlDeviceId,
            currentRaw.SectorSize,
            currentRaw.DiskBytes,
            currentRaw.DiskGuid,
            currentRaw.FirstUsableSector,
            currentRaw.LastUsableSector,
            currentRaw.Partitions,
            currentRaw.SourceFingerprint);

        // The raw fingerprint stays the evidence fingerprint: the snapshot is a relabelling, not new evidence.
        return Validate(identity, original, attachedCurrent, currentRaw.SourceFingerprint);
    }

    /// <summary>Reads the partition number out of the reported node, never out of the list position.</summary>
    private static int ReadNodeNumber(JsonElement node, string device)
    {
        var text = RequireString(node, "node");

        // A device node ending in a digit separates the number with a 'p': /dev/sda1 but /dev/mmcblk0p1.
        var prefix = char.IsAsciiDigit(device[^1]) ? device + "p" : device;
        if (!text.StartsWith(prefix, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"Partition node '{text}' does not belong to the device '{device}'.");
        }

        var digits = text.AsSpan(prefix.Length);
        if (digits.Length == 0 || digits.Length > 9)
        {
            throw new InvalidDataException($"Partition node '{text}' carries no usable partition number.");
        }

        var number = 0;
        foreach (var digit in digits)
        {
            if (!char.IsAsciiDigit(digit))
            {
                throw new InvalidDataException($"Partition node '{text}' carries no usable partition number.");
            }

            number = (number * 10) + (digit - '0');
        }

        if (number <= 0 || number > MaximumPartitionSlots)
        {
            throw new InvalidDataException($"Partition node '{text}' carries an impossible partition number.");
        }

        return number;
    }

    /// <summary>
    /// Parses an sfdisk attribute word. Named flags are independent; <c>GUID:&lt;n&gt;</c> starts the list of
    /// GUID bits that the following bare decimal tokens continue. Every bit may be named once.
    /// </summary>
    private static ulong ParseAttributes(string text, int number)
    {
        var word = 0UL;
        var inGuidBits = false;

        foreach (var token in text.Split(
                     new[] { ',', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            if (token.StartsWith("GUID:", StringComparison.OrdinalIgnoreCase))
            {
                word = SetAttributeBit(word, ReadAttributeBit(token[5..], text, number), text, number);
                inGuidBits = true;
                continue;
            }

            switch (token)
            {
                case "RequiredPartition":
                    word = SetAttributeBit(word, 0, text, number);
                    continue;
                case "NoBlockIOProtocol":
                    word = SetAttributeBit(word, 1, text, number);
                    continue;
                case "LegacyBIOSBootable":
                    word = SetAttributeBit(word, 2, text, number);
                    continue;
            }

            if (inGuidBits)
            {
                word = SetAttributeBit(word, ReadAttributeBit(token, text, number), text, number);
                continue;
            }

            throw new InvalidDataException(
                $"The attribute text of partition {number} carries the unknown token '{token}'.");
        }

        return word;
    }

    private static int ReadAttributeBit(string digits, string text, int number)
    {
        if (digits.Length == 0 || digits.Length > 2)
        {
            throw new InvalidDataException(
                $"The attribute text of partition {number} carries the malformed bit '{digits}' in '{text}'.");
        }

        var index = 0;
        foreach (var digit in digits)
        {
            if (!char.IsAsciiDigit(digit))
            {
                throw new InvalidDataException(
                    $"The attribute text of partition {number} carries the malformed bit '{digits}' in '{text}'.");
            }

            index = (index * 10) + (digit - '0');
        }

        if (index > 63)
        {
            throw new InvalidDataException(
                $"The attribute text of partition {number} names the GUID bit {index}, which no GPT attribute defines.");
        }

        return index;
    }

    private static ulong SetAttributeBit(ulong word, int index, string text, int number)
    {
        var mask = 1UL << index;
        if ((word & mask) != 0UL)
        {
            throw new InvalidDataException(
                $"The attribute text of partition {number} names the bit {index} twice: '{text}'.");
        }

        return word | mask;
    }

    /// <summary>Reads the optional <c>table-length</c>, which sfdisk prints either as a number or as a string.</summary>
    private static long ReadTableLength(JsonElement element)
    {
        long value;

        if (element.ValueKind == JsonValueKind.Number)
        {
            if (!element.TryGetInt64(out value))
            {
                throw new InvalidDataException("The declared table length is not an integer.");
            }
        }
        else if (element.ValueKind == JsonValueKind.String)
        {
            var text = element.GetString() ?? string.Empty;
            if (text.Length == 0 || text.Length > 5)
            {
                throw new InvalidDataException("The declared table length is not a decimal count.");
            }

            foreach (var character in text)
            {
                if (!char.IsAsciiDigit(character))
                {
                    throw new InvalidDataException("The declared table length is not a decimal count.");
                }
            }

            value = long.Parse(text, CultureInfo.InvariantCulture);
        }
        else
        {
            throw new InvalidDataException("The declared table length is neither a number nor a decimal string.");
        }

        if (value <= 0 || value > MaximumPartitionSlots)
        {
            throw new InvalidDataException(
                $"The declared table length {value} is outside 1..{MaximumPartitionSlots}.");
        }

        return value;
    }

    private static GptPartition RequireMatch(
        IReadOnlyDictionary<string, GptPartition> currentByUuid, GptPartition original)
    {
        if (!currentByUuid.TryGetValue(CanonicalUuid(original.PartUuid), out var match))
        {
            throw new InvalidDataException(
                $"The current table no longer carries the original partition {Describe(original)}.");
        }

        return match;
    }

    private static void RequireFingerprint(string fingerprint, string parameter)
    {
        if (string.IsNullOrWhiteSpace(fingerprint))
        {
            throw new ArgumentException(
                "A partition table without a source fingerprint cannot be evidence.", parameter);
        }
    }

    private static string RequireString(JsonElement parent, string property)
    {
        if (!parent.TryGetProperty(property, out var element))
        {
            throw new InvalidDataException($"The document is missing the '{property}' field.");
        }

        if (element.ValueKind != JsonValueKind.String)
        {
            throw new InvalidDataException($"The '{property}' field is not a string.");
        }

        return element.GetString() ?? string.Empty;
    }

    private static long RequireInteger(JsonElement parent, string property)
    {
        if (!parent.TryGetProperty(property, out var element))
        {
            throw new InvalidDataException($"The document is missing the '{property}' field.");
        }

        if (element.ValueKind != JsonValueKind.Number)
        {
            throw new InvalidDataException($"The '{property}' field is not a number.");
        }

        if (!element.TryGetInt64(out var value))
        {
            throw new InvalidDataException($"The '{property}' field is not a representable integer.");
        }

        return value;
    }

    private static string RequireGuid(string text, string what)
    {
        if (!Guid.TryParse(text, out var value) || value == Guid.Empty)
        {
            throw new InvalidDataException($"The {what} '{text}' is not a non-zero GUID.");
        }

        return CanonicalUuid(value);
    }

    private static string CanonicalUuid(Guid value) => value.ToString("D").ToUpperInvariant();

    private static string CanonicalUuid(string value) =>
        Guid.TryParse(value, out var parsed) ? CanonicalUuid(parsed) : value;

    private static string Describe(GptPartition partition) => $"#{partition.Number} \"{partition.Name}\"";

    /// <summary>
    /// SHA-256 over the raw sfdisk text framed by the sector size and disk length, so two different documents
    /// - or the same document read for a different disk - can never share a fingerprint.
    /// </summary>
    private static string ComputeSourceFingerprint(string json, int sectorSize, long diskBytes)
    {
        var prefix = new byte[12];
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(0, 4), sectorSize);
        BinaryPrimitives.WriteInt64LittleEndian(prefix.AsSpan(4, 8), diskBytes);

        var text = Encoding.UTF8.GetBytes(json);

        using var sha256 = SHA256.Create();
        sha256.TransformBlock(prefix, 0, prefix.Length, null, 0);
        sha256.TransformBlock(text, 0, text.Length, null, 0);
        sha256.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

        return Convert.ToHexString(sha256.Hash!);
    }

    /// <summary>
    /// SHA-256 over the canonical fixed-shape JSON of every validated field: the confirmed identity, both
    /// source fingerprints, the caller's current-table fingerprint, the current partitions with their
    /// attributes, the derived record and the plan.
    /// </summary>
    private static string ComputeEvidenceFingerprint(
        DeviceIdentity identity,
        GptTable original,
        GptTable current,
        string currentTableFingerprint,
        LinuxInstallationLayout record,
        AndroidRestorePlan plan)
    {
        var buffer = new ArrayBufferWriter<byte>();

        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();

            writer.WriteStartObject("identity");
            writer.WriteString("serial", identity.Serial);
            writer.WriteString("model", identity.Model);
            writer.WriteString("bootloaderState", identity.BootloaderState.ToString());
            writer.WriteEndObject();

            writer.WriteStartObject("original");
            writer.WriteString("sourceFingerprint", original.SourceFingerprint);
            writer.WriteString("diskGuid", original.DiskGuid);
            writer.WriteEndObject();

            writer.WriteStartObject("current");
            writer.WriteString("sourceFingerprint", current.SourceFingerprint);
            writer.WriteString("deviceId", current.DeviceId);
            writer.WriteString("diskGuid", current.DiskGuid);
            writer.WriteNumber("sectorSize", current.SectorSize);
            writer.WriteNumber("diskBytes", current.DiskBytes);
            writer.WriteStartArray("partitions");
            foreach (var partition in current.Partitions)
            {
                writer.WriteStartObject();
                writer.WriteNumber("number", partition.Number);
                writer.WriteString("name", partition.Name);
                writer.WriteNumber("startSector", partition.StartSector);
                writer.WriteNumber("sectorCount", partition.SectorCount);
                writer.WriteString("typeGuid", partition.TypeGuid);
                writer.WriteString("partUuid", partition.PartUuid);
                writer.WriteNumber("attributes", partition.Attributes);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();

            writer.WriteString("currentTableFingerprint", currentTableFingerprint);

            writer.WriteStartObject("record");
            writer.WriteString("deviceId", record.DeviceId);
            writer.WriteString("userdataPartUuid", record.UserdataPartUuid);
            writer.WriteString("linuxBootPartUuid", record.LinuxBootPartUuid);
            writer.WriteString("linuxRootPartUuid", record.LinuxRootPartUuid);
            writer.WriteNumber("originalUserdataEndSector", record.OriginalUserdataEndSector);
            if (record.BoardBackupPartUuid is not null)
            {
                writer.WriteString("boardBackupPartUuid", record.BoardBackupPartUuid);
            }

            writer.WriteEndObject();

            writer.WriteStartObject("plan");
            writer.WriteNumber("userdataStartSector", plan.UserdataStartSector);
            writer.WriteNumber("userdataEndSectorExclusive", plan.UserdataEndSectorExclusive);
            writer.WriteNumber("restoredAndroidBytes", plan.RestoredAndroidBytes);
            writer.WriteStartArray("removedPartitionNumbers");
            foreach (var number in plan.RemovedPartitionNumbers)
            {
                writer.WriteNumberValue(number);
            }

            writer.WriteEndArray();
            writer.WriteEndObject();

            writer.WriteEndObject();
        }

        return Convert.ToHexString(SHA256.HashData(buffer.WrittenSpan));
    }
}
