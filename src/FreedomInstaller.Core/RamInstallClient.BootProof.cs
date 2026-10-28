using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// The proof-validation part of <see cref="RamInstallClient"/>: the read-only inspect source catalog
/// (parents plus ten bindings) and the single cross-validated build-boots proof. Export and finish
/// remain unimplemented; this file only locks four artifact descriptors and their real metadata.
/// </summary>
public sealed partial class RamInstallClient
{
    private const string KnownLoaderProfile = "tb322fc-abl259-xbl-config-ramdisk-derived";
    private const string StructuralLoaderProfile = "tb322fc-abl-kernel-region-derived";
    private const long KnownLoaderPageSize = 4096L;
    private const string UnknownLoaderProfile = "conservative-default";
    private const long UnknownLoaderMaxRawBytes = 134217728L;
    private const string RecoveryScope = "android-arm64-kernel-only";

    private const string CatalogProperty = "bootSourceCatalog";

    private static readonly string[] SourceRoles =
    {
        "current_boot",
        "vendor_boot",
        "init_boot",
        "abl",
        "xbl_config",
    };

    private static readonly string[] CatalogRoles =
    {
        "currentBoot",
        "vendorBoot",
        "initBoot",
        "abl",
        "xblConfig",
    };

    private static readonly string[] CatalogParentFields =
    {
        "device",
        "deviceId",
        "sectorSize",
        "diskBytes",
        "sysfsDevice",
        "linuxTableFingerprint",
    };

    private static readonly string[] CatalogBindingFields =
    {
        "slot",
        "role",
        "label",
        "partUuid",
        "device",
        "parentDevice",
        "number",
        "startSector",
        "sectorCount",
        "sectorSize",
        "length",
        "deviceId",
        "parentDeviceId",
        "contentRead",
    };

    private static readonly string[] BuiltSlotFields =
    {
        "slot",
        "candidate",
        "report",
        "builderReport",
    };

    private static readonly string[] BuiltFileFields =
    {
        "role",
        "length",
        "sha256",
    };

    private static readonly string[] SlotMaterialFields =
    {
        "schemaVersion",
        "slot",
        "is_kshim",
        "source_sha256",
        "source_lengths",
        "base_image",
        "ramdisks",
        "loader_budget",
        "oem_signed_restored",
        "recovery_scope",
        "signature_verification_performed",
    };

    private static readonly string[] BaseImageFields = { "length", "sha256" };

    private static readonly string[] RamdiskFields =
    {
        "boot_ramdisk_size",
        "vendor_ramdisk_size",
        "init_ramdisk_size",
        "total_ramdisk_size",
        "page_size",
    };

    private static readonly string[] LoaderBudgetFields =
    {
        "profile",
        "evidence",
        "formula",
        "max_raw_bytes",
        "known_loader_match",
        "abl_sha256",
        "xbl_config_sha256",
        "abl_bytes",
        "xbl_config_bytes",
        "total_ramdisk_bytes",
        "page_size",
    };

    private RamInstallBuiltBoots? _builtBoots;

    /// <summary>
    /// The retained inspect source catalog clone, or null for a request without the boot block. It is
    /// evidence only: it never becomes a path, a CLI argument or a content hash.
    /// </summary>
    public JsonElement? BootSourceCatalog { get; private set; }

    /// <summary>
    /// Reads the real prepare, deploy and build-boots statuses once, cross-validates the complete frozen
    /// proof and returns one immutable object. A failed check never caches or fabricates a result.
    /// </summary>
    /// <exception cref="InvalidOperationException">The request has no boot block or is not initialized.</exception>
    /// <exception cref="MaintenanceException">A status or proof field violates the frozen protocol.</exception>
    public async Task<RamInstallBuiltBoots> GetBuiltBootsAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RamInstallBootConfig boot = RequireBootConfiguration();
        RequireInitialized();

        if (_builtBoots is { } cached)
        {
            return cached;
        }

        RamInstallJob prepare = await GetStatusInternalAsync(PrepareLiteral, cancellationToken)
            .ConfigureAwait(false);
        RamInstallJob deploy = await GetStatusInternalAsync(DeployLiteral, cancellationToken)
            .ConfigureAwait(false);
        RamInstallJob build = await GetStatusInternalAsync(BuildBootsLiteral, cancellationToken)
            .ConfigureAwait(false);

        JsonElement prepareResult = RequireSucceededResult(prepare, PrepareLiteral);
        JsonElement deployResult = RequireSucceededResult(deploy, DeployLiteral);
        JsonElement buildResult = RequireSucceededResult(build, BuildBootsLiteral);

        PreparedFilesystems prepared = ValidatePrepareResult(prepareResult);
        ValidateDeployResult(deployResult, prepared);
        RamInstallBuiltBoots built = ValidateBuildResult(buildResult, boot, prepared);

        _builtBoots = built;
        return built;
    }

    private static JsonElement RequireSucceededResult(RamInstallJob job, string literal)
    {
        if (job.State != RamInstallJobState.Succeeded ||
            job.ExitCode != 0 ||
            job.HasError ||
            job.Result is not { } result ||
            result.ValueKind != JsonValueKind.Object)
        {
            throw ProtocolFailure();
        }

        return result;
    }

    private readonly struct PreparedFilesystems
    {
        public PreparedFilesystems(string boot, string root)
        {
            Boot = boot;
            Root = root;
        }

        public string Boot { get; }

        public string Root { get; }
    }

    private PreparedFilesystems ValidatePrepareResult(JsonElement result)
    {
        JsonElement boot = RequireObjectProperty(result, "boot");
        JsonElement root = RequireObjectProperty(result, "root");

        string bootPartUuid = RequireUuidProperty(boot, "partuuid");
        string rootPartUuid = RequireUuidProperty(root, "partuuid");

        if (!string.Equals(bootPartUuid, _request.BootPartUuid, StringComparison.Ordinal) ||
            !string.Equals(rootPartUuid, _request.RootPartUuid, StringComparison.Ordinal))
        {
            throw ProtocolFailure();
        }

        // Filesystem UUIDs are their own identity. They are never compared to, or substituted with, a
        // PARTUUID; only the real deploy and build values must agree with these two.
        return new PreparedFilesystems(
            RequireUuidProperty(boot, "filesystem_uuid"),
            RequireUuidProperty(root, "filesystem_uuid"));
    }

    private void ValidateDeployResult(JsonElement result, PreparedFilesystems prepared)
    {
        string checksum = RequireLowerHashProperty(result, "deployment_checksum");
        if (!string.Equals(checksum, _request.Seed.Commit, StringComparison.Ordinal))
        {
            throw ProtocolFailure();
        }

        JsonElement filesystems = RequireObjectProperty(result, "filesystem_uuids");
        if (!string.Equals(
                RequireUuidProperty(filesystems, "boot"),
                prepared.Boot,
                StringComparison.Ordinal) ||
            !string.Equals(
                RequireUuidProperty(filesystems, "root"),
                prepared.Root,
                StringComparison.Ordinal))
        {
            throw ProtocolFailure();
        }
    }

    private RamInstallBuiltBoots ValidateBuildResult(
        JsonElement result,
        RamInstallBootConfig boot,
        PreparedFilesystems prepared)
    {
        if (!HasExactObjectProperties(result, "deploymentChecksum", "filesystemUuids", "slots"))
        {
            throw ProtocolFailure();
        }

        string checksum = RequireLowerHashProperty(result, "deploymentChecksum");
        if (!string.Equals(checksum, _request.Seed.Commit, StringComparison.Ordinal))
        {
            throw ProtocolFailure();
        }

        JsonElement filesystems = RequireObjectProperty(result, "filesystemUuids");
        if (!HasExactObjectProperties(filesystems, "boot", "root") ||
            !string.Equals(
                RequireUuidProperty(filesystems, "boot"),
                prepared.Boot,
                StringComparison.Ordinal) ||
            !string.Equals(
                RequireUuidProperty(filesystems, "root"),
                prepared.Root,
                StringComparison.Ordinal))
        {
            throw ProtocolFailure();
        }

        JsonElement slots = RequireObjectProperty(result, "slots");
        if (!HasExactObjectProperties(slots, "a", "b"))
        {
            throw ProtocolFailure();
        }

        RamInstallBuiltSlot slotA = ValidateBuiltSlot(
            RequireObjectProperty(slots, "a"),
            "a",
            boot.Slots.A,
            RamInstallExportRole.BootA,
            RamInstallExportRole.ReportA);
        RamInstallBuiltSlot slotB = ValidateBuiltSlot(
            RequireObjectProperty(slots, "b"),
            "b",
            boot.Slots.B,
            RamInstallExportRole.BootB,
            RamInstallExportRole.ReportB);

        return new RamInstallBuiltBoots(checksum, prepared.Boot, prepared.Root, slotA, slotB);
    }

    private static RamInstallBuiltSlot ValidateBuiltSlot(
        JsonElement slot,
        string slotName,
        RamInstallBootSlot materials,
        RamInstallExportRole candidateRole,
        RamInstallExportRole reportRole)
    {
        if (!HasExactObjectProperties(slot, BuiltSlotFields))
        {
            throw ProtocolFailure();
        }

        if (!string.Equals(RequireCatalogString(slot, "slot"), slotName, StringComparison.Ordinal))
        {
            throw ProtocolFailure();
        }

        RamInstallBuiltFile candidate = ReadBuiltFile(
            RequireObjectProperty(slot, "candidate"),
            candidateRole);
        if (candidate.Length != materials.CurrentBoot.Length)
        {
            throw ProtocolFailure();
        }

        RamInstallBuiltFile report = ReadBuiltFile(
            RequireObjectProperty(slot, "report"),
            reportRole);

        JsonElement builderReport = RequireObjectProperty(slot, "builderReport");
        ValidateBuilderReport(builderReport, slotName, materials, candidate);

        return new RamInstallBuiltSlot(slotName, candidate, report, builderReport);
    }

    private static RamInstallBuiltFile ReadBuiltFile(
        JsonElement descriptor,
        RamInstallExportRole role)
    {
        if (!HasExactObjectProperties(descriptor, BuiltFileFields))
        {
            throw ProtocolFailure();
        }

        if (!string.Equals(
                RequireCatalogString(descriptor, "role"),
                RoleLiteral(role),
                StringComparison.Ordinal))
        {
            throw ProtocolFailure();
        }

        return new RamInstallBuiltFile(
            role,
            RequirePositiveInt64Property(descriptor, "length"),
            RequireLowerHashProperty(descriptor, "sha256"));
    }

    private static string RoleLiteral(RamInstallExportRole role) => role switch
    {
        RamInstallExportRole.BootA => "boot_a",
        RamInstallExportRole.BootB => "boot_b",
        RamInstallExportRole.ReportA => "report_a",
        RamInstallExportRole.ReportB => "report_b",
        _ => throw new ArgumentOutOfRangeException(nameof(role), role, "Unknown export role."),
    };

    private static void ValidateBuilderReport(
        JsonElement report,
        string slotName,
        RamInstallBootSlot materials,
        RamInstallBuiltFile candidate)
    {
        if (!RequireTrueProperty(report, "offline_verified") ||
            !RequireStringEquals(report, "layout_mode", "installed") ||
            !RequireStringEquals(report, "default_entry", "android") ||
            RequireInt32Property(report, "default_index") != 0)
        {
            throw ProtocolFailure();
        }

        JsonElement outputs = RequireObjectProperty(report, "outputs");
        JsonElement finalBoot = RequireObjectProperty(outputs, "final_boot");
        long finalLength = RequirePositiveInt64Property(finalBoot, "length");
        string finalHash = RequireLowerHashProperty(finalBoot, "sha256");
        if (finalLength != candidate.Length ||
            !string.Equals(finalHash, candidate.Sha256, StringComparison.Ordinal))
        {
            throw ProtocolFailure();
        }

        JsonElement stockImage = RequireObjectProperty(report, "stock_image");
        long stockLength = RequirePositiveInt64Property(stockImage, "length");
        string stockHash = RequireLowerHashProperty(stockImage, "sha256");

        JsonElement slotMaterial = RequireObjectProperty(report, "slot_material");
        ValidateSlotMaterial(slotMaterial, slotName, materials, stockLength, stockHash);

        JsonElement reportBudget = RequireObjectProperty(report, "loader_budget");
        JsonElement materialBudget = RequireObjectProperty(slotMaterial, "loader_budget");
        if (!JsonSemanticallyEqual(reportBudget, materialBudget))
        {
            throw ProtocolFailure();
        }
    }

    private static void ValidateSlotMaterial(
        JsonElement material,
        string slotName,
        RamInstallBootSlot materials,
        long stockLength,
        string stockHash)
    {
        if (!HasExactObjectProperties(material, SlotMaterialFields))
        {
            throw ProtocolFailure();
        }

        if (!material.TryGetProperty("schemaVersion", out JsonElement schema) ||
            schema.ValueKind != JsonValueKind.Number ||
            !schema.TryGetInt32(out var schemaVersion) ||
            schemaVersion != RamInstallBootConfig.BootSchemaVersion)
        {
            throw ProtocolFailure();
        }

        if (!string.Equals(RequireCatalogString(material, "slot"), slotName, StringComparison.Ordinal))
        {
            throw ProtocolFailure();
        }

        _ = RequireBooleanProperty(material, "is_kshim");

        JsonElement sourceSha = RequireObjectProperty(material, "source_sha256");
        JsonElement sourceLengths = RequireObjectProperty(material, "source_lengths");
        if (!HasExactObjectProperties(sourceSha, SourceRoles) ||
            !HasExactObjectProperties(sourceLengths, SourceRoles))
        {
            throw ProtocolFailure();
        }

        foreach (string role in SourceRoles)
        {
            RamInstallPartitionMaterial descriptor = SelectSourceDescriptor(materials, role);
            if (!string.Equals(
                    RequireLowerHashProperty(sourceSha, role),
                    descriptor.Sha256,
                    StringComparison.Ordinal) ||
                RequirePositiveInt64Property(sourceLengths, role) != descriptor.Length)
            {
                throw ProtocolFailure();
            }
        }

        JsonElement baseImage = RequireObjectProperty(material, "base_image");
        if (!HasExactObjectProperties(baseImage, BaseImageFields))
        {
            throw ProtocolFailure();
        }

        if (RequirePositiveInt64Property(baseImage, "length") != stockLength ||
            !string.Equals(
                RequireLowerHashProperty(baseImage, "sha256"),
                stockHash,
                StringComparison.Ordinal))
        {
            throw ProtocolFailure();
        }

        JsonElement ramdisks = RequireObjectProperty(material, "ramdisks");
        long bootRamdisk;
        long vendorRamdisk;
        long initRamdisk;
        long totalRamdisk;
        long pageSize;
        ValidateRamdisks(ramdisks, out bootRamdisk, out vendorRamdisk, out initRamdisk,
            out totalRamdisk, out pageSize);

        JsonElement budget = RequireObjectProperty(material, "loader_budget");
        ValidateLoaderBudget(budget, materials, totalRamdisk, pageSize);

        if (!RequireFalseProperty(material, "oem_signed_restored") ||
            !RequireStringEquals(material, "recovery_scope", RecoveryScope) ||
            !RequireFalseProperty(material, "signature_verification_performed"))
        {
            throw ProtocolFailure();
        }
    }

    private static void ValidateRamdisks(
        JsonElement ramdisks,
        out long bootRamdisk,
        out long vendorRamdisk,
        out long initRamdisk,
        out long totalRamdisk,
        out long pageSize)
    {
        if (!HasExactObjectProperties(ramdisks, RamdiskFields))
        {
            throw ProtocolFailure();
        }

        bootRamdisk = RequireNonNegativeInt64Property(ramdisks, "boot_ramdisk_size");
        vendorRamdisk = RequireNonNegativeInt64Property(ramdisks, "vendor_ramdisk_size");
        initRamdisk = RequireNonNegativeInt64Property(ramdisks, "init_ramdisk_size");
        totalRamdisk = RequireNonNegativeInt64Property(ramdisks, "total_ramdisk_size");
        pageSize = RequirePositiveInt64Property(ramdisks, "page_size");

        long sum;
        try
        {
            sum = checked(checked(bootRamdisk + vendorRamdisk) + initRamdisk);
        }
        catch (OverflowException)
        {
            throw ProtocolFailure();
        }

        if (sum != totalRamdisk)
        {
            throw ProtocolFailure();
        }
    }

    private static void ValidateLoaderBudget(
        JsonElement budget,
        RamInstallBootSlot materials,
        long totalRamdisk,
        long pageSize)
    {
        if (!HasExactObjectProperties(budget, LoaderBudgetFields))
        {
            throw ProtocolFailure();
        }

        string profile = RequireCatalogString(budget, "profile");
        _ = RequireCatalogString(budget, "evidence");
        _ = RequireCatalogString(budget, "formula");
        long maxRaw = RequirePositiveInt64Property(budget, "max_raw_bytes");
        bool known = RequireBooleanProperty(budget, "known_loader_match");

        if (known)
        {
            // Two reviewed identities: the hash-pinned pair and the structural A/B capture. Both are
            // accepted only at page 4096 under the one checked 256 MiB derivation below.
            if (!(string.Equals(profile, KnownLoaderProfile, StringComparison.Ordinal) ||
                  string.Equals(profile, StructuralLoaderProfile, StringComparison.Ordinal)) ||
                pageSize != KnownLoaderPageSize ||
                maxRaw != KnownLoaderExpectedMaxRaw(totalRamdisk))
            {
                throw ProtocolFailure();
            }
        }
        else
        {
            if (!string.Equals(profile, UnknownLoaderProfile, StringComparison.Ordinal) ||
                maxRaw != UnknownLoaderMaxRawBytes)
            {
                throw ProtocolFailure();
            }
        }

        if (!string.Equals(
                RequireLowerHashProperty(budget, "abl_sha256"),
                materials.Abl.Sha256,
                StringComparison.Ordinal) ||
            !string.Equals(
                RequireLowerHashProperty(budget, "xbl_config_sha256"),
                materials.XblConfig.Sha256,
                StringComparison.Ordinal) ||
            RequirePositiveInt64Property(budget, "abl_bytes") != materials.Abl.Length ||
            RequirePositiveInt64Property(budget, "xbl_config_bytes") != materials.XblConfig.Length ||
            RequireNonNegativeInt64Property(budget, "total_ramdisk_bytes") != totalRamdisk ||
            RequirePositiveInt64Property(budget, "page_size") != pageSize)
        {
            throw ProtocolFailure();
        }
    }

    /// <summary>
    /// The two accepted known profiles (tb322fc/abl259/xbl_config and tb322fc/abl-kernel-region) publish
    /// one exact raw-budget identity, evaluated here in checked Int64:
    /// 268435456 - 524288 - align_up(total_ramdisk, 4096) - 8192 - 2097152.
    /// An unrepresentable total is the same protocol failure as any other mismatch.
    /// </summary>
    private static long KnownLoaderExpectedMaxRaw(long totalRamdisk)
    {
        try
        {
            long alignedRamdisk = checked(totalRamdisk + KnownLoaderPageSize - 1L);
            alignedRamdisk = checked(alignedRamdisk - alignedRamdisk % KnownLoaderPageSize);
            return checked(
                268435456L - 524288L - alignedRamdisk - 8192L - 2097152L);
        }
        catch (OverflowException)
        {
            throw ProtocolFailure();
        }
    }

    private static RamInstallPartitionMaterial SelectSourceDescriptor(
        RamInstallBootSlot slot,
        string role) => role switch
    {
        "current_boot" => slot.CurrentBoot,
        "vendor_boot" => slot.VendorBoot,
        "init_boot" => slot.InitBoot,
        "abl" => slot.Abl,
        "xbl_config" => slot.XblConfig,
        _ => throw ProtocolFailure(),
    };

    private static bool JsonSemanticallyEqual(JsonElement left, JsonElement right)
    {
        try
        {
            JsonNode? leftNode = JsonNode.Parse(left.GetRawText());
            JsonNode? rightNode = JsonNode.Parse(right.GetRawText());
            return leftNode is not null &&
                rightNode is not null &&
                JsonNode.DeepEquals(leftNode, rightNode);
        }
        catch (JsonException)
        {
            throw ProtocolFailure();
        }
    }

    /// <summary>
    /// Validates the read-only inspect source catalog. Every value is measured evidence; no field is
    /// accepted from a caller, no path is returned, and no raw partition content or hash is claimed.
    /// </summary>
    private void ValidateBootSourceCatalog(JsonElement inspectResult, JsonElement catalog)
    {
        RamInstallBootConfig boot = _request.Boot ?? throw ProtocolFailure();

        if (!HasExactObjectProperties(catalog, "parents", "bindings") ||
            !catalog.TryGetProperty("parents", out JsonElement parentsElement) ||
            parentsElement.ValueKind != JsonValueKind.Array ||
            !catalog.TryGetProperty("bindings", out JsonElement bindingsElement) ||
            bindingsElement.ValueKind != JsonValueKind.Array)
        {
            throw ProtocolFailure();
        }

        var parents = new Dictionary<string, CatalogParent>(StringComparer.Ordinal);
        var parentCount = 0;
        foreach (JsonElement element in parentsElement.EnumerateArray())
        {
            parentCount++;
            if (parentCount > 6 || !HasExactObjectProperties(element, CatalogParentFields))
            {
                throw ProtocolFailure();
            }

            CatalogParent parent = ReadCatalogParent(element);
            if (!parents.TryAdd(parent.Device, parent))
            {
                throw ProtocolFailure();
            }
        }

        if (parentCount < 1 || !parents.ContainsKey("/dev/sda"))
        {
            throw ProtocolFailure();
        }

        ValidateSdaParent(parents["/dev/sda"], inspectResult);

        var pairs = new HashSet<string>(StringComparer.Ordinal);
        var partUuids = new HashSet<string>(StringComparer.Ordinal);
        var devices = new HashSet<string>(StringComparer.Ordinal);
        var bindingCount = 0;

        foreach (JsonElement element in bindingsElement.EnumerateArray())
        {
            bindingCount++;
            if (!HasExactObjectProperties(element, CatalogBindingFields))
            {
                throw ProtocolFailure();
            }

            string slotName = RequireCatalogString(element, "slot");
            if (!string.Equals(slotName, "a", StringComparison.Ordinal) &&
                !string.Equals(slotName, "b", StringComparison.Ordinal))
            {
                throw ProtocolFailure();
            }

            string role = RequireCatalogString(element, "role");
            if (Array.IndexOf(CatalogRoles, role) < 0 || !pairs.Add(slotName + "/" + role))
            {
                throw ProtocolFailure();
            }

            RamInstallBootSlot slot = string.Equals(slotName, "a", StringComparison.Ordinal)
                ? boot.Slots.A
                : boot.Slots.B;
            RamInstallPartitionMaterial descriptor = SelectRequestSourceDescriptor(slot, role);

            if (!string.Equals(
                    RequireCatalogString(element, "label"),
                    BootPartitionLabel(slotName, role),
                    StringComparison.Ordinal))
            {
                throw ProtocolFailure();
            }

            string partUuid = RequireUuidProperty(element, "partUuid");
            if (!string.Equals(partUuid, descriptor.PartUuid, StringComparison.Ordinal) ||
                !partUuids.Add(partUuid))
            {
                throw ProtocolFailure();
            }

            if (!RequireFalseProperty(element, "contentRead"))
            {
                throw ProtocolFailure();
            }

            string parentDevice = RequireCatalogString(element, "parentDevice");
            if (!parents.TryGetValue(parentDevice, out CatalogParent parent))
            {
                throw ProtocolFailure();
            }

            if (!string.Equals(
                    RequireCatalogString(element, "parentDeviceId"),
                    parent.DeviceId,
                    StringComparison.Ordinal))
            {
                throw ProtocolFailure();
            }

            int sectorSize;
            if (!element.TryGetProperty("sectorSize", out JsonElement sectorElement) ||
                sectorElement.ValueKind != JsonValueKind.Number ||
                !sectorElement.TryGetInt32(out sectorSize) ||
                sectorSize != parent.SectorSize)
            {
                throw ProtocolFailure();
            }

            long number = RequirePositiveInt64Property(element, "number");
            long startSector = RequireNonNegativeInt64Property(element, "startSector");
            long sectorCount = RequirePositiveInt64Property(element, "sectorCount");
            long length = RequirePositiveInt64Property(element, "length");

            if (length != descriptor.Length)
            {
                throw ProtocolFailure();
            }

            long computedLength;
            long endSector;
            long parentSectors;
            try
            {
                computedLength = checked(sectorCount * sectorSize);
                endSector = checked(startSector + sectorCount);
                parentSectors = parent.DiskBytes / parent.SectorSize;
            }
            catch (OverflowException)
            {
                throw ProtocolFailure();
            }

            if (computedLength != length ||
                startSector >= parentSectors ||
                endSector > parentSectors)
            {
                throw ProtocolFailure();
            }

            string device = RequireCatalogString(element, "device");
            if (!string.Equals(
                    device,
                    parent.Device + number.ToString(CultureInfo.InvariantCulture),
                    StringComparison.Ordinal) ||
                !devices.Add(device))
            {
                throw ProtocolFailure();
            }

            string deviceId = RequireCatalogString(element, "deviceId");
            if (!IsCanonicalDeviceId(deviceId) ||
                string.Equals(deviceId, parent.DeviceId, StringComparison.Ordinal))
            {
                throw ProtocolFailure();
            }

            if (string.Equals(parent.Device, "/dev/sda", StringComparison.Ordinal))
            {
                ExpectedPartition? row = FindExpectedPartition(number);
                if (row is null ||
                    !string.Equals(row.PartUuid, partUuid, StringComparison.Ordinal) ||
                    !string.Equals(row.Name, RequireCatalogString(element, "label"), StringComparison.Ordinal) ||
                    row.StartSector != startSector ||
                    row.SectorCount != sectorCount)
                {
                    throw ProtocolFailure();
                }
            }
        }

        if (bindingCount != 10 || pairs.Count != 10)
        {
            throw ProtocolFailure();
        }

        BootSourceCatalog = catalog.Clone();
    }

    private ExpectedPartition? FindExpectedPartition(long number)
    {
        foreach (ExpectedPartition partition in _request.ExpectedTable.Partitions)
        {
            if (partition.Number == number)
            {
                return partition;
            }
        }

        return null;
    }

    private static RamInstallPartitionMaterial SelectRequestSourceDescriptor(
        RamInstallBootSlot slot,
        string role) => role switch
    {
        "currentBoot" => slot.CurrentBoot,
        "vendorBoot" => slot.VendorBoot,
        "initBoot" => slot.InitBoot,
        "abl" => slot.Abl,
        "xblConfig" => slot.XblConfig,
        _ => throw ProtocolFailure(),
    };

    private static string BootPartitionLabel(string slotName, string role) => role switch
    {
        "currentBoot" => "boot_" + slotName,
        "vendorBoot" => "vendor_boot_" + slotName,
        "initBoot" => "init_boot_" + slotName,
        "abl" => "abl_" + slotName,
        "xblConfig" => "xbl_config_" + slotName,
        _ => throw ProtocolFailure(),
    };

    private readonly struct CatalogParent
    {
        public CatalogParent(
            string device,
            string deviceId,
            int sectorSize,
            long diskBytes,
            string sysfsDevice,
            string linuxTableFingerprint)
        {
            Device = device;
            DeviceId = deviceId;
            SectorSize = sectorSize;
            DiskBytes = diskBytes;
            SysfsDevice = sysfsDevice;
            LinuxTableFingerprint = linuxTableFingerprint;
        }

        public string Device { get; }

        public string DeviceId { get; }

        public int SectorSize { get; }

        public long DiskBytes { get; }

        public string SysfsDevice { get; }

        public string LinuxTableFingerprint { get; }
    }

    private static CatalogParent ReadCatalogParent(JsonElement element)
    {
        string device = RequireCatalogString(element, "device");
        if (!IsFixedParentDevice(device))
        {
            throw ProtocolFailure();
        }

        string deviceId = RequireCatalogString(element, "deviceId");
        if (!IsCanonicalDeviceId(deviceId))
        {
            throw ProtocolFailure();
        }

        if (!element.TryGetProperty("sectorSize", out JsonElement sectorElement) ||
            sectorElement.ValueKind != JsonValueKind.Number ||
            !sectorElement.TryGetInt32(out var sectorSize) ||
            (sectorSize != 512 && sectorSize != 4096))
        {
            throw ProtocolFailure();
        }

        long diskBytes = RequirePositiveInt64Property(element, "diskBytes");
        if (diskBytes % sectorSize != 0)
        {
            throw ProtocolFailure();
        }

        string sysfsDevice = RequireCatalogString(element, "sysfsDevice");
        if (!sysfsDevice.StartsWith("/sys/devices/", StringComparison.Ordinal) ||
            sysfsDevice.StartsWith("/sys/devices/virtual/", StringComparison.Ordinal) ||
            sysfsDevice.Contains("..", StringComparison.Ordinal))
        {
            throw ProtocolFailure();
        }

        return new CatalogParent(
            device,
            deviceId,
            sectorSize,
            diskBytes,
            sysfsDevice,
            RequireLowerHashProperty(element, "linuxTableFingerprint"));
    }

    private void ValidateSdaParent(CatalogParent parent, JsonElement inspectResult)
    {
        if (parent.SectorSize != _request.ExpectedTable.SectorSize ||
            parent.DiskBytes != _request.ExpectedTable.DiskBytes ||
            parent.SectorSize != RequireInt32Property(inspectResult, "sectorSize") ||
            parent.DiskBytes != RequireInt64Property(inspectResult, "diskBytes") ||
            !string.Equals(
                parent.LinuxTableFingerprint,
                RequireLowerHashProperty(inspectResult, "linuxTableFingerprint"),
                StringComparison.Ordinal))
        {
            throw ProtocolFailure();
        }
    }

    private static int RequireInt32Property(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out JsonElement value) ||
            value.ValueKind != JsonValueKind.Number ||
            !value.TryGetInt32(out var result))
        {
            throw ProtocolFailure();
        }

        return result;
    }

    private static long RequireInt64Property(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out JsonElement value) ||
            value.ValueKind != JsonValueKind.Number ||
            !value.TryGetInt64(out var result))
        {
            throw ProtocolFailure();
        }

        return result;
    }

    private static bool IsFixedParentDevice(string value)
    {
        return string.Equals(value, "/dev/sda", StringComparison.Ordinal) ||
            string.Equals(value, "/dev/sdb", StringComparison.Ordinal) ||
            string.Equals(value, "/dev/sdc", StringComparison.Ordinal) ||
            string.Equals(value, "/dev/sdd", StringComparison.Ordinal) ||
            string.Equals(value, "/dev/sde", StringComparison.Ordinal) ||
            string.Equals(value, "/dev/sdf", StringComparison.Ordinal);
    }

    private static bool IsCanonicalDeviceId(string value)
    {
        int separator = value.IndexOf(':', StringComparison.Ordinal);
        if (separator <= 0 ||
            separator == value.Length - 1 ||
            value.IndexOf(':', separator + 1) >= 0)
        {
            return false;
        }

        return IsCanonicalDecimal(value[..separator]) &&
            IsCanonicalDecimal(value[(separator + 1)..]);
    }

    private static bool IsCanonicalDecimal(string value)
    {
        if (value.Length == 0 || value.Length > 20 || (value.Length > 1 && value[0] == '0'))
        {
            return false;
        }

        foreach (char character in value)
        {
            if (character < '0' || character > '9')
            {
                return false;
            }
        }

        return true;
    }

    private static string RequireCatalogString(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out JsonElement value) ||
            value.ValueKind != JsonValueKind.String ||
            string.IsNullOrEmpty(value.GetString()))
        {
            throw ProtocolFailure();
        }

        return value.GetString()!;
    }

    private static JsonElement RequireObjectProperty(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out JsonElement value) ||
            value.ValueKind != JsonValueKind.Object)
        {
            throw ProtocolFailure();
        }

        return value;
    }

    private static long RequirePositiveInt64Property(JsonElement parent, string name)
    {
        long value = RequireInt64Property(parent, name);
        if (value <= 0)
        {
            throw ProtocolFailure();
        }

        return value;
    }

    private static long RequireNonNegativeInt64Property(JsonElement parent, string name)
    {
        long value = RequireInt64Property(parent, name);
        if (value < 0)
        {
            throw ProtocolFailure();
        }

        return value;
    }

    private static bool RequireBooleanProperty(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out JsonElement value) ||
            (value.ValueKind != JsonValueKind.True && value.ValueKind != JsonValueKind.False))
        {
            throw ProtocolFailure();
        }

        return value.ValueKind == JsonValueKind.True;
    }

    private static bool RequireTrueProperty(JsonElement parent, string name)
    {
        return RequireBooleanProperty(parent, name);
    }

    private static bool RequireFalseProperty(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out JsonElement value) ||
            value.ValueKind != JsonValueKind.False)
        {
            throw ProtocolFailure();
        }

        return true;
    }

    private static bool RequireStringEquals(JsonElement parent, string name, string expected)
    {
        return string.Equals(
            RequireCatalogString(parent, name),
            expected,
            StringComparison.Ordinal);
    }

    private static string RequireLowerHashProperty(JsonElement parent, string name)
    {
        string value = RequireCatalogString(parent, name);
        if (!RamInstallValidation.IsLowerSha256(value))
        {
            throw ProtocolFailure();
        }

        return value;
    }

    private static string RequireUuidProperty(JsonElement parent, string name)
    {
        string value = RequireCatalogString(parent, name);
        try
        {
            return RamInstallValidation.NormalizeUuid(value, name);
        }
        catch (ArgumentException)
        {
            throw ProtocolFailure();
        }
    }

    private static bool HasExactObjectProperties(JsonElement element, params string[] names)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonProperty property in element.EnumerateObject())
        {
            if (!seen.Add(property.Name))
            {
                return false;
            }
        }

        if (seen.Count != names.Length)
        {
            return false;
        }

        foreach (string name in names)
        {
            if (!seen.Contains(name))
            {
                return false;
            }
        }

        return true;
    }
}
