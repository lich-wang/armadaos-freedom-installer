using System.Globalization;
using System.Numerics;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace FreedomInstaller.Core;

public sealed partial class UpdatePackageDescriptor
{
    private const long MaxFileBytes = 1024L * 1024L * 1024L * 1024L;
    private const long MaxPartBytes = (2L * 1024L * 1024L * 1024L) - 1L;
    private const long MaxArchiveBytes = long.MaxValue;

    private static readonly HashSet<string> SupportedModelsSet = new(StringComparer.Ordinal)
    {
        "TB322FC",
        "TB323FU",
        "TB710FU",
    };

    // Models whose installed systems have the native dual-slot backend the offline upgrade drives. It follows
    // Freedom's capability table (system_files/usr/lib/armada/updates/models.py, OFFLINE_UPGRADE_MODELS): TB710FU
    // joined it with the native kShim UFS settings and the mirrored boot_a/boot_b updater.
    private static readonly HashSet<string> OfflineUpgradeModelsSet = new(StringComparer.Ordinal)
    {
        "TB322FC",
        "TB323FU",
        "TB710FU",
    };

    /// <summary>
    /// True when <paramref name="model"/> (canonical, case-insensitive) may take an offline upgrade. The single
    /// list the descriptor gate, the transfer adapter and both installer windows use.
    /// </summary>
    public static bool SupportsOfflineUpgrade(string? model) =>
        !string.IsNullOrEmpty(model) && OfflineUpgradeModelsSet.Contains(model.ToUpperInvariant());

    private static readonly HashSet<string> OperationsSet = new(StringComparer.Ordinal)
    {
        "install",
        "offline-upgrade",
        "decky-repair",
    };

    private static readonly HashSet<string> RolesSet = new(StringComparer.Ordinal)
    {
        "manifest",
        "linux-root",
        "linux-boot",
        "kernel",
        "initramfs",
        "runtime",
        "dtb-normal",
        "dtb-diagnostic",
        "recovery",
        "metadata",
    };

    private static readonly HashSet<string> TopKeysSet = new(StringComparer.Ordinal)
    {
        "schemaVersion",
        "kind",
        "product",
        "architecture",
        "releaseId",
        "version",
        "sourceRevision",
        "ociDigest",
        "ostreeCommit",
        "minimumInstallerVersion",
        "minimumUpdaterVersion",
        "supportedModels",
        "operations",
        "archive",
        "parts",
        "files",
        "modelManifests",
        "recoveryManifests",
        "deckySnapshot",
    };

    private static readonly HashSet<string> ArchiveKeysSet = new(StringComparer.Ordinal)
    {
        "fileName",
        "bytes",
        "sha256",
    };

    private static readonly HashSet<string> FileKeysSet = new(StringComparer.Ordinal)
    {
        "path",
        "bytes",
        "sha256",
        "expandedBytes",
        "expandedSha256",
        "compression",
        "role",
    };

    private static readonly HashSet<string> DeckyKeysSet = new(StringComparer.Ordinal)
    {
        "releaseId",
        "tag",
        "publishedAt",
        "assetId",
        "url",
        "size",
        "sha256",
    };

    private static readonly HashSet<string> ExcludedIdentitiesSet = new(StringComparer.Ordinal)
    {
        "latest",
        "stable",
        "beta",
        "testing",
    };

    private static readonly HashSet<string> ReservedWindowsNamesSet = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };

    private readonly HashSet<string> _supportedModels;
    private readonly HashSet<string> _operations;
    private readonly VersionTuple _minimumInstallerVersion;

    private UpdatePackageDescriptor(
        JsonElement validatedRoot,
        string releaseId,
        string version,
        HashSet<string> supportedModels,
        HashSet<string> operations,
        VersionTuple minimumInstallerVersion)
    {
        Root = validatedRoot.Clone();
        ReleaseId = releaseId;
        Version = version;
        _supportedModels = supportedModels;
        _operations = operations;
        _minimumInstallerVersion = minimumInstallerVersion;
    }

    public JsonElement Root { get; }

    public string ReleaseId { get; }

    public string Version { get; }

    public static UpdatePackageDescriptor VerifyAndParse(byte[] document, byte[] signatureBase64)
    {
        using JsonDocument jsonDocument = UpdateSignatureVerifier.VerifyAndParse(document, signatureBase64);
        return ParseVerifiedRoot(jsonDocument.RootElement);
    }

    private static readonly HashSet<string> TopKeysWithBootCapsules = new(TopKeysSet, StringComparer.Ordinal)
    {
        "armadaBootCapsules",
    };

    private static readonly HashSet<string> BootCapsuleKeys = new(StringComparer.Ordinal)
    {
        "board.dtb",
        "manifest.bin",
        "manifest.sig",
    };

    internal static UpdatePackageDescriptor ParseVerifiedRoot(JsonElement root)
    {
        EnsureNoDuplicatePropertiesRecursive(root);

        Dictionary<string, JsonElement> data = RequireExactObject(
            root,
            root.ValueKind == JsonValueKind.Object && root.TryGetProperty("armadaBootCapsules", out _)
                ? TopKeysWithBootCapsules : TopKeysSet,
            "package must contain exactly the schema 1 top-level keys");

        if (!TryGetExactInt64(data["schemaVersion"], out long schemaVersion) || schemaVersion != 1)
        {
            throw new InvalidDataException("schemaVersion must be integer 1");
        }

        if (!IsExactString(data["kind"], "freedom-universal-package")
            || !IsExactString(data["product"], "armadaos-freedom")
            || !IsExactString(data["architecture"], "aarch64"))
        {
            throw new InvalidDataException("package kind, product, or architecture is invalid");
        }

        string releaseId = ValidateIdentity(data["releaseId"], "releaseId");
        string version = ValidateIdentity(data["version"], "version");

        if (data["sourceRevision"].ValueKind != JsonValueKind.String
            || data["sourceRevision"].GetString() is not string sourceRevision
            || !Hex40Regex().IsMatch(sourceRevision))
        {
            throw new InvalidDataException("sourceRevision must be 40 lowercase hexadecimal characters");
        }

        if (data["ociDigest"].ValueKind != JsonValueKind.String
            || data["ociDigest"].GetString() is not string ociDigest
            || !ociDigest.StartsWith("sha256:", StringComparison.Ordinal)
            || !Hex64Regex().IsMatch(ociDigest.AsSpan(7)))
        {
            throw new InvalidDataException("ociDigest must be sha256 followed by 64 lowercase hexadecimal characters");
        }

        ValidateHash(data["ostreeCommit"], "ostreeCommit");
        VersionTuple minimumInstallerVersion = ValidateVersionTuple(data["minimumInstallerVersion"], "minimumInstallerVersion");
        _ = ValidateVersionTuple(data["minimumUpdaterVersion"], "minimumUpdaterVersion");

        HashSet<string> supportedModels = ValidateStringSet(data["supportedModels"], SupportedModelsSet, "supportedModels");
        HashSet<string> operations = ValidateStringSet(data["operations"], OperationsSet, "operations");

        (string archiveFileName, BigInteger archiveBytes) = ValidateArchiveMember(data["archive"], "archive", MaxArchiveBytes);
        if (!archiveFileName.EndsWith(".zip", StringComparison.Ordinal))
        {
            throw new InvalidDataException("archive.fileName must end in .zip");
        }

        JsonElement partsElement = data["parts"];
        if (partsElement.ValueKind != JsonValueKind.Array || partsElement.GetArrayLength() > 999)
        {
            throw new InvalidDataException("parts must be empty or contain 1 through 999 entries");
        }

        int partCount = partsElement.GetArrayLength();
        BigInteger partsSum = BigInteger.Zero;
        int partIndex = 0;
        foreach (JsonElement partElement in partsElement.EnumerateArray())
        {
            string field = $"parts[{partIndex}]";
            (string partFileName, BigInteger partBytes) = ValidateArchiveMember(partElement, field, MaxPartBytes);
            string expectedFileName = string.Create(CultureInfo.InvariantCulture, $"{archiveFileName}.{partIndex + 1:D3}");
            if (!string.Equals(partFileName, expectedFileName, StringComparison.Ordinal))
            {
                throw new InvalidDataException($"{field}.fileName must be {expectedFileName}");
            }

            partsSum += partBytes;
            partIndex++;
        }

        if (partCount > 0 && partsSum != archiveBytes)
        {
            throw new InvalidDataException("part sizes must sum exactly to archive.bytes");
        }

        JsonElement filesElement = data["files"];
        if (filesElement.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("files must contain 1 through 10000 records");
        }

        int fileCount = filesElement.GetArrayLength();
        if (fileCount < 1 || fileCount > 10000)
        {
            throw new InvalidDataException("files must contain 1 through 10000 records");
        }

        Dictionary<string, FileRecord> filesByPath = new(fileCount, StringComparer.Ordinal);
        HashSet<string> foldedPaths = new(fileCount, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, int> roleCounts = new(StringComparer.Ordinal);

        int fileIndex = 0;
        foreach (JsonElement recordElement in filesElement.EnumerateArray())
        {
            Dictionary<string, JsonElement> record = RequireExactObject(
                recordElement,
                FileKeysSet,
                $"files[{fileIndex}] has invalid fields");

            string path = ValidatePortablePath(record["path"], $"files[{fileIndex}].path");
            if (!foldedPaths.Add(path))
            {
                throw new InvalidDataException("file paths must be unique case-insensitively");
            }

            BigInteger bytes = ValidatePositiveInt(record["bytes"], $"{path}.bytes", MaxFileBytes);
            BigInteger expandedBytes = ValidatePositiveInt(record["expandedBytes"], $"{path}.expandedBytes", MaxFileBytes);
            string sha256 = ValidateHash(record["sha256"], $"{path}.sha256");
            string expandedSha256 = ValidateHash(record["expandedSha256"], $"{path}.expandedSha256");

            if (record["compression"].ValueKind != JsonValueKind.String
                || record["compression"].GetString() is not string compression
                || (compression != "none" && compression != "gzip"))
            {
                throw new InvalidDataException($"{path}.compression must be none or gzip");
            }

            if (compression == "none"
                && (bytes != expandedBytes || !string.Equals(sha256, expandedSha256, StringComparison.Ordinal)))
            {
                throw new InvalidDataException($"{path} uncompressed size and digest must match");
            }

            if (record["role"].ValueKind != JsonValueKind.String
                || record["role"].GetString() is not string role
                || !RolesSet.Contains(role))
            {
                throw new InvalidDataException($"{path} has an unsupported role");
            }

            filesByPath.Add(path, new FileRecord(role, compression));
            roleCounts[role] = roleCounts.GetValueOrDefault(role) + 1;
            fileIndex++;
        }

        foreach (string path in filesByPath.Keys)
        {
            int slashIndex = path.IndexOf('/', StringComparison.Ordinal);
            while (slashIndex > 0)
            {
                string prefix = path[..slashIndex];
                if (foldedPaths.Contains(prefix))
                {
                    throw new InvalidDataException("file paths must not collide with parent files");
                }

                slashIndex = path.IndexOf('/', slashIndex + 1);
            }
        }

        if (roleCounts.GetValueOrDefault("linux-root") != 1 || roleCounts.GetValueOrDefault("linux-boot") != 1)
        {
            throw new InvalidDataException("exactly one linux-root and one linux-boot record are required");
        }

        if (!filesByPath.TryGetValue("bundle.json", out FileRecord bundleRecord)
            || !string.Equals(bundleRecord.Role, "manifest", StringComparison.Ordinal))
        {
            throw new InvalidDataException("bundle.json must be an indexed manifest");
        }

        ValidateManifestPaths(
            supportedModels,
            data["modelManifests"],
            data["recoveryManifests"],
            filesByPath);

        if (operations.Contains("offline-upgrade"))
        {
            foreach (FileRecord record in filesByPath.Values)
            {
                if ((record.Role == "linux-root" || record.Role == "linux-boot") && record.Compression != "gzip")
                {
                    throw new InvalidDataException("offline-upgrade requires gzip root and boot images");
                }
            }
        }

        if (data.TryGetValue("armadaBootCapsules", out JsonElement bootCapsules))
        {
            ValidateArmadaBootCapsules(bootCapsules, supportedModels);
        }

        ValidateDeckySnapshot(data["deckySnapshot"]);
        if (operations.Contains("decky-repair") && data["deckySnapshot"].ValueKind == JsonValueKind.Null)
        {
            throw new InvalidDataException("decky-repair requires deckySnapshot metadata");
        }

        return new UpdatePackageDescriptor(
            root,
            releaseId,
            version,
            supportedModels,
            operations,
            minimumInstallerVersion);
    }

    public void RequireOperation(string model, string operation, string installerVersion)
    {
        if (model is null || !_supportedModels.Contains(model))
        {
            throw new InvalidDataException("model is not supported by this package");
        }

        if (operation is null || !_operations.Contains(operation))
        {
            throw new InvalidDataException("operation is not declared by this package");
        }

        if (string.Equals(operation, "offline-upgrade", StringComparison.Ordinal)
            && !OfflineUpgradeModelsSet.Contains(model))
        {
            throw new InvalidDataException("offline-upgrade is not supported for this model");
        }

        if (installerVersion is null)
        {
            throw new InvalidDataException("at least one installer or updater version is required");
        }

        VersionTuple callerVersion = ParseVersionTupleString(installerVersion, "installer_version");
        if (callerVersion.CompareTo(_minimumInstallerVersion) < 0)
        {
            throw new InvalidDataException("version is older than minimumInstallerVersion");
        }
    }

    private static void ValidateArmadaBootCapsules(JsonElement element, HashSet<string> supportedModels)
    {
        if (element.ValueKind != JsonValueKind.Object || !element.EnumerateObject().Any())
        {
            throw new InvalidDataException("armadaBootCapsules must be a nonempty object");
        }

        foreach (JsonProperty property in element.EnumerateObject())
        {
            if ((property.Name is not "TB322FC" and not "TB323FU") || !supportedModels.Contains(property.Name))
            {
                throw new InvalidDataException($"invalid boot capsule model {property.Name}");
            }

            string field = $"armadaBootCapsules.{property.Name}";
            Dictionary<string, JsonElement> capsule = RequireExactObject(
                property.Value, BootCapsuleKeys,
                $"{field} must contain exactly board.dtb, manifest.bin, and manifest.sig");
            ValidateCapsuleBase64(capsule["board.dtb"], $"{field}.board.dtb", 1, 256 * 1024);
            ValidateCapsuleBase64(capsule["manifest.bin"], $"{field}.manifest.bin", 160, 160);
            ValidateCapsuleBase64(capsule["manifest.sig"], $"{field}.manifest.sig", 8, 72);
        }
    }

    private static void ValidateCapsuleBase64(JsonElement element, string field, int minimum, int maximum)
    {
        string error = $"{field} must be canonical base64 encoding {minimum} to {maximum} bytes";
        if (element.ValueKind != JsonValueKind.String || element.GetString() is not string value
            || value.Length > ((maximum + 2) / 3) * 4)
        {
            throw new InvalidDataException(error);
        }

        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(value);
        }
        catch (FormatException ex)
        {
            throw new InvalidDataException(error, ex);
        }

        if (decoded.Length < minimum || decoded.Length > maximum || Convert.ToBase64String(decoded) != value)
        {
            throw new InvalidDataException(error);
        }
    }

    private static void EnsureNoDuplicatePropertiesRecursive(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
            {
                HashSet<string> keys = new(StringComparer.Ordinal);
                foreach (JsonProperty prop in element.EnumerateObject())
                {
                    if (!keys.Add(prop.Name))
                    {
                        throw new InvalidDataException($"duplicate JSON property: {prop.Name}");
                    }

                    EnsureNoDuplicatePropertiesRecursive(prop.Value);
                }

                break;
            }
            case JsonValueKind.Array:
            {
                foreach (JsonElement item in element.EnumerateArray())
                {
                    EnsureNoDuplicatePropertiesRecursive(item);
                }

                break;
            }
            case JsonValueKind.Undefined:
                throw new InvalidDataException("JSON element cannot be undefined");
        }
    }

    private static Dictionary<string, JsonElement> RequireExactObject(
        JsonElement element,
        HashSet<string> expectedKeys,
        string errorMessage)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(errorMessage);
        }

        Dictionary<string, JsonElement> map = new(expectedKeys.Count, StringComparer.Ordinal);
        foreach (JsonProperty prop in element.EnumerateObject())
        {
            if (!expectedKeys.Contains(prop.Name) || !map.TryAdd(prop.Name, prop.Value))
            {
                throw new InvalidDataException(errorMessage);
            }
        }

        if (map.Count != expectedKeys.Count)
        {
            throw new InvalidDataException(errorMessage);
        }

        return map;
    }

    private static bool IsExactString(JsonElement element, string expected) =>
        element.ValueKind == JsonValueKind.String
        && string.Equals(element.GetString(), expected, StringComparison.Ordinal);

    private static string ValidateIdentity(JsonElement element, string field)
    {
        if (element.ValueKind != JsonValueKind.String
            || element.GetString() is not string value
            || !IdentityRegex().IsMatch(value)
            || ExcludedIdentitiesSet.Contains(value))
        {
            throw new InvalidDataException($"{field} is not a valid canonical identifier");
        }

        return value;
    }

    private static VersionTuple ValidateVersionTuple(JsonElement element, string field)
    {
        if (element.ValueKind != JsonValueKind.String || element.GetString() is not string value)
        {
            throw new InvalidDataException($"{field} must be a canonical X.Y.Z version string");
        }

        return ParseVersionTupleString(value, field);
    }

    private static VersionTuple ParseVersionTupleString(string value, string field)
    {
        if (!VersionRegex().IsMatch(value))
        {
            throw new InvalidDataException($"{field} must be a canonical X.Y.Z version string");
        }

        string[] parts = value.Split('.', StringSplitOptions.None);
        return new VersionTuple(
            BigInteger.Parse(parts[0], CultureInfo.InvariantCulture),
            BigInteger.Parse(parts[1], CultureInfo.InvariantCulture),
            BigInteger.Parse(parts[2], CultureInfo.InvariantCulture));
    }

    private static HashSet<string> ValidateStringSet(
        JsonElement element,
        HashSet<string> allowed,
        string field)
    {
        if (element.ValueKind != JsonValueKind.Array || element.GetArrayLength() == 0)
        {
            throw new InvalidDataException($"{field} must be a nonempty list of supported values");
        }

        List<string> values = new(element.GetArrayLength());
        foreach (JsonElement item in element.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String
                || item.GetString() is not string str
                || !allowed.Contains(str))
            {
                throw new InvalidDataException($"{field} must be a nonempty list of supported values");
            }

            values.Add(str);
        }

        HashSet<string> unique = new(values, StringComparer.Ordinal);
        if (unique.Count != values.Count)
        {
            throw new InvalidDataException($"{field} must not contain duplicates");
        }

        return unique;
    }

    private static (string FileName, BigInteger Bytes) ValidateArchiveMember(
        JsonElement element,
        string field,
        long? maximum)
    {
        Dictionary<string, JsonElement> member = RequireExactObject(
            element,
            ArchiveKeysSet,
            $"{field} must contain exactly fileName, bytes, and sha256");

        string name = ValidatePortablePath(member["fileName"], $"{field}.fileName");
        if (name.Contains('/', StringComparison.Ordinal))
        {
            throw new InvalidDataException($"{field}.fileName must be a nonempty basename");
        }

        BigInteger bytes = ValidatePositiveInt(member["bytes"], $"{field}.bytes", maximum);
        _ = ValidateHash(member["sha256"], $"{field}.sha256");
        return (name, bytes);
    }

    private static string ValidatePortablePath(JsonElement element, string field)
    {
        if (element.ValueKind != JsonValueKind.String
            || element.GetString() is not string value
            || value.Length == 0
            || value.Length > 1024)
        {
            throw new InvalidDataException($"{field} must be a nonempty path of at most 1024 characters");
        }

        if (value.StartsWith('/'))
        {
            throw new InvalidDataException($"{field} contains a forbidden path character");
        }

        foreach (char ch in value)
        {
            if (ch < 32 || ch == 127 || ch is '\\' or ':' or '<' or '>' or '"' or '|' or '?' or '*')
            {
                throw new InvalidDataException($"{field} contains a forbidden path character");
            }
        }

        string[] components = value.Split('/', StringSplitOptions.None);
        foreach (string component in components)
        {
            if (component is "" or "." or ".."
                || component.EndsWith('.')
                || component.EndsWith(' '))
            {
                throw new InvalidDataException($"{field} contains a nonportable path component");
            }

            int dotIndex = component.IndexOf('.', StringComparison.Ordinal);
            string stem = dotIndex >= 0 ? component[..dotIndex] : component;
            if (ReservedWindowsNamesSet.Contains(stem))
            {
                throw new InvalidDataException($"{field} contains a reserved Windows basename");
            }
        }

        return value;
    }

    private static void ValidateManifestPaths(
        HashSet<string> supportedModels,
        JsonElement modelManifestsElement,
        JsonElement recoveryManifestsElement,
        Dictionary<string, FileRecord> filesByPath)
    {
        Dictionary<string, JsonElement> manifests = RequireExactObject(
            modelManifestsElement,
            supportedModels,
            "modelManifests must have exactly the supportedModels keys");

        if (recoveryManifestsElement.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("recoveryManifests must be an object keyed by a subset of supportedModels");
        }

        Dictionary<string, JsonElement> recovery = new(StringComparer.Ordinal);
        foreach (JsonProperty prop in recoveryManifestsElement.EnumerateObject())
        {
            if (!supportedModels.Contains(prop.Name) || !recovery.TryAdd(prop.Name, prop.Value))
            {
                throw new InvalidDataException("recoveryManifests must be an object keyed by a subset of supportedModels");
            }
        }

        HashSet<string> modelPathsSet = ValidateManifestGroup("modelManifests", manifests, filesByPath);
        HashSet<string> recoveryPathsSet = ValidateManifestGroup("recoveryManifests", recovery, filesByPath);

        if (modelPathsSet.Overlaps(recoveryPathsSet))
        {
            throw new InvalidDataException("model and recovery manifest paths must be distinct");
        }
    }

    private static HashSet<string> ValidateManifestGroup(
        string field,
        Dictionary<string, JsonElement> group,
        Dictionary<string, FileRecord> filesByPath)
    {
        List<string> paths = new(group.Count);
        foreach ((string model, JsonElement pathElement) in group)
        {
            if (pathElement.ValueKind != JsonValueKind.String
                || pathElement.GetString() is not string path
                || !filesByPath.TryGetValue(path, out FileRecord record))
            {
                throw new InvalidDataException($"{field}.{model} must reference an indexed file");
            }

            if (!string.Equals(record.Role, "manifest", StringComparison.Ordinal))
            {
                throw new InvalidDataException($"{field}.{model} must reference a manifest file");
            }

            paths.Add(path);
        }

        HashSet<string> uniquePaths = new(paths, StringComparer.Ordinal);
        if (uniquePaths.Count != paths.Count)
        {
            throw new InvalidDataException($"{field} paths must be distinct");
        }

        return uniquePaths;
    }

    private static void ValidateDeckySnapshot(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Null)
        {
            return;
        }

        Dictionary<string, JsonElement> snapshot = RequireExactObject(
            element,
            DeckyKeysSet,
            "deckySnapshot must be null or contain exactly the snapshot fields");

        _ = ValidatePositiveInt(snapshot["releaseId"], "deckySnapshot.releaseId", null);
        _ = ValidatePositiveInt(snapshot["assetId"], "deckySnapshot.assetId", null);
        _ = ValidatePositiveInt(snapshot["size"], "deckySnapshot.size", null);

        foreach (string field in new[] { "tag", "publishedAt", "url" })
        {
            if (snapshot[field].ValueKind != JsonValueKind.String
                || string.IsNullOrEmpty(snapshot[field].GetString()))
            {
                throw new InvalidDataException($"deckySnapshot.{field} must be a nonempty string");
            }
        }

        _ = ValidateHash(snapshot["sha256"], "deckySnapshot.sha256");
    }

    private static BigInteger ValidatePositiveInt(JsonElement element, string field, long? maximum)
    {
        string limit = maximum.HasValue
            ? string.Create(CultureInfo.InvariantCulture, $" and at most {maximum.Value}")
            : string.Empty;

        if (!TryGetExactBigInteger(element, out BigInteger value)
            || value <= BigInteger.Zero
            || (maximum.HasValue && value > maximum.Value))
        {
            throw new InvalidDataException($"{field} must be a positive integer{limit}");
        }

        return value;
    }

    private static bool TryGetExactInt64(JsonElement element, out long value)
    {
        value = 0;
        if (!TryGetExactBigInteger(element, out BigInteger bigValue)
            || bigValue < long.MinValue
            || bigValue > long.MaxValue)
        {
            return false;
        }

        value = (long)bigValue;
        return true;
    }

    private static bool TryGetExactBigInteger(JsonElement element, out BigInteger value)
    {
        value = BigInteger.Zero;
        if (element.ValueKind != JsonValueKind.Number)
        {
            return false;
        }

        string raw = element.GetRawText();
        if (string.IsNullOrEmpty(raw))
        {
            return false;
        }

        int start = raw[0] == '-' ? 1 : 0;
        if (start == raw.Length)
        {
            return false;
        }

        for (int i = start; i < raw.Length; i++)
        {
            if (!char.IsAsciiDigit(raw[i]))
            {
                return false;
            }
        }

        return BigInteger.TryParse(raw, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out value);
    }

    private static string ValidateHash(JsonElement element, string field)
    {
        if (element.ValueKind != JsonValueKind.String
            || element.GetString() is not string value
            || !Hex64Regex().IsMatch(value))
        {
            throw new InvalidDataException($"{field} must be 64 lowercase hexadecimal characters");
        }

        return value;
    }

    [GeneratedRegex(@"\A[0-9a-f]{40}\z", RegexOptions.CultureInvariant)]
    private static partial Regex Hex40Regex();

    [GeneratedRegex(@"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant)]
    private static partial Regex Hex64Regex();

    [GeneratedRegex(@"\A[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\z", RegexOptions.CultureInvariant)]
    private static partial Regex IdentityRegex();

    [GeneratedRegex(@"\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\z", RegexOptions.CultureInvariant)]
    private static partial Regex VersionRegex();

    private readonly record struct FileRecord(string Role, string Compression);

    private readonly record struct VersionTuple(BigInteger Major, BigInteger Minor, BigInteger Patch)
        : IComparable<VersionTuple>
    {
        public int CompareTo(VersionTuple other)
        {
            int cmp = Major.CompareTo(other.Major);
            if (cmp != 0)
            {
                return cmp;
            }

            cmp = Minor.CompareTo(other.Minor);
            if (cmp != 0)
            {
                return cmp;
            }

            return Patch.CompareTo(other.Patch);
        }
    }
}
