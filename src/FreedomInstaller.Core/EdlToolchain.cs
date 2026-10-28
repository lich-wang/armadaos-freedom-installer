using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core
{
    /// <summary>
    /// Staged, fully verified EDL toolchain. The loader owns exactly one fresh
    /// edl-toolchain-GUID directory beneath the caller's explicit work root. It never
    /// launches processes, touches devices, downloads anything or modifies its source archive.
    /// </summary>
    public sealed class EdlToolchain : IDisposable
    {
        private const int BufferSize = 81920;

        private const int UnixTypeDirectory = 0x4000;
        private const int UnixTypeRegular = 0x8000;
        private const int UnixTypeSymlink = 0xA000;

        private const string ManifestEntryName = "manifest.json";
        private const string StagingDirectoryPrefix = "edl-toolchain-";
        private const string PythonRuntimeDirectoryName = "runtime";
        private const string PythonExecutableName = "python.exe";
        private const string PythonArchiveName = "python314.zip";
        private const string PythonPathFileName = "python314._pth";
        private const string PythonPathContents = "python314.zip\n.\n../scripts\n";

        // Roles common to every trusted profile, with their reviewed paths and fixed pins. The loader
        // payloads (one for G4, nine for G5) are never listed here: they come from the selected profile.
        private static readonly string[] CommonRoleOrder =
        {
            "client",
            "usbLibrary",
            "license",
            "python",
            "avb",
            "avbCli",
            "gpt",
            "gptCli"
        };

        private static readonly Dictionary<string, string> CommonRolePaths =
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                { "client", "tools/edl-ng.exe" },
                { "usbLibrary", "tools/libusb-1.0.dll" },
                { "license", "tools/LICENSE.txt" },
                { "python", "python/python-3.14.8-embed-amd64.zip" },
                { "avb", "scripts/avb_stock.py" },
                { "avbCli", "scripts/avb_stock_cli.py" },
                { "gpt", "scripts/portable_gpt.py" },
                { "gptCli", "scripts/edl_gpt_cli.py" }
            };

        private static readonly Dictionary<string, (long Bytes, string Sha256)> FixedPins =
            new Dictionary<string, (long Bytes, string Sha256)>(StringComparer.Ordinal)
            {
                {
                    "client",
                    (12015022L, "655530e926b57d70f1c690869c495253a6eaae28746f370d5b9dbf921d4a4b3b")
                },
                {
                    "python",
                    (12601679L, "a93abe456ab01bd96d7a085b3cdb6566b3063f4241360d114142fbdb07f0a310")
                }
            };

        private readonly string _stagingDirectory;
        private bool _disposed;

        private EdlToolchain(
            string stagingDirectory,
            string clientPath,
            string usbLibraryPath,
            string firehosePath,
            string pythonPath,
            string avbCliPath,
            string gptCliPath,
            string profileId,
            string model,
            string androidBuild,
            string hardwareId,
            EdlDeviceProfile profile)
        {
            _stagingDirectory = stagingDirectory;
            ClientPath = clientPath;
            UsbLibraryPath = usbLibraryPath;
            FirehosePath = firehosePath;
            PythonPath = pythonPath;
            AvbCliPath = avbCliPath;
            GptCliPath = gptCliPath;
            StagingDirectory = stagingDirectory;
            ProfileId = profileId;
            Model = model;
            AndroidBuild = androidBuild;
            HardwareId = hardwareId;
            Profile = profile;
        }

        public string ClientPath { get; }

        public string UsbLibraryPath { get; }

        public string FirehosePath { get; }

        public string PythonPath { get; }

        public string AvbCliPath { get; }

        public string GptCliPath { get; }

        public string StagingDirectory { get; }

        public string ProfileId { get; }

        public string Model { get; }

        public string AndroidBuild { get; }

        public string HardwareId { get; }

        /// <summary>
        /// The exact trusted profile this staging was loaded and verified against. Reference identity is
        /// the built-in <see cref="EdlDeviceProfiles"/> object; the manifest declaration never decides it.
        /// </summary>
        public EdlDeviceProfile Profile { get; }

        public static async Task<EdlToolchain> LoadAsync(
            Stream archive,
            string workRoot,
            CancellationToken cancellationToken = default)
        {
            if (archive == null)
            {
                throw new ArgumentNullException(nameof(archive));
            }

            if (string.IsNullOrWhiteSpace(workRoot))
            {
                throw new ArgumentException(
                    "An explicit, non-blank work root directory is required.",
                    nameof(workRoot));
            }

            if (!archive.CanRead || !archive.CanSeek)
            {
                throw new ArgumentException(
                    "The archive stream must be readable and seekable; the caller retains ownership of it.",
                    nameof(archive));
            }

            cancellationToken.ThrowIfCancellationRequested();

            using (var zipArchive = new ZipArchive(archive, ZipArchiveMode.Read, leaveOpen: true))
            {
                var outerEntries = IndexOuterEntries(zipArchive);
                var manifest = ReadManifest(outerEntries, cancellationToken);
                ValidateOuterAllowlist(outerEntries, manifest);

                var stagingDirectory = Path.Combine(
                    Path.GetFullPath(workRoot),
                    StagingDirectoryPrefix + Guid.NewGuid().ToString("N"));

                try
                {
                    Directory.CreateDirectory(stagingDirectory);

                    await ExtractPayloadsAsync(outerEntries, manifest, stagingDirectory, cancellationToken)
                        .ConfigureAwait(false);
                    await ExpandPythonRuntimeAsync(stagingDirectory, cancellationToken).ConfigureAwait(false);

                    return new EdlToolchain(
                        stagingDirectory,
                        StagedPath(stagingDirectory, CommonRolePaths["client"]),
                        StagedPath(stagingDirectory, CommonRolePaths["usbLibrary"]),
                        StagedPath(stagingDirectory, manifest.Profile.LoaderEntryPath),
                        Path.Combine(stagingDirectory, PythonRuntimeDirectoryName, PythonExecutableName),
                        StagedPath(stagingDirectory, CommonRolePaths["avbCli"]),
                        StagedPath(stagingDirectory, CommonRolePaths["gptCli"]),
                        manifest.ProfileId,
                        manifest.Model,
                        manifest.AndroidBuild,
                        manifest.HardwareId,
                        manifest.Profile);
                }
                catch
                {
                    TryDeleteOwnedDirectory(stagingDirectory);
                    throw;
                }
            }
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            TryDeleteOwnedDirectory(_stagingDirectory);
        }

        // ---------------------------------------------------------------- archive indexing

        private static Dictionary<string, ZipArchiveEntry> IndexOuterEntries(ZipArchive zipArchive)
        {
            var entries = new Dictionary<string, ZipArchiveEntry>(StringComparer.Ordinal);
            var seenNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var entry in zipArchive.Entries)
            {
                var name = entry.FullName;

                if (name.Length == 0)
                {
                    throw new InvalidDataException("The archive contains an entry with an empty name.");
                }

                if (!seenNames.Add(name))
                {
                    throw new InvalidDataException(
                        "The archive contains a duplicate or case-colliding entry '" + name + "'.");
                }

                if (name.EndsWith("/", StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "The archive entry '" + name + "' is a directory entry, which is not allowed.");
                }

                ValidateRelativePath(name, allowTrailingSlash: false);

                var unixType = GetUnixType(entry.ExternalAttributes);
                if (unixType != 0 && unixType != UnixTypeRegular)
                {
                    throw new InvalidDataException(
                        "The archive entry '" + name + "' is not a regular file " +
                        "(unix type 0x" + unixType.ToString("X4") + ").");
                }

                entries.Add(name, entry);
            }

            return entries;
        }

        private static void ValidateRelativePath(string name, bool allowTrailingSlash)
        {
            if (name.Length == 0 ||
                name.IndexOf('\\') >= 0 ||
                name.IndexOf(':') >= 0 ||
                name[0] == '/')
            {
                throw UnsafeEntry(name);
            }

            var candidate = allowTrailingSlash ? name.TrimEnd('/') : name;
            if (candidate.Length == 0)
            {
                throw UnsafeEntry(name);
            }

            if (!allowTrailingSlash && name[name.Length - 1] == '/')
            {
                throw UnsafeEntry(name);
            }

            foreach (var segment in candidate.Split('/'))
            {
                if (segment.Length == 0 || segment == "." || segment == "..")
                {
                    throw UnsafeEntry(name);
                }
            }
        }

        private static InvalidDataException UnsafeEntry(string name)
        {
            return new InvalidDataException("The archive entry '" + name + "' has an unsafe path.");
        }

        private static int GetUnixType(int externalAttributes)
        {
            return (externalAttributes >> 16) & 0xF000;
        }

        // ---------------------------------------------------------------- manifest

        private static Manifest ReadManifest(
            Dictionary<string, ZipArchiveEntry> outerEntries,
            CancellationToken cancellationToken)
        {
            ZipArchiveEntry manifestEntry;
            if (!outerEntries.TryGetValue(ManifestEntryName, out manifestEntry))
            {
                throw new InvalidDataException(
                    "The archive is missing the required manifest.json manifest.");
            }

            string json;
            using (var source = manifestEntry.Open())
            {
                using (var buffer = new MemoryStream())
                {
                    source.CopyTo(buffer);
                    json = Encoding.UTF8.GetString(buffer.ToArray());
                }
            }

            cancellationToken.ThrowIfCancellationRequested();

            var root = ParseManifestObject(json);

            long schemaVersion;
            if (!TryGetInt64(root["schemaVersion"], out schemaVersion) || schemaVersion != 1)
            {
                throw new InvalidDataException(
                    "The manifest field 'schemaVersion' must be the numeric value 1.");
            }

            // The manifest profileId is read first and may only select a built-in trusted definition; it can
            // never add identity, pins or hardware authority of its own.
            var declaredProfileId = ReadString(root["profileId"]);
            var profile = EdlDeviceProfiles.FindById(declaredProfileId);
            if (profile == null)
            {
                throw new InvalidDataException(
                    "The manifest field 'profileId' must name a known built-in EDL profile; got '" +
                    (declaredProfileId ?? "<none>") + "'.");
            }

            // An incomplete definition (for example G5 today) is preparation metadata only, so it is
            // rejected before staging creates anything, even when the manifest claims a full identity.
            if (!profile.IsComplete)
            {
                throw new InvalidDataException(
                    "The manifest field 'profileId' names the incomplete EDL profile '" +
                    profile.ProfileId + "'; an incomplete profile cannot be staged or published.");
            }

            var model = RequireIdentityField(root, "model", profile.Model);
            var androidBuild = RequireAllowedDisplayId(root, "androidBuild", profile);

            var hardwareId = ReadString(root["hardwareId"]);
            if (profile.FullHardwareId == null ||
                hardwareId == null ||
                !string.Equals(hardwareId, profile.FullHardwareId, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "The manifest field 'hardwareId' must be exactly '" +
                    (profile.FullHardwareId ?? "<none>") + "' for profile '" + profile.ProfileId + "'.");
            }

            // The expected role/path set is compiled from the eight common roles plus every reviewed loader
            // material of the selected profile. The manifest can only ever restate it, never extend it.
            var expectedRoleOrder = new List<string>(CommonRoleOrder.Length + profile.Materials.Count);
            var expectedPaths = new Dictionary<string, string>(StringComparer.Ordinal);

            foreach (var role in CommonRoleOrder)
            {
                AddExpectedRole(expectedRoleOrder, expectedPaths, role, CommonRolePaths[role]);
            }

            foreach (var material in profile.Materials)
            {
                AddExpectedRole(expectedRoleOrder, expectedPaths, material.Role, material.RelativePath);
            }

            var entriesNode = root["entries"] as JsonArray;
            if (entriesNode == null)
            {
                throw new InvalidDataException(
                    "The manifest field 'entries' must be an array of role entries.");
            }

            var entries = new Dictionary<string, ManifestEntry>(StringComparer.Ordinal);
            foreach (var child in entriesNode)
            {
                var entryObject = child as JsonObject;
                if (entryObject == null)
                {
                    throw new InvalidDataException(
                        "The manifest 'entries' item is not an object and cannot carry a role.");
                }

                var role = ReadString(entryObject["role"]) ?? string.Empty;
                if (role.Length == 0)
                {
                    throw new InvalidDataException(
                        "The manifest contains an entries item without a role.");
                }

                string canonicalPath;
                if (!expectedPaths.TryGetValue(role, out canonicalPath))
                {
                    throw new InvalidDataException(
                        "The manifest contains unknown role '" + role + "'.");
                }

                if (entries.ContainsKey(role))
                {
                    throw new InvalidDataException(
                        "The manifest contains duplicate role '" + role + "'.");
                }

                var path = ReadString(entryObject["path"]) ?? string.Empty;
                if (!string.Equals(path, canonicalPath, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "The manifest path for role '" + role + "' must be exactly '" +
                        canonicalPath + "'.");
                }

                long bytes;
                if (!TryGetInt64(entryObject["bytes"], out bytes) || bytes <= 0)
                {
                    throw new InvalidDataException(
                        "The manifest bytes for role '" + role + "' must be a positive integer.");
                }

                var sha256 = ReadString(entryObject["sha256"]) ?? string.Empty;
                if (!IsSha256Hex(sha256))
                {
                    throw new InvalidDataException(
                        "The manifest sha256 for role '" + role + "' must be 64 hexadecimal characters.");
                }

                entries.Add(role, new ManifestEntry(role, path, bytes, sha256.ToLowerInvariant()));
            }

            foreach (var role in expectedRoleOrder)
            {
                if (!entries.ContainsKey(role))
                {
                    throw new InvalidDataException(
                        "The manifest is missing required role '" + role + "'.");
                }
            }

            foreach (var pin in FixedPins)
            {
                var declared = entries[pin.Key];
                if (declared.Bytes != pin.Value.Bytes ||
                    !string.Equals(declared.Sha256, pin.Value.Sha256, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "The manifest pin for role '" + pin.Key +
                        "' does not match the fixed reviewed payload pin (bytes and sha256).");
                }
            }

            // Every reviewed loader material of the selected profile is pinned, not only the loader entry:
            // a G5 manifest must declare all nine payloads with their compiled path, length and SHA.
            foreach (var material in profile.Materials)
            {
                var declared = entries[material.Role];
                if (declared.Bytes != material.Bytes ||
                    !string.Equals(declared.Sha256, material.Sha256, StringComparison.Ordinal) ||
                    !string.Equals(declared.Path, material.RelativePath, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "The manifest pin for role '" + material.Role +
                        "' does not match the fixed reviewed payload pin (path, bytes and sha256).");
                }
            }

            var orderedEntries = new List<ManifestEntry>(expectedRoleOrder.Count);
            foreach (var role in expectedRoleOrder)
            {
                orderedEntries.Add(entries[role]);
            }

            return new Manifest(profile, model, androidBuild, hardwareId, orderedEntries);
        }

        private static void AddExpectedRole(
            List<string> roleOrder,
            Dictionary<string, string> expectedPaths,
            string role,
            string relativePath)
        {
            if (expectedPaths.ContainsKey(role))
            {
                throw new InvalidDataException(
                    "The trusted role table declares duplicate role '" + role + "'.");
            }

            expectedPaths.Add(role, relativePath);
            roleOrder.Add(role);
        }

        private static string RequireAllowedDisplayId(
            JsonObject root,
            string fieldName,
            EdlDeviceProfile profile)
        {
            var actual = ReadString(root[fieldName]);
            if (actual != null)
            {
                foreach (var allowed in profile.AllowedDisplayIds)
                {
                    if (string.Equals(actual, allowed, StringComparison.Ordinal))
                    {
                        return actual;
                    }
                }
            }

            throw new InvalidDataException(
                "The manifest field '" + fieldName +
                "' must be one of the trusted allowed display ids of profile '" +
                profile.ProfileId + "'.");
        }

        private static JsonObject ParseManifestObject(string json)
        {
            try
            {
                var root = JsonNode.Parse(json) as JsonObject;
                if (root == null)
                {
                    throw new InvalidDataException(
                        "The manifest.json manifest must contain a JSON object at its root.");
                }

                return root;
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException(
                    "The manifest.json manifest is not valid JSON: " + ex.Message,
                    ex);
            }
        }

        private static string RequireIdentityField(JsonObject root, string fieldName, string expected)
        {
            var actual = ReadString(root[fieldName]);
            if (actual == null || !string.Equals(actual, expected, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "The manifest field '" + fieldName + "' must be exactly '" + expected + "'.");
            }

            return actual;
        }

        private static string? ReadString(JsonNode? node)
        {
            var value = node as JsonValue;
            if (value == null)
            {
                return null;
            }

            string? text;
            return value.TryGetValue<string>(out text) ? text : null;
        }

        private static bool TryGetInt64(JsonNode? node, out long value)
        {
            value = 0;
            var jsonValue = node as JsonValue;
            return jsonValue != null && jsonValue.TryGetValue<long>(out value);
        }

        private static bool IsSha256Hex(string value)
        {
            if (value.Length != 64)
            {
                return false;
            }

            foreach (var c in value)
            {
                var isHex = (c >= '0' && c <= '9') ||
                            (c >= 'a' && c <= 'f') ||
                            (c >= 'A' && c <= 'F');
                if (!isHex)
                {
                    return false;
                }
            }

            return true;
        }

        private static void ValidateOuterAllowlist(
            Dictionary<string, ZipArchiveEntry> outerEntries,
            Manifest manifest)
        {
            var expected = new HashSet<string>(StringComparer.Ordinal) { ManifestEntryName };
            foreach (var declared in manifest.OrderedEntries)
            {
                expected.Add(declared.Path);
            }

            foreach (var name in outerEntries.Keys)
            {
                if (!expected.Remove(name))
                {
                    throw new InvalidDataException(
                        "The outer archive contains an unexpected entry '" + name +
                        "'; only the selected profile's reviewed payloads and manifest.json are allowed.");
                }
            }

            if (expected.Count > 0)
            {
                var missing = new List<string>(expected);
                missing.Sort(StringComparer.Ordinal);
                throw new InvalidDataException(
                    "The outer archive is missing the required manifest entry or payload entry '" +
                    string.Join("', '", missing) + "'.");
            }
        }

        // ---------------------------------------------------------------- extraction

        private static async Task ExtractPayloadsAsync(
            Dictionary<string, ZipArchiveEntry> outerEntries,
            Manifest manifest,
            string stagingDirectory,
            CancellationToken cancellationToken)
        {
            foreach (var declared in manifest.OrderedEntries)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var role = declared.Role;

                ZipArchiveEntry entry;
                if (!outerEntries.TryGetValue(declared.Path, out entry))
                {
                    throw new InvalidDataException(
                        "The outer archive is missing the payload entry '" + declared.Path +
                        "' for role '" + role + "'.");
                }

                if (entry.Length != declared.Bytes)
                {
                    throw new InvalidDataException(
                        "The outer archive entry '" + declared.Path + "' for role '" + role +
                        "' declares " + declared.Bytes + " bytes but the entry length is " +
                        entry.Length + ".");
                }

                var targetPath = StagedPath(stagingDirectory, declared.Path);
                var parent = Path.GetDirectoryName(targetPath);
                if (!string.IsNullOrEmpty(parent))
                {
                    Directory.CreateDirectory(parent);
                }

                long total;
                string actualSha256;

                using (var source = entry.Open())
                using (var target = new FileStream(
                           targetPath,
                           FileMode.CreateNew,
                           FileAccess.Write,
                           FileShare.None,
                           BufferSize,
                           useAsync: true))
                using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
                {
                    total = 0;
                    var buffer = new byte[BufferSize];

                    while (true)
                    {
                        var read = await source
                            .ReadAsync(buffer, 0, buffer.Length, cancellationToken)
                            .ConfigureAwait(false);
                        if (read == 0)
                        {
                            break;
                        }

                        cancellationToken.ThrowIfCancellationRequested();
                        hash.AppendData(buffer, 0, read);
                        await target
                            .WriteAsync(buffer, 0, read, cancellationToken)
                            .ConfigureAwait(false);
                        total += read;
                    }

                    actualSha256 = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
                }

                if (total != declared.Bytes ||
                    !string.Equals(actualSha256, declared.Sha256, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "The outer archive entry '" + declared.Path + "' for role '" + role +
                        "' failed payload integrity validation (bytes " + total + ", sha256 " +
                        actualSha256 + ").");
                }
            }
        }

        private static async Task ExpandPythonRuntimeAsync(
            string stagingDirectory,
            CancellationToken cancellationToken)
        {
            var pythonArchivePath = StagedPath(stagingDirectory, CommonRolePaths["python"]);
            if (!File.Exists(pythonArchivePath))
            {
                throw new InvalidDataException(
                    "The staged python payload entry '" + CommonRolePaths["python"] + "' is missing.");
            }

            var runtimeDirectory = Path.Combine(stagingDirectory, PythonRuntimeDirectoryName);
            Directory.CreateDirectory(runtimeDirectory);

            var seenNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            using (var sourceStream = new FileStream(
                       pythonArchivePath,
                       FileMode.Open,
                       FileAccess.Read,
                       FileShare.Read))
            using (var pythonArchive = new ZipArchive(sourceStream, ZipArchiveMode.Read, leaveOpen: false))
            {
                foreach (var member in pythonArchive.Entries)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var name = member.FullName;
                    if (name.Length == 0)
                    {
                        throw new InvalidDataException(
                            "The python runtime entry has an empty name.");
                    }

                    var unixType = GetUnixType(member.ExternalAttributes);
                    if (unixType == UnixTypeSymlink)
                    {
                        throw new InvalidDataException(
                            "The python runtime entry '" + name + "' is a symlink and is not allowed.");
                    }

                    var isDirectory = unixType == UnixTypeDirectory ||
                                      name.EndsWith("/", StringComparison.Ordinal);

                    if (!isDirectory && unixType != 0 && unixType != UnixTypeRegular)
                    {
                        throw new InvalidDataException(
                            "The python runtime entry '" + name + "' is not a regular file " +
                            "(unix type 0x" + unixType.ToString("X4") + ").");
                    }

                    var normalized = isDirectory ? name.TrimEnd('/') : name;
                    ValidateRelativePath(normalized, allowTrailingSlash: false);

                    if (!seenNames.Add(normalized))
                    {
                        throw new InvalidDataException(
                            "The python runtime entry '" + name +
                            "' duplicates or case-collides with another entry.");
                    }

                    var targetPath = StagedPath(runtimeDirectory, normalized);
                    if (isDirectory)
                    {
                        Directory.CreateDirectory(targetPath);
                        continue;
                    }

                    var parent = Path.GetDirectoryName(targetPath);
                    if (!string.IsNullOrEmpty(parent))
                    {
                        Directory.CreateDirectory(parent);
                    }

                    using (var source = member.Open())
                    using (var target = new FileStream(
                               targetPath,
                               FileMode.CreateNew,
                               FileAccess.Write,
                               FileShare.None,
                               BufferSize,
                               useAsync: true))
                    {
                        await CopyAsync(source, target, cancellationToken).ConfigureAwait(false);
                    }
                }
            }

            var pythonExecutablePath = Path.Combine(runtimeDirectory, PythonExecutableName);
            var embeddedArchivePath = Path.Combine(runtimeDirectory, PythonArchiveName);
            var pathFilePath = Path.Combine(runtimeDirectory, PythonPathFileName);

            if (!File.Exists(pythonExecutablePath) ||
                !File.Exists(embeddedArchivePath) ||
                !File.Exists(pathFilePath))
            {
                throw new InvalidDataException(
                    "The python runtime entry is incomplete; runtime/python.exe, " +
                    "runtime/python314.zip and runtime/python314._pth are required.");
            }

            File.WriteAllBytes(pathFilePath, Encoding.UTF8.GetBytes(PythonPathContents));
        }

        private static async Task CopyAsync(
            Stream source,
            Stream destination,
            CancellationToken cancellationToken)
        {
            var buffer = new byte[BufferSize];

            while (true)
            {
                var read = await source
                    .ReadAsync(buffer, 0, buffer.Length, cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    return;
                }

                cancellationToken.ThrowIfCancellationRequested();
                await destination
                    .WriteAsync(buffer, 0, read, cancellationToken)
                    .ConfigureAwait(false);
            }
        }

        // ---------------------------------------------------------------- owned paths

        private static string StagedPath(string root, string relativePath)
        {
            return ResolveContainedPath(root, relativePath.Replace('/', Path.DirectorySeparatorChar));
        }

        private static string ResolveContainedPath(string root, string relativePath)
        {
            var rootFull = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
            var combined = Path.GetFullPath(Path.Combine(rootFull, relativePath));
            var prefix = Path.EndsInDirectorySeparator(rootFull)
                ? rootFull
                : rootFull + Path.DirectorySeparatorChar;

            if (!combined.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "The archive entry '" + relativePath +
                    "' would escape the owned staging directory.");
            }

            return combined;
        }

        private static void TryDeleteOwnedDirectory(string directory)
        {
            if (string.IsNullOrEmpty(directory))
            {
                return;
            }

            try
            {
                if (Directory.Exists(directory))
                {
                    Directory.Delete(directory, recursive: true);
                }
            }
            catch (IOException)
            {
                // Best-effort cleanup of our own staging child only.
            }
            catch (UnauthorizedAccessException)
            {
                // Best-effort cleanup of our own staging child only.
            }
        }

        // ---------------------------------------------------------------- nested types

        private sealed class Manifest
        {
            public Manifest(
                EdlDeviceProfile profile,
                string model,
                string androidBuild,
                string hardwareId,
                IReadOnlyList<ManifestEntry> orderedEntries)
            {
                Profile = profile;
                ProfileId = profile.ProfileId;
                Model = model;
                AndroidBuild = androidBuild;
                HardwareId = hardwareId;
                OrderedEntries = orderedEntries;
            }

            public EdlDeviceProfile Profile { get; }

            public string ProfileId { get; }

            public string Model { get; }

            public string AndroidBuild { get; }

            public string HardwareId { get; }

            /// <summary>
            /// The validated expected entry set in review order: the eight common roles followed by every
            /// loader material of the selected profile. Extraction and the outer allowlist walk this.
            /// </summary>
            public IReadOnlyList<ManifestEntry> OrderedEntries { get; }
        }

        private sealed class ManifestEntry
        {
            public ManifestEntry(string role, string path, long bytes, string sha256)
            {
                Role = role;
                Path = path;
                Bytes = bytes;
                Sha256 = sha256;
            }

            public string Role { get; }

            public string Path { get; }

            public long Bytes { get; }

            public string Sha256 { get; }
        }
    }
}
