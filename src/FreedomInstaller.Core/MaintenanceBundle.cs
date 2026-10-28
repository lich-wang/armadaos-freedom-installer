using System.Buffers;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;

namespace FreedomInstaller.Core;

/// <summary>
/// Metadata for one file carried by a maintenance bundle.
/// </summary>
/// <param name="Role">Logical role, one of the fixed required roles.</param>
/// <param name="Path">Relative archive path exactly as declared by the manifest.</param>
/// <param name="Bytes">Declared length in bytes.</param>
/// <param name="Sha256">Declared lowercase 64-hex SHA-256 digest.</param>
public sealed record MaintenanceAsset(string Role, string Path, long Bytes, string Sha256);

/// <summary>
/// The fixed device profile a maintenance bundle is bound to.
/// </summary>
/// <param name="ProfileId">Profile identity, e.g. the pinned G4 production profile.</param>
/// <param name="Model">Device model code.</param>
/// <param name="AndroidBuild">Full Android build fingerprint.</param>
/// <param name="Soc">SoC identifier.</param>
public sealed record MaintenanceProfile(string ProfileId, string Model, string AndroidBuild, string Soc);

/// <summary>
/// Stable, non-localized failure identities surfaced through <see cref="MaintenanceException.Code"/>.
/// Callers branch on these values; exception messages are diagnostic text only.
/// </summary>
public enum MaintenanceErrorCode
{
    /// <summary>The archive has no usable root manifest.json, or its schema is not the supported version.</summary>
    InvalidManifest = 0,

    /// <summary>The manifest profile is not a known production profile, or its asset pins are not the reviewed pins.</summary>
    UnsupportedProfile = 1,

    /// <summary>The requested model does not match the manifest/profile model.</summary>
    ModelMismatch = 2,

    /// <summary>The requested Android build does not match the manifest/profile build.</summary>
    BuildMismatch = 3,

    /// <summary>A required role, or the entry a role references, is absent from the archive.</summary>
    MissingAsset = 4,

    /// <summary>An entry path is absolute, contains a backslash or colon, or traverses outside the staging root.</summary>
    UnsafeEntry = 5,

    /// <summary>Two entries collide on role or on path (case-insensitively), or two archive entries share a name.</summary>
    DuplicateEntry = 6,

    /// <summary>Payload length differs from the declared length.</summary>
    AssetSizeMismatch = 7,

    /// <summary>Payload digest differs from the declared digest.</summary>
    AssetHashMismatch = 8,

    /// <summary>The provided work root or other ambient state is unusable or unsafe to stage into.</summary>
    UnsafeEnvironment = 9,

    /// <summary>The post-extraction handshake does not match the loaded profile.</summary>
    HandshakeMismatch = 10
}

/// <summary>
/// Failure raised by maintenance bundle loading and access. Carries a stable
/// <see cref="Code"/>; message text is never part of the contract.
/// </summary>
public sealed class MaintenanceException : Exception
{
    public MaintenanceException(MaintenanceErrorCode code, string message)
        : base(message)
    {
        Code = code;
    }

    public MaintenanceException(MaintenanceErrorCode code, string message, Exception? innerException)
        : base(message, innerException)
    {
        Code = code;
    }

    public MaintenanceErrorCode Code { get; }
}

/// <summary>
/// Reviewed production profile and the only accepted asset pins for the G4 build.
/// Callers use these constants instead of re-declaring literals.
/// </summary>
public static class MaintenanceProfiles
{
    /// <summary>Only manifest schema version this loader accepts.</summary>
    public const int ManifestSchemaVersion = 1;

    public const string ProfileId = "g4-198-259-acmncm";
    public const string Model = "TB322FC";
    public const string Soc = "SM8750";
    public const string AndroidBuild = "TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.259_ST_260611";

    public const string BootRole = "boot";
    public const long BootBytes = 100663296L;
    public const string BootSha256 = "81e7da2e2d3910d80dee80e1d6f774db294c8e9aa633d4aca7db9ccd7a50c358";

    public const string ToolboxRole = "toolbox";
    public const long ToolboxBytes = 171162924L;
    public const string ToolboxSha256 = "79a2d937f2cf566591fde9bb8fc1b594fb9e949176fbde0364e9f09976af14a2";

    public const string BootstrapRole = "bootstrap";
    public const string HelperRole = "helper";
    public const string AvbRole = "avb";

    /// <summary>The single supported production profile.</summary>
    public static MaintenanceProfile KnownProfile { get; } =
        new(ProfileId, Model, AndroidBuild, Soc);

    /// <summary>Exactly the roles every bundle must carry, each declared once.</summary>
    public static IReadOnlyList<string> RequiredRoles { get; } =
        Array.AsReadOnly(new[] { BootRole, ToolboxRole, BootstrapRole, HelperRole, AvbRole });
}

/// <summary>
/// A loaded, verified maintenance bundle. Disposing it removes only its own staging
/// directory; the source archive stream, the work root, and sibling files are preserved.
/// </summary>
public interface IMaintenanceBundle : IDisposable
{
    /// <summary>The profile the bundle proved itself against during loading.</summary>
    MaintenanceProfile Profile { get; }

    /// <summary>Metadata for a required role.</summary>
    /// <exception cref="MaintenanceException">The role is not part of this bundle.</exception>
    MaintenanceAsset GetAsset(string role);

    /// <summary>Opens the staged payload for a required role for reading.</summary>
    Stream OpenAsset(string role);
}

/// <summary>
/// Validating loader for maintenance bundles.
/// </summary>
/// <remarks>
/// Archive layout: a root <c>manifest.json</c> with lowerCamel
/// <c>schemaVersion=1</c>, <c>profileId</c>, <c>model</c>, <c>androidBuild</c> and
/// <c>entries[{role,path,bytes,sha256}]</c>, followed by exactly the entries it declares.
/// <para>
/// Loading order is part of the contract: every manifest field, profile pin, role set,
/// entry path and archive reference is validated first, then the small runtime scripts
/// (bootstrap, helper, avb) are length- and hash-checked, and only then are the large
/// boot/toolbox payloads streamed — regardless of manifest order. Structural failures
/// therefore never read payload bytes.
/// </para>
/// <para>
/// <see cref="LoadAsync"/> does not take ownership of <c>archive</c>; the caller closes it.
/// A successful bundle owns exactly one newly created unique child of <c>workRoot</c>;
/// a failed load deletes that partial child again.
/// </para>
/// </remarks>
public sealed class MaintenanceBundle : IMaintenanceBundle
{
    private const int ManifestByteLimit = 1024 * 1024;
    private const int CopyBufferSize = 81920;

    private static readonly string[] ExtractionOrder =
    {
        MaintenanceProfiles.BootstrapRole,
        MaintenanceProfiles.HelperRole,
        MaintenanceProfiles.AvbRole,
        MaintenanceProfiles.BootRole,
        MaintenanceProfiles.ToolboxRole
    };

    private readonly IReadOnlyDictionary<string, MaintenanceAsset> _assets;
    private readonly IReadOnlyDictionary<string, string> _stagedPaths;
    private bool _disposed;

    internal MaintenanceBundle(
        string stagingDirectory,
        MaintenanceProfile profile,
        IReadOnlyDictionary<string, MaintenanceAsset> assets,
        IReadOnlyDictionary<string, string> stagedPaths)
    {
        StagingDirectory = stagingDirectory;
        Profile = profile;
        _assets = assets;
        _stagedPaths = stagedPaths;
    }

    /// <summary>The unique staging child this bundle owns; removed on dispose.</summary>
    public string StagingDirectory { get; }

    public MaintenanceProfile Profile { get; }

    public MaintenanceAsset GetAsset(string role)
    {
        ArgumentException.ThrowIfNullOrEmpty(role);

        if (!_assets.TryGetValue(role, out var asset))
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.MissingAsset,
                $"The bundle does not carry the '{role}' asset.");
        }

        return asset;
    }

    /// <summary>
    /// Opens a fresh read-only stream over the staged copy of <paramref name="role"/>.
    /// The stream never exposes the source archive.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The bundle has already been disposed.</exception>
    /// <exception cref="MaintenanceException">The role is not part of this bundle.</exception>
    public Stream OpenAsset(string role)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrEmpty(role);

        if (!_stagedPaths.TryGetValue(role, out var path) || !File.Exists(path))
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.MissingAsset,
                $"The bundle does not carry the '{role}' asset.");
        }

        return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
    }

    /// <summary>
    /// Idempotently deletes only <see cref="StagingDirectory"/>, leaving the source archive
    /// stream, the work root, and its siblings untouched.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        TryDeleteDirectory(StagingDirectory);
    }

    /// <summary>
    /// Validates and extracts a maintenance archive into a fresh unique child of
    /// <paramref name="workRoot"/>.
    /// </summary>
    /// <param name="archive">Readable, seekable archive stream; ownership stays with the caller.</param>
    /// <param name="expectedModel">Model the caller requires.</param>
    /// <param name="expectedAndroidBuild">Android build the caller requires.</param>
    /// <param name="workRoot">Existing directory under which the staging child is created.</param>
    /// <param name="cancellationToken">Cancels loading without leaving staging residue.</param>
    /// <exception cref="MaintenanceException">Any validation or verification failure.</exception>
    public static async Task<MaintenanceBundle> LoadAsync(
        Stream archive,
        string expectedModel,
        string expectedAndroidBuild,
        string workRoot,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(archive);
        ArgumentException.ThrowIfNullOrEmpty(expectedModel);
        ArgumentException.ThrowIfNullOrEmpty(expectedAndroidBuild);
        ArgumentException.ThrowIfNullOrEmpty(workRoot);

        if (!archive.CanRead || !archive.CanSeek)
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.InvalidManifest,
                "The archive stream must be readable and seekable.");
        }

        var stagingRoot = Path.GetFullPath(workRoot);
        if (!Directory.Exists(stagingRoot))
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.UnsafeEnvironment,
                $"The work root '{workRoot}' does not exist.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        string? stagingDirectory = null;
        try
        {
            using var zip = new ZipArchive(archive, ZipArchiveMode.Read, leaveOpen: true);

            var index = IndexArchiveEntries(zip);
            var manifestBytes = ReadManifestBytes(index);
            var declared = ParseAndValidateManifest(manifestBytes, expectedModel, expectedAndroidBuild);
            var plans = ResolveExtractionPlans(index, declared);

            stagingDirectory = CreateStagingDirectory(stagingRoot);
            var stagedPaths = await ExtractAllAsync(plans, stagingDirectory, cancellationToken).ConfigureAwait(false);

            var assets = new Dictionary<string, MaintenanceAsset>(StringComparer.Ordinal);
            foreach (var pair in declared)
            {
                assets.Add(
                    pair.Key,
                    new MaintenanceAsset(pair.Value.Role, pair.Value.Path, pair.Value.Bytes, pair.Value.Sha256));
            }

            var bundle = new MaintenanceBundle(
                stagingDirectory,
                MaintenanceProfiles.KnownProfile,
                assets,
                stagedPaths);

            stagingDirectory = null;
            return bundle;
        }
        catch
        {
            if (stagingDirectory is not null)
            {
                TryDeleteDirectory(stagingDirectory);
            }

            throw;
        }
    }

    private static Dictionary<string, ZipArchiveEntry> IndexArchiveEntries(ZipArchive zip)
    {
        var index = new Dictionary<string, ZipArchiveEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in zip.Entries)
        {
            if (!index.TryAdd(entry.FullName, entry))
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.DuplicateEntry,
                    $"The archive stores '{entry.FullName}' more than once.");
            }
        }

        return index;
    }

    private static byte[] ReadManifestBytes(IReadOnlyDictionary<string, ZipArchiveEntry> index)
    {
        if (!index.TryGetValue("manifest.json", out var entry))
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.InvalidManifest,
                "The archive has no root manifest.json.");
        }

        using var source = entry.Open();
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int read;
        while ((read = source.Read(chunk, 0, chunk.Length)) > 0)
        {
            if (buffer.Length + read > ManifestByteLimit)
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.InvalidManifest,
                    "manifest.json is unreasonably large.");
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    private static Dictionary<string, DeclaredEntry> ParseAndValidateManifest(
        byte[] manifestBytes,
        string expectedModel,
        string expectedAndroidBuild)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(manifestBytes);
        }
        catch (JsonException exception)
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.InvalidManifest,
                "manifest.json is not valid JSON.",
                exception);
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new MaintenanceException(MaintenanceErrorCode.InvalidManifest, "manifest.json must be an object.");
            }

            if (!root.TryGetProperty("schemaVersion", out var schemaElement) ||
                schemaElement.ValueKind != JsonValueKind.Number ||
                !schemaElement.TryGetInt32(out var schemaVersion) ||
                schemaVersion != MaintenanceProfiles.ManifestSchemaVersion)
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.InvalidManifest,
                    $"manifest.json must declare schemaVersion {MaintenanceProfiles.ManifestSchemaVersion}.");
            }

            var profileId = RequireString(root, "profileId");
            var model = RequireString(root, "model");
            var androidBuild = RequireString(root, "androidBuild");

            if (!string.Equals(profileId, MaintenanceProfiles.ProfileId, StringComparison.Ordinal) ||
                !string.Equals(model, MaintenanceProfiles.Model, StringComparison.Ordinal) ||
                !string.Equals(androidBuild, MaintenanceProfiles.AndroidBuild, StringComparison.Ordinal))
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.UnsupportedProfile,
                    $"Profile '{profileId}' ({model}, {androidBuild}) is not the supported production profile.");
            }

            if (!string.Equals(expectedModel, model, StringComparison.Ordinal))
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.ModelMismatch,
                    $"Requested model '{expectedModel}' does not match bundle model '{model}'.");
            }

            if (!string.Equals(expectedAndroidBuild, androidBuild, StringComparison.Ordinal))
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.BuildMismatch,
                    $"Requested build '{expectedAndroidBuild}' does not match bundle build '{androidBuild}'.");
            }

            if (!root.TryGetProperty("entries", out var entriesElement) ||
                entriesElement.ValueKind != JsonValueKind.Array)
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.InvalidManifest,
                    "manifest.json must declare an entries array.");
            }

            return ValidateDeclaredEntries(entriesElement);
        }
    }

    private static Dictionary<string, DeclaredEntry> ValidateDeclaredEntries(JsonElement entriesElement)
    {
        var declared = new Dictionary<string, DeclaredEntry>(StringComparer.Ordinal);
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var element in entriesElement.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.Object)
            {
                throw new MaintenanceException(MaintenanceErrorCode.InvalidManifest, "Every entry must be an object.");
            }

            var role = RequireString(element, "role").ToLowerInvariant();
            var path = RequireString(element, "path");
            var bytes = RequireBytes(element);
            var sha256 = RequireSha256(element);

            if (!MaintenanceProfiles.RequiredRoles.Contains(role, StringComparer.Ordinal))
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.InvalidManifest,
                    $"Entry role '{role}' is not part of the supported role set.");
            }

            if (!declared.TryAdd(role, new DeclaredEntry(role, path, bytes, sha256)))
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.DuplicateEntry,
                    $"Role '{role}' is declared more than once.");
            }

            if (!paths.Add(path))
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.DuplicateEntry,
                    $"Path '{path}' is declared more than once.");
            }

            ValidateAssetPath(path);
        }

        foreach (var required in MaintenanceProfiles.RequiredRoles)
        {
            if (!declared.ContainsKey(required))
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.MissingAsset,
                    $"The manifest does not declare the required '{required}' role.");
            }
        }

        var boot = declared[MaintenanceProfiles.BootRole];
        if (boot.Bytes != MaintenanceProfiles.BootBytes ||
            !string.Equals(boot.Sha256, MaintenanceProfiles.BootSha256, StringComparison.Ordinal))
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.UnsupportedProfile,
                "The declared boot asset does not match the reviewed production pin.");
        }

        var toolbox = declared[MaintenanceProfiles.ToolboxRole];
        if (toolbox.Bytes != MaintenanceProfiles.ToolboxBytes ||
            !string.Equals(toolbox.Sha256, MaintenanceProfiles.ToolboxSha256, StringComparison.Ordinal))
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.UnsupportedProfile,
                "The declared toolbox asset does not match the reviewed production pin.");
        }

        return declared;
    }

    private static void ValidateAssetPath(string path)
    {
        if (path.Length == 0 ||
            path[0] == '/' ||
            path.Contains('\\') ||
            path.Contains(':') ||
            Path.IsPathRooted(path))
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.UnsafeEntry,
                $"Entry path '{path}' is not a plain relative path.");
        }

        foreach (var segment in path.Split('/'))
        {
            if (segment.Length == 0 || segment == "." || segment == "..")
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.UnsafeEntry,
                    $"Entry path '{path}' contains an unsafe segment.");
            }
        }
    }

    private static Dictionary<string, ExtractionPlan> ResolveExtractionPlans(
        IReadOnlyDictionary<string, ZipArchiveEntry> index,
        IReadOnlyDictionary<string, DeclaredEntry> declared)
    {
        var plans = new Dictionary<string, ExtractionPlan>(StringComparer.Ordinal);
        foreach (var pair in declared)
        {
            if (!index.TryGetValue(pair.Value.Path, out var entry))
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.MissingAsset,
                    $"The archive does not store '{pair.Value.Path}' for role '{pair.Key}'.");
            }

            plans.Add(pair.Key, new ExtractionPlan(pair.Value, entry));
        }

        return plans;
    }

    private static string CreateStagingDirectory(string stagingRoot)
    {
        var child = Path.GetFullPath(Path.Combine(stagingRoot, "mb002-" + Guid.NewGuid().ToString("N")));
        Directory.CreateDirectory(child);
        return child;
    }

    private static async Task<Dictionary<string, string>> ExtractAllAsync(
        IReadOnlyDictionary<string, ExtractionPlan> plans,
        string stagingDirectory,
        CancellationToken cancellationToken)
    {
        var stagedPaths = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var role in ExtractionOrder)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var stagedPath = await ExtractEntryAsync(plans[role], stagingDirectory, cancellationToken)
                .ConfigureAwait(false);
            stagedPaths.Add(role, stagedPath);
        }

        return stagedPaths;
    }

    private static async Task<string> ExtractEntryAsync(
        ExtractionPlan plan,
        string stagingDirectory,
        CancellationToken cancellationToken)
    {
        var relativePath = plan.Declared.Path.Replace('/', Path.DirectorySeparatorChar);
        var destination = Path.GetFullPath(Path.Combine(stagingDirectory, relativePath));
        var stagingPrefix = stagingDirectory.EndsWith(Path.DirectorySeparatorChar)
            ? stagingDirectory
            : stagingDirectory + Path.DirectorySeparatorChar;

        if (!destination.StartsWith(stagingPrefix, StringComparison.Ordinal))
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.UnsafeEntry,
                $"Entry path '{plan.Declared.Path}' would escape the staging directory.");
        }

        var directory = Path.GetDirectoryName(destination);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        if (File.Exists(destination) || Directory.Exists(destination))
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.UnsafeEntry,
                $"Entry path '{plan.Declared.Path}' would overwrite an existing destination.");
        }

        long actualBytes;
        string actualSha256;
        var buffer = ArrayPool<byte>.Shared.Rent(CopyBufferSize);
        try
        {
            using var source = plan.Entry.Open();
            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long total = 0;

            await using (var target = new FileStream(
                destination,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                CopyBufferSize,
                FileOptions.Asynchronous))
            {
                int read;
                while ((read = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)
                           .ConfigureAwait(false)) > 0)
                {
                    hasher.AppendData(buffer, 0, read);
                    await target.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                    total += read;
                }

                await target.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            actualBytes = total;
            actualSha256 = Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        if (actualBytes != plan.Declared.Bytes)
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.AssetSizeMismatch,
                $"Entry '{plan.Declared.Path}' is {actualBytes} bytes but the manifest declares {plan.Declared.Bytes}.");
        }

        if (!string.Equals(actualSha256, plan.Declared.Sha256, StringComparison.Ordinal))
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.AssetHashMismatch,
                $"Entry '{plan.Declared.Path}' does not match the declared SHA-256.");
        }

        return destination;
    }

    private static string RequireString(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.String ||
            string.IsNullOrEmpty(value.GetString()))
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.InvalidManifest,
                $"manifest.json must declare a non-empty '{name}' string.");
        }

        return value.GetString()!;
    }

    private static long RequireBytes(JsonElement element)
    {
        if (!element.TryGetProperty("bytes", out var value) ||
            value.ValueKind != JsonValueKind.Number ||
            !value.TryGetInt64(out var bytes) ||
            bytes <= 0)
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.InvalidManifest,
                "Every entry must declare a positive 'bytes' integer.");
        }

        return bytes;
    }

    private static string RequireSha256(JsonElement element)
    {
        if (!element.TryGetProperty("sha256", out var value) ||
            value.ValueKind != JsonValueKind.String)
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.InvalidManifest,
                "Every entry must declare a 'sha256' string.");
        }

        var text = value.GetString();
        if (text is null || text.Length != 64)
        {
            throw new MaintenanceException(
                MaintenanceErrorCode.InvalidManifest,
                "Every entry must declare a 64-hex 'sha256' digest.");
        }

        foreach (var character in text)
        {
            if (!Uri.IsHexDigit(character))
            {
                throw new MaintenanceException(
                    MaintenanceErrorCode.InvalidManifest,
                    "Every entry must declare a 64-hex 'sha256' digest.");
            }
        }

        return text.ToLowerInvariant();
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private sealed record DeclaredEntry(string Role, string Path, long Bytes, string Sha256);

    private sealed record ExtractionPlan(DeclaredEntry Declared, ZipArchiveEntry Entry);
}
