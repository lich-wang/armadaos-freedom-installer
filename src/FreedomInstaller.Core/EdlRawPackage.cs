using System.Collections.ObjectModel;

namespace FreedomInstaller.Core;

/// <summary>
/// Immutable declaration metadata of a schema 2 direct EDL raw package, as approved in API-v3
/// (package schema 2 metadata declarations).
/// <para>
/// The Android profile fields and <see cref="FirmwareVersions"/> are one optional, coupled declaration
/// group: a standard common package declares none of them, in which case the three profile strings are
/// <c>null</c> and the firmware list is empty. A package that declares the group is checked strictly.
/// Neither form is a device trust, loader, Complete or readiness statement.
/// </para>
/// <para>
/// This object is metadata only. It is not a Ready flag, not a device proof and it retains no file
/// handle or lease. <see cref="PackageReader.ReadEdlRawContract"/> validates the declarations and the
/// actual compressed/ordinary file length and SHA-256; expansion, gzip completeness, filesystem
/// superblocks, final DTB properties and deployment contents stay with the downstream
/// expansion/Prepared implementation.
/// </para>
/// </summary>
public sealed class EdlRawPackageContract
{
    internal EdlRawPackageContract(
        string packageDirectory,
        string packageId,
        string version,
        string deviceModel,
        string sourceCommit,
        bool testOnly,
        string manifestFingerprint,
        PackageStorage storage,
        string? edlProfileId,
        string? hardwareId,
        string? androidBuild,
        IEnumerable<string> firmwareVersions,
        IReadOnlyDictionary<string, EdlRawArtifact> artifacts,
        EdlRawImage bootImage,
        EdlRawImage rootImage,
        EdlRawDeployment deployment,
        EdlRawBootRecipe bootRecipe)
    {
        PackageDirectory = packageDirectory;
        PackageId = packageId;
        Version = version;
        DeviceModel = deviceModel;
        SourceCommit = sourceCommit;
        TestOnly = testOnly;
        ManifestFingerprint = manifestFingerprint;
        Storage = storage;
        EdlProfileId = edlProfileId;
        HardwareId = hardwareId;
        AndroidBuild = androidBuild;
        FirmwareVersions = new List<string>(firmwareVersions).AsReadOnly();
        Artifacts = new ReadOnlyDictionary<string, EdlRawArtifact>(
            new Dictionary<string, EdlRawArtifact>(artifacts, StringComparer.Ordinal));
        BootImage = bootImage;
        RootImage = rootImage;
        Deployment = deployment;
        BootRecipe = bootRecipe;
    }

    /// <summary>Full, resolved path of the validated package directory.</summary>
    public string PackageDirectory { get; }

    /// <summary>Declared <c>packageId</c>.</summary>
    public string PackageId { get; }

    /// <summary>Declared <c>version</c>, never <c>latest</c>.</summary>
    public string Version { get; }

    /// <summary>
    /// Canonical <c>deviceModel</c> as resolved through the shared package model map. The map entry is a
    /// package platform tag, not a validation of real device or DTB compatibility.
    /// </summary>
    public string DeviceModel { get; }

    /// <summary>The exact pinned lower 40-hex source revision declared by the package.</summary>
    public string SourceCommit { get; }

    /// <summary>
    /// Declared <c>testOnly</c> flag. A false value is only a declaration: it is not a readiness,
    /// trust or deployability statement produced by this reader.
    /// </summary>
    public bool TestOnly { get; }

    /// <summary>SHA-256 of the raw package.json bytes, uppercase hexadecimal.</summary>
    public string ManifestFingerprint { get; }

    /// <summary>The four declared storage integers, unchanged from the package contract.</summary>
    public PackageStorage Storage { get; }

    /// <summary>Declared <c>edlProfile.id</c>; <c>null</c> when the optional group is absent.</summary>
    public string? EdlProfileId { get; }

    /// <summary>Declared <c>edlProfile.hardwareId</c>: 16 hex digits, canonical upper case on return;
    /// <c>null</c> when the optional group is absent. A declaration only; it is not a hardware trust or
    /// loader identity statement.</summary>
    public string? HardwareId { get; }

    /// <summary>Declared <c>edlProfile.androidBuild</c>, the complete string as declared; <c>null</c>
    /// when the optional group is absent.</summary>
    public string? AndroidBuild { get; }

    /// <summary>
    /// Declared <c>bootCompatibility.firmwareVersions</c>, as a read-only copy in declared order. Every
    /// entry is a complete declared build; one of them is the declared <see cref="AndroidBuild"/>. Empty
    /// when the optional group is absent.
    /// </summary>
    public IReadOnlyList<string> FirmwareVersions { get; }

    /// <summary>All seven declared artifacts, keyed by role with an ordinal comparer.</summary>
    public IReadOnlyDictionary<string, EdlRawArtifact> Artifacts { get; }

    /// <summary>The <c>linux-boot-raw</c> role: compressed file identity plus expanded declarations.</summary>
    public EdlRawImage BootImage { get; }

    /// <summary>The <c>linux-root-raw</c> role: compressed file identity plus expanded declarations.</summary>
    public EdlRawImage RootImage { get; }

    /// <summary>Declared direct EDL deployment facts.</summary>
    public EdlRawDeployment Deployment { get; }

    /// <summary>Declared boot recipe of the two raw images.</summary>
    public EdlRawBootRecipe BootRecipe { get; }
}

/// <summary>
/// One declared artifact: the role, its relative path, the resolved full path and the observed length
/// and SHA-256 of the actual file. Metadata only; it never represents an open file.
/// </summary>
public sealed class EdlRawArtifact
{
    internal EdlRawArtifact(string role, string relativePath, string fullPath, long bytes, string sha256)
    {
        Role = role;
        RelativePath = relativePath;
        FullPath = fullPath;
        Bytes = bytes;
        Sha256 = sha256;
    }

    /// <summary>Contract role, one of the seven exact schema 2 role names.</summary>
    public string Role { get; }

    /// <summary>Declared relative path inside the package directory.</summary>
    public string RelativePath { get; }

    /// <summary>Resolved full path of the file that was hashed.</summary>
    public string FullPath { get; }

    /// <summary>Observed file length in bytes.</summary>
    public long Bytes { get; }

    /// <summary>Observed SHA-256 of the file, uppercase hexadecimal.</summary>
    public string Sha256 { get; }
}

/// <summary>
/// One of the two compressed raw images. <see cref="CompressedBytes"/> and
/// <see cref="CompressedSha256"/> describe the gzip file on disk; <see cref="ExpandedBytes"/> and
/// <see cref="ExpandedSha256"/> are the declared uncompressed image and are not verified by this
/// reader. No sparse image, decoder or filesystem rewrite is implied.
/// </summary>
public sealed class EdlRawImage
{
    internal EdlRawImage(
        EdlRawArtifact artifact,
        string compression,
        long compressedBytes,
        string compressedSha256,
        long expandedBytes,
        string expandedSha256,
        int sectorSize,
        string fsType,
        Guid fsUuid,
        long minimumPartitionBytes)
    {
        Artifact = artifact;
        Compression = compression;
        CompressedBytes = compressedBytes;
        CompressedSha256 = compressedSha256;
        ExpandedBytes = expandedBytes;
        ExpandedSha256 = expandedSha256;
        SectorSize = sectorSize;
        FsType = fsType;
        FsUuid = fsUuid;
        MinimumPartitionBytes = minimumPartitionBytes;
    }

    /// <summary>The underlying declared artifact (role, path, observed compressed length and hash).</summary>
    public EdlRawArtifact Artifact { get; }

    /// <summary>Declared <c>compression</c>; the schema 2 raw roles only accept gzip.</summary>
    public string Compression { get; }

    /// <summary>Declared compressed file length; equal to <see cref="EdlRawArtifact.Bytes"/>.</summary>
    public long CompressedBytes { get; }

    /// <summary>Declared compressed file SHA-256; equal to <see cref="EdlRawArtifact.Sha256"/>.</summary>
    public string CompressedSha256 { get; }

    /// <summary>Declared uncompressed image length.</summary>
    public long ExpandedBytes { get; }

    /// <summary>Declared uncompressed image SHA-256 (verified downstream, not by this reader).</summary>
    public string ExpandedSha256 { get; }

    /// <summary>Declared sector size of the expanded filesystem.</summary>
    public int SectorSize { get; }

    /// <summary>Declared filesystem type of the expanded image.</summary>
    public string FsType { get; }

    /// <summary>Package-fixed filesystem UUID. Never a per-install GPT PARTUUID.</summary>
    public Guid FsUuid { get; }

    /// <summary>Declared minimum partition size for the expanded image.</summary>
    public long MinimumPartitionBytes { get; }
}

/// <summary>Declared direct EDL deployment facts. <see cref="Commit"/> and <see cref="BootChecksum"/>
/// are separate producer facts; equality is not assumed.</summary>
public sealed class EdlRawDeployment
{
    internal EdlRawDeployment(string kind, string commit, string manifestDigest, string origin, string bootChecksum)
    {
        Kind = kind;
        Commit = commit;
        ManifestDigest = manifestDigest;
        Origin = origin;
        BootChecksum = bootChecksum;
    }

    /// <summary>Declared deployment kind; schema 2 accepts only <c>edl-raw-v1</c>.</summary>
    public string Kind { get; }

    /// <summary>Lowercase 64-hex ostree commit of the deployed tree.</summary>
    public string Commit { get; }

    /// <summary><c>sha256:</c> prefixed lowercase 64-hex manifest digest.</summary>
    public string ManifestDigest { get; }

    /// <summary>Project OSTree origin the package was produced from.</summary>
    public string Origin { get; }

    /// <summary>Lowercase 64-hex boot checksum used by the ostree deployment path.</summary>
    public string BootChecksum { get; }
}

/// <summary>Declared boot recipe of the two raw images: the package-fixed filesystem UUIDs and the two
/// complete boot argument strings.</summary>
public sealed class EdlRawBootRecipe
{
    internal EdlRawBootRecipe(
        Guid bootUuid,
        Guid rootUuid,
        string normalBootArgs,
        string diagnosticBootArgs,
        string defaultEntry)
    {
        BootUuid = bootUuid;
        RootUuid = rootUuid;
        NormalBootArgs = normalBootArgs;
        DiagnosticBootArgs = diagnosticBootArgs;
        DefaultEntry = defaultEntry;
    }

    /// <summary>Filesystem UUID of the boot image; must match <see cref="EdlRawImage.FsUuid"/>.</summary>
    public Guid BootUuid { get; }

    /// <summary>Filesystem UUID of the root image; must match <see cref="EdlRawImage.FsUuid"/>.</summary>
    public Guid RootUuid { get; }

    /// <summary>Complete single-line normal boot arguments.</summary>
    public string NormalBootArgs { get; }

    /// <summary>Complete diagnostic boot arguments: either the normal arguments plus the exact legacy
    /// diagnostic suffix, or, for the canonical <c>TB323FU</c> model only, the exact G5 verbose form of
    /// the normal arguments. The declared string is kept verbatim.</summary>
    public string DiagnosticBootArgs { get; }

    /// <summary>Declared default boot entry; schema 2 accepts only <c>android</c>.</summary>
    public string DefaultEntry { get; }
}
