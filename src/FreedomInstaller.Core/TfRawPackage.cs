using System.Collections.ObjectModel;

namespace FreedomInstaller.Core;

/// <summary>
/// Immutable view of a validated schema 2 TF-card raw package. It wraps the shared
/// <see cref="EdlRawPackageContract"/> of the same strict parser and adds only the TF-specific facts:
/// the <c>tf</c> root medium and the nonzero source internal boot/root UUID pair the TF boot and root
/// filesystems must differ from.
/// <para>
/// <see cref="MaintenanceInitramfs"/> is only the lookup result of the optional
/// <c>tf-maintenance-initramfs</c> role in <see cref="EdlRawPackageContract.Artifacts"/>; it is
/// <c>null</c> when that role is absent. Its presence is metadata and file-hash validation only: it is
/// NOT evidence of a valid RAM initramfs, an adequate boot budget, a disk, a held expanded image, a
/// Ready state, a boot chain, a device or a completion proof.
/// </para>
/// </summary>
public sealed class TfRawPackageContract
{
    internal TfRawPackageContract(
        EdlRawPackageContract raw,
        string rootMedium,
        Guid sourceInternalBootUuid,
        Guid sourceInternalRootUuid)
    {
        Raw = raw;
        RootMedium = rootMedium;
        SourceInternalBootUuid = sourceInternalBootUuid;
        SourceInternalRootUuid = sourceInternalRootUuid;

        MaintenanceInitramfs = raw.Artifacts.TryGetValue(
            PackageReader.TfRawMaintenanceInitramfsRole,
            out var maintenance)
            ? maintenance
            : null;
    }

    /// <summary>The validated shared schema-2 contract this TF view is built on.</summary>
    public EdlRawPackageContract Raw { get; }

    /// <summary>The declared <c>bootRecipe.rootMedium</c>; this target accepts exactly <c>tf</c>.</summary>
    public string RootMedium { get; }

    /// <summary>Nonzero GUID-D <c>sourceInternalBootUuid</c> the TF boot filesystem must differ from.</summary>
    public Guid SourceInternalBootUuid { get; }

    /// <summary>Nonzero GUID-D <c>sourceInternalRootUuid</c> the TF root filesystem must differ from.</summary>
    public Guid SourceInternalRootUuid { get; }

    /// <summary>
    /// The optional <c>tf-maintenance-initramfs</c> artifact, or <c>null</c> when the package declares
    /// only the seven shared roles. A lookup only: no content, budget or boot validity is implied.
    /// </summary>
    public EdlRawArtifact? MaintenanceInitramfs { get; }

    /// <summary>Full, resolved path of the validated package directory.</summary>
    public string PackageDirectory => Raw.PackageDirectory;

    /// <summary>Declared <c>packageId</c>.</summary>
    public string PackageId => Raw.PackageId;

    /// <summary>Declared <c>version</c>, never <c>latest</c>.</summary>
    public string Version => Raw.Version;

    /// <summary>Canonical <c>deviceModel</c> as resolved through the shared package model map.</summary>
    public string DeviceModel => Raw.DeviceModel;

    /// <summary>SHA-256 of the raw package.json bytes, uppercase hexadecimal.</summary>
    public string ManifestFingerprint => Raw.ManifestFingerprint;

    /// <summary>The four declared storage integers, unchanged from the package contract.</summary>
    public PackageStorage Storage => Raw.Storage;

    /// <summary>All declared artifacts, keyed by role with an ordinal comparer.</summary>
    public IReadOnlyDictionary<string, EdlRawArtifact> Artifacts => Raw.Artifacts;

    /// <summary>The <c>linux-boot-raw</c> role: compressed file identity plus expanded declarations.</summary>
    public EdlRawImage BootImage => Raw.BootImage;

    /// <summary>The <c>linux-root-raw</c> role: compressed file identity plus expanded declarations.</summary>
    public EdlRawImage RootImage => Raw.RootImage;

    /// <summary>Declared deployment facts; the kind stays exactly <c>tf-raw-v1</c>.</summary>
    public EdlRawDeployment Deployment => Raw.Deployment;

    /// <summary>Declared boot recipe of the two raw images, bound to the <c>tf</c> root medium.</summary>
    public EdlRawBootRecipe BootRecipe => Raw.BootRecipe;
}
