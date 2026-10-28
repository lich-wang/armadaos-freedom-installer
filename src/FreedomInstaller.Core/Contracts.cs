namespace FreedomInstaller.Core;

/// <summary>Bootloader lock state as reported by fastboot / getprop, or Unknown when the report is missing or contradictory.</summary>
public enum BootloaderState
{
    Unknown = 0,
    Locked = 1,
    Unlocked = 2,
}

/// <summary>How far the transport handshake with a device got.</summary>
public enum ConnectionState
{
    Authorized = 0,
    Unauthorized = 1,
    Offline = 2,
}

/// <summary>One device line of <c>adb devices</c>.</summary>
public sealed record ConnectedDevice(string Serial, ConnectionState ConnectionState);

/// <summary>Identity confirmed by the user before any write is allowed.</summary>
public sealed record DeviceIdentity(string Serial, string Model, BootloaderState BootloaderState)
{
    /// <summary>
    /// Read-only firmware snapshot captured from the same getprop dump that produced
    /// <see cref="Model"/>, or null when the identity was built without one. It is informational only: the
    /// lock state it carries is what Android reported, so it can never open the readiness gate or stand in
    /// for <see cref="BootloaderState"/>, which stays <see cref="BootloaderState.Unknown"/> until fastboot
    /// confirms it.
    /// </summary>
    public FirmwareSnapshot? Firmware { get; init; }
}

/// <summary>One row of a device partition table. Sectors are absolute and sector based, never floats.</summary>
public sealed record DiskPartition(
    long Number,
    string Name,
    long StartSector,
    long SectorCount,
    string TypeGuid,
    string PartUuid);

/// <summary>Read-only snapshot of the partition table reported by the device.</summary>
public sealed record DiskLayout(string DeviceId, int SectorSize, IReadOnlyList<DiskPartition> Partitions);

/// <summary>Space the installation package requires, declared by package metadata.</summary>
public sealed record PackageStorage(
    long LinuxBootBytes,
    long SystemRequiredBytes,
    long DeploymentScratchBytes,
    long MinimumLinuxDataBytes);

/// <summary>
/// Result of <see cref="PartitionPlanner.Plan"/>. Sector fields are absolute disk sectors,
/// so a caller can write them into a partition table without re-deriving the userdata extent.
/// </summary>
public sealed record AllocationPlan(
    long AndroidBytes,
    long LinuxBytes,
    long LinuxBootBytes,
    long LinuxRootBytes,
    long EstimatedLinuxDataBytes,
    long UserdataStartSector,
    long AndroidSectorCount,
    long LinuxBootStartSector,
    long LinuxRootStartSector,
    long EndSectorExclusive);

/// <summary>Installation gate. When <see cref="IsReady"/> is false, <see cref="Reasons"/> is non-empty and names every blocker.</summary>
public sealed record Readiness(bool IsReady, IReadOnlyList<string> Reasons);

/// <summary>
/// Result of <see cref="PackageReader.Validate"/>.
/// <para>
/// <see cref="IsValid"/> means one thing only: the package.json of this directory is structurally
/// complete and every declared artefact is present with the declared length and SHA-256 under the
/// package contract v1. It says nothing about the package being trusted, about it being deployable on a
/// particular unit, or about the device being able to boot it.
/// </para>
/// <para>
/// <see cref="Storage"/> is present only when the whole package validated; it is never inferred from a
/// package that failed validation of its files. <see cref="TestOnly"/> defaults to <c>true</c> so a
/// missing flag can never be read as a production package: the real write backend must refuse any
/// package where it is <c>true</c>.
/// </para>
/// </summary>
public sealed record PackageValidationResult
{
    /// <summary>
    /// Creates a result. The three positional values keep their previous meaning; the contract
    /// metadata below is filled in through init-only properties and only for a fully valid package.
    /// </summary>
    public PackageValidationResult(bool isValid, IReadOnlyList<string> reasons, PackageStorage? storage)
    {
        IsValid = isValid;
        Reasons = reasons;
        Storage = storage;
    }

    /// <summary>Structural completeness of the package directory. Never a trust or deployability statement.</summary>
    public bool IsValid { get; }

    /// <summary>Every reason the package was rejected. Non-empty whenever <see cref="IsValid"/> is false.</summary>
    public IReadOnlyList<string> Reasons { get; }

    /// <summary>Storage declaration of the package. Non-null only for a fully valid package.</summary>
    public PackageStorage? Storage { get; }

    /// <summary>
    /// package.json <c>testOnly</c> flag. Fail-safe default is <c>true</c>, so a result that never got
    /// as far as reading the flag still looks like a test package and not like a production one.
    /// </summary>
    public bool TestOnly { get; init; } = true;

    /// <summary>Declared <c>packageId</c>. Filled only when the whole package validated.</summary>
    public string? PackageId { get; init; }

    /// <summary>Declared <c>version</c> (never <c>latest</c>). Filled only when the whole package validated.</summary>
    public string? Version { get; init; }

    /// <summary>
    /// SHA-256 of the raw package.json bytes, uppercase hexadecimal. Fingerprints the exact manifest
    /// that was accepted; filled only when the whole package validated.
    /// </summary>
    public string? ManifestFingerprint { get; init; }

    /// <summary>
    /// Validated package route metadata, filled only when the whole package validated:
    /// <c>edl-raw-v1</c> for a schema 2 direct EDL raw package, <c>null</c> for a schema 1 offline seed
    /// package and for every invalid result. It is a routing hint, not a Ready flag, not a held-image or
    /// device proof, and it never replaces the downstream expansion and device checks.
    /// </summary>
    public string? DeploymentKind { get; init; }
}
