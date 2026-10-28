using System.Collections.Generic;

namespace FreedomInstaller.Core;

/// <summary>
/// Readiness of the Windows Qualcomm 9008 driver, as established by read-only SetupAPI and PnP queries.
/// </summary>
public enum WindowsDriverCheckState
{
    /// <summary>No matching published package and no present 9008 endpoint was proven.</summary>
    Missing,

    /// <summary>A matching NTamd64 store package exists, its signature is accepted, and no endpoint is present.</summary>
    Prepared,

    /// <summary>Every present 9008 endpoint is started, problem-free, and bound to a verified package.</summary>
    Connected,

    /// <summary>Matching evidence exists but is rejected: signature, binding, service, or device state.</summary>
    Problem,

    /// <summary>A relevant OS query failed, so readiness cannot be established either way.</summary>
    Unknown,

    /// <summary>This platform/architecture/OS version cannot be inspected here.</summary>
    Unsupported,
}

/// <summary>
/// Immutable outcome of a driver readiness probe. <see cref="DriverVersion"/> is the INF
/// <c>DriverVer</c> of the selected package (never a signer version), and <see cref="PublishedInf"/> is
/// the published <c>oem*.inf</c> file name of that package.
/// </summary>
public record WindowsDriverCheckResult(
    WindowsDriverCheckState State,
    string? DriverVersion,
    string? PublishedInf,
    string? Detail)
{
    /// <summary>
    /// True only when the driver is actually usable: a verified package is staged or a healthy endpoint is
    /// bound to one. <see cref="WindowsDriverCheckState.Problem"/>, <see cref="WindowsDriverCheckState.Unknown"/>
    /// and <see cref="WindowsDriverCheckState.Missing"/> are never ready.
    /// </summary>
    public bool IsReady => State is WindowsDriverCheckState.Prepared or WindowsDriverCheckState.Connected;
}

/// <summary>
/// One published OEM INF candidate that contains an NTamd64 model for USB VID_05C6/PID_9008, together with
/// the evidence gathered about it. <see cref="SignatureAccepted"/> alone is not trusted: the signer and
/// catalog must be present and the store location must be known.
/// </summary>
internal sealed record DriverPackageEvidence(
    string InfName,
    string StoreInfPath,
    string? DriverVersion,
    string? DigitalSigner,
    string? CatalogFile,
    bool SignatureAccepted,
    string? SignatureDetail);

/// <summary>
/// Read-only state of one present 9008 device node: its bound service, its bound published INF, and the
/// device node status from <c>CM_Get_DevNode_Status</c>. <see cref="Problem"/> is meaningful only when the
/// node carries DN_HAS_PROBLEM and is zeroed otherwise at capture time.
/// </summary>
internal sealed record DriverEndpointEvidence(
    string DeviceInstanceId,
    string? BoundInfName,
    string? Service,
    uint Status,
    uint Problem,
    bool StatusQuerySucceeded,
    string? FailureDetail);

/// <summary>
/// Everything the pure decision needs, and nothing that requires a live OS. Tests construct this shape
/// through reflection because the assembly has no InternalsVisibleTo.
/// </summary>
internal sealed record DriverEvidenceSnapshot(
    bool WindowsSupported,
    string? UnsupportedReason,
    string? PackageQueryFailure,
    string? EndpointQueryFailure,
    IReadOnlyList<DriverPackageEvidence> Packages,
    IReadOnlyList<DriverEndpointEvidence> Endpoints);
