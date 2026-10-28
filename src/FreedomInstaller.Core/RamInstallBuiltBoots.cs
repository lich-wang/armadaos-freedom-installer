using System;
using System.Text.Json;

namespace FreedomInstaller.Core;

/// <summary>The four fixed artifacts a validated build result can expose.</summary>
public enum RamInstallExportRole
{
    BootA = 0,
    BootB = 1,
    ReportA = 2,
    ReportB = 3,
}

/// <summary>
/// One immutable artifact descriptor locked from a real succeeded build result. The constructor is
/// internal: an instance only exists after the client validated the complete proof.
/// </summary>
public sealed class RamInstallBuiltFile
{
    internal RamInstallBuiltFile(RamInstallExportRole role, long length, string sha256)
    {
        if (!Enum.IsDefined(typeof(RamInstallExportRole), role))
        {
            throw new ArgumentOutOfRangeException(nameof(role));
        }

        if (length <= 0)
        {
            throw new ArgumentException("A built artifact length must be positive.", nameof(length));
        }

        Role = role;
        Length = length;
        Sha256 = RamInstallValidation.RequireLowerSha256(sha256, nameof(sha256));
    }

    public RamInstallExportRole Role { get; }

    public long Length { get; }

    public string Sha256 { get; }
}

/// <summary>
/// One validated slot: its candidate and report descriptors plus the complete cloned builder report.
/// </summary>
public sealed class RamInstallBuiltSlot
{
    internal RamInstallBuiltSlot(
        string slot,
        RamInstallBuiltFile candidate,
        RamInstallBuiltFile report,
        JsonElement builderReport)
    {
        if (!string.Equals(slot, "a", StringComparison.Ordinal) &&
            !string.Equals(slot, "b", StringComparison.Ordinal))
        {
            throw new ArgumentException("A built slot must be exactly a or b.", nameof(slot));
        }

        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(report);

        if (builderReport.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException("A builder report must be a JSON object.", nameof(builderReport));
        }

        Slot = slot;
        Candidate = candidate;
        Report = report;
        BuilderReport = builderReport.Clone();
    }

    public string Slot { get; }

    public RamInstallBuiltFile Candidate { get; }

    public RamInstallBuiltFile Report { get; }

    /// <summary>The complete builder report clone; never a fabricated or partial object.</summary>
    public JsonElement BuilderReport { get; }
}

/// <summary>The exact <c>a</c>/<c>b</c> pair of validated built slots.</summary>
public sealed class RamInstallBuiltSlots
{
    internal RamInstallBuiltSlots(RamInstallBuiltSlot a, RamInstallBuiltSlot b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);

        if (!string.Equals(a.Slot, "a", StringComparison.Ordinal) ||
            !string.Equals(b.Slot, "b", StringComparison.Ordinal))
        {
            throw new ArgumentException("The built slots must be exactly slot a and slot b.", nameof(a));
        }

        A = a;
        B = b;
    }

    public RamInstallBuiltSlot A { get; }

    public RamInstallBuiltSlot B { get; }
}

/// <summary>
/// The complete cross-validated build proof: the real deployment checksum, the two real filesystem
/// UUIDs and the two locked slots. Internal construction happens only after the client verified every
/// relation against the live prepare/deploy/build statuses.
/// </summary>
public sealed class RamInstallBuiltBoots
{
    internal RamInstallBuiltBoots(
        string deploymentChecksum,
        string bootFilesystemUuid,
        string rootFilesystemUuid,
        RamInstallBuiltSlot a,
        RamInstallBuiltSlot b)
    {
        DeploymentChecksum = RamInstallValidation.RequireLowerSha256(
            deploymentChecksum,
            nameof(deploymentChecksum));
        BootFilesystemUuid = RamInstallValidation.NormalizeUuid(
            bootFilesystemUuid,
            nameof(bootFilesystemUuid));
        RootFilesystemUuid = RamInstallValidation.NormalizeUuid(
            rootFilesystemUuid,
            nameof(rootFilesystemUuid));
        Slots = new RamInstallBuiltSlots(a, b);
    }

    public string DeploymentChecksum { get; }

    public string BootFilesystemUuid { get; }

    public string RootFilesystemUuid { get; }

    public RamInstallBuiltSlots Slots { get; }

    /// <summary>Closed mapping from the four export roles to the four locked descriptors.</summary>
    public RamInstallBuiltFile GetArtifact(RamInstallExportRole role) => role switch
    {
        RamInstallExportRole.BootA => Slots.A.Candidate,
        RamInstallExportRole.BootB => Slots.B.Candidate,
        RamInstallExportRole.ReportA => Slots.A.Report,
        RamInstallExportRole.ReportB => Slots.B.Report,
        _ => throw new ArgumentOutOfRangeException(nameof(role), role, "Unknown export role."),
    };
}
