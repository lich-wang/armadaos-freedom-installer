using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace FreedomInstaller.Core;

/// <summary>
/// The optional frozen boot-material block of a RAM install request. Every value is immutable, already
/// validated and serialized with exactly the wire keys; there is no caller path, profile, budget or raw
/// limit knob.
/// </summary>
/// <remarks>
/// The block attests ten partition descriptors (five per slot), the selected runtime and the selected
/// package's Linux assets. The helper still re-verifies every mapping, length and byte digest against the
/// real partition/asset before any write; this object is a claim bound to the request, not authority.
/// </remarks>
public sealed class RamInstallBootConfig
{
    /// <summary>The only accepted boot block schema version.</summary>
    public const int BootSchemaVersion = 1;

    /// <summary>The exact runtime length fixed by the frozen wire.</summary>
    public const long RuntimeLength = 4194304L;

    /// <exception cref="ArgumentException">A slot, digest, length or PARTUUID violates the contract.</exception>
    public RamInstallBootConfig(
        RamInstallBootSlot a,
        RamInstallBootSlot b,
        RamInstallFileIdentity runtime,
        RamInstallLinuxArtifacts linux)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);
        ArgumentNullException.ThrowIfNull(runtime);
        ArgumentNullException.ThrowIfNull(linux);

        if (!string.Equals(a.Slot, "a", StringComparison.Ordinal) ||
            !string.Equals(b.Slot, "b", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The boot slots must be exactly slot a and slot b.",
                nameof(a));
        }

        if (runtime.Length != RuntimeLength)
        {
            throw new ArgumentException(
                "boot.runtime.length must be exactly " + RuntimeLength + " bytes.",
                nameof(runtime));
        }

        var partUuids = new HashSet<string>(StringComparer.Ordinal);
        foreach (RamInstallPartitionMaterial material in a.Materials)
        {
            if (!partUuids.Add(material.PartUuid))
            {
                throw new ArgumentException("All ten boot material PARTUUIDs must be distinct.");
            }
        }

        foreach (RamInstallPartitionMaterial material in b.Materials)
        {
            if (!partUuids.Add(material.PartUuid))
            {
                throw new ArgumentException("All ten boot material PARTUUIDs must be distinct.");
            }
        }

        Slots = new RamInstallBootSlots(a, b);
        Runtime = runtime;
        Linux = linux;
    }

    [JsonPropertyName("schemaVersion")]
    public int SchemaVersion => BootSchemaVersion;

    [JsonPropertyName("slots")]
    public RamInstallBootSlots Slots { get; }

    [JsonPropertyName("runtime")]
    public RamInstallFileIdentity Runtime { get; }

    [JsonPropertyName("linux")]
    public RamInstallLinuxArtifacts Linux { get; }
}

/// <summary>The exact <c>a</c>/<c>b</c> slot pair. No other slot key is representable.</summary>
public sealed class RamInstallBootSlots
{
    /// <exception cref="ArgumentException">The pair is not exactly slot a plus slot b.</exception>
    public RamInstallBootSlots(RamInstallBootSlot a, RamInstallBootSlot b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);

        if (!string.Equals(a.Slot, "a", StringComparison.Ordinal) ||
            !string.Equals(b.Slot, "b", StringComparison.Ordinal))
        {
            throw new ArgumentException("The boot slots must be exactly slot a and slot b.", nameof(a));
        }

        A = a;
        B = b;
    }

    [JsonPropertyName("a")]
    public RamInstallBootSlot A { get; }

    [JsonPropertyName("b")]
    public RamInstallBootSlot B { get; }
}

/// <summary>
/// The five material descriptors of one slot. Each descriptor carries the same <c>slot</c> value, and
/// that value appears only inside the descriptors, never as a sixth slot-level key.
/// </summary>
public sealed class RamInstallBootSlot
{
    /// <exception cref="ArgumentException">A descriptor is null, has another slot, or mixes slots.</exception>
    public RamInstallBootSlot(
        RamInstallPartitionMaterial currentBoot,
        RamInstallPartitionMaterial vendorBoot,
        RamInstallPartitionMaterial initBoot,
        RamInstallPartitionMaterial abl,
        RamInstallPartitionMaterial xblConfig)
    {
        ArgumentNullException.ThrowIfNull(currentBoot);
        ArgumentNullException.ThrowIfNull(vendorBoot);
        ArgumentNullException.ThrowIfNull(initBoot);
        ArgumentNullException.ThrowIfNull(abl);
        ArgumentNullException.ThrowIfNull(xblConfig);

        string slot = currentBoot.Slot;
        RequireSameSlot(slot, vendorBoot);
        RequireSameSlot(slot, initBoot);
        RequireSameSlot(slot, abl);
        RequireSameSlot(slot, xblConfig);

        Slot = slot;
        CurrentBoot = currentBoot;
        VendorBoot = vendorBoot;
        InitBoot = initBoot;
        Abl = abl;
        XblConfig = xblConfig;
    }

    /// <summary>The descriptor slot (<c>a</c> or <c>b</c>). Never serialized at slot level.</summary>
    [JsonIgnore]
    public string Slot { get; }

    [JsonPropertyName("currentBoot")]
    public RamInstallPartitionMaterial CurrentBoot { get; }

    [JsonPropertyName("vendorBoot")]
    public RamInstallPartitionMaterial VendorBoot { get; }

    [JsonPropertyName("initBoot")]
    public RamInstallPartitionMaterial InitBoot { get; }

    [JsonPropertyName("abl")]
    public RamInstallPartitionMaterial Abl { get; }

    [JsonPropertyName("xblConfig")]
    public RamInstallPartitionMaterial XblConfig { get; }

    internal IReadOnlyList<RamInstallPartitionMaterial> Materials =>
        new[] { CurrentBoot, VendorBoot, InitBoot, Abl, XblConfig };

    private static void RequireSameSlot(string slot, RamInstallPartitionMaterial material)
    {
        if (!string.Equals(material.Slot, slot, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Every descriptor of one boot slot must carry that slot.",
                nameof(material));
        }
    }
}

/// <summary>
/// One original partition material: the exact slot, canonical PARTUUID, full original partition byte
/// length and lowercase SHA-256. The length is never a trimmed kernel or header length.
/// </summary>
public sealed class RamInstallPartitionMaterial
{
    /// <exception cref="ArgumentException">A field is outside the frozen contract.</exception>
    public RamInstallPartitionMaterial(string slot, string partUuid, long length, string sha256)
    {
        if (!string.Equals(slot, "a", StringComparison.Ordinal) &&
            !string.Equals(slot, "b", StringComparison.Ordinal))
        {
            throw new ArgumentException("A boot descriptor slot must be exactly a or b.", nameof(slot));
        }

        if (length <= 0)
        {
            throw new ArgumentException(
                "A boot descriptor length must be a positive 64-bit byte count.",
                nameof(length));
        }

        Slot = slot;
        PartUuid = RamInstallValidation.NormalizeUuid(partUuid, nameof(partUuid));
        Length = length;
        Sha256 = RamInstallValidation.RequireLowerSha256(sha256, nameof(sha256));
    }

    [JsonPropertyName("slot")]
    public string Slot { get; }

    [JsonPropertyName("partUuid")]
    public string PartUuid { get; }

    [JsonPropertyName("length")]
    public long Length { get; }

    [JsonPropertyName("sha256")]
    public string Sha256 { get; }
}

/// <summary>A positive byte length plus a lowercase SHA-256. Used by the runtime and Linux assets.</summary>
public sealed class RamInstallFileIdentity
{
    /// <exception cref="ArgumentException">The length or digest is outside the frozen contract.</exception>
    public RamInstallFileIdentity(long length, string sha256)
    {
        if (length <= 0)
        {
            throw new ArgumentException("A file identity length must be a positive 64-bit byte count.", nameof(length));
        }

        Length = length;
        Sha256 = RamInstallValidation.RequireLowerSha256(sha256, nameof(sha256));
    }

    [JsonPropertyName("length")]
    public long Length { get; }

    [JsonPropertyName("sha256")]
    public string Sha256 { get; }
}

/// <summary>The three selected-package Linux assets attested by the request.</summary>
public sealed class RamInstallLinuxArtifacts
{
    /// <exception cref="ArgumentException">An asset identity is null or invalid.</exception>
    public RamInstallLinuxArtifacts(
        RamInstallFileIdentity kernel,
        RamInstallFileIdentity dtb,
        RamInstallFileIdentity initramfs)
    {
        ArgumentNullException.ThrowIfNull(kernel);
        ArgumentNullException.ThrowIfNull(dtb);
        ArgumentNullException.ThrowIfNull(initramfs);

        Kernel = kernel;
        Dtb = dtb;
        Initramfs = initramfs;
    }

    [JsonPropertyName("kernel")]
    public RamInstallFileIdentity Kernel { get; }

    [JsonPropertyName("dtb")]
    public RamInstallFileIdentity Dtb { get; }

    [JsonPropertyName("initramfs")]
    public RamInstallFileIdentity Initramfs { get; }
}
