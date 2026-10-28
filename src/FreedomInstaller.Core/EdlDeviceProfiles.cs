using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace FreedomInstaller.Core;

/// <summary>How the trusted profile reaches Firehose: one bundled loader or a Sahara XML program set.</summary>
public enum EdlLoaderKind
{
    Single,
    SaharaXml
}

/// <summary>
/// One reviewed loader payload of a trusted EDL profile. Metadata only: nothing here is read from,
/// staged into or uploaded to a device.
/// </summary>
public sealed class EdlLoaderMaterial
{
    internal EdlLoaderMaterial(string role, uint? imageId, string relativePath, long bytes, string sha256)
    {
        Role = role;
        ImageId = imageId;
        RelativePath = relativePath;
        Bytes = bytes;
        Sha256 = sha256;
    }

    /// <summary>Logical role, for example <c>firehose</c> or <c>image36</c>.</summary>
    public string Role { get; }

    /// <summary>Programmer image id when the payload declares one; null for the Sahara XML itself.</summary>
    public uint? ImageId { get; }

    /// <summary>Archive-relative path of the payload inside the profile's tool archive.</summary>
    public string RelativePath { get; }

    /// <summary>Reviewed payload length in bytes.</summary>
    public long Bytes { get; }

    /// <summary>Reviewed lowercase 64-hex SHA-256 digest.</summary>
    public string Sha256 { get; }
}

/// <summary>
/// An immutable, statically known EDL device profile. Construction is internal, so the only instances
/// are the reviewed entries of <see cref="EdlDeviceProfiles"/>; there is no registry to mutate and no
/// external enabled switch.
/// <para>
/// <see cref="IsComplete"/> describes the known static configuration only. It is never a live-device
/// proof, and a complete profile is still checked against the actual identity before any device work.
/// </para>
/// </summary>
public sealed class EdlDeviceProfile
{
    internal EdlDeviceProfile(
        string profileId,
        string model,
        string soc,
        string? fullHardwareId,
        IReadOnlyList<string> allowedDisplayIds,
        EdlLoaderKind loaderKind,
        string loaderEntryPath,
        IReadOnlyList<EdlLoaderMaterial> materials,
        string? archiveLogicalName,
        bool isComplete)
    {
        ProfileId = profileId;
        Model = model;
        Soc = soc;
        FullHardwareId = fullHardwareId;
        AllowedDisplayIds = allowedDisplayIds;
        LoaderKind = loaderKind;
        LoaderEntryPath = loaderEntryPath;
        Materials = materials;
        ArchiveLogicalName = archiveLogicalName;
        IsComplete = isComplete;
    }

    public string ProfileId { get; }

    public string Model { get; }

    public string Soc { get; }

    /// <summary>The exact full hardware id, or null while the trusted value is unknown.</summary>
    public string? FullHardwareId { get; }

    /// <summary>
    /// Strict source builds pinned to the bundled loader archive. This is loader-toolset provenance,
    /// never the currently booted Android firmware; it is empty only for a profile whose loader source
    /// build is still unknown.
    /// </summary>
    public IReadOnlyList<string> AllowedDisplayIds { get; }

    public EdlLoaderKind LoaderKind { get; }

    /// <summary>Archive-relative entry path of the loader.</summary>
    public string LoaderEntryPath { get; }

    public IReadOnlyList<EdlLoaderMaterial> Materials { get; }

    /// <summary>
    /// Logical name of the bundled tool archive, or null when no archive is bundled for this profile yet.
    /// This is a resource name, never a filesystem path.
    /// </summary>
    public string? ArchiveLogicalName { get; }

    /// <summary>
    /// True only when the static identity and material configuration is fully known. This is not a
    /// statement that any device, loader or Firehose session exists.
    /// </summary>
    public bool IsComplete { get; }

    /// <summary>
    /// True only for a complete profile whose canonical model matches exactly and whose device reports a
    /// non-blank actual firmware display id. The model comparison is ordinal: no wildcard, prefix,
    /// case-insensitive or trimmed matching. The display id is the device's current build and may differ
    /// from the bundled loader's source build.
    /// </summary>
    public bool SupportsIdentity(DeviceIdentity identity)
    {
        if (identity is null || !IsComplete)
        {
            return false;
        }

        if (!string.Equals(identity.Model, Model, StringComparison.Ordinal))
        {
            return false;
        }

        return !string.IsNullOrWhiteSpace(identity.Firmware?.DisplayId);
    }

    /// <summary>
    /// Fails closed for an incomplete profile. Callers run this before any hardware command so a
    /// preparation-only definition can never reach a device.
    /// </summary>
    /// <exception cref="InvalidOperationException">The profile is incomplete.</exception>
    public void RequireComplete()
    {
        if (!IsComplete)
        {
            throw new InvalidOperationException(
                $"EDL profile '{ProfileId}' is incomplete; its identity and loader materials are not fully known.");
        }
    }
}

/// <summary>
/// The reviewed static EDL profile table. Read-only: there is no registration, no plugin hook and no
/// external switch, and looking a profile up grants no permission to operate a device.
/// </summary>
public static class EdlDeviceProfiles
{
    /// <summary>
    /// The existing G4 profile. It is the default built-in definition and is never switched
    /// automatically.
    /// </summary>
    public static EdlDeviceProfile Default { get; } = new EdlDeviceProfile(
        "g4-9008-259",
        "TB322FC",
        "SM8750",
        "0028D0E100400000",
        Immutable("TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.259_ST_260611"),
        EdlLoaderKind.Single,
        "tools/firehose.melf",
        Immutable(
            new EdlLoaderMaterial(
                "firehose",
                13u,
                "tools/firehose.melf",
                1697740L,
                "a38993803139d881f47adfa66309f8d5e545c2e33eb4576d0a585afae9cd3da0")),
        "FreedomInstaller.EdlTools.zip",
        isComplete: true);

    /// <summary>
    /// The G5 profile. Its static identity, loader pins and bundled archive are fully reviewed, so
    /// <see cref="EdlDeviceProfile.IsComplete"/> is true for the configuration only: that flag never
    /// asserts a live device, a loader transfer or a Firehose session, and every hardware step is still
    /// mandatory at run time against the actual device identity.
    /// </summary>
    private static EdlDeviceProfile G5 { get; } = new EdlDeviceProfile(
        "g5-9008-y7005",
        "TB323FU",
        "SM8850",
        "002B40E100400000",
        Immutable("QCTool-2026.3.21-1/lenovo/devprg_legion-y700-5"),
        EdlLoaderKind.SaharaXml,
        "tools/g5/qsahara_device_programmer.xml",
        Immutable(
            new EdlLoaderMaterial(
                "firehose",
                null,
                "tools/g5/qsahara_device_programmer.xml",
                564L,
                "433749ae084aa0f1b4016b29619b0b0c377d4b2cd22d8a48b423ca6d9cbc83ca"),
            new EdlLoaderMaterial(
                "image36",
                36u,
                "tools/g5/multi_image_qti.mbn",
                12088L,
                "a98c7ae167f5d0daf947dc707e3c3679ea438f30ea6ebc510edf15655a14d223"),
            new EdlLoaderMaterial(
                "image37",
                37u,
                "tools/g5/multi_image.mbn",
                12088L,
                "9dd679f3b38e59af6a7e22598ed85a1918cad41a0af84eac2c33e1b02d6166f8"),
            new EdlLoaderMaterial(
                "image21",
                21u,
                "tools/g5/xbl_sc.elf",
                1174496L,
                "5d277384cac8fb1512562028ca30c67b2314810ad26b2546a6c8653119a056d4"),
            new EdlLoaderMaterial(
                "image60",
                60u,
                "tools/g5/signed_firmware_soc_view.elf",
                203840L,
                "dbfdf2602cadb02fe8272abbce55f3f804ad1e98a8481586bf40fa1cbe2960e3"),
            new EdlLoaderMaterial(
                "image59",
                59u,
                "tools/g5/sequencer_ram.elf",
                4864L,
                "d7dc67ddd77332e558d14b7acb82bc42e1be66a07786403c96b655f46d019636"),
            new EdlLoaderMaterial(
                "image61",
                61u,
                "tools/g5/tme_config.elf",
                43760L,
                "91f17966306617d1a47336ada238865d4faea014a12edc92f08ea79a773e667a"),
            new EdlLoaderMaterial(
                "image13",
                13u,
                "tools/g5/prog_firehose_ddr.elf",
                315384L,
                "109338f05b2597b1238f8b724f400f6753a393f6d84c5c534ff36294bbc2da3e"),
            new EdlLoaderMaterial(
                "image38",
                38u,
                "tools/g5/xbl_config_devprg.elf",
                180928L,
                "199e60752d9f0db398bbc3524839a627f3ae32ab47fb58b90df124b3e0affbbb")),
        "FreedomInstaller.EdlTools.G5.zip",
        isComplete: true);

    /// <summary>The supported models, in the frozen order, as a read-only list.</summary>
    public static IReadOnlyList<string> Models { get; } = Immutable("TB322FC", "TB323FU");

    /// <summary>
    /// Exact ordinal profile lookup. A null, blank or unknown id returns null; a differently cased or
    /// padded id is unknown rather than corrected.
    /// </summary>
    public static EdlDeviceProfile? FindById(string? profileId)
    {
        if (profileId is null)
        {
            return null;
        }

        if (string.Equals(profileId, Default.ProfileId, StringComparison.Ordinal))
        {
            return Default;
        }

        if (string.Equals(profileId, G5.ProfileId, StringComparison.Ordinal))
        {
            return G5;
        }

        return null;
    }

    /// <summary>
    /// Canonical model lookup, ignoring case only. A prefix, suffix, padded or unknown value returns
    /// null. Finding a profile here is not permission to run a device operation.
    /// </summary>
    public static EdlDeviceProfile? FindByModel(string? model)
    {
        if (model is null)
        {
            return null;
        }

        if (string.Equals(model, Default.Model, StringComparison.OrdinalIgnoreCase))
        {
            return Default;
        }

        if (string.Equals(model, G5.Model, StringComparison.OrdinalIgnoreCase))
        {
            return G5;
        }

        return null;
    }

    private static IReadOnlyList<T> Immutable<T>(params T[] items) =>
        new ReadOnlyCollection<T>((T[])items.Clone());
}
