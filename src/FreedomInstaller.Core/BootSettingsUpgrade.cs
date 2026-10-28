using System.Text.Json;

namespace FreedomInstaller.Core;

/// <summary>Reviewed before/after regions for an explicit legacy backup upgrade.
/// These bytes are a plan, not evidence that a device has been changed. The caller
/// must retain the original regions, bind to the current partition, and verify
/// the written image before enabling launcher settings.</summary>
public sealed record BootSettingsUpgradePlan(
    string Model, Guid PartitionUuid, Guid InstallationId, string CompressedSha256,
    long TailOffset, byte[] BeforeHeader, byte[] AfterHeader, byte[] BeforeTail, byte[] AfterTail);

public static class BootSettingsUpgrade
{
    private const int HeaderBytes = 65536;

    /// <summary>Completely verifies a stable v2 image and prepares only its header
    /// and final 64 KiB. Never writes or closes the input, and never recompresses
    /// the recovery archive. The expected partition UUID must come from the target
    /// GPT; an unrelated backup cannot provision that target.</summary>
    public static BootSettingsUpgradePlan Prepare(Stream image, string model,
        Guid expectedPartitionUuid, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(image);
        if (expectedPartitionUuid == Guid.Empty)
            throw new ArgumentException("The target backup partition UUID is required.", nameof(expectedPartitionUuid));
        uint board = BootSettingsRegion.BoardId(model);
        JsonElement manifest = InternalInstallArtifacts.VerifyBoardArchive(image, model, token);
        image.Position = 0;
        var beforeHeader = new byte[HeaderBytes];
        image.ReadExactly(beforeHeader);
        using var document = JsonDocument.Parse(beforeHeader);
        JsonElement header = document.RootElement;
        if (header.GetProperty("schemaVersion").GetInt32() != 2)
            throw new InvalidDataException("Only an unprovisioned legacy v2 archive can be upgraded.");
        if (!manifest.TryGetProperty("ownedPartitionUuids", out var owned) ||
            owned.ValueKind != JsonValueKind.Array || owned.GetArrayLength() != 3 ||
            owned[2].ValueKind != JsonValueKind.String ||
            !Guid.TryParse(owned[2].GetString(), out var partition) || partition != expectedPartitionUuid)
            throw new InvalidDataException("The archive does not own the target backup partition.");
        Guid installation = Guid.Parse(header.GetProperty("installationId").GetString()!);
        long payloadEnd = checked(HeaderBytes + header.GetProperty("compressedBytes").GetInt64());
        byte[] descriptor = BootSettingsRegion.CreateDescriptor(partition, installation, model, payloadEnd);
        var beforeTail = new byte[BootSettingsRegion.Bytes];
        image.Position = BootSettingsRegion.Offset;
        image.ReadExactly(beforeTail);
        if (beforeTail.Any(value => value != 0))
            throw new InvalidDataException("The legacy settings tail is not empty.");
        var afterTail = new byte[BootSettingsRegion.Bytes];
        descriptor.CopyTo(afterTail, 0);
        using var encoded = new MemoryStream();
        using (var writer = new Utf8JsonWriter(encoded))
        {
            writer.WriteStartObject();
            foreach (JsonProperty property in header.EnumerateObject())
            {
                if (property.Name is "schemaVersion" or "configRegionOffset" or
                    "configRegionBytes" or "configPartitionUuid" or "configBoardId")
                    continue;
                property.WriteTo(writer);
            }
            writer.WriteNumber("schemaVersion", 3);
            writer.WriteNumber("configRegionOffset", BootSettingsRegion.Offset);
            writer.WriteNumber("configRegionBytes", BootSettingsRegion.Bytes);
            writer.WriteString("configPartitionUuid", partition.ToString("D"));
            writer.WriteNumber("configBoardId", board);
            writer.WriteEndObject();
        }
        if (encoded.Length >= HeaderBytes)
            throw new InvalidDataException("The upgraded header does not fit its fixed region.");
        var afterHeader = new byte[HeaderBytes];
        Array.Fill(afterHeader, (byte)' ');
        encoded.GetBuffer().AsSpan(0, checked((int)encoded.Length)).CopyTo(afterHeader);
        token.ThrowIfCancellationRequested();
        return new(model, partition, installation, header.GetProperty("compressedSha256").GetString()!,
            BootSettingsRegion.Offset, beforeHeader, afterHeader, beforeTail, afterTail);
    }
}