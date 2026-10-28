using System.Security.Cryptography;
using System.Text.Json;
using FreedomInstaller.Core;

if (args.Length != 4 || !Path.IsPathFullyQualified(args[0]) ||
    !Path.IsPathFullyQualified(args[3]) || !Guid.TryParse(args[2], out var partition))
{
    Console.Error.WriteLine("Usage: BackupSettingsUpgrade <absolute-v2-image> <TB322FC|TB323FU> <GPT-backup-UUID> <new-absolute-output-directory>");
    return 2;
}
try
{
    string output = Path.GetFullPath(args[3]);
    if (Directory.Exists(output) || File.Exists(output) || !Directory.Exists(Path.GetDirectoryName(output)))
        throw new IOException("Choose a new output directory below an existing parent.");
    using var input = new FileStream(args[0], FileMode.Open, FileAccess.Read, FileShare.Read);
    var plan = BootSettingsUpgrade.Prepare(input, args[1], partition, CancellationToken.None);
    Directory.CreateDirectory(output);
    var files = new[] {
        (Name: "header-before.bin", Offset: 0L, Bytes: plan.BeforeHeader),
        (Name: "header-after.bin", Offset: 0L, Bytes: plan.AfterHeader),
        (Name: "tail-before.bin", Offset: plan.TailOffset, Bytes: plan.BeforeTail),
        (Name: "tail-after.bin", Offset: plan.TailOffset, Bytes: plan.AfterTail)
    };
    foreach (var file in files)
    {
        using var stream = new FileStream(Path.Combine(output, file.Name), FileMode.CreateNew, FileAccess.Write);
        stream.Write(file.Bytes);
        stream.Flush(flushToDisk: true);
    }
    var manifest = new {
        schemaVersion = 1, kind = "armada-backup-settings-upgrade-plan", sourceSchemaVersion = 2,
        targetSchemaVersion = 3, model = plan.Model, partitionUuid = plan.PartitionUuid,
        installationId = plan.InstallationId, imageBytes = input.Length,
        compressedSha256 = plan.CompressedSha256, deviceWritten = false,
        regions = files.Select(file => new { fileName = file.Name, offset = file.Offset,
            bytes = file.Bytes.Length, sha256 = Convert.ToHexString(SHA256.HashData(file.Bytes)) })
    };
    using var receipt = new FileStream(Path.Combine(output, "upgrade-plan.json"), FileMode.CreateNew, FileAccess.Write);
    JsonSerializer.Serialize(receipt, manifest, new JsonSerializerOptions { WriteIndented = true });
    receipt.Flush(flushToDisk: true);
    Console.WriteLine("Validated legacy archive. Prepared header/tail changes and original rollback bytes: " + output);
    return 0;
}
catch (Exception error) when (error is IOException or ArgumentException or JsonException or InvalidOperationException)
{
    Console.Error.WriteLine(error.Message);
    return 1;
}