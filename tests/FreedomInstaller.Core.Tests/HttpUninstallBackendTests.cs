using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Contract for <see cref="HttpUninstallBackend"/>. Everything below runs against a fake
/// <see cref="HttpMessageHandler"/>: no socket, no device, no runtime. The validated inputs are produced by the
/// real <see cref="OriginalGptImporter"/> / <see cref="UninstallEvidenceValidator"/> path over the shared
/// <see cref="GptFixture"/> geometry and the literal <see cref="Sfdisk"/> document, so the host is never handed
/// anything a test constructed internally.
/// <para>
/// The assertions describe the intended behaviour (reject untrusted evidence, prepare without any write
/// step) and never assert on a stub exception.
/// </para>
/// </summary>
public sealed class HttpUninstallBackendTests
{
    // --------------------------------------------------------------- prepared transaction

    [Fact]
    public async Task CreatePreparedAsync_ConfirmedDevice_PreparesTheTransactionWithoutAnyWriteStep()
    {
        using var host = new HttpHostFixture();

        var backend = await HttpUninstallBackend.CreatePreparedAsync(
            host.Http,
            host.Connection,
            host.Inputs,
            host.Binding,
            host.Assets,
            host.BackupRoot,
            CancellationToken.None);

        // The snapshot is the runtime's evidence reconciled with the locally validated inputs, not a copy of
        // what the caller passed in.
        var snapshot = backend.Snapshot;
        Assert.Equal(host.Inputs.Identity, snapshot.Identity);
        Assert.Equal(host.Inputs.CurrentTableFingerprint, snapshot.TableFingerprint);
        Assert.Equal(HttpHostFixture.CurrentBootFingerprint, snapshot.CurrentBootFingerprint);
        Assert.Equal(HttpHostFixture.StockFingerprint, snapshot.StockBackupFingerprint);
        Assert.Equal(host.Inputs.EvidenceFingerprint, snapshot.InstallationRecordFingerprint);
        Assert.True(snapshot.MaintenanceValidated);
        Assert.True(snapshot.BothStockBootsValid);
        Assert.Equal(OtaUpdateState.Completed, snapshot.OtaState);

        // The plan fingerprint comes from the runtime; the transaction id is a fresh GUID the host generates,
        // so it can only be checked structurally here and against what actually went on the wire below.
        Assert.Equal(HttpHostFixture.PlanFingerprint, backend.PlanFingerprint);
        Assert.True(Guid.TryParse(backend.TransactionId, out _), "the host must generate the transaction id");

        // The caller picks the backup root; the host owns exactly one new child directory for this transaction.
        Assert.Equal(Path.GetFullPath(host.BackupRoot), Path.GetDirectoryName(backend.BackupDirectory));
        Assert.Contains(backend.TransactionId, Path.GetFileName(backend.BackupDirectory));

        // One GET inspect, five PUT assets and one POST prepare.
        var requests = host.Handler.Requests;
        Assert.Equal(7, requests.Count);
        Assert.Equal("GET /v1/inspect", requests[0].Signature);
        Assert.Equal("POST /v1/prepare", requests[^1].Signature);

        // Exactly the five fixed asset roles are uploaded, and nothing else is PUT.
        var uploadedRoles = requests
            .Where(request => request.Method == "PUT")
            .Select(request => request.Path["/v1/assets/".Length..])
            .OrderBy(role => role, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(
            new[]
            {
                "original_backup_gpt",
                "original_primary_gpt",
                "stock_boot_a",
                "stock_boot_b",
                "trusted_vbmeta_baseline",
            },
            uploadedRoles);

        // Prepare is read-only: no step, no backup acknowledgement and no current-boot download.
        Assert.DoesNotContain(requests, request => request.Path.StartsWith("/v1/transactions", StringComparison.Ordinal));
        Assert.DoesNotContain(requests, request => request.Signature == "POST /v1/ack-backups");
        Assert.DoesNotContain(requests, request => request.Path.StartsWith("/v1/boot/", StringComparison.Ordinal));

        // Every request carries the same session token, and it never appears in the request line.
        Assert.All(requests, request => Assert.Equal("Bearer " + HttpHostFixture.BearerToken, request.Authorization));

        using var prepareDocument = JsonDocument.Parse(requests[^1].BodyText);
        var prepare = prepareDocument.RootElement;

        // The fake runtime echoes the id from the prepare request, so this is the same GUID the host kept.
        Assert.Equal(backend.TransactionId, prepare.GetProperty("transactionId").GetString());
        Assert.Equal(5, prepare.GetProperty("assets").GetArrayLength());

        // The host states what it validated; it never supplies an expected firmware fingerprint of its own.
        var expected = prepare.GetProperty("expected");
        Assert.Equal(host.Inputs.Identity.Model, expected.GetProperty("model").GetString());
        Assert.Equal(host.Inputs.CurrentTableFingerprint, expected.GetProperty("tableFingerprint").GetString());
        Assert.Equal(HttpHostFixture.CurrentBootFingerprint, expected.GetProperty("currentBootFingerprint").GetString());
        Assert.False(expected.TryGetProperty("expectedFingerprint", out _));
    }

    // ------------------------------------------------- local arguments, refused before any I/O

    [Fact]
    public async Task CreatePreparedAsync_BaseAddressIsNotTheUsbAddress_IsRefusedBeforeAnyRequest()
    {
        using var host = new HttpHostFixture();
        var connection = host.Connection with { BaseAddress = new Uri("http://192.0.2.1:8202/") };

        await Assert.ThrowsAnyAsync<ArgumentException>(() => HttpUninstallBackend.CreatePreparedAsync(
            host.Http,
            connection,
            host.Inputs,
            host.Binding,
            host.Assets,
            host.BackupRoot));

        Assert.Empty(host.Handler.Requests);
    }

    [Fact]
    public async Task CreatePreparedAsync_FastbootSerialIsNotTheConfirmedUnit_IsRefusedBeforeAnyRequest()
    {
        using var host = new HttpHostFixture();
        var binding = host.Binding with { FastbootSerial = "FB-OTHER-0009" };

        await Assert.ThrowsAnyAsync<ArgumentException>(() => HttpUninstallBackend.CreatePreparedAsync(
            host.Http,
            host.Connection,
            host.Inputs,
            binding,
            host.Assets,
            host.BackupRoot));

        Assert.Empty(host.Handler.Requests);
    }

    // ------------------------------------------------------- untrusted server evidence

    [Fact]
    public async Task CreatePreparedAsync_SocSerialDisagreesWithInspect_RejectsTheInspectEvidence()
    {
        using var host = new HttpHostFixture(inspectSocSerial: "SOC-TB322FC-9999");

        await Assert.ThrowsAnyAsync<InvalidDataException>(() => HttpUninstallBackend.CreatePreparedAsync(
            host.Http,
            host.Connection,
            host.Inputs,
            host.Binding,
            host.Assets,
            host.BackupRoot));

        Assert.DoesNotContain(host.Handler.Requests, request => request.Signature == "POST /v1/prepare");
    }

    [Fact]
    public async Task CreatePreparedAsync_BootIdDriftedFromTheSession_RejectsTheInspectEvidence()
    {
        using var host = new HttpHostFixture(inspectBootId: "0f9e8d7c-6b5a-4c3d-2e1f-0a9b8c7d6e5f");

        await Assert.ThrowsAnyAsync<InvalidDataException>(() => HttpUninstallBackend.CreatePreparedAsync(
            host.Http,
            host.Connection,
            host.Inputs,
            host.Binding,
            host.Assets,
            host.BackupRoot));

        Assert.DoesNotContain(host.Handler.Requests, request => request.Signature == "POST /v1/prepare");
    }

    [Fact]
    public async Task CreatePreparedAsync_DeviceIsNotRunningFromRamRoot_RejectsTheInspectEvidence()
    {
        using var host = new HttpHostFixture(ramRoot: false);

        await Assert.ThrowsAnyAsync<InvalidDataException>(() => HttpUninstallBackend.CreatePreparedAsync(
            host.Http,
            host.Connection,
            host.Inputs,
            host.Binding,
            host.Assets,
            host.BackupRoot));

        Assert.DoesNotContain(host.Handler.Requests, request => request.Signature == "POST /v1/prepare");
    }

    [Fact]
    public async Task CreatePreparedAsync_DiskGeometryDiffersFromTheValidatedTable_RejectsTheInspectEvidence()
    {
        using var host = new HttpHostFixture(inspectDiskBytes: GptFixture.DiskBytes4096 - 4096L);

        await Assert.ThrowsAnyAsync<InvalidDataException>(() => HttpUninstallBackend.CreatePreparedAsync(
            host.Http,
            host.Connection,
            host.Inputs,
            host.Binding,
            host.Assets,
            host.BackupRoot));

        Assert.DoesNotContain(host.Handler.Requests, request => request.Signature == "POST /v1/prepare");
    }

    [Fact]
    public async Task CreatePreparedAsync_PreparedStateDoesNotProveBothStockBoots_RejectsThePreparedState()
    {
        using var host = new HttpHostFixture(prepareBothStockBootsValid: false);

        await Assert.ThrowsAnyAsync<InvalidDataException>(() => HttpUninstallBackend.CreatePreparedAsync(
            host.Http,
            host.Connection,
            host.Inputs,
            host.Binding,
            host.Assets,
            host.BackupRoot));

        // Nothing beyond the read-only prepare may have been requested.
        Assert.DoesNotContain(host.Handler.Requests, request => request.Path.StartsWith("/v1/transactions", StringComparison.Ordinal));
        Assert.DoesNotContain(host.Handler.Requests, request => request.Signature == "POST /v1/ack-backups");
    }

    [Fact]
    public async Task CreatePreparedAsync_PreparedRestoreBoundsDifferFromThePlan_RejectsThePreparedState()
    {
        using var host = new HttpHostFixture(prepareRestoredAndroidBytes: GptFixture.RestoredAndroidBytes + 4096L);

        await Assert.ThrowsAnyAsync<InvalidDataException>(() => HttpUninstallBackend.CreatePreparedAsync(
            host.Http,
            host.Connection,
            host.Inputs,
            host.Binding,
            host.Assets,
            host.BackupRoot));

        Assert.DoesNotContain(host.Handler.Requests, request => request.Path.StartsWith("/v1/transactions", StringComparison.Ordinal));
        Assert.DoesNotContain(host.Handler.Requests, request => request.Signature == "POST /v1/ack-backups");
    }

    // ---------------------------------------------------------------- secret redaction

    [Fact]
    public void HttpUninstallConnection_ToString_NeverShowsTheBearerToken()
    {
        var connection = new HttpUninstallConnection(
            new Uri(HttpHostFixture.UsbBaseAddress),
            HttpHostFixture.BearerToken,
            HttpHostFixture.BootId);

        // The token is real, so an empty match would make this test meaningless.
        Assert.Equal(64, HttpHostFixture.BearerToken.Length);

        var rendered = connection.ToString();
        Assert.DoesNotContain(HttpHostFixture.BearerToken, rendered);
        Assert.DoesNotContain(HttpHostFixture.BearerToken, $"{connection}");

        // The values a log line does need stay visible, so redaction does not turn the record opaque.
        Assert.Contains(HttpHostFixture.UsbBaseAddress, rendered);
        Assert.Contains(HttpHostFixture.BootId, rendered);
    }
}

/// <summary>
/// One fake runtime: the inspect and prepare documents the host will see, a recording message handler and the
/// artifact directory this test instance owns. Every instance writes only below
/// <c>TEST_ARTIFACT_ROOT/&lt;unique id&gt;</c>; there is no temporary-directory fallback.
/// </summary>
internal sealed class HttpHostFixture : IDisposable
{
    internal const string UsbBaseAddress = "http://192.168.77.1:8202/";

    /// <summary>32 random bytes as 64 hexadecimal characters, exactly as the runtime hands the host its token.</summary>
    internal const string BearerToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    internal const string BootId = "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b";
    internal const string SocSerial = "SOC-TB322FC-0001";
    internal const string ConfirmationToken = "confirmation-7c41f0b6e2";
    internal const string MiscPartUuid = "6c1f2a34-5b6d-4c8e-9f01-2a3b4c5d6e7f";

    /// <summary>
    /// The boot partitions live on a second UFS logical unit, so their GPT UUIDs are not the ones the main table
    /// owns and their device nodes are not the main disk's.
    /// </summary>
    internal const string BootPartUuidA = "8b41d2c3-4e5f-4a6b-9c7d-0e1f2a3b4c5d";
    internal const string BootPartUuidB = "9c52e3d4-5f60-4b7c-8d9e-1f2a3b4c5d6e";

    /// <summary>
    /// The raw GPT digest the host was given out of band; it deliberately is not the digest of the sfdisk JSON
    /// that the validator computes as the current-table source fingerprint.
    /// </summary>
    internal static readonly string ExternalTableSha = new('a', 64);

    internal static readonly byte[] StockBootABytes = Encoding.ASCII.GetBytes("fake-stock-boot-a");
    internal static readonly byte[] StockBootBBytes = Encoding.ASCII.GetBytes("fake-stock-boot-b");

    /// <summary>
    /// The literal current-state snapshots the fake runtime serves from <c>/v1/boot/{role}</c>: 17 bytes per
    /// boot slot so their length matches the fake stock images, and the full 2048-byte misc capture.
    /// </summary>
    internal static readonly byte[] CurrentBootABytes = Enumerable.Repeat((byte)0x41, StockBootABytes.Length).ToArray();
    internal static readonly byte[] CurrentBootBBytes = Enumerable.Repeat((byte)0x42, StockBootBBytes.Length).ToArray();
    internal static readonly byte[] CurrentMiscBytes = new byte[2_048];

    internal static readonly string CurrentBootFingerprint = new('c', 64);
    internal static readonly string BootSlotSha = new('d', 64);
    internal static readonly string BootVbmetaSha = new('e', 64);
    internal static readonly string BootSlotFingerprint = new('f', 64);
    internal static readonly string MiscSha = new('1', 64);
    internal static readonly string MiscFingerprint = new('2', 64);
    internal static readonly string StockFingerprint = new('3', 64);
    internal static readonly string PlanFingerprint = new('4', 64);

    /// <summary>Test-only firmware identities: real-shaped, different per slot, and carrying the model component.</summary>
    internal const string SlotFirmwareFingerprintA = "TB322FC-stock-a-20260314";
    internal const string SlotFirmwareFingerprintB = "TB322FC-stock-b-20260314";

    internal static readonly string SlotRootKeySha = new('7', 64);
    internal static readonly string SlotBootKeySha = new('8', 64);

    private readonly string _socSerial;
    private readonly string _bootId;
    private readonly bool _ramRoot;
    private readonly long _diskBytes;
    private readonly string _tableFingerprint;
    private readonly bool _prepareBothStockBootsValid;
    private readonly long _preparedRestoredAndroidBytes;

    // The exact raw GPT fragments that were parsed into Inputs; the upload must carry these, not invented bytes.
    private byte[] _originalPrimaryGptBytes = Array.Empty<byte>();
    private byte[] _originalBackupGptBytes = Array.Empty<byte>();

    internal HttpHostFixture(
        string? inspectSocSerial = null,
        string? inspectBootId = null,
        bool ramRoot = true,
        long? inspectDiskBytes = null,
        string? inspectTableFingerprint = null,
        bool prepareBothStockBootsValid = true,
        long? prepareRestoredAndroidBytes = null)
    {
        Inputs = BuildInputs();

        _socSerial = inspectSocSerial ?? SocSerial;
        _bootId = inspectBootId ?? BootId;
        _ramRoot = ramRoot;
        _diskBytes = inspectDiskBytes ?? Inputs.CurrentTable.DiskBytes;
        _tableFingerprint = inspectTableFingerprint ?? Inputs.CurrentTableFingerprint;
        _prepareBothStockBootsValid = prepareBothStockBootsValid;
        _preparedRestoredAndroidBytes = prepareRestoredAndroidBytes ?? Inputs.Plan.RestoredAndroidBytes;

        Binding = new UninstallDeviceBinding(
            Inputs.Identity,
            SocSerial,
            Inputs.Identity.Serial,
            OtaUpdateState.Completed);

        Connection = new HttpUninstallConnection(new Uri(UsbBaseAddress), BearerToken, BootId);

        var artifactDirectory = CreateArtifactDirectory();
        Assets = WriteAssets(artifactDirectory);
        BackupRoot = Path.Combine(artifactDirectory, "backup");

        Handler = new RecordingHostHandler(BuildInspectDocument(), BuildPrepareDocument());
        Http = new HttpClient(Handler, disposeHandler: true);
    }

    internal ValidatedUninstallInputs Inputs { get; }

    internal UninstallDeviceBinding Binding { get; }

    internal HttpUninstallConnection Connection { get; }

    internal UninstallRestoreAssets Assets { get; }

    internal string BackupRoot { get; }

    internal RecordingHostHandler Handler { get; }

    internal HttpClient Http { get; }

    public void Dispose() => Http.Dispose();

    /// <summary>
    /// The exact validated input path of <see cref="UninstallEvidenceValidatorTests"/>: raw original GPT bytes
    /// from the shared fixture plus the literal sfdisk document, run through the real validator. The table
    /// fingerprint handed to the validator is the raw GPT digest, which differs from the JSON source fingerprint
    /// the validator derives from the sfdisk document.
    /// </summary>
    private ValidatedUninstallInputs BuildInputs()
    {
        var identity = new DeviceIdentity("R58TEST0001", "TB322FC", BootloaderState.Unlocked);
        var image = GptFixture.RealLike4096();

        _originalPrimaryGptBytes = image.BuildPrimaryFragment().ToArray();
        _originalBackupGptBytes = image.BuildBackupFragment().ToArray();

        var original = OriginalGptImporter.Parse(
            _originalPrimaryGptBytes,
            _originalBackupGptBytes,
            GptFixture.SectorSize4096,
            GptFixture.DiskBytes4096);

        var current = UninstallEvidenceValidator.ReadCurrentSfdisk(Sfdisk.Json(), GptFixture.DiskBytes4096);

        return UninstallEvidenceValidator.Validate(identity, original, current, ExternalTableSha);
    }

    private static string CreateArtifactDirectory()
    {
        var root = Environment.GetEnvironmentVariable("TEST_ARTIFACT_ROOT");
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new InvalidOperationException(
                "TEST_ARTIFACT_ROOT must name the writable artifact root for this run; " +
                "this suite never falls back to a temporary directory.");
        }

        var directory = Path.Combine(root, "H003-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }

    /// <summary>
    /// Five assets. The two GPT fragments must be the valid bytes the validator already accepted, because the
    /// runtime hashes and re-parses them; the stock boots and the baseline may stay tiny since the fake runtime
    /// owns its own AVB and never treats them as real images.
    /// </summary>
    private UninstallRestoreAssets WriteAssets(string directory) => new(
        WriteAsset(directory, "stock_boot_a.img", StockBootABytes),
        WriteAsset(directory, "stock_boot_b.img", StockBootBBytes),
        WriteAsset(directory, "original_primary_gpt.bin", _originalPrimaryGptBytes),
        WriteAsset(directory, "original_backup_gpt.bin", _originalBackupGptBytes),
        WriteAsset(directory, "trusted_vbmeta_baseline.bin", "fake-trusted-vbmeta-baseline"));

    private static string WriteAsset(string directory, string fileName, byte[] content)
    {
        var path = Path.Combine(directory, fileName);
        File.WriteAllBytes(path, content);
        return path;
    }

    private static string WriteAsset(string directory, string fileName, string content)
        => WriteAsset(directory, fileName, Encoding.ASCII.GetBytes(content));

    private string BuildInspectDocument()
    {
        var table = Inputs.CurrentTable;

        var document = new
        {
            schemaVersion = 1,
            model = Inputs.Identity.Model,
            socSerial = _socSerial,
            bootId = _bootId,
            ramRoot = _ramRoot,
            rootFstype = "rootfs",
            compatible = new[] { "lenovo,tb322fc" },
            diskPath = table.DeviceId,
            diskBytes = _diskBytes,
            sectorSize = table.SectorSize,
            tableFingerprint = _tableFingerprint,
            primaryGptValid = true,
            backupGptValid = true,
            layout = new
            {
                device = table.DeviceId,
                sectorSize = table.SectorSize,
                tableFingerprint = HttpHostFixture.ExternalTableSha,
                partitions = table.Partitions
                    .Select(partition => new
                    {
                        number = partition.Number,
                        name = partition.Name,
                        startSector = partition.StartSector,
                        sectorCount = partition.SectorCount,
                        typeGuid = partition.TypeGuid,
                        partUuid = partition.PartUuid,
                    })
                    .ToArray(),
            },
            sfdiskJson = Sfdisk.Json(),
            bootSlots = new
            {
                // Boot lives on its own UFS logical unit: distinct UUIDs, paths off the main disk, and the exact
                // byte length of the fake stock images the host will upload.
                a = new
                {
                    partitionPath = "/dev/sde3",
                    partUuid = BootPartUuidA,
                    bytes = CurrentBootABytes.Length,
                    sha256 = Sha256Hex(CurrentBootABytes),
                    vbmetaSha256 = BootVbmetaSha,
                    slotFingerprint = BootSlotFingerprint,
                },
                b = new
                {
                    partitionPath = "/dev/sde4",
                    partUuid = BootPartUuidB,
                    bytes = CurrentBootBBytes.Length,
                    sha256 = Sha256Hex(CurrentBootBBytes),
                    vbmetaSha256 = BootVbmetaSha,
                    slotFingerprint = BootSlotFingerprint,
                },
            },
            currentBootFingerprint = CurrentBootFingerprint,
            misc = new
            {
                partitionPath = "/dev/sde5",
                partUuid = MiscPartUuid,
                bytes = CurrentMiscBytes.Length,
                sha256 = Sha256Hex(CurrentMiscBytes),
                bcbPending = false,
            },
            miscFingerprint = MiscFingerprint,
            busy = new
            {
                rootOnTarget = false,
                mountedPartitions = Array.Empty<string>(),
                swapPartitions = Array.Empty<string>(),
                holderPartitions = Array.Empty<string>(),
            },
            ota = new { state = "completed", evidence = "post-update boot confirmed" },
            maintenanceValidated = true,

            // A stock boot is only proven by the validator that runs inside prepare, so inspect never claims it.
            bothStockBootsValid = false,
        };

        return JsonSerializer.Serialize(document);
    }

    private string BuildPrepareDocument()
    {
        var plan = Inputs.Plan;

        var document = new
        {
            schemaVersion = 1,

            // transactionId is not fixed here: the fake runtime echoes the GUID from the host's prepare request.
            bootId = _bootId,
            state = "prepared",
            stage = "Prepared",
            nextStep = "restore-boot-a",
            activeStep = (string?)null,
            completedSteps = Array.Empty<string>(),
            planFingerprint = PlanFingerprint,
            stockFingerprint = StockFingerprint,

            // Each slot reports the digest of the stock file the host uploaded for it, in the runtime's own field
            // names. The firmware identity is real-shaped, different per slot, and only a test value.
            slotEvidence = new
            {
                a = new
                {
                    slot = "a",
                    fingerprint = SlotFirmwareFingerprintA,
                    sha256 = Sha256Hex(StockBootABytes),
                    rootKeySha256 = SlotRootKeySha,
                    bootKeySha256 = SlotBootKeySha,
                    hardwareRollbackVerified = false,
                },
                b = new
                {
                    slot = "b",
                    fingerprint = SlotFirmwareFingerprintB,
                    sha256 = Sha256Hex(StockBootBBytes),
                    rootKeySha256 = SlotRootKeySha,
                    bootKeySha256 = SlotBootKeySha,
                    hardwareRollbackVerified = false,
                },
            },
            backupAcknowledged = false,
            confirmationToken = ConfirmationToken,
            bothStockBootsValid = _prepareBothStockBootsValid,

            // The runtime echoes the plan it derived from the CURRENT table; the host only accepts these exact
            // values and never recomputes them itself.
            restoredAndroidBytes = _preparedRestoredAndroidBytes,
            userdataStartSector = plan.UserdataStartSector,
            userdataEndSectorExclusive = plan.UserdataEndSectorExclusive,
            removedPartitionNumbers = plan.RemovedPartitionNumbers,
            error = (object)null,
        };

        return JsonSerializer.Serialize(document);
    }

    internal static string Sha256Hex(byte[] content) =>
        Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
}

/// <summary>One request the host actually sent; the body is kept so the test can read the JSON it carried.</summary>
internal sealed record RecordedHttpRequest(string Method, string Path, byte[] Body, string? Authorization)
{
    internal string Signature => Method + " " + Path;

    internal string BodyText => Encoding.UTF8.GetString(Body);
}

/// <summary>
/// Serves the two read-only documents of a prepared transaction, echoes the hash of every uploaded asset, echoes
/// the transaction id the host generated into the prepare response, and records every request. Any other
/// method/path answers 500 with the unexpected request in the body, so an unplanned step fails visibly instead of
/// looking like a transport error.
/// </summary>
internal sealed class RecordingHostHandler : HttpMessageHandler
{
    private const string AssetsPrefix = "/v1/assets/";

    private readonly string _inspectJson;
    private readonly string _prepareJson;

    internal RecordingHostHandler(string inspectJson, string prepareJson)
    {
        _inspectJson = inspectJson;
        _prepareJson = prepareJson;
    }

    internal List<RecordedHttpRequest> Requests { get; } = new();

    /// <summary>
    /// The exact prepared document last sent, transaction id already echoed, so a lifecycle fake can clone it
    /// for status responses instead of inventing a second shape.
    /// </summary>
    internal string? LastPreparedJson { get; private set; }

    /// <summary>
    /// Serves endpoints that are not part of the read-only prepare exchange. Existing inspect/prepare/PUT
    /// routes keep their own logic; this callback only sees what would otherwise be an unexpected request.
    /// </summary>
    internal Func<RecordedHttpRequest, CancellationToken, Task<HttpResponseMessage>>? ExtraResponse { get; set; }

    /// <summary>
    /// Replaces only the answer to <c>POST /v1/prepare</c> after <see cref="LastPreparedJson"/> has been
    /// recorded, so a fake can lose or corrupt the response while the runtime's accepted prepared state stays
    /// observable through a later status read.
    /// </summary>
    internal Func<RecordedHttpRequest, CancellationToken, Task<HttpResponseMessage>>? PreparedResponseOverride { get; set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null
            ? Array.Empty<byte>()
            : await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);

        var method = request.Method.Method;
        var path = request.RequestUri is null ? string.Empty : request.RequestUri.AbsolutePath;
        var authorization = request.Headers.Authorization?.ToString();

        var recorded = new RecordedHttpRequest(method, path, body, authorization);
        Requests.Add(recorded);

        if (string.Equals(method, "GET", StringComparison.Ordinal)
            && string.Equals(path, "/v1/inspect", StringComparison.Ordinal))
        {
            return Json(_inspectJson);
        }

        if (string.Equals(method, "POST", StringComparison.Ordinal)
            && string.Equals(path, "/v1/prepare", StringComparison.Ordinal))
        {
            var prepared = PrepareResponse(_prepareJson, body);
            LastPreparedJson = prepared;

            if (PreparedResponseOverride is not null)
            {
                return await PreparedResponseOverride(recorded, cancellationToken).ConfigureAwait(false);
            }

            return Json(prepared);
        }

        if (string.Equals(method, "PUT", StringComparison.Ordinal)
            && path.StartsWith(AssetsPrefix, StringComparison.Ordinal))
        {
            return Json(AssetReceipt(path[AssetsPrefix.Length..], body));
        }

        if (ExtraResponse is not null)
        {
            return await ExtraResponse(recorded, cancellationToken).ConfigureAwait(false);
        }

        return new HttpResponseMessage(HttpStatusCode.InternalServerError)
        {
            Content = new StringContent($"fake host: unexpected {method} {path}", Encoding.UTF8, "text/plain"),
        };
    }

    /// <summary>
    /// The runtime never accepts a caller-chosen id: it adopts the GUID the host sent in the prepare request and
    /// echoes it, so every later response for this transaction carries that same id.
    /// </summary>
    private static string PrepareResponse(string template, byte[] requestBody)
    {
        using var request = JsonDocument.Parse(requestBody);
        if (!request.RootElement.TryGetProperty("transactionId", out var transactionId)
            || transactionId.ValueKind != JsonValueKind.String)
        {
            throw new InvalidOperationException("fake host: prepare request carried no transactionId");
        }

        var echoed = transactionId.GetString();
        if (string.IsNullOrWhiteSpace(echoed))
        {
            throw new InvalidOperationException("fake host: prepare request carried no transactionId");
        }

        var response = JsonNode.Parse(template)?.AsObject()
            ?? throw new InvalidOperationException("fake host: prepare document is not a JSON object");
        response["transactionId"] = echoed;
        return response.ToJsonString();
    }

    private static string AssetReceipt(string role, byte[] body)
    {
        var sha256 = Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();
        return JsonSerializer.Serialize(new { role, bytes = body.Length, sha256 });
    }

    private static HttpResponseMessage Json(string json) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json"),
    };
}
