using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Synthetic HTTP tests for the RAM SD card protocol client (TF-RAM-CLIENT-01). A small hand-written
/// HttpMessageHandler fake switches directly on the fixed routes and serves a small in-memory card;
/// no network, no device, no mock DSL. All identities and numbers are synthetic.
/// </summary>
public sealed class TfRamCardWriteTargetTests
{
    private const string BaseUrl = "http://192.168.77.1:8203";

    private const long CardSize = 8L * 1024 * 1024;

    private const int Sector = 512;

    private const string CardKey = "tablet:sd:0123456789abcdef0123456789abcdef";

    private const string CardPath = "/dev/mmcblk1";

    private const string CardSessionId = "0123456789abcdef0123456789abcdef";

    private const string Binding = "f";

    private static readonly string Token = new('a', 64);

    private const string KernelSha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private static readonly Guid BootId = new("6f1c0f2e-8f4a-4b9d-9a3e-5b1d2c4e6f80");

    private static readonly Guid OtherBootId = new("11111111-2222-4333-8444-555555555555");

    private readonly byte[] _card = new byte[CardSize];

    private readonly FakeRamServiceHandler _handler;

    private readonly HttpClient _client;

    public TfRamCardWriteTargetTests()
    {
        _handler = new FakeRamServiceHandler(_card)
        {
            InspectJson = BuildInspectJson(),
        };
        _client = new HttpClient(_handler);
    }

    // ------------------------------------------------------------- happy path

    [Fact]
    public async Task Connect_Inventory_Open_Write_Read_Flush_Close_RoundTrip()
    {
        var session = await ConnectAsync();

        Assert.Equal("TB322FC", session.Model);
        Assert.Equal(1234567890UL, session.SocSerial);
        Assert.Equal(BootId, session.BootId);
        Assert.Equal(KernelSha, session.KernelSha256);

        var cards = await session.DiscoverCardsAsync();
        var card = Assert.Single(cards);
        Assert.Equal(CardKey, card.Key);
        Assert.Equal(CardPath, card.Path);
        Assert.Equal(CardSize, card.SizeBytes);
        Assert.Equal(Sector, card.LogicalSectorSize);

        var target = await session.OpenCardAsync(card);
        Assert.Equal(TfCardSource.Tablet, target.Identity.Source);
        Assert.Equal(CardKey, target.Identity.Key);
        Assert.Equal(CardPath, target.Identity.DevicePath);
        Assert.Equal(CardSize, target.Identity.SizeBytes);
        Assert.Equal(Sector, target.Identity.LogicalSectorSize);
        Assert.Equal(new string('f', 64), target.Identity.BindingSha256);

        var first = Sentinel(0xAB, Sector);
        var second = Sentinel(0xCD, Sector);
        await target.WriteAsync(0, first);
        await target.WriteAsync(Sector, second);

        Assert.Equal(2, _handler.WriteCount);
        Assert.Equal(first, _handler.WriteBodies[0]);
        Assert.Equal(second, _handler.WriteBodies[1]);
        Assert.Equal(new long[] { 0, Sector }, _handler.WriteOffsets);
        Assert.Equal(Sha256Hex(first), _handler.WriteHeaderHashes[0]);
        Assert.Equal(Sha256Hex(second), _handler.WriteHeaderHashes[1]);
        Assert.Equal(0, _card[2 * Sector]);

        var writeRoute = _handler.Routes.Single(r => r.Contains("/write?offset=0"));
        Assert.Equal("POST /v1/card/" + CardSessionId + "/write?offset=0", writeRoute);

        var buffer = new byte[Sector];
        await target.ReadExactlyAsync(0, buffer);
        Assert.Equal(first, buffer);
        Assert.Contains(
            "GET /v1/card/" + CardSessionId + "/read?offset=0&bytes=" + Sector.ToString(CultureInfo.InvariantCulture),
            _handler.Routes);

        await target.FlushAsync();
        Assert.Equal(1, _handler.FlushCount);
        var flushIndex = _handler.Routes.FindIndex(r => r.EndsWith("/flush", StringComparison.Ordinal));
        Assert.True(flushIndex >= 0);
        Assert.Equal(0, _handler.RequestContentLengths[flushIndex]);

        await target.DisposeAsync();
        Assert.Equal(1, _handler.CloseCount);
        Assert.Equal(0, _handler.RequestContentLengths[^1]);

        Assert.All(_handler.Routes, r => Assert.DoesNotContain(Token, r));

        await session.DisposeAsync();
        Assert.Equal(1, _handler.CloseCount);
    }

    [Theory]
    [InlineData("0xABCDEF12")]
    [InlineData("ABCDEF12")]
    [InlineData("2882400018")]
    public async Task Connect_NormalizesSocSerialWireFormats(string wireSerial)
    {
        _handler.InspectJson = BuildInspectJson(socSerial: wireSerial);
        var session = await TfRamMaintenanceSession.ConnectAsync(_client, Token, "TB322FC", 0xABCDEF12UL, KernelSha);
        Assert.Equal(0xABCDEF12UL, session.SocSerial);
    }

    [Fact]
    public async Task Connect_AcceptsG5ModelAndKaanapaliSoc()
    {
        _handler.InspectJson = BuildInspectJson(model: "TB323FU", soc: "kaanapali");
        var session = await TfRamMaintenanceSession.ConnectAsync(_client, Token, "TB323FU", 1234567890UL, KernelSha);
        Assert.Equal("TB323FU", session.Model);
    }

    // ------------------------------------------------------------- handshake rejects

    [Fact]
    public async Task Connect_RejectsBadTokenFormat_WithoutAnyRequest()
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            TfRamMaintenanceSession.ConnectAsync(_client, new string('g', 64), "TB322FC", 1234567890UL, KernelSha));
        Assert.Empty(_handler.Routes);
    }

    [Fact]
    public async Task Connect_RejectsWrongModelReport()
    {
        _handler.InspectJson = BuildInspectJson(model: "TB323FU", soc: "kaanapali");
        var ex = await Assert.ThrowsAnyAsync<InvalidOperationException>(() =>
            TfRamMaintenanceSession.ConnectAsync(_client, Token, "TB322FC", 1234567890UL, KernelSha));
        Assert.Contains("model", ex.Message);
        Assert.DoesNotContain(Token, ex.Message);
    }

    [Fact]
    public async Task Connect_RejectsWrongSocSerialNumber()
    {
        _handler.InspectJson = BuildInspectJson(socSerial: "987654321");
        await Assert.ThrowsAnyAsync<InvalidOperationException>(() =>
            TfRamMaintenanceSession.ConnectAsync(_client, Token, "TB322FC", 1234567890UL, KernelSha));
    }

    [Fact]
    public async Task Connect_RejectsWrongKernelMarker()
    {
        _handler.InspectJson = BuildInspectJson(kernelSha256: new string('e', 64));
        await Assert.ThrowsAnyAsync<InvalidOperationException>(() =>
            TfRamMaintenanceSession.ConnectAsync(_client, Token, "TB322FC", 1234567890UL, KernelSha));
    }

    [Fact]
    public async Task Connect_RejectsZeroBootId()
    {
        _handler.InspectJson = BuildInspectJson(bootId: Guid.Empty);
        await Assert.ThrowsAnyAsync<InvalidOperationException>(() =>
            TfRamMaintenanceSession.ConnectAsync(_client, Token, "TB322FC", 1234567890UL, KernelSha));
    }

    [Fact]
    public async Task Connect_RejectsWrongProtocol()
    {
        _handler.InspectJson = BuildInspectJson(protocol: "tf-card-v2");
        await Assert.ThrowsAnyAsync<InvalidOperationException>(() =>
            TfRamMaintenanceSession.ConnectAsync(_client, Token, "TB322FC", 1234567890UL, KernelSha));
    }

    [Fact]
    public async Task Connect_RejectsRamOnlyFalse()
    {
        _handler.InspectJson = BuildInspectJson(ramOnly: false);
        await Assert.ThrowsAnyAsync<InvalidOperationException>(() =>
            TfRamMaintenanceSession.ConnectAsync(_client, Token, "TB322FC", 1234567890UL, KernelSha));
    }

    [Fact]
    public async Task Connect_RejectsNonTabletSource()
    {
        _handler.InspectJson = BuildInspectJson(source: "reader");
        await Assert.ThrowsAnyAsync<InvalidOperationException>(() =>
            TfRamMaintenanceSession.ConnectAsync(_client, Token, "TB322FC", 1234567890UL, KernelSha));
    }

    [Fact]
    public async Task Connect_RejectsServerError_AndSurfacesShortCodeOnly()
    {
        _handler.InspectStatus = HttpStatusCode.ServiceUnavailable;
        var ex = await Assert.ThrowsAnyAsync<InvalidOperationException>(() =>
            TfRamMaintenanceSession.ConnectAsync(_client, Token, "TB322FC", 1234567890UL, KernelSha));
        Assert.Contains("inspect-fail", ex.Message);
        Assert.DoesNotContain(Token, ex.Message);
        Assert.True(ex.Message.Length < 300);
    }

    [Fact]
    public async Task ServerError_MalformedBody_FallsBackToHttpStatusOnly()
    {
        _handler.InspectStatus = HttpStatusCode.BadGateway;
        _handler.ErrorBodyOverride = "<html>gateway junk page with lots of text</html>";
        var ex = await Assert.ThrowsAnyAsync<InvalidOperationException>(() =>
            TfRamMaintenanceSession.ConnectAsync(_client, Token, "TB322FC", 1234567890UL, KernelSha));
        Assert.Contains("http-502", ex.Message);
        Assert.DoesNotContain("gateway junk", ex.Message);
    }

    [Fact]
    public async Task Connect_RejectsOversizedInspectBody()
    {
        _handler.InspectJson = "{\"schemaVersion\":1,\"padding\":\"" + new string('x', 300_000) + "\"}";
        await Assert.ThrowsAnyAsync<InvalidOperationException>(() =>
            TfRamMaintenanceSession.ConnectAsync(_client, Token, "TB322FC", 1234567890UL, KernelSha));
    }

    [Fact]
    public async Task Discover_AfterHandshake_RejectsDriftedIdentity()
    {
        var session = await ConnectAsync();
        _handler.InspectJson = BuildInspectJson(bootId: OtherBootId);
        await Assert.ThrowsAnyAsync<InvalidOperationException>(() => session.DiscoverCardsAsync());
    }

    // ------------------------------------------------------------- open rejects

    [Fact]
    public async Task Open_RejectsStaleCandidateMissingFromFreshInventory_NoOpenNoWrites()
    {
        var session = await ConnectAsync();
        var stale = Variant(path: "/dev/mmcblk2", key: "tablet:sd:fedcba9876543210fedcba9876543210");
        await Assert.ThrowsAnyAsync<InvalidOperationException>(() => session.OpenCardAsync(stale));
        Assert.DoesNotContain(_handler.Routes, r => r.Contains("/card/open"));
        Assert.Equal(0, _handler.WriteCount);
    }

    [Fact]
    public async Task Open_RejectsDuplicateInventoryCandidates()
    {
        var session = await ConnectAsync();
        _handler.InspectJson = BuildInspectJson(mediaJson: "[" + BuildMediaJson() + "," + BuildMediaJson() + "]");
        await Assert.ThrowsAsync<ArgumentException>(() => session.OpenCardAsync(Variant()));
        Assert.DoesNotContain(_handler.Routes, r => r.Contains("/card/open"));
    }

    [Fact]
    public async Task Open_RejectsGeometryDriftBetweenSelectionAndFreshInventory()
    {
        var session = await ConnectAsync();
        _handler.InspectJson = BuildInspectJson(mediaJson: "[" + BuildMediaJson(sizeBytes: CardSize - Sector) + "]");
        await Assert.ThrowsAnyAsync<InvalidOperationException>(() => session.OpenCardAsync(Variant()));
        Assert.DoesNotContain(_handler.Routes, r => r.Contains("/card/open"));
    }

    [Fact]
    public async Task Open_RejectsIneligibleCandidatesLocally_WithoutRequests()
    {
        var session = await ConnectAsync();
        var baseline = _handler.Routes.Count;

        await Assert.ThrowsAsync<ArgumentException>(() => session.OpenCardAsync(Variant(readOnly: true)));
        await Assert.ThrowsAsync<ArgumentException>(() => session.OpenCardAsync(Variant(mounted: true)));
        await Assert.ThrowsAsync<ArgumentException>(() => session.OpenCardAsync(Variant(androidUsage: "adopted")));
        await Assert.ThrowsAsync<ArgumentException>(() => session.OpenCardAsync(Variant(key: "reader:usb1")));
        await Assert.ThrowsAsync<ArgumentException>(() => session.OpenCardAsync(Variant(path: "/dev/mmcblk1p1")));
        await Assert.ThrowsAsync<ArgumentException>(() => session.OpenCardAsync(Variant(sizeBytes: CardSize + 1)));
        await Assert.ThrowsAsync<ArgumentException>(() => session.OpenCardAsync(Variant(sector: 1024)));

        Assert.Equal(baseline, _handler.Routes.Count);
        Assert.Equal(0, _handler.WriteCount);
    }

    [Fact]
    public async Task Open_RejectsBadServerOpenEnvelope_Variants()
    {
        var session = await ConnectAsync();

        _handler.OpenJsonOverride = OpenEnvelope(CardSessionId, BuildIdentityJson(CardKey, "/dev/mmcblk2", CardSize, Sector, F64('f')));
        await Assert.ThrowsAnyAsync<InvalidOperationException>(() => session.OpenCardAsync(Variant()));

        _handler.OpenJsonOverride = OpenEnvelope(CardSessionId, BuildIdentityJson(CardKey, CardPath, CardSize, Sector, "zz"));
        await Assert.ThrowsAnyAsync<InvalidOperationException>(() => session.OpenCardAsync(Variant()));

        _handler.OpenJsonOverride = OpenEnvelope("short", BuildIdentityJson(CardKey, CardPath, CardSize, Sector, F64('f')));
        await Assert.ThrowsAnyAsync<InvalidOperationException>(() => session.OpenCardAsync(Variant()));
        _handler.OpenJsonOverride = null;

        await session.DisposeAsync();
        // One rollback DELETE per known-valid-ID failed open; the malformed "short" ID is never sent.
        Assert.Equal(2, _handler.CloseCount);
    }

    [Fact]
    public async Task TargetDisposal_ClosesViaSession_NoNullReference_SessionDisposalDoesNotDuplicate()
    {
        var session = await ConnectAsync();
        var target = await session.OpenCardAsync(Variant());

        await target.DisposeAsync();
        Assert.Equal(1, _handler.CloseCount);

        await session.DisposeAsync();
        Assert.Equal(1, _handler.CloseCount);
        Assert.Equal(0, _handler.WriteCount);
    }

    // ------------------------------------------------------------- block IO

    [Fact]
    public async Task IdentityDrift_FailsRevalidate_PoisonsTarget_CloseStillWorks()
    {
        var (session, target) = await OpenAsync();

        _handler.IdentityJsonOverride = "{\"schemaVersion\":1,\"identity\":"
            + BuildIdentityJson(CardKey, CardPath, CardSize, Sector, F64('d')) + "}";
        var drift = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => target.RevalidateAsync().AsTask());
        Assert.Contains("identity-drift", drift.Message);

        var writes = _handler.WriteCount;
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => target.WriteAsync(0, Sentinel(0x11, Sector)).AsTask());
        Assert.Equal(writes, _handler.WriteCount);

        await target.DisposeAsync();
        Assert.Equal(1, _handler.CloseCount);
        await session.DisposeAsync();
    }

    [Fact]
    public async Task Write_RejectsBadRangesLocally_WithoutHttpWrite()
    {
        var (_, target) = await OpenAsync();
        var writes = _handler.WriteCount;
        var buffer = new byte[Sector];

        await Assert.ThrowsAsync<ArgumentException>(() => target.WriteAsync(Sector / 2, buffer).AsTask());
        await Assert.ThrowsAsync<ArgumentException>(() => target.WriteAsync(0, new byte[Sector / 2]).AsTask());
        await Assert.ThrowsAsync<ArgumentException>(() => target.WriteAsync(0, new byte[1024 * 1024 + Sector]).AsTask());
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => target.WriteAsync(CardSize, buffer).AsTask());
        await Assert.ThrowsAsync<ArgumentException>(() => target.WriteAsync(0, Array.Empty<byte>()).AsTask());
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => target.WriteAsync(-Sector, buffer).AsTask());

        Assert.Equal(writes, _handler.WriteCount);
    }

    [Fact]
    public async Task Read_RejectsBadRangesLocally_WithoutHttpRead()
    {
        var (_, target) = await OpenAsync();
        var buffer = new byte[Sector];
        await Assert.ThrowsAsync<ArgumentException>(() => target.ReadExactlyAsync(Sector / 2, buffer).AsTask());
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => target.ReadExactlyAsync(CardSize, buffer).AsTask());
        Assert.DoesNotContain(_handler.Routes, r => r.Contains("/read"));
    }

    [Fact]
    public async Task Write_WrongAckCount_Fails_Poisons_NoBytesApplied()
    {
        var (session, target) = await OpenAsync();

        _handler.WriteResponder = (offset, body) => JsonResponse(
            "{\"schemaVersion\":1,\"writtenBytes\":" + (body.Length + 1).ToString(CultureInfo.InvariantCulture)
            + ",\"sha256\":\"" + Sha256Hex(body) + "\"}");
        var ex = await Assert.ThrowsAnyAsync<InvalidOperationException>(
            () => target.WriteAsync(0, Sentinel(0x22, Sector)).AsTask());
        Assert.DoesNotContain(Token, ex.Message);
        Assert.Contains("writtenBytes", ex.Message);
        Assert.True(_card.AsSpan(0, 2 * Sector).ToArray().All(b => b == 0));

        _handler.WriteResponder = null;
        var writes = _handler.WriteCount;
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => target.WriteAsync(Sector, Sentinel(0x33, Sector)).AsTask());
        Assert.Equal(writes, _handler.WriteCount);

        await session.DisposeAsync();
        Assert.Equal(1, _handler.CloseCount);
    }

    [Fact]
    public async Task Write_WrongAckHash_Fails_AndPoisons()
    {
        var (_, target) = await OpenAsync();
        _handler.WriteResponder = (offset, body) => JsonResponse(
            "{\"schemaVersion\":1,\"writtenBytes\":" + body.Length.ToString(CultureInfo.InvariantCulture)
            + ",\"sha256\":\"" + F64('0') + "\"}");
        await Assert.ThrowsAnyAsync<InvalidOperationException>(
            () => target.WriteAsync(0, Sentinel(0x44, Sector)).AsTask());

        var writes = _handler.WriteCount;
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => target.WriteAsync(0, Sentinel(0x45, Sector)).AsTask());
        Assert.Equal(writes, _handler.WriteCount);
    }

    [Fact]
    public async Task Write_HttpError_Fails_Poisons_NoFabricatedEvidence()
    {
        var (_, target) = await OpenAsync();
        _handler.WriteResponder = (offset, body) => _handler.Error(HttpStatusCode.InsufficientStorage, "sd-readonly", "card is read only");
        var ex = await Assert.ThrowsAnyAsync<InvalidOperationException>(
            () => target.WriteAsync(0, Sentinel(0x55, Sector)).AsTask());
        Assert.Contains("sd-readonly", ex.Message);
        Assert.True(_card.AsSpan(0, Sector).ToArray().All(b => b == 0));

        var writes = _handler.WriteCount;
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => target.WriteAsync(0, Sentinel(0x56, Sector)).AsTask());
        Assert.Equal(writes, _handler.WriteCount);
    }

    [Fact]
    public async Task Read_ShortBody_Rejected_WithoutZeroFill()
    {
        var (session, target) = await OpenAsync();
        _card.AsSpan(0, Sector).Fill(0x55);

        _handler.ReadResponder = (offset, count) =>
        {
            var start = checked((int)offset);
            var actual = _card[start..(start + count - 1)];
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new LyingContent(actual, count),
            };
            response.Headers.Add("X-Content-SHA256", Sha256Hex(actual));
            return response;
        };
        var buffer = new byte[Sector];
        buffer.AsSpan().Fill(0xEE);
        var shortEx = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => target.ReadExactlyAsync(0, buffer).AsTask());
        Assert.Contains("read-short", shortEx.Message, StringComparison.OrdinalIgnoreCase);
        Assert.True(buffer.All(b => b == 0xEE));

        await session.DisposeAsync();
        Assert.Equal(1, _handler.CloseCount);
    }

    [Fact]
    public async Task Read_ExtraBody_Rejected()
    {
        var (_, target) = await OpenAsync();
        _handler.ReadResponder = (offset, count) =>
        {
            var start = checked((int)offset);
            var actual = _card[start..(start + count + 1)];
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new LyingContent(actual, count),
            };
            response.Headers.Add("X-Content-SHA256", Sha256Hex(actual));
            return response;
        };
        var buffer = new byte[Sector];
        var extraEx = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => target.ReadExactlyAsync(0, buffer).AsTask());
        Assert.Contains("read-extra", extraEx.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Read_MissingOrWrongDigest_Rejected()
    {
        // Missing digest, on a fresh target.
        {
            var (session, target) = await OpenAsync();
            _handler.ReadResponder = (offset, count) =>
            {
                var data = new byte[count];
                Array.Copy(_card, offset, data, 0, count);
                var response = BinaryResponse(data);
                response.Headers.Remove("X-Content-SHA256");
                return response;
            };
            var buffer = new byte[Sector];
            var missing = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => target.ReadExactlyAsync(0, buffer).AsTask());
            Assert.Contains("read-digest", missing.Message, StringComparison.OrdinalIgnoreCase);
            await session.DisposeAsync();
            // Session disposal closes the still-open (poisoned) target exactly once.
            Assert.Equal(1, _handler.CloseCount);
        }

        // Wrong digest, on a second fresh target (the first target is poisoned by its failure).
        {
            var (session, target) = await OpenAsync();
            _handler.ReadResponder = (offset, count) =>
            {
                var data = new byte[count];
                Array.Copy(_card, offset, data, 0, count);
                var response = BinaryResponse(data);
                response.Headers.Remove("X-Content-SHA256");
                response.Headers.Add("X-Content-SHA256", F64('0'));
                return response;
            };            var buffer = new byte[Sector];
            var wrong = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => target.ReadExactlyAsync(0, buffer).AsTask());
            Assert.Contains("read-digest", wrong.Message, StringComparison.OrdinalIgnoreCase);

            // A poisoned target issues no further HTTP reads.
            var reads = _handler.Routes.Count(r => r.Contains("/read"));
            await Assert.ThrowsAsync<InvalidOperationException>(() => target.ReadExactlyAsync(0, buffer).AsTask());
            Assert.Equal(reads, _handler.Routes.Count(r => r.Contains("/read")));

            await session.DisposeAsync();
            Assert.Equal(2, _handler.CloseCount);
        }
    }

    [Fact]
    public async Task Flush_NonTrueAck_Rejected_AndPoisons()
    {
        var (session, target) = await OpenAsync();
        _handler.FlushResponder = () => JsonResponse("{\"schemaVersion\":1,\"flushed\":false}");
        var ex = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => target.FlushAsync().AsTask());
        Assert.Contains("flush-ack", ex.Message, StringComparison.OrdinalIgnoreCase);

        var flushes = _handler.FlushCount;
        await Assert.ThrowsAsync<InvalidOperationException>(() => target.FlushAsync().AsTask());
        Assert.Equal(flushes, _handler.FlushCount);

        await session.DisposeAsync();
        Assert.Equal(1, _handler.CloseCount);
    }

    [Fact]
    public async Task Flush_MissingFlag_Rejected()
    {
        var (_, target) = await OpenAsync();
        _handler.FlushResponder = () => JsonResponse("{\"schemaVersion\":1}");
        var missing = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => target.FlushAsync().AsTask());
        Assert.Contains("flush-ack", missing.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Flush_HttpError_Rejected()
    {
        var (_, target) = await OpenAsync();
        _handler.FlushResponder = () => _handler.Error(HttpStatusCode.InternalServerError, "flush-fail", "sync failed");
        var ex = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => target.FlushAsync().AsTask());
        Assert.Contains("flush-fail", ex.Message);
    }

    // ------------------------------------------------------------- close

    [Fact]
    public async Task Close_Failure_PreservesException_ReleasesSlot_DisposeIdempotent()
    {
        var session = await ConnectAsync();
        var target = await session.OpenCardAsync(Variant());

        _handler.CloseResponder = () => _handler.Error(HttpStatusCode.InternalServerError, "close-fail", "device busy");
        var ex = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => target.DisposeAsync().AsTask());
        Assert.Contains("close-fail", ex.Message);
        Assert.Equal(1, _handler.CloseCount);

        await target.DisposeAsync();
        Assert.Equal(1, _handler.CloseCount);

        _handler.CloseResponder = null;
        var second = await session.OpenCardAsync(Variant());
        Assert.NotSame(target, second);
        await session.DisposeAsync();
        Assert.Equal(2, _handler.CloseCount);
    }

    [Fact]
    public async Task Close_FalseAck_Rejected()
    {
        var session = await ConnectAsync();
        var target = await session.OpenCardAsync(Variant());
        _handler.CloseResponder = () => JsonResponse("{\"schemaVersion\":1,\"closed\":false}");
        var falseAck = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => target.DisposeAsync().AsTask());
        Assert.Contains("close-ack", falseAck.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(1, _handler.CloseCount);
    }

    [Fact]
    public async Task DisposedTarget_RejectsFurtherIo_Locally()
    {
        var (session, target) = await OpenAsync();
        await target.DisposeAsync();
        var routes = _handler.Routes.Count;
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => target.WriteAsync(0, Sentinel(0x77, Sector)).AsTask());
        Assert.Equal(routes, _handler.Routes.Count);
        await session.DisposeAsync();
        Assert.Equal(1, _handler.CloseCount);
    }

    [Fact]
    public async Task SessionDisposal_DoesNotDisposeCallerHttpClient()
    {
        var session = await ConnectAsync();
        await session.DisposeAsync();

        using var request = new HttpRequestMessage(HttpMethod.Get, BaseUrl + "/v1/inspect");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", Token);
        using var response = await _client.SendAsync(request);
        response.EnsureSuccessStatusCode();
        Assert.Contains("/v1/inspect", _handler.Routes[^1]);
    }

    // ------------------------------------------------------------- cancellation / timeout

    [Fact]
    public async Task CallerCancellation_Propagates_ClientStaysUsable()
    {
        var session = await ConnectAsync();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => session.DiscoverCardsAsync(cts.Token));

        var cards = await session.DiscoverCardsAsync(CancellationToken.None);
        Assert.Single(cards);
    }

    [Fact]
    public async Task OperationTimeout_BecomesTimeoutException_AndPoisonsTarget()
    {
        var (session, target) = await OpenAsync();
        _handler.WriteResponder = (offset, body) => throw new OperationCanceledException();
        await Assert.ThrowsAsync<TimeoutException>(
            () => target.WriteAsync(0, Sentinel(0x88, Sector)).AsTask());

        _handler.WriteResponder = null;
        var writes = _handler.WriteCount;
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => target.WriteAsync(Sector, Sentinel(0x89, Sector)).AsTask());
        Assert.Equal(writes, _handler.WriteCount);

        await session.DisposeAsync();
        Assert.Equal(1, _handler.CloseCount);
    }

    [Fact]
    public async Task Read_StalledBody_HitsFullBodyDeadline_TimeoutException_PoisonsTarget()
    {
        var (session, target) = await OpenAsync();
        var abort = new CancellationTokenSource();
        var watchdog = new CancellationTokenSource();
        Task? operation = null;
        try
        {
            _handler.ReadResponder = (offset, count) =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StalledContent(count, testAbort: abort.Token),
                };
                response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
                response.Headers.Add("X-Content-SHA256", Sha256Hex(Sentinel(0x00, count)));
                return response;
            };

            var buffer = new byte[Sector];
            operation = target.ReadExactlyAsync(0, buffer).AsTask();
            var watchdogDelay = Task.Delay(TimeSpan.FromSeconds(35), watchdog.Token);
            var completed = await Task.WhenAny(operation, watchdogDelay);
            Assert.Same(operation, completed);
            await Assert.ThrowsAsync<TimeoutException>(() => operation);

            // The timed-out read poisons the target: later IO issues no HTTP request.
            var routes = _handler.Routes.Count;
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => target.WriteAsync(0, Sentinel(0x66, Sector)).AsTask());
            Assert.Equal(routes, _handler.Routes.Count);
        }
        finally
        {
            abort.Cancel();
            watchdog.Cancel();
            if (operation is not null)
            {
                try
                {
                    await operation;
                }
                catch
                {
                    // Cleanup observation only; the original try assertions decide pass/fail.
                }
            }

            await session.DisposeAsync();
        }

        Assert.Equal(1, _handler.CloseCount);
    }

    [Fact]
    public async Task Close_StalledJsonBody_HitsCloseDeadline_TimeoutException_NoDuplicateDelete()
    {
        var session = await ConnectAsync();
        var target = await session.OpenCardAsync(Variant());
        var abort = new CancellationTokenSource();
        var watchdog = new CancellationTokenSource();
        Task? operation = null;
        try
        {
            _handler.CloseResponder = () => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StalledContent(64, "application/json", testAbort: abort.Token),
            };

            operation = target.DisposeAsync().AsTask();
            var watchdogDelay = Task.Delay(TimeSpan.FromSeconds(8), watchdog.Token);
            var completed = await Task.WhenAny(operation, watchdogDelay);
            Assert.Same(operation, completed);
            await Assert.ThrowsAsync<TimeoutException>(() => operation);

            // Exactly one DELETE was issued; the failed close was not retried.
            Assert.Equal(1, _handler.CloseCount);
        }
        finally
        {
            abort.Cancel();
            watchdog.Cancel();
            if (operation is not null)
            {
                try
                {
                    await operation;
                }
                catch
                {
                    // Cleanup observation only; the original try assertions decide pass/fail.
                }
            }

            await session.DisposeAsync();
        }

        Assert.Equal(1, _handler.CloseCount);
    }

    [Fact]
    public async Task OnlyOneActiveCardPerSession()
    {
        var session = await ConnectAsync();
        var first = await session.OpenCardAsync(Variant());
        await Assert.ThrowsAsync<InvalidOperationException>(() => session.OpenCardAsync(Variant()));
        Assert.Equal(0, _handler.CloseCount);

        await first.DisposeAsync();
        var second = await session.OpenCardAsync(Variant());
        Assert.NotSame(first, second);
        await session.DisposeAsync();
        Assert.Equal(2, _handler.CloseCount);
    }

    // ------------------------------------------------------------- helpers

    private async Task<TfRamMaintenanceSession> ConnectAsync()
    {
        return await TfRamMaintenanceSession.ConnectAsync(_client, Token, "TB322FC", 1234567890UL, KernelSha);
    }

    private async Task<(TfRamMaintenanceSession Session, TfRamCardWriteTarget Target)> OpenAsync()
    {
        var session = await ConnectAsync();
        var target = await session.OpenCardAsync(Variant());
        return (session, target);
    }

    private static string F64(char c) => new(c, 64);

    private static byte[] Sentinel(byte value, int count) => Enumerable.Repeat(value, count).ToArray();

    private static string Sha256Hex(byte[] data) =>
        Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private static TfCardCandidate Variant(
        bool readOnly = false,
        bool? mounted = false,
        string androidUsage = "unknown",
        string? key = null,
        string? path = null,
        long? sizeBytes = null,
        int? sector = null)
    {
        return new TfCardCandidate(
            key ?? CardKey,
            path ?? CardPath,
            "Synthetic SD",
            sizeBytes ?? CardSize,
            sector ?? Sector,
            "SD",
            readOnly,
            false,
            false,
            mounted,
            androidUsage);
    }

    private static string BuildInspectJson(
        string model = "TB322FC",
        string soc = "sm8750",
        string socSerial = "1234567890",
        Guid? bootId = null,
        string? kernelSha256 = null,
        string? protocol = "tf-card-v1",
        bool ramOnly = true,
        string? source = "tablet",
        string? mediaJson = null)
    {
        var media = mediaJson ?? "[" + BuildMediaJson() + "]";
        var sb = new StringBuilder();
        sb.Append("{\"schemaVersion\":1");
        sb.Append(",\"protocol\":\"").Append(protocol).Append('"');
        sb.Append(",\"source\":\"").Append(source).Append('"');
        sb.Append(",\"ramOnly\":").Append(ramOnly ? "true" : "false");
        sb.Append(",\"model\":\"").Append(model).Append('"');
        sb.Append(",\"soc\":\"").Append(soc).Append('"');
        sb.Append(",\"socSerial\":\"").Append(socSerial).Append('"');
        sb.Append(",\"bootId\":\"").Append((bootId ?? BootId).ToString("D")).Append('"');
        sb.Append(",\"kernelSha256\":\"").Append(kernelSha256 ?? KernelSha).Append('"');
        sb.Append(",\"media\":").Append(media).Append('}');
        return sb.ToString();
    }

    private static string BuildMediaJson(
        string key = "sd:0123456789abcdef0123456789abcdef",
        string path = CardPath,
        long? sizeBytes = null,
        int? logicalSectorSize = null)
    {
        return "{"
            + "\"key\":\"" + key + "\","
            + "\"path\":\"" + path + "\","
            + "\"displayName\":\"Synthetic SD\","
            + "\"sizeBytes\":" + (sizeBytes ?? CardSize).ToString(CultureInfo.InvariantCulture) + ","
            + "\"logicalSectorSize\":" + (logicalSectorSize ?? Sector).ToString(CultureInfo.InvariantCulture) + ","
            + "\"mediumEvidence\":\"SD\","
            + "\"readOnly\":false,"
            + "\"isSystemDisk\":false,"
            + "\"isOffline\":false,"
            + "\"mounted\":false,"
            + "\"androidUsage\":\"unknown\""
            + "}";
    }

    private static string BuildIdentityJson(string key, string path, long sizeBytes, int logicalSectorSize, string binding)
    {
        return "{"
            + "\"source\":\"tablet\","
            + "\"key\":\"" + key + "\","
            + "\"path\":\"" + path + "\","
            + "\"sizeBytes\":" + sizeBytes.ToString(CultureInfo.InvariantCulture) + ","
            + "\"logicalSectorSize\":" + logicalSectorSize.ToString(CultureInfo.InvariantCulture) + ","
            + "\"bindingSha256\":\"" + binding + "\""
            + "}";
    }

    private static string OpenEnvelope(string cardSessionId, string identityJson)
    {
        return "{\"schemaVersion\":1,\"cardSessionId\":\"" + cardSessionId + "\",\"identity\":" + identityJson + "}";
    }

    private static HttpResponseMessage JsonResponse(string json)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
    }

    private static HttpResponseMessage BinaryResponse(byte[] data)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(data) };
        response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
        response.Headers.Add("X-Content-SHA256", Sha256Hex(data));
        return response;
    }

    /// <summary>
    /// HttpContent whose declared Content-Length differs from the bytes it actually serializes, to
    /// exercise short and extra actual bodies against the fixed contract.
    /// </summary>
    private sealed class LyingContent : HttpContent
    {
        private readonly byte[] _data;

        private readonly long _declaredLength;

        public LyingContent(byte[] data, long declaredLength)
        {
            _data = data;
            _declaredLength = declaredLength;
        }

        protected override bool TryComputeLength(out long length)
        {
            length = _declaredLength;
            return true;
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            return stream.WriteAsync(_data).AsTask();
        }
    }

    /// <summary>
    /// HttpContent that declares a valid length but whose stream never delivers bytes: its ReadAsync
    /// waits on the supplied token, which production wiring cancels at the operation's full-body
    /// deadline. Used to prove deadlines cover body consumption, not just headers.
    /// </summary>
    private sealed class StalledContent : HttpContent
    {
        private readonly long _declaredLength;

        private readonly string _mediaType;

        private readonly CancellationToken _testAbort;

        public StalledContent(long declaredLength, string mediaType = "application/octet-stream", CancellationToken testAbort = default)
        {
            _declaredLength = declaredLength;
            _mediaType = mediaType;
            _testAbort = testAbort;
        }

        protected override bool TryComputeLength(out long length)
        {
            length = _declaredLength;
            return true;
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            // Declared-length zero bytes for clients that buffer; the real read path uses
            // ReadAsStreamAsync and stalls on the token in the returned stream instead.
            return stream.WriteAsync(new byte[_declaredLength]).AsTask();
        }

        protected override Task<Stream> CreateContentReadStreamAsync()
        {
            return Task.FromResult<Stream>(new StalledStream(_declaredLength, _testAbort));
        }

        private sealed class StalledStream : Stream
        {
            private long _remaining;

            private readonly CancellationToken _testAbort;

            public StalledStream(long length, CancellationToken testAbort = default)
            {
                _remaining = length;
                _testAbort = testAbort;
            }

            public override bool CanRead => true;

            public override bool CanSeek => false;

            public override bool CanWrite => false;

            public override long Length => _remaining;

            public override long Position
            {
                get => 0;
                set => throw new NotSupportedException();
            }

            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
            {
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _testAbort);
                await Task.Delay(Timeout.Infinite, linked.Token);
                return 0;
            }

            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

            public override void Flush() { }

            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

            public override void SetLength(long value) => throw new NotSupportedException();

            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }
    }

    /// <summary>
    /// Ordinary hand-written message handler: a direct switch on the fixed protocol routes serving a
    /// small in-memory card. No mock DSL, no reflection, no generic command parser.
    /// </summary>
    private sealed class FakeRamServiceHandler : HttpMessageHandler
    {
        private readonly byte[] _card;

        public FakeRamServiceHandler(byte[] card)
        {
            _card = card;
        }

        public string InspectJson { get; set; } = string.Empty;

        public HttpStatusCode InspectStatus { get; set; } = HttpStatusCode.OK;

        public string? OpenJsonOverride { get; set; }

        public string? IdentityJsonOverride { get; set; }

        public Func<long, byte[], HttpResponseMessage>? WriteResponder { get; set; }

        public Func<long, int, HttpResponseMessage>? ReadResponder { get; set; }

        public Func<HttpResponseMessage>? FlushResponder { get; set; }

        public Func<HttpResponseMessage>? CloseResponder { get; set; }

        public string? ErrorBodyOverride { get; set; }

        public List<string> Routes { get; } = new();

        public List<long?> RequestContentLengths { get; } = new();

        public List<byte[]> WriteBodies { get; } = new();

        public List<long> WriteOffsets { get; } = new();

        public List<string?> WriteHeaderHashes { get; } = new();

        public int WriteCount { get; private set; }

        public int FlushCount { get; private set; }

        public int CloseCount { get; private set; }

        public HttpResponseMessage Error(HttpStatusCode status, string code, string message)
        {
            if (ErrorBodyOverride is not null)
            {
                return new HttpResponseMessage(status)
                {
                    Content = new StringContent(ErrorBodyOverride, Encoding.UTF8, "text/html"),
                };
            }

            var safeCode = code.Replace("\"", string.Empty);
            var safeMessage = message.Replace("\"", string.Empty);
            return new HttpResponseMessage(status)
            {
                Content = new StringContent(
                    "{\"schemaVersion\":1,\"error\":{\"code\":\"" + safeCode + "\",\"message\":\"" + safeMessage + "\"}}",
                    Encoding.UTF8,
                    "application/json"),
            };
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var uri = request.RequestUri!.ToString();
            Assert.Equal(BaseUrl + request.RequestUri.PathAndQuery, uri);
            Assert.Equal("Bearer " + Token, request.Headers.TryGetValues("Authorization", out var auth) ? auth.Single() : null);
            Assert.DoesNotContain(Token, uri);

            Routes.Add(request.Method.Method + " " + request.RequestUri.PathAndQuery);
            RequestContentLengths.Add(request.Content?.Headers.ContentLength);

            var pathAndQuery = request.RequestUri.PathAndQuery;

            if (request.Method == HttpMethod.Get && pathAndQuery == "/v1/inspect")
            {
                if (InspectStatus != HttpStatusCode.OK)
                {
                    return Error(InspectStatus, "inspect-fail", "synthetic inspect failure");
                }

                return JsonResponse(InspectJson);
            }

            if (request.Method == HttpMethod.Post && pathAndQuery == "/v1/card/open")
            {
                var body = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
                if (OpenJsonOverride is not null)
                {
                    return JsonResponse(OpenJsonOverride);
                }

                var identity = BuildIdentityJson(CardKey, CardPath, CardSize, Sector, F64('f'));
                return JsonResponse(OpenEnvelope(CardSessionId, identity));
            }

            var cardPrefix = "/v1/card/" + CardSessionId + "/";
            if (pathAndQuery.StartsWith(cardPrefix, StringComparison.Ordinal))
            {
                var rest = pathAndQuery[cardPrefix.Length..];
                if (request.Method == HttpMethod.Get && rest.StartsWith("identity", StringComparison.Ordinal))
                {
                    if (IdentityJsonOverride is not null)
                    {
                        return JsonResponse(IdentityJsonOverride);
                    }

                    var identity = BuildIdentityJson(CardKey, CardPath, CardSize, Sector, F64('f'));
                    return JsonResponse("{\"schemaVersion\":1,\"identity\":" + identity + "}");
                }

                if (request.Method == HttpMethod.Post && rest.StartsWith("write?offset=", StringComparison.Ordinal))
                {
                    WriteCount++;
                    var body = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
                    var offset = QueryLong(pathAndQuery, "offset");
                    WriteOffsets.Add(offset);
                    WriteBodies.Add(body);
                    WriteHeaderHashes.Add(
                        request.Headers.TryGetValues("X-Content-SHA256", out var values) ? values.FirstOrDefault() : null);
                    if (WriteResponder is not null)
                    {
                        return WriteResponder(offset, body);
                    }

                    if (offset < 0 || offset + body.Length > _card.Length)
                    {
                        return Error(HttpStatusCode.RequestedRangeNotSatisfiable, "range", "out of card bounds");
                    }

                    Array.Copy(body, 0, _card, offset, body.Length);
                    return JsonResponse(
                        "{\"schemaVersion\":1,\"writtenBytes\":" + body.Length.ToString(CultureInfo.InvariantCulture)
                        + ",\"sha256\":\"" + Sha256Hex(body) + "\"}");
                }

                if (request.Method == HttpMethod.Get && rest.StartsWith("read?offset=", StringComparison.Ordinal))
                {
                    var offset = QueryLong(pathAndQuery, "offset");
                    var count = (int)QueryLong(pathAndQuery, "bytes");
                    if (ReadResponder is not null)
                    {
                        return ReadResponder(offset, count);
                    }

                    var data = new byte[count];
                    Array.Copy(_card, offset, data, 0, count);
                    return BinaryResponse(data);
                }

                if (request.Method == HttpMethod.Post && rest == "flush")
                {
                    FlushCount++;
                    if (FlushResponder is not null)
                    {
                        return FlushResponder();
                    }

                    return JsonResponse("{\"schemaVersion\":1,\"flushed\":true}");
                }
            }

            if (request.Method == HttpMethod.Delete && pathAndQuery == "/v1/card/" + CardSessionId)
            {
                CloseCount++;
                if (CloseResponder is not null)
                {
                    return CloseResponder();
                }

                return JsonResponse("{\"schemaVersion\":1,\"closed\":true}");
            }

            return Error(HttpStatusCode.NotFound, "route", "unknown synthetic route");
        }

        private static long QueryLong(string pathAndQuery, string name)
        {
            var query = pathAndQuery[(pathAndQuery.IndexOf('?') + 1)..];
            foreach (var pair in query.Split('&'))
            {
                var kv = pair.Split('=', 2);
                if (kv[0] == name)
                {
                    return long.Parse(kv[1], CultureInfo.InvariantCulture);
                }
            }

            return 0;
        }
    }
}
