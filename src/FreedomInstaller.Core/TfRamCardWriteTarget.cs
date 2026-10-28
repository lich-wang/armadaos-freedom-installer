using System;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// Short factual protocol failure of the RAM SD card service. The message carries only the stable
/// error code and a bounded server detail; it never contains the bearer token, an authorization
/// header or an unbounded response body.
/// </summary>
internal sealed class TfRamProtocolException : InvalidOperationException
{
    internal TfRamProtocolException(string code, string detail)
        : base($"RAM 卡服务协议错误 {code}: {detail}")
    {
        Code = code;
    }

    /// <summary>Stable short error code, suitable for surfacing to the user.</summary>
    internal string Code { get; }
}

/// <summary>
/// Fixed wire plumbing shared by the RAM maintenance session and the opened card target. Every URI is
/// pinned to the RAM service endpoint; client.BaseAddress is never consulted. Every request carries a
/// finite operation timeout linked to caller cancellation, uses ResponseHeadersRead, and every JSON
/// body is read with a hard size bound.
/// </summary>
internal static class TfRamWire
{
    /// <summary>The only RAM service endpoint this client ever talks to.</summary>
    internal const string BaseUri = "http://192.168.77.1:8203";

    internal const string ProtocolName = "tf-card-v1";

    /// <summary>Hard bound for the inspect response, which also carries the media inventory.</summary>
    internal const int MaxInspectBytes = 256 * 1024;

    /// <summary>Hard bound for every small JSON success envelope.</summary>
    internal const int MaxEnvelopeBytes = 8 * 1024;

    /// <summary>Finite timeout for inspect / open / identity / write / read / flush.</summary>
    internal static readonly TimeSpan OperationTimeout = TimeSpan.FromSeconds(30);

    /// <summary>Finite timeout for the close request only.</summary>
    internal static readonly TimeSpan CloseTimeout = TimeSpan.FromSeconds(5);

    private static readonly Regex WholeDevicePathPattern = new("^/dev/mmcblk[0-9]+$", RegexOptions.Compiled);

    internal static Uri Uri(string pathAndQuery) => new(BaseUri + pathAndQuery, UriKind.Absolute);

    internal static TfRamProtocolException Protocol(string code, string detail) => new(code, detail);

    internal static bool IsWholeDevicePath(string path) => WholeDevicePathPattern.IsMatch(path);

    /// <summary>Exactly 64 lowercase hexadecimal digits: the only accepted bearer token shape.</summary>
    internal static bool IsLowerHex64(string? value)
    {
        if (value is null || value.Length != 64)
        {
            return false;
        }

        return value.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }

    internal static bool IsHex64(string? value) => IsHex(value, 64);

    internal static bool IsHex32(string? value) => IsHex(value, 32);

    private static bool IsHex(string? value, int length)
    {
        if (value is null || value.Length != length)
        {
            return false;
        }

        return value.All(IsHexDigit);
    }

    private static bool IsHexDigit(char c) =>
        (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');

    private static bool IsDecimalDigit(char c) => c >= '0' && c <= '9';

    /// <summary>
    /// Normalizes a wire SoC serial to its numeric value. The wire string may be invariant decimal,
    /// 0x-prefixed hexadecimal, or bare hexadecimal containing A-F; the comparison afterwards is
    /// numeric only, never a string or Android device serial comparison.
    /// </summary>
    internal static ulong ParseSocSerial(string wire)
    {
        var text = wire.Trim();
        if (text.Length == 0)
        {
            throw Protocol("socSerial", "socSerial 字段为空。");
        }

        if (text.All(IsDecimalDigit))
        {
            if (!ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var decimalValue))
            {
                throw Protocol("socSerial", "socSerial 十进制值超出 64 位范围。");
            }

            return decimalValue;
        }

        var hex = text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? text[2..]
            : (text.All(IsHexDigit) ? text : null);
        if (string.IsNullOrEmpty(hex) || !hex.All(IsHexDigit))
        {
            throw Protocol("socSerial", "socSerial 既不是十进制也不是十六进制格式。");
        }

        if (!ulong.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hexValue))
        {
            throw Protocol("socSerial", "socSerial 十六进制值超出 64 位范围。");
        }

        return hexValue;
    }

    /// <summary>
    /// Sends one request with the bearer authorization header, ResponseHeadersRead and a token that
    /// is ALREADY OWNED by the caller's bounded operation. This helper never creates or disposes a
    /// second, shorter-lived CTS around the headers; the full-body JSON scope below owns the deadline.
    /// Caller cancellation propagates unchanged. The token is never part of any exception text or URI.
    /// </summary>
    internal static async Task<HttpResponseMessage> SendAsync(
        HttpClient client,
        string bearerToken,
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + bearerToken);
        try
        {
            return await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("RAM 卡服务请求超时，本次操作已放弃。");
        }
    }

    /// <summary>
    /// One bounded JSON exchange: a linked CTS with a finite CancelAfter stays alive through the
    /// headers AND the whole response body read. Returns the materialized JsonDocument which the
    /// caller owns and must dispose. Caller cancellation stays OperationCanceledException; a
    /// deadline hit inside this scope becomes the existing TimeoutException contract. The token is
    /// never logged and the caller HttpClient is never mutated or disposed.
    /// </summary>
    internal static async Task<JsonDocument> SendJsonAsync(
        HttpClient client,
        string bearerToken,
        HttpRequestMessage request,
        int maxBytes,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        operation.CancelAfter(timeout);
        try
        {
            using var response = await SendAsync(client, bearerToken, request, operation.Token);
            return await ReadJsonAsync(response, maxBytes, operation.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("RAM 卡服务请求超时，本次操作已放弃。");
        }
    }

    /// <summary>
    /// Requires HTTP 200, reads the body with a hard size bound and parses it as a JSON object with
    /// schemaVersion 1. Anything else becomes a short factual protocol error.
    /// </summary>
    internal static async Task<JsonDocument> ReadJsonAsync(
        HttpResponseMessage response,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw await CreateServerErrorAsync(response, cancellationToken);
        }

        var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        var buffer = new byte[maxBytes + 1];
        var total = 0;
        using (stream)
        {
            int read;
            while ((read = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total), cancellationToken)) > 0)
            {
                total += read;
                if (total > maxBytes)
                {
                    throw Protocol("body-too-large", $"响应体超过 {maxBytes} 字节上限。");
                }
            }
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(Encoding.UTF8.GetString(buffer, 0, total));
        }
        catch (JsonException exception)
        {
            throw Protocol("body-json", "响应体不是合法 JSON：" + exception.Message);
        }

        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            document.Dispose();
            throw Protocol("body-shape", "响应根节点不是 JSON 对象。");
        }

        RequireSchemaVersion1(document.RootElement);
        return document;
    }

    /// <summary>
    /// Builds a short factual error for a non-200 response. The bounded error envelope
    /// {schemaVersion:1,error:{code,message}} is preferred; a malformed body collapses to a generic
    /// HTTP status error. Neither the authorization header nor the raw body is ever included.
    /// </summary>
    internal static async Task<TfRamProtocolException> CreateServerErrorAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        var status = (int)response.StatusCode;
        try
        {
            var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            var buffer = new byte[4097];
            var total = 0;
            int read;
            while (total < buffer.Length
                && (read = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total), cancellationToken)) > 0)
            {
                total += read;
            }

            using var document = JsonDocument.Parse(Encoding.UTF8.GetString(buffer, 0, total));
            var root = document.RootElement;
            if (root.ValueKind == JsonValueKind.Object
                && root.TryGetProperty("error", out var error)
                && error.ValueKind == JsonValueKind.Object
                && error.TryGetProperty("code", out var codeElement)
                && codeElement.ValueKind == JsonValueKind.String)
            {
                var code = ShortLine(codeElement.GetString() ?? string.Empty, 64);
                var message = string.Empty;
                if (error.TryGetProperty("message", out var messageElement)
                    && messageElement.ValueKind == JsonValueKind.String)
                {
                    message = ShortLine(messageElement.GetString() ?? string.Empty, 200);
                }

                return new TfRamProtocolException(code, message);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            // fall through to the generic HTTP error below
        }

        return new TfRamProtocolException(
            "http-" + status.ToString(CultureInfo.InvariantCulture),
            "服务返回非 200 响应。");
    }

    internal static void RequireSchemaVersion1(JsonElement root)
    {
        if (!root.TryGetProperty("schemaVersion", out var schema)
            || schema.ValueKind != JsonValueKind.Number
            || !schema.TryGetInt32(out var version)
            || version != 1)
        {
            throw Protocol("schemaVersion", "响应 schemaVersion 不是 1。");
        }
    }

    internal static string RequireString(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var property)
            || property.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(property.GetString()))
        {
            throw Protocol(name, $"响应缺少字符串字段 {name}。");
        }

        return property.GetString()!.Trim();
    }

    internal static long RequireInt64(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var property)
            || property.ValueKind != JsonValueKind.Number
            || !property.TryGetInt64(out var value))
        {
            throw Protocol(name, $"响应缺少整数字段 {name}。");
        }

        return value;
    }

    internal static int RequireInt32(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var property)
            || property.ValueKind != JsonValueKind.Number
            || !property.TryGetInt32(out var value))
        {
            throw Protocol(name, $"响应缺少整数字段 {name}。");
        }

        return value;
    }

    /// <summary>
    /// Parses and fully validates one wire identity object: tablet source, tablet-prefixed whole
    /// device key and path, positive sector-aligned size, 512/4096 sector size and a 64-hex binding.
    /// </summary>
    internal static TfCardTargetIdentity ParseIdentity(JsonElement element, string context)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw Protocol("identity", $"{context} 响应的 identity 不是 JSON 对象。");
        }

        var source = RequireString(element, "source");
        if (source != "tablet")
        {
            throw Protocol("identity", $"{context} 响应的 identity.source 不是 tablet。");
        }

        var key = RequireString(element, "key");
        if (!key.StartsWith("tablet:", StringComparison.Ordinal))
        {
            throw Protocol("identity", $"{context} 响应的 identity.key 缺少 tablet: 前缀。");
        }

        var path = RequireString(element, "path");
        if (!IsWholeDevicePath(path))
        {
            throw Protocol("identity", $"{context} 响应的 identity.path 不是整块 /dev/mmcblkN 设备。");
        }

        var sizeBytes = RequireInt64(element, "sizeBytes");
        var logicalSectorSize = RequireInt32(element, "logicalSectorSize");
        if (logicalSectorSize != 512 && logicalSectorSize != 4096)
        {
            throw Protocol("identity", $"{context} 响应的 logicalSectorSize 不是 512 或 4096。");
        }

        if (sizeBytes <= 0 || sizeBytes % logicalSectorSize != 0)
        {
            throw Protocol("identity", $"{context} 响应的 sizeBytes 不是正数或未按扇区对齐。");
        }

        var bindingSha256 = RequireString(element, "bindingSha256");
        if (!IsHex64(bindingSha256))
        {
            throw Protocol("identity", $"{context} 响应的 bindingSha256 不是 64 位十六进制字符。");
        }

        return new TfCardTargetIdentity(
            TfCardSource.Tablet,
            key,
            path,
            sizeBytes,
            logicalSectorSize,
            bindingSha256);
    }

    private static string ShortLine(string value, int maxLength)
    {
        var text = new string(value.Where(c => !char.IsControl(c)).ToArray()).Trim();
        return text.Length <= maxLength ? text : text[..maxLength];
    }
}

/// <summary>
/// One authenticated RAM-service maintenance session to the tablet's temporary-boot SD card service.
/// <see cref="ConnectAsync"/> performs the authorized identity handshake and pins the reported model,
/// normalized SoC serial, boot id and kernel marker claim; every later inspect must reproduce them
/// exactly. The caller owns and disposes the HttpClient; the session never disposes it. Disposal only
/// closes the session's own active card — there is no reset or other device state transition.
/// </summary>
public sealed class TfRamMaintenanceSession : IAsyncDisposable
{
    private const string ModelG4 = "TB322FC";

    private const string ModelG5 = "TB323FU";

    private const string SocSm8750 = "sm8750";

    private const string SocKaanapali = "kaanapali";

    private static bool IsExpectedSocForModel(string model, string soc) =>
        (model == ModelG4 && soc == SocSm8750) || (model == ModelG5 && soc == SocKaanapali);

    private readonly HttpClient _client;

    private readonly string _bearerToken;

    private readonly string _model;

    private readonly ulong _socSerial;

    private readonly Guid _bootId;

    private readonly string _kernelSha256;

    private readonly object _gate = new();

    private TfRamCardWriteTarget? _activeCard;

    private TfRamMaintenanceSession(HttpClient client, string bearerToken, RamInspectReport report)
    {
        _client = client;
        _bearerToken = bearerToken;
        _model = report.Model;
        _socSerial = report.SocSerial;
        _bootId = report.BootId;
        _kernelSha256 = report.KernelSha256;
    }

    /// <summary>Canonical model reported by the handshake.</summary>
    public string Model => _model;

    /// <summary>SoC serial as a normalized numeric value, compared numerically against the expectation.</summary>
    public ulong SocSerial => _socSerial;

    /// <summary>Nonzero boot id (canonical GUID-D) of the RAM boot this session is bound to.</summary>
    public Guid BootId => _bootId;

    /// <summary>Kernel marker claim from the handshake. This is an identity claim, never a live proof
    /// that the running kernel digest matches; the separate Workflow prerequisite owns that proof.</summary>
    public string KernelSha256 => _kernelSha256;

    internal HttpClient Client => _client;

    internal string BearerToken => _bearerToken;

    /// <summary>
    /// Performs the authorized GET /v1/inspect handshake and requires the reported RAM-service
    /// identity to match the caller's expectation exactly: canonical model, numerically equal SoC
    /// serial and byte-equal kernel marker. Any mismatch, wrong protocol, missing ramOnly flag or
    /// bad token shape fails before a session exists.
    /// </summary>
    public static async Task<TfRamMaintenanceSession> ConnectAsync(
        HttpClient client,
        string bearerToken,
        string expectedModel,
        ulong expectedSocSerial,
        string expectedKernelSha256,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        if (!TfRamWire.IsLowerHex64(bearerToken))
        {
            throw new ArgumentException("Bearer 令牌必须是 64 位小写十六进制字符。", nameof(bearerToken));
        }

        if (expectedModel != ModelG4 && expectedModel != ModelG5)
        {
            throw new ArgumentException($"预期机型必须是 {ModelG4} 或 {ModelG5}。", nameof(expectedModel));
        }

        if (expectedSocSerial == 0)
        {
            throw new ArgumentException("预期 SoC 序列号不能为 0。", nameof(expectedSocSerial));
        }

        if (!TfRamWire.IsHex64(expectedKernelSha256))
        {
            throw new ArgumentException("预期内核标记必须是 64 位十六进制字符。", nameof(expectedKernelSha256));
        }

        var report = ParseInspect(await GetInspectJsonAsync(client, bearerToken, cancellationToken));
        if (report.Model != expectedModel)
        {
            throw TfRamWire.Protocol("model", $"RAM 服务报告机型 {report.Model} 与预期 {expectedModel} 不一致。");
        }

        if (report.SocSerial != expectedSocSerial)
        {
            throw TfRamWire.Protocol("socSerial", "RAM 服务报告的 SoC 序列号与预期数值不一致。");
        }

        if (!string.Equals(report.KernelSha256, expectedKernelSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw TfRamWire.Protocol("kernelSha256", "RAM 服务报告的内核标记与预期不一致。");
        }

        return new TfRamMaintenanceSession(client, bearerToken, report);
    }

    /// <summary>
    /// Re-inspects the service and parses the same root JSON through
    /// <see cref="TfCardSupport.ParseCandidates"/> for the tablet source. The retained handshake
    /// identity must be reproduced exactly or the call fails.
    /// </summary>
    public async Task<IReadOnlyList<TfCardCandidate>> DiscoverCardsAsync(CancellationToken cancellationToken = default)
    {
        var report = await InspectAsync(cancellationToken);
        return TfCardSupport.ParseCandidates(report.RawJson, TfCardSource.Tablet);
    }

    /// <summary>
    /// Opens the one selected card. A fresh inspect must list exactly one candidate that matches the
    /// expected key, path, size and sector facts, the candidate must be an eligible whole-device SD
    /// card, and the POST /v1/card/open response must freeze an identity equal to that candidate.
    /// Only one card may be active per session at a time.
    /// </summary>
    public async Task<TfRamCardWriteTarget> OpenCardAsync(TfCardCandidate expected, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expected);
        lock (_gate)
        {
            if (_activeCard is not null)
            {
                throw new InvalidOperationException("本会话已有一张打开的卡片，必须先关闭后才能打开下一张。");
            }
        }

        ValidateSelectableCandidate(expected);
        var report = await InspectAsync(cancellationToken);
        var candidates = TfCardSupport.ParseCandidates(report.RawJson, TfCardSource.Tablet);
        var matches = candidates
            .Where(c => c.Key == expected.Key
                && c.Path == expected.Path
                && c.SizeBytes == expected.SizeBytes
                && c.LogicalSectorSize == expected.LogicalSectorSize)
            .ToList();
        if (matches.Count == 0)
        {
            throw TfRamWire.Protocol("card-missing", "所选卡片不在最新发现结果中，拒绝打开。");
        }

        if (matches.Count > 1)
        {
            throw TfRamWire.Protocol("card-ambiguous", "所选卡片事实匹配到多张候选，拒绝打开。");
        }

        var openJson = JsonSerializer.Serialize(
            new OpenCardRequest(expected.Key, expected.Path, expected.SizeBytes, expected.LogicalSectorSize),
            OpenCardJsonOptions);
        using var request = new HttpRequestMessage(HttpMethod.Post, TfRamWire.Uri("/v1/card/open"));
        request.Content = new StringContent(openJson, Encoding.UTF8, "application/json");
        string? openedId = null;
        var published = false;
        try
        {
            using var json = await TfRamWire.SendJsonAsync(
                _client, _bearerToken, request, TfRamWire.MaxEnvelopeBytes, TfRamWire.OperationTimeout, cancellationToken);
            var root = json.RootElement;
            var cardSessionId = TfRamWire.RequireString(root, "cardSessionId");
            if (!TfRamWire.IsHex32(cardSessionId))
            {
                throw TfRamWire.Protocol("open-session", "cardSessionId 必须是 32 位十六进制字符。");
            }

            openedId = cardSessionId;
            if (!root.TryGetProperty("identity", out var identityElement))
            {
                throw TfRamWire.Protocol("open-identity", "open 响应缺少 identity 字段。");
            }

            var wireIdentity = TfRamWire.ParseIdentity(identityElement, "open");
            if (wireIdentity.Key != expected.Key
                || wireIdentity.DevicePath != expected.Path
                || wireIdentity.SizeBytes != expected.SizeBytes
                || wireIdentity.LogicalSectorSize != expected.LogicalSectorSize)
            {
                throw TfRamWire.Protocol("open-identity", "open 响应的 identity 与所选卡片不一致。");
            }

            var identity = new TfCardTargetIdentity(
                TfCardSource.Tablet,
                expected.Key,
                expected.Path,
                expected.SizeBytes,
                expected.LogicalSectorSize,
                wireIdentity.BindingSha256);
            var target = new TfRamCardWriteTarget(this, identity, cardSessionId);
            lock (_gate)
            {
                if (_activeCard is not null)
                {
                    throw new InvalidOperationException("本会话已有一张打开的卡片，必须先关闭后才能打开下一张。");
                }

                _activeCard = target;
            }

            published = true;
            return target;
        }
        catch (Exception original)
        {
            if (openedId is null || published)
            {
                throw;
            }

            try
            {
                await CloseOwnedCardAsync(openedId);
            }
            catch (Exception cleanup)
            {
                throw new AggregateException("打开卡片失败，且回收服务端卡片会话也失败。", original, cleanup);
            }

            throw;
        }
    }

    internal void ReleaseCard(TfRamCardWriteTarget target)
    {
        lock (_gate)
        {
            if (ReferenceEquals(_activeCard, target))
            {
                _activeCard = null;
            }
        }
    }

    /// <summary>
    /// Closes a server-created card session that this session owns. Used both by target disposal
    /// and by open rollback for a known but unpublished card id. The caller's HttpClient is never disposed.
    /// </summary>
    internal async Task CloseOwnedCardAsync(string cardSessionId)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, TfRamWire.Uri("/v1/card/" + cardSessionId));
        request.Content = new ByteArrayContent(Array.Empty<byte>());
        using var json = await TfRamWire.SendJsonAsync(
            _client, _bearerToken, request, TfRamWire.MaxEnvelopeBytes, TfRamWire.CloseTimeout, CancellationToken.None);
        if (!json.RootElement.TryGetProperty("closed", out var closed) || closed.ValueKind != JsonValueKind.True)
        {
            throw TfRamWire.Protocol("close-ack", "close 未被服务确认为成功。");
        }
    }

    /// <summary>Closes the session's own active card, exactly once. The caller's HttpClient is never
    /// disposed and stays usable afterwards.</summary>
    public async ValueTask DisposeAsync()
    {
        TfRamCardWriteTarget? card;
        lock (_gate)
        {
            card = _activeCard;
            _activeCard = null;
        }

        if (card is not null)
        {
            await card.DisposeAsync();
        }
    }

    private async Task<RamInspectReport> InspectAsync(CancellationToken cancellationToken)
    {
        var report = ParseInspect(await GetInspectJsonAsync(_client, _bearerToken, cancellationToken));
        if (report.Model != _model
            || report.SocSerial != _socSerial
            || report.BootId != _bootId
            || !string.Equals(report.KernelSha256, _kernelSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw TfRamWire.Protocol("inspect-drift", "RAM 服务身份与握手结果不一致，拒绝继续。");
        }

        return report;
    }

    private static async Task<string> GetInspectJsonAsync(
        HttpClient client,
        string bearerToken,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, TfRamWire.Uri("/v1/inspect"));
        using var json = await TfRamWire.SendJsonAsync(
            client, bearerToken, request, TfRamWire.MaxInspectBytes, TfRamWire.OperationTimeout, cancellationToken);
        return json.RootElement.GetRawText();
    }

    private static RamInspectReport ParseInspect(string rawJson)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(rawJson);
        }
        catch (JsonException exception)
        {
            throw TfRamWire.Protocol("inspect-json", "inspect 响应不是合法 JSON：" + exception.Message);
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw TfRamWire.Protocol("inspect-shape", "inspect 响应根节点不是 JSON 对象。");
            }

            TfRamWire.RequireSchemaVersion1(root);
            var protocol = TfRamWire.RequireString(root, "protocol");
            if (protocol != TfRamWire.ProtocolName)
            {
                throw TfRamWire.Protocol("protocol", $"inspect 响应的 protocol 不是 {TfRamWire.ProtocolName}。");
            }

            var source = TfRamWire.RequireString(root, "source");
            if (source != "tablet")
            {
                throw TfRamWire.Protocol("source", "inspect 响应的 source 不是 tablet。");
            }

            if (!root.TryGetProperty("ramOnly", out var ramOnly) || ramOnly.ValueKind != JsonValueKind.True)
            {
                throw TfRamWire.Protocol("ramOnly", "inspect 响应缺少 ramOnly=true。");
            }

            var model = TfRamWire.RequireString(root, "model");
            if (model != ModelG4 && model != ModelG5)
            {
                throw TfRamWire.Protocol("model", $"inspect 响应的机型 {model} 不是 {ModelG4} 或 {ModelG5}。");
            }

            var soc = TfRamWire.RequireString(root, "soc");
            if (!IsExpectedSocForModel(model, soc))
            {
                throw TfRamWire.Protocol(
                    "soc",
                    $"inspect 响应的机型 {model} 与 SoC {soc} 不是配对组合（{ModelG4}/{SocSm8750} 或 {ModelG5}/{SocKaanapali}）。");
            }

            var serialText = TfRamWire.RequireString(root, "socSerial");
            var socSerial = TfRamWire.ParseSocSerial(serialText);
            if (socSerial == 0)
            {
                throw TfRamWire.Protocol("socSerial", "inspect 响应的 SoC 序列号为 0。");
            }

            var bootText = TfRamWire.RequireString(root, "bootId");
            if (!Guid.TryParseExact(bootText, "D", out var bootId) || bootId == Guid.Empty)
            {
                throw TfRamWire.Protocol("bootId", "inspect 响应的 bootId 不是非零的 GUID-D 格式。");
            }

            var kernelSha256 = TfRamWire.RequireString(root, "kernelSha256");
            if (!TfRamWire.IsHex64(kernelSha256))
            {
                throw TfRamWire.Protocol("kernelSha256", "inspect 响应的 kernelSha256 不是 64 位十六进制字符。");
            }

            return new RamInspectReport(
                model,
                socSerial,
                bootId,
                kernelSha256.ToLowerInvariant(),
                rawJson);
        }
    }

    /// <summary>
    /// Only an eligible whole-device SD card may be opened: tablet:sd: key, whole /dev/mmcblkN path,
    /// positive aligned size, 512/4096 sectors, and not read-only, system, offline, mounted or
    /// adopted by Android.
    /// </summary>
    private static void ValidateSelectableCandidate(TfCardCandidate candidate)
    {
        if (!candidate.Key.StartsWith("tablet:sd:", StringComparison.Ordinal))
        {
            throw new ArgumentException($"卡片键 {candidate.Key} 缺少 tablet:sd: 前缀。", nameof(candidate));
        }

        if (!TfRamWire.IsWholeDevicePath(candidate.Path))
        {
            throw new ArgumentException($"卡片路径 {candidate.Path} 不是整块 /dev/mmcblkN 设备。", nameof(candidate));
        }

        if (candidate.LogicalSectorSize != 512 && candidate.LogicalSectorSize != 4096)
        {
            throw new ArgumentException("卡片逻辑扇区必须是 512 或 4096 字节。", nameof(candidate));
        }

        if (candidate.SizeBytes <= 0 || candidate.SizeBytes % candidate.LogicalSectorSize != 0)
        {
            throw new ArgumentException("卡片容量必须是正数并按扇区对齐。", nameof(candidate));
        }

        if (candidate.ReadOnly || candidate.IsSystemDisk || candidate.IsOffline)
        {
            throw new ArgumentException("卡片被报告为只读、系统盘或离线，不能作为写入目标。", nameof(candidate));
        }

        if (candidate.Mounted == true)
        {
            throw new ArgumentException("卡片仍处于挂载状态，不能作为写入目标。", nameof(candidate));
        }

        if (IsAdoptedUsage(candidate.AndroidUsage))
        {
            throw new ArgumentException("卡片已被 Android 采纳为内部存储，不能作为写入目标。", nameof(candidate));
        }
    }

    private static bool IsAdoptedUsage(string? androidUsage)
    {
        var usage = androidUsage?.Trim();
        return string.Equals(usage, "adopted", StringComparison.OrdinalIgnoreCase)
            || string.Equals(usage, "adoptable", StringComparison.OrdinalIgnoreCase);
    }

    private sealed record RamInspectReport(
        string Model,
        ulong SocSerial,
        Guid BootId,
        string KernelSha256,
        string RawJson);

    private sealed record OpenCardRequest(string Key, string Path, long SizeBytes, int LogicalSectorSize);

    private static readonly JsonSerializerOptions OpenCardJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };
}

/// <summary>
/// One opened RAM-service card bound to its frozen real identity. Every block IO revalidates the
/// identity first; any drift, server error, bad acknowledgement or failed transfer poisons the target
/// so later writes cannot resume under a stale session. Dispose still attempts only its own close and
/// is idempotent locally — a failed close releases the session slot and preserves the exception.
/// </summary>
public sealed class TfRamCardWriteTarget : ITfCardWriteTarget
{
    /// <summary>Hard upper bound for one write or read transfer.</summary>
    private const long MaxTransferBytes = 1024 * 1024;

    private TfRamMaintenanceSession? _session;

    private readonly TfCardTargetIdentity _identity;

    private readonly string _cardSessionId;

    private bool _poisoned;

    private bool _disposed;

    internal TfRamCardWriteTarget(TfRamMaintenanceSession session, TfCardTargetIdentity identity, string cardSessionId)
    {
        _session = session;
        _identity = identity;
        _cardSessionId = cardSessionId;
    }

    /// <summary>The frozen identity captured when the card was opened; the wire path is the common
    /// DevicePath.</summary>
    public TfCardTargetIdentity Identity => _identity;

    /// <summary>Re-reads the live identity from GET /v1/card/&lt;id&gt;/identity and requires every
    /// frozen field to come back exactly equal. A drift poisons the target.</summary>
    public async ValueTask<TfCardTargetIdentity> RevalidateAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfUnusable();
        try
        {
            return await RevalidateCoreAsync(cancellationToken);
        }
        catch
        {
            _poisoned = true;
            throw;
        }
    }

    /// <summary>Reads exactly buffer.Length bytes at the byte offset. The response must carry the
    /// exact Content-Length and a matching X-Content-SHA256; short or extra bodies are rejected and
    /// the buffer is never zero-filled.</summary>
    public async ValueTask ReadExactlyAsync(long offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfUnusable();
        ValidateRange(offset, buffer.Length);
        try
        {
            await RevalidateCoreAsync(cancellationToken);
            var expectedLength = buffer.Length;
            // One 30s deadline stays alive through send, error body, the whole read stream, the
            // one-byte extra probe and digest validation; headers alone never own the timeout.
            using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            operation.CancelAfter(TfRamWire.OperationTimeout);
            try
            {
                await ReadExactlyCoreAsync(offset, buffer, expectedLength, operation.Token);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException("RAM 卡服务请求超时，本次操作已放弃。");
            }
        }
        catch
        {
            _poisoned = true;
            throw;
        }
    }

    private async Task ReadExactlyCoreAsync(long offset, Memory<byte> buffer, int expectedLength, CancellationToken operationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, TfRamWire.Uri(
            "/v1/card/" + _cardSessionId + "/read?offset=" + offset.ToString(CultureInfo.InvariantCulture)
            + "&bytes=" + expectedLength.ToString(CultureInfo.InvariantCulture)));
        using var response = await TfRamWire.SendAsync(
            _session!.Client, _session.BearerToken, request, operationToken);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw await TfRamWire.CreateServerErrorAsync(response, operationToken);
        }

        var contentLength = response.Content.Headers.ContentLength;
        if (!contentLength.HasValue || contentLength.Value != expectedLength)
        {
            throw TfRamWire.Protocol("read-length", $"read 响应 Content-Length 与请求的 {expectedLength} 字节不一致。");
        }

        if (!response.Headers.TryGetValues("X-Content-SHA256", out var digestValues))
        {
            throw TfRamWire.Protocol("read-digest", "read 响应缺少 X-Content-SHA256 头。");
        }

        var declaredDigest = digestValues.FirstOrDefault();
        var stream = await response.Content.ReadAsStreamAsync(operationToken);
        var received = new byte[expectedLength];
        var filled = 0;
        int read;
        while (filled < expectedLength
            && (read = await stream.ReadAsync(received.AsMemory(filled, expectedLength - filled), operationToken)) > 0)
        {
            filled += read;
        }

        if (filled < expectedLength)
        {
            throw TfRamWire.Protocol("read-short", "read 响应体短于请求长度，拒绝零填充。");
        }

        var extra = new byte[1];
        if (await stream.ReadAsync(extra, operationToken) > 0)
        {
            throw TfRamWire.Protocol("read-extra", "read 响应体超出请求长度。");
        }

        var actualDigest = ComputeSha256(received);
        if (string.IsNullOrEmpty(declaredDigest)
            || !string.Equals(declaredDigest, actualDigest, StringComparison.OrdinalIgnoreCase))
        {
            throw TfRamWire.Protocol("read-digest", "read 响应 X-Content-SHA256 与实际数据不一致。");
        }

        received.AsMemory().CopyTo(buffer);
    }

    /// <summary>Writes the buffer at the byte offset after revalidation. The request carries an exact
    /// Content-Length and the actual chunk X-Content-SHA256; the acknowledgement must repeat the exact
    /// count and hash or the write is not treated as completed. An uncertain write is never retried
    /// and never silently padded.</summary>
    public async ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfUnusable();
        ValidateRange(offset, buffer.Length);
        try
        {
            await RevalidateCoreAsync(cancellationToken);
            var bytes = buffer.ToArray();
            var digest = ComputeSha256(bytes);
            using var request = new HttpRequestMessage(HttpMethod.Post, TfRamWire.Uri(
                "/v1/card/" + _cardSessionId + "/write?offset=" + offset.ToString(CultureInfo.InvariantCulture)));
            var content = new ByteArrayContent(bytes);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            request.Content = content;
            request.Headers.TryAddWithoutValidation("X-Content-SHA256", digest);
            using var json = await TfRamWire.SendJsonAsync(
                _session!.Client, _session.BearerToken, request, TfRamWire.MaxEnvelopeBytes, TfRamWire.OperationTimeout, cancellationToken);
            var root = json.RootElement;
            var writtenBytes = TfRamWire.RequireInt64(root, "writtenBytes");
            if (writtenBytes != bytes.Length)
            {
                throw TfRamWire.Protocol("write-ack", "writtenBytes 与实际写入数量不一致，拒绝确认本次写入。");
            }

            var ackDigest = TfRamWire.RequireString(root, "sha256");
            if (!string.Equals(ackDigest, digest, StringComparison.OrdinalIgnoreCase))
            {
                throw TfRamWire.Protocol("write-ack", "sha256 与本次分块实际哈希不一致，拒绝确认本次写入。");
            }
        }
        catch
        {
            _poisoned = true;
            throw;
        }
    }

    /// <summary>Flushes previously written bytes. Anything but HTTP 200 with
    /// {schemaVersion:1,flushed:true} is rejected.</summary>
    public async ValueTask FlushAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfUnusable();
        try
        {
            await RevalidateCoreAsync(cancellationToken);
            using var request = new HttpRequestMessage(HttpMethod.Post, TfRamWire.Uri("/v1/card/" + _cardSessionId + "/flush"));
            request.Content = new ByteArrayContent(Array.Empty<byte>());
            using var json = await TfRamWire.SendJsonAsync(
                _session!.Client, _session.BearerToken, request, TfRamWire.MaxEnvelopeBytes, TfRamWire.OperationTimeout, cancellationToken);
            if (!json.RootElement.TryGetProperty("flushed", out var flushed) || flushed.ValueKind != JsonValueKind.True)
            {
                throw TfRamWire.Protocol("flush-ack", "flush 未被服务确认为成功。");
            }
        }
        catch
        {
            _poisoned = true;
            throw;
        }
    }

    /// <summary>Idempotent local disposal that attempts the remote close exactly once with a short
    /// finite timeout. On a failed close the exception is preserved while the local object is still
    /// marked disposed and the session slot is freed. No reset, reboot, EDL or format call is made.</summary>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        var session = _session;
        _session = null;
        try
        {
            await session!.CloseOwnedCardAsync(_cardSessionId);
        }
        finally
        {
            session?.ReleaseCard(this);
        }
    }

    private async Task<TfCardTargetIdentity> RevalidateCoreAsync(CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, TfRamWire.Uri("/v1/card/" + _cardSessionId + "/identity"));
        using var json = await TfRamWire.SendJsonAsync(
            _session!.Client, _session.BearerToken, request, TfRamWire.MaxEnvelopeBytes, TfRamWire.OperationTimeout, cancellationToken);
        if (!json.RootElement.TryGetProperty("identity", out var identityElement))
        {
            throw TfRamWire.Protocol("identity", "identity 响应缺少 identity 字段。");
        }

        var actual = TfRamWire.ParseIdentity(identityElement, "identity");
        if (actual != _identity)
        {
            throw TfRamWire.Protocol("identity-drift", "卡片身份与打开时的冻结身份不一致，本次操作已中止。");
        }

        return actual;
    }

    private void ThrowIfUnusable()
    {
        if (_disposed)
        {
            throw new InvalidOperationException("卡片目标已释放，不能继续使用。");
        }

        if (_poisoned)
        {
            throw new InvalidOperationException("卡片目标已因写入失败或身份漂移被污染，必须重新打开卡片。");
        }
    }

    /// <summary>Range-checks offset and count before anything is sent: positive, sector-aligned,
    /// within the frozen size and at most 1 MiB per transfer.</summary>
    private void ValidateRange(long offset, int count)
    {
        var sector = _identity.LogicalSectorSize;
        if (offset < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(offset), offset, "偏移不能为负数。");
        }

        if (count <= 0)
        {
            throw new ArgumentException("传输数量必须为正数。", nameof(count));
        }

        if (offset % sector != 0)
        {
            throw new ArgumentException($"偏移 {offset} 未按 {sector} 字节扇区对齐。", nameof(offset));
        }

        if (count % sector != 0)
        {
            throw new ArgumentException($"数量 {count} 未按 {sector} 字节扇区对齐。", nameof(count));
        }

        if (count > MaxTransferBytes)
        {
            throw new ArgumentException($"单次传输 {count} 字节超过 1 MiB 上限。", nameof(count));
        }

        if (offset > _identity.SizeBytes || count > _identity.SizeBytes - offset)
        {
            throw new ArgumentOutOfRangeException(nameof(offset), offset, "传输范围超出卡片容量。");
        }
    }

    private static string ComputeSha256(byte[] data) =>
        Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
}
