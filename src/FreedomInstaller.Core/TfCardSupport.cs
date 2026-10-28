using System.Text.Json;

namespace FreedomInstaller.Core;

/// <summary>
/// Where an installation is allowed to land. <see cref="Internal"/> means the tablet's own internal
/// storage, <see cref="TfCard"/> means a removeable microSD / TF card that is separate from the device.
/// </summary>
public enum InstallationTarget
{
    Internal = 0,
    TfCard = 1,
}

/// <summary>
/// How the TF card inventory was obtained. <see cref="Tablet"/> is a read-only query executed on the
/// handheld itself, <see cref="Reader"/> is a read-only query executed on the host through the card
/// reader. The two sources must never be mixed in one candidate list.
/// </summary>
public enum TfCardSource
{
    Tablet = 0,
    Reader = 1,
}

/// <summary>
/// One candidate card as reported by a discovery source. <see cref="Key"/> is prefixed with
/// <c>tablet:</c> or <c>reader:</c> so a candidate can only ever be planned against the source that
/// produced it; the rest of the key is the raw hardware identifier from the wire report.
/// <see cref="MediumEvidence"/> keeps the wire evidence string that justified the classification.
/// </summary>
public sealed record TfCardCandidate(
    string Key,
    string Path,
    string DisplayName,
    long SizeBytes,
    int LogicalSectorSize,
    string MediumEvidence,
    bool ReadOnly,
    bool IsSystemDisk,
    bool IsOffline,
    bool? Mounted,
    string AndroidUsage);

/// <summary>
/// Capacity-only space plan for one TF card. It deliberately carries no partition table, no userdata
/// extent and no Android allocation: the card belongs to Linux, and the numbers here are bytes on the
/// whole device, not sectors of a shared layout.
/// </summary>
public sealed record TfSpacePlan(
    string TargetKey,
    long TotalBytes,
    long LinuxBootBytes,
    long LinuxRootBytes,
    long EstimatedLinuxDataBytes,
    long ReservedBytes);

/// <summary>
/// Pure TF card logic: parse a discovery report and derive a capacity plan. No I/O, no device access.
/// </summary>
public static class TfCardSupport
{
    private const int SupportedSchemaVersion = 1;

    private const string TabletSourceName = "tablet";

    private const string ReaderSourceName = "reader";

    private const long MiB = 1024L * 1024;

    /// <summary>Bytes held back at the start of the card for alignment and partition table slack.</summary>
    private const long ReservedBytes = 2 * MiB;

    /// <summary>Smallest root filesystem the plan will accept, independent of what the package declares.</summary>
    private const long MinimumRootBytes = 32L * 1024 * MiB;

    private const int MinLogicalSectorSize = 512;

    private const int MaxLogicalSectorSize = 4096;

    private const string UnknownUsage = "unknown";

    /// <summary>
    /// Parses a discovery report produced by <see cref="TfCardDiscovery.BuildTabletCommand"/> or
    /// <see cref="TfCardDiscovery.BuildReaderCommand"/>. Returns only candidates that are safe to use:
    /// identity and sector size must be valid and the card must not be a known system disk, read-only,
    /// offline or adopted as Android adoptable storage.
    /// <para>
    /// A card used as Android <em>portable</em> storage is <b>not</b> adopted: it stays a normal card with
    /// a normal partition table, so it is kept as a candidate. Only <c>adopted</c> / <c>adoptable</c>
    /// reports are dropped, and its reported <see cref="TfCardCandidate.AndroidUsage"/> is carried over
    /// unchanged instead of being replaced by a guess.
    /// </para>
    /// <para>
    /// A malformed report (bad JSON, wrong root shape, wrong schema version, a source that does not match
    /// <paramref name="source"/>, duplicate or missing identity, an impossible sector size or a
    /// non-positive / non-sector-aligned capacity) throws <see cref="ArgumentException"/>: the report is
    /// rejected instead of being silently repaired. Card flags are never invented — an absent
    /// <c>mounted</c> value stays <c>null</c> ("unknown"), never <c>false</c>.
    /// </para>
    /// </summary>
    public static IReadOnlyList<TfCardCandidate> ParseCandidates(string json, TfCardSource source)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            throw new ArgumentException("卡片发现报告为空。", nameof(json));
        }

        if (source != TfCardSource.Tablet && source != TfCardSource.Reader)
        {
            throw new ArgumentException($"未知的卡片来源：{source}。", nameof(source));
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException exception)
        {
            throw new ArgumentException($"卡片发现报告不是合法 JSON：{exception.Message}", nameof(json), exception);
        }

        using (document)
        {
            var root = document.RootElement;

            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new ArgumentException("卡片发现报告的根节点不是 JSON 对象。", nameof(json));
            }

            if (!root.TryGetProperty("schemaVersion", out var schemaElement)
                || schemaElement.ValueKind != JsonValueKind.Number
                || !schemaElement.TryGetInt32(out var schemaVersion))
            {
                throw new ArgumentException("卡片发现报告缺少可解析的 schemaVersion。", nameof(json));
            }

            if (schemaVersion != SupportedSchemaVersion)
            {
                throw new ArgumentException(
                    $"不支持的卡片发现报告 schemaVersion：{schemaVersion}，当前只接受 {SupportedSchemaVersion}。",
                    nameof(json));
            }

            var expectedSourceName = source == TfCardSource.Tablet ? TabletSourceName : ReaderSourceName;
            if (!root.TryGetProperty("source", out var sourceElement)
                || sourceElement.ValueKind != JsonValueKind.String
                || string.IsNullOrWhiteSpace(sourceElement.GetString()))
            {
                throw new ArgumentException("卡片发现报告缺少 source 字段。", nameof(json));
            }

            var declaredSource = sourceElement.GetString()!.Trim();
            if (!string.Equals(declaredSource, expectedSourceName, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException(
                    $"卡片发现报告的来源 {declaredSource} 与请求的来源 {expectedSourceName} 不一致，拒绝混合两种来源的卡片列表。",
                    nameof(json));
            }

            if (!root.TryGetProperty("media", out var mediaElement)
                || mediaElement.ValueKind != JsonValueKind.Array)
            {
                throw new ArgumentException("卡片发现报告缺少 media 数组。", nameof(json));
            }

            var candidates = new List<TfCardCandidate>();
            var seenKeys = new HashSet<string>(StringComparer.Ordinal);
            var index = 0;

            foreach (var element in mediaElement.EnumerateArray())
            {
                var label = $"media[{index}]";
                index++;

                if (element.ValueKind != JsonValueKind.Object)
                {
                    throw new ArgumentException($"{label} 不是 JSON 对象。", nameof(json));
                }

                var key = ReadRequiredString(element, label, "key");
                var path = ReadRequiredString(element, label, "path");
                var displayName = ReadRequiredString(element, label, "displayName");
                var mediumEvidence = ReadRequiredString(element, label, "mediumEvidence");
                var sizeBytes = ReadRequiredInt64(element, label, "sizeBytes");
                var logicalSectorSize = ReadRequiredInt32(element, label, "logicalSectorSize");
                var readOnly = ReadRequiredBoolean(element, label, "readOnly");
                var isSystemDisk = ReadRequiredBoolean(element, label, "isSystemDisk");
                var isOffline = ReadRequiredBoolean(element, label, "isOffline");
                var mounted = ReadOptionalBoolean(element, label, "mounted");
                var androidUsage = ReadOptionalString(element, "androidUsage") ?? UnknownUsage;

                if (logicalSectorSize != MinLogicalSectorSize && logicalSectorSize != MaxLogicalSectorSize)
                {
                    throw new ArgumentException(
                        $"{label} 的 logicalSectorSize {logicalSectorSize} 不是 512 或 4096。",
                        nameof(json));
                }

                if (sizeBytes <= 0)
                {
                    throw new ArgumentException($"{label} 的 sizeBytes {sizeBytes} 不是正数。", nameof(json));
                }

                if (sizeBytes % logicalSectorSize != 0)
                {
                    throw new ArgumentException(
                        $"{label} 的 sizeBytes {sizeBytes} 没有按 {logicalSectorSize} 字节扇区对齐。",
                        nameof(json));
                }

                var candidateKey = (source == TfCardSource.Tablet ? TabletSourceName : ReaderSourceName) + ":" + key;

                if (!seenKeys.Add(candidateKey))
                {
                    throw new ArgumentException($"卡片标识 {candidateKey} 在报告中被重复声明。", nameof(json));
                }

                // Only medium evidence the source can actually observe is accepted: the tablet only sees
                // SD / MMC backed cards, while the host reader also sees USB connected readers and
                // removable disks. A USB report from the tablet is therefore dropped, not trusted.
                if (!IsMediumAcceptable(mediumEvidence, source))
                {
                    continue;
                }

                if (readOnly || isSystemDisk || isOffline)
                {
                    continue;
                }

                if (IsAdoptedUsage(androidUsage))
                {
                    continue;
                }

                candidates.Add(new TfCardCandidate(
                    candidateKey,
                    path,
                    displayName,
                    sizeBytes,
                    logicalSectorSize,
                    mediumEvidence,
                    readOnly,
                    isSystemDisk,
                    isOffline,
                    mounted,
                    androidUsage));
            }

            return candidates;
        }
    }

    /// <summary>
    /// Derives the TF capacity plan for <paramref name="card"/> from the storage declaration of
    /// <paramref name="storage"/>. The input card is not modified.
    /// <para>
    /// The plan is pure capacity arithmetic over the whole card, not a partition geometry and not a
    /// protocol: the total is the card size floored to whole MiB, 2 MiB are reserved, the declared Linux
    /// boot size is rounded up to whole MiB, and the root filesystem gets the remainder. The root must
    /// reach <c>max(32 GiB, system + scratch + minimum data)</c>; otherwise the card is rejected instead
    /// of being given an invented capacity. <see cref="PartitionPlanner"/> is never called here.
    /// </para>
    /// <para>
    /// Unsafe cards (read-only, system disk, offline, adopted Android storage), non-positive card or
    /// storage numbers and arithmetic that leaves the 64-bit range throw
    /// <see cref="ArgumentException"/>, and a card that cannot carry the root floor throws
    /// <see cref="InvalidOperationException"/>.
    /// </para>
    /// </summary>
    public static TfSpacePlan Plan(TfCardCandidate card, PackageStorage storage)
    {
        ArgumentNullException.ThrowIfNull(card);
        ArgumentNullException.ThrowIfNull(storage);

        if (card.ReadOnly)
        {
            throw new InvalidOperationException($"卡片 {card.Key} 被报告为只读，不能作为安装目标。");
        }

        if (card.IsSystemDisk)
        {
            throw new InvalidOperationException($"卡片 {card.Key} 被报告为系统盘，不能作为安装目标。");
        }

        if (card.IsOffline)
        {
            throw new InvalidOperationException($"卡片 {card.Key} 被报告为离线，无法确认其容量。");
        }

        if (IsAdoptedUsage(card.AndroidUsage))
        {
            throw new InvalidOperationException(
                $"卡片 {card.Key} 已被 Android 采纳为内部存储（androidUsage={card.AndroidUsage}），不能作为安装目标。");
        }

        if (card.SizeBytes <= 0)
        {
            throw new ArgumentException($"卡片 {card.Key} 的容量 {card.SizeBytes} 不是正数。", nameof(card));
        }

        if (storage.LinuxBootBytes <= 0)
        {
            throw new ArgumentException("storage.linuxBootBytes 必须为正数。", nameof(storage));
        }

        if (storage.SystemRequiredBytes <= 0)
        {
            throw new ArgumentException("storage.systemRequiredBytes 必须为正数。", nameof(storage));
        }

        if (storage.DeploymentScratchBytes < 0)
        {
            throw new ArgumentException("storage.deploymentScratchBytes 不能为负数。", nameof(storage));
        }

        if (storage.MinimumLinuxDataBytes <= 0)
        {
            throw new ArgumentException("storage.minimumLinuxDataBytes 必须为正数。", nameof(storage));
        }

        long totalBytes;
        long linuxBootBytes;
        long requiredRootBytes;
        long linuxRootBytes;

        try
        {
            totalBytes = card.SizeBytes / MiB * MiB;
            linuxBootBytes = checked((storage.LinuxBootBytes + MiB - 1) / MiB * MiB);
            requiredRootBytes = Math.Max(
                MinimumRootBytes,
                checked(storage.SystemRequiredBytes + storage.DeploymentScratchBytes + storage.MinimumLinuxDataBytes));
            linuxRootBytes = checked(totalBytes - linuxBootBytes - ReservedBytes);
        }
        catch (OverflowException exception)
        {
            throw new ArgumentException(
                $"卡片的容量计划溢出 64 位范围，拒绝该声明：{exception.Message}",
                nameof(storage),
                exception);
        }

        if (linuxRootBytes < requiredRootBytes)
        {
            throw new InvalidOperationException(
                $"TF 卡 {card.Key} 的容量 {totalBytes} 字节不足以承载 {linuxBootBytes} 字节引导分区、{ReservedBytes} 字节预留和至少 {requiredRootBytes} 字节根分区。");
        }

        var estimatedDataBytes = linuxRootBytes - storage.SystemRequiredBytes;

        return new TfSpacePlan(
            card.Key,
            totalBytes,
            linuxBootBytes,
            linuxRootBytes,
            estimatedDataBytes,
            ReservedBytes);
    }

    private static string ReadRequiredString(JsonElement element, string label, string name)
    {
        if (!element.TryGetProperty(name, out var property)
            || property.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(property.GetString()))
        {
            throw new ArgumentException($"{label} 缺少非空的 {name}。");
        }

        return property.GetString()!.Trim();
    }

    private static string? ReadOptionalString(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        var value = property.GetString()?.Trim();
        return string.IsNullOrEmpty(value) ? null : value;
    }

    private static long ReadRequiredInt64(JsonElement element, string label, string name)
    {
        if (!element.TryGetProperty(name, out var property)
            || property.ValueKind != JsonValueKind.Number
            || !property.TryGetInt64(out var value))
        {
            throw new ArgumentException($"{label} 缺少整数 {name}。");
        }

        return value;
    }

    private static int ReadRequiredInt32(JsonElement element, string label, string name)
    {
        if (!element.TryGetProperty(name, out var property)
            || property.ValueKind != JsonValueKind.Number
            || !property.TryGetInt32(out var value))
        {
            throw new ArgumentException($"{label} 缺少整数 {name}。");
        }

        return value;
    }

    private static bool ReadRequiredBoolean(JsonElement element, string label, string name)
    {
        if (!element.TryGetProperty(name, out var property)
            || (property.ValueKind != JsonValueKind.True && property.ValueKind != JsonValueKind.False))
        {
            throw new ArgumentException($"{label} 缺少布尔字段 {name}。");
        }

        return property.GetBoolean();
    }

    /// <summary>
    /// Reads a tri-state flag. Absent, <c>null</c> or any non-boolean value stays <c>null</c>: an unknown
    /// mount state must never be reported as an unmounted card.
    /// </summary>
    private static bool? ReadOptionalBoolean(JsonElement element, string label, string name)
    {
        if (!element.TryGetProperty(name, out var property))
        {
            return null;
        }

        return property.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => null,
            _ => throw new ArgumentException($"{label} 的 {name} 必须是布尔值或 null。"),
        };
    }

    /// <summary>
    /// Only evidence the reporting source can observe is accepted, matched as a case-insensitive prefix.
    /// </summary>
    private static bool IsMediumAcceptable(string mediumEvidence, TfCardSource source)
    {
        var evidence = mediumEvidence.Trim();

        if (StartsWithIgnoreCase(evidence, "SD") || StartsWithIgnoreCase(evidence, "MMC"))
        {
            return true;
        }

        // Windows reports USB card readers and USB removable disks as BusType USB, so the host reader
        // accepts them; the tablet query has no such bus and must not treat USB output as a TF card.
        return source == TfCardSource.Reader && StartsWithIgnoreCase(evidence, "USB");
    }

    private static bool StartsWithIgnoreCase(string value, string prefix) =>
        value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// <c>adopted</c> / <c>adoptable</c> means Android reformatted the card as internal storage.
    /// <c>portable</c> does not: a portable card keeps its own partition table and stays usable.
    /// </summary>
    private static bool IsAdoptedUsage(string? androidUsage)
    {
        var usage = androidUsage?.Trim();
        if (string.IsNullOrEmpty(usage))
        {
            return false;
        }

        return string.Equals(usage, "adopted", StringComparison.OrdinalIgnoreCase)
            || string.Equals(usage, "adoptable", StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// Read-only discovery commands. Both are fixed argument vectors with a finite timeout and neither can
/// format, clear, initialize, set or write anything.
/// </summary>
public static class TfCardDiscovery
{
    /// <summary>The only executable used for the host query: Windows PowerShell, resolved by name.</summary>
    private const string ReaderExecutable = "powershell.exe";

    /// <summary>
    /// Fixed, read-only inventory script: one <c>Get-Disk</c> pipeline that reads properties and prints a
    /// discovery report. It contains no format / clear / initialize / set / partition / write verb, and a
    /// failing <c>Get-Disk</c> terminates the process with a non-zero exit code because every error is
    /// terminating.
    /// </summary>
    private const string ReaderScript =
        "$ErrorActionPreference = 'Stop'; "
        + "$media = @(Get-Disk | ForEach-Object { "
        + "$disk = $_; "
        + "if (-not ($disk.BusType -in @('SD','MMC','USB'))) { return }; "
        + "if ($disk.IsSystem -or $disk.IsBoot -or $disk.IsReadOnly -or $disk.IsOffline) { return }; "
        + "$key = [string]$disk.UniqueId; "
        + "if ([string]::IsNullOrWhiteSpace($key)) { $key = [string]$disk.SerialNumber + [string]$disk.Path }; "
        + "if ([string]::IsNullOrWhiteSpace($key)) { return }; "
        + "[pscustomobject]@{ "
        + "key = $key; "
        + "path = [string]$disk.Path; "
        + "displayName = [string]$disk.FriendlyName; "
        + "sizeBytes = [long]$disk.Size; "
        + "logicalSectorSize = [int]$disk.LogicalSectorSize; "
        + "mediumEvidence = [string]$disk.BusType; "
        + "readOnly = [bool]$disk.IsReadOnly; "
        + "isSystemDisk = [bool]$disk.IsSystem; "
        + "isOffline = [bool]$disk.IsOffline; "
        + "mounted = $null; "
        + "androidUsage = 'unknown' "
        + "} }); "
        + "[pscustomobject]@{ schemaVersion = 1; source = 'reader'; media = @($media) } "
        + "| ConvertTo-Json -Depth 4 -Compress";

    private const string TabletInspectorPath = "/usr/libexec/armada/armada-inspect-tf";

    /// <summary>Finite timeout shared by both discovery queries.</summary>
    private static readonly TimeSpan DiscoveryTimeout = TimeSpan.FromSeconds(20);

    /// <summary>Read-only card enumeration through the host card reader.</summary>
    public static ProcessCommand BuildReaderCommand()
        => new(
            ReaderExecutable,
            new[] { "-NoProfile", "-NonInteractive", "-Command", ReaderScript },
            DiscoveryTimeout);

    /// <summary>
    /// Read-only card enumeration executed on the tablet over adb for one serial. The argument vector is
    /// fixed and already separated, and the serial is bound to exactly one device: a blank serial, the
    /// broadcast name <c>all</c> and anything that could arrive as an option, a second command or injected
    /// whitespace are rejected before a command exists.
    /// </summary>
    public static ProcessCommand BuildTabletCommand(string adbPath, string serial)
    {
        if (string.IsNullOrWhiteSpace(adbPath))
        {
            throw new ArgumentException("adb 可执行文件路径为空，无法执行卡片发现。", nameof(adbPath));
        }

        var boundSerial = RequireSingleSerial(serial);

        return new ProcessCommand(
            adbPath.Trim(),
            new[] { "-s", boundSerial, "exec-out", TabletInspectorPath, "--json" },
            DiscoveryTimeout);
    }

    /// <summary>
    /// The same serial binding rules the device transport applies: one concrete serial only. A value with
    /// surrounding whitespace, an embedded space, a control character, a leading option marker or the
    /// broadcast name <c>all</c> would let adb pick or fan out to more than the device the user confirmed.
    /// </summary>
    private static string RequireSingleSerial(string serial)
    {
        if (string.IsNullOrWhiteSpace(serial))
        {
            throw new ArgumentException("设备序列号为空，无法定向查询 TF 卡。", nameof(serial));
        }

        var value = serial.Trim();

        if (string.Equals(value, "all", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("设备序列号不能是广播名 all，必须指向一台具体设备。", nameof(serial));
        }

        if (value[0] == '-')
        {
            throw new ArgumentException($"设备序列号不能以选项前缀开头：{serial}。", nameof(serial));
        }

        foreach (var character in value)
        {
            if (char.IsWhiteSpace(character) || char.IsControl(character))
            {
                throw new ArgumentException($"设备序列号不能包含空白或控制字符：{serial}。", nameof(serial));
            }
        }

        if (value.Contains('"') || value.Contains('\''))
        {
            throw new ArgumentException($"设备序列号不能包含引号：{serial}。", nameof(serial));
        }

        return value;
    }
}
