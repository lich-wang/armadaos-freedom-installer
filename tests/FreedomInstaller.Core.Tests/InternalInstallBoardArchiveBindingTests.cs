using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Gate tests for the board archive binding of the internal preparation context. The inner recovery manifest
/// must carry exactly one entry for every trusted captured file plus the PC backup manifest, both re-built GPT
/// copies and the installation record, and the summary manifest's compressed metadata must be the actual fixed
/// 64 KiB outer header of the held 2 GiB image.
/// <para>
/// The two guards are private static methods of the internal context and no <c>InternalsVisibleTo</c> exists,
/// so this file carries one narrow reflection bridge over those two methods and nothing else. No uninitialized
/// prepared bag, fake device, Sahara session, real backup file or whole image buffer is built here: the
/// fixtures are synthetic JSON descriptors shaped like the frozen v2 schema and small synthetic entry tables.
/// </para>
/// </summary>
public sealed class InternalInstallBoardArchiveBindingTests
{
    private const long ImageBytes = 2147483648L;
    private const long HeaderBytes = 65536L;
    private const long CompressedBytes = 1048576L;
    private const long TarBytes = 2097152L;

    private static readonly string[] ExtraRoles =
    {
        "pc-backup-manifest",
        "post-gpt-primary",
        "post-gpt-backup",
        "installation-record",
    };

    private static readonly Guid InstallationId = Guid.Parse("6f1d2c3b-4a59-4f80-9c71-2d3e4f5a6b7c");

    private static readonly string[] OwnedUuids =
    {
        "0b1c2d3e-4f50-4617-8899-aabbccddeeff",
        "1c2d3e4f-5061-4728-99aa-bbccddeeff00",
        "2d3e4f50-6172-4839-aabb-ccddeeff0011",
    };

    private static readonly string PlanSha = Hash("plan");
    private static readonly string BackupManifestSha = Hash("backup-manifest");
    private static readonly string OriginalFingerprint = Hash("original-gpt");
    private static readonly string PostFingerprint = Hash("post-gpt");
    private static readonly string CompressedSha = Hash("compressed");
    private static readonly string RecoveryManifestSha = Hash("recovery-manifest");
    private static readonly string BoardImageSha = Hash("board-image");

    // ------------------------------------------------------------------ the real guards

    [Fact]
    public void The_two_narrow_guards_are_the_real_private_static_helpers()
    {
        Assert.Equal(8, Guard("RequireRecoveryBindings").GetParameters().Length);
        Assert.Equal(3, Guard("RequireBoardArchiveSummary").GetParameters().Length);

        // The positive fixtures would pass vacuously if the guards went missing, so a deliberately broken
        // manifest must be refused by the same bridge before any positive claim is trusted.
        Assert.Throws<InvalidDataException>(
            () => RequireBindings(RecoveryJson(Removed("boot_b"))));
        Assert.Throws<InvalidDataException>(
            () => RequireSummary(SummaryJson(format: "ustar"), OuterJson(), HeaderBytes + CompressedBytes));
    }

    // ------------------------------------------------------------------ recovery manifest

    [Fact]
    public void Recovery_bindings_accept_the_trusted_capture_manifest_gpt_and_record_set()
    {
        List<Entry> entries = Baseline();

        Assert.Equal(56, entries.Count);
        Assert.Equal(52, entries.Count(entry => !IsExtra(entry.Role)));

        foreach (string role in new[] { "vendor_boot_a", "vendor_boot_b", "recovery_a", "recovery_b", "boot_a", "boot_b" })
        {
            Assert.True(entries.Any(entry => entry.Role == role && entry.Path == role + ".bin"));
        }

        // Slot A and slot B carry different bytes in the fixture, so the tests below would notice any copy.
        Entry bootA = entries.Single(entry => entry.Role == "boot_a");
        Entry bootB = entries.Single(entry => entry.Role == "boot_b");
        Assert.NotEqual(bootA.Sha256, bootB.Sha256);
        Assert.NotEqual(bootA.Length, bootB.Length);

        RequireBindings(RecoveryJson(entries));
    }

    [Theory]
    [InlineData("vendor_boot_a")]
    [InlineData("vendor_boot_b")]
    [InlineData("recovery_a")]
    [InlineData("recovery_b")]
    [InlineData("boot_b")]
    public void Recovery_bindings_refuse_a_manifest_that_omits_a_trusted_role(string role)
    {
        Assert.Throws<InvalidDataException>(
            () => RequireBindings(RecoveryJson(Removed(role))));
    }

    [Fact]
    public void Recovery_bindings_refuse_slot_b_entries_that_reuse_slot_a_bytes()
    {
        Entry bootA = Baseline().Single(entry => entry.Role == "boot_a");

        // Slot B keeps its own path and length so only the content hash can reject the copied bytes.
        List<Entry> entries = Replace("boot_b", entry => entry with { Sha256 = bootA.Sha256 });

        Assert.Throws<InvalidDataException>(() => RequireBindings(RecoveryJson(entries)));
    }

    [Theory]
    [InlineData("pc-backup-manifest")]
    [InlineData("installation-record")]
    [InlineData("post-gpt-primary")]
    [InlineData("post-gpt-backup")]
    public void Recovery_bindings_refuse_changed_trusted_file_metadata(string role)
    {
        List<Entry> entries = Replace(
            role,
            entry => entry with { Sha256 = Hash("other-" + role) });

        Assert.Throws<InvalidDataException>(() => RequireBindings(RecoveryJson(entries)));
    }

    [Theory]
    [InlineData("duplicate")]
    [InlineData("unexpected")]
    [InlineData("path")]
    [InlineData("length")]
    public void Recovery_bindings_refuse_inconsistent_entry_tables(string mutation)
    {
        List<Entry> entries = mutation switch
        {
            "duplicate" => Replace("metadata", _ => Baseline().Single(entry => entry.Role == "boot_a")),
            "unexpected" => Replace(
                "metadata",
                _ => new Entry("super", "super.bin", 1048576L, Hash("super"))),
            "path" => Replace("boot_a", entry => entry with { Path = "boot_a-renamed.bin" }),
            "length" => Replace("boot_a", entry => entry with { Length = entry.Length + 512L }),
            _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
        };

        Assert.Equal(56, entries.Count);
        Assert.Throws<InvalidDataException>(() => RequireBindings(RecoveryJson(entries)));
    }

    [Theory]
    [InlineData("installation")]
    [InlineData("plan")]
    [InlineData("backup-manifest")]
    [InlineData("original-fingerprint")]
    [InlineData("post-fingerprint")]
    [InlineData("owned-uuid")]
    public void Recovery_bindings_refuse_a_manifest_bound_to_different_prepared_facts(string binding)
    {
        string manifest = RecoveryJson(Baseline());
        Action call;

        switch (binding)
        {
            case "installation":
                call = () => RequireBindings(manifest, installationId: Guid.NewGuid());
                break;
            case "plan":
                call = () => RequireBindings(manifest, planSha: Hash("other-plan"));
                break;
            case "backup-manifest":
                call = () => RequireBindings(manifest, backupSha: Hash("other-backup"));
                break;
            case "original-fingerprint":
                call = () => RequireBindings(manifest, originalFp: Hash("other-original"));
                break;
            case "post-fingerprint":
                call = () => RequireBindings(manifest, postFp: Hash("other-post"));
                break;
            case "owned-uuid":
                call = () => RequireBindings(
                    manifest,
                    ownedUuids: new[] { OwnedUuids[0], OwnedUuids[1], Guid.NewGuid().ToString("D") });
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(binding));
        }

        Assert.Throws<InvalidDataException>(call);
    }

    [Theory]
    [InlineData("schema")]
    [InlineData("kind")]
    [InlineData("offset-space")]
    [InlineData("excluded-roles")]
    public void Recovery_bindings_require_the_frozen_v2_manifest_shape(string mutation)
    {
        string manifest = mutation switch
        {
            "schema" => RecoveryJson(Baseline(), schemaVersion: 1),
            "kind" => RecoveryJson(Baseline(), kind: "armada-board-recovery-v1"),
            "offset-space" => RecoveryJson(Baseline(), offsetSpace: "physical-image"),
            "excluded-roles" => RecoveryJson(Baseline(), excludedRoles: new[] { "vendor_boot_a" }),
            _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
        };

        Assert.Throws<InvalidDataException>(() => RequireBindings(manifest));
    }

    // ------------------------------------------------------------------ summary metadata

    [Fact]
    public void Board_archive_summary_accepts_the_header_derived_metadata()
    {
        RequireSummary(SummaryJson(), OuterJson(), HeaderBytes + CompressedBytes);
    }

    [Theory]
    [InlineData("compressed-sha")]
    [InlineData("used-bytes")]
    [InlineData("recovery-sha")]
    [InlineData("old-format")]
    [InlineData("compressed-bytes")]
    [InlineData("tar-bytes")]
    public void Board_archive_summary_refuses_metadata_that_differs_from_the_actual_header(string mutation)
    {
        long usedBytes = HeaderBytes + CompressedBytes;

        string summary = mutation switch
        {
            "compressed-sha" => SummaryJson(compressedSha: Hash("other-compressed")),
            "used-bytes" => SummaryJson(),
            "recovery-sha" => SummaryJson(recoverySha: Hash("other-recovery")),
            "old-format" => SummaryJson(format: "ustar"),
            "compressed-bytes" => SummaryJson(compressedBytes: CompressedBytes + 1L),
            "tar-bytes" => SummaryJson(tarBytes: TarBytes + 512L),
            _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
        };

        if (mutation == "used-bytes")
        {
            usedBytes += 1L;
        }

        Assert.Throws<InvalidDataException>(() => RequireSummary(summary, OuterJson(), usedBytes));
    }

    [Fact]
    public void Board_archive_summary_uses_the_actual_outer_header_not_the_summary_claim()
    {
        // The summary agrees with itself and only the outer header disagrees, so the header stays authoritative.
        Assert.Throws<InvalidDataException>(
            () => RequireSummary(
                SummaryJson(),
                OuterJson(compressedBytes: CompressedBytes + 1L),
                HeaderBytes + CompressedBytes));
    }

    // ------------------------------------------------------------------ fixtures

    private static void RequireBindings(
        string manifestJson,
        Guid? installationId = null,
        string? planSha = null,
        string? backupSha = null,
        string? originalFp = null,
        string? postFp = null,
        IReadOnlyList<string>? ownedUuids = null,
        IReadOnlyDictionary<string, (string Path, long Length, string Sha256)>? expectedEntries = null)
    {
        using JsonDocument document = JsonDocument.Parse(manifestJson);

        Invoke(
            "RequireRecoveryBindings",
            document.RootElement,
            installationId ?? InstallationId,
            planSha ?? PlanSha,
            backupSha ?? BackupManifestSha,
            originalFp ?? OriginalFingerprint,
            postFp ?? PostFingerprint,
            ownedUuids ?? OwnedUuids,
            expectedEntries ?? Expected(Baseline()));
    }

    private static void RequireSummary(string summaryJson, string outerJson, long usedBytes)
    {
        using JsonDocument summary = JsonDocument.Parse(summaryJson);
        using JsonDocument outer = JsonDocument.Parse(outerJson);

        Invoke("RequireBoardArchiveSummary", summary.RootElement, outer.RootElement, usedBytes);
    }

    private static List<Entry> Baseline()
    {
        List<Entry> entries = new();
        int index = 0;

        foreach (string role in CaptureRoles())
        {
            entries.Add(new Entry(role, role + ".bin", 1048576L + (index * 4096L), Hash(role)));
            index++;
        }

        entries.Add(new Entry(
            "pc-backup-manifest", "pc-backup-manifest.json", 262144L, Hash("pc-backup-manifest")));
        entries.Add(new Entry(
            "post-gpt-primary", "post-gpt-primary.bin", 34816L, Hash("post-gpt-primary")));
        entries.Add(new Entry(
            "post-gpt-backup", "post-gpt-backup.bin", 36864L, Hash("post-gpt-backup")));
        entries.Add(new Entry(
            "installation-record", "installation-record.json", 4096L, Hash("installation-record")));

        return entries;
    }

    private static IReadOnlyList<string> CaptureRoles()
    {
        string[] pairs =
        {
            "boot", "vendor_boot", "recovery", "init_boot", "abl", "xbl_config", "dtbo", "vbmeta",
            "vbmeta_system", "vbmeta_vendor", "modem", "dsp", "keymaster", "tz", "hyp", "devcfg",
            "aop", "featenabler", "qupfw",
        };

        List<string> roles = new();
        foreach (string name in pairs)
        {
            roles.Add(name + "_a");
            roles.Add(name + "_b");
        }

        roles.Add("misc");
        roles.Add("metadata");

        for (int lun = 0; lun < 6; lun++)
        {
            roles.Add("gpt_lun" + lun + "_primary");
            roles.Add("gpt_lun" + lun + "_backup");
        }

        return roles;
    }

    private static Dictionary<string, (string Path, long Length, string Sha256)> Expected(
        IEnumerable<Entry> entries)
    {
        Dictionary<string, (string Path, long Length, string Sha256)> map = new(StringComparer.Ordinal);
        foreach (Entry entry in entries)
        {
            map.Add(entry.Role, (entry.Path, entry.Length, entry.Sha256));
        }

        return map;
    }

    private static List<Entry> Removed(string role) =>
        Baseline().Where(entry => entry.Role != role).ToList();

    private static List<Entry> Replace(string role, Func<Entry, Entry> change)
    {
        List<Entry> entries = Baseline();
        int index = entries.FindIndex(entry => entry.Role == role);
        if (index < 0)
        {
            throw new InvalidOperationException("The fixture has no '" + role + "' entry.");
        }

        entries[index] = change(entries[index]);
        return entries;
    }

    private static bool IsExtra(string role) => ExtraRoles.Contains(role, StringComparer.Ordinal);

    private static string RecoveryJson(
        IReadOnlyList<Entry> entries,
        int schemaVersion = 2,
        string kind = "armada-board-recovery",
        string offsetSpace = "uncompressed-tar",
        IReadOnlyList<string>? excludedRoles = null)
    {
        using MemoryStream buffer = new();

        using (Utf8JsonWriter json = new(buffer))
        {
            json.WriteStartObject();
            json.WriteNumber("schemaVersion", schemaVersion);
            json.WriteString("kind", kind);
            json.WriteString("offsetSpace", offsetSpace);
            json.WriteString("installationId", InstallationId.ToString("D"));
            json.WriteString("planSha256", PlanSha);
            json.WriteString("pcBackupManifestSha256", BackupManifestSha);
            json.WriteString("originalGptSourceFingerprint", OriginalFingerprint);
            json.WriteString("postGptSourceFingerprint", PostFingerprint);

            json.WriteStartArray("excludedRoles");
            foreach (string role in excludedRoles ?? Array.Empty<string>())
            {
                json.WriteStringValue(role);
            }

            json.WriteEndArray();

            json.WriteStartArray("ownedPartitionUuids");
            foreach (string uuid in OwnedUuids)
            {
                json.WriteStringValue(uuid);
            }

            json.WriteEndArray();

            json.WriteStartArray("entries");
            long offset = 512L;
            foreach (Entry entry in entries)
            {
                json.WriteStartObject();
                json.WriteString("role", entry.Role);
                json.WriteString("path", entry.Path);
                json.WriteNumber("tarHeaderOffset", offset);
                json.WriteNumber("dataOffset", offset + 512L);
                json.WriteNumber("length", entry.Length);
                json.WriteString("sha256", entry.Sha256);
                json.WriteEndObject();

                offset += 1024L + entry.Length;
            }

            json.WriteEndArray();
            json.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static string OuterJson(
        long compressedBytes = CompressedBytes,
        string? compressedSha = null,
        long tarBytes = TarBytes,
        string? recoverySha = null)
    {
        using MemoryStream buffer = new();

        using (Utf8JsonWriter json = new(buffer))
        {
            json.WriteStartObject();
            json.WriteNumber("schemaVersion", 2);
            json.WriteString("kind", "armada-board-recovery-image");
            json.WriteNumber("imageBytes", ImageBytes);
            json.WriteNumber("headerBytes", HeaderBytes);
            json.WriteNumber("payloadOffset", HeaderBytes);
            json.WriteString("compression", "gzip");
            json.WriteString("tarFormat", "ustar");
            json.WriteNumber("compressedBytes", compressedBytes);
            json.WriteString("compressedSha256", compressedSha ?? CompressedSha);
            json.WriteNumber("uncompressedTarBytes", tarBytes);
            json.WriteString("installationId", InstallationId.ToString("D"));
            json.WriteString("planSha256", PlanSha);
            json.WriteString("recoveryManifestSha256", recoverySha ?? RecoveryManifestSha);
            json.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static string SummaryJson(
        string format = "armada-gzip-ustar-v2",
        long usedBytes = HeaderBytes + CompressedBytes,
        string? compressedSha = null,
        string? recoverySha = null,
        long compressedBytes = CompressedBytes,
        long tarBytes = TarBytes)
    {
        using MemoryStream buffer = new();

        using (Utf8JsonWriter json = new(buffer))
        {
            json.WriteStartObject();
            json.WriteNumber("schemaVersion", 2);
            json.WriteString("kind", "armada-install-artifacts");
            json.WriteString("installationId", InstallationId.ToString("D"));
            json.WriteString("planSha256", PlanSha);
            json.WriteString("boardFormat", "armada-gzip-ustar-v2");

            json.WriteStartArray("excludedRoles");
            json.WriteEndArray();

            json.WriteStartObject("boardArchive");
            json.WriteString("fileName", "board-recovery.img");
            json.WriteNumber("length", ImageBytes);
            json.WriteNumber("usedBytes", usedBytes);
            json.WriteString("sha256", BoardImageSha);
            json.WriteString("format", format);
            json.WriteNumber("payloadOffset", HeaderBytes);
            json.WriteNumber("compressedBytes", compressedBytes);
            json.WriteString("compressedSha256", compressedSha ?? CompressedSha);
            json.WriteNumber("uncompressedTarBytes", tarBytes);
            json.WriteEndObject();

            json.WriteStartObject("recoveryManifest");
            json.WriteString("fileName", "armada-recovery-manifest.json");
            json.WriteNumber("length", HeaderBytes);
            json.WriteString("sha256", recoverySha ?? RecoveryManifestSha);
            json.WriteEndObject();

            json.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static string Hash(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    // ------------------------------------------------------------------ reflection bridge

    private static readonly Type ContextType =
        typeof(InternalInstallBackend).Assembly.GetType(
            "FreedomInstaller.Core.InternalInstallPreparationContext",
            throwOnError: true)
        ?? throw new InvalidOperationException(
            "The assembly no longer declares InternalInstallPreparationContext.");

    private static MethodInfo Guard(string name)
    {
        return ContextType
            .GetMethods(BindingFlags.Static | BindingFlags.NonPublic)
            .SingleOrDefault(method => method.Name == name)
            ?? throw new InvalidOperationException(
                "InternalInstallPreparationContext no longer declares the " + name + " guard this fixture drives.");
    }

    private static void Invoke(string name, params object?[] arguments)
    {
        try
        {
            Guard(name).Invoke(null, arguments);
        }
        catch (TargetInvocationException error) when (error.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(error.InnerException).Throw();
        }
    }

    private sealed record Entry(string Role, string Path, long Length, string Sha256);
}
