#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

internal enum DirectAvbSourceKind
{
    Aosp,
    Oem
}

/// <summary>
/// Holds two independent P1 <see cref="EdlRawAvbChainTests.AvbFixture"/> source groups (A/B).
/// Oem reuses the shared synthetic key of the default fixture; Aosp imports the publicly known
/// AOSP test signing key embedded in the test key resource so the independent writer can sign.
/// No key material is ever printed, exported, or taken from a device; no production Resign path is used.
/// </summary>
internal sealed class DirectAvbSourceTestFixture : IDisposable
{
    internal const string AospKeyResourceName = "FreedomInstaller.AvbTestKey.pem";
    internal const string ExportRootEnvironmentVariable = "DIRECT_AVB_SOURCE_EXPORT_DIR";
    internal const string ExportDirectoryPrefix = "aosp-source";
    internal const string ExportPublicKeyFileName = "public.avbpubkey";
    internal const int SectorSize = 4096;

    internal static readonly string[] SourceNames =
    {
        "recovery_a",
        "recovery_b",
        "vbmeta_system_a",
        "vbmeta_system_b",
        "vbmeta_a",
        "vbmeta_b"
    };

    private readonly EdlRawAvbChainTests.AvbFixture _a;
    private readonly EdlRawAvbChainTests.AvbFixture _b;
    private readonly RSA? _aospKey;

    internal DirectAvbSourceTestFixture(DirectAvbSourceKind kind, DirectAvbSourceKind? slotBKind = null)
    {
        Kind = kind;
        BKind = slotBKind ?? kind;

        RSA? key = null;
        EdlRawAvbChainTests.AvbFixture? a = null;
        EdlRawAvbChainTests.AvbFixture? b = null;
        try
        {
            if (Kind == DirectAvbSourceKind.Aosp || BKind == DirectAvbSourceKind.Aosp)
            {
                key = ImportAospPublicTestKey();
            }

            a = CreateFixture(Kind == DirectAvbSourceKind.Aosp ? key : null);
            RebuildRootPartition(a);

            b = CreateFixture(BKind == DirectAvbSourceKind.Aosp ? key : null);
            RebuildRootPartition(b);

            Sources = MeasureSources(a, b);
            OriginalRootKeySha256 = LowerHex(SHA256.HashData(a.KeyBlob));
            OriginalRootKeySha256BySlot = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["A"] = OriginalRootKeySha256,
                ["B"] = LowerHex(SHA256.HashData(b.KeyBlob))
            };
            ExportedAospSourcePath =
                Kind == DirectAvbSourceKind.Aosp && TryGetExportRoot(out string exportRoot)
                    ? ExportAospSourceGroup(a, exportRoot)
                    : null;
        }
        catch
        {
            a?.Dispose();
            b?.Dispose();
            key?.Dispose();
            throw;
        }

        _a = a!;
        _b = b!;
        _aospKey = key;
    }

    internal DirectAvbSourceKind Kind { get; }

    internal DirectAvbSourceKind BKind { get; }

    internal EdlRawAvbChainTests.AvbFixture A => _a;

    internal EdlRawAvbChainTests.AvbFixture B => _b;

    internal IReadOnlyDictionary<string, VerifiedEdlFile> Sources { get; }

    internal string OriginalRootKeySha256 { get; }

    internal IReadOnlyDictionary<string, string> OriginalRootKeySha256BySlot { get; }

    internal string? ExportedAospSourcePath { get; }

    public void Dispose()
    {
        _a.Dispose();
        _b.Dispose();
        _aospKey?.Dispose();
    }

    private static EdlRawAvbChainTests.AvbFixture CreateFixture(RSA? key)
    {
        return key is null
            ? new EdlRawAvbChainTests.AvbFixture()
            : new EdlRawAvbChainTests.AvbFixture(key);
    }

    private static void RebuildRootPartition(EdlRawAvbChainTests.AvbFixture fixture)
    {
        byte[] partition = fixture.BuildRootPartition(
            fixture.ChainFor("boot", 3u, 4u),
            fixture.ChainFor("recovery", 1u, 8u),
            fixture.ChainFor("vbmeta_system", 2u, 16u));
        File.WriteAllBytes(fixture.VbmetaPath, partition);
        fixture.VbmetaBytes = partition;
        Assert.Equal(0, partition.Length % SectorSize);
    }

    private static RSA ImportAospPublicTestKey()
    {
        Assembly assembly = typeof(EdlRawBootBuilder).Assembly;
        using Stream? stream = assembly.GetManifestResourceStream(AospKeyResourceName);
        Assert.True(stream is not null, "embedded public test key resource is missing: " + AospKeyResourceName);

        using var reader = new StreamReader(stream!, Encoding.ASCII, detectEncodingFromByteOrderMarks: false);
        string pem = reader.ReadToEnd();

        RSA rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(pem);
            Assert.Equal(4096, rsa.KeySize);
            return rsa;
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    private static IReadOnlyDictionary<string, VerifiedEdlFile> MeasureSources(
        EdlRawAvbChainTests.AvbFixture a,
        EdlRawAvbChainTests.AvbFixture b)
    {
        return new Dictionary<string, VerifiedEdlFile>(StringComparer.Ordinal)
        {
            ["recovery_a"] = Measure(a.RecoveryPath),
            ["recovery_b"] = Measure(b.RecoveryPath),
            ["vbmeta_system_a"] = Measure(a.VbmetaSystemPath),
            ["vbmeta_system_b"] = Measure(b.VbmetaSystemPath),
            ["vbmeta_a"] = Measure(a.VbmetaPath),
            ["vbmeta_b"] = Measure(b.VbmetaPath)
        };
    }

    private static VerifiedEdlFile Measure(string path)
    {
        byte[] bytes = File.ReadAllBytes(path);
        Assert.Equal(0, bytes.Length % SectorSize);
        return new VerifiedEdlFile(path, bytes.LongLength, LowerHex(SHA256.HashData(bytes)));
    }

    private static bool TryGetExportRoot(out string exportRoot)
    {
        exportRoot = string.Empty;
        string? configured = Environment.GetEnvironmentVariable(ExportRootEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(configured)) return false;

        Assert.True(Path.IsPathRooted(configured), ExportRootEnvironmentVariable + " must be an absolute path");
        string full = Path.GetFullPath(configured).Replace('\\', '/').TrimEnd('/');
        Assert.True(
            full == "/evidence" || full.StartsWith("/evidence/", StringComparison.Ordinal),
            ExportRootEnvironmentVariable + " must resolve below /evidence, got: " + full);

        exportRoot = full;
        return true;
    }

    private static string ExportAospSourceGroup(EdlRawAvbChainTests.AvbFixture a, string exportRoot)
    {
        string directory = Path.Combine(exportRoot, ExportDirectoryPrefix + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);

        File.WriteAllBytes(Path.Combine(directory, "recovery.img"), a.RecoveryBytes);
        File.WriteAllBytes(Path.Combine(directory, "vbmeta_system.img"), a.VbmetaSystemBytes);
        File.WriteAllBytes(Path.Combine(directory, "vbmeta.img"), a.VbmetaBytes);
        File.WriteAllBytes(Path.Combine(directory, "system.img"), a.SystemLeafBytes);
        File.WriteAllBytes(Path.Combine(directory, "vendor.img"), a.VendorLeafBytes);
        File.WriteAllBytes(Path.Combine(directory, ExportPublicKeyFileName), a.KeyBlob);

        Assert.True(
            File.Exists(Path.Combine(directory, ExportPublicKeyFileName)),
            "aosp source export must contain the public AVB key blob");
        return directory;
    }

    internal static string LowerHex(byte[] hash)
    {
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}

public sealed class DirectAvbSourceFixtureTests
{
    private const string TargetSigningKeyField = "SigningPublicKeySha256";
    private const int RecoveryFooterSize = 64;

    [Theory]
    [InlineData("Oem")]
    [InlineData("Aosp")]
    public void SourcesMatchMeasuredFilesAndSectorLayout(string modeName)
    {
        using var fixture = new DirectAvbSourceTestFixture(ParseKind(modeName));

        Assert.Equal(6, fixture.Sources.Count);
        Assert.Equal(
            DirectAvbSourceTestFixture.SourceNames.OrderBy(name => name, StringComparer.Ordinal).ToArray(),
            fixture.Sources.Keys.OrderBy(name => name, StringComparer.Ordinal).ToArray());

        foreach (string name in DirectAvbSourceTestFixture.SourceNames)
        {
            VerifiedEdlFile source = fixture.Sources[name];
            Assert.True(File.Exists(source.Path), "source file is missing: " + name);
            byte[] bytes = File.ReadAllBytes(source.Path);
            Assert.Equal(bytes.LongLength, source.Length);
            Assert.Equal(0L, source.Length % DirectAvbSourceTestFixture.SectorSize);
            Assert.Equal(DirectAvbSourceTestFixture.LowerHex(SHA256.HashData(bytes)), source.Sha256);
            Assert.Matches("^[0-9a-f]{64}$", source.Sha256);
        }

        Assert.NotEqual(fixture.Sources["recovery_a"].Path, fixture.Sources["recovery_b"].Path);
        Assert.NotEqual(fixture.Sources["vbmeta_a"].Path, fixture.Sources["vbmeta_b"].Path);

        foreach (string name in new[] { "recovery_a", "recovery_b" })
        {
            byte[] bytes = File.ReadAllBytes(fixture.Sources[name].Path);
            Assert.True(bytes.Length > RecoveryFooterSize, name + " must carry an AVB footer");
            Assert.Equal("AVBf", Encoding.ASCII.GetString(bytes, bytes.Length - RecoveryFooterSize, 4));
        }

        foreach (string name in new[] { "vbmeta_a", "vbmeta_b" })
        {
            byte[] bytes = File.ReadAllBytes(fixture.Sources[name].Path);
            Assert.Equal("AVB0", Encoding.ASCII.GetString(bytes, 0, 4));
            Assert.Equal(fixture.Sources[name].Length, bytes.LongLength);
        }

        Assert.Equal(fixture.A.VbmetaBytes, File.ReadAllBytes(fixture.A.VbmetaPath));
        Assert.Equal(fixture.B.VbmetaBytes, File.ReadAllBytes(fixture.B.VbmetaPath));

        string rootText = Encoding.ASCII.GetString(fixture.A.VbmetaBytes);
        Assert.True(rootText.Contains("boot", StringComparison.Ordinal), "root vbmeta must chain boot");
        Assert.True(rootText.Contains("recovery", StringComparison.Ordinal), "root vbmeta must chain recovery");
        Assert.True(rootText.Contains("vbmeta_system", StringComparison.Ordinal), "root vbmeta must chain vbmeta_system");
    }

    [Theory]
    [InlineData("Oem")]
    [InlineData("Aosp")]
    public void OriginalRootKeyMatchesTargetSignerOnlyForAosp(string modeName)
    {
        DirectAvbSourceKind kind = ParseKind(modeName);
        using var fixture = new DirectAvbSourceTestFixture(kind);

        string actual = fixture.OriginalRootKeySha256;
        string target = TargetSigningKeySha256();

        Assert.Matches("^[0-9a-f]{64}$", actual);
        Assert.Equal(actual.ToLowerInvariant(), actual);

        if (kind == DirectAvbSourceKind.Aosp)
        {
            Assert.True(
                string.Equals(target, actual, StringComparison.OrdinalIgnoreCase),
                "AOSP source root key must match the pinned target signing key");
        }
        else
        {
            Assert.False(
                string.Equals(target, actual, StringComparison.OrdinalIgnoreCase),
                "OEM source keeps the shared synthetic key and must not match the pinned target signing key");
        }
    }

    [Theory]
    [InlineData("Oem")]
    [InlineData("Aosp")]
    public void AospSourceExportIsOptionalAndNeverCarriesPrivateKey(string modeName)
    {
        DirectAvbSourceKind kind = ParseKind(modeName);
        using var fixture = new DirectAvbSourceTestFixture(kind);

        bool configured = !string.IsNullOrWhiteSpace(
            Environment.GetEnvironmentVariable(DirectAvbSourceTestFixture.ExportRootEnvironmentVariable));

        if (!configured || kind != DirectAvbSourceKind.Aosp)
        {
            Assert.Null(fixture.ExportedAospSourcePath);
            return;
        }

        string directory = fixture.ExportedAospSourcePath!;
        Assert.True(Directory.Exists(directory), "aosp source export directory is missing");

        foreach (string name in new[] { "recovery.img", "vbmeta_system.img", "vbmeta.img", "system.img", "vendor.img", "public.avbpubkey" })
        {
            Assert.True(File.Exists(Path.Combine(directory, name)), "aosp source export is missing " + name);
        }

        Assert.False(
            Directory.EnumerateFiles(directory, "*.pem", SearchOption.AllDirectories).Any(),
            "aosp source export must never contain private key material");
        Assert.Equal(
            File.ReadAllBytes(fixture.A.VbmetaPath),
            File.ReadAllBytes(Path.Combine(directory, "vbmeta.img")));
    }

    [Fact]
    public void MixedSlotSourcesKeepIndependentOriginalRootKeys()
    {
        using var fixture = new DirectAvbSourceTestFixture(DirectAvbSourceKind.Aosp, DirectAvbSourceKind.Oem);

        Assert.Equal(DirectAvbSourceKind.Aosp, fixture.Kind);
        Assert.Equal(DirectAvbSourceKind.Oem, fixture.BKind);

        string target = TargetSigningKeySha256();
        string slotA = fixture.OriginalRootKeySha256BySlot["A"];
        string slotB = fixture.OriginalRootKeySha256BySlot["B"];

        Assert.True(
            string.Equals(target, slotA, StringComparison.OrdinalIgnoreCase),
            "slot A must sign with the AOSP test key");
        Assert.False(
            string.Equals(target, slotB, StringComparison.OrdinalIgnoreCase),
            "slot B must keep the shared synthetic OEM key");
        Assert.NotEqual(slotA, slotB);

        Assert.Equal(fixture.OriginalRootKeySha256, slotA);
        Assert.Equal(DirectAvbSourceTestFixture.LowerHex(SHA256.HashData(fixture.A.KeyBlob)), slotA);
        Assert.Equal(DirectAvbSourceTestFixture.LowerHex(SHA256.HashData(fixture.B.KeyBlob)), slotB);

        Assert.NotEqual(fixture.Sources["vbmeta_a"].Path, fixture.Sources["vbmeta_b"].Path);
        Assert.NotEqual(fixture.Sources["recovery_a"].Path, fixture.Sources["recovery_b"].Path);
        Assert.Equal(
            fixture.Sources["vbmeta_a"].Sha256,
            DirectAvbSourceTestFixture.LowerHex(SHA256.HashData(fixture.A.VbmetaBytes)));
        Assert.Equal(
            fixture.Sources["vbmeta_b"].Sha256,
            DirectAvbSourceTestFixture.LowerHex(SHA256.HashData(fixture.B.VbmetaBytes)));
    }

    private static DirectAvbSourceKind ParseKind(string modeName)
    {
        return modeName switch
        {
            "Oem" => DirectAvbSourceKind.Oem,
            "Aosp" => DirectAvbSourceKind.Aosp,
            _ => throw new ArgumentOutOfRangeException(nameof(modeName), modeName, "unknown direct AVB source kind")
        };
    }

    private static string TargetSigningKeySha256()
    {
        PropertyInfo? property = typeof(EdlRawBootBuilder).GetProperty(
            TargetSigningKeyField, BindingFlags.Static | BindingFlags.NonPublic);
        Assert.True(property is not null, "internal pin " + TargetSigningKeyField + " is missing");

        string? value = property!.GetValue(null) as string;
        Assert.False(string.IsNullOrWhiteSpace(value), "internal pin " + TargetSigningKeyField + " is empty");
        return value!;
    }
}
