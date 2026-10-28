using System;
using System.Formats.Tar;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Offline validation of the actual TF bootstrap support archive and the actual
/// generated cleanup shell. Uses reflection against the exact production members
/// (the test project has no InternalsVisibleTo, and both members are non-public);
/// no production code is changed and no fixture is exported by default.
/// </summary>
public sealed class TfBootstrapScriptTests
{
    private const string HelperResourceName = "FreedomInstaller.TfMaintenance.Helper.py";
    private const string HelperEntryName = "armada_tf.py";
    private const string LauncherEntryName = "launch_tf.sh";

    private static byte[] InvokeArchiveBuilder()
    {
        var method = typeof(MaintenanceBootstrap).GetMethod(
            "BuildTfSupportArchive",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        return (byte[])method!.Invoke(null, null)!;
    }

    private static string InvokeCleanupScript()
    {
        var method = typeof(MaintenanceBootstrap).GetMethod(
            "BuildTfCleanupScript",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        return (string)method!.Invoke(null, new object?[] { null, null })!;
    }

    private static byte[] ReadResource(string name)
    {
        using var stream = typeof(MaintenanceBootstrap).Assembly.GetManifestResourceStream(name);
        Assert.NotNull(stream);
        using var buffer = new MemoryStream();
        stream!.CopyTo(buffer);
        return buffer.ToArray();
    }

    private static MemoryStream DecompressTar(byte[] archive)
    {
        using var gzip = new GZipStream(new MemoryStream(archive), CompressionMode.Decompress);
        var tar = new MemoryStream();
        gzip.CopyTo(tar);
        tar.Position = 0;
        return tar;
    }

    private static void AssertEntry(TarEntry entry, string name, UnixFileMode mode)
    {
        Assert.Equal(name, entry.Name);
        Assert.Equal(TarEntryType.RegularFile, entry.EntryType);
        Assert.Equal(TarEntryFormat.Ustar, entry.Format);
        Assert.Equal(0, entry.Uid);
        Assert.Equal(0, entry.Gid);
        var ustar = Assert.IsType<UstarTarEntry>(entry);
        Assert.Equal(string.Empty, ustar.UserName);
        Assert.Equal(string.Empty, ustar.GroupName);
        Assert.Equal(DateTimeOffset.UnixEpoch, entry.ModificationTime);
        Assert.Equal(mode, entry.Mode);
    }

    [Fact]
    public void BuildTfSupportArchive_And_BuildTfCleanupScript_ProduceDeterministicUstarArchiveAndExecutableCleanupScript()
    {
        var archive = InvokeArchiveBuilder();
        Assert.NotEmpty(archive);

        // Deterministic: a second build must be byte-identical.
        var archiveAgain = InvokeArchiveBuilder();
        Assert.True(archive.AsSpan().SequenceEqual(archiveAgain), "archive build is deterministic");

        var helperBytes = ReadResource(HelperResourceName);
        Assert.NotEmpty(helperBytes);

        byte[] launcherBytes;
        using (var tar = DecompressTar(archive))
        using (var reader = new TarReader(tar, leaveOpen: true))
        {
            var helperEntry = reader.GetNextEntry();
            Assert.NotNull(helperEntry);
            AssertEntry(helperEntry!, HelperEntryName, (UnixFileMode)0x1a4);
            var helperData = ReadEntryBytes(helperEntry!);
            Assert.True(helperBytes.AsSpan().SequenceEqual(helperData), $"payload of {HelperEntryName}");

            var launcherEntry = reader.GetNextEntry();
            Assert.NotNull(launcherEntry);
            AssertEntry(launcherEntry!, LauncherEntryName, (UnixFileMode)0x1ed);
            launcherBytes = ReadEntryBytes(launcherEntry!);

            Assert.Null(reader.GetNextEntry());
        }

        Assert.NotEmpty(launcherBytes);

        // The actual generated cleanup script for the (null, null) production call,
        // unmodified: fixed paths, records and success marker must be present.
        var cleanup = InvokeCleanupScript();
        Assert.NotEmpty(cleanup);
        Assert.Contains("FREEDOM_TF_CLEANUP_V1_OK", cleanup);
        Assert.Contains("/run/freedom-maintenance/tf-helper.pid", cleanup);
        Assert.Contains("/run/freedom-maintenance/udhcpd.pid", cleanup);
        Assert.Contains("/run/freedom-maintenance/tf-created", cleanup);
        Assert.Contains("/tmp/armada-tf-tools", cleanup);
        Assert.Contains("/tmp/freedom-maintenance/incoming/tf-support", cleanup);
        Assert.Contains("/run/freedom-tf", cleanup);
        Assert.Contains("/tmp/freedom-maintenance/udhcpd.conf", cleanup);

        ExportFixtures(archive, launcherBytes, cleanup);
    }

    private static byte[] ReadEntryBytes(TarEntry entry)
    {
        using var buffer = new MemoryStream();
        Assert.NotNull(entry.DataStream);
        entry.DataStream!.CopyTo(buffer);
        return buffer.ToArray();
    }

    /// <summary>
    /// CI-only evidence export: runs only when TF_BOOTSTRAP_FIXTURE_EXPORT_DIR is explicitly
    /// nonempty and names an existing directory beneath /evidence. Never exports by default.
    /// </summary>
    private static void ExportFixtures(byte[] archive, byte[] launcher, string cleanup)
    {
        var configured = Environment.GetEnvironmentVariable("TF_BOOTSTRAP_FIXTURE_EXPORT_DIR");
        if (string.IsNullOrEmpty(configured))
        {
            return;
        }

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return;
        }

        var full = Path.GetFullPath(configured).Replace('\\', '/');
        if (!Directory.Exists(full) || !full.StartsWith("/evidence/", StringComparison.Ordinal))
        {
            return;
        }

        File.WriteAllBytes(Path.Combine(full, "support.tar.gz"), archive);
        File.WriteAllBytes(Path.Combine(full, "launcher.sh"), launcher);
        File.WriteAllBytes(Path.Combine(full, "cleanup.sh"), System.Text.Encoding.UTF8.GetBytes(cleanup));
    }
}
