using System;
using System.IO;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class InstallerWorkSessionTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CloseCleansOnlyOwnedWorkAndKeepsReports(bool preserveRecovery)
    {
        string root = Path.Combine(Environment.GetEnvironmentVariable("TEST_ARTIFACT_ROOT")!, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        string backup = Path.Combine(root, "user-backup");
        Directory.CreateDirectory(backup);
        File.WriteAllText(Path.Combine(backup, "boot_a.bin"), "original-backup");
        var first = new InstallerWorkSession(root);
        var other = new InstallerWorkSession(root);
        File.WriteAllText(Path.Combine(other.DirectoryPath, "busy.bin"), "other-session");
        string child = Path.Combine(first.DirectoryPath, "preparation");
        Directory.CreateDirectory(child);
        File.WriteAllText(Path.Combine(child, "recovery.img"), "temporary-image");
        File.WriteAllText(Path.Combine(child, "verification.json"), "verified receipt");
        first.Complete(preserveRecovery);
        Assert.Equal(preserveRecovery, Directory.Exists(first.DirectoryPath));
        Assert.Equal("original-backup", File.ReadAllText(Path.Combine(backup, "boot_a.bin")));
        Assert.True(File.Exists(Path.Combine(other.DirectoryPath, "busy.bin")));
        if (!preserveRecovery)
        {
            Assert.Equal("verified receipt", File.ReadAllText(Path.Combine(first.RecordsDirectory, "preparation", "verification.json")));
            Assert.False(File.Exists(Path.Combine(first.RecordsDirectory, "preparation", "recovery.img")));
            first.Complete(false);
        }
        other.Complete(false);
    }
    [Fact]
    public void CleanupDoesNotFollowDirectoryLinks()
    {
        string root = Path.Combine(Environment.GetEnvironmentVariable("TEST_ARTIFACT_ROOT")!, Guid.NewGuid().ToString("N"));
        string backup = Path.Combine(root, "selected-backup");
        Directory.CreateDirectory(backup);
        File.WriteAllText(Path.Combine(backup, "boot.bin"), "keep");
        File.WriteAllText(Path.Combine(backup, "manifest.json"), "keep");
        var work = new InstallerWorkSession(root);
        Directory.CreateSymbolicLink(Path.Combine(work.DirectoryPath, "external"), backup);
        work.Complete(false);
        Assert.False(Directory.Exists(work.DirectoryPath));
        Assert.Equal("keep", File.ReadAllText(Path.Combine(backup, "boot.bin")));
        Assert.False(Directory.Exists(Path.Combine(work.RecordsDirectory, "external")));
    }

}
