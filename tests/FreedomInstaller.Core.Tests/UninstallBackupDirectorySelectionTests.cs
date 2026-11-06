using System;
using System.IO;
using System.Linq;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class UninstallBackupDirectorySelectionTests
{
    private static readonly string ArtifactRoot = ResolveArtifactRoot();

    private static string ResolveArtifactRoot()
    {
        var value = Environment.GetEnvironmentVariable("TEST_ARTIFACT_ROOT");
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException("TEST_ARTIFACT_ROOT must be set to an absolute path for these tests.");
        }

        if (!Path.IsPathRooted(value))
        {
            throw new InvalidOperationException("TEST_ARTIFACT_ROOT must be an absolute path.");
        }

        Directory.CreateDirectory(value);
        return value;
    }

    private static string NewCaseFolder(string name)
    {
        var path = Path.Combine(ArtifactRoot, "UninstallBackupDirectorySelection", name + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static void WriteMarker(string directory, bool manifest = true, bool sidecar = false)
    {
        Directory.CreateDirectory(directory);
        if (manifest)
        {
            File.WriteAllText(Path.Combine(directory, UninstallBackupDirectorySelection.ManifestFileName), "synthetic-marker");
        }

        if (sidecar)
        {
            File.WriteAllText(Path.Combine(directory, UninstallBackupDirectorySelection.ManifestSidecarFileName), "synthetic-sidecar");
        }
    }

    [Fact]
    public void Resolve_FindsSingleImmediateChildAmongIrrelevantSiblings()
    {
        var parent = NewCaseFolder("nesting");
        var backup = Path.Combine(parent, "internal-backup-20240101-000000");
        WriteMarker(backup);
        Directory.CreateDirectory(Path.Combine(parent, "install-root"));
        Directory.CreateDirectory(Path.Combine(parent, "tool-cache"));

        var result = UninstallBackupDirectorySelection.Resolve(parent);

        Assert.Equal(UninstallBackupDirectorySelection.SelectionKind.Selected, result.Kind);
        Assert.Equal(backup, result.DirectoryPath);
        Assert.Single(result.Candidates);
    }

    [Fact]
    public void Resolve_DirectLeafTakesPrecedenceOverChildren()
    {
        var leaf = NewCaseFolder("leaf-precedence");
        WriteMarker(leaf, manifest: false, sidecar: true);
        WriteMarker(Path.Combine(leaf, "internal-backup-child"));

        var result = UninstallBackupDirectorySelection.Resolve(leaf);

        Assert.Equal(UninstallBackupDirectorySelection.SelectionKind.Selected, result.Kind);
        Assert.Equal(leaf, result.DirectoryPath);
        Assert.Single(result.Candidates);
        Assert.Equal(leaf, result.Candidates[0]);
    }

    [Fact]
    public void Resolve_MultipleChildrenAreAmbiguousEvenWithOnePartial()
    {
        var parent = NewCaseFolder("ambiguous");
        var first = Path.Combine(parent, "internal-backup-a");
        var second = Path.Combine(parent, "internal-backup-b");
        WriteMarker(first);
        WriteMarker(second, manifest: false, sidecar: true);

        var result = UninstallBackupDirectorySelection.Resolve(parent);

        Assert.Equal(UninstallBackupDirectorySelection.SelectionKind.Multiple, result.Kind);
        Assert.Null(result.DirectoryPath);
        Assert.Equal(new[] { first, second }.OrderBy(p => p, StringComparer.Ordinal), result.Candidates);
    }

    [Fact]
    public void Resolve_MissingWhenNoMarkersPresent()
    {
        var parent = NewCaseFolder("absent");
        Directory.CreateDirectory(Path.Combine(parent, "install-root"));

        var result = UninstallBackupDirectorySelection.Resolve(parent);

        Assert.Equal(UninstallBackupDirectorySelection.SelectionKind.Missing, result.Kind);
        Assert.Null(result.DirectoryPath);
        Assert.Empty(result.Candidates);
    }

    [Fact]
    public void Resolve_DoesNotRecurseIntoGrandchildren()
    {
        var parent = NewCaseFolder("no-recursion");
        var child = Path.Combine(parent, "internal-backup-parent");
        WriteMarker(Path.Combine(child, "internal-backup-grandchild"));

        var result = UninstallBackupDirectorySelection.Resolve(parent);

        Assert.Equal(UninstallBackupDirectorySelection.SelectionKind.Missing, result.Kind);
        Assert.Null(result.DirectoryPath);
        Assert.Empty(result.Candidates);
    }

    [Fact]
    public void Resolve_PartialMarkersUnderChildArePassedOnward()
    {
        var parent = NewCaseFolder("partial-child");
        var child = Path.Combine(parent, "internal-backup-partial");
        WriteMarker(child, manifest: false, sidecar: true);

        var result = UninstallBackupDirectorySelection.Resolve(parent);

        Assert.Equal(UninstallBackupDirectorySelection.SelectionKind.Selected, result.Kind);
        Assert.Equal(child, result.DirectoryPath);
    }

    [Fact]
    public void Resolve_RejectsRelativePath()
    {
        Assert.Throws<ArgumentException>(() => UninstallBackupDirectorySelection.Resolve("relative\\dir"));
    }

    [Fact]
    public void Resolve_RejectsFilePath()
    {
        var root = NewCaseFolder("file-path");
        var file = Path.Combine(root, "not-a-directory.txt");
        File.WriteAllText(file, "synthetic");

        Assert.ThrowsAny<IOException>(() => UninstallBackupDirectorySelection.Resolve(file));
    }

    [Fact]
    public void Resolve_RejectsNonExistentDirectory()
    {
        var missing = Path.Combine(NewCaseFolder("missing-path"), "does-not-exist");

        Assert.ThrowsAny<IOException>(() => UninstallBackupDirectorySelection.Resolve(missing));
    }

    [Fact]
    public void Resolve_SkipsReparsePointChildWhenSupported()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var parent = NewCaseFolder("reparse-child");
        var target = NewCaseFolder("reparse-target");
        WriteMarker(target);
        var link = Path.Combine(parent, "internal-backup-link");
        Directory.CreateSymbolicLink(link, target);

        var result = UninstallBackupDirectorySelection.Resolve(parent);

        Assert.Equal(UninstallBackupDirectorySelection.SelectionKind.Missing, result.Kind);
        Assert.Null(result.DirectoryPath);
        Assert.Empty(result.Candidates);
    }
}
