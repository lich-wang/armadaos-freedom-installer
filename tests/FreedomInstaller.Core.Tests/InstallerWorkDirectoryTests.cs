using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class InstallerWorkDirectoryTests : IDisposable
{
    private const long GiB = 1024L * 1024 * 1024;
    private readonly string _sandboxRoot;
    private readonly string _systemRoot;
    private readonly string _dataRoot;
    private readonly string _localAppData;

    public InstallerWorkDirectoryTests()
    {
        string artifactBase = Environment.GetEnvironmentVariable("TEST_ARTIFACT_ROOT")
            ?? throw new InvalidOperationException("TEST_ARTIFACT_ROOT must be set for tests.");
        _sandboxRoot = Path.Combine(artifactBase, "installer-work-tests", Guid.NewGuid().ToString("N"));
        _systemRoot = Path.Combine(_sandboxRoot, "system");
        _dataRoot = Path.Combine(_sandboxRoot, "data");
        _localAppData = Path.Combine(_systemRoot, "users", "localappdata");
        Directory.CreateDirectory(_localAppData);
        Directory.CreateDirectory(_dataRoot);
    }

    public void Dispose()
    {
        if (Directory.Exists(_sandboxRoot))
            Directory.Delete(_sandboxRoot, recursive: true);
    }

    [Fact]
    public void Automatic_MatchesLocalAppDataWhenVolumeIsFilesystemRoot()
    {
        string expectedPath = Path.Combine(_localAppData, "ArmadaOS Freedom", "Work");
        var volumes = new[]
        {
            new InstallerWorkVolume(Path.GetPathRoot(_sandboxRoot)!, DriveType.Fixed, true, "NTFS")
        };

        var result = InstallerWorkDirectory.Resolve(
            null,
            _localAppData,
            volumes,
            _ => 10 * GiB,
            candidate =>
            {
                Assert.Equal(expectedPath, candidate);
                InstallerWorkDirectory.ProbeDirectoryWritability(candidate);
            });

        Assert.Equal(expectedPath, result.RootPath);
    }

    [Fact]
    public void Automatic_MacOsUsesLocalAppDataAndSkipsSystemVolumes()
    {
        // DriveInfo on macOS lists "/" plus the boot container's system volumes,
        // all Fixed apfs with the same free space.
        string expectedPath = Path.Combine(_localAppData, "ArmadaOS Freedom", "Work");
        var volumes = new[]
        {
            new InstallerWorkVolume("/System/Volumes/Data", DriveType.Fixed, true, "apfs"),
            new InstallerWorkVolume("/System/Volumes/Preboot", DriveType.Fixed, true, "apfs"),
            new InstallerWorkVolume("/System/Volumes/VM", DriveType.Fixed, true, "apfs"),
            new InstallerWorkVolume("/System/Volumes/xarts/", DriveType.Fixed, true, "apfs"),
            new InstallerWorkVolume(Path.GetPathRoot(_sandboxRoot)!, DriveType.Fixed, true, "apfs")
        };
        var probed = new List<string>();

        var result = InstallerWorkDirectory.Resolve(
            null,
            _localAppData,
            volumes,
            _ => 100 * GiB,
            candidate =>
            {
                probed.Add(candidate);
                if (!candidate.StartsWith(_sandboxRoot, StringComparison.Ordinal))
                    throw new IOException($"unexpected probe outside the test sandbox: {candidate}");
                InstallerWorkDirectory.ProbeDirectoryWritability(candidate);
            });

        Assert.Equal(expectedPath, result.RootPath);
        Assert.Equal(new[] { expectedPath }, probed);
    }

    [Fact]
    public void Automatic_AcceptsExternalHfsVolume()
    {
        var volumes = new[] { new InstallerWorkVolume(_dataRoot, DriveType.Fixed, true, "hfs") };

        var result = InstallerWorkDirectory.Resolve(
            null,
            _localAppData,
            volumes,
            _ => 20 * GiB,
            InstallerWorkDirectory.ProbeDirectoryWritability);

        Assert.Equal(Path.Combine(_dataRoot, "ArmadaOS Freedom", "Work"), result.RootPath);
    }

    [Theory]
    [InlineData(512L * 1024 * 1024)]
    [InlineData(5 * GiB)]
    public void Automatic_SelectsDataVolumeWhenSystemVolumeHasLessFreeSpace(long systemFree)
    {
        var volumes = new[]
        {
            new InstallerWorkVolume(_systemRoot, DriveType.Fixed, true, "NTFS"),
            new InstallerWorkVolume(_dataRoot, DriveType.Fixed, true, "NTFS")
        };

        var result = InstallerWorkDirectory.Resolve(
            null,
            _localAppData,
            volumes,
            path => path.StartsWith(_dataRoot, StringComparison.Ordinal) ? 40 * GiB : systemFree,
            InstallerWorkDirectory.ProbeDirectoryWritability);

        Assert.Equal(Path.Combine(_dataRoot, "ArmadaOS Freedom", "Work"), result.RootPath);
        Assert.Equal(40 * GiB, result.AvailableFreeBytes);
    }

    [Fact]
    public void Automatic_UsesLocalAppDataPathWhenSystemVolumeWins()
    {
        var volumes = new[]
        {
            new InstallerWorkVolume(_systemRoot, DriveType.Fixed, true, "ext4")
        };

        var result = InstallerWorkDirectory.Resolve(
            "   ",
            _localAppData,
            volumes,
            _ => 12 * GiB,
            InstallerWorkDirectory.ProbeDirectoryWritability);

        Assert.Equal(Path.Combine(_localAppData, "ArmadaOS Freedom", "Work"), result.RootPath);
        Assert.Equal(12 * GiB, result.AvailableFreeBytes);
    }

    [Fact]
    public void Automatic_SkipsNonFixedNotReadyUnsupportedFileSystemAndUnknownFree()
    {
        string removableRoot = Directory.CreateDirectory(Path.Combine(_sandboxRoot, "rem")).FullName;
        string fatRoot = Directory.CreateDirectory(Path.Combine(_sandboxRoot, "fat")).FullName;
        string emptyFsRoot = Directory.CreateDirectory(Path.Combine(_sandboxRoot, "emptyfs")).FullName;
        string notReadyRoot = Directory.CreateDirectory(Path.Combine(_sandboxRoot, "notready")).FullName;

        var volumes = new[]
        {
            new InstallerWorkVolume(removableRoot, DriveType.Removable, true, "NTFS"),
            new InstallerWorkVolume(fatRoot, DriveType.Fixed, true, "FAT32"),
            new InstallerWorkVolume(emptyFsRoot, DriveType.Fixed, true, ""),
            new InstallerWorkVolume(notReadyRoot, DriveType.Fixed, false, "NTFS"),
            new InstallerWorkVolume(_systemRoot, DriveType.Fixed, true, "NTFS"),
            new InstallerWorkVolume(_dataRoot, DriveType.Fixed, true, "ReFS")
        };

        var result = InstallerWorkDirectory.Resolve(
            null,
            _localAppData,
            volumes,
            path => path.StartsWith(_systemRoot, StringComparison.Ordinal) ? null : 8 * GiB,
            InstallerWorkDirectory.ProbeDirectoryWritability);

        Assert.Equal(Path.Combine(_dataRoot, "ArmadaOS Freedom", "Work"), result.RootPath);
    }

    [Fact]
    public void Automatic_FallsBackWhenHighestCandidateThrowsOnFreeQueryOrProbe()
    {
        string brokenRoot = Directory.CreateDirectory(Path.Combine(_sandboxRoot, "broken")).FullName;
        var volumes = new[]
        {
            new InstallerWorkVolume(brokenRoot, DriveType.Fixed, true, "NTFS"),
            new InstallerWorkVolume(_dataRoot, DriveType.Fixed, true, "NTFS"),
            new InstallerWorkVolume(_systemRoot, DriveType.Fixed, true, "NTFS")
        };

        var result = InstallerWorkDirectory.Resolve(
            null,
            _localAppData,
            volumes,
            path =>
            {
                if (path.StartsWith(brokenRoot, StringComparison.Ordinal))
                    throw new IOException("Disk read error");
                return path.StartsWith(_dataRoot, StringComparison.Ordinal) ? 50 * GiB : 10 * GiB;
            },
            path =>
            {
                if (path.StartsWith(_dataRoot, StringComparison.Ordinal))
                    throw new UnauthorizedAccessException("Access denied");
                InstallerWorkDirectory.ProbeDirectoryWritability(path);
            });

        Assert.Equal(Path.Combine(_localAppData, "ArmadaOS Freedom", "Work"), result.RootPath);
        Assert.Equal(10 * GiB, result.AvailableFreeBytes);
    }

    [Fact]
    public void Explicit_ValidOverrideChosenEvenWithLessFreeSpaceThanOtherVolumes()
    {
        string customPath = Path.Combine(_systemRoot, "custom-work");
        var volumes = new[]
        {
            new InstallerWorkVolume(_dataRoot, DriveType.Fixed, true, "NTFS")
        };

        var result = InstallerWorkDirectory.Resolve(
            customPath,
            _localAppData,
            volumes,
            path => path.StartsWith(_systemRoot, StringComparison.Ordinal) ? 2 * GiB : 100 * GiB,
            InstallerWorkDirectory.ProbeDirectoryWritability);

        Assert.Equal(customPath, result.RootPath);
        Assert.Equal(2 * GiB, result.AvailableFreeBytes);
    }

    [Fact]
    public void Explicit_InvalidRelativeLowSpaceOrUnwritable_ThrowsAndNeverFallsBack()
    {
        var volumes = new[] { new InstallerWorkVolume(_dataRoot, DriveType.Fixed, true, "NTFS") };
        string customPath = Path.Combine(_systemRoot, "explicit-fail");

        Assert.Throws<IOException>(() => InstallerWorkDirectory.Resolve(
            "relative/work/dir",
            _localAppData,
            volumes,
            _ => 50 * GiB,
            InstallerWorkDirectory.ProbeDirectoryWritability));

        Assert.Throws<IOException>(() => InstallerWorkDirectory.Resolve(
            customPath,
            _localAppData,
            volumes,
            path => path.StartsWith(_systemRoot, StringComparison.Ordinal) ? 512L * 1024 * 1024 : 50 * GiB,
            InstallerWorkDirectory.ProbeDirectoryWritability));

        Assert.Throws<IOException>(() => InstallerWorkDirectory.Resolve(
            customPath,
            _localAppData,
            volumes,
            _ => 5 * GiB,
            _ => throw new UnauthorizedAccessException("Denied")));
    }

    [Fact]
    public void Automatic_ThrowsActionableIOExceptionWhenAllCandidatesFail()
    {
        var volumes = new[]
        {
            new InstallerWorkVolume(_systemRoot, DriveType.Fixed, true, "NTFS"),
            new InstallerWorkVolume(_dataRoot, DriveType.Fixed, true, "NTFS")
        };

        Assert.Throws<IOException>(() => InstallerWorkDirectory.Resolve(
            null,
            _localAppData,
            volumes,
            _ => 512L * 1024 * 1024,
            InstallerWorkDirectory.ProbeDirectoryWritability));
    }

    [Fact]
    public void ProbeDirectoryWritability_CreatesAndCleansUpProbePreservingUserFiles()
    {
        string targetDir = Path.Combine(_sandboxRoot, "probe-target");
        Directory.CreateDirectory(targetDir);
        string existingFile = Path.Combine(targetDir, "keep.txt");
        File.WriteAllText(existingFile, "user data");

        InstallerWorkDirectory.ProbeDirectoryWritability(targetDir);

        string[] remaining = Directory.GetFileSystemEntries(targetDir);
        Assert.Single(remaining);
        Assert.Equal(existingFile, remaining[0]);
        Assert.Equal("user data", File.ReadAllText(existingFile));
    }

    [Fact]
    public void Automatic_RechecksSpaceAfterProbeAndFallsBackIfVolumeFilled()
    {
        var volumes = new[]
        {
            new InstallerWorkVolume(_dataRoot, DriveType.Fixed, true, "NTFS"),
            new InstallerWorkVolume(_systemRoot, DriveType.Fixed, true, "NTFS")
        };
        bool dataProbed = false;
        var result = InstallerWorkDirectory.Resolve(null, _localAppData, volumes,
            path => path.StartsWith(_dataRoot, StringComparison.Ordinal)
                ? (dataProbed ? 0 : 100 * GiB) : 10 * GiB,
            path =>
            {
                InstallerWorkDirectory.ProbeDirectoryWritability(path);
                if (path.StartsWith(_dataRoot, StringComparison.Ordinal)) dataProbed = true;
            });
        Assert.Equal(Path.Combine(_localAppData, "ArmadaOS Freedom", "Work"), result.RootPath);
    }

    [Fact]
    public void Explicit_UnknownSpaceStopsBeforeCreatingWorkFiles()
    {
        bool probed = false;
        string custom = Path.Combine(_dataRoot, "custom");
        Assert.Throws<IOException>(() => InstallerWorkDirectory.Resolve(custom, _localAppData,
            Array.Empty<InstallerWorkVolume>(), _ => null, _ => probed = true));
        Assert.False(probed);
        Assert.False(Directory.Exists(custom));
    }

    [Fact]
    public void SelectedDataVolume_SessionCleanupPreservesBackupAndReports()
    {
        var selected = InstallerWorkDirectory.Resolve(null, _localAppData,
            new[] { new InstallerWorkVolume(_dataRoot, DriveType.Fixed, true, "NTFS") },
            _ => 100 * GiB, InstallerWorkDirectory.ProbeDirectoryWritability);
        string backup = Path.Combine(_dataRoot, "original-backup.img");
        File.WriteAllText(backup, "keep original backup");
        var session = new InstallerWorkSession(selected.RootPath);
        File.WriteAllText(Path.Combine(session.DirectoryPath, "generated.img"), "temporary");
        File.WriteAllText(Path.Combine(session.DirectoryPath, "installer.log"), "operation record");
        session.Complete(false);
        Assert.False(Directory.Exists(session.DirectoryPath));
        Assert.Equal("keep original backup", File.ReadAllText(backup));
        Assert.Single(Directory.GetFiles(Path.Combine(selected.RootPath, "records"), "installer.log", SearchOption.AllDirectories));
        Assert.False(Directory.Exists(Path.Combine(_localAppData, "ArmadaOS Freedom", "Work")));
    }
}
