using System;
using System.IO;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Behaviour tests for the additive per-command working directory, run against the real <c>/bin/pwd</c>.
/// <para>
/// The child directory deliberately carries spaces and non-ASCII characters so a shell-joined path would
/// be observable. These tests start only <c>/bin/pwd</c>, never a device tool, and are restricted to the
/// remote Linux container (Linux Docker); they fail loudly elsewhere instead of skipping.
/// </para>
/// </summary>
public sealed class ProcessWorkingDirectoryTests
{
    private const string PwdBinary = "/bin/pwd";

    private static readonly TimeSpan GenerousTimeout = TimeSpan.FromSeconds(10);

    public ProcessWorkingDirectoryTests()
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new InvalidOperationException(
                "ProcessWorkingDirectoryTests run /bin/pwd and are only allowed inside the Linux test "
                + "container (Linux Docker), never on the Windows host.");
        }
    }

    [Fact]
    public async Task RunAsync_WithWorkingDirectory_RunsInThatExactDirectory_AndLeavesTheGlobalOneUnchanged()
    {
        var root = Path.Combine(
            TestArtifactRoot.Resolve(), "bt001-cwd-中文 空格-" + Guid.NewGuid().ToString("N"));
        var child = Path.Combine(root, "child 中文 dir");

        var globalBefore = Environment.CurrentDirectory;
        Directory.CreateDirectory(child);
        try
        {
            var result = await new ProcessRunner().RunAsync(Pwd(child));

            Assert.Equal(0, result.ExitCode);
            Assert.Equal(Path.GetFullPath(child), result.StandardOutput.Trim());
            Assert.Equal(globalBefore, Environment.CurrentDirectory);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public async Task RunAsync_DefaultAndEmptyWorkingDirectory_BothKeepTheInheritedDirectory()
    {
        var globalBefore = Environment.CurrentDirectory;

        var inherited = await new ProcessRunner().RunAsync(Pwd(null));
        var empty = await new ProcessRunner().RunAsync(Pwd(string.Empty));

        Assert.Equal(0, inherited.ExitCode);
        Assert.Equal(globalBefore, inherited.StandardOutput.Trim());
        Assert.Equal(0, empty.ExitCode);
        Assert.Equal(globalBefore, empty.StandardOutput.Trim());
        Assert.Equal(globalBefore, Environment.CurrentDirectory);
    }

    private static ProcessCommand Pwd(string? workingDirectory) =>
        new(PwdBinary, Array.Empty<string>(), GenerousTimeout) { WorkingDirectory = workingDirectory };
}
