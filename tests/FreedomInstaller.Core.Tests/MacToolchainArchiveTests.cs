using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Loads a real macOS EDL toolchain archive (built with package_edl.py --platform macos-arm64). Skipped unless
/// EDL_TOOLCHAIN_MACOS_TEST_BUNDLE_PATH names one; the client is only started on a macOS host.
/// </summary>
public sealed class MacToolchainArchiveTests
{
    [Fact]
    public async Task Real_macos_archive_stages_an_executable_client_without_python()
    {
        string? bundle = Environment.GetEnvironmentVariable("EDL_TOOLCHAIN_MACOS_TEST_BUNDLE_PATH");
        string? artifacts = Environment.GetEnvironmentVariable("TEST_ARTIFACT_ROOT");
        if (string.IsNullOrWhiteSpace(bundle) || string.IsNullOrWhiteSpace(artifacts))
        {
            return;
        }

        string workRoot = Path.Combine(artifacts, "mac-toolchain-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(workRoot);

        await using FileStream archive = File.OpenRead(bundle);
        using EdlToolchain tools = await EdlToolchain.LoadAsync(archive, workRoot);

        Assert.EndsWith(Path.Combine("tools", "edl-ng"), tools.ClientPath, StringComparison.Ordinal);
        Assert.EndsWith(Path.Combine("tools", "libusb-1.0.dylib"), tools.UsbLibraryPath, StringComparison.Ordinal);
        Assert.Equal(string.Empty, tools.PythonPath);
        Assert.True(File.Exists(tools.FirehosePath));

        if (OperatingSystem.IsMacOS())
        {
            Assert.True(File.GetUnixFileMode(tools.ClientPath).HasFlag(UnixFileMode.UserExecute));
            using Process process = Process.Start(new ProcessStartInfo(tools.ClientPath, "--help")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
            })!;
            string output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();
            Assert.Equal(0, process.ExitCode);
            Assert.Contains("edl-ng", output, StringComparison.Ordinal);
        }
    }
}
