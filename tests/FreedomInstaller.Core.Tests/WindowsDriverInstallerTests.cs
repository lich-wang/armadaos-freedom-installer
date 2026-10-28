using System;
using System.ComponentModel;
using FreedomInstaller.App;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Pure behaviour tests for the exit-code and start-failure interpretation of the Windows driver
/// installer. The asynchronous install path itself is never invoked here: these tests never touch
/// a process, UAC, or a real driver, they only feed the pure classification helpers.
/// </summary>
public sealed class WindowsDriverInstallerTests
{
    [Theory]
    [InlineData(0, "Completed")]
    [InlineData(3010, "RebootRequired")]
    [InlineData(1, "Failed")]
    [InlineData(5, "Failed")]
    [InlineData(1641, "Failed")]
    [InlineData(-1, "Failed")]
    public void InterpretExitCode_ClassifiesExitCodeAndKeepsIt(int exitCode, string expectedOutcome)
    {
        var result = WindowsDriverInstaller.InterpretExitCode(exitCode);

        Assert.Equal(expectedOutcome, result.Outcome.ToString());
        Assert.Equal(exitCode, result.ExitCode);

        if (expectedOutcome == "Failed")
        {
            Assert.False(string.IsNullOrWhiteSpace(result.Error), "failed installs must describe the error");
        }
        else
        {
            Assert.Null(result.Error);
        }
    }

    [Theory]
    [InlineData(1223, "Cancelled")]
    [InlineData(5, "Failed")]
    public void InterpretStartFailure_ClassifiesWin32ErrorCode(int nativeErrorCode, string expectedOutcome)
    {
        var result = WindowsDriverInstaller.InterpretStartFailure(new Win32Exception(nativeErrorCode));

        Assert.Equal(expectedOutcome, result.Outcome.ToString());
        Assert.Null(result.ExitCode);

        if (expectedOutcome == "Cancelled")
        {
            Assert.Null(result.Error);
        }
        else
        {
            Assert.False(string.IsNullOrWhiteSpace(result.Error), "failed starts must describe the error");
        }
    }

    [Fact]
    public void InterpretStartFailure_TreatsOrdinaryExceptionAsFailure()
    {
        var result = WindowsDriverInstaller.InterpretStartFailure(
            new InvalidOperationException("cannot start the installer"));

        Assert.Equal(DriverInstallOutcome.Failed, result.Outcome);
        Assert.Null(result.ExitCode);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
    }

    [Fact]
    public void InterpretStartFailure_DoesNotTreatCancellationExceptionAsUserCancelled()
    {
        var result = WindowsDriverInstaller.InterpretStartFailure(
            new OperationCanceledException("cancelled before start"));

        Assert.Equal(DriverInstallOutcome.Failed, result.Outcome);
        Assert.Null(result.ExitCode);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
    }
}
