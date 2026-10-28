using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

#pragma warning disable CA1416 // Intentional no-hardware contract tests: the Windows annotation is asserted via reflection and no serial port is ever opened.

namespace FreedomInstaller.Core.Tests;

public sealed class ConsoleTestWindowsMaintenanceConsoleContract
{
    private static readonly TimeSpan ConsoleTestTimeout = TimeSpan.FromSeconds(5);

    private static WindowsMaintenanceConsole ConsoleTestCreate(string? portName) =>
        new(portName!);

    [Fact]
    public void ConsoleTestDeclaresWindowsSupportedPlatform()
    {
        IReadOnlyList<string> platforms = typeof(WindowsMaintenanceConsole)
            .GetCustomAttributes<SupportedOSPlatformAttribute>(inherit: false)
            .Select(attribute => attribute.PlatformName)
            .ToList();

        Assert.Contains("windows", platforms, StringComparer.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("com11", "COM11")]
    [InlineData("COM11", "COM11")]
    [InlineData("Com11", "COM11")]
    [InlineData("COM1", "COM1")]
    [InlineData("COM123", "COM123")]
    public void ConsoleTestConstructorCanonicalizesPortNameWithoutOpeningPort(string input, string expectedPortName)
    {
        WindowsMaintenanceConsole console = ConsoleTestCreate(input);

        Assert.Equal(expectedPortName, console.PortName);
        Assert.False(console.IsOpen);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("COM0")]
    [InlineData("LPT1")]
    [InlineData(@"C:\temp\COM1")]
    [InlineData(@"\\.\COM1")]
    [InlineData("COM11\n")]
    [InlineData("COM11\r\n")]
    [InlineData(" COM11")]
    [InlineData("COM11 ")]
    [InlineData("COM\t11")]
    [InlineData("COM１１")]
    public void ConsoleTestConstructorRejectsInvalidPortName(string? portName)
    {
        Assert.ThrowsAny<ArgumentException>(() => ConsoleTestCreate(portName));
    }

    [Fact]
    public async Task ConsoleTestOpenAsyncHonorsPreCanceledToken()
    {
        WindowsMaintenanceConsole console = ConsoleTestCreate("COM11");
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => console.OpenAsync(cancellation.Token));

        Assert.False(console.IsOpen);
    }

    [Fact]
    public async Task ConsoleTestRunCommandAsyncRequiresOpenConsole()
    {
        WindowsMaintenanceConsole console = ConsoleTestCreate("COM11");

        await Assert.ThrowsAnyAsync<InvalidOperationException>(
            () => console.RunCommandAsync("hello", "ready", ConsoleTestTimeout));

        Assert.False(console.IsOpen);
    }

    [Fact]
    public async Task ConsoleTestDisposeAsyncBeforeOpenSucceedsTwice()
    {
        WindowsMaintenanceConsole console = ConsoleTestCreate("COM11");

        await console.DisposeAsync();
        Assert.False(console.IsOpen);

        await console.DisposeAsync();
        Assert.False(console.IsOpen);
        Assert.Equal("COM11", console.PortName);
    }

    [Fact]
    public async Task ConsoleTestOpenAsyncAfterDisposeThrowsObjectDisposed()
    {
        WindowsMaintenanceConsole console = ConsoleTestCreate("COM11");
        await console.DisposeAsync();

        await Assert.ThrowsAnyAsync<ObjectDisposedException>(() => console.OpenAsync());

        Assert.False(console.IsOpen);
    }

    [Fact]
    public async Task ConsoleTestRunCommandAsyncAfterDisposeThrowsObjectDisposed()
    {
        WindowsMaintenanceConsole console = ConsoleTestCreate("COM11");
        await console.DisposeAsync();

        await Assert.ThrowsAnyAsync<ObjectDisposedException>(
            () => console.RunCommandAsync("hello", "ready", ConsoleTestTimeout));

        Assert.False(console.IsOpen);
    }
}

#pragma warning restore CA1416
