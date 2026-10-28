using System.Linq;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class MaintenanceSerialDiscoveryTests
{
    private const string TargetInstance = @"USB\VID_1D6B&PID_0104&MI_00\6&2b8f1c4a&0&0000";

    private static MaintenanceSerialPort Port(string instanceId, string portName)
        => new(instanceId, portName);

    [Fact]
    public void FilterCandidates_keeps_target_device_and_preserves_instance_id()
    {
        var result = MaintenanceSerialDiscovery.FilterCandidates(new[]
        {
            Port(TargetInstance, "COM7"),
        });

        var single = Assert.Single(result);
        Assert.Equal(TargetInstance, single.DeviceInstanceId);
        Assert.Equal("COM7", single.PortName);
    }

    [Theory]
    [InlineData(@"USB\VID_1D6B&PID_0104&MI_00\6&2b8f1c4a&0&0000")]
    [InlineData(@"usb\vid_1d6b&pid_0104&mi_00\6&2b8f1c4a&0&0000")]
    [InlineData(@"USB\VID_1d6b&PID_0104&MI_00\6&2b8f1c4a&0&0000")]
    [InlineData(@"USB\VID_1D6B&PID_0104&REV_0600&MI_00\6&2b8f1c4a&0&0000")]
    public void FilterCandidates_matches_tokens_case_insensitively_and_allows_extra_tokens(string instanceId)
    {
        var result = MaintenanceSerialDiscovery.FilterCandidates(new[] { Port(instanceId, "COM4") });

        Assert.Equal(instanceId, Assert.Single(result).DeviceInstanceId);
    }

    [Theory]
    [InlineData(@"USB\VID_1D6C&PID_0104&MI_00\6&2b8f1c4a&0&0000")]
    [InlineData(@"USB\VID_1D6B&PID_0105&MI_00\6&2b8f1c4a&0&0000")]
    [InlineData(@"USB\VID_1D6B&PID_0104&MI_01\6&2b8f1c4a&0&0000")]
    [InlineData(@"USB\VID_1D6B&PID_0104\6&2b8f1c4a&0&0000")]
    public void FilterCandidates_rejects_wrong_vid_pid_or_interface(string instanceId)
    {
        Assert.Empty(MaintenanceSerialDiscovery.FilterCandidates(new[] { Port(instanceId, "COM5") }));
    }

    [Theory]
    [InlineData("")]
    [InlineData("COM")]
    [InlineData("COM0")]
    [InlineData("COM00")]
    [InlineData("COM05")]
    [InlineData("COM-1")]
    [InlineData("COM257")]
    [InlineData("COM1000")]
    [InlineData("ttyUSB0")]
    [InlineData(" COM7")]
    [InlineData("COM7 ")]
    public void FilterCandidates_rejects_invalid_port_names(string portName)
    {
        Assert.Empty(MaintenanceSerialDiscovery.FilterCandidates(new[] { Port(TargetInstance, portName) }));
    }

    [Theory]
    [InlineData("COM1")]
    [InlineData("COM9")]
    [InlineData("COM10")]
    [InlineData("COM256")]
    public void FilterCandidates_accepts_positive_port_names_up_to_256(string portName)
    {
        Assert.Single(MaintenanceSerialDiscovery.FilterCandidates(new[] { Port(TargetInstance, portName) }));
    }

    [Fact]
    public void FilterCandidates_deduplicates_same_device_and_port()
    {
        var result = MaintenanceSerialDiscovery.FilterCandidates(new[]
        {
            Port(TargetInstance, "COM7"),
            Port(TargetInstance, "COM7"),
        });

        Assert.Single(result);
    }

    [Fact]
    public void FilterCandidates_retains_distinct_devices_sharing_a_port()
    {
        const string otherInstance = @"USB\VID_1D6B&PID_0104&MI_00\7&9c8d7e6f&0&0000";

        var result = MaintenanceSerialDiscovery.FilterCandidates(new[]
        {
            Port(TargetInstance, "COM7"),
            Port(otherInstance, "COM7"),
        });

        Assert.Equal(2, result.Count);
        Assert.Equal(new[] { TargetInstance, otherInstance }, result.Select(port => port.DeviceInstanceId));
        Assert.All(result, port => Assert.Equal("COM7", port.PortName));
    }

    [Fact]
    public void FilterCandidates_sorts_by_com_number()
    {
        var result = MaintenanceSerialDiscovery.FilterCandidates(new[]
        {
            Port(@"USB\VID_1D6B&PID_0104&MI_00\6&aaa&0&0000", "COM10"),
            Port(@"USB\VID_1D6B&PID_0104&MI_00\6&bbb&0&0000", "COM2"),
            Port(@"USB\VID_1D6B&PID_0104&MI_00\6&ccc&0&0000", "COM1"),
            Port(@"USB\VID_1D6B&PID_0105&MI_00\6&ddd&0&0000", "COM3"),
        });

        Assert.Equal(new[] { "COM1", "COM2", "COM10" }, result.Select(port => port.PortName));
    }

    [Fact]
    public void FilterCandidates_returns_empty_for_empty_input()
    {
        Assert.Empty(MaintenanceSerialDiscovery.FilterCandidates(Enumerable.Empty<MaintenanceSerialPort>()));
    }
}
