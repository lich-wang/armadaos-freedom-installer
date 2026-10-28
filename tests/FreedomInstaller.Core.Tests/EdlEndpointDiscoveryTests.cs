using System;
using System.Collections.Generic;
using System.Linq;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Static filter contract of <see cref="WindowsEdlEndpointDiscovery"/>. The tests never call
/// <see cref="WindowsEdlEndpointDiscovery.ReadPresent"/>, so no SetupAPI or PInvoke runs on Linux.
/// </summary>
public sealed class EdlEndpointDiscoveryTests
{
    private const string BusDescription = "QUSB_BULK_CID:045A_SN:C1D2E3F4";

    private static EdlEndpoint Endpoint(string instanceId, string? portName, string busDescription)
        => new(instanceId, portName, busDescription);

    [Fact]
    public void FilterCandidates_keeps_only_exact_usb_vid_pid_and_preserves_nullable_port_and_duplicates()
    {
        var acceptedWithPort = Endpoint(
            @"USB\VID_05C6&PID_9008\5&AAAA&0&1",
            "COM9",
            BusDescription);
        var acceptedNullPort = Endpoint(
            @"usb\vid_05c6&pid_9008\5&BBBB&0&1",
            null,
            BusDescription);

        var pid900E = Endpoint(
            @"USB\VID_05C6&PID_900E\5&CCCC&0&1",
            "COM3",
            BusDescription);
        var misleadingVid = Endpoint(
            @"USB\VID_105C6&PID_9008\5&DDDD&0&1",
            "COM4",
            BusDescription);
        var pidSuffix = Endpoint(
            @"USB\VID_05C6&PID_90080\5&EEEE&0&1",
            "COM5",
            BusDescription);
        var otherBus = Endpoint(
            @"PCI\VID_05C6&PID_9008\5&FFFF&0&1",
            "COM6",
            BusDescription);

        var input = new[]
        {
            acceptedWithPort,
            pid900E,
            misleadingVid,
            pidSuffix,
            otherBus,
            acceptedNullPort,
            acceptedWithPort,
        };

        var filtered = WindowsEdlEndpointDiscovery.FilterCandidates(input);

        Assert.Equal(3, filtered.Count);
        Assert.Equal(2, filtered.Count(endpoint => endpoint == acceptedWithPort));
        Assert.Contains(acceptedNullPort, filtered);
        Assert.DoesNotContain(pid900E, filtered);
        Assert.DoesNotContain(misleadingVid, filtered);
        Assert.DoesNotContain(pidSuffix, filtered);
        Assert.DoesNotContain(otherBus, filtered);
        Assert.Contains(filtered, endpoint => endpoint.PortName is null);
    }
}
