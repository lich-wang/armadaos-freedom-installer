using System.Linq;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>Pure parsing tests for the macOS IOKit endpoint discovery; no ioreg process is started.</summary>
public sealed class MacEdlEndpointDiscoveryTests
{
    private static string Plist(string body) =>
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
        "<plist version=\"1.0\"><array>" + body + "</array></plist>";

    private static string Device(int vid, int pid, long? location, string? product, string children = "") =>
        "<dict>" +
        $"<key>idVendor</key><integer>{vid}</integer>" +
        $"<key>idProduct</key><integer>{pid}</integer>" +
        (location is null ? string.Empty : $"<key>locationID</key><integer>{location}</integer>") +
        (product is null ? string.Empty : $"<key>USB Product Name</key><string>{product}</string>") +
        "<key>IOCFPlugInTypes</key><dict><key>x</key><string>y</string></dict>" +
        (children.Length == 0 ? string.Empty : "<key>IORegistryEntryChildren</key><array>" + children + "</array>") +
        "</dict>";

    [Fact]
    public void Reports_a_9008_device_with_its_location_and_product_string()
    {
        var endpoints = MacEdlEndpointDiscovery.Parse(Plist(
            Device(0x05AC, 0x8104, 0x01000000, "Hub",
                Device(0x05C6, 0x9008, 0x01100000, "QUSB__BULK_CID:0402_SN:650FA815"))));

        EdlEndpoint endpoint = Assert.Single(endpoints);
        Assert.Equal(@"USB\VID_05C6&PID_9008\LOC_01100000", endpoint.DeviceInstanceId);
        Assert.Null(endpoint.PortName);
        Assert.Equal("QUSB__BULK_CID:0402_SN:650FA815", endpoint.BusReportedDeviceDescription);
    }

    [Fact]
    public void Ignores_other_devices_and_a_9008_without_location()
    {
        var endpoints = MacEdlEndpointDiscovery.Parse(Plist(
            Device(0x05C6, 0x9091, 0x01200000, "Android") +
            Device(0x18D1, 0x9008, 0x01300000, "Other vendor") +
            Device(0x05C6, 0x9008, null, "QUSB__BULK_CID:0402_SN:650FA815")));

        Assert.Empty(endpoints);
    }

    [Fact]
    public void Two_devices_stay_two_instances_and_a_missing_product_is_null()
    {
        var endpoints = MacEdlEndpointDiscovery.Parse(Plist(
            Device(0x05C6, 0x9008, 0x01100000, "QUSB__BULK_CID:0402_SN:11111111") +
            Device(0x05C6, 0x9008, 0x02100000, null)));

        Assert.Equal(2, endpoints.Select(e => e.DeviceInstanceId).Distinct().Count());
        Assert.Null(endpoints[1].BusReportedDeviceDescription);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Empty_output_has_no_endpoints(string output)
    {
        Assert.Empty(MacEdlEndpointDiscovery.Parse(output));
    }
}
