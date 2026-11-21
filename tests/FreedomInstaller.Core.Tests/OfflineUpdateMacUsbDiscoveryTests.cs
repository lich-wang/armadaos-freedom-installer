using System.Net;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class OfflineUpdateMacUsbDiscoveryTests
{
    // Shape of `ioreg -r -c IOUSBHostDevice -l -w0` on macOS 14/15 (Apple silicon) with the tablet's Linux
    // network gadget attached: the interface sits several levels below the USB device, under the CDC/NCM driver.
    private const string Fixture = """
+-o USB 10/100/1000 LAN@00100000  <class IOUSBHostDevice, id 0x100000a01, registered, matched, active, busy 0 (10 ms), retain 30>
  | {
  |   "idProduct" = 33107
  |   "idVendor" = 3034
  |   "locationID" = 1048576
  | }
  |
  +-o AppleUSBECMData  <class AppleUSBECMData, id 0x100000a05, registered, matched, active, busy 0 (1 ms), retain 7>
    | {
    | }
    |
    +-o en7  <class IOEthernetInterface, id 0x100000a07, registered, matched, active, busy 0 (1 ms), retain 11>
        {
          "BSD Name" = "en7"
        }

+-o Armada USB network@02200000  <class IOUSBHostDevice, id 0x1000816fb, registered, matched, active, busy 0 (125 ms), retain 36>
  | {
  |   "idProduct" = 260
  |   "USB Product Name" = "Armada USB network"
  |   "idVendor" = 7531
  |   "locationID" = 35651584
  | }
  |
  +-o AppleUSBCDCCompositeDevice  <class AppleUSBCDCCompositeDevice, id 0x1000816fd, !registered, !matched, active, busy 0, retain 4>
  +-o CDC Network Control Model (NCM)@0  <class IOUSBHostInterface, id 0x100081700, registered, matched, active, busy 0 (85 ms), retain 10>
  | | {
  | |   "idProduct" = 260
  | |   "idVendor" = 7531
  | | }
  | |
  | +-o AppleUSBNCMControl  <class AppleUSBNCMControl, id 0x100081709, registered, matched, active, busy 0 (13 ms), retain 8>
  |   +-o AppleUSBNCMData  <class AppleUSBNCMData, id 0x10008170a, registered, matched, active, busy 0 (12 ms), retain 7>
  |     | {
  |     |   "idVendor" = 7531
  |     |   "idProduct" = 260
  |     | }
  |     |
  |     +-o en13  <class IOEthernetInterface, id 0x10008170c, registered, matched, active, busy 0 (12 ms), retain 11>
  |       | {
  |       |   "BSD Name" = "en13"
  |       | }
  |       |
  |       +-o IONetworkStack  <class IONetworkStack, id 0x10008170e, registered, matched, active, busy 0 (0 ms), retain 6>
  +-o CDC Network Data@1  <class IOUSBHostInterface, id 0x100081701, registered, matched, active, busy 0 (0 ms), retain 6>
      {
        "idVendor" = 7531
      }

+-o USB2.0 Hub@01100000  <class IOUSBHostDevice, id 0x100000b01, registered, matched, active, busy 0 (5 ms), retain 20>
  | {
  |   "idProduct" = 2337
  |   "idVendor" = 8457
  | }
  |
  +-o Other gadget@01110000  <class IOUSBHostDevice, id 0x100000b11, registered, matched, active, busy 0 (5 ms), retain 20>
  | | {
  | |   "idProduct" = 256
  | |   "idVendor" = 7531
  | |   "locationID" = 17891328
  | | }
  | |
  | +-o en15  <class IOEthernetInterface, id 0x100000b15, registered, matched, active, busy 0 (5 ms), retain 6>
  |     {
  |       "BSD Name" = "en15"
  |     }
  |
  +-o Wrong vendor@01120000  <class IOUSBHostDevice, id 0x100000b21, registered, matched, active, busy 0 (5 ms), retain 20>
      {
        "idProduct" = 260
        "idVendor" = 7532
      }

""";

    private static (string, bool, IReadOnlyList<(IPAddress, IPAddress)>) Nic(string name, bool up, params string[] addresses) =>
        (name, up, addresses.Select(a => (IPAddress.Parse(a), IPAddress.Parse("255.255.255.0"))).ToList());

    [Fact]
    public void ParseGadgets_FindsGadgetsAndTheirNestedInterfaces()
    {
        var gadgets = OfflineUpdateMacUsbDiscovery.ParseGadgets(Fixture);

        Assert.Equal(2, gadgets.Count);
        Assert.Equal(0x0104, gadgets[0].ProductId);
        Assert.Equal("35651584", gadgets[0].LocationId);
        Assert.Equal(new[] { "en13" }, gadgets[0].Interfaces);
        // A gadget behind a hub is found; a non-gadget USB Ethernet adapter and a wrong vendor are not.
        Assert.Equal(0x0100, gadgets[1].ProductId);
        Assert.Equal(new[] { "en15" }, gadgets[1].Interfaces);
    }

    [Fact]
    public void MatchEndpoints_RequiresUpInterfaceAndUsbSubnetAddress()
    {
        var gadgets = OfflineUpdateMacUsbDiscovery.ParseGadgets(Fixture);
        var endpoints = OfflineUpdateMacUsbDiscovery.MatchEndpoints(gadgets, new[]
        {
            Nic("en13", true, "172.16.42.20"),
            Nic("en15", false, "172.16.42.30"),
            Nic("en7", true, "172.16.42.40"),
        });

        var endpoint = Assert.Single(endpoints);
        Assert.Equal("en13", endpoint.AdapterId);
        Assert.Equal(@"USB\VID_1D6B&PID_0104\35651584", endpoint.DeviceInstanceId);
        Assert.Equal(OfflineUpdateUsbDiscovery.DeviceHost, endpoint.Host);
        Assert.Equal("172.16.42.20", endpoint.LocalAddress);
    }

    [Theory]
    [InlineData("172.16.42.1")]
    [InlineData("172.16.42.255")]
    [InlineData("172.16.43.20")]
    [InlineData("10.0.0.2")]
    public void MatchEndpoints_RejectsAddressesOutsideTheGadgetSubnet(string address)
    {
        var gadgets = OfflineUpdateMacUsbDiscovery.ParseGadgets(Fixture);
        Assert.Empty(OfflineUpdateMacUsbDiscovery.MatchEndpoints(gadgets, new[] { Nic("en13", true, address) }));
    }

    [Fact]
    public void MatchEndpoints_RejectsAWrongMask()
    {
        var gadgets = OfflineUpdateMacUsbDiscovery.ParseGadgets(Fixture);
        var nic = ("en13", true,
            (IReadOnlyList<(IPAddress, IPAddress)>)new[] { (IPAddress.Parse("172.16.42.20"), IPAddress.Parse("255.255.0.0")) });
        Assert.Empty(OfflineUpdateMacUsbDiscovery.MatchEndpoints(gadgets, new[] { nic }));
    }

    [Fact]
    public void MatchEndpoints_ReportsEveryGadgetSoTheCallerCanRefuseSeveral()
    {
        var gadgets = OfflineUpdateMacUsbDiscovery.ParseGadgets(Fixture);
        var endpoints = OfflineUpdateMacUsbDiscovery.MatchEndpoints(gadgets, new[]
        {
            Nic("en13", true, "172.16.42.20"),
            Nic("en15", true, "172.16.42.30"),
        });

        Assert.Equal(2, endpoints.Count);
    }

    [Fact]
    public void ParseGadgets_EmptyOutputHasNoGadgets() =>
        Assert.Empty(OfflineUpdateMacUsbDiscovery.ParseGadgets(string.Empty));

    [Fact]
    public void BuildCommand_RunsIoregReadOnly()
    {
        var command = OfflineUpdateMacUsbDiscovery.BuildCommand();
        Assert.Equal("/usr/sbin/ioreg", command.Executable);
        Assert.Equal(new[] { "-r", "-c", "IOUSBHostDevice", "-l", "-w0" }, command.Arguments);
    }
}
