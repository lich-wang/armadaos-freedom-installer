using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;

namespace FreedomInstaller.Core;

/// <summary>
/// Windows implementation of <see cref="IEdlEndpointDiscovery"/>. It enumerates the present USB devices
/// once through SetupAPI and reads, for each exact <c>VID_05C6/PID_9008</c> instance, the bus-reported
/// device description and the optional port name.
/// <para>
/// The whole type is read-only: it never opens a device, never opens a COM port and never starts a
/// process. <see cref="FilterCandidates"/> is pure and platform-neutral so it is testable off Windows.
/// </para>
/// </summary>
public sealed class WindowsEdlEndpointDiscovery : IEdlEndpointDiscovery
{
    private const string UsbPrefix = "USB\\";
    private const string EnumRootPath = @"SYSTEM\CurrentControlSet\Enum\";
    private const string DeviceParametersKey = "Device Parameters";
    private const string PortNameValue = "PortName";

    private const string TargetVid = "05C6";
    private const string TargetPid = "9008";

    private const uint DigcfPresent = 0x00000002;
    private const uint DigcfAllClasses = 0x00000004;

    private const uint DevPropTypeString = 0x00000012;

    private const int ErrorNoMoreItems = 259;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorNotFound = 1168;

    private static readonly IntPtr InvalidHandleValue = new IntPtr(-1);

    /// <summary>
    /// DEVPKEY_Device_BusReportedDeviceDesc: the string the device itself reported over the bus, which is
    /// the only place the EDL serial appears. Taken from the Windows SDK devpkey.h (Pid 4).
    /// </summary>
    private static readonly DevPropKey BusReportedDeviceDescriptionKey = new DevPropKey
    {
        FmtId = new Guid("540b947e-8b40-45bc-a8a2-6a0b894cbda2"),
        Pid = 4,
    };

    [StructLayout(LayoutKind.Sequential)]
    private struct SpDevInfoData
    {
        public uint CbSize;
        public Guid ClassGuid;
        public uint DevInst;
        public IntPtr Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DevPropKey
    {
        public Guid FmtId;
        public uint Pid;
    }

    [DllImport("setupapi.dll", EntryPoint = "SetupDiGetClassDevsW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr SetupDiGetClassDevs(
        IntPtr classGuid,
        string? enumerator,
        IntPtr hwndParent,
        uint flags);

    [DllImport("setupapi.dll", EntryPoint = "SetupDiEnumDeviceInfo", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiEnumDeviceInfo(
        IntPtr deviceInfoSet,
        uint memberIndex,
        ref SpDevInfoData deviceInfoData);

    [DllImport("setupapi.dll", EntryPoint = "SetupDiGetDeviceInstanceIdW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiGetDeviceInstanceId(
        IntPtr deviceInfoSet,
        ref SpDevInfoData deviceInfoData,
        StringBuilder? deviceInstanceId,
        uint deviceInstanceIdSize,
        out uint requiredSize);

    [DllImport("setupapi.dll", EntryPoint = "SetupDiGetDevicePropertyW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiGetDeviceProperty(
        IntPtr deviceInfoSet,
        ref SpDevInfoData deviceInfoData,
        ref DevPropKey propertyKey,
        out uint propertyType,
        [Out] byte[]? propertyBuffer,
        uint propertyBufferSize,
        out uint requiredSize,
        uint flags);

    [DllImport("setupapi.dll", EntryPoint = "SetupDiDestroyDeviceInfoList", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

    /// <summary>
    /// Enumerates the EDL endpoints Windows currently reports. Non-Windows platforms are rejected with
    /// <see cref="PlatformNotSupportedException"/> before any platform-specific call is reached.
    /// </summary>
    public IReadOnlyList<EdlEndpoint> ReadPresent()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Present EDL endpoint enumeration uses Windows SetupAPI and is only available on Windows.");
        }

        return ReadWindowsPresent();
    }

    /// <summary>
    /// Keeps only endpoints whose USB instance identifier names exactly VID_05C6 and PID_9008. Duplicates
    /// and their order are retained, and nothing about the bus serial is interpreted here: identity and
    /// serial conflict checks belong to <see cref="EdlEntry"/>, which must see every duplicate.
    /// </summary>
    public static IReadOnlyList<EdlEndpoint> FilterCandidates(IEnumerable<EdlEndpoint> presentEndpoints)
    {
        if (presentEndpoints is null)
        {
            throw new ArgumentNullException(nameof(presentEndpoints));
        }

        var matched = new List<EdlEndpoint>();

        foreach (EdlEndpoint? endpoint in presentEndpoints)
        {
            if (endpoint is null)
            {
                continue;
            }

            if (!TryMatchTargetInstanceId(endpoint.DeviceInstanceId))
            {
                continue;
            }

            matched.Add(endpoint);
        }

        return matched.ToArray();
    }

    /// <summary>
    /// One SetupAPI pass over the present USB devices of all classes, so both the Qualcomm COM port and a
    /// WinUSB-bound 9008 instance are seen. The handle is owned and destroyed here; a missing property or
    /// an unreadable port name only leaves that field empty.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<EdlEndpoint> ReadWindowsPresent()
    {
        var found = new List<EdlEndpoint>();

        IntPtr deviceInfoSet = SetupDiGetClassDevs(
            IntPtr.Zero,
            "USB",
            IntPtr.Zero,
            DigcfPresent | DigcfAllClasses);

        if (deviceInfoSet == InvalidHandleValue || deviceInfoSet == IntPtr.Zero)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "SetupDiGetClassDevsW failed for present USB devices.");
        }

        try
        {
            uint index = 0;

            while (true)
            {
                var deviceInfo = new SpDevInfoData
                {
                    CbSize = (uint)Marshal.SizeOf<SpDevInfoData>(),
                };

                if (!SetupDiEnumDeviceInfo(deviceInfoSet, index, ref deviceInfo))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == ErrorNoMoreItems)
                    {
                        break;
                    }

                    throw new Win32Exception(
                        error,
                        "SetupDiEnumDeviceInfo failed for a present USB device.");
                }

                index++;

                string instanceId = ReadDeviceInstanceId(deviceInfoSet, ref deviceInfo);

                // Only the exact 9008 gadget is queried further; no other class or stale tree is touched.
                if (!TryMatchTargetInstanceId(instanceId))
                {
                    continue;
                }

                string? description = ReadBusReportedDescription(deviceInfoSet, ref deviceInfo);
                string? portName = ReadPortName(instanceId);

                found.Add(new EdlEndpoint(instanceId, portName, description));
            }
        }
        finally
        {
            SetupDiDestroyDeviceInfoList(deviceInfoSet);
        }

        return FilterCandidates(found);
    }

    /// <summary>
    /// Reads the bus-reported description through the device property API. A missing property yields a null
    /// description candidate instead of dropping the endpoint; any other OS failure surfaces, and a value
    /// that is not a string is refused rather than replaced by a different property such as FriendlyName.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static string? ReadBusReportedDescription(IntPtr deviceInfoSet, ref SpDevInfoData deviceInfo)
    {
        DevPropKey key = BusReportedDeviceDescriptionKey;

        bool sized = SetupDiGetDeviceProperty(
            deviceInfoSet,
            ref deviceInfo,
            ref key,
            out _,
            null,
            0,
            out uint requiredSize,
            0);

        if (!sized)
        {
            int error = Marshal.GetLastWin32Error();

            // The property is simply absent on this device: the endpoint is kept without a description.
            if (error == ErrorNotFound)
            {
                return null;
            }

            // A sizing call is expected to fail with ERROR_INSUFFICIENT_BUFFER; anything else is an OS error.
            if (error != ErrorInsufficientBuffer)
            {
                throw new Win32Exception(
                    error,
                    "SetupDiGetDevicePropertyW failed while sizing the bus-reported device description.");
            }
        }

        if (requiredSize == 0)
        {
            return null;
        }

        int size = checked((int)requiredSize);
        var buffer = new byte[size];

        if (!SetupDiGetDeviceProperty(
                deviceInfoSet,
                ref deviceInfo,
                ref key,
                out uint propertyType,
                buffer,
                (uint)buffer.Length,
                out uint actualSize,
                0))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "SetupDiGetDevicePropertyW failed while reading the bus-reported device description.");
        }

        if (propertyType != DevPropTypeString)
        {
            throw new InvalidOperationException(
                $"Bus-reported device description has property type {propertyType}, expected a string.");
        }

        // Only the bytes the API actually wrote are decoded, and only trailing NUL padding is removed.
        int bytes = (int)Math.Min(actualSize, (uint)buffer.Length);
        string description = Encoding.Unicode.GetString(buffer, 0, bytes);

        return description.TrimEnd('\0');
    }

    /// <summary>
    /// Reads the optional COM port name from the device instance's <c>Device Parameters</c> key. The key is
    /// opened read-only and disposed; absent, empty, non-string or inaccessible values leave the port null,
    /// because the bus serial - not the port - is the mandatory proof.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static string? ReadPortName(string instanceId)
    {
        try
        {
            using RegistryKey? parameters = Registry.LocalMachine.OpenSubKey(
                EnumRootPath + instanceId + @"\" + DeviceParametersKey,
                writable: false);

            if (parameters?.GetValue(PortNameValue) is string portName && portName.Length > 0)
            {
                return portName;
            }
        }
        catch (UnauthorizedAccessException)
        {
            // Not readable: the port stays unknown instead of being guessed or opened.
        }
        catch (System.Security.SecurityException)
        {
            // Same as an access denial.
        }

        return null;
    }

    [SupportedOSPlatform("windows")]
    private static string ReadDeviceInstanceId(IntPtr deviceInfoSet, ref SpDevInfoData deviceInfo)
    {
        SetupDiGetDeviceInstanceId(deviceInfoSet, ref deviceInfo, null, 0, out uint requiredSize);

        if (requiredSize == 0)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "SetupDiGetDeviceInstanceIdW did not report a required buffer size.");
        }

        var buffer = new StringBuilder((int)requiredSize);
        if (!SetupDiGetDeviceInstanceId(deviceInfoSet, ref deviceInfo, buffer, requiredSize, out _))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "SetupDiGetDeviceInstanceIdW failed for a present USB device.");
        }

        return buffer.ToString();
    }

    /// <summary>
    /// Exact instance-id match: the <c>USB\</c> prefix, a hardware-id segment whose VID/PID tokens are
    /// exactly 05C6/9008, and one non-empty instance segment. Substrings such as VID_105C6, PID_90080 or
    /// PID_900E and other buses such as PCI never match.
    /// </summary>
    private static bool TryMatchTargetInstanceId(string? instanceId)
    {
        if (string.IsNullOrEmpty(instanceId)
            || !instanceId.StartsWith(UsbPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        int separator = instanceId.IndexOf('\\', UsbPrefix.Length);
        if (separator < 0)
        {
            return false;
        }

        string hardwareId = instanceId.Substring(UsbPrefix.Length, separator - UsbPrefix.Length);
        string instance = instanceId.Substring(separator + 1);

        if (instance.Length == 0 || instance.IndexOf('\\') >= 0)
        {
            return false;
        }

        return IsTargetHardwareId(hardwareId);
    }

    private static bool IsTargetHardwareId(string? hardwareId)
    {
        if (string.IsNullOrEmpty(hardwareId))
        {
            return false;
        }

        bool hasVid = false;
        bool hasPid = false;

        foreach (string token in hardwareId.Split('&'))
        {
            if (token.Length == 0)
            {
                return false;
            }

            int underscore = token.IndexOf('_');
            if (underscore <= 0 || underscore == token.Length - 1)
            {
                return false;
            }

            string name = token.Substring(0, underscore);
            string value = token.Substring(underscore + 1);

            if (name.Equals("VID", StringComparison.OrdinalIgnoreCase))
            {
                if (hasVid || !value.Equals(TargetVid, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                hasVid = true;
            }
            else if (name.Equals("PID", StringComparison.OrdinalIgnoreCase))
            {
                if (hasPid || !value.Equals(TargetPid, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                hasPid = true;
            }
        }

        return hasVid && hasPid;
    }
}
