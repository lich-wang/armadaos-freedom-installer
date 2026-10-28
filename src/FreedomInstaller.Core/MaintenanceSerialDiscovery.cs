using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;

namespace FreedomInstaller.Core;

/// <summary>A candidate maintenance serial port bound to its USB device instance.</summary>
public sealed record MaintenanceSerialPort(string DeviceInstanceId, string PortName);

/// <summary>
/// Selects the maintenance serial interface (VID_1D6B / PID_0104 / MI_00) from
/// enumerated USB instances. Never opens the COM port.
/// </summary>
public static class MaintenanceSerialDiscovery
{
    private const string UsbPrefix = "USB\\";
    private const string EnumRootPath = @"SYSTEM\CurrentControlSet\Enum\";
    private const string DeviceParametersKey = "Device Parameters";
    private const string PortNameValue = "PortName";

    private const string TargetVid = "1D6B";
    private const string TargetPid = "0104";
    private const string TargetMi = "00";

    private const uint DigcfPresent = 0x00000002;
    private const int ErrorNoMoreItems = 259;

    private static readonly Guid PortsClassGuid =
        new Guid("4d36e978-e325-11ce-bfc1-08002be10318");

    private static readonly IntPtr InvalidHandleValue = new IntPtr(-1);

    [StructLayout(LayoutKind.Sequential)]
    private struct SpDevInfoData
    {
        public uint CbSize;
        public Guid ClassGuid;
        public uint DevInst;
        public IntPtr Reserved;
    }

    [DllImport("setupapi.dll", EntryPoint = "SetupDiGetClassDevsW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr SetupDiGetClassDevs(
        ref Guid classGuid,
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

    [DllImport("setupapi.dll", EntryPoint = "SetupDiDestroyDeviceInfoList", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

    public static IReadOnlyList<MaintenanceSerialPort> FilterCandidates(
        IEnumerable<MaintenanceSerialPort> ports)
    {
        if (ports is null)
        {
            throw new ArgumentNullException(nameof(ports));
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var matched = new List<(int Number, MaintenanceSerialPort Port)>();

        foreach (MaintenanceSerialPort? port in ports)
        {
            if (port is null)
            {
                continue;
            }

            if (!TryParseTargetInstanceId(port.DeviceInstanceId))
            {
                continue;
            }

            if (!TryParsePortNumber(port.PortName, out int number))
            {
                continue;
            }

            string dedupKey = port.DeviceInstanceId + "\0" + port.PortName;
            if (!seen.Add(dedupKey))
            {
                continue;
            }

            matched.Add((number, port));
        }

        return matched
            .OrderBy(entry => entry.Number)
            .ThenBy(entry => entry.Port.DeviceInstanceId, StringComparer.Ordinal)
            .Select(entry => entry.Port)
            .ToArray();
    }

    [SupportedOSPlatform("windows")]
    public static IReadOnlyList<MaintenanceSerialPort> ReadWindows()
    {
        var found = new List<MaintenanceSerialPort>();

        Guid portsClass = PortsClassGuid;
        IntPtr deviceInfoSet = SetupDiGetClassDevs(
            ref portsClass,
            "USB",
            IntPtr.Zero,
            DigcfPresent);

        if (deviceInfoSet == InvalidHandleValue)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "SetupDiGetClassDevsW failed for present USB port devices.");
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
                        "SetupDiEnumDeviceInfo failed for a present USB port device.");
                }

                index++;

                string instanceId = ReadDeviceInstanceId(deviceInfoSet, ref deviceInfo);
                if (!TryParseTargetInstanceId(instanceId))
                {
                    continue;
                }

                using RegistryKey? parameters = Registry.LocalMachine.OpenSubKey(
                    EnumRootPath + instanceId + @"\" + DeviceParametersKey,
                    writable: false);

                if (parameters?.GetValue(PortNameValue) is string portName)
                {
                    found.Add(new MaintenanceSerialPort(instanceId, portName));
                }
            }
        }
        finally
        {
            SetupDiDestroyDeviceInfoList(deviceInfoSet);
        }

        return FilterCandidates(found);
    }

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
                "SetupDiGetDeviceInstanceIdW failed for a present USB port device.");
        }

        return buffer.ToString();
    }

    private static bool TryParseTargetInstanceId(string? instanceId)
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
        bool hasMi = false;

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
            else if (name.Equals("MI", StringComparison.OrdinalIgnoreCase))
            {
                if (hasMi || !value.Equals(TargetMi, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                hasMi = true;
            }
        }

        return hasVid && hasPid && hasMi;
    }

    private static bool TryParsePortNumber(string? portName, out int number)
    {
        number = 0;

        if (string.IsNullOrEmpty(portName)
            || portName.Length < 4
            || portName.Length > 6
            || !portName.StartsWith("COM", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string digits = portName.Substring(3);
        if (digits.Length == 0 || digits.Length > 3)
        {
            return false;
        }

        foreach (char character in digits)
        {
            if (character < '0' || character > '9')
            {
                return false;
            }
        }

        if (digits.Length > 1 && digits[0] == '0')
        {
            return false;
        }

        number = int.Parse(digits, System.Globalization.CultureInfo.InvariantCulture);
        return number is >= 1 and <= 256;
    }
}
