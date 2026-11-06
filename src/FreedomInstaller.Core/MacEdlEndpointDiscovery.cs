using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.Versioning;
using System.Threading;
using System.Xml;

namespace FreedomInstaller.Core;

/// <summary>
/// macOS counterpart of <see cref="WindowsEdlEndpointDiscovery"/>: lists the present Qualcomm 9008 USB devices
/// from the IOKit registry (<c>ioreg</c>). It only enumerates; it never opens a device or sends a command.
/// <para>
/// Each device becomes one <see cref="EdlEndpoint"/>: the instance id is
/// <c>USB\VID_05C6&amp;PID_9008\LOC_xxxxxxxx</c> (the IOKit <c>locationID</c>, which stays the same while the
/// device stays on the same port) and the bus-reported description is the device's own USB product string,
/// for example <c>QUSB__BULK_CID:0402_SN:650FA815</c>, which carries the serial that callers check.
/// </para>
/// </summary>
public sealed class MacEdlEndpointDiscovery : IEdlEndpointDiscovery
{
    private const int QualcommVid = 0x05C6;
    private const int EdlPid = 0x9008;
    private const string IoregPath = "/usr/sbin/ioreg";
    private static readonly TimeSpan IoregTimeout = TimeSpan.FromSeconds(10);

    // ioreg can exit non-zero while a USB device is detaching or re-enumerating (the tablet rebooting into
    // 9008 is exactly that moment), so a failed read is retried a few times before it is reported.
    private const int IoregAttempts = 5;
    private static readonly TimeSpan IoregRetryDelay = TimeSpan.FromMilliseconds(500);

    [SupportedOSPlatform("macos")]
    public IReadOnlyList<EdlEndpoint> ReadPresent()
    {
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException("IOKit endpoint discovery is only available on macOS.");
        }

        for (int attempt = 1; ; attempt++)
        {
            try
            {
                return Parse(RunIoreg());
            }
            catch (InvalidOperationException) when (attempt < IoregAttempts)
            {
                Thread.Sleep(IoregRetryDelay);
            }
        }
    }

    /// <summary>
    /// Parses the XML property list printed by <c>ioreg -a -l -r -c IOUSBHostDevice</c> and returns one endpoint
    /// per device whose idVendor/idProduct are 05C6/9008. Devices without a locationID are skipped, because
    /// their instance id could not stay stable.
    /// </summary>
    public static IReadOnlyList<EdlEndpoint> Parse(string plistXml)
    {
        var found = new List<EdlEndpoint>();
        if (string.IsNullOrWhiteSpace(plistXml))
        {
            return found;
        }

        var document = new XmlDocument { XmlResolver = null };
        using (var reader = XmlReader.Create(
                   new StringReader(plistXml),
                   new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null }))
        {
            document.Load(reader);
        }

        XmlElement? root = document.DocumentElement;
        XmlElement? top = root is null ? null : FirstElement(root);
        if (top is null)
        {
            return found;
        }

        Walk(top, found);
        return found;
    }

    private static void Walk(XmlElement node, List<EdlEndpoint> found)
    {
        if (node.Name == "array")
        {
            foreach (XmlNode child in node.ChildNodes)
            {
                if (child is XmlElement element)
                {
                    Walk(element, found);
                }
            }

            return;
        }

        if (node.Name != "dict")
        {
            return;
        }

        Dictionary<string, XmlElement> properties = ReadDict(node);
        if (TryReadInteger(properties, "idVendor", out long vid) && vid == QualcommVid
            && TryReadInteger(properties, "idProduct", out long pid) && pid == EdlPid
            && TryReadInteger(properties, "locationID", out long location))
        {
            string? product = properties.TryGetValue("USB Product Name", out XmlElement? name) && name.Name == "string"
                ? name.InnerText
                : null;
            string instanceId = string.Format(
                CultureInfo.InvariantCulture,
                @"USB\VID_{0:X4}&PID_{1:X4}\LOC_{2:X8}",
                QualcommVid,
                EdlPid,
                location);
            found.Add(new EdlEndpoint(instanceId, null, product));
        }

        if (properties.TryGetValue("IORegistryEntryChildren", out XmlElement? children))
        {
            Walk(children, found);
        }
    }

    private static Dictionary<string, XmlElement> ReadDict(XmlElement dict)
    {
        var properties = new Dictionary<string, XmlElement>(StringComparer.Ordinal);
        string? key = null;
        foreach (XmlNode child in dict.ChildNodes)
        {
            if (child is not XmlElement element)
            {
                continue;
            }

            if (element.Name == "key")
            {
                key = element.InnerText;
            }
            else if (key is not null)
            {
                properties[key] = element;
                key = null;
            }
        }

        return properties;
    }

    private static bool TryReadInteger(Dictionary<string, XmlElement> properties, string key, out long value)
    {
        value = 0;
        return properties.TryGetValue(key, out XmlElement? element)
            && element.Name == "integer"
            && long.TryParse(element.InnerText.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    private static XmlElement? FirstElement(XmlElement parent)
    {
        foreach (XmlNode child in parent.ChildNodes)
        {
            if (child is XmlElement element)
            {
                return element;
            }
        }

        return null;
    }

    private static string RunIoreg()
    {
        var start = new ProcessStartInfo(IoregPath)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (string argument in new[] { "-a", "-l", "-r", "-c", "IOUSBHostDevice" })
        {
            start.ArgumentList.Add(argument);
        }

        using Process process = Process.Start(start)
            ?? throw new InvalidOperationException("ioreg could not be started.");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(IoregTimeout))
        {
            try
            {
                process.Kill();
            }
            catch (InvalidOperationException)
            {
            }

            throw new TimeoutException("ioreg did not finish within " + IoregTimeout.TotalSeconds + " seconds.");
        }

        if (process.ExitCode != 0)
        {
            string detail = error.GetAwaiter().GetResult().Trim();
            throw new InvalidOperationException(
                "ioreg exited with code " + process.ExitCode + (detail.Length > 0 ? ": " + detail : "."));
        }

        return output.GetAwaiter().GetResult();
    }
}
