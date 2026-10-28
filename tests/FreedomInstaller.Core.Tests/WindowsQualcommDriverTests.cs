using System;
using System.Reflection;
using System.Runtime.InteropServices;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Verdict and parsing invariants of the read-only Qualcomm 9008 driver probe. These tests never call a
/// native Windows API, never touch a real device and never read a machine's installed drivers: every state
/// is produced from a synthetic evidence snapshot through the production decision seam, and the only
/// Windows-entry-point fact requires a non-Windows host.
/// </summary>
public sealed class WindowsQualcommDriverTests
{
    private const uint DnStarted = 0x00000008;
    private const uint DnHasProblem = 0x00000400;

    private const string StorePath =
        @"C:\Windows\System32\DriverStore\FileRepository\qc9008.inf_amd64_abc123\qc9008.inf";

    [Fact]
    public void Inspect_OnNonWindows_ReturnsUnsupportedWithoutNativeQueries()
    {
        if (OperatingSystem.IsWindows())
        {
            throw new InvalidOperationException(
                "WindowsQualcommDriverTests must run in the Linux CI container; Inspect() there queries real "
                + "installed drivers and must not be used as a test fixture.");
        }

        WindowsDriverCheckResult result = new WindowsQualcommDriver().Inspect();

        Assert.Equal(WindowsDriverCheckState.Unsupported, result.State);
        Assert.False(result.IsReady);
        Assert.Null(result.DriverVersion);
        Assert.Null(result.PublishedInf);
        Assert.False(string.IsNullOrWhiteSpace(result.Detail));
    }

    [Theory]
    [InlineData(false, Architecture.X64, 10, 0, true)]
    [InlineData(true, Architecture.Arm64, 10, 0, true)]
    [InlineData(true, Architecture.X86, 10, 0, true)]
    [InlineData(true, Architecture.X64, 6, 3, true)]
    [InlineData(true, Architecture.X64, 10, 0, false)]
    [InlineData(true, Architecture.X64, 11, 0, false)]
    public void DescribeUnsupportedPlatform_RequiresNativeX64WindowsTenOrLater(
        bool isWindows,
        Architecture osArchitecture,
        int major,
        int minor,
        bool expectUnsupported)
    {
        string? reason = DescribeUnsupportedPlatform(isWindows, osArchitecture, new Version(major, minor));

        if (expectUnsupported)
        {
            Assert.False(string.IsNullOrWhiteSpace(reason));
        }
        else
        {
            Assert.Null(reason);
        }
    }

    [Theory]
    [InlineData(WindowsDriverCheckState.Missing, false)]
    [InlineData(WindowsDriverCheckState.Prepared, true)]
    [InlineData(WindowsDriverCheckState.Connected, true)]
    [InlineData(WindowsDriverCheckState.Problem, false)]
    [InlineData(WindowsDriverCheckState.Unknown, false)]
    [InlineData(WindowsDriverCheckState.Unsupported, false)]
    public void IsReady_IsTrueExactlyForPreparedAndConnected(WindowsDriverCheckState state, bool expected)
    {
        var result = new WindowsDriverCheckResult(state, null, null, null);

        Assert.Equal(expected, result.IsReady);
    }

    [Fact]
    public void Decide_NoEndpointWithVerifiedStorePackage_IsPreparedAndReady()
    {
        WindowsDriverCheckResult result = Decide(
            Snapshot(packages: new[] { Package() }));

        Assert.Equal(WindowsDriverCheckState.Prepared, result.State);
        Assert.True(result.IsReady);
        Assert.Equal("oem147.inf", result.PublishedInf);
        Assert.Equal("10.0.1.2", result.DriverVersion);
        Assert.Contains("oem147.inf", result.Detail!);
    }

    [Fact]
    public void Decide_TextMatchWithoutVerifiedPackage_IsMissingAndNotReady()
    {
        WindowsDriverCheckResult result = Decide(Snapshot());

        Assert.Equal(WindowsDriverCheckState.Missing, result.State);
        Assert.False(result.IsReady);
        Assert.Null(result.PublishedInf);
        Assert.Null(result.DriverVersion);
    }

    [Fact]
    public void Decide_PackageWithUntrustedSignature_IsProblemAndNotReady()
    {
        object package = Package(
            signatureAccepted: false,
            signatureDetail: "Signature not trusted (0xE0000242).");

        WindowsDriverCheckResult result = Decide(Snapshot(packages: new[] { package }));

        Assert.Equal(WindowsDriverCheckState.Problem, result.State);
        Assert.False(result.IsReady);
        Assert.Null(result.PublishedInf);
        Assert.Contains("0xE0000242", result.Detail!);
        Assert.Contains("oem147.inf", result.Detail!);
    }

    [Theory]
    [InlineData(null, "qc9008.cat")]
    [InlineData("Qualcomm", null)]
    [InlineData(" ", "qc9008.cat")]
    [InlineData("", "")]
    [InlineData(null, null)]
    public void Decide_AcceptedFlagWithoutSignerOrCatalogEvidence_IsNeverReady(
        string? digitalSigner,
        string? catalogFile)
    {
        object package = Package(digitalSigner: digitalSigner, catalogFile: catalogFile);

        WindowsDriverCheckResult result = Decide(Snapshot(packages: new[] { package }));

        Assert.Equal(WindowsDriverCheckState.Problem, result.State);
        Assert.False(result.IsReady);
    }

    [Fact]
    public void Decide_VerifiedPackageOutsidePublishedNames_IsNeverReady()
    {
        WindowsDriverCheckResult result = Decide(
            Snapshot(packages: new[] { Package(infName: "qc9008.inf") }));

        Assert.Equal(WindowsDriverCheckState.Problem, result.State);
        Assert.False(result.IsReady);
    }

    [Fact]
    public void Decide_StartedEndpointBoundToVerifiedPackage_IsConnectedAndReady()
    {
        WindowsDriverCheckResult result = Decide(
            Snapshot(
                packages: new[] { Package() },
                endpoints: new[] { Endpoint() }));

        Assert.Equal(WindowsDriverCheckState.Connected, result.State);
        Assert.True(result.IsReady);
        Assert.Equal("oem147.inf", result.PublishedInf);
        Assert.Equal("10.0.1.2", result.DriverVersion);
        Assert.Contains("qcusbser", result.Detail!);
    }

    [Fact]
    public void Decide_StartedEndpointBoundToWinUsb_IsConnected()
    {
        WindowsDriverCheckResult result = Decide(
            Snapshot(
                packages: new[] { Package() },
                endpoints: new[] { Endpoint(service: "WinUSB") }));

        Assert.Equal(WindowsDriverCheckState.Connected, result.State);
        Assert.True(result.IsReady);
    }

    [Fact]
    public void Decide_EndpointBoundToDifferentUnverifiedInf_IsProblem()
    {
        WindowsDriverCheckResult result = Decide(
            Snapshot(
                packages: new[] { Package() },
                endpoints: new[] { Endpoint(boundInfName: "oem999.inf") }));

        Assert.Equal(WindowsDriverCheckState.Problem, result.State);
        Assert.False(result.IsReady);
        Assert.Contains("oem999.inf", result.Detail!);
    }

    [Fact]
    public void Decide_BoundInfUnverifiedOnlyBecauseScanFailed_IsUnknownNotProblem()
    {
        WindowsDriverCheckResult result = Decide(
            Snapshot(
                packages: new[] { Package() },
                endpoints: new[] { Endpoint(boundInfName: "oem999.inf") },
                packageQueryFailure: "oem999.inf could not be inspected (5)."));

        Assert.Equal(WindowsDriverCheckState.Unknown, result.State);
        Assert.False(result.IsReady);
        Assert.Contains("oem999.inf could not be inspected", result.Detail!);
    }

    [Fact]
    public void Decide_EndpointProblemCode28_IsProblem()
    {
        WindowsDriverCheckResult result = Decide(
            Snapshot(
                packages: new[] { Package() },
                endpoints: new[] { Endpoint(status: DnStarted | DnHasProblem, problem: 28) }));

        Assert.Equal(WindowsDriverCheckState.Problem, result.State);
        Assert.False(result.IsReady);
        Assert.Contains("28", result.Detail!);
    }

    [Fact]
    public void Decide_NotStartedEndpoint_IsProblem()
    {
        WindowsDriverCheckResult result = Decide(
            Snapshot(
                packages: new[] { Package() },
                endpoints: new[] { Endpoint(status: 0) }));

        Assert.Equal(WindowsDriverCheckState.Problem, result.State);
        Assert.False(result.IsReady);
        Assert.Contains("not started", result.Detail!);
    }

    [Fact]
    public void Decide_WrongBoundService_IsProblem()
    {
        WindowsDriverCheckResult result = Decide(
            Snapshot(
                packages: new[] { Package() },
                endpoints: new[] { Endpoint(service: "usbser") }));

        Assert.Equal(WindowsDriverCheckState.Problem, result.State);
        Assert.False(result.IsReady);
        Assert.Contains("qcusbser", result.Detail!);
    }

    [Fact]
    public void Decide_OneUnhealthyEndpointAmongTwo_IsProblem()
    {
        WindowsDriverCheckResult result = Decide(
            Snapshot(
                packages: new[] { Package() },
                endpoints: new[]
                {
                    Endpoint(),
                    Endpoint(instanceId: @"USB\VID_05C6&PID_9008\SERIAL2", service: "usbser"),
                }));

        Assert.Equal(WindowsDriverCheckState.Problem, result.State);
        Assert.False(result.IsReady);
        Assert.Contains("SERIAL2", result.Detail!);
    }

    [Fact]
    public void Decide_UnreadableEndpointBinding_IsUnknown()
    {
        WindowsDriverCheckResult result = Decide(
            Snapshot(
                packages: new[] { Package() },
                endpoints: new[] { Endpoint(service: null, boundInfName: null, failureDetail: "DriverInfPath unreadable.") }));

        Assert.Equal(WindowsDriverCheckState.Unknown, result.State);
        Assert.False(result.IsReady);
        Assert.Contains("DriverInfPath unreadable.", result.Detail!);
    }

    [Fact]
    public void Decide_StatusQueryFailure_IsUnknownEvenWithPreparedPackage()
    {
        WindowsDriverCheckResult result = Decide(
            Snapshot(
                packages: new[] { Package() },
                endpoints: new[] { Endpoint(statusQuerySucceeded: false, failureDetail: "CONFIGRET 13.") }));

        Assert.Equal(WindowsDriverCheckState.Unknown, result.State);
        Assert.False(result.IsReady);
        Assert.Contains("CONFIGRET 13.", result.Detail!);
    }

    [Fact]
    public void Decide_EndpointQueryFailure_IsUnknownEvenWithPreparedPackage()
    {
        WindowsDriverCheckResult result = Decide(
            Snapshot(
                packages: new[] { Package() },
                endpointQueryFailure: "SetupDiGetClassDevsW failed (5)."));

        Assert.Equal(WindowsDriverCheckState.Unknown, result.State);
        Assert.False(result.IsReady);
        Assert.Contains("SetupDiGetClassDevsW", result.Detail!);
    }

    [Fact]
    public void Decide_PackageQueryFailureWithoutCandidate_IsUnknownNotMissing()
    {
        WindowsDriverCheckResult result = Decide(
            Snapshot(packageQueryFailure: "oem147.inf could not be inspected (5)."));

        Assert.Equal(WindowsDriverCheckState.Unknown, result.State);
        Assert.False(result.IsReady);
        Assert.Contains("could not be inspected", result.Detail!);
    }

    [Fact]
    public void Decide_NonWindowsSnapshot_IsUnsupported()
    {
        WindowsDriverCheckResult result = Decide(
            Snapshot(windowsSupported: false, unsupportedReason: "Only x64 Windows 10+ is supported."));

        Assert.Equal(WindowsDriverCheckState.Unsupported, result.State);
        Assert.False(result.IsReady);
        Assert.Contains("x64 Windows", result.Detail!);
    }

    [Theory]
    [InlineData(true, 0, "Qualcomm", "qc9008.cat", true)]
    [InlineData(false, unchecked((int)0xE0000241), "Qualcomm", "qc9008.cat", true)]
    [InlineData(false, unchecked((int)0xE0000242), "Qualcomm", "qc9008.cat", false)]
    [InlineData(false, 0, "Qualcomm", "qc9008.cat", false)]
    [InlineData(false, 5, "Qualcomm", "qc9008.cat", false)]
    [InlineData(true, 0, null, "qc9008.cat", false)]
    [InlineData(true, 0, "Qualcomm", null, false)]
    [InlineData(false, unchecked((int)0xE0000241), "", "qc9008.cat", false)]
    public void IsAcceptedSignatureOutcome_AcceptsSuccessAndTrustedPublisherWithEvidenceOnly(
        bool verified,
        int nativeError,
        string? digitalSigner,
        string? catalogFile,
        bool expected)
    {
        bool accepted = IsAcceptedSignatureOutcome(verified, nativeError, digitalSigner, catalogFile);

        Assert.Equal(expected, accepted);
    }

    [Theory]
    [InlineData(@"USB\VID_05C6&PID_9008", true)]
    [InlineData(@"usb\vid_05c6&pid_9008", true)]
    [InlineData(@"USB\VID_05C6&PID_9008&REV_0000", true)]
    [InlineData(@"USB\VID_05C6&PID_9008&MI_00", true)]
    [InlineData(@"USB\VID_105C6&PID_9008", false)]
    [InlineData(@"USB\VID_05C6&PID_90080", false)]
    [InlineData(@"USB\VID_05C6&PID_900E", false)]
    [InlineData(@"USB\VID_05C6&PID_9008&VID_05C6", false)]
    [InlineData(@"USB\VID_05C6", false)]
    [InlineData(@"PCI\VEN_05C6&DEV_9008", false)]
    [InlineData(@"USB\VID_05C6&PID_9008\SERIAL1", false)]
    [InlineData("USB device VID_05C6 PID_9008", false)]
    [InlineData(null, false)]
    public void IsTargetUsbHardwareId_RequiresExactTokenBoundaries(string? hardwareId, bool expected)
    {
        Assert.Equal(expected, IsTargetUsbHardwareId(hardwareId));
    }

    [Theory]
    [InlineData("oem147.inf", true)]
    [InlineData("OEM000.INF", true)]
    [InlineData(@"C:\Windows\INF\OEM7.INF", true)]
    [InlineData("oem.inf", false)]
    [InlineData("oem147.sys", false)]
    [InlineData("oem14a.inf", false)]
    [InlineData("oem-1.inf", false)]
    [InlineData("oem147.inf.bak", false)]
    [InlineData("qc9008.inf", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsPublishedOemInfName_AcceptsOnlyPublishedOemNames(string? fileName, bool expected)
    {
        Assert.Equal(expected, IsPublishedOemInfName(fileName));
    }

    [Theory]
    [InlineData("QcomSerialPort.NTamd64.10.0", true)]
    [InlineData("QcomSerialPort.NTamd64.6.1", true)]
    [InlineData("qcomserialport.ntamd64.10.0...22000", true)]
    [InlineData("QcomSerialPort.NTamd64", true)]
    [InlineData("NTamd64", false)]
    [InlineData("NTamd64.10.0", false)]
    [InlineData(".NTamd64", false)]
    [InlineData("QcomSerialPort.NTx86", false)]
    [InlineData("QcomSerialPort.NTarm64", false)]
    [InlineData("QcomSerialPort.NTamd64x", false)]
    [InlineData("QcomSerialPort.NTamd64.NTarm64", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsNativeAmd64ModelsSection_AcceptsOnlyNativeAmd64(string? section, bool expected)
    {
        Assert.Equal(expected, IsNativeAmd64ModelsSection(section));
    }

    [Theory]
    [InlineData(false, 5, true)]
    [InlineData(false, 87, true)]
    [InlineData(false, 0, true)]
    [InlineData(true, 0, false)]
    [InlineData(false, unchecked((int)0xE0000242), false)]
    [InlineData(false, unchecked((int)0xE0000241), false)]
    public void IsSignatureQueryFailure_SeparatesQueryErrorsFromSignatureVerdicts(
        bool verified,
        int nativeError,
        bool expected)
    {
        Assert.Equal(expected, IsSignatureQueryFailure(verified, nativeError));
    }

    [Theory]
    [InlineData("AcmeDevices", new[] { "NT.5.1" }, false)]
    [InlineData("LegacyPort", new[] { "NTx86" }, false)]
    [InlineData("ArmPort", new[] { "NTarm", "NTarm64" }, false)]
    [InlineData("NoDecorPort", new string[0], false)]
    [InlineData("QcomSerialPort", new[] { "NTamd64.10.0" }, true)]
    [InlineData("QcomSerialPort", new[] { "NTamd64" }, true)]
    [InlineData("QcomSerialPort", new[] { "NT.5.1", "NTamd64.10.0" }, true)]
    [InlineData("QcomSerialPort", new[] { "NTamd64x" }, false)]
    [InlineData("QcomSerialPort", new[] { "Vendor.NTamd64" }, false)]
    [InlineData("", new[] { "NTamd64.10.0" }, false)]
    [InlineData("QcomSerialPort", new[] { "NTarm64" }, false)]
    public void HasNativeModelsDecoration_RequiresBaseAndExactNativeAmd64Decoration(
        string baseSection,
        string[] decorations,
        bool expected)
    {
        Assert.Equal(expected, HasNativeModelsDecoration(baseSection, decorations));
    }

    [Theory]
    [InlineData("qcusbser", true)]
    [InlineData("QCUSBSER", true)]
    [InlineData("WinUSB", true)]
    [InlineData("winusb", true)]
    [InlineData("usbser", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsAcceptedBoundService_AcceptsOnlyQcusbserAndWinUsb(string? service, bool expected)
    {
        Assert.Equal(expected, IsAcceptedBoundService(service));
    }

    private static object Package(
        string infName = "oem147.inf",
        string storeInfPath = StorePath,
        string? driverVersion = "10.0.1.2",
        string? digitalSigner = "Qualcomm",
        string? catalogFile = "qc9008.cat",
        bool signatureAccepted = true,
        string? signatureDetail = "Catalog signature accepted.")
    {
        return Create(
            "DriverPackageEvidence",
            infName,
            storeInfPath,
            driverVersion,
            digitalSigner,
            catalogFile,
            signatureAccepted,
            signatureDetail);
    }

    private static object Endpoint(
        string instanceId = @"USB\VID_05C6&PID_9008\SERIAL1",
        string? boundInfName = "oem147.inf",
        string? service = "qcusbser",
        uint status = DnStarted,
        uint problem = 0,
        bool statusQuerySucceeded = true,
        string? failureDetail = null)
    {
        return Create(
            "DriverEndpointEvidence",
            instanceId,
            boundInfName,
            service,
            status,
            problem,
            statusQuerySucceeded,
            failureDetail);
    }

    private static object Snapshot(
        bool windowsSupported = true,
        string? unsupportedReason = null,
        string? packageQueryFailure = null,
        string? endpointQueryFailure = null,
        object[]? packages = null,
        object[]? endpoints = null)
    {
        return Create(
            "DriverEvidenceSnapshot",
            windowsSupported,
            unsupportedReason,
            packageQueryFailure,
            endpointQueryFailure,
            EvidenceArray("DriverPackageEvidence", packages),
            EvidenceArray("DriverEndpointEvidence", endpoints));
    }

    private static Array EvidenceArray(string elementTypeName, object[]? items)
    {
        object[] values = items ?? Array.Empty<object>();
        Type elementType = CoreType(elementTypeName);
        Array array = Array.CreateInstance(elementType, values.Length);

        for (int index = 0; index < values.Length; index++)
        {
            array.SetValue(values[index], index);
        }

        return array;
    }

    private static WindowsDriverCheckResult Decide(object snapshot)
    {
        MethodInfo method = DriverMethod("Decide");

        return (WindowsDriverCheckResult)method.Invoke(null, new[] { snapshot })!;
    }

    private static string? DescribeUnsupportedPlatform(bool isWindows, Architecture osArchitecture, Version osVersion)
    {
        MethodInfo method = DriverMethod("DescribeUnsupportedPlatform");

        return (string?)method.Invoke(null, new object?[] { isWindows, osArchitecture, osVersion });
    }

    private static bool IsAcceptedSignatureOutcome(
        bool verified,
        int nativeError,
        string? digitalSigner,
        string? catalogFile)
    {
        MethodInfo method = DriverMethod("IsAcceptedSignatureOutcome");

        return (bool)method.Invoke(null, new object?[] { verified, nativeError, digitalSigner, catalogFile })!;
    }

    private static bool HasNativeModelsDecoration(string? baseSection, string[] decorations)
    {
        MethodInfo method = DriverMethod("HasNativeModelsDecoration");

        return (bool)method.Invoke(null, new object?[] { baseSection, decorations })!;
    }

    private static bool IsSignatureQueryFailure(bool verified, int nativeError)
    {
        MethodInfo method = DriverMethod("IsSignatureQueryFailure");

        return (bool)method.Invoke(null, new object?[] { verified, nativeError })!;
    }

    private static bool IsTargetUsbHardwareId(string? hardwareId)
    {
        MethodInfo method = DriverMethod("IsTargetUsbHardwareId");

        return (bool)method.Invoke(null, new object?[] { hardwareId })!;
    }

    private static bool IsPublishedOemInfName(string? fileName)
    {
        MethodInfo method = DriverMethod("IsPublishedOemInfName");

        return (bool)method.Invoke(null, new object?[] { fileName })!;
    }

    private static bool IsNativeAmd64ModelsSection(string? section)
    {
        MethodInfo method = DriverMethod("IsNativeAmd64ModelsSection");

        return (bool)method.Invoke(null, new object?[] { section })!;
    }

    private static bool IsAcceptedBoundService(string? service)
    {
        MethodInfo method = DriverMethod("IsAcceptedBoundService");

        return (bool)method.Invoke(null, new object?[] { service })!;
    }

    private static MethodInfo DriverMethod(string name)
    {
        return typeof(WindowsQualcommDriver).GetMethod(name, BindingFlags.Static | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException($"WindowsQualcommDriver.{name} was not found.");
    }

    private static object Create(string typeName, params object?[] arguments)
    {
        return Activator.CreateInstance(
            CoreType(typeName),
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            args: arguments,
            culture: null)!;
    }

    private static Type CoreType(string name)
    {
        return typeof(WindowsQualcommDriver).Assembly.GetType("FreedomInstaller.Core." + name, throwOnError: true)!;
    }
}
