using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace FreedomInstaller.Core;

/// <summary>
/// Read-only readiness probe for the Qualcomm 9008 Windows driver package.
/// <para>
/// The probe never opens a device, never opens a COM port, never starts a process and never installs
/// anything. On Windows x64 it (1) enumerates the published <c>oem*.inf</c> files through SetupAPI,
/// (2) keeps only INFs that declare a native <c>NTamd64</c> model for the exact USB VID_05C6/PID_9008
/// pair, (3) maps each such published INF to its DriverStore location, reads <c>DriverVer</c> from
/// <c>[Version]</c> and verifies the store INF against its registered catalog, and (4) inspects the actual
/// binding of every present 9008 endpoint (service, bound published INF, devnode status).
/// </para>
/// <para>
/// <see cref="Decide"/> is pure and platform-neutral; all evidence is captured into
/// <see cref="DriverEvidenceSnapshot"/> first so the verdict can be tested without a live Windows host.
/// </para>
/// </summary>
public sealed class WindowsQualcommDriver
{
    private const string UsbPrefix = "USB\\";
    private const string UsbEnumerator = "USB";
    private const string ManufacturerSectionName = "Manufacturer";
    private const string VersionSectionName = "Version";
    private const string DriverVerFieldName = "DriverVer";
    private const string TargetVid = "05C6";
    private const string TargetPid = "9008";
    private const string NativeModelsSectionPrefix = "NTamd64";
    private const string QualcommSerialService = "qcusbser";
    private const string WinUsbService = "WinUSB";

    private const uint InfStyleWin4 = 0x00000002;

    private const uint DigcfPresent = 0x00000002;
    private const uint DigcfAllClasses = 0x00000004;

    private const uint SpdrpService = 0x00000004;
    private const uint RegSz = 0x00000001;
    private const uint DevPropTypeString = 0x00000012;

    private const uint CrSuccess = 0;
    private const uint DnStarted = 0x00000008;
    private const uint DnHasProblem = 0x00000400;

    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorInvalidData = 13;
    private const int ErrorNoMoreItems = 259;
    private const int ErrorNotFound = 1168;

    // SetupAPI section/line absence is reported as SPAPI_E_* HRESULT-style values, not 1874/1875.
    private const int ErrorSectionNotFound = unchecked((int)0xE0000101);
    private const int ErrorLineNotFound = unchecked((int)0xE0000102);

    private const int ErrorAuthenticodeTrustedPublisher = unchecked((int)0xE0000241);
    private const int ErrorAuthenticodeTrustNotEstablished = unchecked((int)0xE0000242);

    /// <summary>Upper bound for every INF string this probe reads, including the store location.</summary>
    private const uint MaxInfFieldChars = 4096;

    private const uint MaxStorePathChars = 32768;

    /// <summary>Upper bound for the published INF name list returned by SetupAPI (characters).</summary>
    private const uint MaxInfListChars = 1 << 20;

    private const int MaxDetailLength = 400;

    private static readonly IntPtr InvalidHandleValue = new IntPtr(-1);

    /// <summary>
    /// DEVPKEY_Device_DriverInfPath: the published INF name the device node is currently bound to
    /// (fmtid A8B865DD-2E3D-4094-AD97-E593A70C75D6, pid 5).
    /// </summary>
    private static readonly DevPropKey DriverInfPathKey = new DevPropKey
    {
        FmtId = new Guid("a8b865dd-2e3d-4094-ad97-e593a70c75d6"),
        Pid = 5,
    };

    [StructLayout(LayoutKind.Sequential)]
    private struct InfContext
    {
        public IntPtr Inf;
        public IntPtr CurrentInf;
        public uint Section;
        public uint Line;
    }

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

    /// <summary>
    /// SP_INF_SIGNER_INFO_V2_W: cbSize (4) + three WCHAR[260] strings + SignerScore, 1568 bytes, no
    /// pointers. <see cref="CbSize"/> must be initialized before the call.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SpInfSignerInfoV2W
    {
        public uint CbSize;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string CatalogFile;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string DigitalSigner;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string DigitalSignerVersion;

        public uint SignerScore;
    }

    [DllImport("setupapi.dll", EntryPoint = "SetupGetInfFileListW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupGetInfFileList(
        string? directoryInf,
        uint infStyle,
        [Out, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U2)] char[]? returnBuffer,
        uint returnBufferSize,
        out uint requiredSize);

    [DllImport("setupapi.dll", EntryPoint = "SetupOpenInfFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr SetupOpenInfFile(
        string fileName,
        string? infClass,
        uint infStyle,
        out uint errorLine);

    [DllImport("setupapi.dll", EntryPoint = "SetupCloseInfFile", SetLastError = true)]
    private static extern void SetupCloseInfFile(IntPtr infHandle);

    [DllImport("setupapi.dll", EntryPoint = "SetupFindFirstLineW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupFindFirstLine(
        IntPtr infHandle,
        string section,
        string? key,
        ref InfContext context);

    [DllImport("setupapi.dll", EntryPoint = "SetupFindNextLine", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupFindNextLine(ref InfContext contextIn, ref InfContext contextOut);

    [DllImport("setupapi.dll", EntryPoint = "SetupGetFieldCount", SetLastError = true)]
    private static extern uint SetupGetFieldCount(ref InfContext context);

    [DllImport("setupapi.dll", EntryPoint = "SetupGetStringFieldW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupGetStringField(
        ref InfContext context,
        uint fieldIndex,
        [Out, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U2)] char[]? returnBuffer,
        uint returnBufferSize,
        out uint requiredSize);

    [DllImport("setupapi.dll", EntryPoint = "SetupDiGetActualModelsSectionW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiGetActualModelsSection(
        ref InfContext context,
        IntPtr altPlatformInfo,
        [Out, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U2)] char[]? extendedSection,
        uint extendedSectionSize,
        out uint requiredSize,
        IntPtr reserved);

    [DllImport("setupapi.dll", EntryPoint = "SetupGetInfDriverStoreLocationW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupGetInfDriverStoreLocation(
        string fileName,
        IntPtr altPlatformInfo,
        string? localeName,
        [Out, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U2)] char[]? returnBuffer,
        uint returnBufferSize,
        out uint requiredSize);

    [DllImport("setupapi.dll", EntryPoint = "SetupVerifyInfFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupVerifyInfFile(
        string infName,
        IntPtr altPlatformInfo,
        ref SpInfSignerInfoV2W infSignerInfo);

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

    [DllImport("setupapi.dll", EntryPoint = "SetupDiDestroyDeviceInfoList", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

    [DllImport("setupapi.dll", EntryPoint = "SetupDiGetDeviceRegistryPropertyW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiGetDeviceRegistryProperty(
        IntPtr deviceInfoSet,
        ref SpDevInfoData deviceInfoData,
        uint property,
        out uint propertyRegDataType,
        [Out] byte[]? propertyBuffer,
        uint propertyBufferSize,
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

    [DllImport("cfgmgr32.dll", EntryPoint = "CM_Get_DevNode_Status", SetLastError = false)]
    private static extern uint CM_Get_DevNode_Status(
        out uint status,
        out uint problemNumber,
        uint devInst,
        uint flags);

    /// <summary>
    /// Inspects driver readiness without changing machine state. Unsupported platforms are rejected before
    /// any native call, and an unexpected OS query failure becomes a bounded
    /// <see cref="WindowsDriverCheckState.Unknown"/> instead of Missing or a false success.
    /// </summary>
    public WindowsDriverCheckResult Inspect()
    {
        if (!OperatingSystem.IsWindows())
        {
            string reason = DescribeUnsupportedPlatform(
                isWindows: false,
                RuntimeInformation.OSArchitecture,
                Environment.OSVersion.Version)
                ?? "Driver readiness can only be inspected on Windows.";

            return UnsupportedResult(reason);
        }

        string? unsupported = DescribeUnsupportedPlatform(
            isWindows: true,
            RuntimeInformation.OSArchitecture,
            Environment.OSVersion.Version);

        if (unsupported is not null)
        {
            return UnsupportedResult(unsupported);
        }

        try
        {
            return Decide(InspectWindows());
        }
        catch (Exception exception) when (IsOsQueryFailure(exception))
        {
            return new WindowsDriverCheckResult(
                WindowsDriverCheckState.Unknown,
                null,
                null,
                Bound("Driver readiness query failed: " + exception.Message));
        }
    }

    /// <summary>
    /// The single platform gate: native x64 Windows 10 or later. Process bitness is deliberately not used,
    /// because a 32-bit process on x64 Windows can still inspect the x64 package and devnodes.
    /// </summary>
    internal static string? DescribeUnsupportedPlatform(bool isWindows, Architecture osArchitecture, Version osVersion)
    {
        if (!isWindows)
        {
            return "Driver readiness can only be inspected on Windows; no native query was attempted.";
        }

        if (osArchitecture != Architecture.X64)
        {
            return "Only a native x64 Windows installation is supported for the Qualcomm 9008 package "
                + $"(reported OS architecture: {osArchitecture}).";
        }

        if (osVersion.Major < 10)
        {
            return $"Windows 10 or later is required to query the driver package (reported version {osVersion}).";
        }

        return null;
    }

    /// <summary>
    /// The pure verdict over captured evidence. Nothing here touches the OS, so it is exercised directly
    /// by tests for every state, including the failures that must never be reported as ready.
    /// </summary>
    internal static WindowsDriverCheckResult Decide(DriverEvidenceSnapshot evidence)
    {
        if (!evidence.WindowsSupported)
        {
            return UnsupportedResult(evidence.UnsupportedReason ?? "This platform is not supported.");
        }

        var verified = new List<DriverPackageEvidence>();
        var rejected = new List<DriverPackageEvidence>();

        for (int index = 0; index < evidence.Packages.Count; index++)
        {
            DriverPackageEvidence package = evidence.Packages[index];

            if (IsVerifiedPackage(package))
            {
                verified.Add(package);
            }
            else
            {
                rejected.Add(package);
            }
        }

        if (evidence.EndpointQueryFailure is not null)
        {
            return UnknownResult(evidence.EndpointQueryFailure);
        }

        if (evidence.Endpoints.Count == 0)
        {
            if (verified.Count > 0)
            {
                DriverPackageEvidence package = verified[0];

                return new WindowsDriverCheckResult(
                    WindowsDriverCheckState.Prepared,
                    package.DriverVersion,
                    package.InfName,
                    Bound($"Verified published package '{package.InfName}' ({package.StoreInfPath}) is staged for "
                        + "an NTamd64 USB VID_05C6/PID_9008 device; no 9008 endpoint is present."));
            }

            if (rejected.Count > 0)
            {
                return ProblemResult(rejected[0]);
            }

            if (evidence.PackageQueryFailure is not null)
            {
                return UnknownResult(evidence.PackageQueryFailure);
            }

            return new WindowsDriverCheckResult(
                WindowsDriverCheckState.Missing,
                null,
                null,
                "No published OEM INF declares an NTamd64 model for USB VID_05C6/PID_9008 and no 9008 endpoint is present.");
        }

        for (int index = 0; index < evidence.Endpoints.Count; index++)
        {
            DriverEndpointEvidence endpoint = evidence.Endpoints[index];

            if (!endpoint.StatusQuerySucceeded)
            {
                return UnknownResult(
                    endpoint.FailureDetail
                    ?? $"Device node status for '{endpoint.DeviceInstanceId}' could not be read.");
            }
        }

        for (int index = 0; index < evidence.Endpoints.Count; index++)
        {
            DriverEndpointEvidence endpoint = evidence.Endpoints[index];

            if ((endpoint.Status & DnStarted) == 0)
            {
                return new WindowsDriverCheckResult(
                    WindowsDriverCheckState.Problem,
                    null,
                    null,
                    Bound($"Endpoint '{endpoint.DeviceInstanceId}' is not started (device node status "
                        + $"0x{endpoint.Status:X8})."));
            }

            if ((endpoint.Status & DnHasProblem) != 0 || endpoint.Problem != 0)
            {
                return new WindowsDriverCheckResult(
                    WindowsDriverCheckState.Problem,
                    null,
                    null,
                    Bound($"Endpoint '{endpoint.DeviceInstanceId}' reports device problem code "
                        + $"{endpoint.Problem} (device node status 0x{endpoint.Status:X8})."));
            }

            // A binding that could not be read leaves readiness unknown, not failed: the devnode itself is
            // healthy and the missing fact is the binding, not the device state.
            if (endpoint.FailureDetail is not null)
            {
                return UnknownResult(endpoint.FailureDetail);
            }

            if (!IsAcceptedBoundService(endpoint.Service))
            {
                return new WindowsDriverCheckResult(
                    WindowsDriverCheckState.Problem,
                    null,
                    null,
                    Bound($"Endpoint '{endpoint.DeviceInstanceId}' is bound to service "
                        + $"'{endpoint.Service ?? "<none>"}', expected qcusbser or WinUSB."));
            }

            if (string.IsNullOrEmpty(endpoint.BoundInfName))
            {
                return new WindowsDriverCheckResult(
                    WindowsDriverCheckState.Problem,
                    null,
                    null,
                    Bound($"Endpoint '{endpoint.DeviceInstanceId}' did not report a published driver INF."));
            }

            DriverPackageEvidence? boundPackage = FindPackage(verified, endpoint.BoundInfName);

            if (boundPackage is null)
            {
                DriverPackageEvidence? boundButRejected = FindPackage(rejected, endpoint.BoundInfName);

                if (boundButRejected is not null)
                {
                    return ProblemResult(boundButRejected);
                }

                // With an unresolved scan failure, the bound INF may simply not have been inspected yet.
                if (evidence.PackageQueryFailure is not null)
                {
                    return UnknownResult(evidence.PackageQueryFailure);
                }

                return new WindowsDriverCheckResult(
                    WindowsDriverCheckState.Problem,
                    null,
                    null,
                    Bound($"Endpoint '{endpoint.DeviceInstanceId}' is bound to '{endpoint.BoundInfName}', which is "
                        + "not a verified published NTamd64 Qualcomm 9008 package."));
            }
        }

        DriverEndpointEvidence first = evidence.Endpoints[0];
        DriverPackageEvidence connected = FindPackage(verified, first.BoundInfName) ?? verified[0];

        return new WindowsDriverCheckResult(
            WindowsDriverCheckState.Connected,
            connected.DriverVersion,
            connected.InfName,
            Bound($"{evidence.Endpoints.Count} present 9008 endpoint(s) are started with service qcusbser/WinUSB "
                + $"bound to verified package '{connected.InfName}' ({connected.StoreInfPath})."));
    }

    /// <summary>
    /// A published <c>oem&lt;digits&gt;.inf</c> name, case-insensitively, with any directory prefix removed
    /// first. Used both for the published file list and for the name a device node reported.
    /// </summary>
    internal static bool IsPublishedOemInfName(string? fileName)
    {
        string? normalized = NormalizeInfFileName(fileName);

        if (normalized is null)
        {
            return false;
        }

        const string prefix = "oem";
        const string extension = ".inf";

        if (normalized.Length <= prefix.Length + extension.Length
            || !normalized.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            || !normalized.EndsWith(extension, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        for (int index = prefix.Length; index < normalized.Length - extension.Length; index++)
        {
            if (normalized[index] is < '0' or > '9')
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Strips any directory part and surrounding whitespace; returns null for an empty name.</summary>
    internal static string? NormalizeInfFileName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        string trimmed = value.Trim();
        int separator = trimmed.LastIndexOfAny(new[] { '\\', '/' });
        string name = separator >= 0 ? trimmed.Substring(separator + 1) : trimmed;

        return name.Trim().Length == 0 ? null : name.Trim();
    }

    /// <summary>
    /// Exact USB hardware-id match: a <c>USB\</c> prefix and <c>VID_05C6</c>/<c>PID_9008</c> tokens delimited
    /// by <c>&amp;</c>. VID_105C6, PID_90080, PID_900E, PCI ids and free text are rejected, as are duplicate
    /// VID/PID tokens.
    /// </summary>
    internal static bool IsTargetUsbHardwareId(string? hardwareId)
    {
        if (string.IsNullOrWhiteSpace(hardwareId))
        {
            return false;
        }

        string value = hardwareId.Trim();

        if (!value.StartsWith(UsbPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string tokens = value.Substring(UsbPrefix.Length);

        if (tokens.Length == 0 || tokens.IndexOf('\\') >= 0)
        {
            return false;
        }

        bool hasVid = false;
        bool hasPid = false;

        foreach (string token in tokens.Split('&'))
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
            string fieldValue = token.Substring(underscore + 1);

            if (name.Equals("VID", StringComparison.OrdinalIgnoreCase))
            {
                if (hasVid || !fieldValue.Equals(TargetVid, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                hasVid = true;
            }
            else if (name.Equals("PID", StringComparison.OrdinalIgnoreCase))
            {
                if (hasPid || !fieldValue.Equals(TargetPid, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                hasPid = true;
            }
        }

        return hasVid && hasPid;
    }

    /// <summary>
    /// Only the native x64 models section ("NTamd64" or a decorated "NTamd64.&lt;target&gt;") is acceptable;
    /// x86 and ARM64 sections are ordinary non-candidates, not errors.
    /// </summary>
    internal static bool IsNativeAmd64ModelsSection(string? section)
    {
        if (string.IsNullOrWhiteSpace(section))
        {
            return false;
        }

        string value = section.Trim();
        string marker = "." + NativeModelsSectionPrefix;

        // The decorated name is "<ModelsBase>.NTamd64" or "<ModelsBase>.NTamd64.<target>", so the platform
        // token must be a dot-delimited suffix after a non-empty base and must end the name or be followed
        // by a dotted target build.
        int token = value.LastIndexOf(marker, StringComparison.OrdinalIgnoreCase);

        if (token <= 0)
        {
            return false;
        }

        int afterToken = token + marker.Length;

        if (afterToken == value.Length)
        {
            return true;
        }

        if (value[afterToken] != '.')
        {
            return false;
        }

        for (int index = afterToken + 1; index < value.Length; index++)
        {
            if (value[index] != '.' && (value[index] < '0' || value[index] > '9'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Pure Manufacturer-line prefilter: a non-empty base and at least one decoration that is exactly
    /// <c>NTamd64</c> or starts with <c>NTamd64.</c> and composes into a native section accepted by
    /// <see cref="IsNativeAmd64ModelsSection"/>. Legacy <c>NT.5.1</c>, x86/ARM-only, unversioned bare
    /// <c>NTamd64</c> without a base, near matches such as <c>NTamd64x</c> and foreign prefixes are all
    /// non-candidates.
    /// </summary>
    internal static bool HasNativeModelsDecoration(string? baseSection, IReadOnlyList<string>? decorations)
    {
        if (string.IsNullOrWhiteSpace(baseSection) || decorations is null)
        {
            return false;
        }

        string baseName = baseSection.Trim();

        for (int index = 0; index < decorations.Count; index++)
        {
            string? decoration = decorations[index];

            if (string.IsNullOrWhiteSpace(decoration))
            {
                continue;
            }

            string value = decoration.Trim();

            if (!value.Equals(NativeModelsSectionPrefix, StringComparison.OrdinalIgnoreCase)
                && !value.StartsWith(NativeModelsSectionPrefix + ".", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (IsNativeAmd64ModelsSection(baseName + "." + value))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>A 9008 port must be bound to the Qualcomm serial service or to WinUSB, nothing else.</summary>
    internal static bool IsAcceptedBoundService(string? service)
    {
        if (string.IsNullOrWhiteSpace(service))
        {
            return false;
        }

        string value = service.Trim();

        return value.Equals(QualcommSerialService, StringComparison.OrdinalIgnoreCase)
            || value.Equals(WinUsbService, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Signature acceptance from the native outcome: real success, or the explicit
    /// ERROR_AUTHENTICODE_TRUSTED_PUBLISHER result, in both cases only with a non-empty signer and catalog.
    /// An arbitrary failure, ERROR_AUTHENTICODE_TRUST_NOT_ESTABLISHED and empty evidence are all rejected.
    /// </summary>
    internal static bool IsAcceptedSignatureOutcome(
        bool verified,
        int nativeError,
        string? digitalSigner,
        string? catalogFile)
    {
        if (string.IsNullOrWhiteSpace(digitalSigner) || string.IsNullOrWhiteSpace(catalogFile))
        {
            return false;
        }

        if (verified)
        {
            return true;
        }

        return nativeError == ErrorAuthenticodeTrustedPublisher;
    }

    /// <summary>
    /// A failed verification that carries an ordinary, non-negative Win32 error did not reach a signature
    /// verdict at all (access denial, invalid parameter, zero). Only HRESULT-style Authenticode results are
    /// precise signature rejections; anything else must surface as a query failure.
    /// </summary>
    internal static bool IsSignatureQueryFailure(bool verified, int nativeError) =>
        !verified && nativeError >= 0;

    private static bool IsVerifiedPackage(DriverPackageEvidence package) =>
        package.SignatureAccepted
        && !string.IsNullOrWhiteSpace(package.StoreInfPath)
        && !string.IsNullOrWhiteSpace(package.DigitalSigner)
        && !string.IsNullOrWhiteSpace(package.CatalogFile)
        && IsPublishedOemInfName(package.InfName);

    private static DriverPackageEvidence? FindPackage(
        List<DriverPackageEvidence> packages,
        string? infName)
    {
        if (string.IsNullOrEmpty(infName))
        {
            return null;
        }

        for (int index = 0; index < packages.Count; index++)
        {
            if (string.Equals(packages[index].InfName, infName, StringComparison.OrdinalIgnoreCase))
            {
                return packages[index];
            }
        }

        return null;
    }

    private static WindowsDriverCheckResult UnsupportedResult(string detail) =>
        new WindowsDriverCheckResult(WindowsDriverCheckState.Unsupported, null, null, Bound(detail));

    private static WindowsDriverCheckResult UnknownResult(string detail) =>
        new WindowsDriverCheckResult(WindowsDriverCheckState.Unknown, null, null, Bound(detail));

    private static WindowsDriverCheckResult ProblemResult(DriverPackageEvidence package) =>
        new WindowsDriverCheckResult(
            WindowsDriverCheckState.Problem,
            null,
            null,
            Bound($"Published package '{package.InfName}' matches an NTamd64 9008 model but is not usable: "
                + (package.SignatureDetail ?? "signature evidence was not accepted.")));

    private static string Bound(string message) =>
        message.Length <= MaxDetailLength ? message : message.Substring(0, MaxDetailLength) + "...";

    private static bool IsOsQueryFailure(Exception exception) =>
        exception is Win32Exception
            or InvalidOperationException
            or IOException
            or UnauthorizedAccessException
            or System.Security.SecurityException
            or OverflowException
            or PlatformNotSupportedException;

    [SupportedOSPlatform("windows")]
    private static DriverEvidenceSnapshot InspectWindows()
    {
        var packages = new List<DriverPackageEvidence>();
        string? packageQueryFailure = null;

        IReadOnlyList<string> publishedInfNames;

        try
        {
            publishedInfNames = ListPublishedOemInfs();
        }
        catch (Exception exception) when (IsOsQueryFailure(exception))
        {
            return new DriverEvidenceSnapshot(
                WindowsSupported: true,
                UnsupportedReason: null,
                PackageQueryFailure: Bound("Published OEM INF enumeration failed: " + exception.Message),
                EndpointQueryFailure: null,
                Packages: Array.Empty<DriverPackageEvidence>(),
                Endpoints: Array.Empty<DriverEndpointEvidence>());
        }

        for (int index = 0; index < publishedInfNames.Count; index++)
        {
            string infName = publishedInfNames[index];

            try
            {
                DriverPackageEvidence? package = InspectPublishedInf(infName);

                if (package is not null)
                {
                    packages.Add(package);
                }
            }
            catch (Exception exception) when (IsOsQueryFailure(exception))
            {
                // One unreadable INF must not turn the whole probe into a Missing verdict.
                packageQueryFailure ??= Bound($"Published INF '{infName}' could not be inspected: {exception.Message}");
            }
        }

        IReadOnlyList<EdlEndpoint> present;

        try
        {
            present = new WindowsEdlEndpointDiscovery().ReadPresent();
        }
        catch (Exception exception) when (IsOsQueryFailure(exception))
        {
            return new DriverEvidenceSnapshot(
                WindowsSupported: true,
                UnsupportedReason: null,
                PackageQueryFailure: packageQueryFailure,
                EndpointQueryFailure: Bound("Present 9008 endpoint query failed: " + exception.Message),
                Packages: packages,
                Endpoints: Array.Empty<DriverEndpointEvidence>());
        }

        var endpoints = new List<DriverEndpointEvidence>(present.Count);
        string? endpointQueryFailure = null;

        try
        {
            CollectEndpointBindings(present, endpoints);
        }
        catch (Exception exception) when (IsOsQueryFailure(exception))
        {
            endpointQueryFailure = Bound("Device binding query failed: " + exception.Message);
        }

        return new DriverEvidenceSnapshot(
            WindowsSupported: true,
            UnsupportedReason: null,
            PackageQueryFailure: packageQueryFailure,
            EndpointQueryFailure: endpointQueryFailure,
            Packages: packages,
            Endpoints: endpoints);
    }

    /// <summary>
    /// Two-pass Unicode MULTI_SZ enumeration of <c>%windir%\inf\oem*.inf</c>. Names only; the sizing call
    /// may legitimately return TRUE, so both results are inspected before trusting the required size.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<string> ListPublishedOemInfs()
    {
        bool sized = SetupGetInfFileList(null, InfStyleWin4, null, 0, out uint requiredSize);

        if (!sized)
        {
            int error = Marshal.GetLastWin32Error();

            if (error != ErrorInsufficientBuffer)
            {
                throw new Win32Exception(error, "SetupGetInfFileListW failed while sizing the published INF list.");
            }
        }

        if (requiredSize == 0)
        {
            return Array.Empty<string>();
        }

        if (requiredSize > MaxInfListChars)
        {
            throw new InvalidOperationException(
                $"SetupGetInfFileListW reported an out-of-range published INF list size ({requiredSize} characters).");
        }

        var buffer = new char[checked((int)requiredSize)];

        if (!SetupGetInfFileList(null, InfStyleWin4, buffer, (uint)buffer.Length, out _))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "SetupGetInfFileListW failed while reading the published INF list.");
        }

        var names = new List<string>();
        int start = 0;

        for (int index = 0; index <= buffer.Length; index++)
        {
            if (index < buffer.Length && buffer[index] != '\0')
            {
                continue;
            }

            if (index == start)
            {
                // Empty string terminates the MULTI_SZ list.
                break;
            }

            string name = new string(buffer, start, index - start);

            if (IsPublishedOemInfName(name))
            {
                names.Add(name);
            }

            start = index + 1;
        }

        return names;
    }

    /// <summary>
    /// Inspects one published INF. Returns null for an ordinary non-candidate (no [Manufacturer] section, no
    /// NTamd64 models section, no exact VID/PID model) and evidence for a real candidate. Unexpected native
    /// failures propagate so the caller can report Unknown instead of Missing.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static DriverPackageEvidence? InspectPublishedInf(string publishedInfName)
    {
        IntPtr infHandle = SetupOpenInfFile(publishedInfName, null, InfStyleWin4, out uint errorLine);

        if (infHandle == InvalidHandleValue || infHandle == IntPtr.Zero)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"SetupOpenInfFileW failed for '{publishedInfName}' (error line {errorLine}).");
        }

        try
        {
            if (!DeclaresTargetModelsSection(infHandle))
            {
                return null;
            }

            string? driverVersion = ReadDriverVer(infHandle);
            string storeInfPath = GetDriverStoreLocation(publishedInfName);

            var signerInfo = new SpInfSignerInfoV2W
            {
                CbSize = (uint)Marshal.SizeOf<SpInfSignerInfoV2W>(),
                CatalogFile = string.Empty,
                DigitalSigner = string.Empty,
                DigitalSignerVersion = string.Empty,
            };

            bool verified = SetupVerifyInfFile(storeInfPath, IntPtr.Zero, ref signerInfo);
            int verificationError = verified ? 0 : Marshal.GetLastWin32Error();

            // A plain Win32 failure (access denied, invalid parameter, zero) is a query failure, not proof
            // that the signature is untrusted; it must reach the Unknown path instead of becoming Problem.
            if (IsSignatureQueryFailure(verified, verificationError))
            {
                throw new Win32Exception(
                    verificationError,
                    $"SetupVerifyInfFileW could not verify '{storeInfPath}'; the result is not a signature verdict.");
            }

            string catalogFile = (signerInfo.CatalogFile ?? string.Empty).Trim();
            string digitalSigner = (signerInfo.DigitalSigner ?? string.Empty).Trim();

            bool accepted = IsAcceptedSignatureOutcome(verified, verificationError, digitalSigner, catalogFile);

            string signatureDetail = accepted
                ? $"Catalog signature accepted (native result {(verified ? "TRUE" : $"0x{verificationError:X8}")}), "
                    + $"signer '{digitalSigner}', catalog '{catalogFile}'."
                : DescribeSignatureRejection(verified, verificationError, digitalSigner, catalogFile);

            return new DriverPackageEvidence(
                InfName: NormalizeInfFileName(publishedInfName) ?? publishedInfName,
                StoreInfPath: storeInfPath,
                DriverVersion: driverVersion,
                DigitalSigner: digitalSigner,
                CatalogFile: catalogFile,
                SignatureAccepted: accepted,
                SignatureDetail: signatureDetail);
        }
        finally
        {
            SetupCloseInfFile(infHandle);
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool DeclaresTargetModelsSection(IntPtr infHandle)
    {
        var context = default(InfContext);

        if (!SetupFindFirstLine(infHandle, ManufacturerSectionName, null, ref context))
        {
            if (IsOrdinaryLookupMiss(Marshal.GetLastWin32Error()))
            {
                return false;
            }

            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "SetupFindFirstLineW failed for the [Manufacturer] section.");
        }

        while (true)
        {
            // Cheap decoration prefilter: SetupDiGetActualModelsSectionW fails for Manufacturer lines that
            // declare no native amd64 model at all (legacy NT.5.1 / NTx86 / ARM-only), which is an ordinary
            // non-candidate and must not turn the whole scan into a query failure.
            if (DeclaresNativeModelsDecoration(ref context))
            {
                string? modelsSection = TryReadActualModelsSection(ref context);

                if (modelsSection is not null
                    && IsNativeAmd64ModelsSection(modelsSection)
                    && SectionDeclaresTargetModel(infHandle, modelsSection))
                {
                    return true;
                }
            }

            var next = default(InfContext);

            if (!SetupFindNextLine(ref context, ref next))
            {
                if (IsOrdinaryLookupMiss(Marshal.GetLastWin32Error()))
                {
                    return false;
                }

                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "SetupFindNextLine failed while enumerating the [Manufacturer] section.");
            }

            context = next;
        }
    }

    /// <summary>
    /// Reads one [Manufacturer] line through SetupAPI (field 1 is the base models name, fields 2..count are
    /// the platform decorations) and decides, purely, whether that line could host a native amd64 models
    /// section. A malformed or unrelated line is skipped by the caller without aborting the scan.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static bool DeclaresNativeModelsDecoration(ref InfContext context)
    {
        string? baseSection = ReadStringField(ref context, 1);

        if (string.IsNullOrWhiteSpace(baseSection))
        {
            return false;
        }

        uint fieldCount = SetupGetFieldCount(ref context);
        var decorations = new List<string>();

        for (uint fieldIndex = 2; fieldIndex <= fieldCount; fieldIndex++)
        {
            string? decoration = ReadStringField(ref context, fieldIndex);

            if (!string.IsNullOrWhiteSpace(decoration))
            {
                decorations.Add(decoration.Trim());
            }
        }

        return HasNativeModelsDecoration(baseSection, decorations);
    }

    /// <summary>
    /// Asks SetupAPI for the host-decorated models section of one [Manufacturer] line. The NULL sizing call
    /// is expected to succeed; a line without a usable section is an ordinary non-candidate.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static string? TryReadActualModelsSection(ref InfContext context)
    {
        bool sized = SetupDiGetActualModelsSection(ref context, IntPtr.Zero, null, 0, out uint requiredSize, IntPtr.Zero);

        if (!sized)
        {
            int error = Marshal.GetLastWin32Error();

            if (error == ErrorSectionNotFound || error == ErrorLineNotFound)
            {
                return null;
            }

            if (error != ErrorInsufficientBuffer)
            {
                throw new Win32Exception(
                    error,
                    "SetupDiGetActualModelsSectionW failed while sizing the models section name.");
            }

            if (requiredSize == 0)
            {
                throw new Win32Exception(
                    error,
                    "SetupDiGetActualModelsSectionW reported no size for the models section name.");
            }
        }

        if (requiredSize == 0 || requiredSize > MaxInfFieldChars)
        {
            return null;
        }

        var buffer = new char[requiredSize];

        if (!SetupDiGetActualModelsSection(
                ref context,
                IntPtr.Zero,
                buffer,
                (uint)buffer.Length,
                out uint actualSize,
                IntPtr.Zero))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "SetupDiGetActualModelsSectionW failed while reading the models section name.");
        }

        int length = (int)Math.Min(actualSize == 0 ? requiredSize : actualSize, (uint)buffer.Length);
        string section = new string(buffer, 0, length).TrimEnd('\0');

        return section.Length == 0 ? null : section;
    }

    /// <summary>
    /// Walks one native models section and matches field 2 onwards (hardware id, then compatible ids) as
    /// exact USB VID_05C6/PID_9008 strings. Descriptions and install-section names are never matched.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static bool SectionDeclaresTargetModel(IntPtr infHandle, string modelsSection)
    {
        var context = default(InfContext);

        if (!SetupFindFirstLine(infHandle, modelsSection, null, ref context))
        {
            if (IsOrdinaryLookupMiss(Marshal.GetLastWin32Error()))
            {
                return false;
            }

            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"SetupFindFirstLineW failed for the models section '{modelsSection}'.");
        }

        while (true)
        {
            uint fieldCount = SetupGetFieldCount(ref context);

            // SetupGetFieldCount counts the value fields only (field 0 is the key), and field indexes are
            // one-based, so the hardware ID and every compatible ID live at 2..fieldCount inclusive.
            for (uint fieldIndex = 2; fieldIndex <= fieldCount; fieldIndex++)
            {
                string? hardwareId = ReadStringField(ref context, fieldIndex);

                if (IsTargetUsbHardwareId(hardwareId))
                {
                    return true;
                }
            }

            var next = default(InfContext);

            if (!SetupFindNextLine(ref context, ref next))
            {
                if (IsOrdinaryLookupMiss(Marshal.GetLastWin32Error()))
                {
                    return false;
                }

                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    $"SetupFindNextLine failed in the models section '{modelsSection}'.");
            }

            context = next;
        }
    }

    [SupportedOSPlatform("windows")]
    private static string? ReadStringField(ref InfContext context, uint fieldIndex)
    {
        bool sized = SetupGetStringField(ref context, fieldIndex, null, 0, out uint requiredSize);

        if (!sized)
        {
            int error = Marshal.GetLastWin32Error();

            if (error != ErrorInsufficientBuffer)
            {
                throw new Win32Exception(error, "SetupGetStringFieldW failed while sizing an INF field.");
            }

            if (requiredSize == 0)
            {
                throw new Win32Exception(error, "SetupGetStringFieldW reported no size for an INF field.");
            }
        }

        if (requiredSize == 0 || requiredSize > MaxInfFieldChars)
        {
            return null;
        }

        var buffer = new char[requiredSize];

        if (!SetupGetStringField(ref context, fieldIndex, buffer, (uint)buffer.Length, out uint actualSize))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "SetupGetStringFieldW failed while reading an INF field.");
        }

        int length = (int)Math.Min(actualSize == 0 ? requiredSize : actualSize, (uint)buffer.Length);

        return new string(buffer, 0, length).TrimEnd('\0');
    }

    /// <summary>Reads the <c>DriverVer</c> value of [Version] and keeps only its version half.</summary>
    [SupportedOSPlatform("windows")]
    private static string? ReadDriverVer(IntPtr infHandle)
    {
        var context = default(InfContext);

        if (!SetupFindFirstLine(infHandle, VersionSectionName, DriverVerFieldName, ref context))
        {
            return null;
        }

        // SetupAPI already splits "DriverVer=date,version" into fields: 1 is the date, 2 is the version.
        string? value = ReadStringField(ref context, 2);

        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        string version = value.Trim();

        return version.Length == 0 ? null : version;
    }

    /// <summary>
    /// Maps the published INF to its DriverStore location. This only locates the package; it does not prove
    /// that the package is staged, which is why the store INF is verified separately.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static string GetDriverStoreLocation(string publishedInfName)
    {
        bool sized = SetupGetInfDriverStoreLocation(
            publishedInfName,
            IntPtr.Zero,
            null,
            null,
            0,
            out uint requiredSize);

        if (!sized)
        {
            int error = Marshal.GetLastWin32Error();

            if (error != ErrorInsufficientBuffer)
            {
                throw new Win32Exception(
                    error,
                    $"SetupGetInfDriverStoreLocationW failed for '{publishedInfName}'.");
            }

            if (requiredSize == 0)
            {
                throw new Win32Exception(
                    error,
                    $"SetupGetInfDriverStoreLocationW reported no size for '{publishedInfName}'.");
            }
        }

        if (requiredSize == 0 || requiredSize > MaxStorePathChars)
        {
            throw new InvalidOperationException(
                $"SetupGetInfDriverStoreLocationW did not report a usable store location for '{publishedInfName}'.");
        }

        var buffer = new char[requiredSize];

        if (!SetupGetInfDriverStoreLocation(
                publishedInfName,
                IntPtr.Zero,
                null,
                buffer,
                (uint)buffer.Length,
                out uint actualSize))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"SetupGetInfDriverStoreLocationW failed while reading the location of '{publishedInfName}'.");
        }

        int length = (int)Math.Min(actualSize == 0 ? requiredSize : actualSize, (uint)buffer.Length);
        string location = new string(buffer, 0, length).TrimEnd('\0');

        if (location.Length == 0)
        {
            throw new InvalidOperationException(
                $"SetupGetInfDriverStoreLocationW returned an empty location for '{publishedInfName}'.");
        }

        return location;
    }

    private static string DescribeSignatureRejection(
        bool verified,
        int nativeError,
        string digitalSigner,
        string catalogFile)
    {
        if (string.IsNullOrWhiteSpace(digitalSigner) || string.IsNullOrWhiteSpace(catalogFile))
        {
            return "SetupVerifyInfFileW returned "
                + (verified ? "success" : $"native error 0x{nativeError:X8}")
                + " without signer/catalog evidence; the package is not accepted.";
        }

        if (nativeError == ErrorAuthenticodeTrustNotEstablished)
        {
            return "The package signature is not trusted (ERROR_AUTHENTICODE_TRUST_NOT_ESTABLISHED, 0xE0000242).";
        }

        return $"SetupVerifyInfFileW failed with native error 0x{nativeError:X8} ({nativeError}).";
    }

    /// <summary>
    /// One read-only pass over the present USB devices, keeping the device information element of every
    /// instance that <see cref="WindowsEdlEndpointDiscovery"/> reported. This mirrors that discovery instead
    /// of re-identifying devices, so the binding examined is exactly the endpoint that was found.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void CollectEndpointBindings(
        IReadOnlyList<EdlEndpoint> endpoints,
        List<DriverEndpointEvidence> results)
    {
        if (endpoints.Count == 0)
        {
            return;
        }

        IntPtr deviceInfoSet = SetupDiGetClassDevs(
            IntPtr.Zero,
            UsbEnumerator,
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
            var wanted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            for (int index = 0; index < endpoints.Count; index++)
            {
                string? endpointId = endpoints[index].DeviceInstanceId;

                if (!string.IsNullOrEmpty(endpointId))
                {
                    wanted.Add(endpointId);
                }
            }

            var members = new Dictionary<string, SpDevInfoData>(StringComparer.OrdinalIgnoreCase);
            uint memberIndex = 0;

            while (true)
            {
                var deviceInfo = new SpDevInfoData
                {
                    CbSize = (uint)Marshal.SizeOf<SpDevInfoData>(),
                };

                if (!SetupDiEnumDeviceInfo(deviceInfoSet, memberIndex, ref deviceInfo))
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

                memberIndex++;

                string instanceId = ReadDeviceInstanceId(deviceInfoSet, ref deviceInfo);

                if (wanted.Contains(instanceId) && !members.ContainsKey(instanceId))
                {
                    members.Add(instanceId, deviceInfo);
                }
            }

            for (int index = 0; index < endpoints.Count; index++)
            {
                string instanceId = endpoints[index].DeviceInstanceId;

                if (string.IsNullOrEmpty(instanceId))
                {
                    results.Add(new DriverEndpointEvidence(
                        string.Empty,
                        null,
                        null,
                        0,
                        0,
                        false,
                        "An EDL endpoint was reported without a device instance identifier."));

                    continue;
                }

                if (members.TryGetValue(instanceId, out SpDevInfoData deviceInfo))
                {
                    results.Add(InspectEndpointBinding(deviceInfoSet, instanceId, ref deviceInfo));
                }
                else
                {
                    results.Add(new DriverEndpointEvidence(
                        instanceId,
                        null,
                        null,
                        0,
                        0,
                        false,
                        Bound($"Endpoint '{instanceId}' was no longer in the present device list.")));
                }
            }
        }
        finally
        {
            SetupDiDestroyDeviceInfoList(deviceInfoSet);
        }
    }

    /// <summary>
    /// One present endpoint, read-only: require a successful devnode status query, then read the bound
    /// service and the bound published INF. A read failure is recorded as an unknown binding, never as a
    /// healthy or a failed device.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static DriverEndpointEvidence InspectEndpointBinding(
        IntPtr deviceInfoSet,
        string instanceId,
        ref SpDevInfoData deviceInfo)
    {
        uint configRet = CM_Get_DevNode_Status(out uint status, out uint problem, deviceInfo.DevInst, 0);

        if (configRet != CrSuccess)
        {
            return new DriverEndpointEvidence(
                instanceId,
                null,
                null,
                0,
                0,
                false,
                Bound($"CM_Get_DevNode_Status failed for '{instanceId}' (CONFIGRET {configRet})."));
        }

        // pulProblemNumber is only meaningful when the node carries DN_HAS_PROBLEM.
        uint problemCode = (status & DnHasProblem) != 0 ? problem : 0;

        try
        {
            string? service = ReadDeviceService(deviceInfoSet, ref deviceInfo);
            string? boundInfName = ReadDeviceDriverInfPath(deviceInfoSet, ref deviceInfo);

            return new DriverEndpointEvidence(
                instanceId,
                NormalizeInfFileName(boundInfName),
                service,
                status,
                problemCode,
                true,
                null);
        }
        catch (Exception exception) when (exception is Win32Exception or InvalidOperationException)
        {
            return new DriverEndpointEvidence(
                instanceId,
                null,
                null,
                status,
                problemCode,
                true,
                Bound($"Device binding for '{instanceId}' could not be read: {exception.Message}"));
        }
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

        if (requiredSize > MaxStorePathChars)
        {
            throw new InvalidOperationException(
                $"SetupDiGetDeviceInstanceIdW reported an out-of-range instance id size ({requiredSize} characters).");
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
    /// SPDRP_SERVICE (REG_SZ) of the device node. An absent property yields null so the caller reports a
    /// service mismatch rather than an unreadable binding.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static string? ReadDeviceService(IntPtr deviceInfoSet, ref SpDevInfoData deviceInfo)
    {
        bool sized = SetupDiGetDeviceRegistryProperty(
            deviceInfoSet,
            ref deviceInfo,
            SpdrpService,
            out _,
            null,
            0,
            out uint requiredSize);

        if (!sized)
        {
            int error = Marshal.GetLastWin32Error();

            if (error is not (ErrorInsufficientBuffer or ErrorInvalidData or ErrorNotFound))
            {
                throw new Win32Exception(error, "SetupDiGetDeviceRegistryPropertyW failed while reading SPDRP_SERVICE.");
            }
        }

        if (requiredSize == 0 || requiredSize > MaxInfFieldChars)
        {
            return null;
        }

        var buffer = new byte[requiredSize];

        if (!SetupDiGetDeviceRegistryProperty(
                deviceInfoSet,
                ref deviceInfo,
                SpdrpService,
                out uint registryType,
                buffer,
                (uint)buffer.Length,
                out uint actualSize))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "SetupDiGetDeviceRegistryPropertyW failed while reading the device service.");
        }

        if (registryType != RegSz)
        {
            return null;
        }

        int byteCount = (int)Math.Min(actualSize == 0 ? requiredSize : actualSize, (uint)buffer.Length);

        return Encoding.Unicode.GetString(buffer, 0, byteCount).TrimEnd('\0');
    }

    /// <summary>
    /// DEVPKEY_Device_DriverInfPath (a published INF name). A missing property yields null; a non-string
    /// value is a read failure, because a different property must never be substituted.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static string? ReadDeviceDriverInfPath(IntPtr deviceInfoSet, ref SpDevInfoData deviceInfo)
    {
        DevPropKey key = DriverInfPathKey;

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

            if (error == ErrorNotFound)
            {
                return null;
            }

            if (error != ErrorInsufficientBuffer)
            {
                throw new Win32Exception(
                    error,
                    "SetupDiGetDevicePropertyW failed while sizing DEVPKEY_Device_DriverInfPath.");
            }
        }

        if (requiredSize == 0 || requiredSize > MaxStorePathChars)
        {
            return null;
        }

        var buffer = new byte[requiredSize];

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
                "SetupDiGetDevicePropertyW failed while reading DEVPKEY_Device_DriverInfPath.");
        }

        if (propertyType != DevPropTypeString)
        {
            throw new InvalidOperationException(
                $"DEVPKEY_Device_DriverInfPath has property type {propertyType}, expected a string.");
        }

        int byteCount = (int)Math.Min(actualSize == 0 ? requiredSize : actualSize, (uint)buffer.Length);

        return Encoding.Unicode.GetString(buffer, 0, byteCount).TrimEnd('\0');
    }

    private static bool IsOrdinaryLookupMiss(int error) =>
        error == ErrorSectionNotFound || error == ErrorLineNotFound;
}
