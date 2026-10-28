using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace FreedomInstaller.Core;

/// <summary>
/// The real Windows raw-card write target: binds one exact TF card seen by the host reader to a raw whole
/// disk handle, locks and dismounts every volume that lives on that disk, and then serves the bounded
/// sector-aligned reads and writes the common card writer drives it with.
/// <para>
/// This is a card target only. It never performs an EDL/UFS operation, never formats or partitions, never
/// runs PowerShell, diskpart or a helper executable, and never falls back to an ordinary file when the
/// platform or the administrator context is missing: an unsupported platform throws
/// <see cref="PlatformNotSupportedException"/> and a non-administrator process throws
/// <see cref="UnauthorizedAccessException"/> before any native access happens.
/// </para>
/// <para>
/// The pure policy decisions (candidate selection, protected-disk refusal, aligned range arithmetic) live
/// in <see cref="WindowsTfDiskSafety"/> and are called by this class before any native IO; the offline tests
/// exercise exactly that shared policy. The native CreateFile, IOCTL and volume-lock behaviour itself is
/// only executable on a real Windows administrator session and is not claimed to be physically tested here.
/// </para>
/// </summary>
public sealed class WindowsTfCardWriteTarget : ITfCardWriteTarget
{
    // ---- fixed Win32 constants (fileapi.h / winioctl.h) ----

    private const int GenericRead = unchecked((int)0x80000000);

    private const int GenericWrite = unchecked((int)0x40000000);

    private const int FileShareReadWrite = 0x00000001 | 0x00000002;

    private const int OpenExisting = 3;

    private const int FileAttributeNormal = 0x00000080;

    private const uint FileDeviceDisk = 0x00000007;

    private const uint IoctlStorageGetDeviceNumber = 0x002D1080;

    private const uint IoctlDiskGetDriveGeometryEx = 0x000700A0;

    private const uint IoctlVolumeGetVolumeDiskExtents = 0x00560000;

    private const uint FsctlLockVolume = 0x00090018;

    private const uint FsctlDismountVolume = 0x00090020;

    private const uint IoctlDiskUpdateProperties = 0x00070140;

    private const int ErrorNoMoreItems = 259;

    private const int ErrorMoreData = 234;

    /// <summary>StorageDeviceNumber layout: device type, number, partition, four bytes each.</summary>
    private const int StorageDeviceNumberBytes = 12;

    /// <summary>DISK_GEOMETRY_EX minimum: DISK_GEOMETRY (24, BytesPerSector at +20) + signed DiskSize at +24.</summary>
    private const int DiskGeometryExBytes = 32;

    /// <summary>VOLUME_DISK_EXTENTS header is 4 used bytes; the DISK_EXTENT array begins at offset 8 on win-x64, each extent is 24 bytes.</summary>
    private const int DiskExtentsHeaderBytes = 8;

    private const int DiskExtentBytes = 24;

    /// <summary>Bound for the variable-sized extents buffer: 64 extents fit in 8 + 64*24 = 1544 bytes.</summary>
    private const int MaxExtentsCount = 64;

    private const int MaxExtentsBufferBytes = DiskExtentsHeaderBytes + MaxExtentsCount * DiskExtentBytes;

    /// <summary>A volume GUID path \\?\Volume{guid}\ needs at most 50 chars; the buffer stays well above that.</summary>
    private const int VolumeGuidBufferChars = 100;

    private const string BindingDomainTag = "freedom-installer.windows-tf-disk-binding.v1";

    private static readonly IntPtr InvalidHandleValue = new(-1);

    // ---- native interop ----

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string filename,
        int desiredAccess,
        int shareMode,
        IntPtr securityAttributes,
        int creationDisposition,
        int flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", EntryPoint = "DeviceIoControl", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        SafeFileHandle device,
        uint ioControlCode,
        IntPtr inBuffer,
        uint inBufferSize,
        byte[]? outBuffer,
        uint outBufferSize,
        out uint bytesReturned,
        IntPtr overlapped);

    [DllImport("kernel32.dll", EntryPoint = "GetVolumePathNameW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumePathName(
        string fileName,
        StringBuilder volumePathName,
        uint bufferLength);

    [DllImport("kernel32.dll", EntryPoint = "GetVolumeNameForVolumeMountPointW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeNameForVolumeMountPoint(
        string volumeMountPoint,
        StringBuilder volumeName,
        uint bufferLength);

    [DllImport("kernel32.dll", EntryPoint = "FindFirstVolumeW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindFirstVolume(StringBuilder volumeName, uint bufferLength);

    [DllImport("kernel32.dll", EntryPoint = "FindNextVolumeW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindNextVolume(IntPtr findVolume, StringBuilder volumeName, uint bufferLength);

    [DllImport("kernel32.dll", EntryPoint = "FindVolumeClose", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindVolumeClose(IntPtr findVolume);

    [StructLayout(LayoutKind.Sequential)]
    private readonly record struct NativeDiskIdentity(uint DeviceType, uint DeviceNumber);

    private sealed record LockedVolume(string VolumePath, SafeFileHandle Handle);

    // ---- bound state ----

    private readonly TfCardCandidate _boundCandidate;

    private readonly ICommandRunner _runner;

    private readonly SafeFileHandle _diskHandle;

    private readonly FileStream _diskStream;

    private readonly SemaphoreSlim _ioSemaphore = new(1, 1);

    private readonly List<LockedVolume> _lockedVolumes;

    private readonly TfCardTargetIdentity _identity;

    private readonly int _deviceNumber;

    private readonly long _diskBytes;

    private readonly int _sectorSize;

    private long _disposed;

    private bool _bytesWritten;

    private WindowsTfCardWriteTarget(
        TfCardCandidate boundCandidate,
        ICommandRunner runner,
        SafeFileHandle diskHandle,
        List<LockedVolume> lockedVolumes,
        TfCardTargetIdentity identity,
        int deviceNumber,
        long diskBytes,
        int sectorSize)
    {
        _boundCandidate = boundCandidate;
        _runner = runner;
        _diskHandle = diskHandle;
        _lockedVolumes = lockedVolumes;
        _identity = identity;
        _deviceNumber = deviceNumber;
        _diskBytes = diskBytes;
        _sectorSize = sectorSize;
        _diskStream = new FileStream(
            diskHandle,
            FileAccess.ReadWrite,
            bufferSize: 1,
            isAsync: false);
    }

    /// <inheritdoc />
    public TfCardTargetIdentity Identity => _identity;

    /// <summary>
    /// Opens and binds the exact card the caller confirmed. The fixed reader discovery command runs fresh
    /// (no caller-supplied command fragments), the pure policy selects the one exact candidate, every
    /// protected local path is resolved to its volume and refused when it maps to the target disk, the
    /// native device number and geometry must match the candidate exactly, and every volume on the disk is
    /// locked and dismounted before the target is returned. The fresh inventory and native identity are
    /// re-checked after the locks and before the target is handed out.
    /// </summary>
    public static async Task<WindowsTfCardWriteTarget> OpenAsync(
        TfCardCandidate expected,
        IReadOnlyList<string> protectedPaths,
        ICommandRunner runner,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(protectedPaths);
        ArgumentNullException.ThrowIfNull(runner);

        RequireWindowsAdministrator();

        // 1. Fresh reader inventory through the one fixed discovery command, parsed by the one real parser.
        var selected = await RunFreshSelectionAsync(expected, runner, cancellationToken).ConfigureAwait(false);

        // 2. Resolve every protected path to the local disks it actually lives on, before the target is opened.
        var protectedResolutions = await Task.Run(
                () => ResolveProtectedPaths(protectedPaths, cancellationToken),
                cancellationToken)
            .ConfigureAwait(false);

        // 3. Open ONLY the exact fresh candidate's Windows disk-interface path, synchronous, read/write shared.
        cancellationToken.ThrowIfCancellationRequested();
        var (diskHandle, deviceNumber, sectorSize, diskBytes) = await Task.Run(
                () => OpenAndProbeDisk(selected),
                cancellationToken)
            .ConfigureAwait(false);

        var lockedVolumes = new List<LockedVolume>();
        try
        {
            // 4. The pure protected-disk policy, on the actual native device number.
            var selectedDiskNumber = RequireValidDiskNumber(deviceNumber.DeviceNumber, selected);
            WindowsTfDiskSafety.RequireUnprotectedDisk(selectedDiskNumber, CollectProtectedDiskNumbers(protectedResolutions));
            RequireNoProtectedPathOnDisk(protectedResolutions, selectedDiskNumber);

            // 5. Lock and dismount every volume that lives on this disk; the handles are held until disposal.
            lockedVolumes = await Task.Run(
                    () => LockVolumesOnDisk(deviceNumber.DeviceNumber),
                    cancellationToken)
                .ConfigureAwait(false);

            // 6. Re-run the same fresh inventory and the native identity comparison after the locks.
            var reselected = await RunFreshSelectionAsync(expected, runner, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(reselected.Path, selected.Path, StringComparison.Ordinal)
                || reselected.SizeBytes != selected.SizeBytes
                || reselected.LogicalSectorSize != selected.LogicalSectorSize)
            {
                throw new InvalidOperationException(
                    $"锁定卷之后读取器清单中的卡片身份发生变化（{reselected.Key}，{reselected.Path}），拒绝绑定。");
            }

            var reprobe = await Task.Run(
                    () => ProbeDisk(diskHandle, selected),
                    cancellationToken)
                .ConfigureAwait(false);
            if (reprobe.DeviceNumber != deviceNumber.DeviceNumber
                || reprobe.BytesPerSector != sectorSize
                || reprobe.DiskBytes != diskBytes)
            {
                throw new InvalidOperationException(
                    $"锁定卷之后磁盘 {selectedDiskNumber} 的原生身份或几何发生变化，拒绝绑定。");
            }

            // 7. Freeze the identity. The binding hashes stable disk identity fields, never the GPT bytes
            //    this operation is about to rewrite.
            var binding = ComputeBindingSha256(selected.Key, selected.Path, selectedDiskNumber, sectorSize, diskBytes);
            var identity = new TfCardTargetIdentity(
                TfCardSource.Reader,
                selected.Key,
                selected.Path,
                selected.SizeBytes,
                selected.LogicalSectorSize,
                binding);

            return new WindowsTfCardWriteTarget(
                selected,
                runner,
                diskHandle,
                lockedVolumes,
                identity,
                selectedDiskNumber,
                diskBytes,
                sectorSize);
        }
        catch
        {
            // A failed or cancelled attempt cleans only the resources this call opened.
            foreach (var locked in lockedVolumes)
            {
                locked.Handle.Dispose();
            }

            diskHandle.Dispose();
            throw;
        }
    }

    /// <inheritdoc />
    public async ValueTask<TfCardTargetIdentity> RevalidateAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        // Fresh eligible inventory: an unplugged or swapped card fails here instead of succeeding.
        await RunFreshSelectionAsync(_boundCandidate, _runner, cancellationToken).ConfigureAwait(false);

        await _ioSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var probe = await Task.Run(() => ProbeDisk(_diskHandle, _boundCandidate), cancellationToken)
                .ConfigureAwait(false);

            if (probe.DeviceNumber != (uint)_deviceNumber
                || probe.BytesPerSector != _sectorSize
                || probe.DiskBytes != _diskBytes)
            {
                throw new InvalidOperationException(
                    $"TF 卡 {_identity.Key} 的原生磁盘号或几何与绑定身份不一致（磁盘号 {probe.DeviceNumber}，{probe.BytesPerSector} 字节扇区，{probe.DiskBytes} 字节），拒绝报告就绪。");
            }

            // The actual bound facts; every field was just re-proven against the live disk.
            return _identity;
        }
        finally
        {
            _ioSemaphore.Release();
        }
    }

    /// <inheritdoc />
    public async ValueTask ReadExactlyAsync(long offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        WindowsTfDiskSafety.RequireAlignedRange(_diskBytes, _sectorSize, offset, buffer.Length);

        await _ioSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await Task.Run(() => ReadExactlyCore(offset, buffer, cancellationToken), cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _ioSemaphore.Release();
        }
    }

    /// <inheritdoc />
    public async ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        WindowsTfDiskSafety.RequireAlignedRange(_diskBytes, _sectorSize, offset, buffer.Length);

        await _ioSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // From the first attempted byte on, disposal must refresh the partition view even if this
            // write fails midway, because some bytes may already have reached the medium.
            _bytesWritten = true;
            await Task.Run(() => WriteCore(offset, buffer, cancellationToken), cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _ioSemaphore.Release();
        }
    }

    /// <inheritdoc />
    public async ValueTask FlushAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        await _ioSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // FileStream.Flush(true) issues FlushFileBuffers: the call returns only after the card's own
            // storage acknowledged the bytes. No boot/EDL operation exists on this path.
            await Task.Run(() => _diskStream.Flush(flushToDisk: true), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ioSemaphore.Release();
        }
    }

    /// <summary>
    /// Idempotent disposal. Once bytes were written, the disk's Windows partition view is refreshed through
    /// IOCTL_DISK_UPDATE_PROPERTIES <b>before</b> the volume locks are released, so Windows cannot keep an
    /// obsolete writable filesystem layout of this card. Every owned handle is closed even when an earlier
    /// cleanup step fails, and unexpected cleanup errors are reported instead of silently swallowed.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        List<Exception>? cleanupErrors = null;

        if (_bytesWritten)
        {
            try
            {
                await Task.Run(RefreshDiskProperties).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                cleanupErrors ??= new List<Exception>();
                cleanupErrors.Add(exception);
            }
        }

        foreach (var locked in _lockedVolumes)
        {
            try
            {
                locked.Handle.Dispose();
            }
            catch (Exception exception)
            {
                cleanupErrors ??= new List<Exception>();
                cleanupErrors.Add(exception);
            }
        }

        _lockedVolumes.Clear();

        try
        {
            // Closing the stream closes the owned disk SafeFileHandle and releases the acquired locks.
            _diskStream.Dispose();
        }
        catch (Exception exception)
        {
            cleanupErrors ??= new List<Exception>();
            cleanupErrors.Add(exception);
        }

        _ioSemaphore.Dispose();

        if (cleanupErrors is not null)
        {
            throw new AggregateException(
                "释放 Windows TF 卡写入目标时出现未预期的清理错误；所有已拥有的句柄均已关闭。",
                cleanupErrors);
        }
    }

    // ---- open helpers ----

    private static void RequireWindowsAdministrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Windows TF 卡原始写入目标使用 Windows 设备 IOCTL 和卷锁，只能在 Windows 上运行；拒绝静默回退到普通文件写入。");
        }

        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            throw new UnauthorizedAccessException(
                "Windows TF 卡原始写入需要以管理员身份运行的进程；当前进程没有管理员令牌，拒绝访问原始磁盘。");
        }
    }

    /// <summary>
    /// Runs the fixed reader discovery command once, requires exit code 0, parses the report with the one
    /// real reader parser and applies the pure selection policy. No caller-supplied command fragment is
    /// ever involved, and a failed query is an error rather than a silent substitution.
    /// </summary>
    private static async Task<TfCardCandidate> RunFreshSelectionAsync(
        TfCardCandidate expected,
        ICommandRunner runner,
        CancellationToken cancellationToken)
    {
        var result = await runner
            .RunAsync(TfCardDiscovery.BuildReaderCommand(), cancellationToken)
            .ConfigureAwait(false);

        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"读取器 TF 卡清单查询失败（退出码 {result.ExitCode}）：{DescribeDiagnostic(result)}；拒绝用旧清单或猜测代替新清单。");
        }

        IReadOnlyList<TfCardCandidate> fresh;
        try
        {
            fresh = TfCardSupport.ParseCandidates(result.StandardOutput, TfCardSource.Reader);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidOperationException("读取器 TF 卡清单无法解析为合法候选列表，拒绝继续。", exception);
        }

        return WindowsTfDiskSafety.Select(expected, fresh);
    }

    private static string DescribeDiagnostic(ProcessResult result)
    {
        var error = result.StandardError.Trim();
        if (error.Length > 0)
        {
            return error;
        }

        var output = result.StandardOutput.Trim();
        return output.Length > 0 ? output : "（命令没有输出任何诊断信息）";
    }

    [SupportedOSPlatform("windows")]
    private static SafeFileHandle OpenRawHandle(string devicePath, int desiredAccess, string what)
    {
        var handle = CreateFile(
            devicePath,
            desiredAccess,
            FileShareReadWrite,
            IntPtr.Zero,
            OpenExisting,
            FileAttributeNormal,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"无法打开{what}「{devicePath}」（只接受已存在的设备，绝不创建或截断路径）。");
        }

        return handle;
    }

    [SupportedOSPlatform("windows")]
    private static NativeDiskIdentity QueryStorageDeviceNumber(SafeFileHandle disk)
    {
        var buffer = new byte[StorageDeviceNumberBytes];
        if (!DeviceIoControl(
                disk,
                IoctlStorageGetDeviceNumber,
                IntPtr.Zero,
                0,
                buffer,
                (uint)buffer.Length,
                out var returned,
                IntPtr.Zero))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "IOCTL_STORAGE_GET_DEVICE_NUMBER 查询失败，无法确认目标磁盘编号。");
        }

        if (returned < StorageDeviceNumberBytes)
        {
            throw new IOException(
                $"IOCTL_STORAGE_GET_DEVICE_NUMBER 只返回了 {returned} 字节，小于结构体要求的 {StorageDeviceNumberBytes} 字节，拒绝信任不完整的原生结果。");
        }

        var deviceType = BitConverter.ToUInt32(buffer, 0);
        if (deviceType != FileDeviceDisk)
        {
            throw new InvalidOperationException(
                $"打开的设备类型 {deviceType} 不是 FILE_DEVICE_DISK（{FileDeviceDisk}），拒绝当作整盘目标。");
        }

        // STORAGE_DEVICE_NUMBER.PartitionNumber at +8: a whole-disk FDO reports exactly 0 (a partition
        // reports its index). Anything else — including uint.MaxValue — is never a whole-disk fallback.
        var partitionNumber = BitConverter.ToUInt32(buffer, 8);
        if (partitionNumber != 0)
        {
            throw new InvalidOperationException(
                $"打开的设备报告分区号 {partitionNumber} 而不是整盘的 0，拒绝把分区设备当作写入目标。");
        }

        return new NativeDiskIdentity(deviceType, BitConverter.ToUInt32(buffer, 4));
    }

    private readonly record struct DiskProbe(uint DeviceNumber, int BytesPerSector, long DiskBytes);

    /// <summary>
    /// Queries the extended drive geometry with a comfortable buffer and requires the actual
    /// bytes-per-sector (DISK_GEOMETRY +20) and signed disk size (+24) to exactly match the fresh
    /// candidate. The returned length is validated: an undersized buffer is never trusted.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static DiskProbe ProbeDisk(SafeFileHandle disk, TfCardCandidate candidate)
    {
        // Drivers may legitimately return more than the 32-byte struct minimum (the Data[] tail), so the
        // buffer is comfortable and only the returned length is validated against the struct minimum.
        var buffer = new byte[256];
        if (!DeviceIoControl(
                disk,
                IoctlDiskGetDriveGeometryEx,
                IntPtr.Zero,
                0,
                buffer,
                (uint)buffer.Length,
                out var returned,
                IntPtr.Zero))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "IOCTL_DISK_GET_DRIVE_GEOMETRY_EX 查询失败，无法确认磁盘几何。");
        }

        if (returned < DiskGeometryExBytes)
        {
            throw new IOException(
                $"IOCTL_DISK_GET_DRIVE_GEOMETRY_EX 只返回了 {returned} 字节，小于结构体要求的 {DiskGeometryExBytes} 字节，拒绝信任不完整的原生结果。");
        }

        var bytesPerSector = BitConverter.ToUInt32(buffer, 20);
        var diskSize = BitConverter.ToInt64(buffer, 24);

        if (bytesPerSector != 512 && bytesPerSector != 4096)
        {
            throw new InvalidOperationException(
                $"磁盘 {candidate.Path} 的实际扇区大小 {bytesPerSector} 不是 512 或 4096，拒绝绑定。");
        }

        if (diskSize <= 0)
        {
            throw new InvalidOperationException(
                $"磁盘 {candidate.Path} 的实际容量 {diskSize} 不是正数，拒绝绑定。");
        }

        if (bytesPerSector != candidate.LogicalSectorSize)
        {
            throw new InvalidOperationException(
                $"磁盘 {candidate.Path} 的实际扇区大小 {bytesPerSector} 与清单报告的 {candidate.LogicalSectorSize} 不一致，拒绝绑定。");
        }

        if (diskSize != candidate.SizeBytes)
        {
            throw new InvalidOperationException(
                $"磁盘 {candidate.Path} 的实际容量 {diskSize} 字节与清单报告的 {candidate.SizeBytes} 字节不一致，拒绝绑定。");
        }

        return new DiskProbe(QueryStorageDeviceNumber(disk).DeviceNumber, (int)bytesPerSector, diskSize);
    }

    [SupportedOSPlatform("windows")]
    private static (SafeFileHandle Handle, NativeDiskIdentity DeviceNumber, int BytesPerSector, long DiskBytes)
        OpenAndProbeDisk(TfCardCandidate selected)
    {
        // The device path comes from Get-Disk itself and may be a disk-interface namespace path; no user
        // text is ever concatenated into it, and OPEN_EXISTING can never create or truncate anything.
        var handle = OpenRawHandle(selected.Path, GenericRead | GenericWrite, "TF 卡整盘设备");
        try
        {
            var probe = ProbeDisk(handle, selected);
            return (handle, new NativeDiskIdentity(FileDeviceDisk, probe.DeviceNumber), probe.BytesPerSector, probe.DiskBytes);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static int RequireValidDiskNumber(uint deviceNumber, TfCardCandidate selected)
    {
        if (deviceNumber > int.MaxValue)
        {
            throw new IOException(
                $"卡片 {selected.Key} 的磁盘编号 {deviceNumber} 超出可校验范围，拒绝继续。");
        }

        return (int)deviceNumber;
    }

    // ---- protected path resolution ----

    private sealed record ProtectedPathResolution(string Path, IReadOnlyList<uint> DiskNumbers);

    /// <summary>
    /// Resolves every protected local path (following reparse points, or its nearest existing parent for a
    /// future output) to the local disk numbers its volume spans. A UNC target — direct or reached through a
    /// reparse redirect — only resolves to an empty list when its server is PROVEN remote; a local server or
    /// alias refuses. An unresolved local path refuses.
    /// </summary>
    private static List<ProtectedPathResolution> ResolveProtectedPaths(
        IReadOnlyList<string> protectedPaths,
        CancellationToken cancellationToken)
    {
        var resolutions = new List<ProtectedPathResolution>();

        foreach (var rawPath in protectedPaths)
        {
            if (string.IsNullOrWhiteSpace(rawPath))
            {
                throw new ArgumentException("受保护路径列表中存在空白路径，无法确认其不在目标磁盘上，拒绝继续。");
            }

            resolutions.Add(new ProtectedPathResolution(
                rawPath.Trim(),
                ResolveLocalVolumeDiskNumbers(rawPath.Trim(), cancellationToken)));
        }

        return resolutions;
    }

    private static List<int> CollectProtectedDiskNumbers(List<ProtectedPathResolution> resolutions)
    {
        var numbers = new List<int>();
        foreach (var resolution in resolutions)
        {
            foreach (var diskNumber in resolution.DiskNumbers)
            {
                if (diskNumber <= int.MaxValue && !numbers.Contains((int)diskNumber))
                {
                    numbers.Add((int)diskNumber);
                }
            }
        }

        return numbers;
    }

    private static void RequireNoProtectedPathOnDisk(List<ProtectedPathResolution> resolutions, int selectedDiskNumber)
    {
        foreach (var resolution in resolutions)
        {
            if (resolution.DiskNumbers.Any(diskNumber => diskNumber == (uint)selectedDiskNumber))
            {
                throw new InvalidOperationException(
                    $"受保护路径「{resolution.Path}」位于选中的目标磁盘 {selectedDiskNumber} 上，拒绝把该磁盘作为写入目标。");
            }
        }
    }

    private static bool IsRemotePath(string path)
    {
        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (path.StartsWith(@"\\?\") || path.StartsWith(@"\\."))
        {
            // Local device namespace and volume GUID paths are local by construction.
            return false;
        }

        return path.StartsWith(@"\\");
    }

    /// <summary>
    /// Follows reparse points to the final local target with a bounded hop count; a redirection that cannot
    /// be resolved surfaces instead of being ignored.
    /// </summary>
    private static string ResolveReparseTargets(string path)
    {
        var current = path;

        for (var hop = 0; hop < 16; hop++)
        {
            FileSystemInfo info = Directory.Exists(current) ? new DirectoryInfo(current) : new FileInfo(current);
            var target = info.LinkTarget;

            if (string.IsNullOrEmpty(target))
            {
                return current;
            }

            current = Path.IsPathRooted(target)
                ? target
                : Path.GetFullPath(Path.Combine(Path.GetDirectoryName(current) ?? string.Empty, target));

            if (IsRemotePath(current))
            {
                return current;
            }
        }

        throw new IOException($"受保护路径「{path}」的符号链接层级超过 16 层，拒绝在无法确认最终位置时继续。");
    }

    /// <summary>
    /// Hard bound for the private DNS resolution used to prove a UNC server is remote. The resolve never
    /// waits longer than this, and a timeout, a resolution error or an undecidable result refuses the
    /// protected path instead of skipping it.
    /// </summary>
    private static readonly TimeSpan UncRemoteProofDnsTimeout = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Splits an ordinary (<c>\\server\share\…</c>) or extended (<c>\\?\UNC\server\share\…</c>) UNC path
    /// into its server and first share segment. A UNC path without an explicit share is not accepted.
    /// </summary>
    private static bool TryGetUncServerShare(string path, out string server, out string share)
    {
        server = string.Empty;
        share = string.Empty;

        string rest;
        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            rest = path.Substring(8);
        }
        else if (path.StartsWith(@"\\", StringComparison.Ordinal))
        {
            rest = path.Substring(2);
        }
        else
        {
            return false;
        }

        var segments = rest.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length < 2 || segments[0].Length == 0 || segments[1].Length == 0)
        {
            return false;
        }

        server = segments[0];
        share = segments[1];
        return true;
    }

    private static bool IsLocalServerName(string server)
    {
        var name = server.TrimEnd('.');

        return name.Length > 0
            && (string.Equals(name, "localhost", StringComparison.OrdinalIgnoreCase)
                || name.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, Environment.MachineName, StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, Dns.GetHostName(), StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// True only for loopback addresses and the host's own NetworkInterface unicast addresses; both sides
    /// are normalized so an IPv4-mapped IPv6 form can never masquerade as a different address.
    /// </summary>
    private static bool IsLocalIpAddress(IPAddress address)
    {
        var candidate = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        if (IPAddress.IsLoopback(candidate))
        {
            return true;
        }

        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            foreach (var unicast in networkInterface.GetIPProperties().UnicastAddresses)
            {
                var local = unicast.Address.IsIPv4MappedToIPv6 ? unicast.Address.MapToIPv4() : unicast.Address;
                if (candidate.Equals(local))
                {
                    return true;
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Proves a UNC server is NOT this host: a literal address is compared directly, a name is resolved
    /// with a bounded DNS query. Any unresolved name, timeout, resolution error or local-interface
    /// enumeration failure refuses the path (fail closed) instead of treating the server as remote.
    /// </summary>
    private static bool ResolvesToLocalAddress(string server, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (IPAddress.TryParse(server, out var literal))
        {
            try
            {
                return IsLocalIpAddress(literal);
            }
            catch (NetworkInformationException exception)
            {
                throw new IOException(
                    $"无法枚举本机网络接口来证明服务器「{server}」不在本机，拒绝继续。", exception);
            }
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(UncRemoteProofDnsTimeout);

        Task<IPAddress[]> resolveTask;
        try
        {
            resolveTask = Dns.GetHostAddressesAsync(server, timeout.Token);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            throw new IOException(
                $"解析受保护路径的服务器名「{server}」失败，无法证明其不在本机，拒绝继续。", exception);
        }

        try
        {
            resolveTask.Wait(timeout.Token);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw new IOException(
                $"解析受保护路径的服务器名「{server}」超过 {UncRemoteProofDnsTimeout.TotalSeconds:0} 秒仍未完成，无法证明其不在本机，拒绝继续。");
        }
        catch (AggregateException exception)
        {
            throw new IOException(
                $"解析受保护路径的服务器名「{server}」失败，无法证明其不在本机，拒绝继续。", exception);
        }

        try
        {
            foreach (var address in resolveTask.Result)
            {
                if (IsLocalIpAddress(address))
                {
                    return true;
                }
            }
        }
        catch (NetworkInformationException exception)
        {
            throw new IOException(
                $"无法枚举本机网络接口来证明服务器「{server}」不在本机，拒绝继续。", exception);
        }

        return false;
    }

    /// <summary>
    /// A protected path that resolves to UNC is skipped only when its server is PROVEN remote. A server
    /// name or address that matches this machine — or one whose remoteness cannot be proven — is refused
    /// with a demand for the fully qualified local path, never silently treated as remote.
    /// </summary>
    private static void RequireProvenRemoteUncServer(
        string resolvedPath,
        string originalPath,
        CancellationToken cancellationToken)
    {
        if (!TryGetUncServerShare(resolvedPath, out var server, out var share))
        {
            throw new IOException(
                $"受保护路径「{originalPath}」解析为无法拆分服务器/共享名的 UNC 路径「{resolvedPath}」，无法证明其不在本机磁盘上，拒绝继续。");
        }

        var local = IsLocalServerName(server) || ResolvesToLocalAddress(server, cancellationToken);
        if (local)
        {
            throw new InvalidOperationException(
                $"受保护路径「{originalPath}」通过服务器「{server}」的共享「{share}」指向本机，该路径可能落在本机磁盘上；请改用其完全限定的本机路径，而不是 UNC 别名。");
        }
    }

    /// <summary>
    /// Resolves one protected path to the disk numbers of the volume it lives on, through
    /// GetVolumePathNameW / GetVolumeNameForVolumeMountPointW and a read-only volume handle. A failed local
    /// resolution or an unreadable volume mapping is an error, never an ignored warning.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<uint> ResolveLocalVolumeDiskNumbers(string protectedPath, CancellationToken cancellationToken)
    {
        var resolved = ResolveReparseTargets(protectedPath);

        if (IsRemotePath(resolved))
        {
            // Only a UNC server proven remote may skip this host's local volume mapping; a local server,
            // alias or undecidable case refuses (this also covers a reparse redirect to UNC).
            RequireProvenRemoteUncServer(resolved, protectedPath, cancellationToken);
            return Array.Empty<uint>();
        }

        if (!Path.IsPathFullyQualified(resolved))
        {
            throw new ArgumentException(
                $"受保护路径「{protectedPath}」不是完全限定的绝对路径，无法确认其不在目标磁盘上，拒绝继续。",
                nameof(protectedPath));
        }

        var mountPointBuffer = new StringBuilder(Math.Max(256, checked(resolved.Length + 2)));
        if (!GetVolumePathName(resolved, mountPointBuffer, (uint)mountPointBuffer.Capacity))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"无法把受保护路径「{protectedPath}」解析到本机卷，拒绝在未确认安全前继续。");
        }

        var mountPoint = mountPointBuffer.ToString();
        if (string.IsNullOrEmpty(mountPoint))
        {
            throw new IOException($"受保护路径「{protectedPath}」解析得到的卷装载点为空，拒绝继续。");
        }

        var volumeBuffer = new StringBuilder(VolumeGuidBufferChars);
        if (!GetVolumeNameForVolumeMountPoint(mountPoint, volumeBuffer, (uint)volumeBuffer.Capacity))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"无法把卷装载点「{mountPoint}」解析为卷 GUID 路径，拒绝继续。");
        }

        var volumeDevicePath = volumeBuffer.ToString().TrimEnd('\\');
        using var volume = OpenRawHandle(volumeDevicePath, GenericRead, $"受保护路径「{protectedPath}」所在的卷");
        return QueryVolumeDiskExtents(volume);
    }

    // ---- volume extents, enumeration and locking ----

    /// <summary>
    /// Queries IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS with a bounded, grown-on-demand buffer and parses the
    /// DISK_EXTENT array (beginning at offset 8, 24 bytes each on win-x64) only after the returned length
    /// is proven to cover it.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<uint> QueryVolumeDiskExtents(SafeFileHandle volume)
    {
        var size = 256;
        while (true)
        {
            var buffer = new byte[size];
            if (DeviceIoControl(
                    volume,
                    IoctlVolumeGetVolumeDiskExtents,
                    IntPtr.Zero,
                    0,
                    buffer,
                    (uint)buffer.Length,
                    out var returned,
                    IntPtr.Zero))
            {
                if (returned < sizeof(uint))
                {
                    throw new IOException(
                        $"IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS 只返回了 {returned} 字节，无法读取范围数量，拒绝猜测。");
                }

                var count = BitConverter.ToUInt32(buffer, 0);
                if (count > MaxExtentsCount)
                {
                    throw new IOException(
                        $"卷声称有 {count} 个磁盘范围，超过校验上限 {MaxExtentsCount}，拒绝按不可信的原生长度分配内存。");
                }

                var needed = DiskExtentsHeaderBytes + checked((int)count * DiskExtentBytes);
                if (returned < needed)
                {
                    throw new IOException(
                        $"IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS 返回 {returned} 字节，不足以容纳 {count} 个范围（需要 {needed} 字节），拒绝信任不完整的结果。");
                }

                var diskNumbers = new List<uint>((int)count);
                for (var index = 0; index < count; index++)
                {
                    diskNumbers.Add(BitConverter.ToUInt32(buffer, DiskExtentsHeaderBytes + index * DiskExtentBytes));
                }

                return diskNumbers;
            }

            var error = Marshal.GetLastWin32Error();
            if (error != ErrorMoreData || size >= MaxExtentsBufferBytes)
            {
                throw new Win32Exception(error, "IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS 查询失败，无法映射卷到磁盘。");
            }

            size = checked(size * 2);
        }
    }

    [SupportedOSPlatform("windows")]
    private static List<string> EnumerateLocalVolumePaths()
    {
        var volumes = new List<string>();
        var buffer = new StringBuilder(VolumeGuidBufferChars);

        var find = FindFirstVolume(buffer, (uint)buffer.Capacity);
        if (find == InvalidHandleValue || find == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "FindFirstVolumeW 枚举本机卷失败。");
        }

        try
        {
            while (true)
            {
                volumes.Add(buffer.ToString());
                buffer.Clear();

                if (!FindNextVolume(find, buffer, (uint)buffer.Capacity))
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error == ErrorNoMoreItems)
                    {
                        break;
                    }

                    throw new Win32Exception(error, "FindNextVolumeW 枚举本机卷失败。");
                }
            }
        }
        finally
        {
            FindVolumeClose(find);
        }

        return volumes;
    }

    /// <summary>
    /// For every volume that touches the target disk: opens its own read-write handle, takes
    /// FSCTL_LOCK_VOLUME and then FSCTL_DISMOUNT_VOLUME, and keeps the handle (and therefore the lock) until
    /// disposal. A volume that cannot be mapped, locked or dismounted refuses the whole operation, and an
    /// earlier acquired lock is released when a later one fails.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static List<LockedVolume> LockVolumesOnDisk(uint targetDiskNumber)
    {
        var acquired = new List<LockedVolume>();

        try
        {
            foreach (var volumePath in EnumerateLocalVolumePaths())
            {
                var extentsPath = volumePath.TrimEnd('\\');
                if (extentsPath.Length == 0)
                {
                    continue;
                }

                SafeFileHandle? lockHandle = null;
                try
                {
                    using (var probeHandle = OpenRawHandle(extentsPath, GenericRead, $"卷 {volumePath}"))
                    {
                        var extents = QueryVolumeDiskExtents(probeHandle);
                        if (!extents.Any(diskNumber => diskNumber == targetDiskNumber))
                        {
                            continue;
                        }
                    }

                    lockHandle = OpenRawHandle(extentsPath, GenericRead | GenericWrite, $"目标盘上的卷 {volumePath}");

                    if (!DeviceIoControl(
                            lockHandle,
                            FsctlLockVolume,
                            IntPtr.Zero,
                            0,
                            null,
                            0,
                            out _,
                            IntPtr.Zero))
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            $"无法锁定目标盘上的卷 {volumePath}（FSCTL_LOCK_VOLUME 失败），拒绝在卷仍可被写入时继续。");
                    }

                    if (!DeviceIoControl(
                            lockHandle,
                            FsctlDismountVolume,
                            IntPtr.Zero,
                            0,
                            null,
                            0,
                            out _,
                            IntPtr.Zero))
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            $"无法卸载目标盘上的卷 {volumePath}（FSCTL_DISMOUNT_VOLUME 失败），拒绝继续。");
                    }

                    acquired.Add(new LockedVolume(volumePath, lockHandle));
                    lockHandle = null;
                }
                finally
                {
                    // Not acquired: close the handle now. Acquired: the lock lives until disposal.
                    lockHandle?.Dispose();
                }
            }
        }
        catch
        {
            // Cleanup earlier handles if a later lock failed.
            foreach (var locked in acquired)
            {
                locked.Handle.Dispose();
            }

            throw;
        }

        return acquired;
    }

    [SupportedOSPlatform("windows")]
    private void RefreshDiskProperties()
    {
        if (!DeviceIoControl(
                _diskHandle,
                IoctlDiskUpdateProperties,
                IntPtr.Zero,
                0,
                null,
                0,
                out _,
                IntPtr.Zero))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "IOCTL_DISK_UPDATE_PROPERTIES 刷新磁盘分区视图失败；Windows 可能保留旧的分区布局。");
        }
    }

    // ---- IO cores (worker thread, serialized) ----

    private void ReadExactlyCore(long offset, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        _diskStream.Seek(offset, SeekOrigin.Begin);

        var completed = 0;
        while (completed < buffer.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var read = _diskStream.Read(buffer.Span[completed..]);
            if (read <= 0)
            {
                throw new EndOfStreamException(
                    $"读取 TF 卡 {_identity.Key} 在偏移 {offset + completed} 处提前结束：需要 {buffer.Length} 字节，实际只读到 {completed} 字节，拒绝用零填充。");
            }

            completed += read;
        }
    }

    private void WriteCore(long offset, ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
    {
        _diskStream.Seek(offset, SeekOrigin.Begin);

        // FileStream.Write(ReadOnlySpan<byte>) returns void: it completes the whole span or throws.
        // A partial-count retry loop cannot exist here, and success is never invented after a throw.
        cancellationToken.ThrowIfCancellationRequested();
        _diskStream.Write(buffer.Span);
    }

    // ---- binding ----

    /// <summary>
    /// SHA256 over unambiguous stable disk identity fields (domain tag, fresh key and device path, native
    /// device number, sector size, capacity) — deliberately NOT over the GPT bytes this operation rewrites.
    /// </summary>
    private static string ComputeBindingSha256(string key, string devicePath, int deviceNumber, int sectorSize, long diskBytes)
    {
        var material = string.Join(
            "\n",
            BindingDomainTag,
            key,
            devicePath,
            deviceNumber.ToString(CultureInfo.InvariantCulture),
            sectorSize.ToString(CultureInfo.InvariantCulture),
            diskBytes.ToString(CultureInfo.InvariantCulture));

        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(material));
        return Convert.ToHexString(hash);
    }

    private void ThrowIfDisposed()
    {
        if (Interlocked.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(WindowsTfCardWriteTarget));
        }
    }
}
