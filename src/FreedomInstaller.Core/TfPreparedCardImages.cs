using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// A held-open, fully preflighted schema 2 TF-card raw package, captured by
/// <see cref="CaptureAsync"/>: the typed contract is re-read under held file handles, every held
/// artifact is rehashed against its declared length and SHA-256, both gzip raw images pass a
/// bounded expansion preflight (exact expanded length, whole-image SHA-256 and the real
/// ext4/Btrfs superblock geometry and UUID checks) and both DTBs are validated through
/// <see cref="EdlRawDtbValidator.ValidateTf"/> with the exact normal/diagnostic boot arguments.
/// <para>
/// The expanded images are never retained: each expansion streams through a bounded
/// <see cref="GZipStream"/> with a 1 MiB buffer and only the first 65684 bytes (the Btrfs window
/// 65536+148; the ext4 superblock sits at 1024+0x158 inside it) of each expansion are inspected.
/// No full raw image is allocated or written to disk, and no expansion directory is created.
/// </para>
/// <para>
/// This is the TF Prepared proof for the card writer. It is still not a device, write-success or
/// completion statement, and the optional maintenance initramfs is held and hashed as an ordinary
/// artifact only: that is never a RAM-initramfs or boot-budget readiness proof. On any failure the
/// capture closes exactly the handles this instance opened; caller files are never deleted.
/// </para>
/// </summary>
public sealed class TfPreparedCardImages : IDisposable
{
    private const string TfRawDeploymentKind = "tf-raw-v1";

    private const string DtbNormalRole = "dtb-normal";

    private const string DtbDiagnosticRole = "dtb-diagnostic";

    /// <summary>The DTB size bound shared with the boot builder (8 MiB).</summary>
    private const long MaxDtbBytes = 8 * 1024 * 1024;

    /// <summary>First <c>65536+148</c> expanded bytes kept for the superblock checks.</summary>
    private const int SuperblockWindowBytes = 65536 + 148;

    private const int Ext4SuperblockOffset = 1024;

    private const int Ext4SuperblockBytes = 0x158;

    private const int BtrfsSuperblockOffset = 65536;

    private const int BtrfsSuperblockBytes = 148;

    private const string Ext4FsTypeName = "ext4";

    private const string BtrfsFsTypeName = "btrfs";

    private const int CopyBufferBytes = 1024 * 1024;

    private readonly TfRawPackageContract _contract;

    private readonly FileStream _metadataStream;

    private readonly List<HeldArtifact> _heldArtifacts;

    private readonly FileStream _bootStream;

    private readonly FileStream _rootStream;

    private readonly List<FileStream> _ownedStreams;

    private readonly EdlRawDtbEvidence _normalDtb;

    private readonly EdlRawDtbEvidence _diagnosticDtb;

    private int _disposed;

    private int _writeClaimed;

    private TfPreparedCardImages(
        TfRawPackageContract contract,
        FileStream metadataStream,
        List<HeldArtifact> heldArtifacts,
        FileStream bootStream,
        FileStream rootStream,
        EdlRawDtbEvidence normalDtb,
        EdlRawDtbEvidence diagnosticDtb)
    {
        _contract = contract;
        _metadataStream = metadataStream;
        _heldArtifacts = heldArtifacts;
        _bootStream = bootStream;
        _rootStream = rootStream;
        _normalDtb = normalDtb;
        _diagnosticDtb = diagnosticDtb;

        _ownedStreams = new List<FileStream>(1 + heldArtifacts.Count) { metadataStream };
        foreach (var item in heldArtifacts)
        {
            _ownedStreams.Add(item.Stream);
        }
    }

    /// <summary>The typed TF contract re-read while every file handle was held open.</summary>
    public TfRawPackageContract Contract => _contract;

    /// <summary>Evidence of the validated normal DTB (exact normal boot arguments, model, kind).</summary>
    public EdlRawDtbEvidence NormalDtb => _normalDtb;

    /// <summary>Evidence of the validated diagnostic DTB (exact diagnostic boot arguments, model, kind).</summary>
    public EdlRawDtbEvidence DiagnosticDtb => _diagnosticDtb;

    /// <summary>
    /// Captures the TF Prepared proof for a successfully imported schema 2 TF-card raw package:
    /// re-reads the typed contract under held read-only handles, rehashes every held file against
    /// the typed facts, preflights both gzip raw images with genuine filesystem checks and
    /// validates both DTBs. The file and hash work runs on the worker pool; cancellation is
    /// observed on entry, inside every loop and before the capture completes.
    /// </summary>
    public static Task<TfPreparedCardImages> CaptureAsync(
        ImportedPackage package,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.Run(() => CaptureCore(package, cancellationToken), cancellationToken);
    }

    private static TfPreparedCardImages CaptureCore(
        ImportedPackage package,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(package);

        var validation = package.Validation;
        if (validation is null || !validation.IsValid)
        {
            throw new InvalidDataException("只有通过结构校验的安装包才能准备 TF 卡镜像。");
        }

        if (validation.TestOnly)
        {
            throw new InvalidDataException("testOnly 安装包禁止用于 TF 卡正式写入准备。");
        }

        if (!string.Equals(validation.DeploymentKind, TfRawDeploymentKind, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"安装包部署类型必须是 {TfRawDeploymentKind}，实际为 {validation.DeploymentKind ?? "（缺失）"}。");
        }

        if (string.IsNullOrEmpty(validation.ManifestFingerprint)
            || validation.Storage is null
            || string.IsNullOrWhiteSpace(package.DeviceModel))
        {
            throw new InvalidDataException("导入结果缺少清单指纹、存储声明或设备型号，无法准备 TF 卡镜像。");
        }

        var root = Path.GetFullPath(package.PackageDirectory);
        if (!Directory.Exists(root))
        {
            throw new InvalidDataException($"安装包目录不存在：{package.PackageDirectory}。");
        }

        RejectReparsePoint(root, "安装包目录");

        var owned = new List<FileStream>();
        try
        {
            // Hold package.json open for the whole capture.
            var metadataPath = Path.Combine(root, "package.json");
            RejectReparsePoint(metadataPath, "package.json");
            var metadataStream = new FileStream(metadataPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            owned.Add(metadataStream);

            // The typed contract, read while the metadata hold is open.
            var contract = PackageReader.ReadTfRawContract(root, package.DeviceModel, cancellationToken);

            // The held metadata bytes must reproduce both the typed and the imported fingerprint,
            // and the typed facts must match what the import claimed.
            var metadataSha256 = HashHeldStream(metadataStream, out _, cancellationToken);
            if (!string.Equals(metadataSha256, contract.ManifestFingerprint, StringComparison.Ordinal)
                || !string.Equals(metadataSha256, validation.ManifestFingerprint, StringComparison.Ordinal))
            {
                throw new InvalidDataException("package.json 的实际 SHA-256 与导入指纹或契约指纹不一致。");
            }

            if (contract.Raw is { TestOnly: true })
            {
                throw new InvalidDataException("安装包契约带有 testOnly 标记，拒绝准备 TF 卡镜像。");
            }

            if (!string.Equals(contract.DeviceModel, package.DeviceModel, StringComparison.Ordinal)
                || !string.Equals(contract.PackageId, validation.PackageId, StringComparison.Ordinal)
                || !string.Equals(contract.Version, validation.Version, StringComparison.Ordinal)
                || contract.Storage != validation.Storage)
            {
                throw new InvalidDataException("安装包契约的型号、标识、版本或存储声明与导入结果不一致。");
            }

            if (contract.Artifacts.Count is not (7 or 8))
            {
                throw new InvalidDataException(
                    $"安装包应声明 7 个共享工件加可选维护工件，实际为 {contract.Artifacts.Count} 个。");
            }

            // Open every declared artifact (the seven shared roles plus the optional eighth) and
            // keep the handles for the lifetime of this instance.
            var held = new List<HeldArtifact>(contract.Artifacts.Count);
            var heldByRole = new Dictionary<string, HeldArtifact>(contract.Artifacts.Count, StringComparer.Ordinal);
            var rootPrefix = Path.EndsInDirectorySeparator(root)
                ? root
                : root + Path.DirectorySeparatorChar;
            foreach (var artifact in contract.Artifacts.Values)
            {
                var fullPath = Path.GetFullPath(artifact.FullPath);
                if (!fullPath.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException($"工件 {artifact.Role} 逃逸出安装包目录：{artifact.FullPath}。");
                }

                RejectReparsePoint(fullPath, artifact.Role);
                var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                owned.Add(stream);
                var item = new HeldArtifact(stream, artifact);
                held.Add(item);
                heldByRole[artifact.Role] = item;
            }

            // Import claims alone are never trusted: rehash every held artifact against the typed
            // facts, including the optional maintenance artifact (an ordinary held/hash proof only).
            foreach (var item in held)
            {
                VerifyHeldArtifact(item, cancellationToken);
            }

            // Bounded gzip preflight of both images: exact expanded length, whole-image SHA-256 and
            // genuine superblock geometry/UUID checks from the stored 65684-byte window.
            var bootItem = heldByRole[contract.BootImage.Artifact.Role];
            var rootItem = heldByRole[contract.RootImage.Artifact.Role];
            ValidateExpandedImage(bootItem.Stream, contract.BootImage, contract.BootRecipe.BootUuid, cancellationToken);
            ValidateExpandedImage(rootItem.Stream, contract.RootImage, contract.BootRecipe.RootUuid, cancellationToken);

            // Both DTBs, bounded and validated with the exact recipe boot arguments.
            var normalDtb = ReadAndValidateDtb(
                heldByRole[DtbNormalRole],
                contract.BootRecipe.NormalBootArgs,
                EdlRawDtbKind.Normal,
                contract,
                cancellationToken);
            var diagnosticDtb = ReadAndValidateDtb(
                heldByRole[DtbDiagnosticRole],
                contract.BootRecipe.DiagnosticBootArgs,
                EdlRawDtbKind.Diagnostic,
                contract,
                cancellationToken);

            cancellationToken.ThrowIfCancellationRequested();
            return new TfPreparedCardImages(
                contract,
                metadataStream,
                held,
                bootItem.Stream,
                rootItem.Stream,
                normalDtb,
                diagnosticDtb);
        }
        catch
        {
            // Close only the handles this capture opened; never delete caller files and never
            // create an expansion directory on failure.
            foreach (var stream in owned)
            {
                stream.Dispose();
            }

            throw;
        }
    }

    /// <summary>
    /// Rehashes the held package.json bytes and every held artifact stream and requires the
    /// lengths and digests to be unchanged since the capture. No image is expanded again and the
    /// stream ownership stays with this instance.
    /// </summary>
    internal async Task RevalidateAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();

        await Task.Run(
            () =>
            {
                var metadataSha256 = HashHeldStream(_metadataStream, out _, cancellationToken);
                if (!string.Equals(metadataSha256, _contract.ManifestFingerprint, StringComparison.Ordinal))
                {
                    throw new InvalidDataException("package.json 在持有期间发生了变化。");
                }

                foreach (var item in _heldArtifacts)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    VerifyHeldArtifact(item, cancellationToken);
                }
            },
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Claims the single write attempt of this capture. A disposed instance rejects, and a second
    /// call rejects even when the first write attempt later failed.
    /// </summary>
    internal void ClaimWriteAttempt()
    {
        ThrowIfDisposed();
        if (Interlocked.CompareExchange(ref _writeClaimed, 1, 0) != 0)
        {
            throw new InvalidOperationException("每个 TF Prepared 凭证只允许一次写入尝试。");
        }
    }

    /// <summary>
    /// Opens the held boot compressed stream rewound to position 0 as a decompressing
    /// <see cref="GZipStream"/> that leaves the held stream open. Only the common writer calls
    /// this, sequentially after <see cref="ClaimWriteAttempt"/>.
    /// </summary>
    internal Stream OpenExpandedBoot()
    {
        ThrowIfDisposed();
        _bootStream.Seek(0, SeekOrigin.Begin);
        return new GZipStream(_bootStream, CompressionMode.Decompress, leaveOpen: true);
    }

    /// <summary>
    /// Opens the held root compressed stream rewound to position 0 as a decompressing
    /// <see cref="GZipStream"/> that leaves the held stream open. Only the common writer calls
    /// this, sequentially after <see cref="ClaimWriteAttempt"/>.
    /// </summary>
    internal Stream OpenExpandedRoot()
    {
        ThrowIfDisposed();
        _rootStream.Seek(0, SeekOrigin.Begin);
        return new GZipStream(_rootStream, CompressionMode.Decompress, leaveOpen: true);
    }

    /// <summary>Closes only the streams this instance owns. Idempotent.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        foreach (var stream in _ownedStreams)
        {
            stream.Dispose();
        }

        _ownedStreams.Clear();
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(TfPreparedCardImages));
        }
    }

    private static void RejectReparsePoint(string path, string label)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException($"{label} 是符号链接或重解析点，拒绝读取：{path}。");
        }
    }

    private static void VerifyHeldArtifact(HeldArtifact item, CancellationToken cancellationToken)
    {
        var sha256 = HashHeldStream(item.Stream, out var length, cancellationToken);
        if (length != item.Artifact.Bytes
            || !string.Equals(sha256, item.Artifact.Sha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"工件 {item.Artifact.Role} 在持有期间发生了变化。");
        }
    }

    /// <summary>Hashes a held stream from position 0 with SHA-256 and rewinds nothing: the stream
    /// stays at the end position and every later consumer seeks explicitly.</summary>
    private static string HashHeldStream(Stream stream, out long length, CancellationToken cancellationToken)
    {
        stream.Seek(0, SeekOrigin.Begin);
        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[CopyBufferBytes];
        long total = 0;
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            total += read;
            sha256.AppendData(buffer, 0, read);
        }

        length = total;
        return Convert.ToHexString(sha256.GetHashAndReset());
    }

    /// <summary>
    /// Expands one held gzip image through a bounded <see cref="GZipStream"/> with a 1 MiB buffer,
    /// requires the output to be exactly the declared expanded length and SHA-256 (rejecting short,
    /// truncated and extra output) and keeps only the first 65684 expanded bytes for the genuine
    /// superblock geometry and UUID checks. No full raw image is allocated.
    /// </summary>
    private static void ValidateExpandedImage(
        FileStream held,
        EdlRawImage image,
        Guid expectedUuid,
        CancellationToken cancellationToken)
    {
        held.Seek(0, SeekOrigin.Begin);
        var window = new byte[SuperblockWindowBytes];
        int windowFilled = 0;
        long total = 0;
        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var gzip = new GZipStream(held, CompressionMode.Decompress, leaveOpen: true);
        var buffer = new byte[CopyBufferBytes];
        int read;
        while ((read = gzip.Read(buffer, 0, buffer.Length)) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            total += read;
            if (total > image.ExpandedBytes)
            {
                throw new InvalidDataException(
                    $"扩展镜像 '{image.Artifact.Role}' 的解压输出超出声明的 {image.ExpandedBytes} 字节。");
            }

            sha256.AppendData(buffer, 0, read);
            if (windowFilled < window.Length)
            {
                var toCopy = (int)Math.Min(read, window.Length - windowFilled);
                Buffer.BlockCopy(buffer, 0, window, windowFilled, toCopy);
                windowFilled += toCopy;
            }
        }

        if (total != image.ExpandedBytes)
        {
            throw new InvalidDataException(
                $"扩展镜像 '{image.Artifact.Role}' 的解压输出不完整：声明 {image.ExpandedBytes} 字节，实际 {total} 字节。");
        }

        var expandedSha256 = Convert.ToHexString(sha256.GetHashAndReset());
        if (!string.Equals(expandedSha256, image.ExpandedSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"扩展镜像 '{image.Artifact.Role}' 的解压 SHA-256 与声明不一致。");
        }

        if (windowFilled != window.Length)
        {
            throw new InvalidDataException($"扩展镜像 '{image.Artifact.Role}' 短于文件系统超级块检查窗口。");
        }

        if (string.Equals(image.FsType, Ext4FsTypeName, StringComparison.Ordinal))
        {
            EdlRawFilesystemValidator.ValidateExt4(
                window.AsSpan(Ext4SuperblockOffset, Ext4SuperblockBytes),
                total,
                image,
                expectedUuid);
        }
        else if (string.Equals(image.FsType, BtrfsFsTypeName, StringComparison.Ordinal))
        {
            EdlRawFilesystemValidator.ValidateBtrfs(
                window.AsSpan(BtrfsSuperblockOffset, BtrfsSuperblockBytes),
                total,
                image,
                expectedUuid);
        }
        else
        {
            throw new InvalidDataException(
                $"扩展镜像 '{image.Artifact.Role}' 声明了不支持的文件系统类型：{image.FsType}。");
        }
    }

    /// <summary>Reads a held DTB fully, bounded by the shared 8 MiB limit, and validates it through
    /// <see cref="EdlRawDtbValidator.ValidateTf"/> with the exact expected boot arguments.</summary>
    private static EdlRawDtbEvidence ReadAndValidateDtb(
        HeldArtifact item,
        string expectedBootArgs,
        EdlRawDtbKind kind,
        TfRawPackageContract contract,
        CancellationToken cancellationToken)
    {
        var stream = item.Stream;
        if (stream.Length > MaxDtbBytes)
        {
            throw new InvalidDataException(
                $"DTB '{item.Artifact.Role}' 超过 {MaxDtbBytes} 字节上限，拒绝读取。");
        }

        var bytes = new byte[stream.Length];
        stream.Seek(0, SeekOrigin.Begin);
        int offset = 0;
        while (offset < bytes.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var read = stream.Read(bytes, offset, bytes.Length - offset);
            if (read <= 0)
            {
                throw new InvalidDataException($"DTB '{item.Artifact.Role}' 在持有期间被截断。");
            }

            offset += read;
        }

        return EdlRawDtbValidator.ValidateTf(
            bytes.AsSpan(),
            expectedBootArgs,
            kind,
            contract.DeviceModel);
    }

    /// <summary>One artifact file held open for the lifetime of the capture.</summary>
    private sealed class HeldArtifact
    {
        internal HeldArtifact(FileStream stream, EdlRawArtifact artifact)
        {
            Stream = stream;
            Artifact = artifact;
        }

        internal FileStream Stream { get; }

        internal EdlRawArtifact Artifact { get; }
    }
}
