using System.Diagnostics.CodeAnalysis;
using SharpCompress.Archives;
using SharpCompress.Common;
using SharpCompress.Common.Rar;
using SharpCompress.Common.SevenZip;
using SharpCompress.Common.Tar;
using SharpCompress.Readers;
using SharpCompress.Readers.Rar;

namespace FreedomInstaller.Core;

/// <summary>
/// Non-ZIP side of the bundle importer: 7z, RAR, TAR and the compressed TAR containers (tar.gz, tar.xz,
/// tar.zst, tar.bz2 and their short spellings).
/// <para>
/// The container is identified from its content, never from the file extension, and a compressed TAR is
/// genuinely unpacked rather than copied out as one opaque blob. The work happens in two sequential
/// passes over the source archive: the first one collects metadata and validates every entry name before
/// a single byte is written, the second one reopens the archive and stream-copies only the planned
/// entries of the selected model, including any schema2 shared files at their mapped destinations.
/// Everything after staging is the unmodified ZIP path: the same
/// <see cref="PackageReader.Validate"/> call, the same bundle/package version check and the same
/// cleanup guarantees. An <c>ArchiveSource</c> supplies the stream, so a split archive is read
/// from its complete volume group without being materialized first.
/// </para>
/// </summary>
public static partial class PackageImporter
{
    /// <summary>
    /// Imports a non-ZIP bundle: inspect everything, then extract only the requested model prefix into
    /// a private stage directory below <paramref name="root"/>.
    /// </summary>
    private static ImportedPackage ImportArchive(
        ArchiveSource source,
        string sourcePath,
        string expectedModel,
        InstallationTarget target,
        string root,
        CancellationToken token)
    {
        var reasons = new List<string>();
        string? stage = null;

        try
        {
            var entries = new List<ArchiveEntryItem>();
            if (!TryInspectArchive(source, entries, reasons, token, out var rawBundle))
            {
                return Invalid(sourcePath, expectedModel, reasons);
            }

            var bundleItem = entries.FirstOrDefault(
                item => !item.IsDirectory
                    && string.Equals(item.Name, BundleFileName, StringComparison.OrdinalIgnoreCase));

            if (bundleItem is null)
            {
                reasons.Add($"合集缺少 {BundleFileName}。");
                return Invalid(sourcePath, expectedModel, reasons);
            }

            if (rawBundle is null)
            {
                reasons.Add($"无法读取合集内的 {BundleFileName}。");
                return Invalid(sourcePath, expectedModel, reasons);
            }

            if (!TryReadBundle(
                rawBundle,
                expectedModel,
                reasons,
                out var bundleVersion,
                out var selectedDirectory,
                out var sharedMappings))
            {
                return Invalid(sourcePath, expectedModel, reasons);
            }

            token.ThrowIfCancellationRequested();

            var nodes = new List<ArchiveNode>(entries.Count);
            foreach (var entry in entries)
            {
                nodes.Add(new ArchiveNode(entry.Name, entry.IsDirectory));
            }

            if (!TryBuildExtractionPlan(nodes, selectedDirectory, sharedMappings, reasons, out var plan))
            {
                return Invalid(sourcePath, expectedModel, reasons);
            }

            var stagePath = Path.Combine(root, Guid.NewGuid().ToString("N"));
            var stageDirectory = Directory.CreateDirectory(stagePath).FullName;
            stage = stageDirectory;

            if (!TryStageArchive(source, plan, stageDirectory, token, reasons))
            {
                DeleteStage(stage, root, reasons);
                return Invalid(sourcePath, expectedModel, reasons);
            }

            token.ThrowIfCancellationRequested();

            var validation = PackageReader.Validate(stageDirectory, expectedModel, target);
            token.ThrowIfCancellationRequested();

            if (!validation.IsValid)
            {
                reasons.AddRange(validation.Reasons);
                DeleteStage(stage, root, reasons);
                return Invalid(sourcePath, expectedModel, reasons);
            }

            if (!string.Equals(validation.Version, bundleVersion, StringComparison.Ordinal))
            {
                reasons.Add($"合集版本 {bundleVersion} 与所选安装包版本 {validation.Version} 不一致，拒绝使用。");
                DeleteStage(stage, root, reasons);
                return Invalid(sourcePath, expectedModel, reasons);
            }

            stage = null;
            return new ImportedPackage(sourcePath, stageDirectory, expectedModel, validation, stageDirectory, root);
        }
        catch (OperationCanceledException)
        {
            TryDeleteStage(stage, root);
            throw;
        }
        catch (Exception exception) when (IsExpectedFailure(exception) || exception is ArchiveException or ArchiveOperationException or InvalidFormatException or IncompleteArchiveException or MultiVolumeExtractionException)
        {
            reasons.Add($"导入安装包时发生错误：{exception.Message}");
            DeleteStage(stage, root, reasons);
            return Invalid(sourcePath, expectedModel, reasons);
        }
    }

    /// <summary>
    /// First pass: enumerate metadata for every entry without writing anything, and read only the root
    /// <c>bundle.json</c> through a bounded, cancellable chunk copy.
    /// </summary>
    private static bool TryInspectArchive(
        ArchiveSource source,
        List<ArchiveEntryItem> entries,
        List<string> reasons,
        CancellationToken token,
        out byte[]? rawBundle)
    {
        rawBundle = null;

        using var stream = source.OpenStream();

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        IArchive? archive = null;
        IReader? reader = null;

        try
        {
            reader = OpenArchiveReader(source, stream, out archive);

            while (reader.MoveToNextEntry())
            {
                token.ThrowIfCancellationRequested();

                var entry = reader.Entry;
                if (entry is null)
                {
                    reasons.Add("归档包含无法解析的条目，拒绝使用。");
                    return false;
                }

                if (!TryDescribeEntry(entry, seen, entries, reasons, source.IsNativeRar, out var described))
                {
                    return false;
                }

                if (rawBundle is null
                    && described is { IsDirectory: false }
                    && string.Equals(described.Name, BundleFileName, StringComparison.OrdinalIgnoreCase))
                {
                    using var input = reader.OpenEntryStream();
                    rawBundle = ReadLimitedStream(input, MaxBundleIndexBytes, token);
                }
                else if (!described.IsDirectory)
                {
                    DrainEntry(reader, token);
                }
            }
        }
        finally
        {
            reader?.Dispose();
            archive?.Dispose();
        }

        return true;
    }

    /// <summary>
    /// Metadata and safety checks applied to one entry before anything is written: normalized relative
    /// name, no case-insensitive duplicate, no symlink or reparse entry, no hard or soft link target, no
    /// encryption and no split or multi-volume part. <paramref name="allowSplit"/> is true only for a
    /// native RAR set, whose entries legitimately span the volumes supplied to the RAR reader.
    /// </summary>
    private static bool TryDescribeEntry(
        IEntry entry,
        HashSet<string> seen,
        List<ArchiveEntryItem> entries,
        List<string> reasons,
        bool allowSplit,
        [NotNullWhen(true)] out ArchiveEntryItem? described)
    {
        described = null;

        if (!TryReadEntryName(entry, out var name, out var normalized, out var isDirectory, out var reason))
        {
            reasons.Add(reason);
            return false;
        }

        if (!seen.Add(normalized))
        {
            reasons.Add($"合集包含重复条目（忽略大小写）：{name}。");
            return false;
        }

        if (IsLinkEntry(entry))
        {
            reasons.Add($"合集包含符号链接或重解析点条目，拒绝使用：{name}。");
            return false;
        }

        if (entry.IsEncrypted)
        {
            reasons.Add($"合集包含加密条目，当前不支持带密码的归档：{name}。");
            return false;
        }

        if (!allowSplit && IsSplitEntry(entry))
        {
            reasons.Add($"合集是分卷归档或被分卷切开的归档，拒绝使用：{name}。");
            return false;
        }

        described = new ArchiveEntryItem(normalized, isDirectory);
        entries.Add(described);
        return true;
    }

    /// <summary>
    /// Second pass: reopen the same file and copy exactly the planned entries, writing each one at its
    /// plan destination so a shared <c>common/</c> file lands on the mapped relative path. Unwanted
    /// entries are drained through the cancellation-aware copy so a solid or streaming container cannot
    /// block cancellation for gigabytes, and the loop stops as soon as every selected entry is handled
    /// instead of reading the rest of the archive.
    /// </summary>
    private static bool TryStageArchive(
        ArchiveSource source,
        IReadOnlyList<ExtractionItem> plan,
        string stageDirectory,
        CancellationToken token,
        List<string> reasons)
    {
        var expected = new Dictionary<string, ExtractionItem>(StringComparer.Ordinal);
        foreach (var planned in plan)
        {
            expected[planned.SourceName] = planned;
        }

        using var stream = source.OpenStream();

        IArchive? archive = null;
        IReader? reader = null;

        try
        {
            reader = OpenArchiveReader(source, stream, out archive);

            var handled = 0;

            while (handled < expected.Count && reader.MoveToNextEntry())
            {
                token.ThrowIfCancellationRequested();

                var entry = reader.Entry;
                if (entry is null)
                {
                    reasons.Add("归档在解包时包含无法解析的条目，拒绝使用。");
                    return false;
                }

                if (!TryReadEntryName(entry, out var name, out var normalized, out var isDirectory, out var reason))
                {
                    reasons.Add(reason);
                    return false;
                }

                if (!expected.TryGetValue(normalized, out var planned))
                {
                    if (!isDirectory)
                    {
                        DrainEntry(reader, token);
                    }

                    continue;
                }

                if (planned.IsDirectory != isDirectory)
                {
                    reasons.Add($"归档条目 {name} 的文件类型与首次枚举不一致，拒绝使用。");
                    return false;
                }

                if (IsLinkEntry(entry)
                    || entry.IsEncrypted
                    || (!source.IsNativeRar && IsSplitEntry(entry)))
                {
                    reasons.Add($"归档条目 {name} 在解包时状态发生变化，拒绝使用。");
                    return false;
                }

                handled++;

                var extractionPath = Path.GetFullPath(Path.Combine(stageDirectory, planned.Destination));
                if (!IsBeneath(extractionPath, stageDirectory))
                {
                    reasons.Add($"条目路径越出解包目录，拒绝写入：{normalized}。");
                    return false;
                }

                if (isDirectory)
                {
                    Directory.CreateDirectory(extractionPath);
                    continue;
                }

                var parent = Path.GetDirectoryName(extractionPath);
                if (parent is not null)
                {
                    Directory.CreateDirectory(parent);
                }

                using var input = reader.OpenEntryStream();
                using var output = new FileStream(
                    extractionPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    CopyBufferSize,
                    FileOptions.SequentialScan);
                CopyCancellable(input, output, token);
            }

            if (handled != expected.Count)
            {
                reasons.Add($"归档缺少所选安装包声明的 {expected.Count - handled} 个条目，拒绝使用。");
                return false;
            }
        }
        finally
        {
            reader?.Dispose();
            archive?.Dispose();
        }

        return true;
    }

    /// <summary>
    /// Normalizes one entry name with the ZIP rules: directories are given the trailing slash they are
    /// matched by, and a name whose directory marker contradicts its type is rejected instead of guessed.
    /// </summary>
    private static bool TryReadEntryName(
        IEntry entry,
        out string name,
        out string normalized,
        out bool isDirectory,
        out string reason)
    {
        normalized = string.Empty;
        isDirectory = false;
        reason = string.Empty;

        var key = entry.Key ?? string.Empty;
        if (key.Length == 0)
        {
            name = string.Empty;
            reason = "归档包含空名称条目，拒绝使用。";
            return false;
        }

        name = entry.IsDirectory && !key.EndsWith('/') ? key + "/" : key;

        if (!TryNormalizeArchiveName(name, out normalized, out isDirectory, out reason))
        {
            return false;
        }

        if (isDirectory != entry.IsDirectory)
        {
            reason = $"归档条目 {key} 的目录标记与名称不一致，拒绝使用。";
            return false;
        }

        return true;
    }

    /// <summary>
    /// Detects a link entry without ever reading <see cref="IEntry.Attrib"/> from a <see cref="TarEntry"/>,
    /// whose inherited attribute accessor is not implemented. TAR links are recognized by their target
    /// name or by the Unix symlink file type in the exposed mode; 7z and RAR keep the attribute checks
    /// they support, plus the 7z extended attributes and the RAR redirect flag, because their
    /// <c>LinkTarget</c> is not populated for those entries.
    /// </summary>
    private static bool IsLinkEntry(IEntry entry)
    {
        if (entry is TarEntry tar)
        {
            return !string.IsNullOrEmpty(tar.LinkTarget) || (tar.Mode & 0xF000) == 0xA000;
        }

        if (entry is RarEntry rar)
        {
            return rar.IsRedir || !string.IsNullOrEmpty(rar.RedirTargetName) || HasSymlinkMode(rar);
        }

        if (entry is SevenZipEntry sevenZip)
        {
            return !string.IsNullOrEmpty(sevenZip.LinkTarget)
                || HasSymlinkMode(sevenZip)
                || (sevenZip.ExtendedAttrib is int extended && (extended & 0xF000) == 0xA000);
        }

        return !string.IsNullOrEmpty(entry.LinkTarget) || HasSymlinkMode(entry);
    }

    /// <summary>
    /// Rejects Unix symlink modes and Windows reparse points, covering both the <c>mode &lt;&lt; 16</c>
    /// layout used by ZIP-like attributes and the plain mode value some TAR readers expose.
    /// </summary>
    private static bool HasSymlinkMode(IEntry entry)
    {
        if (entry.Attrib is not int attributes)
        {
            return false;
        }

        if (((attributes >> 16) & 0xF000) == 0xA000)
        {
            return true;
        }

        if ((attributes & 0xF000) == 0xA000)
        {
            return true;
        }

        return ((FileAttributes)(attributes & 0xFFFF) & FileAttributes.ReparsePoint) != 0;
    }

    /// <summary>
    /// True for an entry cut by a volume or read from a non-first volume. 7z <c>VolumeIndexFirst</c> /
    /// <c>VolumeIndexLast</c> are file-part entry ordinals rather than volume numbers, so only the split
    /// flag is meaningful there; RAR and the other formats keep the volume index checks.
    /// </summary>
    private static bool IsSplitEntry(IEntry entry)
    {
        if (entry.IsSplitAfter == true)
        {
            return true;
        }

        if (entry is SevenZipEntry)
        {
            return false;
        }

        return entry.VolumeIndexFirst > 0 || entry.VolumeIndexLast > 0;
    }

    /// <summary>
    /// Reads one entry into memory with the same bound and cancellation checks as the ZIP path, so
    /// <c>bundle.json</c> can never be inflated past the shared index limit.
    /// </summary>
    private static byte[] ReadLimitedStream(Stream input, int limit, CancellationToken token)
    {
        using var memory = new MemoryStream();

        var buffer = new byte[CopyBufferSize];
        int read;
        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            token.ThrowIfCancellationRequested();

            if (memory.Length + read > limit)
            {
                throw new InvalidDataException($"{BundleFileName} 超出 {limit} 字节上限，拒绝解析。");
            }

            memory.Write(buffer, 0, read);
        }

        return memory.ToArray();
    }

    /// <summary>
    /// Skipping an unwanted entry in a solid or streaming container still requires decoding its data.
    /// Draining it through the cancellable copy keeps cancellation responsive, and Stream.Null keeps the
    /// bytes out of memory and off the disk.
    /// </summary>
    private static void DrainEntry(IReader reader, CancellationToken token)
    {
        using var stream = reader.OpenEntryStream();
        CopyCancellable(stream, Stream.Null, token);
    }

    /// <summary>
    /// Native RAR volumes are opened as a set of files: the pinned multi-volume reader merges them,
    /// solid sets included, and owns the streams it opens because <c>LeaveStreamOpen</c> is false, so no
    /// volume is handled here and the raw parts are never concatenated. 7z has no
    /// <see cref="IReader"/> factory, so it is opened as an archive and read through
    /// <c>ExtractAllEntries()</c>; every other format is opened directly by the reader factory, which
    /// also detects the gzip, bzip2, xz and zstd wrappers and the TAR stream underneath them, and
    /// handles solid RAR. The caller owns and disposes both handles.
    /// </summary>
    private static IReader OpenArchiveReader(ArchiveSource source, Stream stream, out IArchive? archive)
    {
        archive = null;

        if (source.IsNativeRar)
        {
            var files = new List<FileInfo>(source.Parts.Count);
            foreach (var part in source.Parts)
            {
                files.Add(new FileInfo(part));
            }

            return RarReader.OpenReader(files, new ReaderOptions { LeaveStreamOpen = false });
        }

        if (HasSevenZipSignature(stream))
        {
            archive = ArchiveFactory.OpenArchive(stream, CreateArchiveOptions());
            return archive.ExtractAllEntries();
        }

        return ReaderFactory.OpenReader(stream, CreateArchiveOptions());
    }

    /// <summary>
    /// Detects the 7z signature <c>37 7A BC AF 27 1C</c> at the current start of the stream and restores
    /// the position, because 7z is the only container <see cref="ReaderFactory"/> cannot open.
    /// </summary>
    private static bool HasSevenZipSignature(Stream stream)
    {
        var position = stream.Position;

        Span<byte> signature = stackalloc byte[6];
        var read = stream.Read(signature);

        stream.Position = position;

        return read == signature.Length
            && signature[0] == 0x37
            && signature[1] == 0x7A
            && signature[2] == 0xBC
            && signature[3] == 0xAF
            && signature[4] == 0x27
            && signature[5] == 0x1C;
    }

    private static ReaderOptions CreateArchiveOptions() => new() { LeaveStreamOpen = true };

    private sealed record ArchiveEntryItem(string Name, bool IsDirectory);
}
