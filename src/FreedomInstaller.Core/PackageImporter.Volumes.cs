using System.Text.RegularExpressions;

namespace FreedomInstaller.Core;

/// <summary>
/// Split archive support: raw numeric volumes (<c>.zip.001</c>, <c>.7z.001</c>, <c>.tar.gz.001</c> and
/// every other container split the same way) and native RAR volume sets (<c>.part1.rar</c>,
/// <c>.part01.rar</c>).
/// <para>
/// The file the caller selected only names the group it belongs to. Every volume of that group in the
/// same directory must exist from index 1 upwards without a gap, and the volumes are ordered by their
/// numeric index instead of their names. The caller keeps the path it passed in, so selecting a middle
/// volume is still visible in <see cref="ImportedPackage.SourcePath"/> while the group is read from its
/// first volume. Nothing is guessed from the file name, no model is inferred from it and no combined
/// temporary file is produced.
/// </para>
/// </summary>
public static partial class PackageImporter
{
    /// <summary>Smallest numeric suffix treated as a raw split volume.</summary>
    private const int MinVolumeDigits = 3;

    /// <summary>Largest numeric suffix accepted, so a hostile name cannot define an absurd index.</summary>
    private const int MaxVolumeDigits = 9;

    private static readonly Regex PartRarPattern = new(
        @"^(?<base>.+?)\.part(?<number>[0-9]+)\.rar$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>
    /// Resolves the file the caller selected into the complete volume group it names, or into a single
    /// archive when the name carries no raw numeric suffix and no RAR part pattern.
    /// </summary>
    /// <exception cref="InvalidDataException">The group has a bad index, mixed padding or a gap.</exception>
    private static ArchiveSource ResolveArchiveSource(string fullSource)
    {
        var directory = Path.GetDirectoryName(fullSource);
        var fileName = Path.GetFileName(fullSource);

        if (string.IsNullOrEmpty(directory) || fileName.Length == 0 || !File.Exists(fullSource))
        {
            throw new FileNotFoundException($"找不到安装包文件：{fullSource}。", fullSource);
        }

        var lastDot = fileName.LastIndexOf('.');
        if (lastDot > 0)
        {
            var digits = fileName[(lastDot + 1)..];
            if (digits.Length >= MinVolumeDigits && IsAsciiDigits(digits))
            {
                return ResolveNumericVolumes(directory, fileName[..lastDot], digits.Length);
            }
        }

        var partMatch = PartRarPattern.Match(fileName);
        if (partMatch.Success)
        {
            return ResolvePartRarVolumes(
                directory,
                partMatch.Groups["base"].Value,
                partMatch.Groups["number"].Value.Length);
        }

        return ArchiveSource.Single(fullSource);
    }

    /// <summary>Collects <c>&lt;base&gt;.NNN</c> volumes; the suffix width comes from the selected name.</summary>
    private static ArchiveSource ResolveNumericVolumes(string directory, string groupBase, int width)
    {
        RequireSupportedWidth(groupBase, width);

        var prefix = groupBase + ".";
        var volumes = new SortedDictionary<int, string>(Comparer<int>.Default);

        foreach (var path in Directory.EnumerateFiles(directory))
        {
            var name = Path.GetFileName(path);
            if (!name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var digits = name[prefix.Length..];
            if (!IsAsciiDigits(digits))
            {
                continue;
            }

            AddVolume(volumes, digits, width, path, name);
        }

        return BuildVolumeSource(directory, groupBase, width, volumes, nativeRar: false);
    }

    /// <summary>Collects real RAR volumes <c>&lt;base&gt;.partNN.rar</c>; they are read, not concatenated.</summary>
    private static ArchiveSource ResolvePartRarVolumes(string directory, string groupBase, int width)
    {
        RequireSupportedWidth(groupBase, width);

        var volumes = new SortedDictionary<int, string>(Comparer<int>.Default);

        foreach (var path in Directory.EnumerateFiles(directory))
        {
            var name = Path.GetFileName(path);
            var match = PartRarPattern.Match(name);
            if (!match.Success)
            {
                continue;
            }

            if (!string.Equals(match.Groups["base"].Value, groupBase, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            AddVolume(volumes, match.Groups["number"].Value, width, path, name);
        }

        return BuildVolumeSource(directory, groupBase, width, volumes, nativeRar: true);
    }

    /// <summary>
    /// Records one volume by its numeric index. Mixed padding is rejected instead of accepted as a
    /// second volume, and so is the same index appearing twice.
    /// </summary>
    private static void AddVolume(
        SortedDictionary<int, string> volumes,
        string digits,
        int width,
        string path,
        string name)
    {
        if (digits.Length != width)
        {
            throw new InvalidDataException($"分卷文件编号位数不一致：{name} 与已匹配的 {width} 位编号不同。");
        }

        if (!int.TryParse(digits, out var index))
        {
            throw new InvalidDataException($"分卷文件编号无效：{name}。");
        }

        if (!volumes.TryAdd(index, path))
        {
            throw new InvalidDataException(
                $"分卷文件编号重复：{name} 与 {Path.GetFileName(volumes[index])} 都是第 {index} 卷。");
        }
    }

    /// <summary>
    /// Verifies the group starts at volume 1 and is contiguous by walking the ordered indexes with an
    /// expected counter, so no range of integers is ever enumerated. The last volume is never guessed:
    /// a missing tail is left to the decoder and hash checks that reject a truncated archive.
    /// </summary>
    private static ArchiveSource BuildVolumeSource(
        string directory,
        string groupBase,
        int width,
        SortedDictionary<int, string> volumes,
        bool nativeRar)
    {
        var expected = 1;

        if (volumes.Count == 0)
        {
            throw new InvalidDataException($"没有找到可用的分卷文件：{groupBase}。");
        }

        foreach (var volume in volumes)
        {
            if (volume.Key != expected)
            {
                throw new InvalidDataException(
                    $"分卷文件缺失：{FormatVolumeName(directory, groupBase, expected, width, nativeRar)}。");
            }

            expected++;
        }

        return new ArchiveSource(volumes.Values.ToArray(), nativeRar);
    }

    private static string FormatVolumeName(string directory, string groupBase, int index, int width, bool nativeRar)
    {
        var padded = index.ToString().PadLeft(width, '0');
        var name = nativeRar ? $"{groupBase}.part{padded}.rar" : $"{groupBase}.{padded}";
        return Path.Combine(directory, name);
    }

    private static void RequireSupportedWidth(string groupBase, int width)
    {
        if (width < 1 || width > MaxVolumeDigits)
        {
            throw new InvalidDataException($"分卷编号位数不受支持：{groupBase}（{width} 位）。");
        }
    }

    private static bool IsAsciiDigits(string value)
    {
        if (value.Length == 0)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!char.IsAsciiDigit(character))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// One archive to read: the selected file itself or the complete ordered volume group it belongs to.
    /// A stream is opened per pass, so no handle outlives the pass that needed it.
    /// </summary>
    private sealed class ArchiveSource
    {
        internal ArchiveSource(IReadOnlyList<string> parts, bool nativeRar)
        {
            Parts = parts;
            IsNativeRar = nativeRar;
        }

        /// <summary>Full paths in numeric volume order, always starting at volume 1.</summary>
        internal IReadOnlyList<string> Parts { get; }

        /// <summary>
        /// True for a genuine RAR volume set. Those volumes carry their own headers and must be read by
        /// the multi-volume RAR reader instead of being concatenated into one byte stream.
        /// </summary>
        internal bool IsNativeRar { get; }

        internal static ArchiveSource Single(string fullSource) =>
            new(new[] { fullSource }, nativeRar: false);

        /// <summary>
        /// Returns the logical archive stream: an ordinary seekable file for one volume, the raw
        /// concatenation for a split archive, and the first volume of a native RAR set, whose remaining
        /// volumes are opened by the RAR reader itself.
        /// </summary>
        internal Stream OpenStream() =>
            IsNativeRar || Parts.Count == 1
                ? OpenPart(Parts[0])
                : new ConcatenatedArchiveStream(Parts);
    }

    private static FileStream OpenPart(string path) =>
        new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            CopyBufferSize,
            FileOptions.SequentialScan);

    /// <summary>
    /// Seekable read-only stream over the raw split volumes, in volume order, without a combined
    /// temporary file, a full buffer or an extraction pass. Reads stop at the recorded length of the
    /// volume they are in and a volume that ends early is reported as
    /// <see cref="EndOfStreamException"/>, so a truncated set is never mistaken for a complete archive.
    /// Disposing closes only the read handles owned here.
    /// </summary>
    private sealed class ConcatenatedArchiveStream : Stream
    {
        private readonly IReadOnlyList<string> _paths;

        private readonly FileStream[] _streams;

        private readonly long[] _offsets;

        private readonly long[] _lengths;

        private readonly long _length;

        private long _position;

        private int _index;

        private bool _disposed;

        internal ConcatenatedArchiveStream(IReadOnlyList<string> parts)
        {
            _paths = parts;
            _streams = new FileStream[parts.Count];
            _offsets = new long[parts.Count];
            _lengths = new long[parts.Count];

            var offset = 0L;

            try
            {
                for (var index = 0; index < parts.Count; index++)
                {
                    var stream = OpenPart(parts[index]);
                    _streams[index] = stream;
                    _lengths[index] = stream.Length;
                    _offsets[index] = offset;
                    offset += stream.Length;
                }
            }
            catch
            {
                // A volume that could not be opened must not leave the ones before it open.
                Dispose();
                throw;
            }

            _length = offset;
        }

        public override bool CanRead => !_disposed;

        public override bool CanSeek => !_disposed;

        public override bool CanWrite => false;

        public override long Length
        {
            get
            {
                ThrowIfDisposed();
                return _length;
            }
        }

        public override long Position
        {
            get
            {
                ThrowIfDisposed();
                return _position;
            }
            set => Seek(value, SeekOrigin.Begin);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            ArgumentNullException.ThrowIfNull(buffer);
            ArgumentOutOfRangeException.ThrowIfNegative(offset);
            ArgumentOutOfRangeException.ThrowIfNegative(count);

            if (count > buffer.Length - offset)
            {
                throw new ArgumentException("读取范围超出缓冲区。", nameof(count));
            }

            return Read(buffer.AsSpan(offset, count));
        }

        public override int Read(Span<byte> buffer)
        {
            ThrowIfDisposed();

            if (buffer.Length == 0 || _position >= _length)
            {
                return 0;
            }

            var written = 0;

            while (written < buffer.Length && _position < _length)
            {
                var part = _index;
                var partLength = _lengths[part];
                var localOffset = _position - _offsets[part];

                if (localOffset >= partLength)
                {
                    _index = part + 1;
                    continue;
                }

                var available = (int)Math.Min(buffer.Length - written, partLength - localOffset);
                var stream = _streams[part];
                stream.Position = localOffset;

                var read = stream.Read(buffer.Slice(written, available));
                if (read <= 0)
                {
                    throw new EndOfStreamException($"分卷文件提前结束：{_paths[part]}。");
                }

                written += read;
                _position += read;
            }

            return written;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            ThrowIfDisposed();

            var target = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => _position + offset,
                SeekOrigin.End => _length + offset,
                _ => throw new ArgumentException("不支持该定位基准。", nameof(origin)),
            };

            if (target < 0)
            {
                throw new IOException("不能把位置移动到分卷归档开头之前。");
            }

            _position = target;
            _index = IndexOf(target);
            return _position;
        }

        public override void Flush()
        {
        }

        public override void SetLength(long value) =>
            throw new NotSupportedException("分卷归档是只读流。");

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException("分卷归档是只读流。");

        public override void Write(ReadOnlySpan<byte> buffer) =>
            throw new NotSupportedException("分卷归档是只读流。");

        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                _disposed = true;

                if (disposing)
                {
                    foreach (var stream in _streams)
                    {
                        stream?.Dispose();
                    }
                }
            }

            base.Dispose(disposing);
        }

        /// <summary>Maps a logical offset to the volume that holds it.</summary>
        private int IndexOf(long position)
        {
            if (position >= _length)
            {
                return _lengths.Length - 1;
            }

            var index = _index < 0 || _index >= _lengths.Length ? 0 : _index;

            while (index > 0 && _offsets[index] > position)
            {
                index--;
            }

            while (index < _lengths.Length - 1 && _offsets[index] + _lengths[index] <= position)
            {
                index++;
            }

            return index;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(ConcatenatedArchiveStream));
            }
        }
    }
}
