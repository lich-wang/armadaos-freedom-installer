#nullable enable

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core
{
    /// <summary>
    /// Validates the closed gzip + newc070701 maintenance initramfs format used by tablet RAM mode.
    /// This performs content-structure verification only; it makes no kernel-live, trust, boot-budget
    /// or readiness claim and never extracts entries to the filesystem.
    /// </summary>
    public static class TfMaintenanceInitramfsValidator
    {
        private const long MaxExpandedBytesLimit = 256L * 1024L * 1024L;
        private const int MaxNameBytes = 4096;
        private const int MaxEntries = 65536;
        private const int PrefixLimit = 4096;
        private const int HardlinkPrefixBudget = 8 * 1024 * 1024;
        private const int HeaderSize = 110;

        private const uint FileTypeMask = 0xF000u;
        private const uint RegularFileType = 0x8000u;
        private const uint DirectoryType = 0x4000u;
        private const uint SymlinkType = 0xA000u;

        private const string InitPath = "init";
        private const string BusyboxPath = "bin/busybox";
        private const string MarkerPath = "etc/armada/tf-maintenance.json";
        private const string TrailerName = "TRAILER!!!";

        private static readonly Encoding StrictUtf8 = new UTF8Encoding(false, true);
        private static readonly int[] FieldOffsets = { 6, 14, 22, 30, 38, 46, 54, 62, 70, 78, 86, 94, 102 };

        public static Task ValidateAsync(
            VerifiedEdlFile artifact,
            string expectedModel,
            string expectedKernelSha256,
            long maxExpandedBytes,
            CancellationToken ct = default)
        {
            if (artifact == null)
            {
                throw new ArgumentNullException(nameof(artifact));
            }

            if (string.IsNullOrEmpty(artifact.Path))
            {
                throw new ArgumentException("Artifact path is required.", nameof(artifact));
            }

            if (!IsCanonicalModel(expectedModel))
            {
                throw new ArgumentException("Expected model must be TB322FC or TB323FU.", nameof(expectedModel));
            }

            if (!IsSha64(expectedKernelSha256))
            {
                throw new ArgumentException("Expected kernel SHA-256 must be 64 hexadecimal characters.", nameof(expectedKernelSha256));
            }

            if (!IsSha64(artifact.Sha256))
            {
                throw new ArgumentException("Artifact SHA-256 must be 64 hexadecimal characters.", nameof(artifact));
            }

            if (maxExpandedBytes <= 0 || maxExpandedBytes > MaxExpandedBytesLimit)
            {
                throw new ArgumentOutOfRangeException(nameof(maxExpandedBytes), "Expansion limit must be positive and at most 256 MiB.");
            }

            if (artifact.Length <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(artifact), "Artifact length must be positive.");
            }

            string expectedKernel = expectedKernelSha256.ToLowerInvariant();
            string expectedSha = artifact.Sha256.ToLowerInvariant();

            return Task.Run(
                () => ValidateCoreAsync(artifact, expectedModel, expectedKernel, expectedSha, maxExpandedBytes, ct),
                ct);
        }

        private static async Task ValidateCoreAsync(
            VerifiedEdlFile artifact,
            string expectedModel,
            string expectedKernel,
            string expectedSha,
            long maxExpandedBytes,
            CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();

            string path = artifact.Path;
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                throw new FileNotFoundException("Artifact file was not found.", path);
            }

            if ((info.Attributes & FileAttributes.ReparsePoint) != 0 || info.LinkTarget != null)
            {
                throw new InvalidDataException("Artifact must be a regular file, not a link.");
            }

            if (info.Length != artifact.Length)
            {
                throw new InvalidDataException("Artifact length does not match the verified claim.");
            }

            await using var file = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);

            if (file.Length != artifact.Length)
            {
                throw new InvalidDataException("Artifact changed while it was being verified.");
            }

            string actualSha = (await HashStreamAsync(file, artifact.Length, ct).ConfigureAwait(false)).ToLowerInvariant();
            if (!string.Equals(actualSha, expectedSha, StringComparison.Ordinal))
            {
                throw new InvalidDataException("Artifact SHA-256 does not match the verified claim.");
            }

            file.Position = 0;

            await using var gzip = new GZipStream(file, CompressionMode.Decompress, leaveOpen: true);
            await ParseGzipAsync(gzip, maxExpandedBytes, expectedModel, expectedKernel, ct).ConfigureAwait(false);
        }

        private static async Task ParseGzipAsync(
            Stream gzip,
            long maxExpandedBytes,
            string expectedModel,
            string expectedKernel,
            CancellationToken ct)
        {
            var reader = new BoundedReader(gzip, maxExpandedBytes, ct);
            var seenPaths = new HashSet<string>(StringComparer.Ordinal);
            var inodes = new Dictionary<InodeKey, InodeRecord>();
            var required = new Dictionary<string, RequiredEntry>(StringComparer.Ordinal);
            var requiredInodePaths = new Dictionary<InodeKey, string>();

            byte[] header = new byte[HeaderSize];
            byte[] dataBuffer = new byte[64 * 1024];
            byte[] padding = new byte[4];

            long prefixBudget = HardlinkPrefixBudget;
            int entryCount = 0;
            bool sawTrailer = false;

            while (!sawTrailer)
            {
                ct.ThrowIfCancellationRequested();

                entryCount++;
                if (entryCount > MaxEntries)
                {
                    throw new InvalidDataException("Archive contains too many entries.");
                }

                if (!await reader.TryReadExactOrEofAsync(header, 0, HeaderSize).ConfigureAwait(false))
                {
                    throw new InvalidDataException("Archive is missing its TRAILER!!! entry.");
                }

                if (header[0] != (byte)'0' || header[1] != (byte)'7' || header[2] != (byte)'0' ||
                    header[3] != (byte)'7' || header[4] != (byte)'0' || header[5] != (byte)'1')
                {
                    throw new InvalidDataException("Archive is not a newc 070701 archive.");
                }

                uint[] fields = new uint[13];
                for (int i = 0; i < fields.Length; i++)
                {
                    fields[i] = ParseHex8(header.AsSpan(FieldOffsets[i], 8));
                }

                uint ino = fields[0];
                uint mode = fields[1];
                uint nlink = fields[4];
                long fileSize = fields[6];
                uint nameSize = fields[11];
                uint check = fields[12];

                if (check != 0)
                {
                    throw new InvalidDataException("newc header check field must be zero.");
                }

                if (nameSize == 0 || nameSize > MaxNameBytes)
                {
                    throw new InvalidDataException("Archive entry name size is invalid.");
                }

                if (fileSize > maxExpandedBytes)
                {
                    throw new InvalidDataException("Archive entry exceeds the allowed expansion limit.");
                }

                byte[] nameBytes = new byte[(int)nameSize];
                await reader.ReadExactAsync(nameBytes, 0, (int)nameSize).ConfigureAwait(false);

                if (nameBytes[nameBytes.Length - 1] != 0)
                {
                    throw new InvalidDataException("Archive entry name is not NUL terminated.");
                }

                int nameLength = nameBytes.Length;
                while (nameLength > 0 && nameBytes[nameLength - 1] == 0)
                {
                    nameLength--;
                }

                for (int i = 0; i < nameLength; i++)
                {
                    if (nameBytes[i] == 0)
                    {
                        throw new InvalidDataException("Archive entry name contains an interior NUL.");
                    }
                }

                string rawName;
                try
                {
                    rawName = StrictUtf8.GetString(nameBytes, 0, nameLength);
                }
                catch (DecoderFallbackException)
                {
                    throw new InvalidDataException("Archive entry name is not valid UTF-8.");
                }

                int namePadding = (4 - ((HeaderSize + (int)nameSize) & 3)) & 3;
                if (namePadding > 0)
                {
                    await reader.ReadExactAsync(padding, 0, namePadding).ConfigureAwait(false);
                }

                uint fileType = mode & FileTypeMask;
                bool isRegular = fileType == RegularFileType;
                bool isDirectory = fileType == DirectoryType;
                bool isSymlink = fileType == SymlinkType;

                if (!isRegular && !isSymlink && fileSize != 0)
                {
                    throw new InvalidDataException("Non-regular, non-symlink archive entry must not carry data.");
                }

                string path = Canonicalize(rawName, isDirectory);

                if (path == TrailerName)
                {
                    if (fileSize != 0)
                    {
                        throw new InvalidDataException("TRAILER!!! entry must have zero size.");
                    }

                    sawTrailer = true;
                    break;
                }

                if (!seenPaths.Add(path))
                {
                    throw new InvalidDataException("Archive contains a duplicate canonical path.");
                }

                bool isRequired = path == InitPath || path == BusyboxPath || path == MarkerPath;
                if (isRequired && !isRegular)
                {
                    throw new InvalidDataException($"Required entry '{path}' is not a regular file.");
                }

                bool hasInode = isRegular && nlink > 1;
                InodeKey inodeKey = hasInode ? new InodeKey(fields[7], fields[8], ino) : default;

                if (hasInode && fileSize > 0)
                {
                    long keep = Math.Min(fileSize, PrefixLimit);
                    if (keep > prefixBudget)
                    {
                        throw new InvalidDataException("Archive exceeds the bounded hardlink prefix budget.");
                    }

                    prefixBudget -= keep;
                }

                bool hashData = isRegular && (isRequired || nlink > 1);
                DataDigest? digest = null;
                if (fileSize > 0)
                {
                    digest = await ReadDataAsync(
                        reader,
                        fileSize,
                        hashData,
                        hashData ? PrefixLimit : 0,
                        dataBuffer,
                        ct).ConfigureAwait(false);
                }

                if (hasInode && fileSize > 0)
                {
                    if (!inodes.TryGetValue(inodeKey, out InodeRecord record))
                    {
                        record = new InodeRecord();
                        inodes.Add(inodeKey, record);
                    }

                    if (record.DataLength >= 0)
                    {
                        throw new InvalidDataException("Hardlink group carries more than one data body.");
                    }

                    DataDigest body = digest!;
                    record.DataLength = fileSize;
                    record.Sha256 = body.Sha256;
                    record.Prefix = body.Prefix;
                }

                if (isRequired)
                {
                    if (hasInode)
                    {
                        if (requiredInodePaths.TryGetValue(inodeKey, out string existingPath) &&
                            !string.Equals(existingPath, path, StringComparison.Ordinal))
                        {
                            throw new InvalidDataException("Required entries share an ambiguous hardlink identity.");
                        }

                        requiredInodePaths[inodeKey] = path;
                    }

                    required.Add(path, new RequiredEntry
                    {
                        Path = path,
                        Executable = (mode & 0x49u) != 0,
                        Digest = digest,
                        HasInode = hasInode,
                        Inode = inodeKey
                    });
                }

                int dataPadding = (int)((4 - (fileSize & 3)) & 3);
                if (dataPadding > 0)
                {
                    await reader.ReadExactAsync(padding, 0, dataPadding).ConfigureAwait(false);
                }
            }

            byte[] zeroBuffer = new byte[8 * 1024];
            while (true)
            {
                int read = await reader.ReadAsync(zeroBuffer.AsMemory(0, zeroBuffer.Length)).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                for (int i = 0; i < read; i++)
                {
                    if (zeroBuffer[i] != 0)
                    {
                        throw new InvalidDataException("Non-zero data follows the TRAILER!!! entry.");
                    }
                }
            }

            ValidateRequiredEntries(required, inodes, expectedModel, expectedKernel);
        }

        private static async ValueTask<DataDigest> ReadDataAsync(
            BoundedReader reader,
            long length,
            bool hash,
            int prefixLimit,
            byte[] buffer,
            CancellationToken ct)
        {
            var digest = new DataDigest { Length = length };

            IncrementalHash? hasher = hash ? IncrementalHash.CreateHash(HashAlgorithmName.SHA256) : null;
            try
            {
                int prefixSize = hash ? (int)Math.Min(length, prefixLimit) : 0;
                byte[] prefix = prefixSize > 0 ? new byte[prefixSize] : Array.Empty<byte>();
                int prefixWritten = 0;
                long remaining = length;

                while (remaining > 0)
                {
                    ct.ThrowIfCancellationRequested();

                    int want = (int)Math.Min(remaining, buffer.Length);
                    int read = await reader.ReadAsync(buffer.AsMemory(0, want)).ConfigureAwait(false);
                    if (read == 0)
                    {
                        throw new InvalidDataException("Archive entry data is truncated.");
                    }

                    hasher?.AppendData(buffer, 0, read);

                    if (prefixWritten < prefix.Length)
                    {
                        int copy = Math.Min(read, prefix.Length - prefixWritten);
                        Buffer.BlockCopy(buffer, 0, prefix, prefixWritten, copy);
                        prefixWritten += copy;
                    }

                    remaining -= read;
                }

                if (hasher != null)
                {
                    digest.Sha256 = Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
                }

                digest.Prefix = prefix;
                return digest;
            }
            finally
            {
                hasher?.Dispose();
            }
        }

        private static void ValidateRequiredEntries(
            Dictionary<string, RequiredEntry> required,
            Dictionary<InodeKey, InodeRecord> inodes,
            string expectedModel,
            string expectedKernel)
        {
            RequiredEntry init = GetRequired(required, InitPath);
            if (!init.Executable)
            {
                throw new InvalidDataException("'init' must be executable.");
            }

            DataDigest initData = ResolveData(init, inodes);
            if (initData.Length <= 0)
            {
                throw new InvalidDataException("'init' must not be empty.");
            }

            ValidateInitScript(initData);

            RequiredEntry busybox = GetRequired(required, BusyboxPath);
            if (!busybox.Executable)
            {
                throw new InvalidDataException("'bin/busybox' must be executable.");
            }

            ValidateBusyboxElf(ResolveData(busybox, inodes));

            RequiredEntry marker = GetRequired(required, MarkerPath);
            DataDigest markerData = ResolveData(marker, inodes);
            if (markerData.Length <= 0 || markerData.Length > 4096)
            {
                throw new InvalidDataException("Maintenance marker size is invalid.");
            }

            if (markerData.Prefix.Length != markerData.Length)
            {
                throw new InvalidDataException("Maintenance marker content was not retained in full.");
            }

            ValidateMarkerJson(markerData.Prefix, expectedModel, expectedKernel);
        }

        private static RequiredEntry GetRequired(Dictionary<string, RequiredEntry> required, string path)
        {
            if (!required.TryGetValue(path, out RequiredEntry entry))
            {
                throw new InvalidDataException($"Required entry '{path}' is missing.");
            }

            return entry;
        }

        private static DataDigest ResolveData(RequiredEntry entry, Dictionary<InodeKey, InodeRecord> inodes)
        {
            DataDigest? direct = entry.Digest;
            if (direct != null)
            {
                return direct;
            }

            if (entry.HasInode &&
                inodes.TryGetValue(entry.Inode, out InodeRecord record) &&
                record.DataLength >= 0)
            {
                return new DataDigest
                {
                    Length = record.DataLength,
                    Sha256 = record.Sha256,
                    Prefix = record.Prefix
                };
            }

            throw new InvalidDataException($"Required entry '{entry.Path}' has no resolvable hardlink data.");
        }

        private static void ValidateInitScript(DataDigest data)
        {
            byte[] prefix = data.Prefix;
            if (prefix.Length == 0)
            {
                throw new InvalidDataException("'init' script prefix is unavailable.");
            }

            int lineEnd = -1;
            for (int i = 0; i < prefix.Length; i++)
            {
                if (prefix[i] == (byte)'\n')
                {
                    lineEnd = i;
                    break;
                }
            }

            if (lineEnd < 0)
            {
                if (data.Length > prefix.Length)
                {
                    throw new InvalidDataException("'init' script first line is incomplete within the bounded prefix.");
                }

                lineEnd = prefix.Length;
            }

            if (lineEnd < 2 || prefix[0] != (byte)'#' || prefix[1] != (byte)'!')
            {
                throw new InvalidDataException("'init' must start with a '#!' script line.");
            }

            int index = 2;
            while (index < lineEnd && (prefix[index] == (byte)' ' || prefix[index] == (byte)'\t'))
            {
                index++;
            }

            if (index >= lineEnd || prefix[index] != (byte)'/')
            {
                throw new InvalidDataException("'init' script line must name a nonempty absolute interpreter.");
            }

            while (index < lineEnd && prefix[index] != (byte)' ' && prefix[index] != (byte)'\t')
            {
                byte c = prefix[index];
                if (c == 0 || (c < 0x20 && c != (byte)'\t') || c == 0x7F)
                {
                    throw new InvalidDataException("'init' script interpreter contains an invalid control character.");
                }

                index++;
            }
        }

        private static void ValidateBusyboxElf(DataDigest data)
        {
            if (data.Length < 64 || data.Prefix.Length < 64)
            {
                throw new InvalidDataException("'bin/busybox' is too small to be an ELF64 binary.");
            }

            byte[] p = data.Prefix;
            if (p[0] != 0x7F || p[1] != (byte)'E' || p[2] != (byte)'L' || p[3] != (byte)'F')
            {
                throw new InvalidDataException("'bin/busybox' is not an ELF file.");
            }

            if (p[4] != 2 || p[5] != 1 || p[6] != 1)
            {
                throw new InvalidDataException("'bin/busybox' is not a little-endian ELF64 file.");
            }

            ushort type = BinaryPrimitives.ReadUInt16LittleEndian(p.AsSpan(16, 2));
            ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(p.AsSpan(18, 2));

            if (type != 2 && type != 3)
            {
                throw new InvalidDataException("'bin/busybox' ELF type must be ET_EXEC or ET_DYN.");
            }

            if (machine != 183)
            {
                throw new InvalidDataException("'bin/busybox' ELF machine must be AArch64.");
            }
        }

        private static void ValidateMarkerJson(byte[] json, string expectedModel, string expectedKernel)
        {
            JsonDocument document;
            try
            {
                document = JsonDocument.Parse(
                    new ReadOnlyMemory<byte>(json),
                    new JsonDocumentOptions
                    {
                        AllowTrailingCommas = false,
                        CommentHandling = JsonCommentHandling.Disallow
                    });
            }
            catch (JsonException)
            {
                throw new InvalidDataException("Maintenance marker is not valid JSON.");
            }

            using (document)
            {
                JsonElement root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                {
                    throw new InvalidDataException("Maintenance marker must be a JSON object.");
                }

                var names = new HashSet<string>(StringComparer.Ordinal);
                bool schemaOk = false;
                bool modelOk = false;
                bool kernelOk = false;
                bool transportOk = false;

                foreach (JsonProperty property in root.EnumerateObject())
                {
                    if (!names.Add(property.Name))
                    {
                        throw new InvalidDataException("Maintenance marker contains a duplicate JSON field.");
                    }

                    switch (property.Name)
                    {
                        case "schema":
                            if (property.Value.ValueKind != JsonValueKind.Number ||
                                !property.Value.TryGetInt32(out int schema) ||
                                schema != 1)
                            {
                                throw new InvalidDataException("Maintenance marker schema must be 1.");
                            }

                            schemaOk = true;
                            break;

                        case "expectedModel":
                            if (property.Value.ValueKind != JsonValueKind.String ||
                                !string.Equals(property.Value.GetString(), expectedModel, StringComparison.Ordinal))
                            {
                                throw new InvalidDataException("Maintenance marker expectedModel does not match.");
                            }

                            modelOk = true;
                            break;

                        case "kernelSha256":
                            string? kernel = property.Value.ValueKind == JsonValueKind.String
                                ? property.Value.GetString()
                                : null;
                            if (!IsSha64(kernel) ||
                                !string.Equals(kernel, expectedKernel, StringComparison.OrdinalIgnoreCase))
                            {
                                throw new InvalidDataException("Maintenance marker kernelSha256 does not match.");
                            }

                            kernelOk = true;
                            break;

                        case "transportProtocol":
                            if (property.Value.ValueKind != JsonValueKind.String ||
                                !string.Equals(property.Value.GetString(), "tf-card-v1", StringComparison.Ordinal))
                            {
                                throw new InvalidDataException("Maintenance marker transportProtocol is invalid.");
                            }

                            transportOk = true;
                            break;

                        default:
                            throw new InvalidDataException("Maintenance marker contains an unexpected JSON field.");
                    }
                }

                if (!schemaOk || !modelOk || !kernelOk || !transportOk || names.Count != 4)
                {
                    throw new InvalidDataException("Maintenance marker must contain exactly the four required JSON fields.");
                }
            }
        }

        private static string Canonicalize(string rawName, bool isDirectory)
        {
            if (rawName.Length == 0)
            {
                throw new InvalidDataException("Archive entry has an empty name.");
            }

            string value = rawName;
            if (value.Length > 2 && value[0] == '.' && value[1] == '/')
            {
                value = value.Substring(2);
            }

            if (value.Length == 0)
            {
                throw new InvalidDataException("Archive entry path is empty after normalization.");
            }

            if (value == ".")
            {
                if (!isDirectory)
                {
                    throw new InvalidDataException("The '.' entry must be a directory.");
                }

                return value;
            }

            if (value[0] == '/')
            {
                throw new InvalidDataException("Archive entry path must not be absolute.");
            }

            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                if (c == '\0' || c == '\\' || c == ':' || c < 0x20)
                {
                    throw new InvalidDataException("Archive entry path contains an unsafe character.");
                }
            }

            if (value[value.Length - 1] == '/')
            {
                throw new InvalidDataException("Archive entry path must not end with a slash.");
            }

            string[] segments = value.Split('/');
            for (int i = 0; i < segments.Length; i++)
            {
                string segment = segments[i];
                if (segment.Length == 0 || segment == "." || segment == "..")
                {
                    throw new InvalidDataException("Archive entry path contains an empty, current or parent segment.");
                }
            }

            return value;
        }

        private static uint ParseHex8(ReadOnlySpan<byte> value)
        {
            uint result = 0;
            for (int i = 0; i < 8; i++)
            {
                byte b = value[i];
                int digit;
                if (b >= (byte)'0' && b <= (byte)'9')
                {
                    digit = b - (byte)'0';
                }
                else if (b >= (byte)'a' && b <= (byte)'f')
                {
                    digit = b - (byte)'a' + 10;
                }
                else if (b >= (byte)'A' && b <= (byte)'F')
                {
                    digit = b - (byte)'A' + 10;
                }
                else
                {
                    throw new InvalidDataException("newc header contains a non-hexadecimal field.");
                }

                result = (result << 4) | (uint)digit;
            }

            return result;
        }

        private static async Task<string> HashStreamAsync(FileStream stream, long expectedLength, CancellationToken ct)
        {
            if (stream.Length != expectedLength)
            {
                throw new InvalidDataException("Artifact length does not match the verified claim.");
            }

            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            byte[] buffer = new byte[64 * 1024];
            long total = 0;

            while (true)
            {
                ct.ThrowIfCancellationRequested();
                int read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                total += read;
                if (total > expectedLength)
                {
                    throw new InvalidDataException("Artifact length does not match the verified claim.");
                }

                hash.AppendData(buffer, 0, read);
            }

            if (total != expectedLength)
            {
                throw new InvalidDataException("Artifact length does not match the verified claim.");
            }

            return Convert.ToHexString(hash.GetHashAndReset());
        }

        private static bool IsCanonicalModel(string? model)
        {
            return model == "TB322FC" || model == "TB323FU";
        }

        private static bool IsSha64(string? value)
        {
            if (value == null || value.Length != 64)
            {
                return false;
            }

            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                bool hex = (c >= '0' && c <= '9') ||
                           (c >= 'a' && c <= 'f') ||
                           (c >= 'A' && c <= 'F');
                if (!hex)
                {
                    return false;
                }
            }

            return true;
        }

        private readonly struct InodeKey : IEquatable<InodeKey>
        {
            public InodeKey(uint devMajor, uint devMinor, uint ino)
            {
                DevMajor = devMajor;
                DevMinor = devMinor;
                Ino = ino;
            }

            public uint DevMajor { get; }

            public uint DevMinor { get; }

            public uint Ino { get; }

            public bool Equals(InodeKey other)
            {
                return DevMajor == other.DevMajor && DevMinor == other.DevMinor && Ino == other.Ino;
            }

            public override bool Equals(object? obj)
            {
                return obj is InodeKey other && Equals(other);
            }

            public override int GetHashCode()
            {
                return HashCode.Combine(DevMajor, DevMinor, Ino);
            }
        }

        private sealed class InodeRecord
        {
            public long DataLength = -1;
            public string Sha256 = string.Empty;
            public byte[] Prefix = Array.Empty<byte>();
        }

        private sealed class RequiredEntry
        {
            public string Path = string.Empty;
            public bool Executable;
            public DataDigest? Digest;
            public bool HasInode;
            public InodeKey Inode;
        }

        private sealed class DataDigest
        {
            public long Length;
            public string Sha256 = string.Empty;
            public byte[] Prefix = Array.Empty<byte>();
        }

        private sealed class BoundedReader
        {
            private readonly Stream stream;
            private readonly long maxBytes;
            private readonly CancellationToken ct;
            private readonly byte[] buffer = new byte[64 * 1024];
            private int offset;
            private int count;
            private long total;

            public BoundedReader(Stream stream, long maxBytes, CancellationToken ct)
            {
                this.stream = stream;
                this.maxBytes = maxBytes;
                this.ct = ct;
            }

            public async ValueTask<int> ReadAsync(Memory<byte> destination)
            {
                if (destination.Length == 0)
                {
                    return 0;
                }

                if (offset == count)
                {
                    int read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false);
                    if (read == 0)
                    {
                        return 0;
                    }

                    total += read;
                    if (total > maxBytes)
                    {
                        throw new InvalidDataException("Archive expands beyond the allowed limit.");
                    }

                    offset = 0;
                    count = read;
                }

                int take = Math.Min(destination.Length, count - offset);
                buffer.AsSpan(offset, take).CopyTo(destination.Span);
                offset += take;
                return take;
            }

            public async ValueTask ReadExactAsync(byte[] destination, int destinationOffset, int length)
            {
                int done = 0;
                while (done < length)
                {
                    int read = await ReadAsync(destination.AsMemory(destinationOffset + done, length - done)).ConfigureAwait(false);
                    if (read == 0)
                    {
                        throw new InvalidDataException("Archive is truncated.");
                    }

                    done += read;
                }
            }

            public async ValueTask<bool> TryReadExactOrEofAsync(byte[] destination, int destinationOffset, int length)
            {
                int done = 0;
                while (done < length)
                {
                    int read = await ReadAsync(destination.AsMemory(destinationOffset + done, length - done)).ConfigureAwait(false);
                    if (read == 0)
                    {
                        if (done == 0)
                        {
                            return false;
                        }

                        throw new InvalidDataException("Archive is truncated.");
                    }

                    done += read;
                }

                return true;
            }
        }
    }
}
