using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

public static partial class GlobalEdlBackup
{
    // The modern AOSP virtual_ab_message is the exact 64 bytes at offset 32768 inside misc.
    private const int GlobalVabMessageOffset = 32768;
    private const int GlobalVabMessageBytes = 64;
    private const int GlobalVabMinimumMiscBytes = GlobalVabMessageOffset + GlobalVabMessageBytes;
    private const string GlobalVabPartitionName = "misc";

    private const string GlobalVabUnconfirmedPrefix = "global-backup-android-update-unconfirmed:";
    private const string GlobalVabUnconfirmedMessage =
        "Cannot confirm Android update is complete; finish Android update and reboot Android before creating this backup.";

    /// <summary>
    /// Accepts only a well-formed virtual_ab_message whose status is exactly
    /// <see cref="BootVirtualAbState.Completed"/>. A zero, short, malformed or truncated header is never
    /// treated as Completed; every other state is refused with the stable
    /// <c>global-backup-android-update-unconfirmed:</c> prefix.
    /// </summary>
    internal static void RequireGlobalVabCompleted(ReadOnlySpan<byte> message)
    {
        var parsed = BootVirtualAbControl.ParseMessageBytes(message);

        if (!parsed.IsFormatValid || parsed.State != BootVirtualAbState.Completed)
        {
            throw new InvalidDataException(GlobalVabUnconfirmedPrefix + " " + GlobalVabUnconfirmedMessage);
        }
    }

    /// <summary>
    /// Proves that Android's last virtual A/B update is fully merged before any large partition of the
    /// capture is read. Only the single 512/4096-byte sector that holds misc's offset 32768 is fetched;
    /// the raw one-sector probe is kept as evidence. This never writes, resets or enumerates userdata.
    /// </summary>
    internal static async Task CaptureRequireCompletedVirtualAbAsync(
        EdlClient client,
        IReadOnlyDictionary<int, GptTable> tables,
        IReadOnlyList<EdlGeometry> geometries,
        string workDirectory,
        string logDirectory,
        IProgress<GlobalEdlProgress>? progress,
        CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(tables);
        ArgumentNullException.ThrowIfNull(geometries);
        if (string.IsNullOrWhiteSpace(workDirectory))
        {
            throw new ArgumentException("A work directory is required.", nameof(workDirectory));
        }

        if (string.IsNullOrWhiteSpace(logDirectory))
        {
            throw new ArgumentException("A log directory is required.", nameof(logDirectory));
        }

        token.ThrowIfCancellationRequested();

        if (geometries.Count < 1 || !tables.TryGetValue(0, out GptTable lun0) || lun0 is null)
        {
            throw GlobalVabUnconfirmed("the verified layout carries no LUN0 GPT table and geometry.");
        }

        EdlGeometry geometry = geometries[0];
        if (geometry is null || geometry.Lun != 0)
        {
            throw GlobalVabUnconfirmed("the verified geometry does not start with LUN0.");
        }

        int sectorSize = geometry.SectorSize;
        if (sectorSize != 512 && sectorSize != 4096)
        {
            throw GlobalVabUnconfirmed("LUN0 reports an unsupported sector size " + sectorSize + ".");
        }

        if (lun0.SectorSize != sectorSize)
        {
            throw GlobalVabUnconfirmed("the LUN0 GPT table and geometry disagree about the sector size.");
        }

        GptPartition? misc = null;
        foreach (GptPartition partition in lun0.Partitions)
        {
            if (!string.Equals(partition.Name, GlobalVabPartitionName, StringComparison.Ordinal))
            {
                continue;
            }

            if (misc is not null)
            {
                throw GlobalVabUnconfirmed("LUN0 carries more than one misc partition.");
            }

            misc = partition;
        }

        if (misc is null)
        {
            throw GlobalVabUnconfirmed("LUN0 carries no misc partition.");
        }

        if (misc.SectorCount <= 0)
        {
            throw GlobalVabUnconfirmed("the LUN0 misc partition carries no sectors.");
        }

        long miscBytes = checked(misc.SectorCount * (long)sectorSize);
        if (miscBytes < GlobalVabMinimumMiscBytes)
        {
            throw GlobalVabUnconfirmed(
                "the LUN0 misc partition holds " + miscBytes + " bytes, at least " + GlobalVabMinimumMiscBytes + " are required.");
        }

        int withinSector = GlobalVabMessageOffset % sectorSize;
        if (withinSector + GlobalVabMessageBytes > sectorSize)
        {
            throw GlobalVabUnconfirmed("the virtual A/B message does not fit inside one misc sector.");
        }

        long startSector = checked(misc.StartSector + (GlobalVabMessageOffset / sectorSize));
        long endSector = checked(startSector + 1);
        if (startSector < 0 || endSector > geometry.TotalSectors)
        {
            throw GlobalVabUnconfirmed("the virtual A/B message sector lies outside LUN0.");
        }

        string unique = Guid.NewGuid().ToString("N");
        string probePath = Path.Combine(workDirectory, "vab-misc-" + unique + ".bin");
        string logPrefix = CaptureLogPath(logDirectory, 0, "vab-misc-" + unique);

        CaptureReport(progress, "verify-backup", GlobalVabPartitionName, 0, 0, GlobalVabMessageBytes);

        EdlReadEvidence evidence = await client
            .ReadAsync(0, startSector, 1, probePath, null, logPrefix, token)
            .ConfigureAwait(false);

        CaptureExpectRead(evidence, sectorSize, "LUN 0 misc virtual A/B probe");
        string deviceSha = CaptureNormalizeSha(evidence.Sha256, "LUN 0 misc virtual A/B probe");

        byte[] sectorBytes = new byte[sectorSize];
        using (FileStream probe = new(
                   probePath,
                   FileMode.Open,
                   FileAccess.Read,
                   FileShare.Read,
                   sectorSize,
                   FileOptions.SequentialScan))
        {
            if (probe.Length != sectorSize)
            {
                throw GlobalVabUnconfirmed(
                    "the misc probe file holds " + probe.Length + " bytes, expected " + sectorSize + ".");
            }

            int offset = 0;
            while (offset < sectorBytes.Length)
            {
                token.ThrowIfCancellationRequested();
                int read = probe.Read(sectorBytes, offset, sectorBytes.Length - offset);
                if (read <= 0)
                {
                    throw GlobalVabUnconfirmed("the misc probe file ended before its sector was read.");
                }

                offset += read;
            }

            if (probe.ReadByte() != -1)
            {
                throw GlobalVabUnconfirmed("the misc probe file grew while it was verified.");
            }
        }

        string actualSha = Convert.ToHexString(SHA256.HashData(sectorBytes));
        if (!string.Equals(actualSha, deviceSha, StringComparison.OrdinalIgnoreCase))
        {
            throw GlobalVabUnconfirmed("the misc probe file digest does not match the device read.");
        }

        RequireGlobalVabCompleted(new ReadOnlySpan<byte>(sectorBytes, withinSector, GlobalVabMessageBytes));

        CaptureReport(progress, "verify-backup", GlobalVabPartitionName, 0, GlobalVabMessageBytes, GlobalVabMessageBytes);
    }

    /// <summary>
    /// Re-proves the same Completed virtual_ab_message from the archive's own misc region before the
    /// partition verification loop can hand out a restore set. Only the first misc chunk is decompressed;
    /// the sink keeps the 64 message bytes and discards every other byte, so no 64 MiB buffer is held.
    /// Read-only: no temporary file is created inside the backup directory.
    /// </summary>
    internal static async Task RequireArchiveVirtualAbCompletedAsync(
        string directory,
        GlobalEdlManifest manifest,
        CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        token.ThrowIfCancellationRequested();

        GlobalEdlRegion? miscRegion = null;
        foreach (GlobalEdlRegion region in manifest.Regions)
        {
            if (region.Lun != 0 ||
                !string.Equals(region.Kind, PartitionKind, StringComparison.Ordinal) ||
                !string.Equals(region.PartitionName, GlobalVabPartitionName, StringComparison.Ordinal))
            {
                continue;
            }

            if (miscRegion is not null)
            {
                throw GlobalVabUnconfirmed("the archive carries more than one LUN0 misc partition region.");
            }

            miscRegion = region;
        }

        if (miscRegion is null)
        {
            throw GlobalVabUnconfirmed("the archive carries no LUN0 misc partition region.");
        }

        if (miscRegion.Chunks is null || miscRegion.Chunks.Count == 0)
        {
            throw GlobalVabUnconfirmed("the archive's misc region carries no chunks.");
        }

        GlobalEdlChunk first = miscRegion.Chunks[0];
        if (first.OffsetBytes != 0 || first.RawBytes < GlobalVabMinimumMiscBytes)
        {
            throw GlobalVabUnconfirmed("the archive's misc region does not begin with the virtual A/B message window.");
        }

        using GlobalVabWindowSink sink = new();
        await VerifyChunkAsync(ResolveChunkPath(directory, first.FileName), first, sink, token).ConfigureAwait(false);

        if (!sink.IsWindowComplete)
        {
            throw GlobalVabUnconfirmed("the archive's misc chunk ended before the virtual A/B message window.");
        }

        RequireGlobalVabCompleted(sink.Window);
    }

    private static InvalidDataException GlobalVabUnconfirmed(string detail)
    {
        return new InvalidDataException(GlobalVabUnconfirmedPrefix + " " + detail);
    }

    /// <summary>
    /// Write-only sink that keeps exactly the 64 bytes [32768, 32832) of a decompressed misc chunk and
    /// silently discards every other byte while tracking the raw position.
    /// </summary>
    private sealed class GlobalVabWindowSink : Stream
    {
        private readonly byte[] _window = new byte[GlobalVabMessageBytes];
        private long _position;
        private int _covered;

        internal bool IsWindowComplete => _covered >= GlobalVabMessageBytes;

        internal ReadOnlySpan<byte> Window => _window;

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => _position;

        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
        {
            WriteCore(new ReadOnlySpan<byte>(buffer, offset, count));
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            WriteCore(buffer);
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
        {
            WriteCore(buffer.Span);
            return default;
        }

        private void WriteCore(ReadOnlySpan<byte> data)
        {
            long start = _position;
            long end = checked(start + data.Length);
            long windowStart = GlobalVabMessageOffset;
            long windowEnd = windowStart + GlobalVabMessageBytes;

            long copyStart = Math.Max(start, windowStart);
            long copyEnd = Math.Min(end, windowEnd);
            if (copyEnd > copyStart)
            {
                int sourceOffset = (int)(copyStart - start);
                int destinationOffset = (int)(copyStart - windowStart);
                int count = (int)(copyEnd - copyStart);
                data.Slice(sourceOffset, count).CopyTo(_window.AsSpan(destinationOffset, count));

                int covered = (int)(copyEnd - windowStart);
                if (covered > _covered)
                {
                    _covered = covered;
                }
            }

            _position = end;
        }
    }
}
