using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// The frozen identity of the card target a raw write is bound to. Every field is fixed when the
/// target is first opened and must be reproduced exactly by every revalidation before and after the
/// write; any difference aborts the write.
/// </summary>
/// <param name="Source">Kind of target the card is bound to.</param>
/// <param name="Key">Target key, always prefixed <c>tablet:</c> or <c>reader:</c> to match
/// <see cref="Source"/>.</param>
/// <param name="DevicePath">Nonempty device path of the card.</param>
/// <param name="SizeBytes">Card size in bytes: positive and aligned to
/// <see cref="LogicalSectorSize"/>.</param>
/// <param name="LogicalSectorSize">Logical sector size: 512 or 4096 bytes.</param>
/// <param name="BindingSha256">64 hexadecimal digits binding this identity to the opened target.</param>
public sealed record TfCardTargetIdentity(
    TfCardSource Source,
    string Key,
    string DevicePath,
    long SizeBytes,
    int LogicalSectorSize,
    string BindingSha256);

/// <summary>
/// One opened, raw sector-addressable TF card target. The writer uses exact offsets only; it never
/// repositions a shared cursor, resets, or touches anything outside this card. The caller owns the
/// target and disposes it; the writer never does.
/// </summary>
public interface ITfCardWriteTarget : IAsyncDisposable
{
    /// <summary>The frozen identity captured when the target was opened.</summary>
    TfCardTargetIdentity Identity { get; }

    /// <summary>Re-reads the actual identity of the opened target right now; every frozen field must
    /// come back exactly equal or the write aborts.</summary>
    ValueTask<TfCardTargetIdentity> RevalidateAsync(CancellationToken ct = default);

    /// <summary>Reads exactly <c>buffer.Length</c> bytes at the byte offset, or fails.</summary>
    ValueTask ReadExactlyAsync(long offset, Memory<byte> buffer, CancellationToken ct = default);

    /// <summary>Writes <c>buffer</c> at the byte offset. The writer only ever issues sector-aligned
    /// ranges that were checked to lie inside the planned regions of this card.</summary>
    ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> buffer, CancellationToken ct = default);

    /// <summary>Flushes all previously written bytes so the following read-back verifies real card
    /// contents, not a cache.</summary>
    ValueTask FlushAsync(CancellationToken ct = default);
}

/// <summary>Stages of the raw card write-and-verify pipeline, in execution order. Writing stages and
/// read-back verification stages are reported separately.</summary>
public enum TfCardWriteStage
{
    Revalidating,
    WritingGpt,
    WritingBoot,
    WritingRoot,
    VerifyingGpt,
    VerifyingBoot,
    VerifyingRoot,
    Completed
}

/// <summary>One factual progress report of the raw card write. <see cref="BytesCompleted"/> and
/// <see cref="TotalBytes"/> carry the actual expanded byte counts during image write and read-back
/// stages; both may be null for stages without a byte stream.</summary>
/// <param name="Stage">Current stage.</param>
/// <param name="BytesCompleted">Actual bytes handled so far in this stage, when applicable.</param>
/// <param name="TotalBytes">Actual total bytes of this stage, when applicable.</param>
/// <param name="Detail">Short factual detail, when applicable.</param>
public sealed record TfCardWriteProgress(
    TfCardWriteStage Stage,
    long? BytesCompleted,
    long? TotalBytes,
    string? Detail);

/// <summary>Factual proof of one fully verified raw TF card write: the identity that was revalidated
/// before and after the write, the layout that was written and parsed back, the package fingerprint
/// and the two declared expanded image hashes that the read-back confirmed. <see cref="FullyVerified"/>
/// is true only for instances produced by the internal success constructor; nothing else can mint
/// evidence.</summary>
public sealed class TfCardWriteEvidence
{
    internal TfCardWriteEvidence(
        TfCardTargetIdentity target,
        TfCardLayoutPlan layout,
        string manifestFingerprint,
        string bootImageSha256,
        string rootImageSha256)
    {
        Target = target;
        Layout = layout;
        ManifestFingerprint = manifestFingerprint;
        BootImageSha256 = bootImageSha256;
        RootImageSha256 = rootImageSha256;
        FullyVerified = true;
    }

    /// <summary>The frozen target identity that survived revalidation before and after the write.</summary>
    public TfCardTargetIdentity Target { get; }

    /// <summary>The planned layout that was written and independently parsed back.</summary>
    public TfCardLayoutPlan Layout { get; }

    /// <summary>Manifest fingerprint of the prepared package the images came from.</summary>
    public string ManifestFingerprint { get; }

    /// <summary>Declared expanded boot image SHA-256 confirmed by complete read-back.</summary>
    public string BootImageSha256 { get; }

    /// <summary>Declared expanded root image SHA-256 confirmed by complete read-back.</summary>
    public string RootImageSha256 { get; }

    /// <summary>Always true on evidence; only the internal success constructor can create evidence.</summary>
    public bool FullyVerified { get; }
}

/// <summary>
/// Streams one prepared TF card (new GPT plus the two gzip-expanded images) onto a raw card target
/// and verifies every written byte by read-back. No full-card or raw-image allocation, no zeroing,
/// no temp files, no retry: any exception or cancellation stops the write immediately with no later
/// writes and no evidence, and the consumed preparation must be redone for a retry. The caller keeps
/// ownership of, and disposal duty for, both the target and the prepared images. This card proof is
/// not a whole-install completion statement.
/// </summary>
public static class TfCardRawWriter
{
    private const int CopyBufferBytes = 1024 * 1024;
    private const string TabletKeyPrefix = "tablet:";
    private const string ReaderKeyPrefix = "reader:";
    private const string BootPartitionName = "ARMADA_TF_BOOT";
    private const string RootPartitionName = "ARMADA_TF_ROOT";

    /// <summary>Writes the planned GPT and both expanded images onto the card and verifies everything
    /// by read-back, reporting writing and verification progress. On success returns factual
    /// fully-verified evidence; on any failure the exception propagates and no evidence exists.</summary>
    public static async Task<TfCardWriteEvidence> WriteAndVerifyAsync(
        TfPreparedCardImages images,
        ITfCardWriteTarget target,
        TfCardLayoutPlan layout,
        IProgress<TfCardWriteProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(images);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(layout);
        cancellationToken.ThrowIfCancellationRequested();

        images.ClaimWriteAttempt();

        progress?.Report(new TfCardWriteProgress(
            TfCardWriteStage.Revalidating, null, null, "Checking the frozen target identity and layout."));

        var frozen = target.Identity;
        ValidateFrozenIdentity(frozen);

        var actual = await target.RevalidateAsync(cancellationToken).ConfigureAwait(false);
        if (!frozen.Equals(actual))
        {
            throw new InvalidOperationException(
                "The card target no longer matches its frozen identity; refusing to write.");
        }

        if (actual.SizeBytes != layout.CardBytes || actual.LogicalSectorSize != layout.LogicalSectorSize)
        {
            throw new InvalidOperationException(
                "The actual card geometry does not match the planned layout.");
        }

        ValidatePartitionRanges(layout, actual.LogicalSectorSize);

        var contract = images.Contract;
        var bootImage = contract.BootImage;
        var rootImage = contract.RootImage;
        var sector = layout.LogicalSectorSize;

        checked
        {
            if (bootImage.ExpandedBytes % sector != 0
                || bootImage.ExpandedBytes > layout.BootSectorCount * sector
                || bootImage.MinimumPartitionBytes > layout.BootSectorCount * sector)
            {
                throw new InvalidOperationException(
                    "The declared expanded boot image does not fit its planned partition.");
            }

            if (rootImage.ExpandedBytes % sector != 0
                || rootImage.ExpandedBytes > layout.RootSectorCount * sector
                || rootImage.MinimumPartitionBytes > layout.RootSectorCount * sector)
            {
                throw new InvalidOperationException(
                    "The declared expanded root image does not fit its planned partition.");
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        await images.RevalidateAsync(cancellationToken).ConfigureAwait(false);

        var gpt = TfCardLayout.SerializeGpt(layout);
        ValidateGptRange(gpt.PrimaryOffsetBytes, gpt.PrimaryBytes.Length, actual.LogicalSectorSize, actual.SizeBytes);
        ValidateGptRange(gpt.BackupOffsetBytes, gpt.BackupBytes.Length, actual.LogicalSectorSize, actual.SizeBytes);

        long bootOffset = checked(layout.BootStartSector * sector);
        long rootOffset = checked(layout.RootStartSector * sector);
        var buffer = new byte[CopyBufferBytes];

        progress?.Report(new TfCardWriteProgress(
            TfCardWriteStage.WritingGpt, null, null,
            $"Writing the GPT primary fragment at byte {gpt.PrimaryOffsetBytes} and the backup at byte {gpt.BackupOffsetBytes}."));
        await target.WriteAsync(gpt.PrimaryOffsetBytes, gpt.PrimaryBytes, cancellationToken).ConfigureAwait(false);
        await target.WriteAsync(gpt.BackupOffsetBytes, gpt.BackupBytes, cancellationToken).ConfigureAwait(false);

        progress?.Report(new TfCardWriteProgress(
            TfCardWriteStage.WritingBoot, 0, bootImage.ExpandedBytes,
            $"Writing the expanded boot image at byte {bootOffset}."));
        await using (var bootStream = images.OpenExpandedBoot())
        {
            await CopyImageAsync(
                target, bootStream, bootOffset, bootImage.ExpandedBytes,
                TfCardWriteStage.WritingBoot, progress, buffer, cancellationToken).ConfigureAwait(false);
        }

        progress?.Report(new TfCardWriteProgress(
            TfCardWriteStage.WritingRoot, 0, rootImage.ExpandedBytes,
            $"Writing the expanded root image at byte {rootOffset}."));
        await using (var rootStream = images.OpenExpandedRoot())
        {
            await CopyImageAsync(
                target, rootStream, rootOffset, rootImage.ExpandedBytes,
                TfCardWriteStage.WritingRoot, progress, buffer, cancellationToken).ConfigureAwait(false);
        }

        await target.FlushAsync(cancellationToken).ConfigureAwait(false);

        progress?.Report(new TfCardWriteProgress(
            TfCardWriteStage.VerifyingGpt, null, null, "Reading back and parsing both GPT fragments."));
        await VerifyGptAsync(target, gpt, layout, cancellationToken).ConfigureAwait(false);

        progress?.Report(new TfCardWriteProgress(
            TfCardWriteStage.VerifyingBoot, 0, bootImage.ExpandedBytes,
            $"Hashing the written boot image at byte {bootOffset}."));
        await VerifyWrittenImageAsync(
            target, bootOffset, bootImage.ExpandedBytes, bootImage.ExpandedSha256, "boot",
            TfCardWriteStage.VerifyingBoot, progress, buffer, cancellationToken).ConfigureAwait(false);

        progress?.Report(new TfCardWriteProgress(
            TfCardWriteStage.VerifyingRoot, 0, rootImage.ExpandedBytes,
            $"Hashing the written root image at byte {rootOffset}."));
        await VerifyWrittenImageAsync(
            target, rootOffset, rootImage.ExpandedBytes, rootImage.ExpandedSha256, "root",
            TfCardWriteStage.VerifyingRoot, progress, buffer, cancellationToken).ConfigureAwait(false);

        var final = await target.RevalidateAsync(cancellationToken).ConfigureAwait(false);
        if (!frozen.Equals(final))
        {
            throw new InvalidOperationException(
                "The card target identity changed during the write; refusing to report evidence.");
        }

        progress?.Report(new TfCardWriteProgress(
            TfCardWriteStage.Completed, null, null, "The card write is fully verified."));
        return new TfCardWriteEvidence(
            frozen, layout, contract.ManifestFingerprint,
            bootImage.ExpandedSha256, rootImage.ExpandedSha256);
    }

    private static void ValidateFrozenIdentity(TfCardTargetIdentity identity)
    {
        if (!Enum.IsDefined(identity.Source))
        {
            throw new InvalidOperationException("The frozen card target source is not defined.");
        }

        var prefix = identity.Source == TfCardSource.Tablet ? TabletKeyPrefix : ReaderKeyPrefix;
        if (identity.Key is null || !identity.Key.StartsWith(prefix, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The frozen card target key must start with \"{prefix}\".");
        }

        if (string.IsNullOrWhiteSpace(identity.DevicePath))
        {
            throw new InvalidOperationException("The frozen card target device path must not be empty.");
        }

        if (identity.LogicalSectorSize != 512 && identity.LogicalSectorSize != 4096)
        {
            throw new InvalidOperationException(
                "The frozen card target logical sector size must be 512 or 4096 bytes.");
        }

        if (identity.SizeBytes <= 0 || identity.SizeBytes % identity.LogicalSectorSize != 0)
        {
            throw new InvalidOperationException(
                "The frozen card target size must be positive and aligned to its logical sector size.");
        }

        if (!IsHex64(identity.BindingSha256))
        {
            throw new InvalidOperationException(
                "The frozen card target binding hash must be 64 hexadecimal digits.");
        }
    }

    private static bool IsHex64(string? value)
    {
        if (value is null || value.Length != 64)
        {
            return false;
        }

        foreach (var c in value)
        {
            if (!Uri.IsHexDigit(c))
            {
                return false;
            }
        }

        return true;
    }

    private static void ValidatePartitionRanges(TfCardLayoutPlan layout, int sectorSize)
    {
        checked
        {
            if (layout.TotalSectors <= 0 || layout.CardBytes <= 0)
            {
                throw new InvalidOperationException("The planned layout must cover a positive card size.");
            }

            if (layout.TotalSectors > layout.CardBytes / sectorSize)
            {
                throw new InvalidOperationException("The planned sectors exceed the card size.");
            }

            if (layout.BootSectorCount <= 0 || layout.RootSectorCount <= 0)
            {
                throw new InvalidOperationException("The planned partitions must have a positive size.");
            }

            long bootEnd = layout.BootStartSector + layout.BootSectorCount;
            long rootEnd = layout.RootStartSector + layout.RootSectorCount;
            if (layout.BootStartSector < 0 || bootEnd > layout.TotalSectors)
            {
                throw new InvalidOperationException("The planned boot partition is outside the card.");
            }

            if (layout.RootStartSector < 0 || rootEnd > layout.TotalSectors)
            {
                throw new InvalidOperationException("The planned root partition is outside the card.");
            }

            if (layout.BootStartSector < rootEnd && layout.RootStartSector < bootEnd)
            {
                throw new InvalidOperationException("The planned boot and root partitions overlap.");
            }
        }
    }

    private static void ValidateGptRange(long offset, int length, int sectorSize, long cardBytes)
    {
        if (offset < 0 || length <= 0)
        {
            throw new InvalidOperationException("The serialized GPT fragment placement is invalid.");
        }

        checked
        {
            if (offset % sectorSize != 0
                || length % sectorSize != 0
                || offset + length > cardBytes)
            {
                throw new InvalidOperationException(
                    "A serialized GPT fragment must be sector-aligned and inside the card.");
            }
        }
    }

    /// <summary>Streams exactly the declared expanded bytes from the gzip reader onto the card. GZip
    /// may return short or unaligned reads, so each aligned chunk is read exactly before it is
    /// written; one extra raw byte past the declared length is rejected.</summary>
    private static async Task CopyImageAsync(
        ITfCardWriteTarget target,
        Stream expandedImage,
        long offset,
        long expectedBytes,
        TfCardWriteStage stage,
        IProgress<TfCardWriteProgress>? progress,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        long written = 0;
        while (written < expectedBytes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var chunk = (int)Math.Min(buffer.Length, expectedBytes - written);
            await expandedImage.ReadExactlyAsync(buffer.AsMemory(0, chunk), cancellationToken).ConfigureAwait(false);
            await target.WriteAsync(offset + written, buffer.AsMemory(0, chunk), cancellationToken).ConfigureAwait(false);
            written += chunk;
            progress?.Report(new TfCardWriteProgress(stage, written, expectedBytes, null));
        }

        if (await expandedImage.ReadAsync(buffer.AsMemory(0, 1), cancellationToken).ConfigureAwait(false) > 0)
        {
            throw new InvalidOperationException(
                "The expanded image has more raw bytes than its declared length.");
        }
    }

    private static async Task VerifyGptAsync(
        ITfCardWriteTarget target,
        TfGptWriteSet gpt,
        TfCardLayoutPlan layout,
        CancellationToken cancellationToken)
    {
        var primary = await ReadFragmentAsync(target, gpt.PrimaryOffsetBytes, gpt.PrimaryBytes.Length, cancellationToken).ConfigureAwait(false);
        if (!primary.AsSpan().SequenceEqual(gpt.PrimaryBytes))
        {
            throw new InvalidOperationException("The primary GPT read-back does not match the written bytes.");
        }

        var backup = await ReadFragmentAsync(target, gpt.BackupOffsetBytes, gpt.BackupBytes.Length, cancellationToken).ConfigureAwait(false);
        if (!backup.AsSpan().SequenceEqual(gpt.BackupBytes))
        {
            throw new InvalidOperationException("The backup GPT read-back does not match the written bytes.");
        }

        var table = OriginalGptImporter.Parse(primary, backup, layout.LogicalSectorSize, layout.CardBytes);
        if (!GuidMatches(table.DiskGuid, layout.DiskGuid))
        {
            throw new InvalidOperationException("The parsed disk GUID does not match the planned disk GUID.");
        }

        if (table.Partitions.Count != 2)
        {
            throw new InvalidOperationException("The parsed GPT must hold exactly the boot and root partitions.");
        }

        VerifyPartition(table.Partitions[0], 1, BootPartitionName, layout.BootGuid, layout.BootStartSector, layout.BootSectorCount);
        VerifyPartition(table.Partitions[1], 2, RootPartitionName, layout.RootGuid, layout.RootStartSector, layout.RootSectorCount);
    }

    private static async Task<byte[]> ReadFragmentAsync(
        ITfCardWriteTarget target,
        long offset,
        int length,
        CancellationToken cancellationToken)
    {
        var fragment = new byte[length];
        await target.ReadExactlyAsync(offset, fragment, cancellationToken).ConfigureAwait(false);
        return fragment;
    }

    private static void VerifyPartition(
        GptPartition partition,
        int number,
        string name,
        Guid plannedUuid,
        long startSector,
        long sectorCount)
    {
        if (partition.Number != number || partition.Name != name)
        {
            throw new InvalidOperationException(
                $"The parsed GPT partition {number} must be named \"{name}\".");
        }

        if (!GuidMatches(partition.PartUuid, plannedUuid))
        {
            throw new InvalidOperationException(
                $"The parsed partition {number} GUID does not match the planned GUID.");
        }

        if (partition.StartSector != startSector || partition.SectorCount != sectorCount)
        {
            throw new InvalidOperationException(
                $"The parsed partition {number} extent does not match the planned extent.");
        }
    }

    private static bool GuidMatches(string? parsed, Guid planned)
        => Guid.TryParse(parsed, out var value) && value == planned;

    /// <summary>Reads back the complete written image from the card in bounded aligned chunks and
    /// compares the incremental SHA-256 against the declared expanded hash. No header-only sampling.</summary>
    private static async Task VerifyWrittenImageAsync(
        ITfCardWriteTarget target,
        long offset,
        long expectedBytes,
        string expectedSha256,
        string imageName,
        TfCardWriteStage stage,
        IProgress<TfCardWriteProgress>? progress,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long read = 0;
        while (read < expectedBytes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var chunk = (int)Math.Min(buffer.Length, expectedBytes - read);
            await target.ReadExactlyAsync(offset + read, buffer.AsMemory(0, chunk), cancellationToken).ConfigureAwait(false);
            hash.AppendData(buffer, 0, chunk);
            read += chunk;
            progress?.Report(new TfCardWriteProgress(stage, read, expectedBytes, null));
        }

        var actualHex = Convert.ToHexString(hash.GetHashAndReset());
        if (!string.Equals(actualHex, expectedSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"The read-back {imageName} image SHA-256 does not match the declared expanded hash.");
        }
    }
}
