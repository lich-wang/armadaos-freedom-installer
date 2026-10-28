using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>Modern AOSP virtual A/B merge state carried in the virtual_ab_message.</summary>
public enum BootVirtualAbState
{
    Completed = 0,
    Unknown = 1,
    Snapshotted = 2,
    Merging = 3,
    Cancelled = 4,
}

/// <summary>
/// Read-only observations parsed from one verified misc capture's modern AOSP
/// virtual_ab_message (the exact 64 bytes at offset 32768; header per
/// android.googlesource.com platform/bootable/recovery boot_control_message, version 2).
/// Facts never constitute device-write authority or permission to touch any partition:
/// consumers must independently bind the same machine to a fresh capture they verified
/// themselves.
/// <para>
/// <see cref="SourceSlot"/> is provenance only — it is never the active slot, and no
/// CurrentSlot value is derived here. The legacy A/B boot_control merge bits at offset 2048
/// are a different structure and are deliberately irrelevant to this parse.
/// </para>
/// </summary>
public sealed record BootVirtualAbControlFacts
{
    internal BootVirtualAbControlFacts(
        BootVirtualAbState state,
        bool isFormatValid,
        int? sourceSlot,
        string? messageSha256,
        VerifiedEdlFile misc)
    {
        State = state;
        IsFormatValid = isFormatValid;
        SourceSlot = sourceSlot;
        MessageSha256 = messageSha256;
        Misc = misc;
    }

    /// <summary>Merge state mapped from the raw status byte; <see cref="BootVirtualAbState.Unknown"/> also covers invalid format.</summary>
    public BootVirtualAbState State { get; }

    /// <summary>True when the 64-byte message parsed cleanly; distinguishes status=Unknown from a malformed message.</summary>
    public bool IsFormatValid { get; }

    /// <summary>Raw source_slot (0 or 1) when the format is valid, even for status=Unknown; null otherwise. Provenance only.</summary>
    public int? SourceSlot { get; }

    /// <summary>SHA-256 (lowercase hex) of the exact 64 message bytes when available, even if the format is invalid; null for short files. Evidence only.</summary>
    public string? MessageSha256 { get; }

    /// <summary>Normalized path plus the whole-file length and SHA-256 actually observed on read (never the supplied claim values).</summary>
    public VerifiedEdlFile Misc { get; }
}

/// <summary>
/// Read-only parser for the modern AOSP virtual_ab_message inside one verified misc capture.
/// Strictly observational: opens the capture read-only with FileShare.Read, streams the whole
/// file to verify the caller's length and SHA-256 claim before and after parsing (without
/// buffering the whole capture), and never mutates the file, opens a device, or writes output.
/// The legacy AB32 boot_control block at offset 2048 is never parsed or interpreted (its bytes
/// do still contribute to the whole-file hash): its low merge bits are not proof of anything
/// here, and the source_slot is never treated as the active slot.
/// </summary>
public static class BootVirtualAbControl
{
    private const int MessageOffset = 32768;
    private const int MessageSize = 64;
    private const long MinimumMiscLength = MessageOffset + MessageSize;
    private const uint VirtualAbMagic = 0x56740AB0u;
    private const byte SupportedMessageVersion = 2;
    private const byte MaxMergeStatus = (byte)BootVirtualAbState.Cancelled;
    private const byte MaxSourceSlot = 1;
    private const int StreamBufferSize = 64 * 1024;
    private const string InvalidPrefix = "boot-virtual-ab-control-invalid:";

    /// <summary>
    /// Parses the virtual_ab_message of one claimed misc capture. Rejects with
    /// <see cref="InvalidDataException"/> carrying the stable prefix
    /// <c>boot-virtual-ab-control-invalid:</c> when the file does not match the capture claim.
    /// A pre-canceled token fails before any path resolution or file access.
    /// </summary>
    public static Task<BootVirtualAbControlFacts> ReadAsync(VerifiedEdlFile misc, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(misc);
        if (cancellationToken.IsCancellationRequested)
        {
            return Task.FromCanceled<BootVirtualAbControlFacts>(cancellationToken);
        }

        return Task.Run(() => ReadCore(misc, cancellationToken), cancellationToken);
    }

    private static BootVirtualAbControlFacts ReadCore(VerifiedEdlFile claim, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (claim.Length < 0)
        {
            throw Invalid($"claimed misc length {claim.Length} is negative");
        }

        string normalizedPath = Path.GetFullPath(claim.Path);
        using (var stream = new FileStream(
                   normalizedPath,
                   FileMode.Open,
                   FileAccess.Read,
                   FileShare.Read,
                   bufferSize: StreamBufferSize,
                   FileOptions.SequentialScan))
        {
            // First pass: stream and hash the entire file without buffering it whole.
            (long firstLength, string firstSha) = VerifyWholeStream(stream, claim, cancellationToken);

            // Message read: exactly 64 bytes at offset 32768, only when the file is long enough.
            byte[]? message = null;
            if (firstLength >= MinimumMiscLength)
            {
                stream.Seek(MessageOffset, SeekOrigin.Begin);
                message = ReadExact(stream, MessageSize, cancellationToken);
            }

            BootVirtualAbControlFacts facts = Parse(message, normalizedPath, firstLength, firstSha);

            // Second pass while the same read-only handle is still held: the bytes parsed above
            // must still be the bytes the claim describes (guards against concurrent mutation).
            cancellationToken.ThrowIfCancellationRequested();
            stream.Seek(0, SeekOrigin.Begin);
            (long secondLength, string secondSha) = VerifyWholeStream(stream, claim, cancellationToken);
            if (secondLength != firstLength || !string.Equals(secondSha, firstSha, StringComparison.Ordinal))
            {
                throw Invalid("misc content changed between verification passes");
            }

            return facts;
        }
    }

    /// <summary>
    /// Streams the capture from the current position to actual EOF through one fixed buffer,
    /// refusing claims whose length or SHA-256 do not match what is actually observed. Returns
    /// the observed length and lowercase SHA-256. Reads until real EOF (not the initial
    /// stream.Length) so a stream that shrinks or grows mid-read is detected by the length
    /// checks before the SHA is ever accepted.
    /// </summary>
    private static (long Length, string Sha256) VerifyWholeStream(
        FileStream stream, VerifiedEdlFile claim, CancellationToken cancellationToken)
    {
        if (stream.Length != claim.Length)
        {
            throw Invalid($"misc stream length {stream.Length} does not match claimed capture length {claim.Length}");
        }

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[StreamBufferSize];
        long total = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                break; // actual EOF
            }

            hash.AppendData(buffer, 0, read);
            total += read;
        }

        if (total != claim.Length)
        {
            throw Invalid($"misc stream yielded {total} bytes at EOF while {claim.Length} were claimed");
        }

        if (stream.Length != total)
        {
            throw Invalid($"misc stream length changed during verification: ends at {stream.Length}, {total} bytes were read");
        }

        cancellationToken.ThrowIfCancellationRequested();
        string observed = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
        if (!string.Equals(observed, NormalizeSha(claim.Sha256), StringComparison.Ordinal))
        {
            throw Invalid("observed misc SHA-256 does not match the capture claim (stale or tampered capture)");
        }

        return (total, observed);
    }

    /// <summary>Reads exactly <paramref name="count"/> bytes from the current position.</summary>
    private static byte[] ReadExact(FileStream stream, int count, CancellationToken cancellationToken)
    {
        var message = new byte[count];
        int total = 0;
        while (total < count)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int read = stream.Read(message, total, count - total);
            if (read == 0)
            {
                throw Invalid($"misc stream ended after {total} bytes inside the {count}-byte virtual_ab message");
            }

            total += read;
        }

        return message;
    }

    /// <summary>
    /// Maps one verified capture to facts. A short file (no complete 64-byte message) is invalid
    /// format: Unknown with no source slot and no message SHA. Field checks are exact: version 2,
    /// magic 0x56740AB0, status 0..4, source slot 0 or 1; the remaining 57 bytes are reserved and
    /// may be arbitrary. The legacy AB32 merge bits at offset 2048 play no part in this mapping.
    /// </summary>
    private static BootVirtualAbControlFacts Parse(byte[]? message, string normalizedPath, long observedLength, string observedSha)
    {
        var misc = new VerifiedEdlFile(normalizedPath, observedLength, observedSha);
        if (message is null)
        {
            return new BootVirtualAbControlFacts(
                BootVirtualAbState.Unknown,
                isFormatValid: false,
                sourceSlot: null,
                messageSha256: null,
                misc);
        }

        // Evidence even when the format turns out invalid.
        string messageSha256 = Convert.ToHexString(SHA256.HashData(message)).ToLowerInvariant();

        (BootVirtualAbState state, bool formatValid, int? sourceSlot) = ParseMessageBytes(message);

        return new BootVirtualAbControlFacts(
            state,
            formatValid,
            sourceSlot,
            messageSha256,
            misc);
    }

    /// <summary>
    /// Pure parse of one candidate 64-byte virtual_ab_message. The span must be exactly 64 bytes;
    /// any other length (including a short file's empties) is an invalid format, never Completed.
    /// Field checks are exact: version 2, magic 0x56740AB0, status 0..4, source slot 0 or 1.
    /// <see cref="BootVirtualAbState.Completed"/> is only ever returned together with a valid format.
    /// </summary>
    internal static (BootVirtualAbState State, bool IsFormatValid, int? SourceSlot) ParseMessageBytes(
        ReadOnlySpan<byte> message)
    {
        if (message.Length != MessageSize)
        {
            return (BootVirtualAbState.Unknown, false, null);
        }

        byte version = message[0];
        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(1));
        byte mergeStatus = message[5];
        byte sourceSlot = message[6];

        bool formatValid = version == SupportedMessageVersion
            && magic == VirtualAbMagic
            && mergeStatus <= MaxMergeStatus
            && sourceSlot <= MaxSourceSlot;
        if (!formatValid)
        {
            return (BootVirtualAbState.Unknown, false, null);
        }

        return ((BootVirtualAbState)mergeStatus, true, sourceSlot);
    }

    private static string NormalizeSha(string? claimed)
    {
        return (claimed ?? string.Empty).Trim().ToLowerInvariant();
    }

    private static InvalidDataException Invalid(string detail)
    {
        return new InvalidDataException($"{InvalidPrefix} {detail}");
    }
}
