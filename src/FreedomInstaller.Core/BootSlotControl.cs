using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// Read-only observations parsed from one verified misc capture's boot-control block (AOSP
/// boot_control v1, the exact 32 bytes at offset 2048). Facts never constitute device-write
/// authority, proof of Android identity, or permission to touch any partition: consumers must
/// independently bind the same machine to a fresh capture they verified themselves.
/// <see cref="MergeStatus"/> is reported factually only; virtual A/B source-slot policy belongs
/// to a separate outer guard and is never inferred from slot fields here.
/// </summary>
public sealed record BootSlotControlFacts
{
    internal BootSlotControlFacts(
        string currentSlot,
        string controlSha256,
        uint crc32,
        byte mergeStatus,
        VerifiedEdlFile misc,
        bool needsBootloaderAttention = false)
    {
        CurrentSlot = currentSlot;
        ControlSha256 = controlSha256;
        Crc32 = crc32;
        MergeStatus = mergeStatus;
        Misc = misc;
        NeedsBootloaderAttention = needsBootloaderAttention;
    }

    /// <summary>Observed active slot letter, normalized to exactly <c>a</c> or <c>b</c> (parsed from the raw <c>_a</c>/<c>_b</c> suffix).</summary>
    public string CurrentSlot { get; }

    /// <summary>SHA-256 (lowercase hex) of the exact 32 control bytes at offset 2048.</summary>
    public string ControlSha256 { get; }

    /// <summary>CRC-32 (IEEE, reflected) stored over the first 28 control bytes; re-checked, never trusted.</summary>
    public uint Crc32 { get; }

    /// <summary>Raw low-3-bit merge_status field. Factual only — no OTA-completion inference is made.</summary>
    public byte MergeStatus { get; }

    /// <summary>Normalized path plus the whole-file length and SHA-256 actually observed on read (never the supplied claim values).</summary>
    public VerifiedEdlFile Misc { get; }

    /// <summary>
    /// True only when the recovery reader accepted the selected slot solely because it is an
    /// exhausted current-boot slot (priority above zero, verity clean, unsuccessful, zero tries
    /// remaining). Always false for the strict public read path.
    /// </summary>
    public bool NeedsBootloaderAttention { get; }
}

/// <summary>
/// Read-only parser for the AOSP boot_control v1 block inside one verified misc capture
/// (header definition: android.googlesource.com platform/hardware/interfaces boot/1.1
/// boot_control_definition.h). Strictly observational: opens the capture read-only with
/// FileShare.Read, verifies the whole-file length and SHA-256 against the caller's claim
/// before and after parsing, and never mutates the file, issues device commands, or writes
/// any output. The virtual A/B source_slot field is deliberately not parsed as the active slot.
/// </summary>
public static class BootSlotControl
{
    private const int ControlOffset = 2048;
    private const int ControlSize = 32;
    private const int MinimumMiscLength = ControlOffset + ControlSize;
    private const uint BootCtrlMagic = 0x42414342u;
    private const byte SupportedBootCtrlVersion = 1;
    private const int RequiredSlotCount = 2;
    private const string InvalidPrefix = "boot-slot-control-invalid:";

    /// <summary>
    /// Parses the boot-control block of one claimed misc capture. Rejects with
    /// <see cref="InvalidDataException"/> carrying the stable prefix
    /// <c>boot-slot-control-invalid:</c> when the file does not match the capture claim or the
    /// control metadata is contradictory. A pre-canceled token fails before any file access.
    /// </summary>
    public static Task<BootSlotControlFacts> ReadAsync(VerifiedEdlFile misc, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(misc);
        if (cancellationToken.IsCancellationRequested)
        {
            return Task.FromCanceled<BootSlotControlFacts>(cancellationToken);
        }

        return Task.Run(() => ReadCore(misc, cancellationToken, allowExhaustedSelected: false), cancellationToken);
    }

    /// <summary>
    /// Internal recovery-only read for a future CLOSED TF "RestorePrevious" flow: identical strict
    /// verification to <see cref="ReadAsync"/>, but additionally accepts a selected slot that is
    /// exactly an exhausted current-boot slot (priority above zero, verity clean, unsuccessful,
    /// zero tries remaining). Such facts carry <see cref="BootSlotControlFacts.NeedsBootloaderAttention"/>
    /// set to true; no other relaxation is made and nothing is ever written back.
    /// </summary>
    internal static Task<BootSlotControlFacts> ReadForRecoveryAsync(VerifiedEdlFile misc, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(misc);
        if (cancellationToken.IsCancellationRequested)
        {
            return Task.FromCanceled<BootSlotControlFacts>(cancellationToken);
        }

        return Task.Run(() => ReadCore(misc, cancellationToken, allowExhaustedSelected: true), cancellationToken);
    }

    private static BootSlotControlFacts ReadCore(VerifiedEdlFile claim, CancellationToken cancellationToken, bool allowExhaustedSelected)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string normalizedPath = Path.GetFullPath(claim.Path);
        using (var stream = new FileStream(
                   normalizedPath,
                   FileMode.Open,
                   FileAccess.Read,
                   FileShare.Read,
                   bufferSize: 4096,
                   FileOptions.SequentialScan))
        {
            byte[] complete = BufferWhole(stream, claim, cancellationToken);
            string firstSha = AssertMatchesClaim(complete, claim);
            BootSlotControlFacts facts = ParseCore(complete, claim, allowExhaustedSelected);

            // Reverify the capture against the claim before closing: the bytes parsed above must
            // still be the bytes the claim describes (guards against concurrent mutation).
            stream.Seek(0, SeekOrigin.Begin);
            byte[] reread = BufferWhole(stream, claim, cancellationToken);
            string secondSha = AssertMatchesClaim(reread, claim);
            if (!string.Equals(firstSha, secondSha, StringComparison.Ordinal))
            {
                throw Invalid("misc content changed between verification passes");
            }

            return facts;
        }
    }

    /// <summary>
    /// Pure verification and parse of one complete misc image against its capture claim. Also the
    /// strongly-typed entry point tests drive directly with synthetic bytes: it performs no IO.
    /// </summary>
    internal static BootSlotControlFacts Parse(byte[] completeMisc, VerifiedEdlFile claim)
    {
        return ParseCore(completeMisc, claim, allowExhaustedSelected: false);
    }

    /// <summary>Single shared parse pipeline; <paramref name="allowExhaustedSelected"/> is the only behavioral difference between paths.</summary>
    private static BootSlotControlFacts ParseCore(byte[] completeMisc, VerifiedEdlFile claim, bool allowExhaustedSelected)
    {
        ArgumentNullException.ThrowIfNull(completeMisc);
        ArgumentNullException.ThrowIfNull(claim);
        if (completeMisc.Length < MinimumMiscLength)
        {
            throw Invalid($"misc is {completeMisc.Length} bytes, too short for the control block at offset {ControlOffset}");
        }

        if (completeMisc.Length != claim.Length)
        {
            throw Invalid($"misc length {completeMisc.Length} does not match claimed capture length {claim.Length}");
        }

        string observedSha = AssertMatchesClaim(completeMisc, claim);
        string normalizedPath = Path.GetFullPath(claim.Path);

        var block = new byte[ControlSize];
        Array.Copy(completeMisc, ControlOffset, block, 0, ControlSize);
        string controlSha256 = Sha256Hex(block);

        // slot_suffix[0..3]: require the literal NUL-terminated _a/_b; byte 3 is reserved and may
        // hold garbage. No substring search and no fallback to a uniquely bootable slot.
        bool isA = block[0] == (byte)'_' && block[1] == (byte)'a' && block[2] == 0x00;
        bool isB = block[0] == (byte)'_' && block[1] == (byte)'b' && block[2] == 0x00;
        if (!isA && !isB)
        {
            throw Invalid("slot suffix missing or malformed (need literal _a\\0 or _b\\0 at control offset 0)");
        }

        // Facts expose the normalized slot letter; the raw suffix is kept only for diagnostics.
        string currentSlot = isA ? "a" : "b";
        string rawSuffix = isA ? "_a" : "_b";
        int selected = isA ? 0 : 1;
        int other = 1 - selected;

        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(block.AsSpan(4));
        if (magic != BootCtrlMagic)
        {
            throw Invalid($"unknown boot control magic 0x{magic:X8}, expected 0x{BootCtrlMagic:X8}");
        }

        byte version = block[8];
        if (version != SupportedBootCtrlVersion)
        {
            throw Invalid($"unsupported boot control version {version}, expected {SupportedBootCtrlVersion}");
        }

        int slotCount = block[9] & 0b111;
        if (slotCount != RequiredSlotCount)
        {
            throw Invalid($"unsupported slot count {slotCount}, expected exactly {RequiredSlotCount}");
        }

        byte mergeStatus = (byte)(block[10] & 0b111);

        uint storedCrc = BinaryPrimitives.ReadUInt32LittleEndian(block.AsSpan(28));
        uint computedCrc = Crc32Ieee(block.AsSpan(0, 28));
        if (storedCrc != computedCrc)
        {
            throw Invalid($"control block CRC-32 mismatch: stored 0x{storedCrc:X8}, computed 0x{computedCrc:X8}");
        }

        (int Priority, int Tries, bool Successful, bool VerityCorrupted) DecodeSlot(int index)
        {
            int packed = block[12 + (index * 2)];
            int verity = block[13 + (index * 2)];
            return (packed & 0x0F, (packed >> 4) & 0x07, (packed & 0x80) != 0, (verity & 0x01) != 0);
        }

        static bool IsBootable(int priority, int tries, bool successful, bool verityCorrupted)
        {
            return priority > 0 && !verityCorrupted && (successful || tries > 0);
        }

        var selectedSlot = DecodeSlot(selected);
        bool selectedBootable = IsBootable(selectedSlot.Priority, selectedSlot.Tries, selectedSlot.Successful, selectedSlot.VerityCorrupted);
        bool needsBootloaderAttention = false;
        if (!selectedBootable)
        {
            // Sole recovery relaxation: the selected slot is an exhausted current-boot slot —
            // real priority above zero, verity clean, unsuccessful boot, zero tries remaining.
            // Everything else (priority 0, verity corruption, other shapes) still rejects.
            bool isExhaustedCurrentBoot =
                selectedSlot.Priority > 0
                && !selectedSlot.VerityCorrupted
                && !selectedSlot.Successful
                && selectedSlot.Tries == 0;
            if (!(allowExhaustedSelected && isExhaustedCurrentBoot))
            {
                throw Invalid(
                    $"selected slot {rawSuffix} is unbootable (priority {selectedSlot.Priority}, " +
                    $"tries {selectedSlot.Tries}, successful {selectedSlot.Successful}, " +
                    $"verityCorrupted {selectedSlot.VerityCorrupted})");
            }

            needsBootloaderAttention = true;
        }

        var otherSlot = DecodeSlot(other);
        if (IsBootable(otherSlot.Priority, otherSlot.Tries, otherSlot.Successful, otherSlot.VerityCorrupted)
            && otherSlot.Priority > selectedSlot.Priority)
        {
            throw Invalid(
                $"contradictory metadata: unsuffixed slot is bootable with strictly higher priority " +
                $"{otherSlot.Priority} than suffix-selected {rawSuffix} priority {selectedSlot.Priority}");
        }

        return new BootSlotControlFacts(
            currentSlot,
            controlSha256,
            storedCrc,
            mergeStatus,
            new VerifiedEdlFile(normalizedPath, completeMisc.Length, observedSha),
            needsBootloaderAttention);
    }

    /// <summary>Reads the whole capture into one buffer, refusing claims that do not match the stream.</summary>
    private static byte[] BufferWhole(Stream stream, VerifiedEdlFile claim, CancellationToken cancellationToken)
    {
        long length = stream.Length;
        if (length < MinimumMiscLength)
        {
            throw Invalid($"misc stream is {length} bytes, shorter than the {MinimumMiscLength}-byte minimum");
        }

        if (length != claim.Length)
        {
            throw Invalid($"misc stream length {length} does not match claimed capture length {claim.Length}");
        }

        if (length > int.MaxValue)
        {
            throw Invalid("misc stream is too large to verify as a single buffer");
        }

        var buffer = new byte[(int)length];
        int total = 0;
        while (total < buffer.Length)
        {
            int read = stream.Read(buffer, total, buffer.Length - total);
            if (read == 0)
            {
                throw Invalid($"misc stream ended after {total} bytes while {claim.Length} were claimed");
            }

            total += read;
            cancellationToken.ThrowIfCancellationRequested();
        }

        return buffer;
    }

    /// <summary>Checks the actually observed SHA-256 against the claim; the claim alone is never evidence.</summary>
    private static string AssertMatchesClaim(byte[] completeMisc, VerifiedEdlFile claim)
    {
        string observed = Sha256Hex(completeMisc);
        if (!string.Equals(observed, NormalizeSha(claim.Sha256), StringComparison.Ordinal))
        {
            throw Invalid("observed misc SHA-256 does not match the capture claim (stale or tampered capture)");
        }

        return observed;
    }

    /// <summary>CRC-32/ISO-HDLC: reflected 0xEDB88320, init 0xFFFFFFFF, final XOR 0xFFFFFFFF.</summary>
    private static uint Crc32Ieee(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFFu;
        foreach (byte value in data)
        {
            crc ^= value;
            for (int bit = 0; bit < 8; bit++)
            {
                uint mask = (crc & 1) != 0 ? 0xEDB88320u : 0u;
                crc = (crc >> 1) ^ mask;
            }
        }

        return crc ^ 0xFFFFFFFFu;
    }

    private static string Sha256Hex(ReadOnlySpan<byte> data)
    {
        return Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
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
