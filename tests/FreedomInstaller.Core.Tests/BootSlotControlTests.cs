using System;
using System.Buffers.Binary;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Behavioural tests for the read-only misc boot-control parser. All fixtures are synthetic
/// files written under <see cref="TestArtifactRoot"/>; no device, backup or shared file is read.
/// The CRC oracle comes from the BCL ZipArchive implementation, never from a copy of production
/// code, and every assertion drives the real ReadAsync/Parse path — no reflection assertions on
/// method existence.
/// </summary>
public sealed class BootSlotControlTests
{
    private const int ControlOffset = 2048;
    private const int ControlSize = 32;
    private const long MiscLength = 4096;

    // ---------------------------------------------------------------- fixtures

    /// <summary>Builds a valid 32-byte boot_control v1 block selecting <paramref name="suffix"/>.</summary>
    private static byte[] ControlBlock(string suffix, byte mergeStatus = 0, int? aPriority = null, int? bPriority = null)
    {
        // Defaults mirror real boot_control usage: the suffix-selected slot has high priority,
        // the other slot low — any strictly-higher-other default would fail production rules.
        bool selectsA = suffix == "_a";
        int defaultSelected = 15;
        int defaultOther = 1;
        int resolvedAPriority = aPriority ?? (selectsA ? defaultSelected : defaultOther);
        int resolvedBPriority = bPriority ?? (selectsA ? defaultOther : defaultSelected);

        var block = new byte[ControlSize];
        byte[] suffixBytes = Encoding.ASCII.GetBytes(suffix);
        block[0] = suffixBytes[0];
        block[1] = suffixBytes[1];
        block[2] = 0x00; // NUL terminator; byte 3 stays reserved/garbage-tolerant.
        block[3] = 0x7F; // reserved byte: arbitrary value tolerated by the parser
        BinaryPrimitives.WriteUInt32LittleEndian(block.AsSpan(4), 0x42414342u);
        block[8] = 1;   // version
        block[9] = 2;   // nb_slot (low 3 bits)
        block[10] = (byte)(mergeStatus & 0b111);
        block[11] = 0;  // reserved

        WriteSlot(block, 0, resolvedAPriority, triesRemaining: 0, successful: true, verityCorrupted: false);
        WriteSlot(block, 1, resolvedBPriority, triesRemaining: 0, successful: true, verityCorrupted: false);

        BinaryPrimitives.WriteUInt32LittleEndian(block.AsSpan(28), Crc32Oracle(block.AsSpan(0, 28)));
        return block;
    }

    private static void WriteSlot(byte[] block, int index, int priority, int triesRemaining, bool successful, bool verityCorrupted)
    {
        int packed = (priority & 0x0F) | ((triesRemaining & 0x07) << 4);
        if (successful)
        {
            packed |= 0x80;
        }

        block[12 + (index * 2)] = (byte)packed;
        block[13 + (index * 2)] = verityCorrupted ? (byte)0x01 : (byte)0x00;
    }

    private static byte[] MiscImage(byte[] control) => BuildMisc(control);

    private static byte[] BuildMisc(byte[] control)
    {
        var misc = new byte[MiscLength];
        Array.Copy(control, 0, misc, ControlOffset, ControlSize);
        return misc;
    }

    private static async Task<(string Path, VerifiedEdlFile Claim)> WriteFixtureAsync(byte[] misc)
    {
        string path = Path.Combine(TestArtifactRoot.Resolve(), "bootslot-" + Guid.NewGuid().ToString("N") + ".img");
        await File.WriteAllBytesAsync(path, misc);
        string sha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(misc)).ToLowerInvariant();
        return (path, new VerifiedEdlFile(path, misc.Length, sha));
    }

    /// <summary>Independent CRC-32 (IEEE) oracle: the value the BCL ZIP writer computes for 28 bytes.</summary>
    private static uint Crc32Oracle(ReadOnlySpan<byte> data)
    {
        var zipBuffer = new MemoryStream();
        using (var archive = new ZipArchive(zipBuffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            ZipArchiveEntry entry = archive.CreateEntry("crc-oracle");
            using (var entryStream = entry.Open())
            {
                entryStream.Write(data.ToArray(), 0, data.Length);
            }
        }

        // ZIP local file header: signature at 0, CRC-32 at offset 14, little-endian.
        return BinaryPrimitives.ReadUInt32LittleEndian(zipBuffer.ToArray().AsSpan(14));
    }

    private static byte[] TamperControlByte(byte[] misc, int offsetInControl, byte value)
    {
        var copy = (byte[])misc.Clone();
        copy[ControlOffset + offsetInControl] = value;
        return copy;
    }

    private static async Task<InvalidDataException> AssertInvalidAsync(VerifiedEdlFile claim)
    {
        InvalidDataException failure = await Assert.ThrowsAsync<InvalidDataException>(
            () => BootSlotControl.ReadAsync(claim, CancellationToken.None));
        Assert.StartsWith("boot-slot-control-invalid:", failure.Message, StringComparison.Ordinal);
        return failure;
    }

    // ---------------------------------------------------------------- happy path

    [Fact]
    public async Task ReadAsync_ValidSlotA_ReturnsFactsAndObservedFileEvidence()
    {
        byte[] misc = MiscImage(ControlBlock("_a"));
        (string path, VerifiedEdlFile claim) = await WriteFixtureAsync(misc);
        try
        {
            BootSlotControlFacts facts = await BootSlotControl.ReadAsync(claim, CancellationToken.None);

            Assert.Equal("a", facts.CurrentSlot);
            Assert.Equal(MiscLength, facts.Misc.Length);
            Assert.Equal(Path.GetFullPath(path), facts.Misc.Path);

            // Observed evidence, not the claim values: whole-file SHA-256 recomputed here.
            string observedFileSha = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(misc)).ToLowerInvariant();
            Assert.Equal(observedFileSha, facts.Misc.Sha256);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadAsync_ValidSlotB_ReturnsSlotB()
    {
        byte[] misc = MiscImage(ControlBlock("_b"));
        (string path, VerifiedEdlFile claim) = await WriteFixtureAsync(misc);
        try
        {
            BootSlotControlFacts facts = await BootSlotControl.ReadAsync(claim, CancellationToken.None);
            Assert.Equal("b", facts.CurrentSlot);
            Assert.Equal((byte)0, facts.MergeStatus);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadAsync_MergeStatusRoundTrips_FactualOnly()
    {
        byte[] misc = MiscImage(ControlBlock("_a", mergeStatus: 2));
        (string path, VerifiedEdlFile claim) = await WriteFixtureAsync(misc);
        try
        {
            BootSlotControlFacts facts = await BootSlotControl.ReadAsync(claim, CancellationToken.None);
            Assert.Equal((byte)2, facts.MergeStatus);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadAsync_ControlSha256_DescribesExactControlBytes()
    {
        byte[] control = ControlBlock("_a");
        byte[] misc = MiscImage(control);
        (string path, VerifiedEdlFile claim) = await WriteFixtureAsync(misc);
        try
        {
            BootSlotControlFacts facts = await BootSlotControl.ReadAsync(claim, CancellationToken.None);
            string expectedControlSha = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(control)).ToLowerInvariant();
            Assert.Equal(expectedControlSha, facts.ControlSha256);
        }
        finally
        {
            File.Delete(path);
        }
    }

    // ---------------------------------------------------------------- corruption and contradiction

    [Fact]
    public async Task ReadAsync_CrcCorruption_RejectsWithStablePrefix()
    {
        // Corrupt only the stored CRC (control byte 28) of an otherwise valid block, so the
        // rejection genuinely exercises the CRC check instead of an earlier field.
        byte[] misc = TamperControlByte(MiscImage(ControlBlock("_a")), 28, 0xFF);
        (string path, VerifiedEdlFile claim) = await WriteFixtureAsync(misc);
        try
        {
            InvalidDataException failure = await AssertInvalidAsync(claim);
            Assert.Contains("CRC-32", failure.Message, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadAsync_MissingSuffix_UniquePriorityCannotSubstitute()
    {
        byte[] control = ControlBlock("_a");
        control[1] = (byte)'x'; // breaks the literal suffix; slot _a stays uniquely bootable (priority 15 vs 1)
        var misc = BuildMisc(control);
        (string path, VerifiedEdlFile claim) = await WriteFixtureAsync(misc);
        try
        {
            InvalidDataException failure = await AssertInvalidAsync(claim);
            Assert.Contains("suffix", failure.Message, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadAsync_SuffixContradictedByStrictlyHigherOtherPriority_Rejects()
    {
        // Suffix says _a but the _b entry is bootable with strictly higher priority.
        byte[] misc = MiscImage(ControlBlock("_a", aPriority: 3, bPriority: 9));
        (string path, VerifiedEdlFile claim) = await WriteFixtureAsync(misc);
        try
        {
            InvalidDataException failure = await AssertInvalidAsync(claim);
            Assert.Contains("contradictory", failure.Message, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadAsync_EqualPrioritiesWithValidSuffix_Accepted()
    {
        byte[] misc = MiscImage(ControlBlock("_a", aPriority: 7, bPriority: 7));
        (string path, VerifiedEdlFile claim) = await WriteFixtureAsync(misc);
        try
        {
            BootSlotControlFacts facts = await BootSlotControl.ReadAsync(claim, CancellationToken.None);
            Assert.Equal("a", facts.CurrentSlot);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadAsync_UnbootableSelectedSlot_Rejects()
    {
        // Selected _a has priority 0 (unbootable) while _b is bootable — suffix still wins the check, and must reject.
        byte[] misc = MiscImage(ControlBlock("_a", aPriority: 0, bPriority: 15));
        (string path, VerifiedEdlFile claim) = await WriteFixtureAsync(misc);
        try
        {
            await AssertInvalidAsync(claim);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadAsync_VerityCorruptedSelectedSlot_Rejects()
    {
        byte[] control = ControlBlock("_a");
        WriteSlot(control, 0, 15, triesRemaining: 7, successful: false, verityCorrupted: true);
        BinaryPrimitives.WriteUInt32LittleEndian(control.AsSpan(28), Crc32Oracle(control.AsSpan(0, 28)));
        var misc = BuildMisc(control);
        (string path, VerifiedEdlFile claim) = await WriteFixtureAsync(misc);
        try
        {
            InvalidDataException failure = await AssertInvalidAsync(claim);
            Assert.Contains("selected slot", failure.Message, StringComparison.Ordinal);
            Assert.Contains("_a", failure.Message, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    // ---------------------------------------------------------------- structural rejects

    [Fact]
    public async Task ReadAsync_UnknownMagic_Rejects()
    {
        byte[] control = ControlBlock("_a");
        BinaryPrimitives.WriteUInt32LittleEndian(control.AsSpan(4), 0xDEADBEEFu);
        BinaryPrimitives.WriteUInt32LittleEndian(control.AsSpan(28), Crc32Oracle(control.AsSpan(0, 28)));
        (string path, VerifiedEdlFile claim) = await WriteFixtureAsync(BuildMisc(control));
        try
        {
            await AssertInvalidAsync(claim);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadAsync_UnsupportedVersion_Rejects()
    {
        byte[] control = ControlBlock("_a");
        control[8] = 2;
        BinaryPrimitives.WriteUInt32LittleEndian(control.AsSpan(28), Crc32Oracle(control.AsSpan(0, 28)));
        (string path, VerifiedEdlFile claim) = await WriteFixtureAsync(BuildMisc(control));
        try
        {
            InvalidDataException failure = await AssertInvalidAsync(claim);
            Assert.Contains("version", failure.Message, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadAsync_UnsupportedSlotCount_Rejects()
    {
        byte[] control = ControlBlock("_a");
        control[9] = 3;
        BinaryPrimitives.WriteUInt32LittleEndian(control.AsSpan(28), Crc32Oracle(control.AsSpan(0, 28)));
        (string path, VerifiedEdlFile claim) = await WriteFixtureAsync(BuildMisc(control));
        try
        {
            InvalidDataException failure = await AssertInvalidAsync(claim);
            Assert.Contains("slot count", failure.Message, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadAsync_TamperedWholeFileClaim_RejectsBeforeParsing()
    {
        byte[] misc = MiscImage(ControlBlock("_a"));
        (string path, VerifiedEdlFile _) = await WriteFixtureAsync(misc);
        try
        {
            var wrongClaim = new VerifiedEdlFile(path, misc.Length, new string('0', 64));
            await AssertInvalidAsync(wrongClaim);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadAsync_WrongClaimLength_Rejects()
    {
        byte[] misc = MiscImage(ControlBlock("_a"));
        (string path, VerifiedEdlFile claim) = await WriteFixtureAsync(misc);
        try
        {
            var wrongLength = new VerifiedEdlFile(claim.Path, claim.Length + 1, claim.Sha256);
            await AssertInvalidAsync(wrongLength);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadAsync_ShortFile_Rejects()
    {
        // Real short file: 2079 bytes (one short of the 2080-byte minimum) with matching
        // claim, so the rejection is the genuine minimum-control-size check.
        byte[] misc = new byte[2079];
        (string path, VerifiedEdlFile claim) = await WriteFixtureAsync(misc);
        try
        {
            InvalidDataException failure = await AssertInvalidAsync(claim);
            Assert.Contains("shorter than", failure.Message, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    // ---------------------------------------------------------------- cancellation

    [Fact]
    public async Task ReadAsync_PreCanceled_NeverReadsFile()
    {
        byte[] misc = MiscImage(ControlBlock("_a"));
        (string path, VerifiedEdlFile _) = await WriteFixtureAsync(misc);

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        // Make any file read impossible before invoking: the pre-cancel guard must win first.
        File.Move(path, path + ".moved");

        Task<BootSlotControlFacts> task = BootSlotControl.ReadAsync(
            new VerifiedEdlFile(path, misc.Length, "placeholder-sha-never-checked"), cts.Token);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
        Assert.True(task.IsCanceled);
        File.Move(path + ".moved", path);
        File.Delete(path);
    }

    // ---------------------------------------------------------------- internal pure parse

    [Fact]
    public void Parse_ValidBytes_ReturnsFactsWithoutIo()
    {
        byte[] misc = MiscImage(ControlBlock("_b", mergeStatus: 1));
        VerifiedEdlFile claim = new("/irrelevant/claim/path", misc.Length, Sha256Of(misc));

        BootSlotControlFacts facts = ParseViaReflection(misc, claim);

        Assert.Equal("b", facts.CurrentSlot);
        Assert.Equal((byte)1, facts.MergeStatus);
        Assert.Equal(Sha256Of(misc), facts.Misc.Sha256);
    }

    [Fact]
    public void Parse_ShortBuffer_Throws()
    {
        byte[] misc = new byte[2079];
        VerifiedEdlFile claim = new("/irrelevant", misc.Length, Sha256Of(misc));
        InvalidDataException failure = Assert.Throws<InvalidDataException>(() => ParseViaReflection(misc, claim));
        Assert.StartsWith("boot-slot-control-invalid:", failure.Message, StringComparison.Ordinal);
        Assert.Contains("too short", failure.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Narrow reflection adapter: the assembly has no InternalsVisibleTo, so tests invoke the
    /// internal pure <c>Parse(byte[], VerifiedEdlFile)</c> through this wrapper only, unwrapping
    /// the TargetInvocationException so real exceptions (including InvalidDataException) surface.
    /// </summary>
    private static BootSlotControlFacts ParseViaReflection(byte[] completeMisc, VerifiedEdlFile claim)
    {
        MethodInfo parse = typeof(BootSlotControl).GetMethod(
            "Parse",
            BindingFlags.Static | BindingFlags.NonPublic,
            binder: null,
            types: new[] { typeof(byte[]), typeof(VerifiedEdlFile) },
            modifiers: null)!;
        try
        {
            return (BootSlotControlFacts)parse.Invoke(null, new object?[] { completeMisc, claim })!;
        }
        catch (TargetInvocationException invocation)
        {
            ExceptionDispatchInfo.Capture(invocation.InnerException!).Throw();
            throw; // unreachable: Capture(...).Throw() always throws
        }
    }

    private static string Sha256Of(byte[] data)
    {
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(data)).ToLowerInvariant();
    }

    // ---------------------------------------------------------------- recovery reader (TF-RECOVERY-SLOT-01)

    /// <summary>Control block whose selected slot is an exhausted current-boot slot (priority above zero, verity clean, unsuccessful, zero tries).</summary>
    private static byte[] ExhaustedSelectedControl(string suffix)
    {
        bool selectsA = suffix == "_a";
        byte[] control = ControlBlock(suffix, aPriority: selectsA ? 15 : 1, bPriority: selectsA ? 1 : 15);
        WriteSlot(control, selectsA ? 0 : 1, priority: 15, triesRemaining: 0, successful: false, verityCorrupted: false);
        WriteSlot(control, selectsA ? 1 : 0, priority: 1, triesRemaining: 0, successful: true, verityCorrupted: false);
        BinaryPrimitives.WriteUInt32LittleEndian(control.AsSpan(28), Crc32Oracle(control.AsSpan(0, 28)));
        return control;
    }

    /// <summary>
    /// Narrow reflection adapter for the internal recovery-only read: invokes the real
    /// <c>ReadForRecoveryAsync(VerifiedEdlFile, CancellationToken)</c>, returns the real task, and
    /// unwraps the <see cref="TargetInvocationException"/> wrapper only. No facts are forged.
    /// </summary>
    private static Task<BootSlotControlFacts> ReadForRecoveryViaReflection(VerifiedEdlFile claim, CancellationToken cancellationToken)
    {
        MethodInfo readForRecovery = typeof(BootSlotControl).GetMethod(
            "ReadForRecoveryAsync",
            BindingFlags.Static | BindingFlags.NonPublic,
            binder: null,
            types: new[] { typeof(VerifiedEdlFile), typeof(CancellationToken) },
            modifiers: null)!;
        try
        {
            return (Task<BootSlotControlFacts>)readForRecovery.Invoke(null, new object?[] { claim, cancellationToken })!;
        }
        catch (TargetInvocationException invocation)
        {
            ExceptionDispatchInfo.Capture(invocation.InnerException!).Throw();
            throw; // unreachable: Capture(...).Throw() always throws
        }
    }

    [Fact]
    public async Task ReadForRecoveryAsync_ExhaustedSelectedSlot_PublicStrictRejects_RecoveryAcceptsWithAttention()
    {
        byte[] misc = MiscImage(ExhaustedSelectedControl("_a"));
        (string path, VerifiedEdlFile claim) = await WriteFixtureAsync(misc);
        try
        {
            // The strict public path rejects the same capture outright.
            InvalidDataException strictFailure = await AssertInvalidAsync(claim);
            Assert.Contains("selected slot", strictFailure.Message, StringComparison.Ordinal);
            Assert.Contains("_a", strictFailure.Message, StringComparison.Ordinal);

            // The recovery path accepts it, flagging bootloader attention with real evidence.
            BootSlotControlFacts facts = await ReadForRecoveryViaReflection(claim, CancellationToken.None);
            Assert.True(facts.NeedsBootloaderAttention);
            Assert.Equal("a", facts.CurrentSlot);
            Assert.Equal(MiscLength, facts.Misc.Length);
            Assert.Equal(Path.GetFullPath(path), facts.Misc.Path);
            Assert.Equal(Sha256Of(misc), facts.Misc.Sha256);

            byte[] control = new byte[ControlSize];
            Array.Copy(misc, ControlOffset, control, 0, ControlSize);
            Assert.Equal(Sha256Of(control), facts.ControlSha256);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadForRecoveryAsync_PriorityZeroSelected_StillRejects()
    {
        // Priority 0 is not "exhausted" — it is not bootable at all; recovery must not accept it.
        byte[] control = ControlBlock("_a", aPriority: 0, bPriority: 15);
        byte[] misc = MiscImage(control);
        (string path, VerifiedEdlFile claim) = await WriteFixtureAsync(misc);
        try
        {
            Task<BootSlotControlFacts> task = ReadForRecoveryViaReflection(claim, CancellationToken.None);
            InvalidDataException failure = await Assert.ThrowsAsync<InvalidDataException>(() => task);
            Assert.StartsWith("boot-slot-control-invalid:", failure.Message, StringComparison.Ordinal);
            Assert.Contains("selected slot", failure.Message, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadForRecoveryAsync_VerityCorruptedSelected_StillRejects()
    {
        // Verity corruption disqualifies even the exhausted shape: recovery keeps the strict reject.
        byte[] control = ExhaustedSelectedControl("_a");
        WriteSlot(control, 0, priority: 15, triesRemaining: 0, successful: false, verityCorrupted: true);
        BinaryPrimitives.WriteUInt32LittleEndian(control.AsSpan(28), Crc32Oracle(control.AsSpan(0, 28)));
        byte[] misc = MiscImage(control);
        (string path, VerifiedEdlFile claim) = await WriteFixtureAsync(misc);
        try
        {
            Task<BootSlotControlFacts> task = ReadForRecoveryViaReflection(claim, CancellationToken.None);
            InvalidDataException failure = await Assert.ThrowsAsync<InvalidDataException>(() => task);
            Assert.StartsWith("boot-slot-control-invalid:", failure.Message, StringComparison.Ordinal);
            Assert.Contains("selected slot", failure.Message, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadForRecoveryAsync_OtherBootableStrictlyHigherPriority_StillRejects()
    {
        // Exhausted selected _a (priority 5), but the other slot is bootable with strictly higher
        // priority 15 — the contradictory-metadata guard must stay in force on the recovery path.
        byte[] control = ExhaustedSelectedControl("_a");
        WriteSlot(control, 0, priority: 5, triesRemaining: 0, successful: false, verityCorrupted: false);
        WriteSlot(control, 1, priority: 15, triesRemaining: 0, successful: true, verityCorrupted: false);
        BinaryPrimitives.WriteUInt32LittleEndian(control.AsSpan(28), Crc32Oracle(control.AsSpan(0, 28)));
        byte[] misc = MiscImage(control);
        (string path, VerifiedEdlFile claim) = await WriteFixtureAsync(misc);
        try
        {
            Task<BootSlotControlFacts> task = ReadForRecoveryViaReflection(claim, CancellationToken.None);
            InvalidDataException failure = await Assert.ThrowsAsync<InvalidDataException>(() => task);
            Assert.StartsWith("boot-slot-control-invalid:", failure.Message, StringComparison.Ordinal);
            Assert.Contains("contradictory", failure.Message, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadForRecoveryAsync_CrcCorruption_StillRejects()
    {
        // Recovery never bypasses the CRC check: stored CRC tampered, both bytes 28 of the block.
        byte[] misc = TamperControlByte(MiscImage(ExhaustedSelectedControl("_a")), 28, 0xFF);
        (string path, VerifiedEdlFile claim) = await WriteFixtureAsync(misc);
        try
        {
            Task<BootSlotControlFacts> task = ReadForRecoveryViaReflection(claim, CancellationToken.None);
            InvalidDataException failure = await Assert.ThrowsAsync<InvalidDataException>(() => task);
            Assert.StartsWith("boot-slot-control-invalid:", failure.Message, StringComparison.Ordinal);
            Assert.Contains("CRC-32", failure.Message, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadForRecoveryAsync_NormalSuccessfulSelected_AttentionFalse()
    {
        // A normal bootable capture: public path succeeds and recovery path agrees — no attention.
        byte[] misc = MiscImage(ControlBlock("_a"));
        (string path, VerifiedEdlFile claim) = await WriteFixtureAsync(misc);
        try
        {
            BootSlotControlFacts strictFacts = await BootSlotControl.ReadAsync(claim, CancellationToken.None);
            Assert.False(strictFacts.NeedsBootloaderAttention);

            BootSlotControlFacts recoveryFacts = await ReadForRecoveryViaReflection(claim, CancellationToken.None);
            Assert.False(recoveryFacts.NeedsBootloaderAttention);
            Assert.Equal("a", recoveryFacts.CurrentSlot);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadForRecoveryAsync_NonZeroTriesUnsuccessfulSelected_AttentionFalseNormalReject()
    {
        // Selected slot with nonzero tries and unsuccessful is a normal bootable shape
        // (successful || tries > 0): accepted strictly, never flagged for attention.
        byte[] control = ControlBlock("_a");
        WriteSlot(control, 0, priority: 15, triesRemaining: 3, successful: false, verityCorrupted: false);
        BinaryPrimitives.WriteUInt32LittleEndian(control.AsSpan(28), Crc32Oracle(control.AsSpan(0, 28)));
        byte[] misc = MiscImage(control);
        (string path, VerifiedEdlFile claim) = await WriteFixtureAsync(misc);
        try
        {
            BootSlotControlFacts strictFacts = await BootSlotControl.ReadAsync(claim, CancellationToken.None);
            Assert.False(strictFacts.NeedsBootloaderAttention);

            BootSlotControlFacts recoveryFacts = await ReadForRecoveryViaReflection(claim, CancellationToken.None);
            Assert.False(recoveryFacts.NeedsBootloaderAttention);
            Assert.Equal("a", recoveryFacts.CurrentSlot);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadForRecoveryAsync_PreCanceled_NeverReadsFile()
    {
        // Pre-cancellation with a nonexistent unique NAS path: must cancel before any IO.
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        string path = Path.Combine(TestArtifactRoot.Resolve(), "bootslot-recovery-" + Guid.NewGuid().ToString("N") + ".img");

        Task<BootSlotControlFacts> task = ReadForRecoveryViaReflection(
            new VerifiedEdlFile(path, MiscLength, new string('0', 64)), cts.Token);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
        Assert.True(task.IsCanceled);
    }
}
