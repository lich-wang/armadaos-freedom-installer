using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Behavioural tests for the read-only modern AOSP virtual_ab_message parser. All fixtures are
/// synthetic byte arrays written under <see cref="TestArtifactRoot"/>; no device, backup or
/// shared file is read, no fixture exceeds 65536 bytes, and every assertion drives the real
/// ReadAsync path (no reflection assertions on method existence). The legacy AB32 boot_control
/// merge bits at offset 2048 are planted as decoys to prove they cannot influence the result.
/// </summary>
public sealed class BootVirtualAbControlTests
{
    private const int MessageOffset = 32768;
    private const int MessageSize = 64;
    private const int LegacyControlOffset = 2048;
    private const long MiscLength = 40960; // >= MessageOffset + MessageSize, <= 65536.
    private const uint VirtualAbMagic = 0x56740AB0u;

    // ---------------------------------------------------------------- fixtures

    /// <summary>Builds one exact 64-byte virtual_ab_message (version 2) with arbitrary reserved tail.</summary>
    private static byte[] Message(byte status, byte sourceSlot, bool garbageTail = true)
    {
        var message = new byte[MessageSize];
        message[0] = 2; // version
        BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(1), VirtualAbMagic);
        message[5] = status;
        message[6] = sourceSlot;
        if (garbageTail)
        {
            for (int i = 7; i < MessageSize; i++)
            {
                message[i] = (byte)(i * 7 + 3); // reserved bytes: arbitrary values tolerated
            }
        }

        return message;
    }

    /// <summary>Synthetic misc image: VAB message at 32768 plus contradictory AB32 decoy bytes at 2048.</summary>
    private static byte[] MiscImage(byte[] message, byte legacyAb32MergeBits = 0b101, char suffix = 'a')
    {
        var misc = new byte[MiscLength];
        // Decoy: AB32-style bytes with merge status low-3 bits that contradict the VAB status.
        misc[LegacyControlOffset] = (byte)'_';
        misc[LegacyControlOffset + 1] = (byte)suffix;
        misc[LegacyControlOffset + 2] = 0x00;
        misc[LegacyControlOffset + 10] = legacyAb32MergeBits;
        Array.Copy(message, 0, misc, MessageOffset, message.Length);
        return misc;
    }

    private static VerifiedEdlFile ClaimFor(string path, byte[] bytes)
    {
        string sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        return new VerifiedEdlFile(path, bytes.Length, sha);
    }

    private static async Task<(string Path, byte[] Bytes)> WriteFixtureAsync(byte[] bytes)
    {
        string path = Path.Combine(TestArtifactRoot.Resolve(), "bootvab-" + Guid.NewGuid().ToString("N") + ".img");
        await File.WriteAllBytesAsync(path, bytes);
        return (path, bytes);
    }

    private static async Task<T> ReadOwnedAsync<T>(byte[] fixtureBytes, Func<VerifiedEdlFile, Task<T>> read)
    {
        (string path, byte[] bytes) = await WriteFixtureAsync(fixtureBytes);
        try
        {
            return await read(ClaimFor(path, bytes));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static async Task AssertInvalidAsync(VerifiedEdlFile claim, string because)
    {
        InvalidDataException failure = await Assert.ThrowsAsync<InvalidDataException>(
            () => BootVirtualAbControl.ReadAsync(claim));
        Assert.StartsWith("boot-virtual-ab-control-invalid:", failure.Message);
        Assert.Contains(because, failure.Message, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------- valid parses

    [Theory]
    [InlineData(0, BootVirtualAbState.Completed, 0, 'a')]
    [InlineData(0, BootVirtualAbState.Completed, 1, 'a')]
    [InlineData(1, BootVirtualAbState.Unknown, 0, 'a')]
    [InlineData(1, BootVirtualAbState.Unknown, 1, 'a')]
    [InlineData(2, BootVirtualAbState.Snapshotted, 0, 'b')]
    [InlineData(2, BootVirtualAbState.Snapshotted, 1, 'b')]
    [InlineData(3, BootVirtualAbState.Merging, 0, 'a')]
    [InlineData(3, BootVirtualAbState.Merging, 1, 'a')]
    [InlineData(4, BootVirtualAbState.Cancelled, 0, 'b')]
    [InlineData(4, BootVirtualAbState.Cancelled, 1, 'b')]
    public async Task ReadAsync_ValidLayout_MapsStatusAndKeepsFacts(
        byte status, BootVirtualAbState expectedState, byte sourceSlot, char suffix)
    {
        byte[] message = Message(status, sourceSlot);
        byte[] misc = MiscImage(message, suffix: suffix);

        await ReadOwnedAsync(misc, async claim =>
        {
            BootVirtualAbControlFacts facts = await BootVirtualAbControl.ReadAsync(claim);

            Assert.Equal(expectedState, facts.State);
            Assert.True(facts.IsFormatValid);
            Assert.Equal((int)sourceSlot, facts.SourceSlot);
            Assert.Equal(
                Convert.ToHexString(SHA256.HashData(message)).ToLowerInvariant(),
                facts.MessageSha256);
            Assert.Equal(claim.Length, facts.Misc.Length);
            Assert.Equal(claim.Sha256, facts.Misc.Sha256);
            Assert.Equal(Path.GetFullPath(claim.Path), facts.Misc.Path);
            return true;
        });
    }

    [Fact]
    public async Task ReadAsync_DoesNotModifyFixture()
    {
        byte[] misc = MiscImage(Message((byte)BootVirtualAbState.Merging, 1));

        await ReadOwnedAsync(misc, async claim =>
        {
            await BootVirtualAbControl.ReadAsync(claim);
            Assert.Equal(misc, await File.ReadAllBytesAsync(claim.Path));
            return true;
        });
    }

    // -------------------------------------------------- source slot provenance

    [Theory]
    [InlineData(0b000, (byte)BootVirtualAbState.Cancelled, 1, 'a')]
    [InlineData(0b111, (byte)BootVirtualAbState.Snapshotted, 0, 'a')]
    [InlineData(0b010, (byte)BootVirtualAbState.Completed, 0, 'b')]
    public async Task ReadAsync_LegacyAb32Bits_NeverDetermineState(
        byte legacyMergeBits, byte vabStatus, byte vabSourceSlot, char suffix)
    {
        // The AB32 decoy merge bits contradict the VAB status; only the VAB message may win.
        // Suffix _a/_b varies independently of the VAB source slot: neither implies the other.
        byte[] misc = MiscImage(Message(vabStatus, vabSourceSlot), legacyMergeBits, suffix);

        await ReadOwnedAsync(misc, async claim =>
        {
            BootVirtualAbControlFacts facts = await BootVirtualAbControl.ReadAsync(claim);
            Assert.Equal((BootVirtualAbState)vabStatus, facts.State);
            Assert.Equal((int)vabSourceSlot, facts.SourceSlot);
            return true;
        });
    }

    // ---------------------------------------------------------- invalid formats

    [Fact]
    public async Task ReadAsync_StatusUnknownOne_IsValidFormatAndRetainsSourceSlot()
    {
        byte[] misc = MiscImage(Message(1, 1));

        await ReadOwnedAsync(misc, async claim =>
        {
            BootVirtualAbControlFacts facts = await BootVirtualAbControl.ReadAsync(claim);
            Assert.Equal(BootVirtualAbState.Unknown, facts.State);
            Assert.True(facts.IsFormatValid);
            Assert.Equal(1, facts.SourceSlot);
            Assert.NotNull(facts.MessageSha256);
            return true;
        });
    }

    [Theory]
    [InlineData("magic", 2, 0x56740AB1u, 0, 0)] // wrong magic
    [InlineData("version", 3, 0x56740AB0u, 0, 0)] // wrong version
    [InlineData("version", 1, 0x56740AB0u, 0, 0)] // legacy version is not this layout
    [InlineData("merge status", 2, 0x56740AB0u, 5, 0)] // status beyond Cancelled
    [InlineData("source slot", 2, 0x56740AB0u, 0, 2)] // slot beyond 1
    public async Task ReadAsync_InvalidField_IsUnknownWithoutSourceSlot(
        string field, byte version, uint magic, byte status, byte sourceSlot)
    {
        var message = new byte[MessageSize];
        message[0] = version;
        BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(1), magic);
        message[5] = status;
        message[6] = sourceSlot;
        byte[] misc = MiscImage(message);

        await ReadOwnedAsync(misc, async claim =>
        {
            BootVirtualAbControlFacts facts = await BootVirtualAbControl.ReadAsync(claim);
            Assert.Equal(BootVirtualAbState.Unknown, facts.State);
            Assert.False(facts.IsFormatValid);
            Assert.Null(facts.SourceSlot);
            // Message SHA is evidence even for invalid formats.
            Assert.Equal(
                Convert.ToHexString(SHA256.HashData(message)).ToLowerInvariant(),
                facts.MessageSha256);
            return true;
        });

        Assert.False(string.IsNullOrEmpty(field));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(32768)]
    [InlineData(32831)]
    public async Task ReadAsync_ShortFile_IsUnknownWithoutMessageSha(int length)
    {
        byte[] misc = new byte[length];
        if (length == 32768)
        {
            // Plenty of decoy bytes but not one full message.
            misc[0] = 2;
        }

        await ReadOwnedAsync(misc, async claim =>
        {
            BootVirtualAbControlFacts facts = await BootVirtualAbControl.ReadAsync(claim);
            Assert.Equal(BootVirtualAbState.Unknown, facts.State);
            Assert.False(facts.IsFormatValid);
            Assert.Null(facts.SourceSlot);
            Assert.Null(facts.MessageSha256);
            Assert.Equal(length, facts.Misc.Length);
            return true;
        });
    }

    // ------------------------------------------------------------ claim mismatch

    [Fact]
    public async Task ReadAsync_FileChangedAfterClaim_ThrowsStablePrefix()
    {
        byte[] misc = MiscImage(Message((byte)BootVirtualAbState.Completed, 0));
        (string path, _) = await WriteFixtureAsync(misc);
        try
        {
            VerifiedEdlFile claim = ClaimFor(path, misc);
            await File.WriteAllBytesAsync(path, MiscImage(Message((byte)BootVirtualAbState.Merging, 1)));
            await AssertInvalidAsync(claim, "SHA-256");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadAsync_WrongClaimedSha_ThrowsStablePrefix()
    {
        byte[] misc = MiscImage(Message((byte)BootVirtualAbState.Completed, 0));
        (string path, byte[] bytes) = await WriteFixtureAsync(misc);
        try
        {
            VerifiedEdlFile badSha = new(path, bytes.Length, new string('0', 64));
            await AssertInvalidAsync(badSha, "SHA-256");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadAsync_WrongClaimedLength_Throws()
    {
        byte[] misc = MiscImage(Message((byte)BootVirtualAbState.Completed, 0));
        (string path, byte[] bytes) = await WriteFixtureAsync(misc);
        try
        {
            VerifiedEdlFile wrongLength = new(path, bytes.Length + 1, ClaimFor(path, bytes).Sha256);
            await AssertInvalidAsync(wrongLength, "length");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadAsync_NegativeClaimedLength_Throws()
    {
        await Assert.ThrowsAsync<InvalidDataException>(
            () => BootVirtualAbControl.ReadAsync(
                new VerifiedEdlFile(Path.Combine(TestArtifactRoot.Resolve(), "bootvab-negative-" + Guid.NewGuid().ToString("N")), -1, new string('0', 64))));
    }

    [Fact]
    public async Task ReadAsync_NullClaim_ThrowsArgumentNull()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => BootVirtualAbControl.ReadAsync(null!));
    }

    // ------------------------------------------------------------ actual IO failure

    [Fact]
    public async Task ReadAsync_MissingFile_ThrowsFileNotFound()
    {
        // Unique path that is never created: a genuine IO failure, never folded into Unknown.
        string nonexistent = Path.Combine(
            TestArtifactRoot.Resolve(), "bootvab-missing-" + Guid.NewGuid().ToString("N") + ".img");
        var claim = new VerifiedEdlFile(nonexistent, MiscLength, new string('0', 64));

        await Assert.ThrowsAsync<FileNotFoundException>(
            () => BootVirtualAbControl.ReadAsync(claim));
        Assert.False(File.Exists(nonexistent));
    }

    // ------------------------------------------------------------ cancellation

    [Fact]
    public async Task ReadAsync_PreCanceledToken_NonexistentPath_CancelsBeforeIo()
    {
        // Unique path that is never created: any file access would surface as IO, not cancel.
        string nonexistent = Path.Combine(
            TestArtifactRoot.Resolve(), "bootvab-precancel-" + Guid.NewGuid().ToString("N") + ".img");
        var claim = new VerifiedEdlFile(nonexistent, MiscLength, new string('0', 64));
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => BootVirtualAbControl.ReadAsync(claim, canceled.Token));
        Assert.False(File.Exists(nonexistent));
    }
}
