using System;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Focused tests of the bounded, pure BCB overlay builder used by the post-RAM misc write. They pin the six
/// rules the write depends on: only 512/4096 sectors, exactly one rounded 2048-byte unit, an empty or exact
/// <c>bootonce-bootloader</c> pending command, an empty recovery, exact preservation of every non-BCB byte and
/// no mutation of the input.
/// <para>
/// The builder is internal and no <c>InternalsVisibleTo</c> exists, so this file carries the same narrow
/// reflection bridge as the EX001 run-state tests: resolve the one method, invoke the real production code and
/// unwrap <see cref="TargetInvocationException"/>. No backend, transport, device or file system is involved.
/// </para>
/// </summary>
public sealed class InternalInstallExecutionBcbTests
{
    private const int CommandBytes = 32;
    private const int RecoveryOffset = 64;
    private const int RecoveryBytes = 768;
    private const int Unit512Bytes = 2048;
    private const int Unit4096Bytes = 4096;

    private const string FixedCommand = "boot-recovery";
    private const string FixedRecovery = "recovery\n--wipe_data\n--reason=armada-internal-install\n";
    private const string BootOnce = "bootonce-bootloader";

    [Fact]
    public void Empty_command_block_becomes_the_fixed_install_bcb_with_real_newlines()
    {
        byte[] result = Build(new byte[Unit512Bytes], 512);

        Assert.Equal(Unit512Bytes, result.Length);
        Assert.Equal(FixedCommand, AsciiField(result, 0, CommandBytes));

        string recovery = AsciiField(result, RecoveryOffset, RecoveryBytes);
        Assert.Equal(FixedRecovery, recovery);
        Assert.Contains('\n', recovery);
        Assert.DoesNotContain("\\n", recovery);
    }

    [Fact]
    public void Boot_once_bootloader_is_accepted_and_replaced()
    {
        byte[] fresh = new byte[Unit512Bytes];
        Encoding.ASCII.GetBytes(BootOnce).CopyTo(fresh, 0);

        byte[] result = Build(fresh, 512);

        Assert.Equal(FixedCommand, AsciiField(result, 0, CommandBytes));
        Assert.Equal(FixedRecovery, AsciiField(result, RecoveryOffset, RecoveryBytes));
    }

    [Fact]
    public void Foreign_or_badly_padded_pending_command_is_refused()
    {
        byte[] reboot = new byte[Unit512Bytes];
        Encoding.ASCII.GetBytes("reboot").CopyTo(reboot, 0);
        Assert.Throws<InvalidOperationException>(() => Build(reboot, 512));

        byte[] badPadding = new byte[Unit512Bytes];
        Encoding.ASCII.GetBytes(BootOnce).CopyTo(badPadding, 0);
        badPadding[BootOnce.Length] = 0x01;
        Assert.Throws<InvalidOperationException>(() => Build(badPadding, 512));
    }

    [Fact]
    public void Non_empty_recovery_block_is_refused()
    {
        byte[] fresh = new byte[Unit512Bytes];
        fresh[RecoveryOffset] = 0x01;

        Assert.Throws<InvalidOperationException>(() => Build(fresh, 512));
    }

    [Fact]
    public void Five_twelve_byte_sectors_write_one_2048_byte_unit_and_preserve_status_stage_and_padding()
    {
        byte[] fresh = new byte[Unit512Bytes];
        Fill(fresh, 32, 32, 0x11);
        Fill(fresh, 832, Unit512Bytes - 832, 0x22);

        byte[] result = Build(fresh, 512);

        Assert.Equal(Unit512Bytes, result.Length);
        Assert.Equal(Slice(fresh, 32, 32), Slice(result, 32, 32));
        Assert.Equal(Slice(fresh, 832, Unit512Bytes - 832), Slice(result, 832, Unit512Bytes - 832));
        Assert.Equal(FixedCommand, AsciiField(result, 0, CommandBytes));
        Assert.Equal(FixedRecovery, AsciiField(result, RecoveryOffset, RecoveryBytes));
    }

    [Fact]
    public void Four_thousand_ninety_six_byte_sectors_preserve_the_suffix_beyond_2048()
    {
        byte[] fresh = new byte[Unit4096Bytes];
        Fill(fresh, 2048, 2048, 0x5A);

        byte[] result = Build(fresh, 4096);

        Assert.Equal(Unit4096Bytes, result.Length);
        Assert.Equal(Slice(fresh, 2048, 2048), Slice(result, 2048, 2048));
        Assert.Equal(FixedCommand, AsciiField(result, 0, CommandBytes));
        Assert.Equal(FixedRecovery, AsciiField(result, RecoveryOffset, RecoveryBytes));
    }

    [Fact]
    public void Builder_never_modifies_the_input_unit()
    {
        byte[] fresh = new byte[Unit512Bytes];
        Fill(fresh, 32, 32, 0x33);
        Fill(fresh, 832, Unit512Bytes - 832, 0x44);
        byte[] before = (byte[])fresh.Clone();

        _ = Build(fresh, 512);

        Assert.Equal(before, fresh);
    }

    [Fact]
    public void Unit_length_and_sector_size_are_validated()
    {
        Assert.Throws<ArgumentNullException>(() => Build(null!, 512));
        Assert.Throws<ArgumentOutOfRangeException>(() => Build(new byte[Unit4096Bytes], 1024));
        Assert.Throws<ArgumentException>(() => Build(new byte[1024], 512));
        Assert.Throws<ArgumentException>(() => Build(new byte[Unit4096Bytes], 512));
        Assert.Throws<ArgumentException>(() => Build(new byte[Unit512Bytes], 4096));
    }

    private static readonly MethodInfo Builder = typeof(InternalInstallBackend).GetMethod(
        "BuildInstallBcbWriteUnit",
        BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException(
            "InternalInstallBackend no longer declares the private static BuildInstallBcbWriteUnit method.");

    private static byte[] Build(byte[] freshWriteUnit, int sectorSize)
    {
        try
        {
            return (byte[])Builder.Invoke(null, new object?[] { freshWriteUnit, sectorSize })!;
        }
        catch (TargetInvocationException error) when (error.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(error.InnerException).Throw();
            throw;
        }
    }

    private static string AsciiField(byte[] bytes, int offset, int length) =>
        Encoding.ASCII.GetString(bytes, offset, length).TrimEnd('\0');

    private static byte[] Slice(byte[] bytes, int offset, int length)
    {
        byte[] slice = new byte[length];
        Array.Copy(bytes, offset, slice, 0, length);
        return slice;
    }

    private static void Fill(byte[] bytes, int offset, int length, byte value)
    {
        for (int index = offset; index < offset + length; index++)
        {
            bytes[index] = value;
        }
    }
}
