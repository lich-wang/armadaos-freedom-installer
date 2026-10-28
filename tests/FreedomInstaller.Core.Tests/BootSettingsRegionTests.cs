using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.ExceptionServices;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class BootSettingsRegionTests
{
    private static readonly Guid Partition = Guid.Parse("00112233-4455-6677-8899-aabbccddeeff");
    private static readonly Guid Installation = Guid.Parse("10213243-5465-7687-98a9-bacbdcedfe0f");
    private const long Offset = (2L << 30) - 65536;
    private static object? Call(string name, params object[] args)
    {
        var type = typeof(InternalInstallArtifacts).Assembly.GetType("FreedomInstaller.Core.BootSettingsRegion");
        Assert.NotNull(type);
        var method = type.GetMethod(name, BindingFlags.Static | BindingFlags.NonPublic);
        Assert.NotNull(method);
        try { return method.Invoke(null, args); }
        catch (TargetInvocationException e) when (e.InnerException != null)
        { ExceptionDispatchInfo.Capture(e.InnerException).Throw(); throw; }
    }
    private static byte[] Descriptor(string model = "TB322FC", long end = 1048576) =>
        (byte[])Call("CreateDescriptor", Partition, Installation, model, end)!;
    private static void Verify(byte[] region, string model = "TB322FC", long end = 1048576) =>
        Call("VerifyRegion", region, Partition, Installation, model, end);

    [Theory]
    [InlineData("TB322FC", 1u)]
    [InlineData("TB323FU", 2u)]
    public void Descriptor_matches_the_bootloader_wire_format(string model, uint board)
    {
        var d = Descriptor(model);
        Assert.Equal(4096, d.Length);
        Assert.Equal("KSCFGV3\0"u8.ToArray(), d[..8]);
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(8)));
        Assert.Equal(4096u, BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(12)));
        Assert.Equal(2L << 30, BinaryPrimitives.ReadInt64LittleEndian(d.AsSpan(16)));
        Assert.Equal(1048576, BinaryPrimitives.ReadInt64LittleEndian(d.AsSpan(24)));
        Assert.Equal(Offset, BinaryPrimitives.ReadInt64LittleEndian(d.AsSpan(32)));
        Assert.Equal(65536u, BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(40)));
        Assert.Equal(4096u, BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(44)));
        Assert.Equal(Convert.FromHexString("00112233445566778899AABBCCDDEEFF"), d[48..64]);
        Assert.Equal(Convert.FromHexString("102132435465768798A9BACBDCEDFE0F"), d[64..80]);
        Assert.Equal(4096u, BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(80)));
        Assert.Equal(8192u, BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(84)));
        Assert.Equal(board, BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(88)));
        Assert.All(d[92..4092], b => Assert.Equal((byte)0, b));
        uint crc = uint.MaxValue;
        foreach (byte b in d[..4092]) {
            crc ^= b;
            for (int i=0; i<8; i++) crc = (crc >> 1) ^ ((crc & 1) != 0 ? 0xedb88320u : 0);
        }
        Assert.Equal(~crc, BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(4092)));
        var export = Environment.GetEnvironmentVariable("KSHIM_CONFIG_FIXTURE");
        if (model == "TB322FC" && !string.IsNullOrEmpty(export))
            File.WriteAllBytes(export, d);
    }

    [Fact]
    public void Settings_writes_or_torn_slots_do_not_invalidate_recovery()
    {
        var region = new byte[65536];
        Descriptor().CopyTo(region, 0);
        Verify(region);
        Array.Fill(region, (byte)0xa5, 4096, 8192);
        Verify(region);
        region[12288] = 1;
        Assert.Throws<InvalidDataException>(() => Verify(region));
    }

    [Fact]
    public void Descriptor_identity_bounds_and_crc_are_bound_to_the_archive()
    {
        var region = new byte[65536];
        Descriptor().CopyTo(region, 0);
        Assert.Throws<InvalidDataException>(() => Verify(region, "TB323FU"));
        Assert.Throws<InvalidDataException>(() => Verify(region, end: 1048577));
        region[48] ^= 1;
        Assert.Throws<InvalidDataException>(() => Verify(region));
        Descriptor().CopyTo(region, 0);
        region[4092] ^= 1;
        Assert.Throws<InvalidDataException>(() => Verify(region));
        Assert.Throws<InvalidDataException>(() => Verify(new byte[65536]));
        Assert.Throws<InvalidDataException>(() => Verify(new byte[4096]));
    }

    [Fact]
    public void Only_supported_boards_and_nonoverlapping_payloads_can_be_provisioned()
    {
        Assert.Throws<InvalidDataException>(() => Descriptor("unknown"));
        Assert.Throws<InvalidDataException>(() => Descriptor(end: 65535));
        Assert.Throws<InvalidDataException>(() => Descriptor(end: Offset+1));
        Assert.Throws<InvalidDataException>(() =>
            Call("CreateDescriptor", Guid.Empty, Installation, "TB322FC", 1048576L));
        Assert.Throws<InvalidDataException>(() =>
            Call("CreateDescriptor", Partition, Guid.Empty, "TB322FC", 1048576L));
        Assert.Equal(4096, Descriptor(end: Offset).Length);
    }
}
