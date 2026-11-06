using System.Buffers.Binary;
using System.Security.Cryptography;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class CurrentBootSlotTests :
    IClassFixture<EdlClientToolchainFixture>, IClassFixture<Gen5EdlToolchainFixture>
{
    private readonly EdlClientToolchainFixture _g4;
    private readonly Gen5EdlToolchainFixture _g5;

    public CurrentBootSlotTests(EdlClientToolchainFixture g4, Gen5EdlToolchainFixture g5)
    {
        _g4 = g4;
        _g5 = g5;
    }

    [Theory]
    [InlineData(false, "a")]
    [InlineData(false, "b")]
    [InlineData(true, "a")]
    [InlineData(true, "b")]
    public async Task ZeroMisc_UsesVerifiedBootGptForBothModels(bool gen5, string slot)
    {
        using var h = await Capture(gen5, slot, "valid");
        int before = h.Runner.Commands.Count;
        var result = await CurrentBootSlot.ReadAsync(h.Backup);
        Assert.Equal(slot, result.CurrentSlot);
        Assert.Equal(64, result.ControlSha256.Length);
        Assert.NotEqual(Convert.ToHexString(SHA256.HashData(new byte[32])), result.ControlSha256, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(before, h.Runner.Commands.Count);
        Assert.False(result.NeedsBootloaderAttention);
        Assert.Equal(result, await CurrentBootSlot.ReadAsync(h.Backup));
    }

    [Theory]
    [InlineData(false, "both-active")]
    [InlineData(true, "both-active")]
    [InlineData(false, "neither-active")]
    [InlineData(true, "neither-active")]
    [InlineData(false, "unbootable")]
    [InlineData(true, "unbootable")]
    [InlineData(false, "exhausted")]
    [InlineData(true, "exhausted")]
    [InlineData(false, "malformed-aosp")]
    [InlineData(true, "malformed-aosp")]
    [InlineData(false, "zero-priority")]
    [InlineData(true, "zero-priority")]
    public async Task InvalidAuthority_IsRejectedWithoutDeviceIo(bool gen5, string scenario)
    {
        using var h = await Capture(gen5, "b", scenario);
        int before = h.Runner.Commands.Count;
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => CurrentBootSlot.ReadAsync(h.Backup));
        Assert.StartsWith("boot-slot-control-invalid:", error.Message);
        Assert.Equal(before, h.Runner.Commands.Count);
    }

    [Theory]
    [InlineData(false, "successful-no-retries")]
    [InlineData(true, "successful-no-retries")]
    [InlineData(false, "unconfirmed-with-retries")]
    [InlineData(true, "unconfirmed-with-retries")]
    public async Task BootableSlotFlags_AreAccepted(bool gen5, string scenario)
    {
        using var h = await Capture(gen5, "b", scenario);
        Assert.Equal("b", (await CurrentBootSlot.ReadAsync(h.Backup)).CurrentSlot);
    }

    [Theory]
    [InlineData("misc")]
    [InlineData("gpt_lun4_primary")]
    [InlineData("gpt_lun4_backup")]
    public async Task ChangedCapture_IsRejected(string role)
    {
        using var h = await Capture(true, "b", "valid");
        h.Backup.Dispose();
        string path = h.Backup.Files[role].FilePath;
        byte[] data = await File.ReadAllBytesAsync(path);
        data[0] ^= 0x01;
        await File.WriteAllBytesAsync(path, data);
        await Assert.ThrowsAsync<InvalidDataException>(() => CurrentBootSlot.ReadAsync(h.Backup));
    }

    private async Task<Case> Capture(bool gen5, string slot, string scenario)
    {
        string parent = gen5 ? _g5.NewCaseDirectory(nameof(CurrentBootSlotTests)) : _g4.NewCaseDirectory(nameof(CurrentBootSlotTests));
        EdlToolchain tools = gen5 ? _g5.Toolchain : _g4.Toolchain;
        var device = IB001SyntheticDevice.Create(gen5: gen5);
        var miscRange = device.Expectation("misc");
        byte[] misc = device.PayloadFor(miscRange.Lun, miscRange.Start, miscRange.Count)!;
        Array.Clear(misc);
        if (scenario == "malformed-aosp") misc[2048] = 0x5A;

        byte[] primary = device.PayloadFor(4, 0, 64)!;
        byte[] backup = device.PayloadFor(4, device.TotalSectors(4) - 64, 64)!;
        var table = OriginalGptImporter.Parse(primary, backup, 4096, device.TotalSectors(4) * 4096);
        ulong active = 0x0077000000000000UL;
        ulong inactive = 0x00F3000000000000UL;
        if (scenario == "both-active") inactive |= 1UL << 50;
        if (scenario == "neither-active") active &= ~(1UL << 50);
        if (scenario == "unbootable") active |= 1UL << 55;
        if (scenario == "exhausted") active &= ~((1UL << 54) | (7UL << 51));
        if (scenario == "successful-no-retries") active &= ~(7UL << 51);
        if (scenario == "unconfirmed-with-retries") active &= ~(1UL << 54);
        if (scenario == "zero-priority") active &= ~(3UL << 48);
        var specs = table.Partitions.Select(p => new GptPartitionSpec(
            p.Number, p.Name, p.TypeGuid, p.PartUuid, p.StartSector, p.SectorCount,
            p.Name == "boot_" + slot ? active :
            p.Name is "boot_a" or "boot_b" ? inactive : p.Attributes)).ToArray();
        var image = new GptImage(table.SectorSize, table.DiskBytes, table.DiskGuid,
            table.FirstUsableSector, table.LastUsableSector, specs);
        byte[] pBytes = image.BuildPrimaryFragment();
        byte[] bBytes = image.BuildBackupFragment();
        Array.Clear(primary);
        Array.Clear(backup);
        pBytes.CopyTo(primary, 0);
        bBytes.CopyTo(backup, backup.Length - bBytes.Length);

        string hwid = gen5 ? "002B40E100400000" : E003EdlTestData.HardwareId;
        var runner = new IB001FakeEdlRunner(device, hardwareId: hwid);
        var identity = new AndroidMaintenanceIdentity(
            new DeviceIdentity(E003EdlTestData.SocSerialDecimal, tools.Model, BootloaderState.Unknown)
            {
                Firmware = new FirmwareSnapshot(gen5
                    ? "TB323FU_CN_OPEN_USER_Q00020.0_A16_ZUXOS_2.0.11.043_ST_260309"
                    : "TB322FC_CN_OPEN_USER_Q0041.1_W_ZUXOS_1.5.10.259_ST_260611", null, null, null, BootloaderState.Unknown)
            }, E003EdlTestData.SocSerialDecimal);
        var client = new EdlClient(tools,
            new EdlEntryResult(identity, E003EdlTestData.Endpoint(), E003EdlTestData.BusSerialHex),
            runner, new E003ScriptedEndpointDiscovery { Endpoints = new[] { E003EdlTestData.Endpoint() } });
        return new Case(await InternalInstallBackup.CreateAsync(client, parent), runner);
    }

    private sealed record Case(InternalBackupSet Backup, IB001FakeEdlRunner Runner) : IDisposable
    {
        public void Dispose() => Backup.Dispose();
    }
}
