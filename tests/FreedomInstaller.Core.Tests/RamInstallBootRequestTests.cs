using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Focused coverage for the optional frozen boot block: omitted-boot byte equality with the front
/// request, the exact serialized keys, digest binding, immutability and every closed validation rule.
/// </summary>
public sealed class RamInstallBootRequestTests
{
    [Fact]
    public void NullBoot_KeepsTheExactFrontFieldSetBytesAndHash()
    {
        RamInstallRequest front = Rh002TestData.CreateRequest();
        RamInstallRequest explicitNull = Rh003TestData.CreateRequest(boot: null);

        byte[] frontBytes = Rh002TestData.RequestBytes(front);
        byte[] nullBytes = Rh002TestData.RequestBytes(explicitNull);

        Assert.Equal(frontBytes, nullBytes);
        Assert.Equal(front.RequestSha256, explicitNull.RequestSha256);
        Assert.Null(explicitNull.Boot);

        using var document = JsonDocument.Parse(nullBytes);
        Assert.Equal(
            new[]
            {
                "schemaVersion", "model", "device", "expectedSocSerial", "expectedBootId",
                "userdataGiB", "originalUserdataEndSector", "bootPartUuid", "rootPartUuid",
                "backupPartUuid", "expectedTable", "seed",
            }.OrderBy(name => name, StringComparer.Ordinal),
            document.RootElement.EnumerateObject().Select(property => property.Name)
                .OrderBy(name => name, StringComparer.Ordinal));
        Assert.False(document.RootElement.TryGetProperty("boot", out _));
        Assert.DoesNotContain("\"boot\"", System.Text.Encoding.UTF8.GetString(nullBytes), StringComparison.Ordinal);
    }

    [Fact]
    public void PopulatedBoot_UsesTheExactWireKeysAndBindsTheDigest()
    {
        RamInstallBootConfig boot = Rh003TestData.CreateBoot();
        RamInstallRequest request = Rh003TestData.CreateRequest(boot);
        byte[] bytes = Rh002TestData.RequestBytes(request);

        Assert.Equal(
            request.RequestSha256,
            Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant());
        Assert.NotEqual(Rh002TestData.CreateRequest().RequestSha256, request.RequestSha256);
        Assert.True(bytes.Length <= 1 << 20);

        using var document = JsonDocument.Parse(bytes);
        JsonElement root = document.RootElement;

        Assert.Equal(
            new[]
            {
                "schemaVersion", "model", "device", "expectedSocSerial", "expectedBootId",
                "userdataGiB", "originalUserdataEndSector", "bootPartUuid", "rootPartUuid",
                "backupPartUuid", "expectedTable", "seed", "boot",
            }.OrderBy(name => name, StringComparer.Ordinal),
            root.EnumerateObject().Select(property => property.Name)
                .OrderBy(name => name, StringComparer.Ordinal));

        JsonElement bootElement = root.GetProperty("boot");
        Assert.Equal(
            new[] { "schemaVersion", "slots", "runtime", "linux" }
                .OrderBy(name => name, StringComparer.Ordinal),
            bootElement.EnumerateObject().Select(property => property.Name)
                .OrderBy(name => name, StringComparer.Ordinal));
        Assert.Equal(1, bootElement.GetProperty("schemaVersion").GetInt32());

        JsonElement slots = bootElement.GetProperty("slots");
        Assert.Equal(
            new[] { "a", "b" },
            slots.EnumerateObject().Select(property => property.Name)
                .OrderBy(name => name, StringComparer.Ordinal));

        string[] slotKeys =
        {
            "currentBoot", "vendorBoot", "initBoot", "abl", "xblConfig",
        };

        foreach (string slotName in new[] { "a", "b" })
        {
            JsonElement slot = slots.GetProperty(slotName);
            Assert.Equal(
                slotKeys.OrderBy(name => name, StringComparer.Ordinal),
                slot.EnumerateObject().Select(property => property.Name)
                    .OrderBy(name => name, StringComparer.Ordinal));

            foreach (string materialName in slotKeys)
            {
                JsonElement descriptor = slot.GetProperty(materialName);
                Assert.Equal(
                    new[] { "slot", "partUuid", "length", "sha256" }
                        .OrderBy(name => name, StringComparer.Ordinal),
                    descriptor.EnumerateObject().Select(property => property.Name)
                        .OrderBy(name => name, StringComparer.Ordinal));
                Assert.Equal(slotName, descriptor.GetProperty("slot").GetString());
                Assert.Equal(64, descriptor.GetProperty("sha256").GetString()!.Length);
                Assert.True(descriptor.GetProperty("length").GetInt64() > 0);
            }
        }

        JsonElement runtime = bootElement.GetProperty("runtime");
        Assert.Equal(
            new[] { "length", "sha256" }.OrderBy(name => name, StringComparer.Ordinal),
            runtime.EnumerateObject().Select(property => property.Name)
                .OrderBy(name => name, StringComparer.Ordinal));
        Assert.Equal(RamInstallBootConfig.RuntimeLength, runtime.GetProperty("length").GetInt64());

        JsonElement linux = bootElement.GetProperty("linux");
        Assert.Equal(
            new[] { "kernel", "dtb", "initramfs" }.OrderBy(name => name, StringComparer.Ordinal),
            linux.EnumerateObject().Select(property => property.Name)
                .OrderBy(name => name, StringComparer.Ordinal));
    }

    [Fact]
    public void BootConfig_IsImmutableAndExposesNoWireExtras()
    {
        RamInstallBootConfig boot = Rh003TestData.CreateBoot();

        Assert.NotNull(boot.Slots);
        Assert.Equal("a", boot.Slots.A.Slot);
        Assert.Equal("b", boot.Slots.B.Slot);

        foreach (Type type in new[]
                 {
                     typeof(RamInstallBootConfig), typeof(RamInstallBootSlots), typeof(RamInstallBootSlot),
                     typeof(RamInstallPartitionMaterial), typeof(RamInstallFileIdentity),
                     typeof(RamInstallLinuxArtifacts),
                 })
        {
            foreach (PropertyInfo property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            {
                Assert.False(property.CanWrite, type.Name + "." + property.Name + " must be read-only.");
            }
        }

        // The slot identity is a descriptor field, never an extra slot-level key.
        Assert.Empty(typeof(RamInstallBootSlot)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(property => property.Name == "Slot" &&
                property.GetCustomAttribute<System.Text.Json.Serialization.JsonPropertyNameAttribute>() is not null));
    }

    [Fact]
    public void BootConfig_RejectsSlotPairThatIsNotExactlyAAndB()
    {
        RamInstallBootSlot slotA = Rh003TestData.CreateSlot("a");
        RamInstallBootSlot slotB = Rh003TestData.CreateSlot("b");

        Assert.Throws<ArgumentException>(() => new RamInstallBootSlots(slotB, slotA));
        Assert.Throws<ArgumentException>(() => new RamInstallBootConfig(
            slotB,
            slotA,
            Rh003TestData.RuntimeIdentity(),
            Rh003TestData.LinuxArtifacts()));
    }

    [Fact]
    public void BootSlot_RejectsDescriptorFromAnotherSlot()
    {
        RamInstallPartitionMaterial a = Rh003TestData.CreateMaterial("a", Rh003TestData.SlotAUuids[0]);
        RamInstallPartitionMaterial b = Rh003TestData.CreateMaterial("b", Rh003TestData.SlotBUuids[0]);

        Assert.Throws<ArgumentException>(() => new RamInstallBootSlot(
            a,
            b,
            Rh003TestData.CreateMaterial("a", Rh003TestData.SlotAUuids[2]),
            Rh003TestData.CreateMaterial("a", Rh003TestData.SlotAUuids[3]),
            Rh003TestData.CreateMaterial("a", Rh003TestData.SlotAUuids[4])));
    }

    [Fact]
    public void BootConfig_RejectsDuplicatePartUuidsAcrossTheTenMaterials()
    {
        RamInstallPartitionMaterial shared = Rh003TestData.CreateMaterial("a", Rh003TestData.SlotAUuids[0]);
        var slotA = new RamInstallBootSlot(
            shared,
            Rh003TestData.CreateMaterial("a", Rh003TestData.SlotAUuids[1]),
            Rh003TestData.CreateMaterial("a", Rh003TestData.SlotAUuids[2]),
            Rh003TestData.CreateMaterial("a", Rh003TestData.SlotAUuids[3]),
            Rh003TestData.CreateMaterial("a", Rh003TestData.SlotAUuids[4]));

        var slotB = new RamInstallBootSlot(
            Rh003TestData.CreateMaterial("b", Rh003TestData.SlotAUuids[0]),
            Rh003TestData.CreateMaterial("b", Rh003TestData.SlotBUuids[1]),
            Rh003TestData.CreateMaterial("b", Rh003TestData.SlotBUuids[2]),
            Rh003TestData.CreateMaterial("b", Rh003TestData.SlotBUuids[3]),
            Rh003TestData.CreateMaterial("b", Rh003TestData.SlotBUuids[4]));

        Assert.Throws<ArgumentException>(() => new RamInstallBootConfig(
            slotA,
            slotB,
            Rh003TestData.RuntimeIdentity(),
            Rh003TestData.LinuxArtifacts()));
    }

    [Fact]
    public void BootConfig_RejectsRuntimeOfAnotherLength()
    {
        Assert.Throws<ArgumentException>(() => new RamInstallBootConfig(
            Rh003TestData.CreateSlot("a"),
            Rh003TestData.CreateSlot("b"),
            new RamInstallFileIdentity(4096, new string('a', 64)),
            Rh003TestData.LinuxArtifacts()));
    }

    [Theory]
    [InlineData("uppercase-sha")]
    [InlineData("short-sha")]
    [InlineData("zero-length")]
    [InlineData("negative-length")]
    [InlineData("bad-slot")]
    [InlineData("bad-guid")]
    public void BootDescriptors_RejectEveryOutOfContractValue(string kind)
    {
        Action create;
        switch (kind)
        {
            case "uppercase-sha":
                create = () => _ = new RamInstallFileIdentity(1, new string('A', 64));
                break;
            case "short-sha":
                create = () => _ = new RamInstallFileIdentity(1, new string('a', 63));
                break;
            case "zero-length":
                create = () => _ = new RamInstallFileIdentity(0, new string('a', 64));
                break;
            case "negative-length":
                create = () => _ = Rh003TestData.CreateMaterial("a", Rh003TestData.SlotAUuids[0], length: -1);
                break;
            case "bad-slot":
                create = () => _ = Rh003TestData.CreateMaterial("c", Rh003TestData.SlotAUuids[0]);
                break;
            case "bad-guid":
                create = () => _ = Rh003TestData.CreateMaterial("a", "not-a-guid");
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(kind));
        }

        Assert.ThrowsAny<ArgumentException>(create);
    }

    [Fact]
    public void BootDescriptors_Accept64BitLengths()
    {
        var material = Rh003TestData.CreateMaterial("a", Rh003TestData.SlotAUuids[0], length: 6L * 1024 * 1024 * 1024);
        Assert.True(material.Length > int.MaxValue);

        var identity = new RamInstallFileIdentity(6L * 1024 * 1024 * 1024, new string('a', 64));
        Assert.True(identity.Length > int.MaxValue);
    }

    [Fact]
    public async Task NoBootRequest_RejectsEveryBootActionBeforeAnyConsoleCommand()
    {
        RamInstallRequest request = Rh002TestData.CreateRequest();
        var console = new Rh003FailingConsole();
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.GetStatusAsync(RamInstallAction.ReceiveOriginalBootA));
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.GetStatusAsync(RamInstallAction.ReceiveRuntime));
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.GetStatusAsync(RamInstallAction.BuildBoots));
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.GetStatusAsync(RamInstallAction.ExportBootA));
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.GetStatusAsync(RamInstallAction.Finish));
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.WaitForCompletionAsync(RamInstallAction.ReceiveRuntime, TimeSpan.FromSeconds(1)));
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.ReceiveOriginalBootAAsync(
                new VerifiedEdlFile("C:/fake/original-boot-a.img", 4096, new string('a', 64)),
                progress: null,
                TimeSpan.FromSeconds(1)));
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.ReceiveRuntimeAsync(
                new VerifiedEdlFile("C:/fake/runtime.bin", RamInstallBootConfig.RuntimeLength, new string('a', 64)),
                progress: null,
                TimeSpan.FromSeconds(1)));
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.StartBuildBootsAsync());

        Assert.Empty(console.Calls);
    }

    [Fact]
    public async Task UndefinedAction_IsRejectedBeforeAnyConsoleCommand()
    {
        RamInstallRequest request = Rh003TestData.CreateRequest(Rh003TestData.CreateBoot());
        var console = new Rh003FailingConsole();
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => client.GetStatusAsync((RamInstallAction)99));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => client.WaitForCompletionAsync((RamInstallAction)99, TimeSpan.FromSeconds(1)));

        Assert.Empty(console.Calls);
    }

    [Fact]
    public async Task FinishCompletion_IsNeverWaitedOnTheRamJob()
    {
        RamInstallRequest request = Rh003TestData.CreateRequest(Rh003TestData.CreateBoot());
        var console = new Rh003FailingConsole();
        var client = new RamInstallClient(Rh002TestData.CreateSession(console), request);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.WaitForCompletionAsync(RamInstallAction.Finish, TimeSpan.FromSeconds(1)));

        Assert.Empty(console.Calls);
    }
}

/// <summary>Shared RH003 boot fixtures. Only synthetic digests and lengths are used.</summary>
internal static class Rh003TestData
{
    public static readonly string[] SlotAUuids =
    {
        "aaaaaaa1-1111-4111-8111-111111111111",
        "aaaaaaa2-2222-4222-8222-222222222222",
        "aaaaaaa3-3333-4333-8333-333333333333",
        "aaaaaaa4-4444-4444-8444-444444444444",
        "aaaaaaa5-5555-4555-8555-555555555555",
    };

    public static readonly string[] SlotBUuids =
    {
        "bbbbbbb1-1111-4111-8111-111111111111",
        "bbbbbbb2-2222-4222-8222-222222222222",
        "bbbbbbb3-3333-4333-8333-333333333333",
        "bbbbbbb4-4444-4444-8444-444444444444",
        "bbbbbbb5-5555-4555-8555-555555555555",
    };

    public const long DefaultMaterialLength = 4096;

    public static RamInstallPartitionMaterial CreateMaterial(
        string slot,
        string partUuid,
        long length = DefaultMaterialLength,
        string? sha256 = null)
    {
        return new RamInstallPartitionMaterial(slot, partUuid, length, sha256 ?? new string('c', 64));
    }

    public static RamInstallBootSlot CreateSlot(
        string slot,
        long currentBootLength = DefaultMaterialLength,
        string? currentBootSha256 = null)
    {
        string[] uuids = slot == "a" ? SlotAUuids : SlotBUuids;
        return new RamInstallBootSlot(
            CreateMaterial(slot, uuids[0], currentBootLength, currentBootSha256),
            CreateMaterial(slot, uuids[1]),
            CreateMaterial(slot, uuids[2]),
            CreateMaterial(slot, uuids[3]),
            CreateMaterial(slot, uuids[4]));
    }

    public static RamInstallFileIdentity RuntimeIdentity(long length = RamInstallBootConfig.RuntimeLength, string? sha256 = null)
    {
        return new RamInstallFileIdentity(length, sha256 ?? new string('b', 64));
    }

    public static RamInstallLinuxArtifacts LinuxArtifacts()
    {
        return new RamInstallLinuxArtifacts(
            new RamInstallFileIdentity(1024, new string('d', 64)),
            new RamInstallFileIdentity(512, new string('e', 64)),
            new RamInstallFileIdentity(2048, new string('f', 64)));
    }

    public static RamInstallBootConfig CreateBoot(
        long originalBootALength = DefaultMaterialLength,
        string? originalBootASha256 = null,
        long runtimeLength = RamInstallBootConfig.RuntimeLength,
        string? runtimeSha256 = null)
    {
        return new RamInstallBootConfig(
            CreateSlot("a", originalBootALength, originalBootASha256),
            CreateSlot("b"),
            RuntimeIdentity(runtimeLength, runtimeSha256),
            LinuxArtifacts());
    }

    public static RamInstallRequest CreateRequest(RamInstallBootConfig? boot)
    {
        return new RamInstallRequest(
            Rh002TestData.SocSerial,
            Rh002TestData.BootId,
            Rh002TestData.UserdataGiB,
            Rh002TestData.OriginalUserdataEndSector,
            Rh002TestData.BootUuid,
            Rh002TestData.RootUuid,
            Rh002TestData.BackupUuid,
            new ExpectedTable(
                Rh002TestData.SectorSize,
                Rh002TestData.DiskBytes,
                Rh002TestData.DiskGuid,
                Rh002TestData.DefaultPartitions()),
            Rh002TestData.CreateSeed(),
            boot);
    }
}

/// <summary>A console that must never be used by the boot-gate tests.</summary>
internal sealed class Rh003FailingConsole : IMaintenanceConsole
{
    public List<string> Calls { get; } = new();

    public Task<string> RunCommandAsync(
        string script,
        string expectedMarker,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        Calls.Add(script);
        throw new InvalidOperationException("No console command is expected.");
    }
}
