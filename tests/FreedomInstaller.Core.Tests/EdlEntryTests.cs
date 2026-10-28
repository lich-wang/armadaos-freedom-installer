using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

internal sealed class EdlFakeCommandRunner : ICommandRunner
{
    private readonly Func<ProcessCommand, ProcessResult> _handler;

    public EdlFakeCommandRunner(Func<ProcessCommand, ProcessResult>? handler = null)
    {
        _handler = handler ?? (_ => new ProcessResult(0, string.Empty, string.Empty));
    }

    public List<ProcessCommand> Commands { get; } = new();

    public static EdlFakeCommandRunner Succeeding() => new();

    public Task<ProcessResult> RunAsync(ProcessCommand command, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Commands.Add(command);
        return Task.FromResult(_handler(command));
    }
}

internal sealed class EdlFakeEndpointDiscovery : IEdlEndpointDiscovery
{
    private readonly Queue<IReadOnlyList<EdlEndpoint>> _pollResults;
    private readonly Action<int>? _onRead;

    public EdlFakeEndpointDiscovery(
        IEnumerable<IReadOnlyList<EdlEndpoint>> pollResults,
        Action<int>? onRead = null)
    {
        _pollResults = new Queue<IReadOnlyList<EdlEndpoint>>(pollResults);
        _onRead = onRead;
    }

    public int Calls { get; private set; }

    public IReadOnlyList<EdlEndpoint> ReadPresent()
    {
        Calls++;
        _onRead?.Invoke(Calls);

        return _pollResults.Count > 0
            ? _pollResults.Dequeue()
            : Array.Empty<EdlEndpoint>();
    }
}

/// <summary>BCL-only manual clock: timestamps advance only when the test says so.</summary>
internal sealed class EdlManualTimeProvider : TimeProvider
{
    private readonly long _frequency;
    private long _timestamp;

    public EdlManualTimeProvider(long startTimestamp = 0, long timestampFrequency = 1000)
    {
        _frequency = timestampFrequency;
        _timestamp = startTimestamp;
    }

    public override long TimestampFrequency => _frequency;

    public override long GetTimestamp() => Interlocked.Read(ref _timestamp);

    public void Advance(TimeSpan delta) =>
        Interlocked.Add(ref _timestamp, (long)(delta.TotalSeconds * TimestampFrequency));
}

public sealed class EdlEntryTests
{
    private const string AdbPath = "/opt/platform-tools/adb";
    private const string Serial = "HA1B2C3D4";
    private const string SocDecimal = "3251823604";
    private const string BusSnHex = "C1D2E3F4";
    private const string InstanceId = @"USB\VID_05C6&PID_9008\5&2A3B4C5D&0&1";
    private const string BusDescription = "QUSB_BULK_CID:045A_SN:C1D2E3F4";

    // Synthetic serial and non-blank actual firmware. Only the model matches a real G5 observation.
    private const string G5Model = "TB323FU";
    private const string G5ActualDisplayId = "TB323FU_SYNTHETIC_ACTUAL_FIRMWARE";

    private static EdlEndpoint Endpoint(
        string instanceId = InstanceId,
        string? portName = "COM7",
        string? busDescription = BusDescription)
        => new(instanceId, portName, busDescription);

    private static AndroidMaintenanceIdentity CreateAndroid(
        string serial = Serial,
        string socSerial = SocDecimal,
        string model = MaintenanceProfiles.Model,
        string? displayId = MaintenanceProfiles.AndroidBuild,
        bool includeFirmware = true,
        BootloaderState bootloaderState = BootloaderState.Unknown)
        => new(
            new DeviceIdentity(serial, model, bootloaderState)
            {
                Firmware = includeFirmware
                    ? new FirmwareSnapshot(displayId, "google/fingerprint", "16", "2026-06-01", bootloaderState)
                    : null,
            },
            socSerial);

    private static EdlEntry CreateEntry(
        ICommandRunner runner,
        IEdlEndpointDiscovery discovery,
        TimeProvider? timeProvider = null)
        => new(AdbPath, runner, discovery, timeProvider);

    [Fact]
    public async Task EnterAsync_normal_decimal_soc_returns_result_and_issues_exactly_one_reboot()
    {
        var endpoint = Endpoint();
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { endpoint } });
        var entry = CreateEntry(runner, discovery);
        var android = CreateAndroid();

        var result = await entry.EnterAsync(android);

        var command = Assert.Single(runner.Commands);
        Assert.Equal(AdbPath, command.Executable);
        Assert.Equal(new[] { "-s", Serial, "reboot", "edl" }, command.Arguments);
        Assert.Equal(TimeSpan.FromSeconds(10), command.Timeout);

        Assert.Same(android, result.AndroidIdentity);
        Assert.Equal(endpoint, result.Endpoint);
        Assert.Equal(BusSnHex, result.BusSerialHex);
    }

    [Theory]
    [InlineData(BootloaderState.Unknown, "c1d2e3f4")]
    [InlineData(BootloaderState.Locked, "C1D2E3F4")]
    public async Task EnterAsync_accepts_unknown_or_locked_bootloader_state_and_lowercase_bus_hex(
        BootloaderState bootloaderState,
        string busSn)
    {
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(
            new[] { new[] { Endpoint(busDescription: "QUSB_BULK_CID:045A_SN:" + busSn) } });
        var entry = CreateEntry(runner, discovery);
        var android = CreateAndroid(bootloaderState: bootloaderState);

        var result = await entry.EnterAsync(android);

        Assert.Equal(BusSnHex, result.BusSerialHex);
        Assert.Single(runner.Commands);
    }

    [Fact]
    public async Task EnterAsync_collapses_case_variant_duplicate_instance_ids_and_accepts_null_port()
    {
        var withPort = Endpoint(InstanceId, "COM7");
        var withoutPort = Endpoint(InstanceId.ToLowerInvariant(), null);
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { withPort, withoutPort } });
        var entry = CreateEntry(runner, discovery);

        var result = await entry.EnterAsync(CreateAndroid());

        Assert.Contains(result.Endpoint, new[] { withPort, withoutPort });
        Assert.Equal(BusSnHex, result.BusSerialHex);
        Assert.Single(runner.Commands);
    }

    [Fact]
    public async Task EnterAsync_rejects_conflicting_sn_within_same_instance_duplicates()
    {
        var matching = Endpoint(InstanceId, "COM7", "QUSB_BULK_CID:045A_SN:C1D2E3F4");
        var conflicting = Endpoint(InstanceId.ToLowerInvariant(), null, "QUSB_BULK_CID:045A_SN:DEADBEEF");
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { matching, conflicting } });
        var entry = CreateEntry(runner, discovery);

        await Assert.ThrowsAsync<InvalidOperationException>(() => entry.EnterAsync(CreateAndroid()));

        Assert.Single(runner.Commands);
        Assert.Equal(1, discovery.Calls);
    }

    [Fact]
    public async Task EnterAsync_rejects_two_distinct_instance_ids_even_with_same_sn()
    {
        var first = Endpoint(@"USB\VID_05C6&PID_9008\5&AAAAAAAA&0&1");
        var second = Endpoint(@"USB\VID_05C6&PID_9008\5&BBBBBBBB&0&1");
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { first, second } });
        var entry = CreateEntry(runner, discovery);

        await Assert.ThrowsAsync<InvalidOperationException>(() => entry.EnterAsync(CreateAndroid()));

        Assert.Single(runner.Commands);
        Assert.Equal(1, discovery.Calls);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("QUSB_BULK_CID:045A")]
    [InlineData("QUSB_BULK_CID:045A_SN:E3E8547")]
    [InlineData("QUSB_BULK_CID:045A_SN:C1D2E3F40")]
    [InlineData("QUSB_BULK_CID:045A_SN:C1D2E3F4_SN:C1D2E3F4")]
    [InlineData("QUSB_BULK_CID:045A_SN:C1D2E3F4_SN:DEADBEEF")]
    [InlineData("QUSB_BULK_CID:045A_SN:DEADBEEF")]
    public async Task EnterAsync_rejects_unusable_bus_description(string? busDescription)
    {
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(
            new[] { new[] { Endpoint(busDescription: busDescription) } });
        var entry = CreateEntry(runner, discovery);

        await Assert.ThrowsAsync<InvalidOperationException>(() => entry.EnterAsync(CreateAndroid()));

        Assert.Single(runner.Commands);
        Assert.Equal(1, discovery.Calls);
    }

    [Theory]
    [InlineData("")]
    [InlineData("0xC1D2E3F4")]
    [InlineData("-1")]
    [InlineData("3823 654012")]
    [InlineData("4294967296")]
    [InlineData("3251823604 ")]
    public async Task EnterAsync_rejects_invalid_soc_before_any_command(string socSerial)
    {
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { Endpoint() } });
        var entry = CreateEntry(runner, discovery);

        await RedAssert.RejectedAsync(() => entry.EnterAsync(CreateAndroid(socSerial: socSerial)));

        Assert.Empty(runner.Commands);
        Assert.Equal(0, discovery.Calls);
    }

    [Theory]
    [InlineData("TB323FU", true, "HA1B2C3D4", null)]
    [InlineData("TB322FC", true, "HA1B2C3D4", "")]
    [InlineData("TB322FC", false, "HA1B2C3D4", null)]
    [InlineData("TB322FC", true, "BAD SERIAL", null)]
    [InlineData("TB322FC", true, " ", null)]
    public async Task EnterAsync_rejects_invalid_android_identity_before_any_command(
        string model,
        bool includeFirmware,
        string serial,
        string? displayId)
    {
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { Endpoint() } });
        var entry = CreateEntry(runner, discovery);
        var android = CreateAndroid(
            serial: serial,
            model: model,
            displayId: displayId ?? MaintenanceProfiles.AndroidBuild,
            includeFirmware: includeFirmware);

        await RedAssert.RejectedAsync(() => entry.EnterAsync(android));

        Assert.Empty(runner.Commands);
        Assert.Equal(0, discovery.Calls);
    }

    [Fact]
    public async Task EnterAsync_nonzero_reboot_exit_is_io_error_and_skips_discovery()
    {
        var runner = new EdlFakeCommandRunner(_ => new ProcessResult(1, string.Empty, "reboot refused"));
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { Endpoint() } });
        var entry = CreateEntry(runner, discovery);

        await Assert.ThrowsAsync<IOException>(() => entry.EnterAsync(CreateAndroid()));

        Assert.Single(runner.Commands);
        Assert.Equal(0, discovery.Calls);
    }

    [Fact]
    public async Task EnterAsync_propagates_runner_timeout_without_discovery()
    {
        var runner = new EdlFakeCommandRunner(_ => throw new TimeoutException("adb reboot timed out"));
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { Endpoint() } });
        var entry = CreateEntry(runner, discovery);

        await Assert.ThrowsAsync<TimeoutException>(() => entry.EnterAsync(CreateAndroid()));

        Assert.Single(runner.Commands);
        Assert.Equal(0, discovery.Calls);
    }

    [Fact]
    public async Task EnterAsync_pre_cancelled_token_issues_no_command()
    {
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { Endpoint() } });
        var entry = CreateEntry(runner, discovery);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => entry.EnterAsync(CreateAndroid(), new CancellationToken(canceled: true)));

        Assert.Empty(runner.Commands);
        Assert.Equal(0, discovery.Calls);
    }

    [Fact]
    public async Task EnterAsync_cancellation_during_discovery_does_not_reboot_again()
    {
        using var cts = new CancellationTokenSource();
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(
            new[] { new[] { Endpoint() } },
            _ => cts.Cancel());
        var entry = CreateEntry(runner, discovery);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => entry.EnterAsync(CreateAndroid(), cts.Token));

        Assert.Single(runner.Commands);
        Assert.Equal(1, discovery.Calls);
    }

    [Fact]
    public async Task EnterAsync_times_out_quickly_when_discovery_advances_past_deadline()
    {
        var clock = new EdlManualTimeProvider();
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(
            new[] { Array.Empty<EdlEndpoint>() },
            _ => clock.Advance(EdlEntry.DiscoveryTimeout));
        var entry = CreateEntry(runner, discovery, clock);

        await Assert.ThrowsAsync<TimeoutException>(() => entry.EnterAsync(CreateAndroid()))
            .WaitAsync(TimeSpan.FromSeconds(2));

        Assert.Equal(1, discovery.Calls);
        Assert.Single(runner.Commands);
    }

    [Fact]
    public async Task EnterAsync_polls_until_endpoint_appears_with_single_reboot()
    {
        var clock = new EdlManualTimeProvider();
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(
            new[] { Array.Empty<EdlEndpoint>(), new[] { Endpoint() } },
            call =>
            {
                if (call == 1)
                {
                    clock.Advance(TimeSpan.FromMilliseconds(100));
                }
            });
        var entry = CreateEntry(runner, discovery, clock);

        var result = await entry.EnterAsync(CreateAndroid()).WaitAsync(TimeSpan.FromSeconds(2));

        Assert.Equal(2, discovery.Calls);
        Assert.Equal(BusSnHex, result.BusSerialHex);
        Assert.Single(runner.Commands);
    }

    [Fact]
    public async Task WaitForPresentAsync_returns_already_present_endpoint_without_any_command()
    {
        var endpoint = Endpoint();
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { endpoint } });
        var entry = CreateEntry(runner, discovery);
        var android = CreateAndroid();

        var result = await entry.WaitForPresentAsync(android);

        Assert.Same(android, result.AndroidIdentity);
        Assert.Equal(endpoint, result.Endpoint);
        Assert.Equal(BusSnHex, result.BusSerialHex);
        Assert.Equal(1, discovery.Calls);
        Assert.Empty(runner.Commands);
    }

    [Fact]
    public async Task WaitForPresentAsync_polls_empty_present_set_then_returns_endpoint_without_any_command()
    {
        var clock = new EdlManualTimeProvider();
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(
            new[] { Array.Empty<EdlEndpoint>(), new[] { Endpoint() } },
            call =>
            {
                if (call == 1)
                {
                    clock.Advance(TimeSpan.FromMilliseconds(100));
                }
            });
        var entry = CreateEntry(runner, discovery, clock);
        var android = CreateAndroid();

        var result = await entry.WaitForPresentAsync(android).WaitAsync(TimeSpan.FromSeconds(2));

        Assert.Same(android, result.AndroidIdentity);
        Assert.Equal(BusSnHex, result.BusSerialHex);
        Assert.Equal(2, discovery.Calls);
        Assert.Empty(runner.Commands);
    }

    [Fact]
    public async Task WaitForPresentAsync_rejects_mismatched_bus_serial_without_any_command()
    {
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(
            new[] { new[] { Endpoint(busDescription: "QUSB_BULK_CID:045A_SN:DEADBEEF") } });
        var entry = CreateEntry(runner, discovery);

        await Assert.ThrowsAsync<InvalidOperationException>(() => entry.WaitForPresentAsync(CreateAndroid()));

        Assert.Equal(1, discovery.Calls);
        Assert.Empty(runner.Commands);
    }

    [Fact]
    public async Task WaitForPresentAsync_rejects_two_distinct_instance_ids_even_with_same_sn_without_any_command()
    {
        var first = Endpoint(@"USB\VID_05C6&PID_9008\5&AAAAAAAA&0&1");
        var second = Endpoint(@"USB\VID_05C6&PID_9008\5&BBBBBBBB&0&1");
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { first, second } });
        var entry = CreateEntry(runner, discovery);

        await Assert.ThrowsAsync<InvalidOperationException>(() => entry.WaitForPresentAsync(CreateAndroid()));

        Assert.Equal(1, discovery.Calls);
        Assert.Empty(runner.Commands);
    }

    [Fact]
    public async Task WaitForPresentAsync_times_out_on_manual_clock_without_any_command()
    {
        var clock = new EdlManualTimeProvider();
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(
            new[] { Array.Empty<EdlEndpoint>() },
            _ => clock.Advance(EdlEntry.DiscoveryTimeout));
        var entry = CreateEntry(runner, discovery, clock);

        await Assert.ThrowsAsync<TimeoutException>(() => entry.WaitForPresentAsync(CreateAndroid()))
            .WaitAsync(TimeSpan.FromSeconds(2));

        Assert.Equal(1, discovery.Calls);
        Assert.Empty(runner.Commands);
    }

    [Fact]
    public async Task WaitForPresentAsync_pre_cancelled_token_reads_nothing()
    {
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { Endpoint() } });
        var entry = CreateEntry(runner, discovery);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => entry.WaitForPresentAsync(CreateAndroid(), new CancellationToken(canceled: true)));

        Assert.Equal(0, discovery.Calls);
        Assert.Empty(runner.Commands);
    }

    [Theory]
    [InlineData("TB323FU", MaintenanceProfiles.AndroidBuild)]
    [InlineData(MaintenanceProfiles.Model, " \t")]
    public async Task WaitForPresentAsync_rejects_invalid_profile_before_commands_or_discovery(
        string model,
        string displayId)
    {
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { Endpoint() } });
        var entry = CreateEntry(runner, discovery);
        var android = CreateAndroid(model: model, displayId: displayId);

        await Assert.ThrowsAsync<InvalidOperationException>(() => entry.WaitForPresentAsync(android));

        Assert.Equal(0, discovery.Calls);
        Assert.Empty(runner.Commands);
    }

    private static EdlDeviceProfile RequireProfile(string profileId)
    {
        var profile = EdlDeviceProfiles.FindById(profileId);
        Assert.NotNull(profile);
        return profile!;
    }

    [Fact]
    public async Task EnterAsync_explicit_default_profile_keeps_single_reboot_and_proof()
    {
        var endpoint = Endpoint();
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { endpoint } });
        var entry = CreateEntry(runner, discovery);
        var android = CreateAndroid();

        var result = await entry.EnterAsync(android, EdlDeviceProfiles.Default);

        var command = Assert.Single(runner.Commands);
        Assert.Equal(AdbPath, command.Executable);
        Assert.Equal(new[] { "-s", Serial, "reboot", "edl" }, command.Arguments);
        Assert.Equal(TimeSpan.FromSeconds(10), command.Timeout);

        Assert.Same(android, result.AndroidIdentity);
        Assert.Equal(endpoint, result.Endpoint);
        Assert.Equal(BusSnHex, result.BusSerialHex);
        Assert.Equal(1, discovery.Calls);
    }

    [Fact]
    public async Task EnterAsync_old_route_and_explicit_default_route_agree()
    {
        var oldRunner = EdlFakeCommandRunner.Succeeding();
        var oldDiscovery = new EdlFakeEndpointDiscovery(new[] { new[] { Endpoint() } });
        var explicitRunner = EdlFakeCommandRunner.Succeeding();
        var explicitDiscovery = new EdlFakeEndpointDiscovery(new[] { new[] { Endpoint() } });
        var android = CreateAndroid();

        var oldResult = await CreateEntry(oldRunner, oldDiscovery).EnterAsync(android);
        var explicitResult = await CreateEntry(explicitRunner, explicitDiscovery)
            .EnterAsync(android, EdlDeviceProfiles.Default);

        var oldCommand = Assert.Single(oldRunner.Commands);
        var explicitCommand = Assert.Single(explicitRunner.Commands);
        Assert.Equal(oldCommand.Executable, explicitCommand.Executable);
        Assert.Equal(oldCommand.Arguments, explicitCommand.Arguments);
        Assert.Equal(oldCommand.Timeout, explicitCommand.Timeout);

        Assert.Same(oldResult.AndroidIdentity, explicitResult.AndroidIdentity);
        Assert.Equal(oldResult.Endpoint, explicitResult.Endpoint);
        Assert.Equal(oldResult.BusSerialHex, explicitResult.BusSerialHex);
    }

    [Fact]
    public async Task WaitForPresentAsync_explicit_default_profile_returns_present_endpoint_without_any_command()
    {
        var endpoint = Endpoint();
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { endpoint } });
        var entry = CreateEntry(runner, discovery);
        var android = CreateAndroid();

        var result = await entry.WaitForPresentAsync(android, EdlDeviceProfiles.Default);

        Assert.Same(android, result.AndroidIdentity);
        Assert.Equal(endpoint, result.Endpoint);
        Assert.Equal(BusSnHex, result.BusSerialHex);
        Assert.Equal(1, discovery.Calls);
        Assert.Empty(runner.Commands);
    }

    [Fact]
    public async Task EnterAsync_explicit_g5_profile_enters_with_single_reboot_and_correlated_bus_identity()
    {
        var profile = RequireProfile("g5-9008-y7005");
        Assert.True(profile.IsComplete);

        var endpoint = Endpoint();
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { endpoint } });
        var entry = CreateEntry(runner, discovery);
        var android = CreateAndroid(model: G5Model, displayId: G5ActualDisplayId);

        var result = await entry.EnterAsync(android, profile);

        var command = Assert.Single(runner.Commands);
        Assert.Equal(AdbPath, command.Executable);
        Assert.Equal(new[] { "-s", Serial, "reboot", "edl" }, command.Arguments);
        Assert.Equal(TimeSpan.FromSeconds(10), command.Timeout);

        Assert.Same(android, result.AndroidIdentity);
        Assert.Equal(endpoint, result.Endpoint);
        Assert.Equal(BusSnHex, result.BusSerialHex);
        Assert.Equal(1, discovery.Calls);
    }

    [Fact]
    public async Task WaitForPresentAsync_explicit_g5_profile_returns_present_endpoint_without_any_command()
    {
        var profile = RequireProfile("g5-9008-y7005");
        Assert.True(profile.IsComplete);

        var endpoint = Endpoint();
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { endpoint } });
        var entry = CreateEntry(runner, discovery);
        var android = CreateAndroid(model: G5Model, displayId: G5ActualDisplayId);

        var result = await entry.WaitForPresentAsync(android, profile);

        Assert.Same(android, result.AndroidIdentity);
        Assert.Equal(endpoint, result.Endpoint);
        Assert.Equal(BusSnHex, result.BusSerialHex);
        Assert.Equal(1, discovery.Calls);
        Assert.Empty(runner.Commands);
    }

    [Fact]
    public async Task EnterAsync_null_profile_is_rejected_before_runner_or_discovery()
    {
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { Endpoint() } });
        var entry = CreateEntry(runner, discovery);

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => entry.EnterAsync(CreateAndroid(), (EdlDeviceProfile)null!));

        Assert.Empty(runner.Commands);
        Assert.Equal(0, discovery.Calls);
    }

    [Fact]
    public async Task WaitForPresentAsync_null_profile_is_rejected_before_any_io()
    {
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { Endpoint() } });
        var entry = CreateEntry(runner, discovery);

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => entry.WaitForPresentAsync(CreateAndroid(), (EdlDeviceProfile)null!));

        Assert.Empty(runner.Commands);
        Assert.Equal(0, discovery.Calls);
    }

    [Fact]
    public async Task EnterAsync_explicit_default_profile_refuses_another_model_before_io()
    {
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { Endpoint() } });
        var entry = CreateEntry(runner, discovery);
        var android = CreateAndroid(model: "TB323FU", displayId: MaintenanceProfiles.AndroidBuild);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => entry.EnterAsync(android, EdlDeviceProfiles.Default));

        Assert.Empty(runner.Commands);
        Assert.Equal(0, discovery.Calls);
    }

    [Fact]
    public async Task WaitForPresentAsync_explicit_default_profile_refuses_another_model_before_any_io()
    {
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { Endpoint() } });
        var entry = CreateEntry(runner, discovery);
        var android = CreateAndroid(model: "TB323FU", displayId: MaintenanceProfiles.AndroidBuild);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => entry.WaitForPresentAsync(android, EdlDeviceProfiles.Default));

        Assert.Empty(runner.Commands);
        Assert.Equal(0, discovery.Calls);
    }

    [Theory]
    [InlineData("tb322fc")]
    [InlineData("TB322FC ")]
    [InlineData("TB322F")]
    [InlineData("TB322FCX")]
    public async Task Explicit_profile_refuses_noncanonical_model_even_though_lookup_accepts_the_query(
        string model)
    {
        var profile = EdlDeviceProfiles.FindByModel("tb322fc");
        Assert.NotNull(profile);

        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { Endpoint() } });
        var entry = CreateEntry(runner, discovery);
        var android = CreateAndroid(model: model);

        await Assert.ThrowsAsync<InvalidOperationException>(() => entry.EnterAsync(android, profile!));

        Assert.Empty(runner.Commands);
        Assert.Equal(0, discovery.Calls);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => entry.WaitForPresentAsync(android, profile!));

        Assert.Empty(runner.Commands);
        Assert.Equal(0, discovery.Calls);
    }

    [Theory]
    [InlineData("tb322fc_cn_open_user_q00041.1_w_zuxos_1.5.10.259_st_260611")]
    [InlineData("TB322FC_CN_OPEN_USER_Q00041.1_W_ZUXOS_1.5.10.259_ST_260611 ")]
    [InlineData("TB322FC_CN_OPEN_USER_Q00041.1_V_ZUXOS_1.1.11.120_ST_250727")]
    public async Task Explicit_default_profile_accepts_nonblank_actual_firmware_and_preserves_entry_semantics(
        string displayId)
    {
        var endpoint = Endpoint();
        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { endpoint }, new[] { endpoint } });
        var entry = CreateEntry(runner, discovery);
        // Synthetic snapshot data; only DisplayId mirrors a real observation.
        var android = new AndroidMaintenanceIdentity(
            new DeviceIdentity(Serial, MaintenanceProfiles.Model, BootloaderState.Locked)
            {
                Firmware = new FirmwareSnapshot(
                    displayId,
                    "Lenovo/TB322FC/TB322FC:15/TEST/FW01:user/release-keys",
                    "15",
                    "2025-07-01",
                    BootloaderState.Locked),
            },
            SocDecimal);

        var entered = await entry.EnterAsync(android, EdlDeviceProfiles.Default);

        var command = Assert.Single(runner.Commands);
        Assert.Equal(AdbPath, command.Executable);
        Assert.Equal(new[] { "-s", Serial, "reboot", "edl" }, command.Arguments);
        Assert.Same(android, entered.AndroidIdentity);
        Assert.Equal(endpoint, entered.Endpoint);
        Assert.Equal(BusSnHex, entered.BusSerialHex);
        Assert.Equal(displayId, entered.AndroidIdentity.Identity.Firmware!.DisplayId);
        Assert.Equal(1, discovery.Calls);

        var present = await entry.WaitForPresentAsync(android, EdlDeviceProfiles.Default);

        Assert.Same(android, present.AndroidIdentity);
        Assert.Equal(endpoint, present.Endpoint);
        Assert.Equal(BusSnHex, present.BusSerialHex);
        Assert.Equal(displayId, present.AndroidIdentity.Identity.Firmware!.DisplayId);
        Assert.Equal(2, discovery.Calls);
        Assert.Single(runner.Commands);
    }

    [Fact]
    public async Task Explicit_routes_leave_the_trusted_profiles_unchanged()
    {
        var defaultProfile = EdlDeviceProfiles.Default;
        var g5Profile = RequireProfile("g5-9008-y7005");

        var runner = EdlFakeCommandRunner.Succeeding();
        var discovery = new EdlFakeEndpointDiscovery(new[] { new[] { Endpoint() } });
        var entry = CreateEntry(runner, discovery);

        await entry.EnterAsync(CreateAndroid(), defaultProfile);

        Assert.Same(defaultProfile, EdlDeviceProfiles.FindById(defaultProfile.ProfileId));
        Assert.Same(g5Profile, EdlDeviceProfiles.FindById(g5Profile.ProfileId));
        Assert.True(defaultProfile.IsComplete);
        Assert.True(g5Profile.IsComplete);
        Assert.Equal("g4-9008-259", defaultProfile.ProfileId);
        Assert.Equal("0028D0E100400000", defaultProfile.FullHardwareId);
        Assert.Equal("FreedomInstaller.EdlTools.zip", defaultProfile.ArchiveLogicalName);
        Assert.Equal(new[] { "TB322FC", "TB323FU" }, EdlDeviceProfiles.Models);
    }
}
