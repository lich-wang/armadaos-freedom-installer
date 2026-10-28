using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// CORE-AUTO-01. Automatic 9008 profile detection and the endpoint-only read it reuses.
/// <para>
/// Only the transport boundary is faked (<see cref="E003FakeCommandRunner"/> and
/// <see cref="E003ScriptedEndpointDiscovery"/>); <see cref="GlobalEdlDetection"/> and
/// <see cref="GlobalEdlBinding"/> are the objects under test. No process, client binary or device is touched:
/// the client path is an empty placeholder file in a temporary directory. The toolchain fixture of the EDL
/// client tests is deliberately not used, because detection never reads or pins the client content.
/// </para>
/// </summary>
public sealed class GlobalEdlDetectionTests : IDisposable
{
    private const string G4HardwareId = "0028D0E100400000";
    private const string G5HardwareId = "002B40E100400000";
    private const string UnknownHardwareId = "0028D0E10040000B";

    private static readonly TimeSpan IdentifyTimeout = TimeSpan.FromSeconds(30);

    private readonly string _caseDirectory;
    private readonly string _clientPath;

    public GlobalEdlDetectionTests()
    {
        _caseDirectory = Path.Combine(
            Path.GetTempPath(),
            "core-auto-01-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_caseDirectory);

        _clientPath = Path.Combine(_caseDirectory, "edl-ng.exe");
        File.WriteAllBytes(_clientPath, Array.Empty<byte>());
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_caseDirectory, recursive: true);
        }
        catch (IOException)
        {
            // Best effort: the placeholder directory is owned by this test.
        }
        catch (UnauthorizedAccessException)
        {
            // Best effort: the placeholder directory is owned by this test.
        }
    }

    // ------------------------------------------------------------------ successful detection

    [Fact]
    public async Task Detect_G4_full_hardware_id_selects_the_builtin_g4_profile_with_one_exact_command()
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(E003EdlTestData.Endpoint());
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        runner.Enqueue(
            "[INFO] edl-ng identify started\n" +
            IdentityLine(serial: E003EdlTestData.BusSerialHex.ToLowerInvariant()) +
            "\n[INFO] client finished");

        EdlDeviceProfile profile = await GlobalEdlDetection.DetectAsync(_clientPath, runner, discovery);

        Assert.Same(EdlDeviceProfiles.FindByModel("TB322FC"), profile);
        Assert.Equal("g4-9008-259", profile.ProfileId);
        Assert.Equal(1, runner.CallCount);
        Assert.Equal(2, discovery.ReadCount);

        ProcessCommand command = runner.Commands[0];
        Assert.Equal(_clientPath, command.Executable);
        Assert.Equal(IdentifyTimeout, command.Timeout);
        Assert.Equal(_caseDirectory, command.WorkingDirectory);
        Assert.Equal(new[] { "--pid", "9008", "--loglevel", "Debug", "identify" }, command.Arguments);
        Assert.Equal(5, command.Arguments.Count);
        Assert.DoesNotContain("--loader", command.Arguments);
        Assert.DoesNotContain("--vid", command.Arguments);
        Assert.DoesNotContain("--memory", command.Arguments);
        Assert.DoesNotContain("printgpt", command.Arguments);
        Assert.DoesNotContain("read-sector", command.Arguments);
        Assert.DoesNotContain("write-sector", command.Arguments);
        Assert.DoesNotContain("reset", command.Arguments);
    }

    [Fact]
    public async Task Detect_G5_full_hardware_id_selects_the_builtin_g5_profile()
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(E003EdlTestData.Endpoint());
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        runner.Enqueue(IdentityLine(hwid: G5HardwareId));

        EdlDeviceProfile profile = await GlobalEdlDetection.DetectAsync(_clientPath, runner, discovery);

        Assert.Same(EdlDeviceProfiles.FindByModel("TB323FU"), profile);
        Assert.Equal("g5-9008-y7005", profile.ProfileId);
        Assert.Equal(G5HardwareId, profile.FullHardwareId, StringComparer.Ordinal);
        Assert.Equal(1, runner.CallCount);
        Assert.Equal(2, discovery.ReadCount);

        // The G5 profile still must not drag its loader into a detection command.
        Assert.DoesNotContain("--loader", runner.Commands[0].Arguments);
    }

    [Theory]
    [InlineData("0028d0e100400000")]
    [InlineData("0028D0E100400000")]
    public async Task Detect_hardware_id_case_is_accepted_and_mapped_to_the_g4_profile(string hwid)
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(E003EdlTestData.Endpoint());
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        runner.Enqueue(IdentityLine(hwid: hwid));

        EdlDeviceProfile profile = await GlobalEdlDetection.DetectAsync(_clientPath, runner, discovery);

        Assert.Same(EdlDeviceProfiles.Default, profile);
    }

    [Theory]
    [InlineData("c1d2e3f4")]
    [InlineData("C1D2E3F4")]
    public async Task Detect_expected_bus_serial_is_enforced_before_the_command(string expected)
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(E003EdlTestData.Endpoint());
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        runner.Enqueue(IdentityLine());

        EdlDeviceProfile profile = await GlobalEdlDetection.DetectAsync(
            _clientPath,
            runner,
            discovery,
            expected);

        Assert.Same(EdlDeviceProfiles.Default, profile);
        Assert.Equal(1, runner.CallCount);
        Assert.Equal(2, discovery.ReadCount);
    }

    [Fact]
    public async Task Detect_expected_bus_serial_mismatch_is_rejected_before_the_command()
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(E003EdlTestData.Endpoint());
        E003FakeCommandRunner runner = new E003FakeCommandRunner();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => GlobalEdlDetection.DetectAsync(_clientPath, runner, discovery, "DEADBEEF"));

        Assert.Equal(0, runner.CallCount);
        Assert.Equal(1, discovery.ReadCount);
    }

    [Theory]
    [InlineData("00000000")]
    [InlineData("FFFFFFFF")]
    [InlineData("E3E8547")]
    [InlineData("C1D2E3F40")]
    [InlineData("E3E8547Z")]
    public async Task Detect_malformed_expected_bus_serial_is_rejected_before_any_read(string expected)
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(E003EdlTestData.Endpoint());
        E003FakeCommandRunner runner = new E003FakeCommandRunner();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => GlobalEdlDetection.DetectAsync(_clientPath, runner, discovery, expected));

        Assert.Equal(0, runner.CallCount);
        Assert.Equal(0, discovery.ReadCount);
    }

    // ------------------------------------------------------------------ rejected identity lines

    [Theory]
    [InlineData("ARMADA_EDL_IDENTITY_V1 serial=00000000 hwid=0028D0E100400000")]
    [InlineData("ARMADA_EDL_IDENTITY_V1 serial=FFFFFFFF hwid=0028D0E100400000")]
    [InlineData("ARMADA_EDL_IDENTITY_V1 serial=E3E8547 hwid=0028D0E100400000")]
    [InlineData("ARMADA_EDL_IDENTITY_V1 serial=C1D2E3F40 hwid=0028D0E100400000")]
    [InlineData("ARMADA_EDL_IDENTITY_V1 serial=E3E8547Z hwid=0028D0E100400000")]
    [InlineData("ARMADA_EDL_IDENTITY_V1 serial= hwid=0028D0E100400000")]
    [InlineData("ARMADA_EDL_IDENTITY_V1 serial=C1D2E3F4 hwid=0000000000000000")]
    [InlineData("ARMADA_EDL_IDENTITY_V1 serial=C1D2E3F4 hwid=FFFFFFFFFFFFFFFF")]
    [InlineData("ARMADA_EDL_IDENTITY_V1 serial=C1D2E3F4 hwid=0028D0E10040000")]
    [InlineData("ARMADA_EDL_IDENTITY_V1 serial=C1D2E3F4 hwid=0028D0E1004000000")]
    [InlineData("ARMADA_EDL_IDENTITY_V1 serial=C1D2E3F4 hwid=0028D0E10040000Z")]
    [InlineData("ARMADA_EDL_IDENTITY_V1 serial=C1D2E3F4")]
    [InlineData("ARMADA_EDL_IDENTITY_V1 hwid=0028D0E100400000")]
    [InlineData("ARMADA_EDL_IDENTITY_V1 serial=C1D2E3F4  hwid=0028D0E100400000")]
    [InlineData("ARMADA_EDL_IDENTITY_V1  serial=C1D2E3F4 hwid=0028D0E100400000")]
    [InlineData("ARMADA_EDL_IDENTITY_V1 serial=C1D2E3F4 hwid=0028D0E100400000 ")]
    [InlineData("ARMADA_EDL_IDENTITY_V1 serial=C1D2E3F4 hwid=0028D0E100400000 extra")]
    [InlineData("xARMADA_EDL_IDENTITY_V1 serial=C1D2E3F4 hwid=0028D0E100400000")]
    [InlineData("[INFO] ARMADA_EDL_IDENTITY_V1 serial=C1D2E3F4 hwid=0028D0E100400000")]
    [InlineData("ARMADA_EDL_IDENTITY_V1 serial=C1D2E3F4 hwid=0028D0E100400000\rARMADA_EDL_IDENTITY_V1 serial=C1D2E3F4 hwid=0028D0E100400000")]
    public async Task Detect_malformed_or_lookalike_identity_line_is_rejected(string output)
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(E003EdlTestData.Endpoint());
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        runner.Enqueue(output);

        Exception error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => GlobalEdlDetection.DetectAsync(_clientPath, runner, discovery));

        Assert.False(string.IsNullOrWhiteSpace(error.Message));

        // Rejected before the endpoint is read again: a malformed report is never acted on.
        Assert.Equal(1, runner.CallCount);
        Assert.Equal(1, discovery.ReadCount);
    }

    [Fact]
    public async Task Detect_missing_marker_is_rejected_even_with_valid_values()
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(E003EdlTestData.Endpoint());
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        runner.Enqueue(
            "[INFO] Serial Number: C1D2E3F4\n" +
            "[INFO] HWID: 0028D0E100400000\n" +
            "[INFO] identify finished");

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => GlobalEdlDetection.DetectAsync(_clientPath, runner, discovery));

        Assert.Equal(1, runner.CallCount);
        Assert.Equal(1, discovery.ReadCount);
    }

    [Fact]
    public async Task Detect_duplicate_identical_identity_lines_are_rejected()
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(E003EdlTestData.Endpoint());
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        runner.Enqueue(IdentityLine() + "\n" + IdentityLine());

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => GlobalEdlDetection.DetectAsync(_clientPath, runner, discovery));

        Assert.Equal(1, runner.CallCount);
        Assert.Equal(1, discovery.ReadCount);
    }

    [Fact]
    public async Task Detect_marker_on_standard_error_only_is_rejected()
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(E003EdlTestData.Endpoint());
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        runner.Enqueue(
            "[INFO] identify finished",
            standardError: IdentityLine());

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => GlobalEdlDetection.DetectAsync(_clientPath, runner, discovery));

        Assert.Equal(1, runner.CallCount);
        Assert.Equal(1, discovery.ReadCount);
    }

    [Fact]
    public async Task Detect_nonzero_exit_is_rejected_even_with_a_valid_identity_line()
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(E003EdlTestData.Endpoint());
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        runner.Enqueue(IdentityLine(), exitCode: 3, standardError: "identify failed");

        Exception error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => GlobalEdlDetection.DetectAsync(_clientPath, runner, discovery));

        Assert.Contains("exited with code 3", error.Message, StringComparison.Ordinal);
        Assert.Equal(1, runner.CallCount);
        Assert.Equal(1, discovery.ReadCount);
    }

    // ------------------------------------------------------------------ rejected hardware mapping

    [Fact]
    public async Task Detect_unknown_hardware_id_is_rejected_without_a_fallback_profile()
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(E003EdlTestData.Endpoint());
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        runner.Enqueue(IdentityLine(hwid: UnknownHardwareId));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => GlobalEdlDetection.DetectAsync(_clientPath, runner, discovery));

        Assert.Equal(1, runner.CallCount);
        Assert.Equal(2, discovery.ReadCount);
    }

    [Fact]
    public async Task Detect_serial_mismatching_the_endpoint_is_rejected()
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(E003EdlTestData.Endpoint());
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        runner.Enqueue(IdentityLine(serial: "DEADBEEF"));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => GlobalEdlDetection.DetectAsync(_clientPath, runner, discovery));

        Assert.Equal(1, runner.CallCount);
        Assert.Equal(2, discovery.ReadCount);
    }

    // ------------------------------------------------------------------ transport changes around the command

    [Fact]
    public async Task Detect_instance_change_during_the_command_is_rejected()
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(E003EdlTestData.Endpoint());
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        runner.Enqueue(
            IdentityLine(),
            sideEffect: _ => discovery.Endpoints = new[]
            {
                E003EdlTestData.Endpoint(instanceId: E003EdlTestData.OtherInstanceId),
            });

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => GlobalEdlDetection.DetectAsync(_clientPath, runner, discovery));

        Assert.Equal(1, runner.CallCount);
        Assert.Equal(2, discovery.ReadCount);
    }

    [Fact]
    public async Task Detect_bus_serial_change_during_the_command_is_rejected()
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(E003EdlTestData.Endpoint());
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        runner.Enqueue(
            IdentityLine(),
            sideEffect: _ => discovery.Endpoints = new[]
            {
                E003EdlTestData.Endpoint(description: "QUSB_BULK_CID:045A_SN:DEADBEEF"),
            });

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => GlobalEdlDetection.DetectAsync(_clientPath, runner, discovery));

        Assert.Equal(1, runner.CallCount);
        Assert.Equal(2, discovery.ReadCount);
    }

    [Fact]
    public async Task Detect_a_second_device_appearing_during_the_command_is_rejected()
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(E003EdlTestData.Endpoint());
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        runner.Enqueue(
            IdentityLine(),
            sideEffect: _ => discovery.Endpoints = new[]
            {
                E003EdlTestData.Endpoint(),
                E003EdlTestData.Endpoint(instanceId: E003EdlTestData.OtherInstanceId),
            });

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => GlobalEdlDetection.DetectAsync(_clientPath, runner, discovery));

        Assert.Equal(1, runner.CallCount);
        Assert.Equal(2, discovery.ReadCount);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    public async Task Detect_ambiguous_or_absent_device_before_the_command_runs_nothing(int endpoints)
    {
        EdlEndpoint[] present = endpoints switch
        {
            0 => Array.Empty<EdlEndpoint>(),
            2 => new[]
            {
                E003EdlTestData.Endpoint(),
                E003EdlTestData.Endpoint(instanceId: E003EdlTestData.OtherInstanceId),
            },
            _ => throw new ArgumentOutOfRangeException(nameof(endpoints)),
        };

        E003ScriptedEndpointDiscovery discovery = Discovery(present);
        E003FakeCommandRunner runner = new E003FakeCommandRunner();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => GlobalEdlDetection.DetectAsync(_clientPath, runner, discovery));

        Assert.Equal(0, runner.CallCount);
        Assert.Equal(1, discovery.ReadCount);
    }

    [Theory]
    [InlineData("QUSB_BULK_CID:045A_SN:00000000")]
    [InlineData("QUSB_BULK_CID:045A_SN:FFFFFFFF")]
    [InlineData("QUSB_BULK_CID:045A_SN:E3E8547")]
    [InlineData("QUSB_BULK_CID:045A_SN:E3E8547Z")]
    [InlineData("QUSB_BULK_CID:045A_SN:C1D2E3F4_SN:C1D2E3F4")]
    public async Task Detect_unusable_bus_serial_before_the_command_runs_nothing(string description)
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(
            E003EdlTestData.Endpoint(description: description));
        E003FakeCommandRunner runner = new E003FakeCommandRunner();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => GlobalEdlDetection.DetectAsync(_clientPath, runner, discovery));

        Assert.Equal(0, runner.CallCount);
        Assert.Equal(1, discovery.ReadCount);
    }

    [Fact]
    public async Task Detect_conflicting_duplicate_interface_serials_before_the_command_runs_nothing()
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(
            E003EdlTestData.Endpoint(),
            E003EdlTestData.Endpoint(description: "QUSB_BULK_CID:045A_SN:DEADBEEF"));
        E003FakeCommandRunner runner = new E003FakeCommandRunner();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => GlobalEdlDetection.DetectAsync(_clientPath, runner, discovery));

        Assert.Equal(0, runner.CallCount);
        Assert.Equal(1, discovery.ReadCount);
    }

    // ------------------------------------------------------------------ client path and cancellation

    [Fact]
    public async Task Detect_missing_client_file_is_rejected_before_any_read_or_run()
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(E003EdlTestData.Endpoint());
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        string missing = Path.Combine(_caseDirectory, "absent.exe");

        await Assert.ThrowsAsync<FileNotFoundException>(
            () => GlobalEdlDetection.DetectAsync(missing, runner, discovery));

        Assert.Equal(0, runner.CallCount);
        Assert.Equal(0, discovery.ReadCount);
    }

    [Fact]
    public async Task Detect_relative_client_path_is_rejected_before_any_read_or_run()
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(E003EdlTestData.Endpoint());
        E003FakeCommandRunner runner = new E003FakeCommandRunner();

        await Assert.ThrowsAsync<ArgumentException>(
            () => GlobalEdlDetection.DetectAsync("edl-ng.exe", runner, discovery));

        Assert.Equal(0, runner.CallCount);
        Assert.Equal(0, discovery.ReadCount);
    }

    [Fact]
    public async Task Detect_null_discovery_is_rejected()
    {
        E003FakeCommandRunner runner = new E003FakeCommandRunner();

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => GlobalEdlDetection.DetectAsync(_clientPath, runner, null!));

        Assert.Equal(0, runner.CallCount);
    }

    [Fact]
    public async Task Detect_cancelled_token_is_rejected_before_any_read_or_run()
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(E003EdlTestData.Endpoint());
        E003FakeCommandRunner runner = new E003FakeCommandRunner();

        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => GlobalEdlDetection.DetectAsync(
                _clientPath,
                runner,
                discovery,
                expectedBusSerialHex: null,
                cancellationToken: cancellation.Token));

        Assert.Equal(0, runner.CallCount);
        Assert.Equal(0, discovery.ReadCount);
    }

    [Fact]
    public async Task Detect_cancellation_from_the_runner_propagates_unchanged()
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(E003EdlTestData.Endpoint());
        E003FakeCommandRunner runner = new E003FakeCommandRunner();
        runner.EnqueueFailure(new OperationCanceledException("cancelled by the caller"));

        Exception error = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => GlobalEdlDetection.DetectAsync(_clientPath, runner, discovery));

        Assert.IsNotType<InvalidOperationException>(error);
        Assert.Equal(1, runner.CallCount);
        Assert.Equal(1, discovery.ReadCount);
    }

    // ------------------------------------------------------------------ endpoint-only refactor

    [Fact]
    public void ReadEndpoint_returns_the_instance_and_normalized_serial_then_enforces_expectation()
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(E003EdlTestData.Endpoint());

        (EdlEndpoint endpoint, string serial) = GlobalEdlBinding.ReadEndpoint(discovery);

        Assert.Equal(E003EdlTestData.DeviceInstanceId, endpoint.DeviceInstanceId);
        Assert.Equal(E003EdlTestData.BusSerialHex, serial, StringComparer.Ordinal);
        Assert.Equal(1, discovery.ReadCount);

        Assert.Throws<InvalidOperationException>(
            () => GlobalEdlBinding.ReadEndpoint(discovery, "DEADBEEF"));
        Assert.Equal(2, discovery.ReadCount);

        // A malformed expectation is refused before the provider is asked at all.
        Assert.Throws<InvalidOperationException>(
            () => GlobalEdlBinding.ReadEndpoint(discovery, "E3E8547"));
        Assert.Equal(2, discovery.ReadCount);
    }

    [Fact]
    public void Attach_still_produces_the_candidate_offline_identity_from_the_same_read_endpoint()
    {
        E003ScriptedEndpointDiscovery discovery = Discovery(E003EdlTestData.Endpoint());

        EdlEntryResult binding = GlobalEdlBinding.Attach(EdlDeviceProfiles.Default, discovery);

        Assert.Null(binding.AndroidIdentity);
        Assert.Equal(E003EdlTestData.BusSerialHex, binding.BusSerialHex, StringComparer.Ordinal);
        Assert.Equal(E003EdlTestData.DeviceInstanceId, binding.Endpoint.DeviceInstanceId);
        Assert.Equal(1, discovery.ReadCount);

        GlobalEdlIdentity offline = Assert.IsType<GlobalEdlIdentity>(binding.OfflineIdentity);
        Assert.Equal(EdlDeviceProfiles.Default.ProfileId, offline.ProfileId);
        Assert.Equal(EdlDeviceProfiles.Default.Model, offline.Model);
        Assert.Equal(G4HardwareId, offline.HardwareId, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(E003EdlTestData.BusSerialHex, offline.BusSerialHex, StringComparer.Ordinal);
        Assert.Null(offline.AndroidSerial);
        Assert.Null(offline.FirmwareDisplayId);
    }

    // ------------------------------------------------------------------ helpers

    private static E003ScriptedEndpointDiscovery Discovery(params EdlEndpoint[] endpoints) =>
        new() { Endpoints = endpoints };

    /// <summary>
    /// The reviewed single-line identity protocol, interleaved with ordinary tool log lines by the caller
    /// where that matters.
    /// </summary>
    private static string IdentityLine(
        string serial = E003EdlTestData.BusSerialHex,
        string hwid = G4HardwareId) =>
        "ARMADA_EDL_IDENTITY_V1 serial=" + serial + " hwid=" + hwid;
}
