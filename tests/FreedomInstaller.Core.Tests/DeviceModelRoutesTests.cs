using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// The fail-closed write gate of a model that is registered only for identification, its 9008 tool profile and
/// read-only validation (today exactly TB710FU). The gate must hold back every casing of TB710FU, must never
/// throw for TB322FC / TB323FU, and the write entry points that can be reached without a device must refuse a
/// TB710FU input with the stable route-pending code before any other work.
/// </summary>
public sealed class DeviceModelRoutesTests
{
    private const string Serial = "HA1B2C3D4";
    private const string SocSerial = "0x1234ABCD";

    // ---------------------------------------------------------------- predicate and throw matrix

    [Theory]
    [InlineData("TB710FU")]
    [InlineData("tb710fu")]
    [InlineData("Tb710Fu")]
    public void Tb710fu_in_any_casing_is_route_pending_and_throws(string model)
    {
        Assert.True(DeviceModelRoutes.IsWriteRoutePending(model));

        var failure = Assert.Throws<InvalidOperationException>(() => DeviceModelRoutes.RequireWriteRoute(model));
        Assert.StartsWith(DeviceModelRoutes.RoutePendingCode + ":", failure.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("TB322FC")]
    [InlineData("TB323FU")]
    [InlineData("tb322fc")]
    [InlineData("tb323fu")]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(" TB710FU")]
    [InlineData("TB710FU ")]
    [InlineData("TB710F")]
    [InlineData("TB710FUX")]
    [InlineData("Lenovo TB710FU")]
    [InlineData("25091RP04C")]
    public void Every_other_value_is_left_to_the_existing_model_checks(string? model)
    {
        // Nothing is trimmed or normalised here: only an exact (case-insensitive) TB710FU is held back, and
        // the gate never throws for G4 / G5 or for values the existing exact checks already refuse.
        Assert.False(DeviceModelRoutes.IsWriteRoutePending(model));
        DeviceModelRoutes.RequireWriteRoute(model);
    }

    [Fact]
    public void Constants_name_the_model_and_the_stable_code()
    {
        Assert.Equal("TB710FU", DeviceModelRoutes.Tb710fuModel);
        Assert.Equal("MODEL_ROUTE_PENDING", DeviceModelRoutes.RoutePendingCode);
        Assert.Contains(DeviceModelRoutes.Tb710fuModel, EdlDeviceProfiles.Models);
    }

    // ---------------------------------------------------------------- direct install entry

    [Fact]
    public void Route_refusal_is_recognised_only_by_its_exact_prefix()
    {
        var refusal = Assert.Throws<InvalidOperationException>(() => DeviceModelRoutes.RequireWriteRoute("TB710FU"));
        Assert.True(DeviceModelRoutes.IsRouteRefusal(refusal));
        Assert.DoesNotContain("PR", refusal.Message, StringComparison.Ordinal);

        Assert.False(DeviceModelRoutes.IsRouteRefusal(null));
        Assert.False(DeviceModelRoutes.IsRouteRefusal(new InvalidOperationException("other failure")));
        Assert.False(DeviceModelRoutes.IsRouteRefusal(
            new InvalidOperationException("x " + DeviceModelRoutes.RoutePendingCode + ": not at the start")));
        Assert.False(DeviceModelRoutes.IsRouteRefusal(
            new InvalidDataException(DeviceModelRoutes.RoutePendingCode + ": wrong exception type")));
    }

    [Fact]
    public void Direct_install_profile_gate_lets_tb710fu_through_the_open_install_route()
    {
        Assert.False(DeviceModelRoutes.IsInstallRoutePending("TB710FU"));
        DeviceModelRoutes.RequireInstallRoute("TB710FU");

        var failure = InvokeRequireDirectDeviceProfile(Check("TB710FU", "TB710FU_SYNTHETIC_ACTUAL_FIRMWARE"));

        // The install route is open; the remaining write routes stay pending.
        Assert.Null(failure);
        Assert.True(DeviceModelRoutes.IsWriteRoutePending("TB710FU"));
    }

    [Fact]
    public void Direct_install_profile_gate_still_passes_a_supported_g4_identity()
    {
        // Control: the new gate sits in front of the unchanged profile selection and lets G4 through.
        Assert.Null(InvokeRequireDirectDeviceProfile(Check("TB322FC", MaintenanceProfiles.AndroidBuild)));
    }

    [Fact]
    public void Direct_install_profile_gate_keeps_the_existing_refusal_for_an_unknown_model()
    {
        var failure = InvokeRequireDirectDeviceProfile(Check("TB999XX", "SYNTHETIC"));

        var refusal = Assert.IsType<InvalidOperationException>(failure);
        Assert.DoesNotContain(DeviceModelRoutes.RoutePendingCode, refusal.Message, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- boot maintenance historical identity

    [Fact]
    public async Task Historical_identity_of_a_tb710fu_backup_is_refused_once_its_profile_is_resolved()
    {
        using var root = new TempDirectory();
        WriteBackupManifest(root.Path, "{\"profile\":{\"profileId\":\"tb710fu-9008-495\"}}");

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(
            () => BootMaintenanceBackend.ReadHistoricalIdentityAsync(root.Path));

        Assert.StartsWith(DeviceModelRoutes.RoutePendingCode + ":", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Historical_identity_of_a_g4_backup_passes_the_gate_and_fails_later_on_the_partial_manifest()
    {
        // Control: the same partial manifest naming the G4 profile is refused by the existing parser, not by
        // the route gate.
        using var root = new TempDirectory();
        WriteBackupManifest(root.Path, "{\"profile\":{\"profileId\":\"g4-9008-259\"}}");

        var failure = await Assert.ThrowsAnyAsync<Exception>(
            () => BootMaintenanceBackend.ReadHistoricalIdentityAsync(root.Path));

        Assert.DoesNotContain(DeviceModelRoutes.RoutePendingCode, failure.Message, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- helpers

    private static InternalDeviceCheckResult Check(string model, string displayId)
    {
        var identity = new DeviceIdentity(Serial, model, BootloaderState.Unknown)
        {
            Firmware = new FirmwareSnapshot(displayId, null, null, null, BootloaderState.Unknown),
        };

        var constructor = typeof(InternalDeviceCheckResult).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            new[]
            {
                typeof(AndroidMaintenanceIdentity),
                typeof(string),
                typeof(string),
                typeof(BootloaderState),
                typeof(OtaUpdateState),
                typeof(AndroidReturnState),
                typeof(bool),
                typeof(InternalDeviceCheckStage?),
                typeof(string),
                typeof(string),
            },
            modifiers: null)
            ?? throw new InvalidOperationException(
                "InternalDeviceCheckResult no longer exposes the ten-parameter internal constructor.");

        return (InternalDeviceCheckResult)constructor.Invoke(new object?[]
        {
            new AndroidMaintenanceIdentity(identity, SocSerial),
            Serial,
            "fixture-product",
            BootloaderState.Locked,
            OtaUpdateState.Completed,
            AndroidReturnState.Verified,
            false,
            null,
            null,
            "a",
        });
    }

    /// <summary>Runs the private gate and returns the exception it threw, or null when it passed.</summary>
    private static Exception? InvokeRequireDirectDeviceProfile(InternalDeviceCheckResult check)
    {
        MethodInfo method = typeof(InternalInstallBackend).GetMethod(
            "RequireDirectDeviceProfile",
            BindingFlags.Static | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("InternalInstallBackend.RequireDirectDeviceProfile was not found.");

        try
        {
            method.Invoke(null, new object?[] { check });
            return null;
        }
        catch (TargetInvocationException wrapped) when (wrapped.InnerException is not null)
        {
            return wrapped.InnerException;
        }
    }

    private static void WriteBackupManifest(string directory, string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        string manifest = Path.Combine(directory, "backup-manifest.json");
        File.WriteAllBytes(manifest, bytes);
        File.WriteAllText(manifest + ".sha256", Convert.ToHexString(SHA256.HashData(bytes)) + "\n");
    }

    private sealed class TempDirectory : IDisposable
    {
        public TempDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(), "tb710fu-route-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
