using System;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// G5P1A RED contract: the trusted G5 profile is complete, firmware-independent and admits the
/// currently installed build as well as any other non-blank synthetic build. Identity values here are
/// synthetic metadata only; no device, loader or partition bytes are touched.
/// </summary>
public sealed class Gen5FirmwareIndependentProfileTests
{
    private const string ActualFirmware =
        "TB323FU_CN_OPEN_USER_Q00020.0_A16_ZUXOS_2.0.11.043_ST_260309";

    private static DeviceIdentity Identity(string model, string build) =>
        new DeviceIdentity("SYNTHETIC", model, BootloaderState.Locked)
        {
            Firmware = new FirmwareSnapshot(build, "synthetic/fingerprint", "16", "2026-03-05", BootloaderState.Locked)
        };

    private static EdlDeviceProfile G5()
    {
        var profile = EdlDeviceProfiles.FindByModel("TB323FU");
        Assert.NotNull(profile);
        return profile!;
    }

    [Fact]
    public void FindByModel_TB323FU_ExposesReviewedCompleteG5Profile()
    {
        var profile = G5();

        Assert.Equal("g5-9008-y7005", profile.ProfileId);
        Assert.Equal("TB323FU", profile.Model);
        Assert.True(profile.IsComplete);
        Assert.Equal("002B40E100400000", profile.FullHardwareId);
        Assert.Equal("FreedomInstaller.EdlTools.G5.zip", profile.ArchiveLogicalName);
        Assert.Equal(EdlLoaderKind.SaharaXml, profile.LoaderKind);
        Assert.Equal("tools/g5/qsahara_device_programmer.xml", profile.LoaderEntryPath);
        Assert.Equal(9, profile.Materials.Count);
        Assert.Equal(
            new[] { "QCTool-2026.3.21-1/lenovo/devprg_legion-y700-5" },
            profile.AllowedDisplayIds);
    }

    [Theory]
    [InlineData(ActualFirmware)]
    [InlineData("OTHER_BUILD")]
    public void SupportsIdentity_AdmitsAnyNonBlankFirmware(string build)
    {
        Assert.True(G5().SupportsIdentity(Identity("TB323FU", build)));
    }

    [Theory]
    [InlineData("TB323FU", "")]
    [InlineData("TB323FU", "   ")]
    [InlineData("TB322FC", ActualFirmware)]
    [InlineData("TB323FV", ActualFirmware)]
    public void SupportsIdentity_RejectsBlankFirmwareOrWrongModel(string model, string build)
    {
        Assert.False(G5().SupportsIdentity(Identity(model, build)));
    }

    [Fact]
    public void RequireComplete_CompleteG5ProfileSucceeds()
    {
        G5().RequireComplete();
    }
}
