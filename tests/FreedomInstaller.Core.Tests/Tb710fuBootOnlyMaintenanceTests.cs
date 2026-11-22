using System;
using System.Collections.Generic;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// The AOSP-preserving boot-only maintenance route of TB710FU: its locked chain keeps the original root vbmeta and an
/// RSA2048 vbmeta_system, so an AfterUpdate plan may write boot_a / boot_b and nothing else.
/// </summary>
public sealed class Tb710fuBootOnlyMaintenanceTests
{
    private static BootMaintenanceBackend.PlannedRegion Region(string role, string? slot, bool write) =>
        new(role, slot, 0, 1024, 16, 16 * 4096, new string('a', 64),
            write ? "/candidate/" + role : null, write ? new string('b', 64) : null);

    [Fact]
    public void A_boot_only_plan_passes()
    {
        BootMaintenanceBackend.RequireBootOnlyAfterPlan(new[]
        {
            Region("boot_b", "b", write: true),
            Region("boot_a", "a", write: true),
        });
    }

    [Fact]
    public void Unchanged_metadata_regions_may_be_listed_but_not_written()
    {
        // A region whose candidate equals the current bytes is planned without a write; it is not a metadata write.
        BootMaintenanceBackend.RequireBootOnlyAfterPlan(new[]
        {
            Region("boot_a", "a", write: true),
            Region("vbmeta_a", "a", write: false),
        });
    }

    [Theory]
    [InlineData("vbmeta_a", "a")]
    [InlineData("vbmeta_b", "b")]
    [InlineData("vbmeta_system_a", "a")]
    [InlineData("vbmeta_system_b", "b")]
    [InlineData("recovery_a", "a")]
    [InlineData("recovery_b", "b")]
    [InlineData("efisp", null)]
    public void Any_written_role_besides_boot_is_refused(string role, string? slot)
    {
        var failure = Assert.Throws<InvalidOperationException>(() =>
            BootMaintenanceBackend.RequireBootOnlyAfterPlan(new[]
            {
                Region("boot_a", "a", write: true),
                Region(role, slot, write: true),
            }));

        Assert.StartsWith("boot-maintenance-plan-incomplete:", failure.Message, StringComparison.Ordinal);
        Assert.Contains(role, failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void The_trust_mode_is_a_new_value_that_keeps_the_existing_ones()
    {
        // Appended: persisted receipts that store the existing names and values keep their meaning.
        Assert.Equal(0, (int)BootMaintenanceBootTrust.StockOriginal);
        Assert.Equal(1, (int)BootMaintenanceBootTrust.AospResigned);
        Assert.Equal(2, (int)BootMaintenanceBootTrust.GblPreserveOem);
        Assert.Equal(3, (int)BootMaintenanceBootTrust.AospPreserved);
    }

    [Theory]
    [InlineData("TB322FC", true)]
    [InlineData("TB323FU", true)]
    [InlineData("TB710FU", true)]
    [InlineData("tb710fu", false)]
    [InlineData("TB710FU ", false)]
    [InlineData("TB999XX", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void An_all_zero_misc_defers_to_the_gpt_slot_only_for_the_exact_qualcomm_models(string? model, bool expected)
    {
        // TB710FU's bootloader leaves the AOSP boot_control block zero, so every write route (install, boot
        // maintenance, uninstall) resolves its current slot from the GPT flags; anything else stays refused.
        Assert.Equal(expected, CurrentBootSlot.UsesQualcommGptSlot(model));
    }

    [Fact]
    public void The_profile_declares_the_boot_only_route_for_tb710fu_only()
    {
        Assert.Equal(EdlInstallBootTrust.AospPreservedBoot, EdlDeviceProfiles.FindByModel("TB710FU")!.InstallBootTrust);
        Assert.NotEqual(EdlInstallBootTrust.AospPreservedBoot, EdlDeviceProfiles.FindByModel("TB322FC")!.InstallBootTrust);
        Assert.NotEqual(EdlInstallBootTrust.AospPreservedBoot, EdlDeviceProfiles.FindByModel("TB323FU")!.InstallBootTrust);
    }
}
