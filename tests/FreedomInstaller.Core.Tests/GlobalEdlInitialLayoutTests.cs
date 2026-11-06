using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// The per-model initial-layout contract the read-only global backup checks before it captures anything. The
/// six GPTs come from the synthetic <see cref="GlobalEdlTestDevice"/> (default G4 layout, the G5 layout, and the
/// optional TB710FU layout without lenovocust / lenovoraw / efisp); no toolchain, archive or device is involved.
/// </summary>
public sealed class GlobalEdlInitialLayoutTests
{
    [Fact]
    public void Tb710fu_layout_satisfies_the_tb710fu_contract()
    {
        Validate(Tables(new GlobalEdlTestDevice(tb710fu: true)), "TB710FU");
    }

    [Fact]
    public void G4_and_G5_layouts_still_satisfy_their_own_contracts()
    {
        Validate(Tables(new GlobalEdlTestDevice()), "TB322FC");
        Validate(Tables(new GlobalEdlTestDevice(gen5: true)), "TB323FU");
    }

    [Fact]
    public void Tb710fu_layout_does_not_satisfy_the_g4_contract()
    {
        // TB322FC requires lenovocust / lenovoraw, which the TB710FU layout does not carry.
        Assert.IsType<InvalidDataException>(
            Capture(Tables(new GlobalEdlTestDevice(tb710fu: true)), "TB322FC"));
    }

    [Fact]
    public void G5_layout_does_not_satisfy_the_tb710fu_contract()
    {
        // TB710FU requires proinfo / lenovolock, which the G5 layout does not carry.
        Assert.IsType<InvalidDataException>(
            Capture(Tables(new GlobalEdlTestDevice(gen5: true)), "TB710FU"));
    }

    [Theory]
    [InlineData("tb710fu")]
    [InlineData(" TB710FU")]
    [InlineData("TB710F")]
    public void Tb710fu_contract_is_selected_only_by_the_exact_model(string model)
    {
        Assert.IsType<InvalidDataException>(Capture(Tables(new GlobalEdlTestDevice(tb710fu: true)), model));
    }

    private static Dictionary<int, GptTable> Tables(GlobalEdlTestDevice device)
    {
        var tables = new Dictionary<int, GptTable>();
        foreach ((int lun, byte[] disk) in device.Disks)
        {
            // The whole synthetic disk is both fragments: primary from LBA 0, backup ending at the disk end.
            tables[lun] = OriginalGptImporter.Parse(disk, disk, GlobalEdlTestDevice.SectorSize, disk.LongLength);
        }

        return tables;
    }

    private static void Validate(IReadOnlyDictionary<int, GptTable> tables, string model)
    {
        Exception? failure = Capture(tables, model);
        Assert.True(failure is null, failure?.ToString());
    }

    private static Exception? Capture(IReadOnlyDictionary<int, GptTable> tables, string model)
    {
        MethodInfo method = typeof(GlobalEdlBackup).GetMethod(
            "ValidateInitialLayout",
            BindingFlags.Static | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("GlobalEdlBackup.ValidateInitialLayout was not found.");

        try
        {
            method.Invoke(null, new object?[] { tables, model });
            return null;
        }
        catch (TargetInvocationException wrapped) when (wrapped.InnerException is not null)
        {
            return wrapped.InnerException;
        }
    }
}
