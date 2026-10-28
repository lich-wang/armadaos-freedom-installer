using System;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class TfCardLayoutOverflowTests
{
    private static readonly Guid DiskGuid = new Guid("0A010203-0405-4607-8809-0A0B0C0D0E0F");
    private static readonly Guid BootGuid = new Guid("0B020304-0506-4708-990A-0B0C0D0E0F10");
    private static readonly Guid RootGuid = new Guid("0C030405-0607-480A-AA0B-0C0D0E0F1011");

    [Fact]
    public void BootImageSectorRoundingOverflowThrows()
    {
        const long cardBytes = 64L * 1024 * 1024 * 1024;
        const long bootBytes = long.MaxValue - 511 - 1048576;
        const long rootImageBytes = 32L * 1024 * 1024 * 1024;

        Assert.Throws<OverflowException>(() =>
            TfCardLayout.Create(
                cardBytes,
                512,
                bootBytes,
                rootImageBytes,
                rootImageBytes,
                DiskGuid,
                BootGuid,
                RootGuid));
    }

    [Fact]
    public void MinimumRootSectorRoundingOverflowThrows()
    {
        const long cardBytes = 64L * 1024 * 1024 * 1024;
        const long bootBytes = 1L * 1024 * 1024 * 1024;
        const long rootImageBytes = 32L * 1024 * 1024 * 1024;

        Assert.Throws<OverflowException>(() =>
            TfCardLayout.Create(
                cardBytes,
                512,
                bootBytes,
                rootImageBytes,
                long.MaxValue,
                DiskGuid,
                BootGuid,
                RootGuid));
    }
}
