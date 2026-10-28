using System;
using System.Reflection;
using System.Runtime.ExceptionServices;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Focused span tests for the direct EDL raw write view
/// <c>InternalInstallBackend.CreateDirectRawWriteRegion</c>.
/// <para>
/// These tests drive only the pure metadata helper through narrow reflection: the helper and the internal
/// <see cref="GptPartition"/> constructor. Every path is a fake metadata path, so nothing here opens a file,
/// hashes bytes, talks to a device or proves that any source image, package or result is valid or ready.
/// </para>
/// <para>
/// The actual flow properties - the fixed write order, the pending acknowledgement until the full readback,
/// zero RAM work, exactly one reset and the whole Android handoff - are deliberately NOT tested here. They
/// stay untested until the host provides the real factory (native builder) fixture, and are not replaced by
/// source-text assertions or a fake-ready shortcut.
/// </para>
/// </summary>
public sealed class InternalInstallDirectExecutionSpanTests
{
    private const string ImageSha = "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90";

    private const string Role = "linux_boot";

    // ------------------------------------------------------------------ actual image span

    [Fact]
    public void Short_512_byte_image_uses_its_actual_sector_count_not_the_partition()
    {
        GptPartition target = NewPartition(startSector: 2048, sectorCount: 4096);
        var geometry = new EdlGeometry(0, 512, 1_000_000);
        var raw = new VerifiedEdlFile(@"C:\evidence\linux-boot.raw", 1536, ImageSha);

        InternalArtifactRegion region = CreateRegion(target, geometry, raw);

        Assert.Equal(Role, region.Role, StringComparer.Ordinal);
        Assert.Equal(0, region.Lun);
        Assert.Equal(2048L, region.StartSector);
        Assert.Equal(3L, region.SectorCount);
        Assert.Equal(512, region.SectorSize);
        Assert.Equal(raw.Path, region.FilePath, StringComparer.Ordinal);
        Assert.Equal(1536L, region.Length);
        Assert.Equal(ImageSha, region.Sha256, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void Short_4096_byte_image_uses_its_actual_sector_count_not_the_partition()
    {
        GptPartition target = NewPartition(startSector: 34, sectorCount: 100_000);
        var geometry = new EdlGeometry(0, 4096, 4_000_000);
        var raw = new VerifiedEdlFile(@"C:\evidence\linux-root.raw", 8192, ImageSha);

        InternalArtifactRegion region = CreateRegion(target, geometry, raw);

        Assert.Equal(2L, region.SectorCount);
        Assert.Equal(4096, region.SectorSize);
        Assert.Equal(8192L, region.Length);
        Assert.Equal(34L, region.StartSector);
    }

    [Fact]
    public void An_image_that_exactly_fills_the_target_is_allowed()
    {
        GptPartition target = NewPartition(startSector: 100, sectorCount: 3);
        var geometry = new EdlGeometry(0, 512, 10_000);
        var raw = new VerifiedEdlFile(@"C:\evidence\exact.raw", 1536, ImageSha);

        InternalArtifactRegion region = CreateRegion(target, geometry, raw);

        Assert.Equal(3L, region.SectorCount);
        Assert.Equal(target.SectorCount, region.SectorCount);
    }

    [Fact]
    public void An_image_longer_than_int_max_value_stays_a_64_bit_length()
    {
        const long ImageLength = 2_147_484_160L; // 4_194_305 sectors of 512 bytes.

        GptPartition target = NewPartition(startSector: 0, sectorCount: 4_194_305);
        var geometry = new EdlGeometry(0, 512, 10_000_000);
        var raw = new VerifiedEdlFile(@"C:\evidence\large.raw", ImageLength, ImageSha);

        InternalArtifactRegion region = CreateRegion(target, geometry, raw);

        Assert.Equal(4_194_305L, region.SectorCount);
        Assert.Equal(ImageLength, region.Length);
        Assert.True(region.Length > int.MaxValue);
    }

    // ------------------------------------------------------------------ refused image metadata

    [Fact]
    public void A_zero_length_image_is_refused()
    {
        GptPartition target = NewPartition(startSector: 2048, sectorCount: 4096);
        var geometry = new EdlGeometry(0, 512, 1_000_000);
        var raw = new VerifiedEdlFile(@"C:\evidence\empty.raw", 0, ImageSha);

        Assert.Throws<ArgumentException>(() => CreateRegion(target, geometry, raw));
    }

    [Fact]
    public void A_misaligned_image_is_refused()
    {
        GptPartition target = NewPartition(startSector: 2048, sectorCount: 4096);
        var geometry = new EdlGeometry(0, 512, 1_000_000);
        var raw = new VerifiedEdlFile(@"C:\evidence\misaligned.raw", 513, ImageSha);

        Assert.Throws<ArgumentException>(() => CreateRegion(target, geometry, raw));
    }

    [Fact]
    public void An_image_larger_than_the_target_is_refused()
    {
        GptPartition target = NewPartition(startSector: 2048, sectorCount: 3);
        var geometry = new EdlGeometry(0, 512, 1_000_000);
        var raw = new VerifiedEdlFile(@"C:\evidence\oversize.raw", 2048, ImageSha);

        Assert.Throws<ArgumentException>(() => CreateRegion(target, geometry, raw));
    }

    [Fact]
    public void A_blank_image_path_is_refused()
    {
        GptPartition target = NewPartition(startSector: 2048, sectorCount: 4096);
        var geometry = new EdlGeometry(0, 512, 1_000_000);
        var raw = new VerifiedEdlFile("  ", 1536, ImageSha);

        Assert.Throws<ArgumentException>(() => CreateRegion(target, geometry, raw));
    }

    [Fact]
    public void A_non_hexadecimal_image_sha_is_refused()
    {
        GptPartition target = NewPartition(startSector: 2048, sectorCount: 4096);
        var geometry = new EdlGeometry(0, 512, 1_000_000);
        var raw = new VerifiedEdlFile(@"C:\evidence\linux-boot.raw", 1536, new string('z', 64));

        Assert.Throws<ArgumentException>(() => CreateRegion(target, geometry, raw));
    }

    // ------------------------------------------------------------------ refused geometry and target

    [Fact]
    public void A_target_beyond_the_probed_geometry_is_refused()
    {
        GptPartition target = NewPartition(startSector: 999_000, sectorCount: 2_000);
        var geometry = new EdlGeometry(0, 512, 1_000_000);
        var raw = new VerifiedEdlFile(@"C:\evidence\linux-boot.raw", 512, ImageSha);

        Assert.Throws<ArgumentException>(() => CreateRegion(target, geometry, raw));
    }

    [Fact]
    public void A_sector_end_beyond_a_64_bit_address_is_refused_instead_of_wrapping()
    {
        GptPartition target = NewPartition(startSector: long.MaxValue - 1, sectorCount: 10);
        var geometry = new EdlGeometry(0, 512, long.MaxValue);
        var raw = new VerifiedEdlFile(@"C:\evidence\linux-boot.raw", 512, ImageSha);

        Assert.Throws<ArgumentException>(() => CreateRegion(target, geometry, raw));
    }

    [Fact]
    public void A_non_positive_geometry_sector_size_is_refused()
    {
        GptPartition target = NewPartition(startSector: 0, sectorCount: 10);
        var geometry = new EdlGeometry(0, 0, 1_000_000);
        var raw = new VerifiedEdlFile(@"C:\evidence\linux-boot.raw", 512, ImageSha);

        Assert.Throws<ArgumentException>(() => CreateRegion(target, geometry, raw));
    }

    [Fact]
    public void A_geometry_without_sectors_is_refused()
    {
        GptPartition target = NewPartition(startSector: 0, sectorCount: 10);
        var geometry = new EdlGeometry(0, 512, 0);
        var raw = new VerifiedEdlFile(@"C:\evidence\linux-boot.raw", 512, ImageSha);

        Assert.Throws<ArgumentException>(() => CreateRegion(target, geometry, raw));
    }

    [Fact]
    public void A_negative_target_start_sector_is_refused()
    {
        GptPartition target = NewPartition(startSector: -1, sectorCount: 10);
        var geometry = new EdlGeometry(0, 512, 1_000_000);
        var raw = new VerifiedEdlFile(@"C:\evidence\linux-boot.raw", 512, ImageSha);

        Assert.Throws<ArgumentException>(() => CreateRegion(target, geometry, raw));
    }

    [Fact]
    public void A_foreign_lun_is_refused()
    {
        GptPartition target = NewPartition(startSector: 0, sectorCount: 10);
        var geometry = new EdlGeometry(1, 512, 1_000_000);
        var raw = new VerifiedEdlFile(@"C:\evidence\linux-boot.raw", 512, ImageSha);

        Assert.Throws<ArgumentException>(() => CreateRegion(target, geometry, raw));
    }

    [Fact]
    public void A_blank_role_is_refused()
    {
        GptPartition target = NewPartition(startSector: 0, sectorCount: 10);
        var geometry = new EdlGeometry(0, 512, 1_000_000);
        var raw = new VerifiedEdlFile(@"C:\evidence\linux-boot.raw", 512, ImageSha);

        Assert.Throws<ArgumentException>(() => CreateRegion(target, geometry, raw, role: " "));
    }

    // ------------------------------------------------------------------ narrow reflection

    private static InternalArtifactRegion CreateRegion(
        GptPartition target,
        EdlGeometry geometry,
        VerifiedEdlFile raw,
        string role = Role)
    {
        MethodInfo method = typeof(InternalInstallBackend).GetMethod(
                "CreateDirectRawWriteRegion",
                BindingFlags.Static | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "The direct raw write view helper is missing from InternalInstallBackend.");

        try
        {
            return (InternalArtifactRegion)method.Invoke(null, new object[] { target, geometry, raw, role })!;
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }
    }

    private static GptPartition NewPartition(long startSector, long sectorCount)
    {
        ConstructorInfo? constructor = typeof(GptPartition).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            new[]
            {
                typeof(int), typeof(string), typeof(string), typeof(string),
                typeof(long), typeof(long), typeof(ulong),
            },
            modifiers: null);

        Assert.NotNull(constructor);

        return (GptPartition)constructor!.Invoke(new object[]
        {
            1,
            "linux_boot",
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
            startSector,
            sectorCount,
            0UL,
        });
    }
}
