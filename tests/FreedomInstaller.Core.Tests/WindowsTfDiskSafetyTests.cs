using System;
using System.Collections.Generic;
using System.Linq;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Real behavior tests for the pure safety policy the live Windows raw-card target calls before native IO.
/// Synthetic candidates/paths only — no real local device, no native call, no fake success.
/// </summary>
public sealed class WindowsTfDiskSafetyTests
{
    private const string SdBus = "SD";
    private const string MmcBus = "MMC";
    private const string UsbBus = "USB";
    private const string NvmeBus = "NVMe";
    private const string ScsiBus = "SCSI";

    private const string CardKey = "reader:USBSTOR\\DISK&VEN_TEST&PROD_SYNTHETIC\\0&SYNTH&0";

    // Synthetic device namespace paths only (never real local drives).
    private const string DiskInterfacePath = @"\\?\USBSTOR#disk&ven_synthetic&prod_card#synthetic-0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
    private const string VolumeInterfacePath = @"\\?\USBSTOR#disk&ven_synthetic&prod_card#synthetic-0#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}";
    private const string DriveLetterDevicePath = @"\\?\C:\users\public";
    private const string VolumeDevicePath = @"\\.\C:";
    private const string OrdinaryFilePath = @"D:\tmp\card.img";
    private const string UncFilePath = @"\\NAS\share\card.img";

    private const long CardBytes = 32L * 1024 * 1024 * 1024;

    private static TfCardCandidate Candidate(
        string? key = null,
        string? path = null,
        long sizeBytes = CardBytes,
        int sector = 512,
        string bus = SdBus,
        bool readOnly = false,
        bool isSystem = false,
        bool isOffline = false,
        string displayName = "SYNTHETIC CARD")
        => new(
            key ?? CardKey,
            path ?? DiskInterfacePath,
            displayName,
            sizeBytes,
            sector,
            bus,
            readOnly,
            isSystem,
            isOffline,
            Mounted: null,
            AndroidUsage: "unknown");
    private static List<TfCardCandidate> Fresh(params TfCardCandidate[] candidates) => new(candidates);

    // ---- selection: exact eligible matches succeed ----

    [Fact]
    public void Select_exact_eligible_usb_reader_card_with_disk_interface_path_succeeds()
    {
        var expected = Candidate(bus: UsbBus, path: DiskInterfacePath);

        var selected = WindowsTfDiskSafety.Select(expected, Fresh(Candidate(bus: UsbBus, path: DiskInterfacePath)));

        Assert.Equal(expected.Key, selected.Key);
        Assert.Equal(DiskInterfacePath, selected.Path);
    }

    [Theory]
    [InlineData(SdBus)]
    [InlineData(MmcBus)]
    [InlineData(UsbBus)]
    public void Select_accepts_each_exact_supported_bus(string bus)
    {
        var expected = Candidate(bus: bus);

        var selected = WindowsTfDiskSafety.Select(expected, Fresh(Candidate(bus: bus)));

        Assert.Equal(expected.Key, selected.Key);
    }

    [Fact]
    public void Select_accepts_disk_interface_path_from_get_disk()
    {
        var expected = Candidate(path: DiskInterfacePath, bus: UsbBus);

        var selected = WindowsTfDiskSafety.Select(expected, Fresh(expected));

        Assert.Equal(DiskInterfacePath, selected.Path);
    }

    [Fact]
    public void Select_accepts_device_namespace_physicaldrive_path()
    {
        const string devicePath = @"\\.\PhysicalDrive9";
        var expected = Candidate(path: devicePath, bus: UsbBus);

        var selected = WindowsTfDiskSafety.Select(expected, Fresh(expected));

        Assert.Equal(devicePath, selected.Path);
    }

    [Fact]
    public void Select_picks_expected_card_from_larger_inventory()
    {
        var expected = Candidate();
        var other = Candidate(key: "reader:OTHERSYNTH0", path: @"\\.\SYNTHETICPHYSICALDRIVE8", bus: UsbBus);

        var selected = WindowsTfDiskSafety.Select(expected, Fresh(other, expected));

        Assert.Equal(expected.Key, selected.Key);
    }

    // ---- selection: identity and presence changes refuse ----

    [Fact]
    public void Select_missing_candidate_refuses()
    {
        var expected = Candidate();
        var different = Candidate(key: "reader:DIFFERENTSYNTH");

        Assert.Throws<InvalidOperationException>(() => WindowsTfDiskSafety.Select(expected, Fresh(different)));
    }

    [Fact]
    public void Select_empty_inventory_refuses()
    {
        Assert.Throws<InvalidOperationException>(() => WindowsTfDiskSafety.Select(Candidate(), Fresh()));
    }

    [Fact]
    public void Select_changed_key_refuses()
    {
        var expected = Candidate();
        var fresh = Candidate(key: "reader:CHANGEDKEY");

        Assert.Throws<InvalidOperationException>(() => WindowsTfDiskSafety.Select(expected, Fresh(fresh)));
    }

    [Fact]
    public void Select_changed_path_refuses()
    {
        var expected = Candidate();
        var fresh = Candidate(path: @"\\.\SYNTHETICPHYSICALDRIVE7");

        Assert.Throws<InvalidOperationException>(() => WindowsTfDiskSafety.Select(expected, Fresh(fresh)));
    }

    [Fact]
    public void Select_changed_size_refuses()
    {
        var expected = Candidate();
        var fresh = Candidate(sizeBytes: CardBytes - 512);

        Assert.Throws<InvalidOperationException>(() => WindowsTfDiskSafety.Select(expected, Fresh(fresh)));
    }

    [Fact]
    public void Select_changed_sector_size_refuses()
    {
        var expected = Candidate();
        var fresh = Candidate(sector: 4096, sizeBytes: CardBytes);

        Assert.Throws<InvalidOperationException>(() => WindowsTfDiskSafety.Select(expected, Fresh(fresh)));
    }

    [Fact]
    public void Select_duplicate_identity_in_fresh_list_refuses()
    {
        var expected = Candidate();

        Assert.Throws<InvalidOperationException>(() => WindowsTfDiskSafety.Select(
            expected,
            Fresh(Candidate(), Candidate())));
    }

    // ---- selection: foreign source, dangerous paths, unsafe state, bad bus, bad geometry ----

    [Fact]
    public void Select_tablet_sourced_key_refuses_as_foreign_source()
    {
        Assert.Throws<ArgumentException>(() => WindowsTfDiskSafety.Select(
            Candidate(key: "tablet:SYNTH0"),
            Fresh()));
    }

    [Fact]
    public void Select_missing_reader_prefix_refuses()
    {
        Assert.Throws<ArgumentException>(() => WindowsTfDiskSafety.Select(
            Candidate(key: "SYNTH0"),
            Fresh()));
    }

    [Theory]
    [InlineData(VolumeInterfacePath)]
    [InlineData(VolumeDevicePath)]
    [InlineData(@"\\.\C:\file")]
    [InlineData(DiskInterfacePath + @"\file")]
    [InlineData(DriveLetterDevicePath)]
    [InlineData(OrdinaryFilePath)]
    [InlineData(UncFilePath)]
    [InlineData("")]
    [InlineData("   ")]
    public void Select_dangerous_ordinary_file_path_refuses(string path)
    {
        Assert.Throws<ArgumentException>(() => WindowsTfDiskSafety.Select(
            Candidate(path: path),
            Fresh(Candidate(path: path))));
    }

    [Theory]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(false, false, true)]
    public void Select_readonly_system_offline_refuses(bool readOnly, bool isSystem, bool isOffline)
    {
        Assert.Throws<InvalidOperationException>(() => WindowsTfDiskSafety.Select(
            Candidate(readOnly: readOnly, isSystem: isSystem, isOffline: isOffline),
            Fresh(Candidate(readOnly: readOnly, isSystem: isSystem, isOffline: isOffline))));
    }

    [Theory]
    [InlineData(NvmeBus)]
    [InlineData(ScsiBus)]
    [InlineData("")]
    [InlineData("USBSTOR")]
    [InlineData("  USB  ")]
    [InlineData("sdcard")]
    public void Select_bus_other_than_exact_sd_mmc_usb_refuses(string bus)
    {
        Assert.Throws<ArgumentException>(() => WindowsTfDiskSafety.Select(
            Candidate(bus: bus),
            Fresh(Candidate(bus: bus))));
    }

    [Theory]
    [InlineData(100, 512)]
    [InlineData(-1, 512)]
    [InlineData(CardBytes, 1024)]
    [InlineData(CardBytes + 1, 512)]
    [InlineData(0, 512)]
    public void Select_invalid_geometry_refuses(long sizeBytes, int sector)
    {
        Assert.Throws<ArgumentException>(() => WindowsTfDiskSafety.Select(
            Candidate(sizeBytes: sizeBytes, sector: sector),
            Fresh(Candidate(sizeBytes: sizeBytes, sector: sector))));
    }

    [Fact]
    public void Select_blank_display_name_refuses_as_blank_identity()
    {
        Assert.Throws<ArgumentException>(() => WindowsTfDiskSafety.Select(
            Candidate(displayName: "  "),
            Fresh(Candidate(displayName: "  "))));
    }

    // ---- protected disk numbers ----

    [Fact]
    public void RequireUnprotectedDisk_distinct_number_succeeds()
    {
        WindowsTfDiskSafety.RequireUnprotectedDisk(9, new[] { 0, 1, 2 });
    }

    [Fact]
    public void RequireUnprotectedDisk_selected_number_in_protected_list_refuses()
    {
        Assert.Throws<InvalidOperationException>(() => WindowsTfDiskSafety.RequireUnprotectedDisk(
            1,
            new[] { 0, 1, 2 }));
    }

    [Fact]
    public void RequireUnprotectedDisk_empty_protected_list_succeeds()
    {
        WindowsTfDiskSafety.RequireUnprotectedDisk(0, Array.Empty<int>());
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(-42)]
    public void RequireUnprotectedDisk_negative_selected_number_refuses(int diskNumber)
    {
        Assert.Throws<ArgumentException>(() => WindowsTfDiskSafety.RequireUnprotectedDisk(
            diskNumber,
            new[] { 0, 1 }));
    }

    [Fact]
    public void RequireUnprotectedDisk_negative_protected_number_refuses()
    {
        Assert.Throws<ArgumentException>(() => WindowsTfDiskSafety.RequireUnprotectedDisk(
            9,
            new[] { 0, -3, 1 }));
    }

    // ---- aligned ranges ----

    [Theory]
    [InlineData(0, 512)]
    [InlineData(512, 512)]
    [InlineData(1024L * 1024 * 1024, 4096)]
    [InlineData(8589934592L, 4096)]
    public void RequireAlignedRange_aligned_boundaries_succeed(long offset, int sector)
    {
        WindowsTfDiskSafety.RequireAlignedRange(CardBytes, sector, offset, sector);
    }

    [Fact]
    public void RequireAlignedRange_exact_end_boundary_succeeds()
    {
        WindowsTfDiskSafety.RequireAlignedRange(1024, 512, 512, 512);
    }

    [Theory]
    [InlineData(-512, 512)]
    [InlineData(256, 512)]
    [InlineData(1, 4096)]
    public void RequireAlignedRange_misaligned_or_negative_offset_refuses(long offset, int sector)
    {
        Assert.Throws<ArgumentException>(() =>
            WindowsTfDiskSafety.RequireAlignedRange(CardBytes, sector, offset, sector));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-512)]
    [InlineData(100)]
    [InlineData(511)]
    public void RequireAlignedRange_invalid_count_refuses(int count)
    {
        Assert.Throws<ArgumentException>(() =>
            WindowsTfDiskSafety.RequireAlignedRange(CardBytes, 512, 0, count));
    }

    [Fact]
    public void RequireAlignedRange_end_overrun_refuses()
    {
        Assert.Throws<ArgumentException>(() =>
            WindowsTfDiskSafety.RequireAlignedRange(1024, 512, 512, 1024));
    }

    [Fact]
    public void RequireAlignedRange_overflow_refuses()
    {
        Assert.Throws<ArgumentException>(() =>
            WindowsTfDiskSafety.RequireAlignedRange(long.MaxValue, 512, long.MaxValue - 511, 1024));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(100)]
    [InlineData(1023)]
    [InlineData(513)]
    public void RequireAlignedRange_invalid_sector_size_refuses(int sectorSize)
    {
        Assert.Throws<ArgumentException>(() =>
            WindowsTfDiskSafety.RequireAlignedRange(CardBytes, sectorSize, 0, 512));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void RequireAlignedRange_invalid_disk_bytes_refuses(long diskBytes)
    {
        Assert.Throws<ArgumentException>(() =>
            WindowsTfDiskSafety.RequireAlignedRange(diskBytes, 512, 0, 512));
    }

    // ---- integration with the real TfCardSupport reader parser ----

    [Fact]
    public void Select_via_real_reader_parser_inventory_selects_exact_card()
    {
        string readerJson = @"{""schemaVersion"":1,""source"":""reader"",""media"":["
            + @"{""key"":""SYNTH0"",""path"":""" + DiskInterfacePath.Replace(@"\", @"\\") + @""",""displayName"":""SYNTHETIC CARD"",""sizeBytes"":32000000000,""logicalSectorSize"":512,"
            + @"""mediumEvidence"":""USB"",""readOnly"":false,""isSystemDisk"":false,""isOffline"":false,""mounted"":null,""androidUsage"":""unknown""}"
            + @"]}";

        var fresh = TfCardSupport.ParseCandidates(readerJson, TfCardSource.Reader);
        var expected = fresh.Single();

        var selected = WindowsTfDiskSafety.Select(expected, fresh);

        Assert.Equal("reader:SYNTH0", selected.Key);
        Assert.Equal(DiskInterfacePath, selected.Path);
        Assert.Equal(32000000000, selected.SizeBytes);
        Assert.Equal(512, selected.LogicalSectorSize);
    }

    [Fact]
    public void Select_via_real_reader_parser_readonly_card_dropped_so_expected_refuses()
    {
        string readerJson = @"{""schemaVersion"":1,""source"":""reader"",""media"":["
            + @"{""key"":""SYNTH0"",""path"":""" + DiskInterfacePath.Replace(@"\", @"\\") + @""",""displayName"":""SYNTHETIC CARD"",""sizeBytes"":32000000000,""logicalSectorSize"":512,"
            + @"""mediumEvidence"":""USB"",""readOnly"":true,""isSystemDisk"":false,""isOffline"":false,""mounted"":null,""androidUsage"":""unknown""}"
            + @"]}";

        var fresh = TfCardSupport.ParseCandidates(readerJson, TfCardSource.Reader);

        Assert.Empty(fresh);
        Assert.Throws<InvalidOperationException>(() => WindowsTfDiskSafety.Select(
            Candidate(sizeBytes: 32000000000),
            fresh));
    }

    [Fact]
    public void Select_via_real_reader_parser_scsi_disk_dropped_so_expected_refuses()
    {
        string readerJson = @"{""schemaVersion"":1,""source"":""reader"",""media"":["
            + @"{""key"":""SYNTH9"",""path"":""" + DiskInterfacePath.Replace(@"\", @"\\") + @""",""displayName"":""SYNTHETIC DISK"",""sizeBytes"":32000000000,""logicalSectorSize"":512,"
            + @"""mediumEvidence"":""SCSI"",""readOnly"":false,""isSystemDisk"":false,""isOffline"":false,""mounted"":null,""androidUsage"":""unknown""}"
            + @"]}";

        var fresh = TfCardSupport.ParseCandidates(readerJson, TfCardSource.Reader);

        Assert.Empty(fresh);
        Assert.Throws<InvalidOperationException>(() => WindowsTfDiskSafety.Select(
            Candidate(sizeBytes: 32000000000),
            fresh));
    }
}
