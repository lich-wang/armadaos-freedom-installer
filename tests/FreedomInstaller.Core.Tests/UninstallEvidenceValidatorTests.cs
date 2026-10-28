using System;
using System.IO;
using System.Text;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Contract for <see cref="UninstallEvidenceValidator"/>. The "current" table is a literal sfdisk document in
/// the shape the device tooling really prints, and the "original" table is decoded from the raw GPT bytes of
/// <see cref="OriginalGptImporterTests"/>' fixture, so the whole path is exercised end to end without any
/// device, file or process. Tests that assert reading or validation behaviour are expected to fail with
/// <see cref="NotImplementedException"/> until the implementation lands.
/// </summary>
public sealed class UninstallEvidenceValidatorTests
{
    // --------------------------------------------------------------- reading sfdisk JSON

    [Fact]
    public void ReadCurrentSfdisk_RealLikeTable_KeepsDeviceUnitAndCanonicalAttributes()
    {
        var table = UninstallEvidenceValidator.ReadCurrentSfdisk(Sfdisk.Json(), GptFixture.DiskBytes4096);

        // The reporter's device node and its unit are what the write backend has to talk to.
        Assert.Equal("/dev/sda", table.DeviceId);
        Assert.Equal(4096, table.SectorSize);
        Assert.Equal(507_376_566_272L, table.DiskBytes);
        Assert.Equal("10BEF391-0EBA-9668-B82C-4E092F4C4467", table.DiskGuid);
        Assert.Equal(6L, table.FirstUsableSector);
        Assert.Equal(123_871_226L, table.LastUsableSector);
        Assert.Equal(4, table.Partitions.Count);
        Assert.False(string.IsNullOrWhiteSpace(table.SourceFingerprint));

        // "GUID:50,60" is two attribute bits, not two characters.
        var proinfo = GptFixture.Partition(table, 1);
        Assert.Equal((1UL << 50) | (1UL << 60), proinfo.Attributes);
        Assert.Equal("proinfo", proinfo.Name);
        Assert.Equal(6L, proinfo.StartSector);
        Assert.Equal(768L, proinfo.SectorCount);

        // No attrs key at all means "no attributes", not "unknown".
        Assert.Equal(0UL, GptFixture.Partition(table, 2).Attributes);
        Assert.Equal(5_972_392L, GptFixture.Partition(table, 2).StartSector);
        Assert.Equal(33_554_432L, GptFixture.Partition(table, 2).SectorCount);

        Assert.Equal("F7617F07-9D25-C653-DC40-E4F8C5816B6A", GptFixture.Partition(table, 3).PartUuid);
        Assert.Equal("C52E5589-00AB-799D-4253-F7A50A6E6191", GptFixture.Partition(table, 4).PartUuid);
    }

    [Fact]
    public void ReadCurrentSfdisk_AttributeOrderDoesNotChangeTheWord()
    {
        var ascending = UninstallEvidenceValidator.ReadCurrentSfdisk(
            Sfdisk.Json(proinfoAttrs: "GUID:50,60"), GptFixture.DiskBytes4096);
        var descending = UninstallEvidenceValidator.ReadCurrentSfdisk(
            Sfdisk.Json(proinfoAttrs: "GUID:60,50"), GptFixture.DiskBytes4096);

        Assert.Equal(
            GptFixture.Partition(ascending, 1).Attributes,
            GptFixture.Partition(descending, 1).Attributes);
    }

    [Theory]
    [InlineData("GUID:99")] // a GUID bit no GPT attribute defines
    [InlineData("GUID:50,99")]
    [InlineData("GUID:50,50")] // the same bit listed twice
    [InlineData("MadeUpFlag")]
    public void ReadCurrentSfdisk_RejectsAttributeTextItCannotMapExactly(string attrs)
    {
        // Unknown or repeated attribute names must reject the table: silently dropping them would let the
        // writer act on a layout whose flags it never saw.
        AssertInvalidData(() => UninstallEvidenceValidator.ReadCurrentSfdisk(
            Sfdisk.Json(proinfoAttrs: attrs), GptFixture.DiskBytes4096));
    }

    [Theory]
    [InlineData("not json at all")]
    [InlineData("{\"partitiontable\":{\"label\":\"dos\",\"id\":\"10BEF391-0EBA-9668-B82C-4E092F4C4467\",\"sectorsize\":4096}}")]
    public void ReadCurrentSfdisk_RejectsDocumentsThatAreNotAGptTable(string json)
    {
        AssertInvalidData(() => UninstallEvidenceValidator.ReadCurrentSfdisk(json, GptFixture.DiskBytes4096));
    }

    // ------------------------------------------------------------- accepted evidence

    [Fact]
    public void Validate_RealLikeLegacyGeometry_ReturnsRecordPlanAndKeepsCurrentAttributes()
    {
        var identity = Identity();
        var original = OriginalTable();
        var current = CurrentTable(Sfdisk.Json());

        var inputs = UninstallEvidenceValidator.Validate(identity, original, current, current.SourceFingerprint);

        Assert.Equal(identity, inputs.Identity);

        // The two tables keep their own provenance: the original stays the raw capture, the current one stays
        // the table the disk reported, and neither is swapped for the other.
        Assert.Equal(original.SourceFingerprint, inputs.OriginalTable.SourceFingerprint);
        Assert.Equal(current.SourceFingerprint, inputs.CurrentTable.SourceFingerprint);

        // The record names the CURRENT device node and the ORIGINAL userdata end; the two added partitions
        // are taken from the current table because only it carries their UUIDs.
        Assert.Equal("/dev/sda", inputs.Record.DeviceId);
        Assert.Equal("7F6876B2-2CE6-51A0-505D-A7865864D1BD", inputs.Record.UserdataPartUuid);
        Assert.Equal("F7617F07-9D25-C653-DC40-E4F8C5816B6A", inputs.Record.LinuxBootPartUuid);
        Assert.Equal("C52E5589-00AB-799D-4253-F7A50A6E6191", inputs.Record.LinuxRootPartUuid);
        Assert.Equal(123_871_227L, inputs.Record.OriginalUserdataEndSector);

        Assert.Equal(5_972_392L, inputs.Plan.UserdataStartSector);
        Assert.Equal(123_871_227L, inputs.Plan.UserdataEndSectorExclusive);
        Assert.Equal(482_913_628_160L, inputs.Plan.RestoredAndroidBytes); // 117,898,835 sectors of 4096 bytes

        // Exactly the two owned Linux partitions are dropped; userdata and the vendor stay.
        Assert.Equal(2, inputs.Plan.RemovedPartitionNumbers.Count);
        Assert.Contains(3L, inputs.Plan.RemovedPartitionNumbers);
        Assert.Contains(4L, inputs.Plan.RemovedPartitionNumbers);

        // Attributes may change between the capture and now (OTA state lives there). The validated inputs
        // must keep the words the CURRENT table carries and never resurrect the original ones.
        Assert.Equal((1UL << 50) | (1UL << 60), GptFixture.Partition(inputs.CurrentTable, 1).Attributes);
        Assert.Equal(0UL, GptFixture.Partition(inputs.OriginalTable, 1).Attributes);

        Assert.False(string.IsNullOrWhiteSpace(inputs.OriginalGptFingerprint));
        Assert.Equal(original.SourceFingerprint, inputs.OriginalGptFingerprint);
        Assert.False(string.IsNullOrWhiteSpace(inputs.CurrentTableFingerprint));
        Assert.False(string.IsNullOrWhiteSpace(inputs.EvidenceFingerprint));
        Assert.NotEqual(inputs.OriginalGptFingerprint, inputs.EvidenceFingerprint);
    }

    [Fact]
    public void Validate_KeepsExternalRawFingerprintIndependentFromJsonSource()
    {
        // The inspector's raw GPT digest and sfdisk's own SourceFingerprint are two different facts about two
        // different byte ranges; the JSON SourceFingerprint is never the raw capture digest. Validation must
        // therefore neither reject a raw fingerprint that differs from it nor quietly drop the raw digest on
        // the way into EvidenceFingerprint.
        var identity = Identity();
        var original = OriginalTable();
        var current = CurrentTable(Sfdisk.Json());

        var rawFingerprint = new string('A', 64);
        var alternateRawFingerprint = new string('B', 64);

        Assert.NotEqual(current.SourceFingerprint, rawFingerprint);
        Assert.NotEqual(current.SourceFingerprint, alternateRawFingerprint);

        var first = UninstallEvidenceValidator.Validate(identity, original, current, rawFingerprint);
        var second = UninstallEvidenceValidator.Validate(identity, original, current, alternateRawFingerprint);

        // The supplied external raw digest survives verbatim, and the table keeps its own JSON provenance.
        Assert.Equal(rawFingerprint, first.CurrentTableFingerprint);
        Assert.Equal(alternateRawFingerprint, second.CurrentTableFingerprint);
        Assert.Equal(current.SourceFingerprint, first.CurrentTable.SourceFingerprint);
        Assert.Equal(current.SourceFingerprint, second.CurrentTable.SourceFingerprint);

        // A different raw digest must reach the bound evidence fingerprint, or the two captures would be
        // indistinguishable after the fact.
        Assert.NotEqual(first.EvidenceFingerprint, second.EvidenceFingerprint);
    }

    // ----------------------------------------------------------- rejected evidence

    [Theory]
    [InlineData(EvidenceDefect.VendorMoved)]
    [InlineData(EvidenceDefect.VendorRemoved)]
    [InlineData(EvidenceDefect.UserdataUuidChanged)]
    [InlineData(EvidenceDefect.UserdataStartChanged)]
    [InlineData(EvidenceDefect.DiskGuidChanged)]
    [InlineData(EvidenceDefect.SectorSizeChanged)]
    [InlineData(EvidenceDefect.UnknownAddedPartition)]
    public void Validate_RejectsCurrentEvidenceThatNoLongerMatchesTheOriginal(EvidenceDefect defect)
    {
        var identity = Identity();
        var original = OriginalTable();

        var json = defect switch
        {
            EvidenceDefect.VendorMoved => Sfdisk.Json(proinfoStart: 1_000L),
            EvidenceDefect.VendorRemoved => Sfdisk.Json(includeProinfo: false),
            EvidenceDefect.UserdataUuidChanged => Sfdisk.Json(userdataUuid: "99999999-8888-4777-8666-555544443333"),
            EvidenceDefect.UserdataStartChanged => Sfdisk.Json(userdataStart: GptFixture.UserdataStart + 8L),
            EvidenceDefect.DiskGuidChanged => Sfdisk.Json(diskId: "99999999-8888-4777-8666-555544443333"),
            EvidenceDefect.SectorSizeChanged => Sfdisk.Json(sectorSize: 512),
            EvidenceDefect.UnknownAddedPartition => Sfdisk.Json(addUnknownPartition: true),
            _ => throw new InvalidOperationException("fixture: unknown defect " + defect),
        };

        // Reading the reported table and validating it are both part of the path that must reject: for
        // SectorSizeChanged the reader may legitimately refuse the sfdisk metadata first (4096-specific
        // usable bounds and entries declared under a 512-byte unit), so the assertion has to cover the whole
        // round trip instead of failing while the fixture is still being built.
        AssertEvidenceRejected(() =>
        {
            var current = CurrentTable(json);

            UninstallEvidenceValidator.Validate(
                identity, original, current, current.SourceFingerprint);
        });
    }

    [Fact]
    public void Validate_RejectsJsonTableAsOriginalEvenWhenGeometryMatches()
    {
        var identity = Identity();

        // ReadCurrentSfdisk builds a GptTable out of whatever JSON it is handed, so a table it produced must
        // never be accepted as the ORIGINAL capture. This document is forged to look like the factory disk —
        // full-size userdata and no Linux partitions — while still naming the live /dev/sda node, and only
        // OriginalGptImporter.Parse can produce an original (which names no device at all).
        var forgedOriginal = UninstallEvidenceValidator.ReadCurrentSfdisk(
            Sfdisk.Json(userdataSize: GptFixture.UserdataCount, includeLinuxPartitions: false),
            GptFixture.DiskBytes4096);

        var current = CurrentTable(Sfdisk.Json());

        // Passing the current table twice would fail for the right reason by accident, so the forged table is
        // a genuinely different one whose every geometry field agrees with the original's factory layout.
        // With no origin discriminator the validator would compute a fully matching plan and mint a
        // validated token from a table it read off the wire instead of from captured GPT bytes.
        AssertEvidenceRejected(() =>
            UninstallEvidenceValidator.Validate(identity, forgedOriginal, current, current.SourceFingerprint));
    }

    // ----------------------------------------------------------------------- helpers

    /// <summary>
    /// A concrete, non-placeholder identity. The validator is not allowed to derive identity from a dump path,
    /// so it always receives one that was confirmed up front. The model is one of the explicitly supported
    /// ones (TB322FC/TB323FU) so that neither the happy path nor the negative cases trip the unsupported-model
    /// gate instead of the behaviour under test; the serial is synthetic.
    /// </summary>
    private static DeviceIdentity Identity()
        => new("R58TEST0001", "TB322FC", BootloaderState.Unlocked);

    private static GptTable OriginalTable()
    {
        var image = GptFixture.RealLike4096();

        return OriginalGptImporter.Parse(
            image.BuildPrimaryFragment(),
            image.BuildBackupFragment(),
            GptFixture.SectorSize4096,
            GptFixture.DiskBytes4096);
    }

    private static GptTable CurrentTable(string json)
        => UninstallEvidenceValidator.ReadCurrentSfdisk(json, GptFixture.DiskBytes4096);

    private static void AssertInvalidData(Action action)
    {
        var exception = Record.Exception(action);

        Assert.NotNull(exception);
        Assert.True(
            exception is InvalidDataException,
            "expected InvalidDataException but got " + exception!.GetType().FullName);
    }

    /// <summary>
    /// A rejected evidence set may surface as <see cref="InvalidDataException"/> (the bytes are not a table
    /// this tool trusts) or as <see cref="ArgumentException"/> (the table was handed in as an argument). What
    /// matters is that nothing is accepted, so both are allowed here and nothing else is.
    /// </summary>
    private static void AssertEvidenceRejected(Action action)
    {
        var exception = Record.Exception(action);

        Assert.NotNull(exception);
        Assert.True(
            exception is InvalidDataException || exception is ArgumentException,
            "expected InvalidDataException or ArgumentException but got " + exception!.GetType().FullName);
    }
}

/// <summary>Which part of the current evidence is made to disagree with the original table.</summary>
public enum EvidenceDefect
{
    VendorMoved,
    VendorRemoved,
    UserdataUuidChanged,
    UserdataStartChanged,
    DiskGuidChanged,
    SectorSizeChanged,
    UnknownAddedPartition,
}

/// <summary>
/// Writes sfdisk's <c>--json</c> output for the real-like disk, byte for byte in the shape the tool prints.
/// The document is assembled here so every test can name the one field that differs.
/// </summary>
internal static class Sfdisk
{
    internal const string DiskId = "10BEF391-0EBA-9668-B82C-4E092F4C4467";
    internal const string Device = "/dev/sda";

    internal static string Json(
        string diskId = DiskId,
        string label = "gpt",
        string unit = "sectors",
        long firstLba = 6L,
        long lastLba = 123_871_226L,
        int tableLength = 32,
        int sectorSize = 4096,
        string proinfoAttrs = "GUID:50,60",
        long proinfoStart = GptFixture.ProinfoStart,
        long proinfoSize = GptFixture.ProinfoCount,
        bool includeProinfo = true,
        string userdataUuid = GptFixture.UserdataUuid,
        long userdataStart = GptFixture.UserdataStart,
        long userdataSize = GptFixture.CurrentUserdataCount,
        bool addUnknownPartition = false,
        bool includeLinuxPartitions = true)
    {
        var partitions = new StringBuilder();

        if (includeProinfo)
        {
            Append(partitions, 1, proinfoStart, proinfoSize, GptFixture.ProinfoType, GptFixture.ProinfoUuid, "proinfo", proinfoAttrs);
        }

        Append(partitions, 2, userdataStart, userdataSize, GptFixture.UserdataType, userdataUuid, "userdata", attrs: null);

        // Omitting the two Linux partitions leaves the factory shape of the disk, which is what a forged
        // "original" looks like; the node numbers of everything that remains are unchanged.
        if (includeLinuxPartitions)
        {
            Append(partitions, 3, GptFixture.BootStart, GptFixture.BootCount, GptFixture.LinuxType, GptFixture.BootUuid, "ARMADA_BOOT", attrs: null);
            Append(partitions, 4, GptFixture.RootStart, GptFixture.RootCount, GptFixture.LinuxType, GptFixture.RootUuid, "ARMADA_ROOT", attrs: null);
        }

        if (addUnknownPartition)
        {
            Append(partitions, 5, 800L, 1_024L, GptFixture.ProinfoType, "AAAAAAAA-BBBB-4CCC-8DDD-EEEEFFFF0000", "metadata", attrs: null);
        }

        var document = new StringBuilder();
        document.Append("{\"partitiontable\":{\"label\":\"").Append(label)
            .Append("\",\"id\":\"").Append(diskId)
            .Append("\",\"device\":\"").Append(Device)
            .Append("\",\"unit\":\"").Append(unit)
            .Append("\",\"firstlba\":").Append(firstLba)
            .Append(",\"lastlba\":").Append(lastLba)
            .Append(",\"table-length\":\"").Append(tableLength)
            .Append("\",\"sectorsize\":").Append(sectorSize)
            .Append(",\"partitions\":[").Append(partitions)
            .Append("]}}");

        return document.ToString();
    }

    private static void Append(
        StringBuilder builder,
        int nodeNumber,
        long start,
        long size,
        string type,
        string uuid,
        string name,
        string? attrs)
    {
        if (builder.Length > 0)
        {
            builder.Append(',');
        }

        builder.Append("{\"node\":\"").Append(Device).Append(nodeNumber)
            .Append("\",\"start\":").Append(start)
            .Append(",\"size\":").Append(size)
            .Append(",\"type\":\"").Append(type)
            .Append("\",\"uuid\":\"").Append(uuid)
            .Append("\",\"name\":\"").Append(name).Append('"');

        if (attrs is not null)
        {
            builder.Append(",\"attrs\":\"").Append(attrs).Append('"');
        }

        builder.Append('}');
    }
}
