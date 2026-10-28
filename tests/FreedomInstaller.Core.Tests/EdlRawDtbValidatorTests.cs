using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class EdlRawDtbValidatorTests
{
    private const uint FdtMagic = 0xD00DFEED;
    private const uint FdtBeginNode = 1;
    private const uint FdtEndNode = 2;
    private const uint FdtProp = 3;
    private const uint FdtNop = 4;
    private const uint FdtEnd = 9;

    private const string G4Model = "TB322FC";
    private const string G5Model = "TB323FU";

    private const string G4NormalArgs = "console=ttyMSM0,115200n8 androidboot.hardware=qcom";
    private const string G4DiagnosticArgs = "console=ttyMSM0,115200n8 armada.diag=1";
    private const string G5NormalArgs = "console=ttyMSM0,115200n8 androidboot.hardware=qcom";
    private const string G5DiagnosticArgs = "console=ttyMSM0,115200n8 armada.diag=1";

    private static readonly string[] G4Compatible = { "lenovo,elden", "qcom,sm8750" };
    private static readonly string[] G5Compatible = { "lenovo,baldur", "qcom,kaanapali" };

    [Fact]
    public void G4NormalProducesFactsForBootBuilderProtocolOne()
    {
        byte[] blob = CreateValidBlob(G4Compatible, G4NormalArgs, "os", 5);
        byte[] snapshot = (byte[])blob.Clone();

        EdlRawDtbEvidence evidence = EdlRawDtbValidator.Validate(
            blob,
            G4NormalArgs,
            EdlRawDtbKind.Normal,
            G4Model);

        Assert.Equal(EdlRawDtbKind.Normal, evidence.Kind);
        Assert.Equal(G4Model, evidence.DeviceModel);
        Assert.Equal(blob.LongLength, evidence.Length);
        Assert.Equal(IndependentSha256(blob), evidence.Sha256);
        Assert.Equal(G4Compatible, evidence.Compatible);
        Assert.Equal(G4NormalArgs, evidence.BootArgs);
        Assert.Equal("os", evidence.BootStage);
        Assert.Equal("internal", evidence.RootMedium);
        Assert.Equal(5u, evidence.InitrdEntryIndex);
        Assert.Equal(snapshot, blob);
    }

    [Fact]
    public void G4DiagnosticUsesMaintenanceStage()
    {
        byte[] blob = CreateValidBlob(G4Compatible, G4DiagnosticArgs, "maintenance", 5);
        byte[] snapshot = (byte[])blob.Clone();

        EdlRawDtbEvidence evidence = EdlRawDtbValidator.Validate(
            blob,
            G4DiagnosticArgs,
            EdlRawDtbKind.Diagnostic,
            G4Model);

        Assert.Equal(EdlRawDtbKind.Diagnostic, evidence.Kind);
        Assert.Equal(G4Model, evidence.DeviceModel);
        Assert.Equal(blob.LongLength, evidence.Length);
        Assert.Equal(IndependentSha256(blob), evidence.Sha256);
        Assert.Equal(G4Compatible, evidence.Compatible);
        Assert.Equal(G4DiagnosticArgs, evidence.BootArgs);
        Assert.Equal("maintenance", evidence.BootStage);
        Assert.Equal("internal", evidence.RootMedium);
        Assert.Equal(5u, evidence.InitrdEntryIndex);
        Assert.Equal(snapshot, blob);
    }

    [Fact]
    public void G5CanonicalPairWithNewCellFiveIsAcceptedAsDataOnly()
    {
        byte[] blob = CreateValidBlob(G5Compatible, G5NormalArgs, "os", 5);

        EdlRawDtbEvidence evidence = EdlRawDtbValidator.Validate(
            blob,
            G5NormalArgs,
            EdlRawDtbKind.Normal,
            G5Model);

        Assert.Equal(EdlRawDtbKind.Normal, evidence.Kind);
        Assert.Equal(G5Model, evidence.DeviceModel);
        Assert.Equal(G5Compatible, evidence.Compatible);
        Assert.Equal(blob.LongLength, evidence.Length);
        Assert.Equal(IndependentSha256(blob), evidence.Sha256);
        Assert.Equal(G5NormalArgs, evidence.BootArgs);
        Assert.Equal("os", evidence.BootStage);
        Assert.Equal("internal", evidence.RootMedium);
        Assert.Equal(5u, evidence.InitrdEntryIndex);
    }

    [Fact]
    public void CompatibleIsDefensivelyClonedAndReadOnly()
    {
        byte[] blob = CreateValidBlob(G4Compatible, G4NormalArgs, "os", 5);

        EdlRawDtbEvidence evidence = EdlRawDtbValidator.Validate(
            blob,
            G4NormalArgs,
            EdlRawDtbKind.Normal,
            G4Model);

        IList<string> list = Assert.IsAssignableFrom<IList<string>>(evidence.Compatible);

        Assert.Throws<NotSupportedException>(() => list[0] = "mutated");
        Assert.Throws<NotSupportedException>(() => list.Add("mutated"));
        Assert.Equal(G4Compatible, evidence.Compatible);
    }

    [Theory]
    [InlineData(MalformedFdtCase.WrongTotal)]
    [InlineData(MalformedFdtCase.WrongMagic)]
    [InlineData(MalformedFdtCase.UnsupportedVersion)]
    [InlineData(MalformedFdtCase.StructOutOfRange)]
    [InlineData(MalformedFdtCase.StringsOutOfRange)]
    [InlineData(MalformedFdtCase.BlockOverlap)]
    [InlineData(MalformedFdtCase.ReserveUnterminated)]
    [InlineData(MalformedFdtCase.BadToken)]
    [InlineData(MalformedFdtCase.UnbalancedNodes)]
    [InlineData(MalformedFdtCase.BadNameOffset)]
    [InlineData(MalformedFdtCase.UnterminatedName)]
    [InlineData(MalformedFdtCase.MissingChosen)]
    [InlineData(MalformedFdtCase.DuplicateChosen)]
    [InlineData(MalformedFdtCase.DuplicateBootArgs)]
    [InlineData(MalformedFdtCase.InvalidUtf8BootArgs)]
    [InlineData(MalformedFdtCase.MissingNulBootArgs)]
    [InlineData(MalformedFdtCase.InvalidUtf8Compatible)]
    [InlineData(MalformedFdtCase.MissingNulCompatible)]
    [InlineData(MalformedFdtCase.EmptyCompatibleItem)]
    [InlineData(MalformedFdtCase.ExpectedArgsMismatch)]
    [InlineData(MalformedFdtCase.WrongStage)]
    [InlineData(MalformedFdtCase.WrongMedium)]
    [InlineData(MalformedFdtCase.InitrdIndexFour)]
    [InlineData(MalformedFdtCase.InitrdIndexSeven)]
    [InlineData(MalformedFdtCase.InitrdTwoCells)]
    [InlineData(MalformedFdtCase.StaleInitrdStart)]
    [InlineData(MalformedFdtCase.StaleInitrdEnd)]
    [InlineData(MalformedFdtCase.MissingRequiredPair)]
    [InlineData(MalformedFdtCase.MixedModelTokens)]
    [InlineData(MalformedFdtCase.G5Sm8850Alias)]
    public void RejectsMalformedSyntheticDtb(MalformedFdtCase malformed)
    {
        byte[] blob = CreateMalformedBlob(malformed);
        string expectedModel = malformed == MalformedFdtCase.G5Sm8850Alias ? G5Model : G4Model;
        string expectedBootArgs = malformed == MalformedFdtCase.ExpectedArgsMismatch
            ? G4NormalArgs + " "
            : G4NormalArgs;

        Assert.Throws<InvalidDataException>(() =>
            EdlRawDtbValidator.Validate(blob, expectedBootArgs, EdlRawDtbKind.Normal, expectedModel));
    }

    [Theory]
    [InlineData("")]
    [InlineData("a=b\nc=d")]
    [InlineData("a=b\0c=d")]
    public void RejectsInvalidExpectedBootArgs(string expectedBootArgs)
    {
        byte[] blob = CreateValidBlob(G4Compatible, G4NormalArgs, "os", 5);

        Assert.Throws<ArgumentException>(() =>
            EdlRawDtbValidator.Validate(blob, expectedBootArgs, EdlRawDtbKind.Normal, G4Model));
    }

    [Fact]
    public void RejectsExpectedBootArgsOver4096Utf8Bytes()
    {
        byte[] blob = CreateValidBlob(G4Compatible, G4NormalArgs, "os", 5);
        string oversized = new string('a', 4097);

        Assert.Throws<ArgumentException>(() =>
            EdlRawDtbValidator.Validate(blob, oversized, EdlRawDtbKind.Normal, G4Model));
    }

    [Fact]
    public void RejectsUnknownKind()
    {
        byte[] blob = CreateValidBlob(G4Compatible, G4NormalArgs, "os", 5);

        Assert.Throws<ArgumentException>(() =>
            EdlRawDtbValidator.Validate(blob, G4NormalArgs, (EdlRawDtbKind)99, G4Model));
    }

    [Fact]
    public void RejectsUnknownModel()
    {
        byte[] blob = CreateValidBlob(G4Compatible, G4NormalArgs, "os", 5);

        Assert.Throws<ArgumentException>(() =>
            EdlRawDtbValidator.Validate(blob, G4NormalArgs, EdlRawDtbKind.Normal, "TB999XX"));
    }

    public static TheoryData<string, string, string, string> TfPositiveCases => new TheoryData<string, string, string, string>
    {
        { G4Model, G4NormalArgs, "os", G4NormalArgs },
        { G4Model, G4DiagnosticArgs, "maintenance", G4DiagnosticArgs },
        { G5Model, G5NormalArgs, "os", G5NormalArgs },
        { G5Model, G5DiagnosticArgs, "maintenance", G5DiagnosticArgs }
    };

    [Theory]
    [MemberData(nameof(TfPositiveCases))]
    public void ValidateTfAcceptsMatchingTfTreeAndReturnsParsedFacts(
        string model,
        string bootArgs,
        string stage,
        string expectedArgs)
    {
        string[] compatible = model == G4Model ? G4Compatible : G5Compatible;
        byte[] blob = CreateBootTree(
            EncodeStringList(compatible),
            EncodeString(bootArgs),
            stage,
            "tf",
            EncodeBigEndianCells(5)).Build();
        byte[] snapshot = (byte[])blob.Clone();

        EdlRawDtbKind kind = stage == "os" ? EdlRawDtbKind.Normal : EdlRawDtbKind.Diagnostic;
        EdlRawDtbEvidence evidence = EdlRawDtbValidator.ValidateTf(
            blob,
            expectedArgs,
            kind,
            model);

        Assert.Equal(kind, evidence.Kind);
        Assert.Equal(model, evidence.DeviceModel);
        Assert.Equal(blob.LongLength, evidence.Length);
        Assert.Equal(IndependentSha256(blob), evidence.Sha256);
        Assert.Equal(compatible, evidence.Compatible);
        Assert.Equal(expectedArgs, evidence.BootArgs);
        Assert.Equal(stage, evidence.BootStage);
        Assert.Equal("tf", evidence.RootMedium);
        Assert.Equal(5u, evidence.InitrdEntryIndex);
        Assert.Equal(snapshot, blob);
    }

    [Fact]
    public void ValidateRejectsValidTfTree()
    {
        byte[] blob = CreateBootTree(
            EncodeStringList(G4Compatible),
            EncodeString(G4NormalArgs),
            "os",
            "tf",
            EncodeBigEndianCells(5)).Build();

        Assert.Throws<InvalidDataException>(() =>
            EdlRawDtbValidator.Validate(blob, G4NormalArgs, EdlRawDtbKind.Normal, G4Model));
    }

    [Fact]
    public void ValidateTfRejectsValidInternalTree()
    {
        byte[] blob = CreateValidBlob(G4Compatible, G4NormalArgs, "os", 5);

        Assert.Throws<InvalidDataException>(() =>
            EdlRawDtbValidator.ValidateTf(blob, G4NormalArgs, EdlRawDtbKind.Normal, G4Model));
    }

    [Theory]
    [InlineData(TfRejectionCase.ForeignModel)]
    [InlineData(TfRejectionCase.WrongStage)]
    [InlineData(TfRejectionCase.MismatchedBootArgs)]
    [InlineData(TfRejectionCase.WrongInitrdCell)]
    [InlineData(TfRejectionCase.UnknownMedium)]
    [InlineData(TfRejectionCase.EmptyMedium)]
    public void ValidateTfRejectsBadTfTrees(TfRejectionCase rejection)
    {
        byte[] blob = CreateTfRejectionBlob(rejection);

        Assert.Throws<InvalidDataException>(() =>
            EdlRawDtbValidator.ValidateTf(blob, TfExpectedArgs(rejection), TfExpectedKind(rejection), TfExpectedModel(rejection)));
    }

    private static string TfExpectedArgs(TfRejectionCase rejection)
    {
        return rejection == TfRejectionCase.ForeignModel ? G5NormalArgs : G4NormalArgs;
    }

    private static EdlRawDtbKind TfExpectedKind(TfRejectionCase rejection)
    {
        return rejection == TfRejectionCase.WrongStage ? EdlRawDtbKind.Diagnostic : EdlRawDtbKind.Normal;
    }

    private static string TfExpectedModel(TfRejectionCase rejection)
    {
        return rejection == TfRejectionCase.ForeignModel ? G5Model : G4Model;
    }

    private static byte[] CreateTfRejectionBlob(TfRejectionCase rejection)
    {
        switch (rejection)
        {
            case TfRejectionCase.ForeignModel:
                return CreateBootTree(
                    EncodeStringList(G4Compatible),
                    EncodeString(G5NormalArgs),
                    "os",
                    "tf",
                    EncodeBigEndianCells(5)).Build();

            case TfRejectionCase.WrongStage:
                return CreateBootTree(
                    EncodeStringList(G4Compatible),
                    EncodeString(G4NormalArgs),
                    "os",
                    "tf",
                    EncodeBigEndianCells(5)).Build();

            case TfRejectionCase.MismatchedBootArgs:
                return CreateBootTree(
                    EncodeStringList(G4Compatible),
                    EncodeString(G4NormalArgs + " "),
                    "os",
                    "tf",
                    EncodeBigEndianCells(5)).Build();

            case TfRejectionCase.WrongInitrdCell:
                return CreateBootTree(
                    EncodeStringList(G4Compatible),
                    EncodeString(G4NormalArgs),
                    "os",
                    "tf",
                    EncodeBigEndianCells(7)).Build();

            case TfRejectionCase.UnknownMedium:
                return CreateBootTree(
                    EncodeStringList(G4Compatible),
                    EncodeString(G4NormalArgs),
                    "os",
                    "usb",
                    EncodeBigEndianCells(5)).Build();

            case TfRejectionCase.EmptyMedium:
                return CreateBootTree(
                    EncodeStringList(G4Compatible),
                    EncodeString(G4NormalArgs),
                    "os",
                    string.Empty,
                    EncodeBigEndianCells(5)).Build();

            default:
                throw new ArgumentOutOfRangeException(nameof(rejection), rejection, "Unhandled TF rejection case.");
        }
    }

    private static string IndependentSha256(byte[] blob)
    {
        byte[] hash = SHA256.HashData(blob);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static byte[] CreateValidBlob(string[] compatible, string bootArgs, string stage, params uint[] initrdCells)
    {
        return CreateBootTree(
            EncodeStringList(compatible),
            EncodeString(bootArgs),
            stage,
            "internal",
            EncodeBigEndianCells(initrdCells)).Build();
    }

    private static FdtBuilder CreateBootTree(
        byte[] compatibleData,
        byte[] bootArgsData,
        string stage,
        string rootMedium,
        byte[] initrdCells,
        int chosenCount = 1,
        int bootArgsCount = 1)
    {
        var builder = new FdtBuilder();
        builder.BeginNode(string.Empty);
        builder.Prop("compatible", compatibleData);

        for (int chosen = 0; chosen < chosenCount; chosen++)
        {
            builder.BeginNode("chosen");
            for (int copy = 0; copy < bootArgsCount; copy++)
            {
                builder.Prop("bootargs", bootArgsData);
            }

            builder.Prop("armada,boot-stage", EncodeString(stage));
            builder.Prop("armada,root-medium", EncodeString(rootMedium));
            builder.Prop("kshim,initrd-entry", initrdCells);
            builder.EndNode();
        }

        builder.BeginNode("memory@80000000");
        builder.Prop("device_type", EncodeString("memory"));
        builder.Nop();
        builder.EndNode();

        builder.EndNode();
        builder.RawToken(FdtEnd);
        return builder;
    }

    private static byte[] CreateBlobWithExtraChosenProperty(string propertyName)
    {
        var builder = new FdtBuilder();
        builder.BeginNode(string.Empty);
        builder.Prop("compatible", EncodeStringList(G4Compatible));
        builder.BeginNode("chosen");
        builder.Prop("bootargs", EncodeString(G4NormalArgs));
        builder.Prop("armada,boot-stage", EncodeString("os"));
        builder.Prop("armada,root-medium", EncodeString("internal"));
        builder.Prop("kshim,initrd-entry", EncodeBigEndianCells(5));
        builder.Prop(propertyName, EncodeBigEndianCells(0));
        builder.EndNode();
        builder.EndNode();
        builder.RawToken(FdtEnd);
        return builder.Build();
    }

    private static byte[] CreateMalformedBlob(MalformedFdtCase malformed)
    {
        FdtBuilder ValidBuilder()
        {
            return CreateBootTree(
                EncodeStringList(G4Compatible),
                EncodeString(G4NormalArgs),
                "os",
                "internal",
                EncodeBigEndianCells(5));
        }

        switch (malformed)
        {
            case MalformedFdtCase.WrongTotal:
                return ValidBuilder().Build(new FdtBuildOptions { TotalSizeDelta = -4 });

            case MalformedFdtCase.WrongMagic:
                return ValidBuilder().Build(new FdtBuildOptions { Magic = 0xDEADBEEF });

            case MalformedFdtCase.UnsupportedVersion:
                return ValidBuilder().Build(new FdtBuildOptions { Version = 18, LastCompatibleVersion = 17 });

            case MalformedFdtCase.StructOutOfRange:
                return ValidBuilder().Build(new FdtBuildOptions { StructOffset = 0xFFFFFF00 });

            case MalformedFdtCase.StringsOutOfRange:
                return ValidBuilder().Build(new FdtBuildOptions { StringsOffset = 0xFFFFFF00 });

            case MalformedFdtCase.BlockOverlap:
                return ValidBuilder().Build(new FdtBuildOptions { StringsOffset = 56 });

            case MalformedFdtCase.ReserveUnterminated:
                return ValidBuilder().Build(new FdtBuildOptions { ReserveUnterminated = true });

            case MalformedFdtCase.BadToken:
            {
                var builder = new FdtBuilder();
                builder.BeginNode(string.Empty);
                builder.Prop("compatible", EncodeStringList(G4Compatible));
                builder.RawToken(7);
                builder.EndNode();
                builder.RawToken(FdtEnd);
                return builder.Build();
            }

            case MalformedFdtCase.UnbalancedNodes:
            {
                var builder = new FdtBuilder();
                builder.BeginNode(string.Empty);
                builder.Prop("compatible", EncodeStringList(G4Compatible));
                builder.RawToken(FdtEnd);
                return builder.Build();
            }

            case MalformedFdtCase.BadNameOffset:
            {
                var builder = new FdtBuilder();
                builder.BeginNode(string.Empty);
                builder.Prop("compatible", EncodeStringList(G4Compatible));
                builder.PropWithNameOffset(0xFFFF, EncodeString("x"));
                builder.EndNode();
                builder.RawToken(FdtEnd);
                return builder.Build();
            }

            case MalformedFdtCase.UnterminatedName:
            {
                var builder = new FdtBuilder();
                builder.BeginNode(string.Empty);
                builder.Prop("compatible", EncodeStringList(G4Compatible));
                builder.BeginNode("chosen");
                builder.Prop("bootargs", EncodeString(G4NormalArgs));
                builder.PropWithUnterminatedName("unterminated-name", EncodeString("x"));
                builder.EndNode();
                builder.EndNode();
                builder.RawToken(FdtEnd);
                return builder.Build();
            }

            case MalformedFdtCase.MissingChosen:
                return CreateBootTree(
                    EncodeStringList(G4Compatible),
                    EncodeString(G4NormalArgs),
                    string.Empty,
                    string.Empty,
                    Array.Empty<byte>(),
                    chosenCount: 0).Build();

            case MalformedFdtCase.DuplicateChosen:
                return CreateBootTree(
                    EncodeStringList(G4Compatible),
                    EncodeString(G4NormalArgs),
                    "os",
                    "internal",
                    EncodeBigEndianCells(5),
                    chosenCount: 2).Build();

            case MalformedFdtCase.DuplicateBootArgs:
                return CreateBootTree(
                    EncodeStringList(G4Compatible),
                    EncodeString(G4NormalArgs),
                    "os",
                    "internal",
                    EncodeBigEndianCells(5),
                    bootArgsCount: 2).Build();

            case MalformedFdtCase.InvalidUtf8BootArgs:
                return CreateBootTree(
                    EncodeStringList(G4Compatible),
                    new byte[] { 0x61, 0x3D, 0x62, 0xFF, 0x00 },
                    "os",
                    "internal",
                    EncodeBigEndianCells(5)).Build();

            case MalformedFdtCase.MissingNulBootArgs:
                return CreateBootTree(
                    EncodeStringList(G4Compatible),
                    new byte[] { 0x61, 0x3D, 0x62 },
                    "os",
                    "internal",
                    EncodeBigEndianCells(5)).Build();

            case MalformedFdtCase.InvalidUtf8Compatible:
            {
                byte[] compatible = ConcatBytes(
                    EncodeString("lenovo,elden"),
                    new byte[] { 0xFF, 0x00 });
                return CreateBootTree(
                    compatible,
                    EncodeString(G4NormalArgs),
                    "os",
                    "internal",
                    EncodeBigEndianCells(5)).Build();
            }

            case MalformedFdtCase.MissingNulCompatible:
            {
                byte[] compatible = EncodeStringList(G4Compatible);
                Array.Resize(ref compatible, compatible.Length - 1);
                return CreateBootTree(
                    compatible,
                    EncodeString(G4NormalArgs),
                    "os",
                    "internal",
                    EncodeBigEndianCells(5)).Build();
            }

            case MalformedFdtCase.EmptyCompatibleItem:
            {
                byte[] compatible = ConcatBytes(
                    EncodeString("lenovo,elden"),
                    new byte[] { 0x00 },
                    EncodeString("qcom,sm8750"));
                return CreateBootTree(
                    compatible,
                    EncodeString(G4NormalArgs),
                    "os",
                    "internal",
                    EncodeBigEndianCells(5)).Build();
            }

            case MalformedFdtCase.ExpectedArgsMismatch:
                return ValidBuilder().Build();

            case MalformedFdtCase.WrongStage:
                return CreateBootTree(
                    EncodeStringList(G4Compatible),
                    EncodeString(G4NormalArgs),
                    "maintenance",
                    "internal",
                    EncodeBigEndianCells(5)).Build();

            case MalformedFdtCase.WrongMedium:
                return CreateBootTree(
                    EncodeStringList(G4Compatible),
                    EncodeString(G4NormalArgs),
                    "os",
                    "external",
                    EncodeBigEndianCells(5)).Build();

            case MalformedFdtCase.InitrdIndexFour:
                return CreateValidBlob(G4Compatible, G4NormalArgs, "os", 4);

            case MalformedFdtCase.InitrdIndexSeven:
                return CreateValidBlob(G4Compatible, G4NormalArgs, "os", 7);

            case MalformedFdtCase.InitrdTwoCells:
                return CreateValidBlob(G4Compatible, G4NormalArgs, "os", 5, 0);

            case MalformedFdtCase.StaleInitrdStart:
                return CreateBlobWithExtraChosenProperty("linux,initrd-start");

            case MalformedFdtCase.StaleInitrdEnd:
                return CreateBlobWithExtraChosenProperty("linux,initrd-end");

            case MalformedFdtCase.MissingRequiredPair:
                return CreateBootTree(
                    EncodeStringList(new[] { "lenovo,elden" }),
                    EncodeString(G4NormalArgs),
                    "os",
                    "internal",
                    EncodeBigEndianCells(5)).Build();

            case MalformedFdtCase.MixedModelTokens:
                return CreateBootTree(
                    EncodeStringList(new[] { "lenovo,elden", "qcom,sm8750", "lenovo,baldur", "qcom,kaanapali" }),
                    EncodeString(G4NormalArgs),
                    "os",
                    "internal",
                    EncodeBigEndianCells(5)).Build();

            case MalformedFdtCase.G5Sm8850Alias:
                return CreateBootTree(
                    EncodeStringList(new[] { "lenovo,baldur", "qcom,sm8850" }),
                    EncodeString(G4NormalArgs),
                    "os",
                    "internal",
                    EncodeBigEndianCells(5)).Build();

            default:
                throw new ArgumentOutOfRangeException(nameof(malformed), malformed, "Unhandled synthetic DTB case.");
        }
    }

    private static byte[] EncodeStringList(IEnumerable<string> values)
    {
        var bytes = new List<byte>();
        foreach (string value in values)
        {
            bytes.AddRange(Encoding.UTF8.GetBytes(value));
            bytes.Add(0);
        }

        return bytes.ToArray();
    }

    private static byte[] EncodeString(string value)
    {
        byte[] raw = Encoding.UTF8.GetBytes(value);
        byte[] terminated = new byte[raw.Length + 1];
        raw.CopyTo(terminated, 0);
        return terminated;
    }

    private static byte[] EncodeBigEndianCells(params uint[] cells)
    {
        byte[] bytes = new byte[cells.Length * 4];
        for (int i = 0; i < cells.Length; i++)
        {
            bytes[i * 4] = (byte)(cells[i] >> 24);
            bytes[i * 4 + 1] = (byte)(cells[i] >> 16);
            bytes[i * 4 + 2] = (byte)(cells[i] >> 8);
            bytes[i * 4 + 3] = (byte)cells[i];
        }

        return bytes;
    }

    private static byte[] ConcatBytes(params byte[][] parts)
    {
        int length = 0;
        foreach (byte[] part in parts)
        {
            length += part.Length;
        }

        byte[] result = new byte[length];
        int offset = 0;
        foreach (byte[] part in parts)
        {
            Buffer.BlockCopy(part, 0, result, offset, part.Length);
            offset += part.Length;
        }

        return result;
    }

    private static void WriteUInt32(List<byte> target, uint value)
    {
        target.Add((byte)(value >> 24));
        target.Add((byte)(value >> 16));
        target.Add((byte)(value >> 8));
        target.Add((byte)value);
    }

    private static void WriteUInt32(byte[] target, int offset, uint value)
    {
        target[offset] = (byte)(value >> 24);
        target[offset + 1] = (byte)(value >> 16);
        target[offset + 2] = (byte)(value >> 8);
        target[offset + 3] = (byte)value;
    }

    private sealed class FdtBuildOptions
    {
        public int TotalSizeDelta;
        public uint Magic = FdtMagic;
        public uint Version = 17;
        public uint LastCompatibleVersion = 16;
        public uint StructOffset;
        public uint StringsOffset;
        public bool ReserveUnterminated;
    }

    private sealed class FdtBuilder
    {
        private static readonly Encoding Utf8 = new UTF8Encoding(false);

        private readonly List<byte> _structBlock = new List<byte>();
        private readonly List<byte> _stringsBlock = new List<byte>();
        private readonly Dictionary<string, int> _nameOffsets = new Dictionary<string, int>(StringComparer.Ordinal);

        public FdtBuilder BeginNode(string name)
        {
            WriteUInt32(_structBlock, FdtBeginNode);
            _structBlock.AddRange(Utf8.GetBytes(name));
            _structBlock.Add(0);
            PadTo4(_structBlock);
            return this;
        }

        public FdtBuilder EndNode()
        {
            WriteUInt32(_structBlock, FdtEndNode);
            return this;
        }

        public FdtBuilder Nop()
        {
            WriteUInt32(_structBlock, FdtNop);
            return this;
        }

        public FdtBuilder RawToken(uint token)
        {
            WriteUInt32(_structBlock, token);
            return this;
        }

        public FdtBuilder Prop(string name, byte[] data)
        {
            return PropWithNameOffset((uint)NameOffset(name), data);
        }

        public FdtBuilder PropWithNameOffset(uint nameOffset, byte[] data)
        {
            WriteUInt32(_structBlock, FdtProp);
            WriteUInt32(_structBlock, (uint)data.Length);
            WriteUInt32(_structBlock, nameOffset);
            _structBlock.AddRange(data);
            PadTo4(_structBlock);
            return this;
        }

        public FdtBuilder PropWithUnterminatedName(string name, byte[] data)
        {
            int offset = _stringsBlock.Count;
            _stringsBlock.AddRange(Utf8.GetBytes(name));
            return PropWithNameOffset((uint)offset, data);
        }

        public byte[] Build()
        {
            return Build(new FdtBuildOptions());
        }

        public byte[] Build(FdtBuildOptions options)
        {
            const int headerSize = 40;
            const int reserveSize = 16;
            int structOffset = headerSize + reserveSize;
            int stringsOffset = structOffset + _structBlock.Count;
            int minimumSize = stringsOffset + _stringsBlock.Count;
            int arraySize = minimumSize + Math.Max(0, options.TotalSizeDelta);
            byte[] blob = new byte[arraySize];

            WriteUInt32(blob, 0, options.Magic);
            WriteUInt32(blob, 4, (uint)(minimumSize + options.TotalSizeDelta));
            WriteUInt32(blob, 8, options.StructOffset != 0 ? options.StructOffset : (uint)structOffset);
            WriteUInt32(blob, 12, options.StringsOffset != 0 ? options.StringsOffset : (uint)stringsOffset);
            WriteUInt32(blob, 16, (uint)headerSize);
            WriteUInt32(blob, 20, options.Version);
            WriteUInt32(blob, 24, options.LastCompatibleVersion);
            WriteUInt32(blob, 28, 0);
            WriteUInt32(blob, 32, (uint)_stringsBlock.Count);
            WriteUInt32(blob, 36, (uint)_structBlock.Count);

            if (options.ReserveUnterminated)
            {
                for (int i = headerSize; i < headerSize + reserveSize; i++)
                {
                    blob[i] = 0x5A;
                }
            }

            _structBlock.CopyTo(blob, structOffset);
            _stringsBlock.CopyTo(blob, stringsOffset);
            return blob;
        }

        private static void PadTo4(List<byte> target)
        {
            while (target.Count % 4 != 0)
            {
                target.Add(0);
            }
        }

        private int NameOffset(string name)
        {
            int offset;
            if (!_nameOffsets.TryGetValue(name, out offset))
            {
                offset = _stringsBlock.Count;
                _stringsBlock.AddRange(Utf8.GetBytes(name));
                _stringsBlock.Add(0);
                _nameOffsets.Add(name, offset);
            }

            return offset;
        }
    }
}

public enum MalformedFdtCase
{
    WrongTotal,
    WrongMagic,
    UnsupportedVersion,
    StructOutOfRange,
    StringsOutOfRange,
    BlockOverlap,
    ReserveUnterminated,
    BadToken,
    UnbalancedNodes,
    BadNameOffset,
    UnterminatedName,
    MissingChosen,
    DuplicateChosen,
    DuplicateBootArgs,
    InvalidUtf8BootArgs,
    MissingNulBootArgs,
    InvalidUtf8Compatible,
    MissingNulCompatible,
    EmptyCompatibleItem,
    ExpectedArgsMismatch,
    WrongStage,
    WrongMedium,
    InitrdIndexFour,
    InitrdIndexSeven,
    InitrdTwoCells,
    StaleInitrdStart,
    StaleInitrdEnd,
    MissingRequiredPair,
    MixedModelTokens,
    G5Sm8850Alias
}

public enum TfRejectionCase
{
    ForeignModel,
    WrongStage,
    MismatchedBootArgs,
    WrongInitrdCell,
    UnknownMedium,
    EmptyMedium
}
