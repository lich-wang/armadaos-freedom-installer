using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Contract tests for <see cref="InternalStorageReader"/>. The exact adb argv, the 20 second timeout, the
/// one-shot fallback and the two snapshot shapes are pinned here; a fake <see cref="ICommandRunner"/>
/// answers with canned output, so no test starts a process, touches a device or reads a file.
/// <para>
/// These tests pin the implemented reader: the helper response must satisfy the maintained
/// <c>inspect_layout</c> contract before any value is used, the fallback is exactly one <c>df -k /data</c>
/// query and every unusable answer becomes a bounded typed error. The assertions must not be weakened.
/// </para>
/// </summary>
public sealed class InternalStorageReaderTests
{
    private const string AdbPath = "/evidence/platform-tools/adb";
    private const string Serial = "R58M12345ABC";

    private const string HelperMissingStdout =
        "/system/bin/sh: /usr/libexec/armada/armada-installer: not found\n";

    private const string ValidMaintenanceJson =
        "{\n" +
        "  \"device\": \"/dev/block/sda\",\n" +
        "  \"sectorSize\": 4096,\n" +
        "  \"tableFingerprint\": \"9f2c4d1e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f\",\n" +
        "  \"partitions\": [\n" +
        "    {\"number\": 1, \"name\": \"boot\", \"startSector\": 2048, \"sectorCount\": 65536, " +
        "\"typeGuid\": \"C12A7328-F81F-11D2-BA4B-00A0C93EC93B\", \"partUuid\": \"11111111-2222-3333-4444-555555555555\"},\n" +
        "    {\"number\": 2, \"name\": \"userdata\", \"startSector\": 67584, \"sectorCount\": 262144, " +
        "\"typeGuid\": \"0FC63DAF-8483-4772-8E79-3D69D8477DE4\", \"partUuid\": \"66666666-7777-8888-9999-AAAAAAAAAAAA\"}\n" +
        "  ]\n" +
        "}";

    private const string Fingerprint =
        "9f2c4d1e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f";

    private const string DfHeader =
        "Filesystem     1K-blocks     Used Available Use% Mounted on\n";

    private const string DfDataRow =
        "/dev/block/dm-52 115343360 20480000 94308352 18% /data\n";

    private const string ValidDf = DfHeader + DfDataRow;

    private const long DfTotalBytes = 115343360L * 1024L;   // raw 1K-blocks, not used + available
    private const long DfUsedBytes = 20480000L * 1024L;
    private const long DfAvailableBytes = 94308352L * 1024L;

    // Captured verbatim from TEST0001 (TB322FC, ZUI .259) with `adb shell -T df -k /data`. ZUI answers
    // with the /data/user/0 bind mount, and read-only mountinfo confirms /data and /data/user/0 are the
    // same f2fs device (major:minor 254:63, /dev/block/dm-63), so this is a legitimate /data answer.
    private const string DfZuiHeader =
        "Filesystem       1K-blocks    Used Available Use% Mounted on\n";

    private const string DfZuiAliasRow =
        "/dev/block/dm-63 134215680 6307900 127776708 5% /data/user/0\n";

    private const long ZuiTotalBytes = 134215680L * 1024L;
    private const long ZuiUsedBytes = 6307900L * 1024L;
    private const long ZuiAvailableBytes = 127776708L * 1024L;

    private static readonly string[] HelperArguments =
    {
        "-s", Serial, "shell", "-T", "/usr/libexec/armada/armada-installer", "inspect-layout", "--json",
    };

    private static readonly string[] DfArguments =
    {
        "-s", Serial, "shell", "-T", "df", "-k", "/data",
    };

    // ------------------------------------------------------------ maintenance layout

    [Fact]
    public async Task ReadAsync_ValidMaintenanceJson_ReturnsRealLayoutAndUserdataTotal()
    {
        var runner = new FakeCommandRunner();
        runner.ExpectPrimary(Ok(ValidMaintenanceJson));

        var snapshot = await ReaderFor(runner).ReadAsync(Serial);

        Assert.Equal(InternalStorageSource.MaintenanceLayout, snapshot.Source);
        Assert.Equal(Fingerprint, snapshot.TableFingerprint);
        Assert.Null(snapshot.UsedBytes);
        Assert.Null(snapshot.AvailableBytes);

        // userdata is 262144 sectors of 4096 bytes; the total must come from the layout, not from a guess.
        Assert.Equal(262144L * 4096L, snapshot.TotalBytes);

        var layout = Assert.IsType<DiskLayout>(snapshot.Layout);
        Assert.Equal("/dev/block/sda", layout.DeviceId);
        Assert.Equal(4096, layout.SectorSize);
        Assert.Equal(2, layout.Partitions.Count);

        var userdata = layout.Partitions.Single(partition => partition.Name == "userdata");
        Assert.Equal(67584L, userdata.StartSector);
        Assert.Equal(262144L, userdata.SectorCount);

        Assert.Equal(1, runner.CommandCount);
        Assert.Equal(HelperArguments, runner.Commands[0].Arguments.ToArray());
        Assert.Equal(TimeSpan.FromSeconds(20), runner.Commands[0].Timeout);
    }

    [Fact]
    public async Task ReadAsync_HelperMissingWithExit127_FallsBackExactlyOnceToDf()
    {
        var runner = new FakeCommandRunner();
        runner.ExpectPrimary(new ProcessResult(127, HelperMissingStdout, string.Empty));
        runner.ExpectDf(Ok(ValidDf));

        var snapshot = await ReaderFor(runner).ReadAsync(Serial);

        Assert.Equal(InternalStorageSource.AndroidFileSystem, snapshot.Source);
        Assert.Equal(DfTotalBytes, snapshot.TotalBytes);
        Assert.Equal(DfUsedBytes, snapshot.UsedBytes);
        Assert.Equal(DfAvailableBytes, snapshot.AvailableBytes);
        Assert.Null(snapshot.Layout);
        Assert.Null(snapshot.TableFingerprint);

        // Exactly one fallback: no second helper call, no second df, no invented metadata.
        Assert.Equal(2, runner.CommandCount);
        Assert.Equal(DfArguments, runner.Commands[1].Arguments.ToArray());
        Assert.Equal(TimeSpan.FromSeconds(20), runner.Commands[1].Timeout);
    }

    [Fact]
    public async Task ReadAsync_HelperNotFoundTextWithExitZero_FallsBack()
    {
        // Screenshot regression: Android's shell prints "not found" on stdout and still exits 0.
        var runner = new FakeCommandRunner();
        runner.ExpectPrimary(new ProcessResult(0, HelperMissingStdout, string.Empty));
        runner.ExpectDf(Ok(ValidDf));

        var snapshot = await ReaderFor(runner).ReadAsync(Serial);

        Assert.Equal(InternalStorageSource.AndroidFileSystem, snapshot.Source);
        Assert.Equal(DfTotalBytes, snapshot.TotalBytes);
        Assert.Equal(2, runner.CommandCount);
    }

    [Fact]
    public async Task ReadAsync_MalformedJson_FallsBack()
    {
        var runner = new FakeCommandRunner();
        runner.ExpectPrimary(Ok("{\"device\": \"/dev/block/sda\", \"sectorSize\":"));
        runner.ExpectDf(Ok(ValidDf));

        var snapshot = await ReaderFor(runner).ReadAsync(Serial);

        Assert.Equal(InternalStorageSource.AndroidFileSystem, snapshot.Source);
        Assert.Equal(2, runner.CommandCount);
    }

    [Fact]
    public async Task ReadAsync_JsonMissingRequiredField_FallsBack()
    {
        const string missingSectorSize =
            "{\"device\":\"/dev/block/sda\",\"tableFingerprint\":\"" + Fingerprint + "\"," +
            "\"partitions\":[{\"number\":1,\"name\":\"userdata\",\"startSector\":2048," +
            "\"sectorCount\":262144,\"typeGuid\":\"0FC63DAF-8483-4772-8E79-3D69D8477DE4\"," +
            "\"partUuid\":\"66666666-7777-8888-9999-AAAAAAAAAAAA\"}]}";

        var runner = new FakeCommandRunner();
        runner.ExpectPrimary(Ok(missingSectorSize));
        runner.ExpectDf(Ok(ValidDf));

        var snapshot = await ReaderFor(runner).ReadAsync(Serial);

        Assert.Equal(InternalStorageSource.AndroidFileSystem, snapshot.Source);
        Assert.Equal(2, runner.CommandCount);
    }

    public static IEnumerable<object[]> InvalidMaintenanceJson
    {
        get
        {
            // 2048 is a power of two but not an accepted sector size: only 512 and 4096 are valid.
            yield return new object[]
            {
                "{\"device\":\"/dev/block/sda\",\"sectorSize\":2048,\"tableFingerprint\":\"" + Fingerprint + "\"," +
                "\"partitions\":[{\"number\":1,\"name\":\"userdata\",\"startSector\":2048,\"sectorCount\":1000," +
                "\"typeGuid\":\"0FC63DAF-8483-4772-8E79-3D69D8477DE4\",\"partUuid\":\"66666666-7777-8888-9999-AAAAAAAAAAAA\"}]}",
            };

            // No userdata partition: the helper answer cannot produce a userdata total.
            yield return new object[]
            {
                "{\"device\":\"/dev/block/sda\",\"sectorSize\":4096,\"tableFingerprint\":\"" + Fingerprint + "\"," +
                "\"partitions\":[{\"number\":1,\"name\":\"boot\",\"startSector\":2048,\"sectorCount\":65536," +
                "\"typeGuid\":\"C12A7328-F81F-11D2-BA4B-00A0C93EC93B\",\"partUuid\":\"11111111-2222-3333-4444-555555555555\"}]}",
            };

            // Two userdata partitions: ambiguous, so no single total may be chosen.
            yield return new object[]
            {
                "{\"device\":\"/dev/block/sda\",\"sectorSize\":4096,\"tableFingerprint\":\"" + Fingerprint + "\"," +
                "\"partitions\":[" +
                "{\"number\":1,\"name\":\"userdata\",\"startSector\":2048,\"sectorCount\":1000," +
                "\"typeGuid\":\"0FC63DAF-8483-4772-8E79-3D69D8477DE4\",\"partUuid\":\"66666666-7777-8888-9999-AAAAAAAAAAAA\"}," +
                "{\"number\":2,\"name\":\"userdata\",\"startSector\":3048,\"sectorCount\":1000," +
                "\"typeGuid\":\"0FC63DAF-8483-4772-8E79-3D69D8477DE4\",\"partUuid\":\"BBBBBBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF\"}]}",
            };
        }
    }

    [Theory]
    [MemberData(nameof(InvalidMaintenanceJson))]
    public async Task ReadAsync_InvalidMaintenanceSemantics_FallsBack(string json)
    {
        var runner = new FakeCommandRunner();
        runner.ExpectPrimary(Ok(json));
        runner.ExpectDf(Ok(ValidDf));

        var snapshot = await ReaderFor(runner).ReadAsync(Serial);

        // Bad structure must never be turned into a guessed layout; the df snapshot has no layout at all.
        Assert.Equal(InternalStorageSource.AndroidFileSystem, snapshot.Source);
        Assert.Null(snapshot.Layout);
        Assert.Null(snapshot.TableFingerprint);
        Assert.Equal(2, runner.CommandCount);
    }

    // -------------------------------------------------------------- Android fallback

    [Fact]
    public async Task ReadAsync_DfUsesRawTotal_NotUsedPlusAvailable()
    {
        var runner = new FakeCommandRunner();
        runner.ExpectPrimary(new ProcessResult(127, HelperMissingStdout, string.Empty));
        runner.ExpectDf(Ok(ValidDf));

        var snapshot = await ReaderFor(runner).ReadAsync(Serial);

        // The raw 1K-blocks total differs from used + available, so it proves which column was used.
        Assert.Equal(115343360L * 1024L, snapshot.TotalBytes);
        Assert.NotEqual(DfUsedBytes + DfAvailableBytes, snapshot.TotalBytes);
        Assert.Equal(20480000L * 1024L, snapshot.UsedBytes);
        Assert.Equal(94308352L * 1024L, snapshot.AvailableBytes);
    }

    [Fact]
    public async Task ReadAsync_DfWrappedFilesystemName_IsJoinedBeforeParsing()
    {
        const string wrapped =
            DfHeader +
            "/dev/block/dm-52\n" +
            "                115343360 20480000 94308352 18% /data\n";

        var runner = new FakeCommandRunner();
        runner.ExpectPrimary(new ProcessResult(127, HelperMissingStdout, string.Empty));
        runner.ExpectDf(Ok(wrapped));

        var snapshot = await ReaderFor(runner).ReadAsync(Serial);

        Assert.Equal(DfTotalBytes, snapshot.TotalBytes);
        Assert.Equal(DfUsedBytes, snapshot.UsedBytes);
        Assert.Equal(DfAvailableBytes, snapshot.AvailableBytes);
    }

    [Fact]
    public async Task ReadAsync_DfCrLf_IsParsed()
    {
        const string crlf =
            "Filesystem     1K-blocks     Used Available Use% Mounted on\r\n" +
            "/dev/block/dm-52 115343360 20480000 94308352 18% /data\r\n";

        var runner = new FakeCommandRunner();
        runner.ExpectPrimary(new ProcessResult(127, HelperMissingStdout, string.Empty));
        runner.ExpectDf(Ok(crlf));

        var snapshot = await ReaderFor(runner).ReadAsync(Serial);

        Assert.Equal(InternalStorageSource.AndroidFileSystem, snapshot.Source);
        Assert.Equal(DfTotalBytes, snapshot.TotalBytes);
    }

    [Fact]
    public async Task ReadAsync_DfWrongMount_ThrowsTypedInvalidResponse()
    {
        const string wrongMount =
            DfHeader +
            "/dev/block/dm-52 115343360 20480000 94308352 18% /storage/emulated\n" +
            "/dev/block/dm-53 115343360 20480000 94308352 18% /metadata\n";

        var runner = new FakeCommandRunner();
        runner.ExpectPrimary(new ProcessResult(127, HelperMissingStdout, string.Empty));
        runner.ExpectDf(Ok(wrongMount));

        var exception = await Assert.ThrowsAsync<InternalStorageReadException>(
            () => ReaderFor(runner).ReadAsync(Serial));

        // /storage/emulated and /metadata are not /data; an answer about another mount is not evidence.
        Assert.Equal(InternalStorageReadFailure.InvalidResponse, exception.Failure);
        Assert.False(string.IsNullOrWhiteSpace(exception.Message));
        Assert.InRange(exception.Diagnostic.Length, 1, 512);
    }

    [Theory]
    [InlineData(
        "Filesystem     1K-blocks     Used Available Use% Mounted on\n" +
        "/dev/block/dm-52 115343360 20480000 94308352 18% /data\n" +
        "/dev/block/dm-52 115343360 20480000 94308352 18% /data\n")]
    [InlineData(
        "Filesystem     1K-blocks     Used Available Use% Mounted on\n" +
        "/dev/block/dm-52 115343360 -1 94308352 18% /data\n")]
    [InlineData(
        "Filesystem     1K-blocks     Used Available Use% Mounted on\n" +
        "/dev/block/dm-52 99999999999999999999 20480000 94308352 18% /data\n")]
    [InlineData(
        "Filesystem     1K-blocks     Used Available Use% Mounted on\n")]
    public async Task ReadAsync_DfDuplicateNegativeOverflowOrEmpty_ThrowsInvalidResponse(string dfOutput)
    {
        var runner = new FakeCommandRunner();
        runner.ExpectPrimary(new ProcessResult(127, HelperMissingStdout, string.Empty));
        runner.ExpectDf(Ok(dfOutput));

        var exception = await Assert.ThrowsAsync<InternalStorageReadException>(
            () => ReaderFor(runner).ReadAsync(Serial));

        Assert.Equal(InternalStorageReadFailure.InvalidResponse, exception.Failure);
        Assert.InRange(exception.Diagnostic.Length, 1, 512);
        Assert.Equal(2, runner.CommandCount);
    }

    [Fact]
    public async Task ReadAsync_FallbackDenied_ThrowsTypedUnavailable()
    {
        var runner = new FakeCommandRunner();
        runner.ExpectPrimary(new ProcessResult(127, HelperMissingStdout, string.Empty));
        runner.ExpectDf(new ProcessResult(1, string.Empty, "df: /data: Permission denied\n"));

        var exception = await Assert.ThrowsAsync<InternalStorageReadException>(
            () => ReaderFor(runner).ReadAsync(Serial));

        Assert.Equal(InternalStorageReadFailure.Unavailable, exception.Failure);
        Assert.False(string.IsNullOrWhiteSpace(exception.Message));
        Assert.InRange(exception.Diagnostic.Length, 1, 512);
    }

    // ---------------------------------------------------- ZUI /data/user/0 bind mount

    [Fact]
    public async Task ReadAsync_ZuiAliasRowOnly_SucceedsAsTheSingleDataAnswer()
    {
        var runner = new FakeCommandRunner();
        runner.ExpectPrimary(new ProcessResult(127, HelperMissingStdout, string.Empty));
        runner.ExpectDf(Ok(DfZuiHeader + DfZuiAliasRow));

        var snapshot = await ReaderFor(runner).ReadAsync(Serial);

        // The captured ZUI row names /data/user/0; rejecting it would reject real hardware.
        Assert.Equal(InternalStorageSource.AndroidFileSystem, snapshot.Source);
        Assert.Equal(ZuiTotalBytes, snapshot.TotalBytes);
        Assert.Equal(ZuiUsedBytes, snapshot.UsedBytes);
        Assert.Equal(ZuiAvailableBytes, snapshot.AvailableBytes);
        Assert.NotEqual(ZuiUsedBytes + ZuiAvailableBytes, snapshot.TotalBytes);
        Assert.Null(snapshot.Layout);
        Assert.Null(snapshot.TableFingerprint);

        // Exactly two read-only, serial-bound queries: the helper attempt and the one df fallback.
        Assert.Equal(2, runner.CommandCount);
        Assert.Equal(HelperArguments, runner.Commands[0].Arguments.ToArray());
        Assert.Equal(DfArguments, runner.Commands[1].Arguments.ToArray());
        Assert.All(runner.Commands, command => Assert.Equal(TimeSpan.FromSeconds(20), command.Timeout));
        Assert.All(runner.Commands, command => Assert.Contains(Serial, command.Arguments));
    }

    [Theory]
    [InlineData(
        "/dev/block/dm-63 134215680 6307900 127776708 5% /data/user/0\n" +
        "/dev/block/dm-63 134215680 6307900 127776708 5% /data/user/0\n")]
    [InlineData(
        "/dev/block/dm-63 134215680 6307900 127776708 5% /data\n" +
        "/dev/block/dm-63 134215680 6307900 127776708 5% /data/user/0\n")]
    public async Task ReadAsync_DuplicateOrMixedDataRows_ThrowsInvalidResponse(string rows)
    {
        var runner = new FakeCommandRunner();
        runner.ExpectPrimary(new ProcessResult(127, HelperMissingStdout, string.Empty));
        runner.ExpectDf(Ok(DfHeader + rows));

        var exception = await Assert.ThrowsAsync<InternalStorageReadException>(
            () => ReaderFor(runner).ReadAsync(Serial));

        // Two rows describing the same file system are ambiguous; neither may become the single answer.
        Assert.Equal(InternalStorageReadFailure.InvalidResponse, exception.Failure);
        Assert.InRange(exception.Diagnostic.Length, 1, 512);
        Assert.Equal(2, runner.CommandCount);
    }

    [Theory]
    [InlineData("/dev/block/dm-63 134215680 6307900 127776708 5% /data/user/10\n")]
    [InlineData("/dev/block/dm-63 134215680 6307900 127776708 5% /data/user/0/media\n")]
    [InlineData("/dev/block/dm-63 134215680 6307900 127776708 5% /data_mirror\n")]
    public async Task ReadAsync_UnrelatedDataLikeMountOnly_ThrowsInvalidResponse(string row)
    {
        var runner = new FakeCommandRunner();
        runner.ExpectPrimary(new ProcessResult(127, HelperMissingStdout, string.Empty));
        runner.ExpectDf(Ok(DfHeader + row));

        var exception = await Assert.ThrowsAsync<InternalStorageReadException>(
            () => ReaderFor(runner).ReadAsync(Serial));

        // Another profile, a child directory or the mirror share a prefix but are not /data itself.
        Assert.Equal(InternalStorageReadFailure.InvalidResponse, exception.Failure);
        Assert.InRange(exception.Diagnostic.Length, 1, 512);
        Assert.Equal(2, runner.CommandCount);
    }

    // ------------------------------------------------------- guards and process scope

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\n")]
    public async Task ReadAsync_BlankSerial_RejectsBeforeAnyProcess(string serial)
    {
        var runner = new FakeCommandRunner();

        await Assert.ThrowsAsync<ArgumentException>(() => ReaderFor(runner).ReadAsync(serial));

        // A blank -s value would let adb pick a device, so nothing may be started.
        Assert.Equal(0, runner.CommandCount);
    }

    [Fact]
    public async Task ReadAsync_Cancellation_PropagatesAndDoesNotFallBack()
    {
        var runner = new FakeCommandRunner();
        runner.ExpectPrimaryCancellation();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ReaderFor(runner).ReadAsync(Serial));

        // Cancellation is not a bad helper answer: no df fallback may follow it.
        Assert.Equal(1, runner.CommandCount);
    }

    [Fact]
    public async Task ReadAsync_Timeout_PropagatesAndDoesNotFallBack()
    {
        var runner = new FakeCommandRunner();
        runner.ExpectPrimaryTimeout();

        await Assert.ThrowsAsync<TimeoutException>(() => ReaderFor(runner).ReadAsync(Serial));

        // A timeout is not a parse failure: a second command would only add another 20 second wait.
        Assert.Equal(1, runner.CommandCount);
    }

    [Fact]
    public async Task ReadAsync_RepeatedReads_DoNotReusePreviousSuccess()
    {
        var runner = new FakeCommandRunner();
        runner.ExpectPrimary(Ok(ValidMaintenanceJson));
        runner.ExpectPrimary(new ProcessResult(127, HelperMissingStdout, string.Empty));
        runner.ExpectDf(Ok(ValidDf));

        var reader = ReaderFor(runner);
        var first = await reader.ReadAsync(Serial);
        var second = await reader.ReadAsync(Serial);

        Assert.Equal(InternalStorageSource.MaintenanceLayout, first.Source);
        Assert.Equal(InternalStorageSource.AndroidFileSystem, second.Source);
        Assert.Equal(3, runner.CommandCount);
    }

    [Fact]
    public async Task ReadAsync_NeverUsesExecOutOrWriteRootRebootCommands()
    {
        var runner = new FakeCommandRunner();
        runner.ExpectPrimary(new ProcessResult(127, HelperMissingStdout, string.Empty));
        runner.ExpectDf(Ok(ValidDf));

        await ReaderFor(runner).ReadAsync(Serial);

        Assert.Equal(2, runner.CommandCount);
        foreach (var command in runner.Commands)
        {
            var joined = string.Join(' ', command.Arguments);

            // The fixed query contract is read-only: no exec-out stream, no root, no reboot, no push.
            Assert.False(joined.Contains("exec-out", StringComparison.OrdinalIgnoreCase), joined);
            Assert.False(joined.Contains("root", StringComparison.OrdinalIgnoreCase), joined);
            Assert.False(joined.Contains("reboot", StringComparison.OrdinalIgnoreCase), joined);
            Assert.False(joined.Contains("push", StringComparison.OrdinalIgnoreCase), joined);
            Assert.False(joined.Contains("flash", StringComparison.OrdinalIgnoreCase), joined);
            Assert.Equal(TimeSpan.FromSeconds(20), command.Timeout);
        }
    }

    // ------------------------------------------------------------------------ helpers

    private static InternalStorageReader ReaderFor(FakeCommandRunner runner) => new(AdbPath, runner);

    private static ProcessResult Ok(string standardOutput) => new(0, standardOutput, string.Empty);

    /// <summary>
    /// Fake <see cref="ICommandRunner"/> for the storage boundary. Every expected call pins the executable,
    /// the complete argv in order and the 20 second timeout, then returns a complete result or throws a
    /// configured timeout/cancellation. No real adb, device, file or process is involved.
    /// </summary>
    private sealed class FakeCommandRunner : ICommandRunner
    {
        private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(20);

        private readonly Queue<Step> _steps = new();
        private readonly List<ProcessCommand> _commands = new();

        internal IReadOnlyList<ProcessCommand> Commands => _commands;

        internal int CommandCount => _commands.Count;

        internal void Expect(string executable, string[] arguments, ProcessResult result) =>
            _steps.Enqueue(new Step(executable, arguments, result, null));

        internal void ExpectPrimary(ProcessResult result) =>
            Expect(AdbPath, HelperArguments, result);

        internal void ExpectDf(ProcessResult result) =>
            Expect(AdbPath, DfArguments, result);

        internal void ExpectPrimaryCancellation() =>
            _steps.Enqueue(new Step(
                AdbPath,
                HelperArguments,
                null,
                new OperationCanceledException("simulated cancellation")));

        internal void ExpectPrimaryTimeout() =>
            _steps.Enqueue(new Step(
                AdbPath,
                HelperArguments,
                null,
                new TimeoutException("simulated 20 second timeout")));

        public Task<ProcessResult> RunAsync(ProcessCommand command, CancellationToken cancellationToken = default)
        {
            _commands.Add(command);
            cancellationToken.ThrowIfCancellationRequested();

            Assert.True(
                _steps.Count > 0,
                $"unexpected extra command #{_commands.Count}: {command.Executable} {string.Join(' ', command.Arguments)}");

            var step = _steps.Dequeue();

            Assert.Equal(step.Executable, command.Executable);
            Assert.Equal(step.Arguments, command.Arguments.ToArray());
            Assert.Equal(QueryTimeout, command.Timeout);

            if (step.Failure is not null)
            {
                return Task.FromException<ProcessResult>(step.Failure);
            }

            return Task.FromResult(step.Result!);
        }

        private sealed record Step(
            string Executable,
            string[] Arguments,
            ProcessResult? Result,
            Exception? Failure);
    }
}
