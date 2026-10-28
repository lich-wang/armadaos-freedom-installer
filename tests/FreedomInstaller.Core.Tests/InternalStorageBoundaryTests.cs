using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Boundary regression for <see cref="InternalStorageReader"/>: the helper answer must be structurally and
/// numerically sound before it is used, and the single <c>df -k /data</c> fallback must stay inside the
/// capacity contract instead of publishing an impossible total/used/available triple.
/// <para>
/// The tests pin the public reader only, through a local <see cref="ICommandRunner"/> fake: no process,
/// device, file or network is touched. The helper JSON uses the T002 <c>inspect_layout</c> shape
/// (<c>device</c>, <c>sectorSize</c>, <c>tableFingerprint</c>, <c>partitions</c>) with well-formed defaults,
/// and each malformed case changes exactly one thing from that valid baseline.
/// </para>
/// <para>
/// The four df rows below must all be rejected with <see cref="InternalStorageReadFailure.InvalidResponse"/>
/// even though they parse as integers. The existing KiB overflow guard already rejects the first row; the
/// other three are the red that the separate production fix must turn green. No structural GPT/overlap
/// case lives here: those gates belong to <see cref="PartitionPlanner"/>.
/// </para>
/// </summary>
public sealed class InternalStorageBoundaryTests
{
    private const string AdbPath = "/evidence/platform-tools/adb";
    private const string Serial = "OFFLINE-QA";

    private const string HelperMissingStdout =
        "/system/bin/sh: /usr/libexec/armada/armada-installer: not found\n";

    private const string DfHeader =
        "Filesystem     1K-blocks     Used Available Use% Mounted on\n";

    // 100 GiB total, 20 GiB used, 78 GiB available. Available keeps a 2 GiB reserve, so the row is a
    // meaningful, well-formed default whose used + available (98 GiB) stays below the reported total.
    private const string SafeDfRow =
        "/dev/block/dm-52 104857600 20971520 81788928 21% /data\n";

    private const string ValidDf = DfHeader + SafeDfRow;

    private const long SafeTotalBytes = 104857600L * 1024L;
    private const long SafeUsedBytes = 20971520L * 1024L;
    private const long SafeAvailableBytes = 81788928L * 1024L;

    private const string Fingerprint =
        "9f2c4d1e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f";

    private const string BootTypeGuid = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
    private const string BootUuid = "11111111-2222-3333-4444-555555555555";
    private const string UserdataTypeGuid = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
    private const string UserdataUuid = "66666666-7777-8888-9999-AAAAAAAAAAAA";

    private static readonly string[] HelperArguments =
    {
        "-s", Serial, "shell", "-T", "/usr/libexec/armada/armada-installer", "inspect-layout", "--json",
    };

    private static readonly string[] DfArguments =
    {
        "-s", Serial, "shell", "-T", "df", "-k", "/data",
    };

    // ---------------------------------------------------------------- df capacity contract

    /// <summary>
    /// A df row that parses as three unsigned integers is still not a usable capacity answer when the
    /// numbers cannot all be true at once. Each case below is exactly one violation:
    /// <list type="bullet">
    /// <item><c>9007199254740992</c> 1K-blocks parses as a long but times 1024 exceeds <see cref="long.MaxValue"/>;</item>
    /// <item><c>100 80 30</c> reports used + available above the total;</item>
    /// <item><c>0 0 0</c> reports a zero-capacity /data;</item>
    /// <item><c>100 150 0</c> reports more used than total.</item>
    /// </list>
    /// </summary>
    [Theory]
    [InlineData("9007199254740992 0 0")]
    [InlineData("100 80 30")]
    [InlineData("0 0 0")]
    [InlineData("100 150 0")]
    public async Task ReadAsync_DfRowViolatingCapacityContract_ThrowsInvalidResponse(string columns)
    {
        var runner = new FakeRunner()
            .Expect(new ProcessResult(127, HelperMissingStdout, string.Empty))
            .Expect(Ok(DfHeader + "/dev/block/dm-52 " + columns + " 50% /data\n"));

        var exception = await Assert.ThrowsAsync<InternalStorageReadException>(
            () => ReaderFor(runner).ReadAsync(Serial));

        Assert.Equal(InternalStorageReadFailure.InvalidResponse, exception.Failure);
        Assert.False(string.IsNullOrWhiteSpace(exception.Message));
        Assert.InRange(exception.Diagnostic.Length, 1, 512);

        // exit 127 starts exactly one df fallback; the rejected row must not be followed by another query.
        Assert.Equal(2, runner.CommandCount);
        Assert.Equal(HelperArguments, runner.Commands[0].Arguments.ToArray());
        Assert.Equal(DfArguments, runner.Commands[1].Arguments.ToArray());
        Assert.All(runner.Commands, command => Assert.Equal(TimeSpan.FromSeconds(20), command.Timeout));
    }

    // ------------------------------------------------------- helper numeric boundary fallback

    /// <summary>
    /// The device root key and every other helper field stay valid; only the userdata sector count is
    /// negative or zero. That is not an extent the reader may turn into a total, so the one df fallback
    /// must supply the snapshot instead.
    /// </summary>
    [Theory]
    [InlineData("-1")]
    [InlineData("0")]
    public async Task ReadAsync_ValidHelperWithNonPositiveUserdataCount_FallsBackToFileSystem(string sectorCount)
    {
        var snapshot = await ReadAfterInvalidHelperAsync(LayoutJson("2048", sectorCount, "4096"));

        AssertFileSystemFallback(snapshot);
    }

    /// <summary>
    /// <c>startSector + sectorCount</c> must stay representable. A start near <see cref="long.MaxValue"/>
    /// with a count that crosses it is rejected before the extent can be used.
    /// </summary>
    [Fact]
    public async Task ReadAsync_UserdataStartPlusCountOverflows_FallsBackToFileSystem()
    {
        // 9223372036854775800 + 16 > long.MaxValue (9223372036854775807).
        var snapshot = await ReadAfterInvalidHelperAsync(
            LayoutJson("9223372036854775800", "16", "4096"));

        AssertFileSystemFallback(snapshot);
    }

    /// <summary>
    /// The userdata byte total is a checked multiplication. <see cref="long.MaxValue"/> sectors of 512
    /// bytes overflows, so the helper answer is unusable and the df snapshot is used instead.
    /// </summary>
    [Fact]
    public async Task ReadAsync_UserdataBytesMultiplicationOverflows_FallsBackToFileSystem()
    {
        var snapshot = await ReadAfterInvalidHelperAsync(
            LayoutJson("0", "9223372036854775807", "512"));

        AssertFileSystemFallback(snapshot);
    }

    // --------------------------------------------------------------------------- test helpers

    private static async Task<InternalStorageSnapshot> ReadAfterInvalidHelperAsync(string helperJson)
    {
        var runner = new FakeRunner()
            .Expect(Ok(helperJson))
            .Expect(Ok(ValidDf));

        var snapshot = await ReaderFor(runner).ReadAsync(Serial);

        // The helper answer is judged, then exactly one df fallback replaces it; no retry of the helper.
        Assert.Equal(2, runner.CommandCount);
        Assert.Equal(HelperArguments, runner.Commands[0].Arguments.ToArray());
        Assert.Equal(DfArguments, runner.Commands[1].Arguments.ToArray());
        Assert.All(runner.Commands, command => Assert.Equal(TimeSpan.FromSeconds(20), command.Timeout));

        return snapshot;
    }

    private static void AssertFileSystemFallback(InternalStorageSnapshot snapshot)
    {
        // A fallback carries capacity numbers only: no layout, no fingerprint and no invented table.
        Assert.Equal(InternalStorageSource.AndroidFileSystem, snapshot.Source);
        Assert.Equal(SafeTotalBytes, snapshot.TotalBytes);
        Assert.Equal(SafeUsedBytes, snapshot.UsedBytes);
        Assert.Equal(SafeAvailableBytes, snapshot.AvailableBytes);
        Assert.Null(snapshot.Layout);
        Assert.Null(snapshot.TableFingerprint);
    }

    /// <summary>
    /// The T002 <c>inspect_layout</c> shape with one valid boot partition and one userdata extent. The
    /// caller changes only the userdata boundary that the case is about.
    /// </summary>
    private static string LayoutJson(string startSector, string sectorCount, string sectorSize)
    {
        return "{\n" +
            "  \"device\": \"/dev/block/sda\",\n" +
            "  \"sectorSize\": " + sectorSize + ",\n" +
            "  \"tableFingerprint\": \"" + Fingerprint + "\",\n" +
            "  \"partitions\": [\n" +
            "    {\"number\": 1, \"name\": \"boot\", \"startSector\": 2048, \"sectorCount\": 65536, " +
            "\"typeGuid\": \"" + BootTypeGuid + "\", \"partUuid\": \"" + BootUuid + "\"},\n" +
            "    {\"number\": 2, \"name\": \"userdata\", \"startSector\": " + startSector +
            ", \"sectorCount\": " + sectorCount + ", " +
            "\"typeGuid\": \"" + UserdataTypeGuid + "\", \"partUuid\": \"" + UserdataUuid + "\"}\n" +
            "  ]\n" +
            "}";
    }

    private static InternalStorageReader ReaderFor(FakeRunner runner) => new(AdbPath, runner);

    private static ProcessResult Ok(string standardOutput) => new(0, standardOutput, string.Empty);

    /// <summary>
    /// Local command-runner fake. It records every command and hands out canned results in order, so a
    /// missing or extra query fails the assertion instead of silently reaching a real adb.
    /// </summary>
    private sealed class FakeRunner : ICommandRunner
    {
        private readonly Queue<ProcessResult> _results = new();

        internal List<ProcessCommand> Commands { get; } = new();

        internal int CommandCount => Commands.Count;

        internal FakeRunner Expect(ProcessResult result)
        {
            _results.Enqueue(result);
            return this;
        }

        public Task<ProcessResult> RunAsync(ProcessCommand command, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Commands.Add(command);

            Assert.True(
                _results.Count > 0,
                $"unexpected extra command #{Commands.Count}: {command.Executable} {string.Join(' ', command.Arguments)}");

            return Task.FromResult(_results.Dequeue());
        }
    }
}
