using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FreedomInstaller.App;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class OfflineUpdateRecoveryTests
{
    private const string PlanFileName = "plan.json";
    private const string ManifestFileName = "recovery-manifest.json";
    private const string AckFileName = "recovery-ack.json";
    private const string FirstPath = "trust/slots/a/boot.img";
    private const string SecondPath = "recovery-header.bin";

    /// <summary>
    /// The UI export gate accepts exactly the receipt the Core exporter fills
    /// from the same fixture: a prepared top-level state with the nested
    /// awaiting_recovery_export triple. Pinning the two contracts together
    /// keeps a stricter UI check from silently disabling a real export.
    /// </summary>
    [Fact]
    public void UiRecoveryMetadata_AcceptsTheReceiptShapeProducedByTheCoreFixture()
    {
        var fixture = CreateFixture();
        var receipt = JsonSerializer.SerializeToElement(new
        {
            schemaVersion = 1,
            state = "prepared",
            result = new
            {
                state = "awaiting_recovery_export",
                transactionId = fixture.TransactionId,
                planSha256 = fixture.PlanSha256,
                recoveryManifestSha256 = fixture.RecoveryManifestSha256
            }
        });

        Assert.True(OfflineUpdateUiState.TryGetRecoveryMetadata(
            receipt,
            out string? transactionId, out string? planSha256, out string? manifestSha256));
        Assert.Equal(fixture.Context,
            new OfflineUpdateRecoveryContext(transactionId!, fixture.Model, planSha256!, manifestSha256!));
    }

    [Theory]
    [InlineData("TB999XX")]
    [InlineData("tb710fu")]
    public async Task SaveAsync_RejectsAModelOutsideTheOfflineUpgradeListBeforeReadingAnySource(string model)
    {
        using var root = new TestRoot();
        var fixture = CreateFixture(model);
        var sourceCalls = 0;

        Task<Stream> OpenSource(string path, CancellationToken token)
        {
            sourceCalls++;
            return Task.FromResult<Stream>(new MemoryStream());
        }

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            PackageImporter.SaveOfflineUpdateRecoveryAsync(
                root.WorkRoot,
                fixture.Context,
                fixture.PlanBytes,
                fixture.ManifestBytes,
                OpenSource));

        Assert.Equal(0, sourceCalls);
    }

    [Theory]
    [InlineData("TB322FC")]
    [InlineData("TB323FU")]
    [InlineData("TB710FU")]
    public async Task SaveAsync_CopiesAndBindsEveryUpgradeModelWithoutAutomaticCleanup(string model)
    {
        using var root = new TestRoot();
        var fixture = CreateFixture(model);
        var originalNeighbor = File.ReadAllBytes(root.WorkNeighborPath);
        var savedDirectories = new List<string>();

        for (var invocation = 0; invocation < 2; invocation++)
        {
            var calls = new List<string>();
            var streams = new List<TrackingMemoryStream>();
            var reports = new List<OfflineUpdateRecoveryProgress>();
            var progress = new InlineProgress<OfflineUpdateRecoveryProgress>(reports.Add);

            Task<Stream> OpenSource(string path, CancellationToken token)
            {
                calls.Add(path);
                var payload = fixture.Files.Single(file => file.Path == path).Bytes;
                var stream = new TrackingMemoryStream(payload, writable: false);
                streams.Add(stream);
                return Task.FromResult<Stream>(stream);
            }

            var result = await PackageImporter.SaveOfflineUpdateRecoveryAsync(
                root.WorkRoot,
                fixture.Context,
                fixture.PlanBytes,
                fixture.ManifestBytes,
                OpenSource,
                progress);

            Assert.False((object)result is IDisposable);
            Assert.True(Directory.Exists(result.DirectoryPath));
            Assert.Equal(result.DirectoryPath, Path.GetDirectoryName(result.PlanPath));
            Assert.Equal(result.DirectoryPath, Path.GetDirectoryName(result.ManifestPath));
            Assert.Equal(fixture.PlanBytes, File.ReadAllBytes(result.PlanPath));
            Assert.Equal(fixture.ManifestBytes, File.ReadAllBytes(result.ManifestPath));
            Assert.Equal(fixture.Files.Select(file => file.Path), calls);
            Assert.All(streams, stream => Assert.True(stream.Disposed));

            foreach (var file in fixture.Files)
            {
                var storedPath = Path.Combine(
                    result.DirectoryPath,
                    file.Path.Replace('/', Path.DirectorySeparatorChar));
                var storedBytes = File.ReadAllBytes(storedPath);
                Assert.Equal(file.Bytes, storedBytes);
                Assert.Equal(file.Sha256, Sha256(storedBytes));
            }

            var totalBytes = fixture.Files.Sum(file => (long)file.Bytes.Length);
            Assert.Equal(2, reports.Count);
            Assert.Equal(FirstPath, reports[0].RelativePath);
            Assert.Equal(fixture.Files[0].Bytes.Length, reports[0].BytesCompleted);
            Assert.Equal(totalBytes, reports[0].TotalBytes);
            Assert.Equal(SecondPath, reports[1].RelativePath);
            Assert.Equal(totalBytes, reports[1].BytesCompleted);
            Assert.Equal(totalBytes, reports[1].TotalBytes);

            AssertAcknowledgement(result, fixture);
            Assert.Equal(originalNeighbor, File.ReadAllBytes(root.WorkNeighborPath));
            Assert.Equal(root.NeighborContents, File.ReadAllBytes(root.RootNeighborPath));
            Assert.True(Directory.Exists(root.WorkRoot));
            savedDirectories.Add(result.DirectoryPath);
        }

        Assert.NotEqual(savedDirectories[0], savedDirectories[1]);
        Assert.Equal(2, FindStages(root).Count);
        Assert.Equal(
            File.ReadAllBytes(Path.Combine(savedDirectories[0], SecondPath)),
            File.ReadAllBytes(Path.Combine(savedDirectories[1], SecondPath)));
    }

    [Fact]
    public async Task Catalog_SkipsAForeignCandidateAndStillFindsTheLaterValidBundle()
    {
        using var root = new TestRoot();
        string descriptorSha = new('d', 64);
        var fixture = CreateBoundFixture(descriptorSha);
        string validDirectory = await SaveBundleAsync(root.WorkRoot, fixture);

        // A leftover with an acknowledgement but without this transaction's
        // metadata sorts first; it must be reported, left byte-identical and
        // must not hide the valid bundle behind it.
        string foreignDirectory = Path.Combine(root.WorkRoot, "aaa-foreign");
        Directory.CreateDirectory(foreignDirectory);
        string foreignAck = Path.Combine(foreignDirectory, AckFileName);
        File.WriteAllText(foreignAck, "{}");
        byte[] foreignBytes = File.ReadAllBytes(foreignAck);

        var scan = OfflineUpdateRecoveryCatalog.Scan(root.WorkRoot, fixture.Context, descriptorSha);

        Assert.Equal(validDirectory, scan.Recovery?.DirectoryPath);
        var skipped = Assert.Single(scan.Skipped);
        Assert.Equal(foreignDirectory, skipped.DirectoryPath);
        Assert.False(string.IsNullOrWhiteSpace(skipped.Reason));
        Assert.Equal(foreignBytes, File.ReadAllBytes(foreignAck));
        Assert.True(Directory.Exists(foreignDirectory));
    }

    [Fact]
    public async Task Catalog_SkipsADamagedBundleAndKeepsItInPlace()
    {
        using var root = new TestRoot();
        string descriptorSha = new('d', 64);
        var fixture = CreateBoundFixture(descriptorSha);
        string damagedDirectory = await SaveBundleAsync(root.WorkRoot, fixture);

        // The bundle was acknowledged once, then one payload file changed.
        string payloadPath = Path.Combine(
            damagedDirectory, FirstPath.Replace('/', Path.DirectorySeparatorChar));
        File.WriteAllBytes(payloadPath, MutateFirstByte(File.ReadAllBytes(payloadPath)));
        byte[] damagedSnapshot = File.ReadAllBytes(payloadPath);

        // Keep the damaged candidate first in ordinal order so the valid
        // bundle behind it is what proves the scan keeps going.
        string damagedCandidate = Path.Combine(root.WorkRoot, "aaa-damaged");
        Directory.Move(damagedDirectory, damagedCandidate);
        payloadPath = Path.Combine(
            damagedCandidate, FirstPath.Replace('/', Path.DirectorySeparatorChar));

        string validDirectory = await SaveBundleAsync(root.WorkRoot, fixture);

        var scan = OfflineUpdateRecoveryCatalog.Scan(root.WorkRoot, fixture.Context, descriptorSha);

        Assert.Equal(validDirectory, scan.Recovery?.DirectoryPath);
        var skipped = Assert.Single(scan.Skipped);
        Assert.Equal(damagedCandidate, skipped.DirectoryPath);
        Assert.Equal(damagedSnapshot, File.ReadAllBytes(payloadPath));
        Assert.True(File.Exists(Path.Combine(damagedCandidate, AckFileName)));
    }

    [Fact]
    public void Catalog_AllCandidatesInvalid_ReturnsNullInOrdinalOrderAndLeavesThemAckIntact()
    {
        using var root = new TestRoot();
        var context = new OfflineUpdateRecoveryContext(
            Guid.NewGuid().ToString("D"), "TB322FC", new string('a', 64), new string('b', 64));
        string descriptorSha = new('d', 64);

        string foreign = Path.Combine(root.WorkRoot, "a-foreign");
        Directory.CreateDirectory(foreign);
        File.WriteAllText(Path.Combine(foreign, AckFileName), "{}");

        // An empty acknowledgement is not evidence: it may never unlock
        // execution, so the bundle stays unusable and untouched.
        string emptyAck = Path.Combine(root.WorkRoot, "b-empty-ack");
        Directory.CreateDirectory(emptyAck);
        File.WriteAllBytes(Path.Combine(emptyAck, AckFileName), Array.Empty<byte>());

        // A directory without an acknowledgement is not a candidate at all.
        string noAck = Path.Combine(root.WorkRoot, "c-no-ack");
        Directory.CreateDirectory(noAck);
        File.WriteAllText(Path.Combine(noAck, PlanFileName), "{}");

        var scan = OfflineUpdateRecoveryCatalog.Scan(root.WorkRoot, context, descriptorSha);

        Assert.Null(scan.Recovery);
        Assert.Equal(new[] { foreign, emptyAck }, scan.Skipped.Select(entry => entry.DirectoryPath));
        Assert.True(File.Exists(Path.Combine(foreign, AckFileName)));
        Assert.True(File.Exists(Path.Combine(emptyAck, AckFileName)));
        Assert.True(File.Exists(Path.Combine(noAck, PlanFileName)));
    }

    [Fact]
    public void Catalog_MissingRoot_ReturnsNullWithoutReportingACandidate()
    {
        using var root = new TestRoot();
        var context = new OfflineUpdateRecoveryContext(
            Guid.NewGuid().ToString("D"), "TB322FC", new string('a', 64), new string('b', 64));

        var scan = OfflineUpdateRecoveryCatalog.Scan(
            Path.Combine(root.Root, "absent"), context, new string('d', 64));

        Assert.Null(scan.Recovery);
        Assert.Empty(scan.Skipped);
    }

    [Fact]
    public void Catalog_CancelledToken_ThrowsAndReportsNothing()
    {
        using var root = new TestRoot();
        var context = new OfflineUpdateRecoveryContext(
            Guid.NewGuid().ToString("D"), "TB322FC", new string('a', 64), new string('b', 64));
        string foreign = Path.Combine(root.WorkRoot, "a-foreign");
        Directory.CreateDirectory(foreign);
        File.WriteAllText(Path.Combine(foreign, AckFileName), "{}");

        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        Assert.ThrowsAny<OperationCanceledException>(() => OfflineUpdateRecoveryCatalog.Scan(
            root.WorkRoot, context, new string('d', 64), cancelled.Token));
        Assert.True(File.Exists(Path.Combine(foreign, AckFileName)));
    }

    [Fact]
    public async Task MetadataAndBindingFailures_AreRejectedBeforeSourceOrStageCreation()
    {
        var cases = new[]
        {
            "plan-hash",
            "manifest-hash",
            "plan-transaction",
            "manifest-transaction",
            "plan-model",
            "manifest-model",
            "policy",
            "plan-schema",
            "manifest-schema",
            "missing-model-with-alias",
            "duplicate-json-property"
        };

        foreach (var testCase in cases)
        {
            using var root = new TestRoot();
            var fixture = CreateFixture();
            var sourceCalls = 0;

            switch (testCase)
            {
                case "plan-hash":
                    fixture.PlanSha256 = new string('0', 64);
                    break;
                case "manifest-hash":
                    fixture.RecoveryManifestSha256 = new string('0', 64);
                    break;
                case "plan-transaction":
                    SetPlan(fixture, ReplaceRequired(
                        Text(fixture.PlanBytes),
                        $"\"transactionId\": \"{fixture.TransactionId}\"",
                        $"\"transactionId\": \"{Guid.NewGuid():D}\""));
                    break;
                case "manifest-transaction":
                    SetManifest(fixture, ReplaceRequired(
                        Text(fixture.ManifestBytes),
                        $"\"transactionId\": \"{fixture.TransactionId}\"",
                        $"\"transactionId\": \"{Guid.NewGuid():D}\""));
                    break;
                case "plan-model":
                    SetPlan(fixture, ReplaceRequired(
                        Text(fixture.PlanBytes),
                        "\"model\": \"TB322FC\"",
                        "\"model\": \"TB323FU\""));
                    break;
                case "manifest-model":
                    SetManifest(fixture, ReplaceRequired(
                        Text(fixture.ManifestBytes),
                        "\"model\": \"TB322FC\"",
                        "\"model\": \"TB323FU\""));
                    break;
                case "policy":
                    SetPlan(fixture, ReplaceRequired(
                        Text(fixture.PlanBytes),
                        "\"policy\": \"offline-dual\"",
                        "\"policy\": \"offline-single\""));
                    break;
                case "plan-schema":
                    SetPlan(fixture, ReplaceRequired(
                        Text(fixture.PlanBytes),
                        "\"schemaVersion\": 1",
                        "\"schemaVersion\": 2"));
                    break;
                case "manifest-schema":
                    SetManifest(fixture, ReplaceRequired(
                        Text(fixture.ManifestBytes),
                        "\"schemaVersion\": 1",
                        "\"schemaVersion\": 2"));
                    break;
                case "missing-model-with-alias":
                    SetPlan(fixture, ReplaceRequired(
                        Text(fixture.PlanBytes),
                        "\"model\": \"TB322FC\"",
                        "\"deviceModel\": \"TB322FC\""));
                    break;
                case "duplicate-json-property":
                    SetPlan(fixture, ReplaceRequired(
                        Text(fixture.PlanBytes),
                        "\"operation\": \"offline-upgrade\",",
                        "\"operation\": \"offline-upgrade\",\n  \"operation\": \"offline-upgrade\","));
                    break;
            }

            Task<Stream> OpenSource(string path, CancellationToken token)
            {
                sourceCalls++;
                throw new UnreachableException("Validation must precede source opening.");
            }

            await Assert.ThrowsAsync<InvalidDataException>(() =>
                PackageImporter.SaveOfflineUpdateRecoveryAsync(
                    root.WorkRoot,
                    fixture.Context,
                    fixture.PlanBytes,
                    fixture.ManifestBytes,
                    OpenSource));

            Assert.Equal(0, sourceCalls);
            Assert.Empty(FindStages(root));
            Assert.Equal(root.NeighborContents, File.ReadAllBytes(root.RootNeighborPath));
            Assert.Equal(root.WorkNeighborContents, File.ReadAllBytes(root.WorkNeighborPath));
        }
    }

    public static IEnumerable<object[]> InvalidPortablePaths()
    {
        yield return new object[] { "../outside.bin" };
        yield return new object[] { "/absolute.bin" };
        yield return new object[] { "trust\\slots\\boot.img" };
        yield return new object[] { "C:/boot.img" };
        yield return new object[] { "trust/<bad>.img" };
        yield return new object[] { "trust/>bad.img" };
        yield return new object[] { "trust/pipe|bad.img" };
        yield return new object[] { "trust/question?.img" };
        yield return new object[] { "trust/star*.img" };
        yield return new object[] { "trust/quote\"bad.img" };
        yield return new object[] { "trust/CON.txt" };
        yield return new object[] { "trust/trailing./boot.img" };
        yield return new object[] { "trust/trailing /boot.img" };
        yield return new object[] { "trust//boot.img" };
        yield return new object[] { ManifestFileName };
        yield return new object[] { "case-collision" };
    }

    [Theory]
    [MemberData(nameof(InvalidPortablePaths))]
    public async Task InvalidPortablePathsAndCaseCollisions_NeverOpenSources(string invalidPath)
    {
        using var root = new TestRoot();
        RecoveryFixture fixture;

        if (invalidPath == "case-collision")
        {
            fixture = CreateFixture(files: new[]
            {
                new RecoveryPayload(FirstPath, Bytes(4097, 1)),
                new RecoveryPayload(FirstPath.ToUpperInvariant(), Bytes(1029, 73))
            });
        }
        else
        {
            fixture = CreateFixture(files: new[]
            {
                new RecoveryPayload(invalidPath, Bytes(4097, 1))
            });
        }

        var sourceCalls = 0;
        Task<Stream> OpenSource(string path, CancellationToken token)
        {
            sourceCalls++;
            throw new UnreachableException("Portable path validation must precede source opening.");
        }

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            PackageImporter.SaveOfflineUpdateRecoveryAsync(
                root.WorkRoot,
                fixture.Context,
                fixture.PlanBytes,
                fixture.ManifestBytes,
                OpenSource));

        Assert.Equal(0, sourceCalls);
        Assert.Empty(FindStages(root));
    }

    [Theory]
    [InlineData("short")]
    [InlineData("oversized")]
    [InlineData("same-size-wrong-hash")]
    public async Task BadSourceContent_DisposesSourceAndRemovesTheNewAttemptWithoutAck(string mode)
    {
        using var root = new TestRoot();
        var fixture = CreateFixture(files: new[]
        {
            new RecoveryPayload(FirstPath, Bytes(8193, 19))
        });
        var original = (byte[])fixture.Files[0].Bytes.Clone();
        var supplied = mode switch
        {
            "short" => original[..^1],
            "oversized" => original.Concat(new byte[] { 0x5a }).ToArray(),
            _ => MutateFirstByte(original)
        };
        TrackingMemoryStream? remote = null;
        string? attempt = null;
        var calls = new List<string>();

        Task<Stream> OpenSource(string path, CancellationToken token)
        {
            calls.Add(path);
            attempt = Assert.Single(FindStages(root));
            remote = new TrackingMemoryStream(supplied, writable: false);
            return Task.FromResult<Stream>(remote);
        }

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            PackageImporter.SaveOfflineUpdateRecoveryAsync(
                root.WorkRoot,
                fixture.Context,
                fixture.PlanBytes,
                fixture.ManifestBytes,
                OpenSource));

        Assert.Equal(new[] { FirstPath }, calls);
        Assert.NotNull(remote);
        Assert.True(remote.Disposed);
        Assert.NotNull(attempt);
        Assert.False(Directory.Exists(attempt));
        Assert.Empty(FindStages(root));
        Assert.False(File.Exists(Path.Combine(attempt, AckFileName)));
        Assert.Equal(original, fixture.Files[0].Bytes);
        Assert.Equal(root.WorkNeighborContents, File.ReadAllBytes(root.WorkNeighborPath));
    }

    [Fact]
    public async Task CancellationAndSynchronousProgressFailure_LeaveNoAckAndPreserveCause()
    {
        using (var root = new TestRoot())
        {
            var fixture = CreateFixture();
            using var cancelled = new CancellationTokenSource();
            cancelled.Cancel();
            var sourceCalls = 0;

            Task<Stream> OpenSource(string path, CancellationToken token)
            {
                sourceCalls++;
                throw new UnreachableException();
            }

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                PackageImporter.SaveOfflineUpdateRecoveryAsync(
                    root.WorkRoot,
                    fixture.Context,
                    fixture.PlanBytes,
                    fixture.ManifestBytes,
                    OpenSource,
                    token: cancelled.Token));
            Assert.Equal(0, sourceCalls);
            Assert.Empty(FindStages(root));
        }

        using (var root = new TestRoot())
        {
            var fixture = CreateFixture(files: new[]
            {
                new RecoveryPayload(FirstPath, Bytes(8193, 31))
            });
            using var cancellation = new CancellationTokenSource();
            CancelAfterReadMemoryStream? remote = null;
            string? attempt = null;

            Task<Stream> OpenSource(string path, CancellationToken token)
            {
                attempt = Assert.Single(FindStages(root));
                remote = new CancelAfterReadMemoryStream(fixture.Files[0].Bytes, cancellation);
                return Task.FromResult<Stream>(remote);
            }

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                PackageImporter.SaveOfflineUpdateRecoveryAsync(
                    root.WorkRoot,
                    fixture.Context,
                    fixture.PlanBytes,
                    fixture.ManifestBytes,
                    OpenSource,
                    token: cancellation.Token));
            Assert.NotNull(remote);
            Assert.True(remote.Disposed);
            Assert.NotNull(attempt);
            Assert.False(Directory.Exists(attempt));
            Assert.Empty(FindStages(root));
        }

        using (var root = new TestRoot())
        {
            var fixture = CreateFixture(files: new[]
            {
                new RecoveryPayload(FirstPath, Bytes(8193, 47))
            });
            var cause = new InlineProgressException("inline progress failed");
            var progress = new InlineProgress<OfflineUpdateRecoveryProgress>(_ => throw cause);
            TrackingMemoryStream? remote = null;
            string? attempt = null;

            Task<Stream> OpenSource(string path, CancellationToken token)
            {
                attempt = Assert.Single(FindStages(root));
                remote = new TrackingMemoryStream(fixture.Files[0].Bytes, writable: false);
                return Task.FromResult<Stream>(remote);
            }

            var actual = await Assert.ThrowsAsync<InlineProgressException>(() =>
                PackageImporter.SaveOfflineUpdateRecoveryAsync(
                    root.WorkRoot,
                    fixture.Context,
                    fixture.PlanBytes,
                    fixture.ManifestBytes,
                    OpenSource,
                    progress));
            Assert.Same(cause, actual);
            Assert.NotNull(remote);
            Assert.True(remote.Disposed);
            Assert.NotNull(attempt);
            Assert.False(Directory.Exists(attempt));
            Assert.Empty(FindStages(root));
        }
    }

    [Fact]
    public async Task ReadbackTamperOpenFailureAndInvalidMetadataLength_DoNotProduceAck()
    {
        using (var root = new TestRoot())
        {
            var fixture = CreateFixture(files: new[]
            {
                new RecoveryPayload(FirstPath, Bytes(8193, 61))
            });
            TamperOnDisposeMemoryStream? remote = null;
            var calls = new List<string>();
            string? attempt = null;

            Task<Stream> OpenSource(string path, CancellationToken token)
            {
                calls.Add(path);
                attempt = Assert.Single(FindStages(root));
                var target = Path.Combine(attempt, FirstPath.Replace('/', Path.DirectorySeparatorChar));
                remote = new TamperOnDisposeMemoryStream(fixture.Files[0].Bytes, target);
                return Task.FromResult<Stream>(remote);
            }

            await Assert.ThrowsAsync<InvalidDataException>(() =>
                PackageImporter.SaveOfflineUpdateRecoveryAsync(
                    root.WorkRoot,
                    fixture.Context,
                    fixture.PlanBytes,
                    fixture.ManifestBytes,
                    OpenSource));
            Assert.Equal(new[] { FirstPath }, calls);
            Assert.NotNull(remote);
            Assert.True(remote.Disposed);
            Assert.True(remote.Tampered);
            Assert.NotNull(attempt);
            Assert.False(Directory.Exists(attempt));
            Assert.Empty(FindStages(root));
        }

        using (var root = new TestRoot())
        {
            var fixture = CreateFixture();
            var cause = new SourceOpenException("source open failed");

            Task<Stream> OpenSource(string path, CancellationToken token) => throw cause;

            var actual = await Assert.ThrowsAsync<SourceOpenException>(() =>
                PackageImporter.SaveOfflineUpdateRecoveryAsync(
                    root.WorkRoot,
                    fixture.Context,
                    fixture.PlanBytes,
                    fixture.ManifestBytes,
                    OpenSource));
            Assert.Same(cause, actual);
            Assert.Empty(FindStages(root));
        }

        using (var root = new TestRoot())
        {
            var fixture = CreateFixture();
            fixture.ManifestBytes = Array.Empty<byte>();
            fixture.RecoveryManifestSha256 = Sha256(fixture.ManifestBytes);
            var sourceCalls = 0;

            Task<Stream> OpenSource(string path, CancellationToken token)
            {
                sourceCalls++;
                throw new UnreachableException();
            }

            await Assert.ThrowsAsync<InvalidDataException>(() =>
                PackageImporter.SaveOfflineUpdateRecoveryAsync(
                    root.WorkRoot,
                    fixture.Context,
                    fixture.PlanBytes,
                    fixture.ManifestBytes,
                    OpenSource));
            Assert.Equal(0, sourceCalls);
            Assert.Empty(FindStages(root));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedAttempt_RemovesOnlyTheNewAttemptAndKeepsTheExistingBundle(bool cancel)
    {
        using var root = new TestRoot();
        var fixture = CreateFixture();
        string existing = await SaveBundleAsync(root.WorkRoot, fixture);
        string existingAck = Path.Combine(existing, AckFileName);
        string existingPayload = Path.Combine(existing, FirstPath.Replace('/', Path.DirectorySeparatorChar));
        byte[] ackBefore = File.ReadAllBytes(existingAck);
        byte[] payloadBefore = File.ReadAllBytes(existingPayload);

        var failing = CreateFixture(files: new[] { new RecoveryPayload(FirstPath, Bytes(8193, 19)) });
        using var cancellation = new CancellationTokenSource();
        string? attempt = null;

        Task<Stream> OpenSource(string path, CancellationToken token)
        {
            attempt = FindStages(root).Single(stage => !string.Equals(stage, existing, StringComparison.Ordinal));
            return Task.FromResult<Stream>(cancel
                ? new CancelAfterReadMemoryStream(failing.Files[0].Bytes, cancellation)
                : new MemoryStream(failing.Files[0].Bytes[..^1], writable: false));
        }

        Func<Task> save = () => PackageImporter.SaveOfflineUpdateRecoveryAsync(
            root.WorkRoot,
            failing.Context,
            failing.PlanBytes,
            failing.ManifestBytes,
            OpenSource,
            token: cancel ? cancellation.Token : default);

        if (cancel)
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(save);
        }
        else
        {
            await Assert.ThrowsAsync<InvalidDataException>(save);
        }

        Assert.NotNull(attempt);
        Assert.False(Directory.Exists(attempt));
        Assert.Equal(new[] { existing }, FindStages(root));
        Assert.Equal(ackBefore, File.ReadAllBytes(existingAck));
        Assert.Equal(payloadBefore, File.ReadAllBytes(existingPayload));
    }

    [Fact]
    public async Task FailedAttempt_WhenCleanupValidationFails_KeepsTheOriginalErrorAndTheExistingBundle()
    {
        using var root = new TestRoot();
        var fixture = CreateFixture();
        string existing = await SaveBundleAsync(root.WorkRoot, fixture);
        string existingAck = Path.Combine(existing, AckFileName);
        string existingPayload = Path.Combine(existing, FirstPath.Replace('/', Path.DirectorySeparatorChar));
        byte[] ackBefore = File.ReadAllBytes(existingAck);
        byte[] payloadBefore = File.ReadAllBytes(existingPayload);

        var failing = CreateFixture(files: new[] { new RecoveryPayload(FirstPath, Bytes(8193, 19)) });
        var cause = new SourceOpenException("source open failed");
        string? attempt = null;

        Task<Stream> OpenSource(string path, CancellationToken token)
        {
            attempt = FindStages(root).Single(stage => !string.Equals(stage, existing, StringComparison.Ordinal));

            // Replace the private attempt directory with a file: the cleanup
            // guard revalidates the path, refuses it with InvalidDataException
            // and must not replace the real failure.
            Directory.Delete(attempt, recursive: true);
            File.WriteAllText(attempt, "not a directory");
            throw cause;
        }

        var actual = await Assert.ThrowsAsync<SourceOpenException>(() =>
            PackageImporter.SaveOfflineUpdateRecoveryAsync(
                root.WorkRoot,
                failing.Context,
                failing.PlanBytes,
                failing.ManifestBytes,
                OpenSource));

        Assert.Same(cause, actual);
        Assert.NotNull(attempt);
        Assert.True(File.Exists(attempt));
        Assert.Equal(new[] { existing }, FindStages(root));
        Assert.Equal(ackBefore, File.ReadAllBytes(existingAck));
        Assert.Equal(payloadBefore, File.ReadAllBytes(existingPayload));
    }

    [LinuxFact]
    public async Task LoadCanonicalizesLinkedAncestorsLikeSaveAndRejectsLinkNodes()
    {
        using var root = new TestRoot();
        string descriptorSha = new('d', 64);
        var fixture = CreateBoundFixture(descriptorSha);

        string realParent = Path.Combine(root.Root, "real-parent");
        string workRoot = Path.Combine(realParent, "work");
        Directory.CreateDirectory(workRoot);
        string linkParent = Path.Combine(root.Root, "linked-parent");
        Directory.CreateSymbolicLink(linkParent, realParent);
        string linkedWork = Path.Combine(linkParent, "work");

        // Saving through the linked ancestor stores the canonical path, and loading back through the
        // same link has to resolve to exactly that path.
        string saved = await SaveBundleAsync(linkedWork, fixture);
        Assert.True(
            saved.StartsWith(Path.GetFullPath(workRoot) + Path.DirectorySeparatorChar, StringComparison.Ordinal),
            saved);

        var loaded = PackageImporter.LoadOfflineUpdateRecovery(
            Path.Combine(linkedWork, Path.GetFileName(saved)), fixture.Context, descriptorSha);
        Assert.Equal(saved, loaded.DirectoryPath);

        // A bundle directory that is itself a link is never followed.
        string linkedBundle = Path.Combine(workRoot, "linked-bundle");
        Directory.CreateSymbolicLink(linkedBundle, saved);
        Assert.Throws<InvalidDataException>(() => PackageImporter.LoadOfflineUpdateRecovery(
            linkedBundle, fixture.Context, descriptorSha));

        // Neither is a link anywhere below the bundle directory.
        string shared = Path.Combine(root.Root, "shared-target");
        Directory.CreateDirectory(shared);
        Directory.CreateSymbolicLink(Path.Combine(saved, "linked-descendant"), shared);
        Assert.Throws<InvalidDataException>(() => PackageImporter.LoadOfflineUpdateRecovery(
            saved, fixture.Context, descriptorSha));
    }

    [Fact]
    public void LoadMissingBundle_ReportsInvalidWithoutCreatingRoots()
    {
        using var root = new TestRoot();
        var context = new OfflineUpdateRecoveryContext(
            Guid.NewGuid().ToString("D"), "TB322FC", new string('a', 64), new string('b', 64));
        string missing = Path.Combine(root.WorkRoot, "absent-bundle");

        Assert.Throws<InvalidDataException>(() =>
            PackageImporter.LoadOfflineUpdateRecovery(missing, context, new string('d', 64)));

        Assert.False(Directory.Exists(missing));
        Assert.Equal(root.WorkNeighborContents, File.ReadAllBytes(root.WorkNeighborPath));
    }

    /// <summary>
    /// The existing fixture plan omits the package binding that the strict
    /// loader re-checks, so add it and rebuild the plan digest exactly as the
    /// device's exported plan.json carries it.
    /// </summary>
    private static RecoveryFixture CreateBoundFixture(string descriptorSha, string model = "TB322FC")
    {
        var fixture = CreateFixture(model);
        SetPlan(fixture, ReplaceRequired(
            Text(fixture.PlanBytes),
            "\"recoveryManifestSha256\"",
            $"\"packageDescriptorSha256\": \"{descriptorSha}\",\n  \"recoveryManifestSha256\""));
        return fixture;
    }

    private static async Task<string> SaveBundleAsync(
        string sessionRoot, RecoveryFixture fixture, CancellationToken token = default)
    {
        Task<Stream> OpenSource(string path, CancellationToken ct)
        {
            var payload = fixture.Files.Single(file => file.Path == path).Bytes;
            return Task.FromResult<Stream>(new MemoryStream(payload, writable: false));
        }

        var saved = await PackageImporter.SaveOfflineUpdateRecoveryAsync(
            sessionRoot, fixture.Context, fixture.PlanBytes, fixture.ManifestBytes, OpenSource, token: token);
        return saved.DirectoryPath;
    }

    private static RecoveryFixture CreateFixture(
        string model = "TB322FC",
        IReadOnlyList<RecoveryPayload>? files = null)
    {
        files ??= new[]
        {
            new RecoveryPayload(FirstPath, Bytes(8193, 1)),
            new RecoveryPayload(SecondPath, Bytes(1027, 79))
        };
        var transactionId = Guid.NewGuid().ToString("D");
        var manifestSha = new string('0', 64);
        var planText = $$"""
{
  "schemaVersion": 1,
  "operation": "offline-upgrade",
  "transactionId": "{{transactionId}}",
  "model": "{{model}}",
  "policy": "offline-dual",
  "recoveryManifestSha256": "{{manifestSha}}"
}
""";
        var entries = string.Join(",\n", files.Select((file, index) => $$"""
    {
      "path": {{JsonSerializer.Serialize(file.Path)}},
      "bytes": {{file.Bytes.Length}},
      "sha256": "{{file.Sha256}}",
      "kind": "{{(index == 0 ? "slot-image" : "recovery-header")}}"
    }
"""));
        var manifestText = $$"""
{
  "schemaVersion": 1,
  "operation": "offline-upgrade",
  "transactionId": "{{transactionId}}",
  "model": "{{model}}",
  "files": [
{{entries}}
  ]
}
""";
        var manifestBytes = Utf8(manifestText);
        manifestSha = Sha256(manifestBytes);
        planText = planText.Replace(new string('0', 64), manifestSha, StringComparison.Ordinal);
        var planBytes = Utf8(planText);
        return new RecoveryFixture(transactionId, model, files, planBytes, manifestBytes);
    }

    private static void SetPlan(RecoveryFixture fixture, string planText)
    {
        fixture.PlanBytes = Utf8(planText);
        fixture.PlanSha256 = Sha256(fixture.PlanBytes);
    }

    private static void SetManifest(RecoveryFixture fixture, string manifestText)
    {
        fixture.ManifestBytes = Utf8(manifestText);
        var oldManifestSha = fixture.RecoveryManifestSha256;
        fixture.RecoveryManifestSha256 = Sha256(fixture.ManifestBytes);
        SetPlan(fixture, ReplaceRequired(
            Text(fixture.PlanBytes),
            oldManifestSha,
            fixture.RecoveryManifestSha256));
    }


    private static void AssertAcknowledgement(SavedOfflineUpdateRecovery result, RecoveryFixture fixture)
    {
        var ackPath = Path.Combine(result.DirectoryPath, AckFileName);
        var ackBytes = File.ReadAllBytes(ackPath);
        Assert.Equal(result.Acknowledgement, ackBytes);
        using var document = JsonDocument.Parse(Text(ackBytes));
        var root = document.RootElement;

        Assert.Equal(
            new[] { "schemaVersion", "operation", "transactionId", "planSha256", "recoveryManifestSha256", "files" },
            root.EnumerateObject().Select(property => property.Name));

        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("offline-upgrade", root.GetProperty("operation").GetString());
        Assert.Equal(fixture.TransactionId, root.GetProperty("transactionId").GetString());
        Assert.Equal(fixture.PlanSha256, root.GetProperty("planSha256").GetString());
        Assert.Equal(fixture.RecoveryManifestSha256, root.GetProperty("recoveryManifestSha256").GetString());

        var entries = root.GetProperty("files").EnumerateArray().ToList();
        Assert.Equal(fixture.Files.Count, entries.Count);
        for (var index = 0; index < fixture.Files.Count; index++)
        {
            var entry = entries[index];
            Assert.Equal(
                new[] { "path", "bytes", "sha256" },
                entry.EnumerateObject().Select(property => property.Name));
            Assert.Equal(fixture.Files[index].Path, entry.GetProperty("path").GetString());
            Assert.Equal(fixture.Files[index].Bytes.Length, entry.GetProperty("bytes").GetInt64());
            Assert.Equal(fixture.Files[index].Sha256, entry.GetProperty("sha256").GetString());
        }
    }

    private sealed record RecoveryPayload(string Path, byte[] Bytes)
    {
        public string Sha256 => OfflineUpdateRecoveryTests.Sha256(Bytes);
    }

    private sealed class RecoveryFixture
    {
        public RecoveryFixture(
            string transactionId,
            string model,
            IReadOnlyList<RecoveryPayload> files,
            byte[] planBytes,
            byte[] manifestBytes)
        {
            TransactionId = transactionId;
            Model = model;
            Files = files;
            PlanBytes = planBytes;
            ManifestBytes = manifestBytes;
            PlanSha256 = Sha256(planBytes);
            RecoveryManifestSha256 = Sha256(manifestBytes);
        }

        public byte[] PlanBytes { get; set; }
        public byte[] ManifestBytes { get; set; }
        public string PlanSha256 { get; set; }
        public string RecoveryManifestSha256 { get; set; }
        public string TransactionId { get; }
        public string Model { get; }
        public IReadOnlyList<RecoveryPayload> Files { get; }

        public OfflineUpdateRecoveryContext Context => new(
            TransactionId,
            Model,
            PlanSha256,
            RecoveryManifestSha256);
    }

    private sealed class TestRoot : IDisposable
    {
        private static readonly string BaseRoot =
            Environment.GetEnvironmentVariable("TEST_ARTIFACT_ROOT") is { Length: > 0 } value
                ? value
                : Path.GetTempPath();

        public TestRoot()
        {
            var unique = $"offline-recovery-tests-{Guid.NewGuid():D}";
            Root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.Combine(BaseRoot, unique)));
            Directory.CreateDirectory(Root);
            WorkRoot = Path.Combine(Root, "work");
            Directory.CreateDirectory(WorkRoot);
            WorkNeighborContents = Bytes(521, 101);
            WorkNeighborPath = Path.Combine(WorkRoot, "neighbor.bin");
            File.WriteAllBytes(WorkNeighborPath, WorkNeighborContents);
            NeighborContents = Bytes(733, 202);
            RootNeighborPath = Path.Combine(Root, "neighbor-root.bin");
            File.WriteAllBytes(RootNeighborPath, NeighborContents);
        }

        public string Root { get; }
        public string WorkRoot { get; }
        public string WorkNeighborPath { get; }
        public byte[] WorkNeighborContents { get; }
        public string RootNeighborPath { get; }
        public byte[] NeighborContents { get; }

        public void Dispose()
        {
            var canonicalRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Root));
            var canonicalBase = Path.TrimEndingDirectorySeparator(Path.GetFullPath(BaseRoot));
            var parent = Directory.GetParent(canonicalRoot)?.FullName;
            var canonicalParent = parent is null ? null : Path.TrimEndingDirectorySeparator(Path.GetFullPath(parent));
            if (!string.Equals(canonicalRoot, canonicalBase, StringComparison.Ordinal) &&
                string.Equals(canonicalParent, canonicalBase, StringComparison.Ordinal) &&
                Directory.Exists(canonicalRoot))
            {
                Directory.Delete(canonicalRoot, recursive: true);
            }
        }
    }

    private static List<string> FindStages(TestRoot root) =>
        Directory.EnumerateDirectories(root.WorkRoot, "offline-update-*")
            .ToList();

    private static byte[] Utf8(string text) => Encoding.UTF8.GetBytes(text);

    private static string Text(byte[] bytes) => Encoding.UTF8.GetString(bytes);

    private static string Sha256(byte[] bytes)
    {
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static byte[] Bytes(int length, int seed)
    {
        var data = new byte[length];
        for (var index = 0; index < data.Length; index++)
        {
            data[index] = (byte)((seed * 31 + index * 7 + 1) % 255 + 1);
        }

        return data;
    }

    private static byte[] MutateFirstByte(byte[] source)
    {
        var copy = (byte[])source.Clone();
        copy[0] = (byte)(copy[0] ^ 0xff);
        return copy;
    }

    private static string ReplaceRequired(string text, string old, string @new)
    {
        var first = text.IndexOf(old, StringComparison.Ordinal);
        Assert.True(first >= 0, $"Expected fragment not found: {old}");
        Assert.Equal(first, text.LastIndexOf(old, StringComparison.Ordinal));
        return text.Remove(first, old.Length).Insert(first, @new);
    }

    private sealed class InlineProgress<T> : IProgress<T>
    {
        private readonly Action<T> report;

        public InlineProgress(Action<T> report) => this.report = report;

        public void Report(T value) => report(value);
    }

    private sealed class InlineProgressException : Exception
    {
        public InlineProgressException(string message) : base(message)
        {
        }
    }

    private sealed class SourceOpenException : Exception
    {
        public SourceOpenException(string message) : base(message)
        {
        }
    }

    private class TrackingMemoryStream : MemoryStream
    {
        private int disposed;

        public TrackingMemoryStream(byte[] bytes, bool writable)
            : base(bytes, writable: writable)
        {
        }

        public bool Disposed => disposed != 0;

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Interlocked.Exchange(ref disposed, 1);
            }

            base.Dispose(disposing);
        }

        public override ValueTask DisposeAsync()
        {
            Dispose(disposing: true);
            return default;
        }
    }

    private sealed class CancelAfterReadMemoryStream : TrackingMemoryStream
    {
        private readonly CancellationTokenSource cancellation;

        public CancelAfterReadMemoryStream(byte[] bytes, CancellationTokenSource cancellation)
            : base(bytes, writable: false) => this.cancellation = cancellation;

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken)
        {
            var read = base.ReadAsync(buffer, cancellationToken);
            if (read.IsCompletedSuccessfully && read.Result > 0)
            {
                cancellation.Cancel();
            }

            return read;
        }
    }

    private sealed class TamperOnDisposeMemoryStream : TrackingMemoryStream
    {
        private readonly string targetPath;
        private int tampered;

        public TamperOnDisposeMemoryStream(byte[] bytes, string targetPath)
            : base(bytes, writable: false) => this.targetPath = targetPath;

        public bool Tampered => tampered != 0;

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing && Interlocked.Exchange(ref tampered, 1) == 0 && File.Exists(targetPath))
            {
                using var stream = new FileStream(
                    targetPath,
                    FileMode.Open,
                    FileAccess.ReadWrite,
                    FileShare.Read);
                var original = stream.ReadByte();
                stream.Position = 0;
                stream.WriteByte((byte)(original ^ 0xff));
            }
        }
    }
}
