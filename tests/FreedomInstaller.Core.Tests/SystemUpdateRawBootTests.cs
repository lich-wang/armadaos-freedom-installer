using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using AvbFixture = FreedomInstaller.Core.Tests.EdlRawAvbChainTests.AvbFixture;

namespace FreedomInstaller.Core.Tests;

public sealed class SystemUpdateRawBootTests : IClassFixture<EdlRawGblEnvelopeTests.SharedFixture>
{
    private const string KeyResource = "FreedomInstaller.AvbTestKey.pem";
    private const string NormalArgs = "console=ttyMSM0,115200n8 androidboot.hardware=qcom";
    private readonly EdlRawGblEnvelopeTests.SharedFixture _fx;

    public SystemUpdateRawBootTests(EdlRawGblEnvelopeTests.SharedFixture fx) => _fx = fx;

    public static IEnumerable<object[]> Models()
    {
        yield return new object[] { "TB322FC", new[] { "lenovo,elden", "qcom,sm8750" } };
        yield return new object[] { "TB323FU", new[] { "lenovo,baldur", "qcom,kaanapali" } };
        yield return new object[] { "TB710FU", new[] { "lenovo,tb710fu", "qcom,sm8650" } };
    }

    [Theory]
    [MemberData(nameof(Models))]
    public async Task RawBuilder_RealPackUnpackRepack_RoundTripsAllInputs(string model, string[] compatible)
    {
        var tools = ToolClaims.Create();
        string dir = CaseDirectory();
        var input = CreateInput(dir, model, compatible, tools);
        var runner = new RecordingRunner(new ProcessRunner());
        SystemUpdateRawRequest request = input.Request;
        var sourceClaims = new[] { request.BaseImage, request.Kernel, request.Initramfs, request.Runtime,
            request.DtbNormal, request.DtbDiagnostic, request.Packer, request.Unpacker };

        SystemUpdateRawBoot built = await EdlRawBootBuilder.BuildSystemUpdateRawAsync(request, runner);

        Assert.Equal(3, runner.Commands.Count);
        Assert.Equal(new[] { tools.Packer.Path, tools.Unpacker.Path, tools.Packer.Path },
            runner.Commands.Select(c => c.Executable));
        Assert.Equal(model, built.Model);
        Assert.Equal(request.MaxRawBytes, built.RawBudgetBytes);
        Assert.True(built.PackedRaw.Length > 0 && built.PackedRaw.Length <= request.MaxRawBytes);
        Assert.Equal(Sha(built.PackedRaw.Path), built.PackedRaw.Sha256, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(new FileInfo(built.PackedRaw.Path).Length, built.PackedRaw.Length);
        Assert.Equal(model, built.NormalDtb.DeviceModel);
        Assert.Equal(model, built.DiagnosticDtb.DeviceModel);
        Assert.Equal(EdlRawDtbKind.Normal, built.NormalDtb.Kind);
        Assert.Equal(EdlRawDtbKind.Diagnostic, built.DiagnosticDtb.Kind);

        string unpacked = Path.Combine(input.Output, "unpacked");
        AssertBytes(request.BaseImage.Path, Path.Combine(unpacked, "BaseImage"));
        AssertBytes(request.Runtime.Path, Path.Combine(unpacked, "Shim.bin"));
        AssertBytes(built.LinuxPadded.Path, Path.Combine(unpacked, "Image-01-Linux"));
        AssertBytes(request.DtbNormal.Path, Path.Combine(unpacked, "Image-03-DTB"));
        AssertBytes(request.DtbDiagnostic.Path, Path.Combine(unpacked, "Image-04-DTB"));
        AssertBytes(request.Initramfs.Path, Path.Combine(unpacked, "Image-05-Blob"));

        byte[] kernel = File.ReadAllBytes(request.Kernel.Path);
        byte[] linux = File.ReadAllBytes(built.LinuxPadded.Path);
        Assert.Equal(256, kernel.Length);
        Assert.Equal(4096, linux.Length);
        Assert.Equal(kernel.Take(64), linux.Take(64));
        Assert.Equal(kernel, linux.Take(kernel.Length).ToArray());
        Assert.All(linux.Skip(kernel.Length), b => Assert.Equal(0, b));
        foreach (VerifiedEdlFile claim in sourceClaims)
        {
            Assert.Equal(claim.Length, new FileInfo(claim.Path).Length);
            Assert.Equal(claim.Sha256, Sha(claim.Path), StringComparer.OrdinalIgnoreCase);
        }
        // TB710FU reaches only the file payload here: this test neither creates nor asserts an A/B claim.
    }

    [Fact]
    public async Task RawBuilder_ToAospEnvelope_SignedCandidateContainsExactRaw()
    {
        var tools = ToolClaims.Create();
        string dir = CaseDirectory();
        var input = CreateInput(dir, "TB322FC", new[] { "lenovo,elden", "qcom,sm8750" }, tools);
        SystemUpdateRawBoot raw = await EdlRawBootBuilder.BuildSystemUpdateRawAsync(input.Request, new ProcessRunner());
        using RSA key = LoadPublicTestRsa();
        using var avb = new AvbFixture(key);
        byte[] root = avb.BuildRootPartition(avb.ChainFor("boot", 3, 0),
            avb.ChainFor("recovery", 1, 0), avb.ChainFor("vbmeta_system", 2, 0));
        string rootPath = Path.Combine(dir, "vbmeta-aosp.img");
        File.WriteAllBytes(rootPath, root);
        string output = Path.Combine(dir, "candidate-aosp.img");
        EdlRawBuiltBoot normal = _fx.NormalBuilt;

        SystemUpdateBootEnvelope envelope = await EdlRawBootBuilder.PrepareSystemUpdateEnvelopeAsync(
            "a", normal.CandidateBoot, Claim(Path.Combine(_fx.Workspace.Root, "slot-a", "vendor-a.img")),
            Claim(Path.Combine(_fx.Workspace.Root, "slot-a", "init-a.img")),
            Claim(Path.Combine(_fx.Workspace.Root, "slot-a", "abl-a.bin")),
            Claim(Path.Combine(_fx.Workspace.Root, "slot-a", "xbl-a.bin")), Claim(rootPath), raw.PackedRaw,
            normal.SlotMaterial.LoaderBudget.MaxRawBytes, output, SystemUpdateEnvelopeMode.AospResign);

        Assert.True(envelope.PayloadDigestMatchesSignedMetadata);
        Assert.Equal(raw.PackedRaw.Sha256, Sha(DecompressCandidateKernel(output)), StringComparer.OrdinalIgnoreCase);
        byte[] image = File.ReadAllBytes(output);
        ulong vbOffset = BinaryPrimitives.ReadUInt64BigEndian(image.AsSpan(image.Length - 64 + 20, 8));
        ulong vbSize = BinaryPrimitives.ReadUInt64BigEndian(image.AsSpan(image.Length - 64 + 28, 8));
        byte[] signed = image.AsSpan(checked((int)vbOffset), checked((int)vbSize)).ToArray();
        AvbFixture.AssertAuthenticatedSignedBlob(signed);
        Assert.Equal(Sha(signed), envelope.MetadataSha256, StringComparer.OrdinalIgnoreCase);
        // Successful file signing makes no assertion about physical hardware authorization.
    }

    [Theory]
    [InlineData("TB322FC", "lenovo,elden", "qcom,sm8750")]
    [InlineData("TB323FU", "lenovo,baldur", "qcom,kaanapali")]
    [InlineData("TB710FU", "lenovo,tb710fu", "qcom,sm8650")]
    public async Task RawBuilder_UnmarkedRuntimeForMirrorPolicy_FailsBeforeNativeExecution(
        string model, string required, string soc)
    {
        var tools = ToolClaims.Create();
        var input = CreateInput(CaseDirectory(), model, new[] { required, soc }, tools);
        string runtime = Unmarked(input.Request.Runtime.Path);
        SystemUpdateRawRequest request = input.Request with { Runtime = Claim(runtime) };
        var runner = new RecordingRunner(new ProcessRunner());

        var exception = await Assert.ThrowsAsync<InvalidDataException>(() =>
            EdlRawBootBuilder.BuildSystemUpdateRawAsync(request, runner));

        Assert.Contains("ARMADA_LINUX_MIRROR_V1", exception.Message, StringComparison.Ordinal);
        Assert.Empty(runner.Commands);
        Assert.False(Directory.Exists(input.Output));
    }

    [Fact]
    public async Task RawBuilder_InvalidClaimsAndHeaders_FailBeforeNativeExecution()
    {
        var tools = ToolClaims.Create();
        await Reject("bad-hash", "TB322FC", new[] { "lenovo,elden", "qcom,sm8750" }, tools, r =>
            r with { Kernel = new VerifiedEdlFile(r.Kernel.Path, r.Kernel.Length, new string('0', 64)) }, false);
        await Reject("wrong-model", "TB322FC", new[] { "lenovo,baldur", "qcom,kaanapali" }, tools, r => r, true);
        await Reject("runtime-length", "TB322FC", new[] { "lenovo,elden", "qcom,sm8750" }, tools, r =>
        {
            string p = Path.Combine(Path.GetDirectoryName(r.Runtime.Path)!, "runtime-short.bin");
            File.WriteAllBytes(p, File.ReadAllBytes(r.Runtime.Path).AsSpan(0, checked((int)r.Runtime.Length - 1)).ToArray());
            return r with { Runtime = Claim(p) };
        }, false);
        await Reject("text-offset", "TB322FC", new[] { "lenovo,elden", "qcom,sm8750" }, tools, r =>
        {
            string p = Path.Combine(Path.GetDirectoryName(r.Kernel.Path)!, "kernel-offset.bin");
            byte[] b = File.ReadAllBytes(r.Kernel.Path);
            b[8] ^= 1;
            File.WriteAllBytes(p, b);
            return r with { Kernel = Claim(p) };
        }, false);
    }

    [Fact]
    public async Task RawBuilder_NativeFailureCancellationAndExistingOutput_NeverSucceed()
    {
        var tools = ToolClaims.Create();
        var failing = CreateInput(CaseDirectory(), "TB322FC", new[] { "lenovo,elden", "qcom,sm8750" }, tools);
        var runner = new FailSecondRunner();
        IOException failure = await Assert.ThrowsAsync<IOException>(() =>
            EdlRawBootBuilder.BuildSystemUpdateRawAsync(failing.Request, runner));
        Assert.Contains("7", failure.Message, StringComparison.Ordinal);
        Assert.Equal(2, runner.Commands.Count);
        Assert.True(File.Exists(Path.Combine(failing.Output, "PackedKernel")));
        Assert.False(Directory.Exists(Path.Combine(failing.Output, "unpacked")));
        Assert.Empty(Directory.EnumerateFiles(failing.Output, "candidate*.img"));

        var cancelled = CreateInput(CaseDirectory(), "TB322FC", new[] { "lenovo,elden", "qcom,sm8750" }, tools);
        var cancelRunner = new RecordingRunner(new ProcessRunner());
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            EdlRawBootBuilder.BuildSystemUpdateRawAsync(cancelled.Request, cancelRunner, cts.Token));
        Assert.Empty(cancelRunner.Commands);
        Assert.False(Directory.Exists(cancelled.Output));

        var sentinel = CreateInput(CaseDirectory(), "TB322FC", new[] { "lenovo,elden", "qcom,sm8750" }, tools);
        Directory.CreateDirectory(sentinel.Output);
        string marker = Path.Combine(sentinel.Output, "sentinel");
        File.WriteAllText(marker, "keep");
        var sentinelRunner = new RecordingRunner(new ProcessRunner());
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            EdlRawBootBuilder.BuildSystemUpdateRawAsync(sentinel.Request, sentinelRunner));
        Assert.Empty(sentinelRunner.Commands);
        Assert.Equal("keep", File.ReadAllText(marker));
    }

    [Fact]
    public async Task RawBuilder_StagedInputMutationAfterNativeRoundTrip_FinalIntegrityRejects()
    {
        var tools = ToolClaims.Create();
        var input = CreateInput(CaseDirectory(), "TB322FC", new[] { "lenovo,elden", "qcom,sm8750" }, tools);
        var runner = new MutateStagedRunner(input.Output);
        InvalidOperationException ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            EdlRawBootBuilder.BuildSystemUpdateRawAsync(input.Request, runner));
        Assert.Contains("Staged initramfs mutated", ex.Message, StringComparison.Ordinal);
        Assert.Equal(3, runner.Commands.Count);
    }

    private async Task Reject(string name, string model, string[] compatible, ToolClaims tools,
        Func<SystemUpdateRawRequest, SystemUpdateRawRequest> change, bool outputMayExist)
    {
        var input = CreateInput(CaseDirectory() + "-" + name, model, compatible, tools);
        var runner = new RecordingRunner(new ProcessRunner());
        SystemUpdateRawRequest request = change(input.Request);
        Type expected = name switch
        {
            "runtime-length" => typeof(ArgumentException),
            "text-offset" => typeof(InvalidOperationException),
            _ => typeof(InvalidDataException),
        };
        await Assert.ThrowsAsync(expected, () => EdlRawBootBuilder.BuildSystemUpdateRawAsync(request, runner));
        Assert.Empty(runner.Commands);
        Assert.Equal(outputMayExist, Directory.Exists(input.Output));
    }

    private Input CreateInput(string dir, string model, string[] compatible, ToolClaims tools)
    {
        Directory.CreateDirectory(dir);
        var artifacts = _fx.Package.Contract.Artifacts;
        VerifiedEdlFile Copy(VerifiedEdlFile source, string name)
        {
            string p = Path.Combine(dir, name);
            File.Copy(source.Path, p);
            return Claim(p);
        }
        VerifiedEdlFile Dtb(string name, string[] compat, string args, string stage)
        {
            byte[] blob = (byte[])typeof(EdlRawDtbValidatorTests).GetMethod("CreateValidBlob",
                BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, new object[] { compat, args, stage, new uint[] { 5 } })!;
            string p = Path.Combine(dir, name);
            File.WriteAllBytes(p, blob);
            return Claim(p);
        }
        var baseImage = Copy(_fx.NormalBuilt.BaseImage, "base.img");
        var kernel = Copy(new VerifiedEdlFile(artifacts["kernel"].FullPath, artifacts["kernel"].Bytes, artifacts["kernel"].Sha256), "kernel.bin");
        var init = Copy(new VerifiedEdlFile(artifacts["initramfs"].FullPath, artifacts["initramfs"].Bytes, artifacts["initramfs"].Sha256), "initramfs.bin");
        var runtime = Copy(new VerifiedEdlFile(artifacts["runtime"].FullPath, artifacts["runtime"].Bytes, artifacts["runtime"].Sha256), "runtime.bin");
        string output = Path.Combine(dir, "output");
        var request = new SystemUpdateRawRequest(model, baseImage, kernel, init, runtime,
            Dtb("normal.dtb", compatible, NormalArgs, "os"),
            Dtb("diagnostic.dtb", compatible, "console=ttyMSM0,115200n8 armada.diag=1", "maintenance"),
            NormalArgs, "console=ttyMSM0,115200n8 armada.diag=1",
            _fx.NormalBuilt.SlotMaterial.LoaderBudget.MaxRawBytes, output, tools.Packer, tools.Unpacker);
        return new Input(request, output);
    }

    private string CaseDirectory()
    {
        string p = Path.Combine(_fx.Workspace.Root, "raw-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(p);
        return p;
    }

    private static VerifiedEdlFile Claim(string path) => new(path, new FileInfo(path).Length, Sha(path));
    private static string Sha(string path) => Sha(File.ReadAllBytes(path));
    private static string Sha(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    /// <summary>Copies the file without the policy marker and returns the new path.</summary>
    private static string Unmarked(string path)
    {
        byte[] bytes = File.ReadAllBytes(path);
        byte[] marker = Encoding.ASCII.GetBytes("ARMADA_LINUX_MIRROR_V1");
        int offset = bytes.AsSpan().IndexOf(marker);
        Assert.True(offset >= 0);
        bytes.AsSpan(offset, marker.Length).Clear();
        string output = path + ".unmarked";
        File.WriteAllBytes(output, bytes);
        return output;
    }
    private static void AssertBytes(string expected, string actual) => Assert.Equal(File.ReadAllBytes(expected), File.ReadAllBytes(actual));

    private static byte[] DecompressCandidateKernel(string path)
    {
        byte[] image = File.ReadAllBytes(path);
        int size = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(8, 4)));
        using var gzip = new GZipStream(new MemoryStream(image, 4096, size), CompressionMode.Decompress);
        using var result = new MemoryStream();
        gzip.CopyTo(result);
        return result.ToArray();
    }

    private static RSA LoadPublicTestRsa()
    {
        using Stream stream = typeof(EdlRawBootBuilder).Assembly.GetManifestResourceStream(KeyResource)!;
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var rsa = RSA.Create();
        rsa.ImportFromPem(reader.ReadToEnd());
        return rsa;
    }

    private sealed record Input(SystemUpdateRawRequest Request, string Output);

    private sealed class ToolClaims
    {
        internal VerifiedEdlFile Packer { get; }
        internal VerifiedEdlFile Unpacker { get; }
        private ToolClaims(VerifiedEdlFile p, VerifiedEdlFile u) { Packer = p; Unpacker = u; }
        internal static ToolClaims Create()
        {
            string p = Environment.GetEnvironmentVariable("EDL_RAW_LINUX_PACKER_PATH")
                ?? throw new InvalidOperationException("EDL_RAW_LINUX_PACKER_PATH is required.");
            string u = Environment.GetEnvironmentVariable("EDL_RAW_LINUX_UNPACKER_PATH")
                ?? throw new InvalidOperationException("EDL_RAW_LINUX_UNPACKER_PATH is required.");
            return new ToolClaims(Claim(p), Claim(u));
        }
    }

    private class RecordingRunner : ICommandRunner
    {
        private readonly ICommandRunner _inner;
        internal List<ProcessCommand> Commands { get; } = new();
        internal RecordingRunner(ICommandRunner inner) => _inner = inner;
        public virtual async Task<ProcessResult> RunAsync(ProcessCommand command, CancellationToken cancellationToken = default)
        {
            Commands.Add(command);
            return await _inner.RunAsync(command, cancellationToken);
        }
    }

    private sealed class FailSecondRunner : RecordingRunner
    {
        internal FailSecondRunner() : base(new ProcessRunner()) { }
        public override Task<ProcessResult> RunAsync(ProcessCommand command, CancellationToken cancellationToken = default)
        {
            if (Commands.Count == 1)
            {
                Commands.Add(command);
                return Task.FromResult(new ProcessResult(7, "", "injected native failure"));
            }
            return base.RunAsync(command, cancellationToken);
        }
    }

    private sealed class MutateStagedRunner : RecordingRunner
    {
        private readonly string _output;
        internal MutateStagedRunner(string output) : base(new ProcessRunner()) { _output = output; }
        public override async Task<ProcessResult> RunAsync(ProcessCommand command, CancellationToken cancellationToken = default)
        {
            ProcessResult result = await base.RunAsync(command, cancellationToken);
            if (Commands.Count == 3)
            {
                string staged = Path.Combine(_output, "initramfs");
                byte[] bytes = File.ReadAllBytes(staged);
                Assert.NotEmpty(bytes);
                bytes[0] ^= 1;
                File.WriteAllBytes(staged, bytes);
            }
            return result;
        }
    }
}
