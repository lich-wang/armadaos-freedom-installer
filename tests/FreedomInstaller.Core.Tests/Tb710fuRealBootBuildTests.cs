// Fork only: builds both TB710FU slot candidates from partitions read off a real tablet and a real
// TB710FU EDL raw package, through the same Linux oracle adapter the boot builder tests use. Skipped
// unless TB710FU_REAL_SLOT_DIR (boot/vendor_boot/init_boot/abl/xbl_config _a/_b images) and
// TB710FU_REAL_BUNDLE (the bundle ZIP) are set; those inputs are device data and are never committed.
using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;
using Xunit.Abstractions;

namespace FreedomInstaller.Core.Tests;

public sealed class Tb710fuRealBootBuildTests
{
    private readonly ITestOutputHelper _output;

    public Tb710fuRealBootBuildTests(ITestOutputHelper output) => _output = output;

    private static VerifiedEdlFile Claim(string path)
    {
        using FileStream stream = File.OpenRead(path);
        return new VerifiedEdlFile(path, stream.Length, Convert.ToHexString(SHA256.HashData(stream)));
    }

    [Fact]
    public async Task Both_slots_build_from_real_tablet_partitions()
    {
        string? slots = Environment.GetEnvironmentVariable("TB710FU_REAL_SLOT_DIR");
        string? bundle = Environment.GetEnvironmentVariable("TB710FU_REAL_BUNDLE");
        if (string.IsNullOrWhiteSpace(slots) || string.IsNullOrWhiteSpace(bundle))
        {
            return;
        }

        string work = Path.Combine(
            Environment.GetEnvironmentVariable("TEST_ARTIFACT_ROOT") ?? Path.GetTempPath(),
            "tb710fu-real-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(work);

        using ImportedPackage imported = await PackageImporter.ImportAsync(
            bundle, "TB710FU", InstallationTarget.Internal, work);
        EdlRawPackageContract contract = PackageReader.ReadEdlRawContract(imported.PackageDirectory, "TB710FU");

        using EdlRawBootTools tools = await EdlRawBootTools.LoadAsync(
            Claim(Environment.GetEnvironmentVariable("EDL_RAW_PACKER_PATH")!),
            Claim(Environment.GetEnvironmentVariable("EDL_RAW_UNPACKER_PATH")!));
        var runner = new EdlRawBootBuilderTests.LinuxOracleRunner(
            tools,
            Environment.GetEnvironmentVariable("EDL_RAW_LINUX_PACKER_PATH")!,
            Environment.GetEnvironmentVariable("EDL_RAW_LINUX_UNPACKER_PATH")!);

        foreach (string slot in new[] { "b", "a" })
        {
            string P(string role) => Path.Combine(slots, role + "_" + slot + ".img");
            using EdlRawBuiltBoot built = await EdlRawBootBuilder.BuildAsync(
                new EdlRawBootBuildRequest(
                    slot,
                    Claim(P("boot")),
                    Claim(P("vendor_boot")),
                    Claim(P("init_boot")),
                    Claim(P("abl")),
                    Claim(P("xbl_config")),
                    contract,
                    tools,
                    work),
                runner);

            _output.WriteLine(
                $"slot {slot}: candidate {built.CandidateBoot.Length} B sha {built.CandidateBoot.Sha256}, "
                + $"packed raw {built.PackedRaw.Length} B, budget {built.SlotMaterial.LoaderBudget.Profile} "
                + $"{built.SlotMaterial.LoaderBudget.MaxRawBytes}, payload {built.Envelope.OriginalImageSize} B, "
                + $"rollback {built.Envelope.RollbackIndex}");
            File.Copy(built.CandidateBoot.Path, Path.Combine(work, "candidate_boot_" + slot + ".img"));
            Assert.Equal(100663296L, built.CandidateBoot.Length);
        }
    }
}
