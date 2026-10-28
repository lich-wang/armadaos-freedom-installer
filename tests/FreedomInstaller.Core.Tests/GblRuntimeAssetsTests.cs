using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Contract tests for the fixed offline GBL runtime asset provider. The production type is internal and
/// may not exist yet, so it is reached through narrow reflection; these tests compile either way.
/// The assets are the real standard ones, never fixtures.
/// </summary>
public sealed class GblRuntimeAssetsTests
{
    private const long StandardAssetLength = 282_624;

    [Theory]
    [InlineData("Prc", "generic_superfastboot_prc.efi", "B91DB7974DA80976BC73ADD671F4ADFB833AEA4FD0D9D7604B75CB63415FED84")]
    [InlineData("Row", "generic_superfastboot_row.efi", "E21F6D5FFE29113943092AC4A2A75E4FA03960831CC8855316C784B472999ABD")]
    public async Task StageAsync_MaterializesRealStandardAsset(string region, string fileName, string expectedSha256)
    {
        using var owned = new OwnedEvidenceDirectory();
        var destination = Path.Combine(owned.Path, fileName);

        var result = await StageAsync(region, owned.Path);

        Assert.Equal(destination, result.Path);
        Assert.Equal(StandardAssetLength, result.Length);
        Assert.Equal(expectedSha256, result.Sha256);

        var bytes = File.ReadAllBytes(destination);
        Assert.Equal(StandardAssetLength, bytes.LongLength);
        Assert.Equal(expectedSha256, Convert.ToHexString(SHA256.HashData(bytes)));
    }

    [Fact]
    public async Task StageAsync_DoesNotOverwriteExistingFixedTargetFile()
    {
        using var owned = new OwnedEvidenceDirectory();
        var destination = Path.Combine(owned.Path, "generic_superfastboot_prc.efi");
        byte[] sentinel = [0x47, 0x42, 0x4C, 0x2D, 0x54, 0x31]; // "GBL-T1"
        File.WriteAllBytes(destination, sentinel);

        await Assert.ThrowsAsync<IOException>(() => StageAsync("Prc", owned.Path));

        Assert.True(File.Exists(destination));
        Assert.Equal(sentinel, File.ReadAllBytes(destination));
    }

    private static async Task<VerifiedEdlFile> StageAsync(string regionName, string existingOwnedEvidenceDir)
    {
        var assembly = typeof(VerifiedEdlFile).Assembly;

        var assetsType = assembly.GetType("FreedomInstaller.Core.Gbl.GblRuntimeAssets", throwOnError: false);
        Assert.NotNull(assetsType);

        var regionType = assembly.GetType("FreedomInstaller.Core.Gbl.GblRuntimeRegion", throwOnError: false);
        Assert.NotNull(regionType);
        Assert.True(regionType!.IsEnum);

        var method = assetsType!.GetMethod(
            "StageAsync",
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        Assert.Equal(typeof(Task<VerifiedEdlFile>), method!.ReturnType);

        var parameters = method.GetParameters();
        Assert.Equal(3, parameters.Length);
        Assert.Equal(regionType, parameters[0].ParameterType);
        Assert.Equal(typeof(string), parameters[1].ParameterType);
        Assert.Equal(typeof(CancellationToken), parameters[2].ParameterType);

        var region = Enum.Parse(regionType, regionName, ignoreCase: false);

        object? invoked;
        try
        {
            invoked = method.Invoke(null, [region, existingOwnedEvidenceDir, CancellationToken.None]);
        }
        catch (TargetInvocationException ex) when (ex.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
            throw;
        }

        var task = Assert.IsAssignableFrom<Task<VerifiedEdlFile>>(invoked);
        return await task;
    }

    /// <summary>Removes only the directory this test created.</summary>
    private sealed class OwnedEvidenceDirectory : IDisposable
    {
        internal OwnedEvidenceDirectory()
        {
            Path = System.IO.Path.Combine(
                TestArtifactRoot.Resolve(),
                "gbl-runtime-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        internal string Path { get; }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(Path))
                {
                    Directory.Delete(Path, recursive: true);
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
}
