using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

/// <summary>
/// Focused coverage for <see cref="RamInstallSupport"/>: the caller's length/SHA-256 claim is only a
/// claim, so the real file is hashed, the handle is held for the support's lifetime and every
/// mismatch is rejected before the file can be used as an upload.
/// </summary>
public sealed class RamInstallSupportTests
{
    [Fact]
    public async Task LoadAsync_RealFile_ReportsTheVerifiedLengthAndDigest()
    {
        using var temp = new RamInstallSupportTempDirectory();
        var bytes = CreateBytes(12345);
        var path = temp.WriteFile("install-support.tar.gz", bytes);
        var digest = Sha256Hex(bytes);

        using var support = await RamInstallSupport.LoadAsync(new VerifiedEdlFile(path, bytes.Length, digest));

        Assert.Equal((long)bytes.Length, support.Length);
        Assert.Equal(digest, support.Sha256);
        Assert.False(support.IsDisposed);
    }

    [Fact]
    public async Task LoadAsync_ClaimedLengthThatDiffersFromTheFile_IsRejected()
    {
        using var temp = new RamInstallSupportTempDirectory();
        var bytes = CreateBytes(4096);
        var path = temp.WriteFile("install-support.tar.gz", bytes);
        var digest = Sha256Hex(bytes);

        var tooLong = await Assert.ThrowsAsync<MaintenanceException>(
            () => RamInstallSupport.LoadAsync(new VerifiedEdlFile(path, bytes.Length + 1, digest)));
        Assert.Equal(MaintenanceErrorCode.AssetSizeMismatch, tooLong.Code);

        var tooShort = await Assert.ThrowsAsync<MaintenanceException>(
            () => RamInstallSupport.LoadAsync(new VerifiedEdlFile(path, bytes.Length - 1, digest)));
        Assert.Equal(MaintenanceErrorCode.AssetSizeMismatch, tooShort.Code);

        // A rejected load must not keep the file open.
        Assert.True(File.Exists(path));
        File.Delete(path);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task LoadAsync_ClaimedDigestThatDiffersFromTheFile_IsRejected()
    {
        using var temp = new RamInstallSupportTempDirectory();
        var bytes = CreateBytes(4096);
        var path = temp.WriteFile("install-support.tar.gz", bytes);

        var exception = await Assert.ThrowsAsync<MaintenanceException>(
            () => RamInstallSupport.LoadAsync(new VerifiedEdlFile(path, bytes.Length, new string('a', 64))));

        Assert.Equal(MaintenanceErrorCode.AssetHashMismatch, exception.Code);
    }

    [Theory]
    [InlineData("uppercase")]
    [InlineData("short")]
    [InlineData("non-hex")]
    public async Task LoadAsync_ClaimedDigestMustBeLowercase64Hex(string variant)
    {
        using var temp = new RamInstallSupportTempDirectory();
        var bytes = CreateBytes(4096);
        var path = temp.WriteFile("install-support.tar.gz", bytes);
        var digest = variant switch
        {
            "uppercase" => new string('A', 64),
            "short" => Sha256Hex(bytes).Substring(0, 63),
            "non-hex" => new string('z', 64),
            _ => throw new ArgumentOutOfRangeException(nameof(variant)),
        };

        var exception = await Assert.ThrowsAsync<MaintenanceException>(
            () => RamInstallSupport.LoadAsync(new VerifiedEdlFile(path, bytes.Length, digest)));

        Assert.Equal(MaintenanceErrorCode.AssetHashMismatch, exception.Code);
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(-1L)]
    public async Task LoadAsync_NonPositiveClaimedLength_IsRejectedBeforeOpeningAnything(long claimedLength)
    {
        var exception = await Assert.ThrowsAsync<MaintenanceException>(
            () => RamInstallSupport.LoadAsync(
                new VerifiedEdlFile("Z:/definitely-not-present/install-support.tar.gz", claimedLength, new string('a', 64))));

        Assert.Equal(MaintenanceErrorCode.AssetSizeMismatch, exception.Code);
    }

    [Fact]
    public async Task LoadAsync_ClaimedLengthAboveTheLimit_IsRejectedBeforeOpeningAnything()
    {
        var exception = await Assert.ThrowsAsync<MaintenanceException>(
            () => RamInstallSupport.LoadAsync(
                new VerifiedEdlFile(
                    "Z:/definitely-not-present/install-support.tar.gz",
                    RamInstallSupport.MaxBytes + 1,
                    new string('a', 64))));

        Assert.Equal(MaintenanceErrorCode.AssetSizeMismatch, exception.Code);
    }

    [Fact]
    public async Task LoadAsync_MissingFile_IsRejectedAsUnsafe()
    {
        using var temp = new RamInstallSupportTempDirectory();
        var missing = System.IO.Path.Combine(temp.Root, "missing-install-support.tar.gz");

        var exception = await Assert.ThrowsAsync<MaintenanceException>(
            () => RamInstallSupport.LoadAsync(new VerifiedEdlFile(missing, 4096, new string('a', 64))));

        Assert.Equal(MaintenanceErrorCode.UnsafeEnvironment, exception.Code);
    }

    [Fact]
    public async Task LoadAsync_EmptyFile_IsRejectedAsASizeMismatch()
    {
        using var temp = new RamInstallSupportTempDirectory();
        var path = temp.WriteFile("install-support.tar.gz", Array.Empty<byte>());

        var exception = await Assert.ThrowsAsync<MaintenanceException>(
            () => RamInstallSupport.LoadAsync(new VerifiedEdlFile(path, 1, new string('a', 64))));

        Assert.Equal(MaintenanceErrorCode.AssetSizeMismatch, exception.Code);
    }

    [Fact]
    public async Task LoadAsync_WithPreCancelledToken_DoesNotCreateSupport()
    {
        using var temp = new RamInstallSupportTempDirectory();
        var bytes = CreateBytes(1024);
        var path = temp.WriteFile("install-support.tar.gz", bytes);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => RamInstallSupport.LoadAsync(
                new VerifiedEdlFile(path, bytes.Length, Sha256Hex(bytes)),
                cancellation.Token));
    }

    [Fact]
    public async Task Dispose_ReleasesTheHeldFile_AndIsIdempotent()
    {
        using var temp = new RamInstallSupportTempDirectory();
        var bytes = CreateBytes(2048);
        var path = temp.WriteFile("install-support.tar.gz", bytes);

        var support = await RamInstallSupport.LoadAsync(
            new VerifiedEdlFile(path, bytes.Length, Sha256Hex(bytes)));

        Assert.False(support.IsDisposed);
        support.Dispose();
        Assert.True(support.IsDisposed);
        support.Dispose();
        Assert.True(support.IsDisposed);

        File.Delete(path);
        Assert.False(File.Exists(path));
    }

    private static byte[] CreateBytes(int length)
    {
        var bytes = new byte[length];
        new Random(13).NextBytes(bytes);
        return bytes;
    }

    private static string Sha256Hex(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private sealed class RamInstallSupportTempDirectory : IDisposable
    {
        public RamInstallSupportTempDirectory()
        {
            Root = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "rh001-support-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public string WriteFile(string name, byte[] content)
        {
            var path = System.IO.Path.Combine(Root, name);
            File.WriteAllBytes(path, content);
            return path;
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(Root))
                {
                    Directory.Delete(Root, recursive: true);
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
