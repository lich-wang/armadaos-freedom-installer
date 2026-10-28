// real standard-native ext4/BLS business tests for BootMaintenanceInstalledLinux.VerifyCaptured.
// Each positive fact is established from an actual mke2fs-built ext4 image plus one synthetic 4096-byte
// Btrfs primary superblock header. The synthetic header carries ONLY the FSID/header facts production
// reads (magic, bytenr, FSID, total_bytes, sectorsize); it is NOT a real Btrfs filesystem and asserts
// nothing about root-tree health. Tests/reports must keep that distinction.
// Compilation and execution happen only in the CI Linux container; any failure here is a real fixture
// or binding error, never an expected RED state.
using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FreedomInstaller.Core;
using Xunit;

namespace FreedomInstaller.Core.Tests;

public sealed class BootMaintenanceInstalledLinuxTests
{
    private const string MismatchPrefix = "maintenance-installed-linux-mismatch: ";

    private const string Mke2fsPath = "/usr/sbin/mke2fs";

    private const long ImageBytes = 32 * 1024 * 1024;

    private const int BtrfsSuperblockBytes = 4096;

    private static readonly VerifyCapturedDelegate VerifyCaptured = CreateVerifyCapturedDelegate();

    private static readonly Type FactsType =
        typeof(EdlRawBootBuilder).Assembly.GetType("FreedomInstaller.Core.InstalledLinuxBootFacts")
        ?? throw new InvalidOperationException("FreedomInstaller.Core.InstalledLinuxBootFacts was not found");

    /// <summary>
    /// Thin bridge to the internal static reader. The Span parameter travels unboxed through the
    /// delegate; the reference return is bound covariantly to object by CreateDelegate.
    /// </summary>
    private delegate object VerifyCapturedDelegate(
        Stream ext4Fs,
        ReadOnlySpan<byte> btrfsPrimarySb,
        EdlRawPackageContract contract,
        CancellationToken cancellationToken);

    private static VerifyCapturedDelegate CreateVerifyCapturedDelegate()
    {
        MethodInfo method = typeof(EdlRawBootBuilder).Assembly
            .GetType("FreedomInstaller.Core.BootMaintenanceInstalledLinux")
            ?.GetMethod("VerifyCaptured", BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException(
                "FreedomInstaller.Core.BootMaintenanceInstalledLinux.VerifyCaptured was not found");
        return (VerifyCapturedDelegate)method.CreateDelegate(typeof(VerifyCapturedDelegate));
    }

    private static Guid FactGuid(object facts, string property) =>
        Assert.IsType<Guid>(ReadFact(facts, property));

    private static string FactString(object facts, string property) =>
        Assert.IsType<string>(ReadFact(facts, property));

    private static object ReadFact(object facts, string property) =>
        FactsType.GetProperty(property, BindingFlags.Public | BindingFlags.Instance)?.GetValue(facts)
        ?? throw new InvalidOperationException($"InstalledLinuxBootFacts.{property} was not found or was null");

    // ---------------------------------------------------------------- facts 1: positive binding

    [Fact]
    public async Task VerifyCaptured_NativeExt4DefaultBlsEntry_BindsPackageFacts()
    {
        using var package = new EdlRawBootBuilderTests.SyntheticPackage();
        using var workspace = new EdlRawBootBuilderTests.Workspace();

        string tree = await WriteStandardTreeAsync(workspace.Root, package.Contract);
        string image = await BuildImageAsync(tree, workspace.Root, package.Contract.BootRecipe.BootUuid);
        byte[] superblock = BuildBtrfsPrimarySuperblock(package.Contract.BootRecipe.RootUuid);

        await using FileStream ext4 = OpenImageForRead(image);
        object facts = VerifyCaptured(ext4, superblock, package.Contract, CancellationToken.None);

        Assert.Equal(package.Contract.BootRecipe.BootUuid, FactGuid(facts, "BootUuid"));
        Assert.Equal(package.Contract.BootRecipe.RootUuid, FactGuid(facts, "RootUuid"));
        Assert.Equal("/loader/entries/10-selected.conf", FactString(facts, "SelectedEntryPath"));
        Assert.Equal(package.Contract.Deployment.BootChecksum, FactString(facts, "BootChecksum"));
        Assert.Equal(package.Contract.Artifacts["kernel"].Sha256.ToLowerInvariant(), FactString(facts, "KernelSha256"));
        Assert.Equal(package.Contract.Artifacts["initramfs"].Sha256.ToLowerInvariant(), FactString(facts, "InitramfsSha256"));
    }

    // ------------------------------------------------- fact 2: default entry kernel mismatch

    [Fact]
    public async Task VerifyCaptured_DefaultEntryKernelDiffersFromPackage_ThrowsKernelMismatch()
    {
        using var package = new EdlRawBootBuilderTests.SyntheticPackage();
        using var workspace = new EdlRawBootBuilderTests.Workspace();

        string tree = Path.Combine(workspace.Root, "tree");
        (string loaderDir, string entriesDir, string imagesDir) = CreateTree(tree);
        File.Copy(package.Contract.Artifacts["kernel"].FullPath, Path.Combine(imagesDir, "wrong-kernel"));
        FlipLastByte(Path.Combine(imagesDir, "wrong-kernel"));
        File.Copy(package.Contract.Artifacts["kernel"].FullPath, Path.Combine(imagesDir, "vmlinuz"), overwrite: true);
        File.Copy(package.Contract.Artifacts["initramfs"].FullPath, Path.Combine(imagesDir, "initrd"));
        await File.WriteAllTextAsync(Path.Combine(loaderDir, "loader.conf"), "default 10-selected.conf\n");
        await WriteEntryAsync(
            Path.Combine(entriesDir, "10-selected.conf"), "/images/wrong-kernel", "/images/initrd",
            package.Contract.BootRecipe.NormalBootArgs);
        await WriteEntryAsync(
            Path.Combine(entriesDir, "20-good.conf"), "/images/vmlinuz", "/images/initrd",
            package.Contract.BootRecipe.NormalBootArgs);

        string image = await BuildImageAsync(tree, workspace.Root, package.Contract.BootRecipe.BootUuid);
        byte[] superblock = BuildBtrfsPrimarySuperblock(package.Contract.BootRecipe.RootUuid);

        await using FileStream ext4 = OpenImageForRead(image);
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(
            () => VerifyCaptured(ext4, superblock, package.Contract, CancellationToken.None));

        Assert.StartsWith(MismatchPrefix, error.Message);
        Assert.Contains("kernel", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    // --------------------------------------------- fact 3: two entries but no loader default

    [Fact]
    public async Task VerifyCaptured_LoaderDefaultMissing_ThrowsDefaultMismatch()
    {
        using var package = new EdlRawBootBuilderTests.SyntheticPackage();
        using var workspace = new EdlRawBootBuilderTests.Workspace();

        string tree = Path.Combine(workspace.Root, "tree");
        (string loaderDir, string entriesDir, string imagesDir) = CreateTree(tree);
        File.Copy(package.Contract.Artifacts["kernel"].FullPath, Path.Combine(imagesDir, "vmlinuz"));
        File.Copy(package.Contract.Artifacts["kernel"].FullPath, Path.Combine(imagesDir, "alt-kernel"));
        File.Copy(package.Contract.Artifacts["initramfs"].FullPath, Path.Combine(imagesDir, "initrd"));
        await File.WriteAllTextAsync(Path.Combine(loaderDir, "loader.conf"), "# no default configured\n");
        await WriteEntryAsync(
            Path.Combine(entriesDir, "10-selected.conf"), "/images/vmlinuz", "/images/initrd",
            package.Contract.BootRecipe.NormalBootArgs);
        await WriteEntryAsync(
            Path.Combine(entriesDir, "20-alt.conf"), "/images/alt-kernel", "/images/initrd",
            package.Contract.BootRecipe.NormalBootArgs);

        string image = await BuildImageAsync(tree, workspace.Root, package.Contract.BootRecipe.BootUuid);
        byte[] superblock = BuildBtrfsPrimarySuperblock(package.Contract.BootRecipe.RootUuid);

        await using FileStream ext4 = OpenImageForRead(image);
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(
            () => VerifyCaptured(ext4, superblock, package.Contract, CancellationToken.None));

        Assert.StartsWith(MismatchPrefix, error.Message);
        Assert.Contains("default", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    // --------------------------------------------------- fact 4: wrong Btrfs root FSID

    [Fact]
    public async Task VerifyCaptured_RootFsidDiffersFromPackage_ThrowsUuidMismatch()
    {
        using var package = new EdlRawBootBuilderTests.SyntheticPackage();
        using var workspace = new EdlRawBootBuilderTests.Workspace();

        string tree = await WriteStandardTreeAsync(workspace.Root, package.Contract);
        string image = await BuildImageAsync(tree, workspace.Root, package.Contract.BootRecipe.BootUuid);
        byte[] superblock = BuildBtrfsPrimarySuperblock(package.Contract.BootRecipe.RootUuid);
        superblock[32] ^= 0xFF;

        await using FileStream ext4 = OpenImageForRead(image);
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(
            () => VerifyCaptured(ext4, superblock, package.Contract, CancellationToken.None));

        Assert.StartsWith(MismatchPrefix, error.Message);
        Assert.True(
            error.Message.Contains("fsid", StringComparison.OrdinalIgnoreCase)
            || error.Message.Contains("uuid", StringComparison.OrdinalIgnoreCase),
            $"expected a UUID/FSID mismatch detail, got: {error.Message}");
    }

    // ------------------------------------------- fact 5: selected initramfs bytes differ

    [Fact]
    public async Task VerifyCaptured_SelectedInitramfsBytesDiffer_ThrowsInitramfsMismatch()
    {
        using var package = new EdlRawBootBuilderTests.SyntheticPackage();
        using var workspace = new EdlRawBootBuilderTests.Workspace();

        string tree = Path.Combine(workspace.Root, "tree");
        (string loaderDir, string entriesDir, string imagesDir) = CreateTree(tree);
        File.Copy(package.Contract.Artifacts["kernel"].FullPath, Path.Combine(imagesDir, "vmlinuz"));
        File.Copy(package.Contract.Artifacts["initramfs"].FullPath, Path.Combine(imagesDir, "initrd"));
        FlipLastByte(Path.Combine(imagesDir, "initrd"));
        await File.WriteAllTextAsync(Path.Combine(loaderDir, "loader.conf"), "default 10-selected.conf\n");
        await WriteEntryAsync(
            Path.Combine(entriesDir, "10-selected.conf"), "/images/vmlinuz", "/images/initrd",
            package.Contract.BootRecipe.NormalBootArgs);

        string image = await BuildImageAsync(tree, workspace.Root, package.Contract.BootRecipe.BootUuid);
        byte[] superblock = BuildBtrfsPrimarySuperblock(package.Contract.BootRecipe.RootUuid);

        await using FileStream ext4 = OpenImageForRead(image);
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(
            () => VerifyCaptured(ext4, superblock, package.Contract, CancellationToken.None));

        Assert.StartsWith(MismatchPrefix, error.Message);
        Assert.Contains("initramfs", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    // --------------------------------------- fact 6: selected BLS ostree checksum differs

    [Fact]
    public async Task VerifyCaptured_SelectedOstreeChecksumDiffers_ThrowsChecksumMismatch()
    {
        using var package = new EdlRawBootBuilderTests.SyntheticPackage();
        using var workspace = new EdlRawBootBuilderTests.Workspace();

        string checksum = package.Contract.Deployment.BootChecksum;
        string mutatedOptions = package.Contract.BootRecipe.NormalBootArgs
            .Replace(checksum, OtherHex(checksum.Length), StringComparison.Ordinal);
        Assert.NotEqual(package.Contract.BootRecipe.NormalBootArgs, mutatedOptions);

        string tree = Path.Combine(workspace.Root, "tree");
        (string loaderDir, string entriesDir, string imagesDir) = CreateTree(tree);
        File.Copy(package.Contract.Artifacts["kernel"].FullPath, Path.Combine(imagesDir, "vmlinuz"));
        File.Copy(package.Contract.Artifacts["initramfs"].FullPath, Path.Combine(imagesDir, "initrd"));
        await File.WriteAllTextAsync(Path.Combine(loaderDir, "loader.conf"), "default 10-selected.conf\n");
        await WriteEntryAsync(
            Path.Combine(entriesDir, "10-selected.conf"), "/images/vmlinuz", "/images/initrd", mutatedOptions);

        string image = await BuildImageAsync(tree, workspace.Root, package.Contract.BootRecipe.BootUuid);
        byte[] superblock = BuildBtrfsPrimarySuperblock(package.Contract.BootRecipe.RootUuid);

        await using FileStream ext4 = OpenImageForRead(image);
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(
            () => VerifyCaptured(ext4, superblock, package.Contract, CancellationToken.None));

        Assert.StartsWith(MismatchPrefix, error.Message);
        Assert.True(
            error.Message.Contains("checksum", StringComparison.OrdinalIgnoreCase)
            || error.Message.Contains("ostree", StringComparison.OrdinalIgnoreCase),
            $"expected a boot checksum mismatch detail, got: {error.Message}");
    }

    // --------------------------------- fact 7: pre-cancelled token refuses before parsing

    [Fact]
    public void VerifyCaptured_PreCancelledToken_ThrowsBeforeExt4Parsing()
    {
        using var package = new EdlRawBootBuilderTests.SyntheticPackage();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        byte[] zeros = new byte[4096];

        Assert.Throws<OperationCanceledException>(() => VerifyCaptured(
            new MemoryStream(Array.Empty<byte>(), writable: false), zeros, package.Contract, cancellation.Token));
        Assert.Throws<OperationCanceledException>(() => VerifyCaptured(
            new MemoryStream(zeros, writable: false), zeros, package.Contract, cancellation.Token));
    }

    // ------------------------------ fact 8: alternate boot generation binds the same package

    [Fact]
    public async Task VerifyCaptured_AlternateBootGeneration_BindsSamePackageFacts()
    {
        using var package = new EdlRawBootBuilderTests.SyntheticPackage();
        using var workspace = new EdlRawBootBuilderTests.Workspace();

        string originalOptions = package.Contract.BootRecipe.NormalBootArgs;
        string rotatedOptions = originalOptions.Contains("boot.0", StringComparison.Ordinal)
            ? originalOptions.Replace("boot.0", "boot.1", StringComparison.Ordinal)
            : originalOptions.Replace("boot.1", "boot.0", StringComparison.Ordinal);
        Assert.NotEqual(originalOptions, rotatedOptions);

        string tree = await WriteStandardTreeAsync(workspace.Root, package.Contract);
        string selectedEntry = Path.Combine(tree, "loader", "entries", "10-selected.conf");
        await WriteEntryAsync(selectedEntry, "/images/vmlinuz", "/images/initrd", rotatedOptions);

        string image = await BuildImageAsync(tree, workspace.Root, package.Contract.BootRecipe.BootUuid);
        byte[] superblock = BuildBtrfsPrimarySuperblock(package.Contract.BootRecipe.RootUuid);

        await using FileStream ext4 = OpenImageForRead(image);
        object facts = VerifyCaptured(ext4, superblock, package.Contract, CancellationToken.None);

        Assert.Equal(package.Contract.BootRecipe.BootUuid, FactGuid(facts, "BootUuid"));
        Assert.Equal(package.Contract.BootRecipe.RootUuid, FactGuid(facts, "RootUuid"));
        Assert.Equal("/loader/entries/10-selected.conf", FactString(facts, "SelectedEntryPath"));
        Assert.Equal(package.Contract.Deployment.BootChecksum, FactString(facts, "BootChecksum"));
        Assert.Equal(package.Contract.Artifacts["kernel"].Sha256.ToLowerInvariant(), FactString(facts, "KernelSha256"));
        Assert.Equal(package.Contract.Artifacts["initramfs"].Sha256.ToLowerInvariant(), FactString(facts, "InitramfsSha256"));
    }

    // --------------------------------------------------- fact 9: wrong stateroot is refused

    [Fact]
    public async Task VerifyCaptured_WrongStateroot_Refuses()
    {
        using var package = new EdlRawBootBuilderTests.SyntheticPackage();
        using var workspace = new EdlRawBootBuilderTests.Workspace();

        string originalOptions = package.Contract.BootRecipe.NormalBootArgs;
        string ostreeToken = string.Empty;
        foreach (string candidate in originalOptions.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (candidate.StartsWith("ostree=", StringComparison.Ordinal))
            {
                Assert.True(ostreeToken.Length == 0, "the package options declare more than one ostree token");
                ostreeToken = candidate;
            }
        }

        Assert.True(ostreeToken.Length > 0, "the package options declare no ostree token");
        string[] tokenParts = ostreeToken.Split('/');
        Assert.True(tokenParts.Length == 6 && tokenParts[3].Length > 0, "unexpected package ostree token shape");
        tokenParts[3] = "wrongstateroot";
        string mutatedOptions = originalOptions.Replace(ostreeToken, string.Join('/', tokenParts), StringComparison.Ordinal);
        Assert.NotEqual(originalOptions, mutatedOptions);

        string tree = Path.Combine(workspace.Root, "tree");
        (string loaderDir, string entriesDir, string imagesDir) = CreateTree(tree);
        File.Copy(package.Contract.Artifacts["kernel"].FullPath, Path.Combine(imagesDir, "vmlinuz"));
        File.Copy(package.Contract.Artifacts["initramfs"].FullPath, Path.Combine(imagesDir, "initrd"));
        await File.WriteAllTextAsync(Path.Combine(loaderDir, "loader.conf"), "default 10-selected.conf\n");
        await WriteEntryAsync(
            Path.Combine(entriesDir, "10-selected.conf"), "/images/vmlinuz", "/images/initrd", mutatedOptions);

        string image = await BuildImageAsync(tree, workspace.Root, package.Contract.BootRecipe.BootUuid);
        byte[] superblock = BuildBtrfsPrimarySuperblock(package.Contract.BootRecipe.RootUuid);

        await using FileStream ext4 = OpenImageForRead(image);
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(
            () => VerifyCaptured(ext4, superblock, package.Contract, CancellationToken.None));

        Assert.StartsWith(MismatchPrefix, error.Message);
        Assert.Contains("state root", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ------------------------------------------------------------------ fixture helpers

    private static async Task<string> WriteStandardTreeAsync(string root, EdlRawPackageContract contract)
    {
        string tree = Path.Combine(root, "tree");
        (string loaderDir, string entriesDir, string imagesDir) = CreateTree(tree);
        File.Copy(contract.Artifacts["kernel"].FullPath, Path.Combine(imagesDir, "vmlinuz"));
        File.Copy(contract.Artifacts["initramfs"].FullPath, Path.Combine(imagesDir, "initrd"));
        await File.WriteAllTextAsync(Path.Combine(loaderDir, "loader.conf"), "default 10-selected.conf\n");
        await WriteEntryAsync(
            Path.Combine(entriesDir, "10-selected.conf"), "/images/vmlinuz", "/images/initrd",
            contract.BootRecipe.NormalBootArgs);
        return tree;
    }

    private static (string LoaderDir, string EntriesDir, string ImagesDir) CreateTree(string tree)
    {
        string loaderDir = Path.Combine(tree, "loader");
        string entriesDir = Path.Combine(loaderDir, "entries");
        string imagesDir = Path.Combine(tree, "images");
        Directory.CreateDirectory(entriesDir);
        Directory.CreateDirectory(imagesDir);
        return (loaderDir, entriesDir, imagesDir);
    }

    private static Task WriteEntryAsync(string path, string kernelPath, string initramfsPath, string options) =>
        File.WriteAllTextAsync(
            path,
            "title Freedom Installer\n"
            + "linux " + kernelPath + "\n"
            + "initrd " + initramfsPath + "\n"
            + "options " + options + "\n");

    private static async Task<string> BuildImageAsync(string tree, string root, Guid filesystemUuid)
    {
        Assert.True(
            OperatingSystem.IsLinux(),
            "BM05 ext4 fixtures require the CI Linux container with a real mke2fs; this is a real environment prerequisite, not a skip.");
        Assert.True(File.Exists(Mke2fsPath), $"{Mke2fsPath} was not found in the CI Linux container.");

        string image = Path.Combine(root, "boot.img");
        await using (FileStream sparse = new FileStream(image, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            sparse.SetLength(ImageBytes);
        }

        var start = new ProcessStartInfo
        {
            FileName = Mke2fsPath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("-q");
        start.ArgumentList.Add("-F");
        start.ArgumentList.Add("-t");
        start.ArgumentList.Add("ext4");
        start.ArgumentList.Add("-b");
        start.ArgumentList.Add("4096");
        start.ArgumentList.Add("-U");
        start.ArgumentList.Add(filesystemUuid.ToString("D"));
        start.ArgumentList.Add("-d");
        start.ArgumentList.Add(tree);
        start.ArgumentList.Add(image);

        using Process process = new Process { StartInfo = start };
        Assert.True(process.Start(), "mke2fs could not be started in the CI Linux container.");
        Task<string> stdout = process.StandardOutput.ReadToEndAsync();
        Task<string> stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
            await Task.WhenAll(stdout, stderr);
        }
        catch (OperationCanceledException)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
            }

            await Task.WhenAll(process.WaitForExitAsync(), stdout, stderr);
            throw;
        }

        Assert.True(
            process.ExitCode == 0,
            $"mke2fs failed (exit {process.ExitCode}).\nstdout: {stdout.Result}\nstderr: {stderr.Result}");
        return image;
    }

    private static FileStream OpenImageForRead(string image) =>
        new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read);

    /// <summary>
    /// Synthetic 4096-byte Btrfs primary superblock header: scope is FSID/header facts only
    /// (magic at 64, bytenr 65536 at 48, FSID at 32, 512 MiB total_bytes at 112, 4096-byte
    /// sectorsize at 144). No real Btrfs tree and no root-health claim.
    /// </summary>
    private static byte[] BuildBtrfsPrimarySuperblock(Guid fsid)
    {
        var superblock = new byte[BtrfsSuperblockBytes];
        Encoding.ASCII.GetBytes("_BHRfS_M").CopyTo(superblock, 64);
        BinaryPrimitives.WriteInt64LittleEndian(superblock.AsSpan(48), 65536);
        Assert.True(
            fsid.TryWriteBytes(superblock.AsSpan(32), bigEndian: true, out _),
            "the Btrfs FSID did not fit the synthetic superblock");
        BinaryPrimitives.WriteInt64LittleEndian(superblock.AsSpan(112), 512L * 1024 * 1024);
        BinaryPrimitives.WriteInt32LittleEndian(superblock.AsSpan(144), 4096);
        return superblock;
    }

    private static void FlipLastByte(string path)
    {
        using FileStream stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        stream.Seek(-1, SeekOrigin.End);
        int last = stream.ReadByte();
        stream.Seek(-1, SeekOrigin.End);
        stream.WriteByte((byte)(last ^ 0xFF));
    }

    private static string OtherHex(int length)
    {
        const string digits = "0123456789abcdef";
        var other = new char[length];
        for (int i = 0; i < length; i++)
        {
            other[i] = digits[(i + 1) % digits.Length];
        }

        return new string(other);
    }
}
