using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core.Gbl;

/// <summary>
/// The two standard GBL runtime variants. The enum is closed on purpose: there is no "unknown" or
/// "default" member, so a caller can never fall through to an unverified asset.
/// </summary>
internal enum GblRuntimeRegion
{
    Prc,
    Row,
}

/// <summary>
/// Stages one pinned standard GBL runtime EFI asset out of this assembly into a caller-owned evidence
/// directory.
/// <para>
/// The asset is fixed at compile time: source version <c>6.2.192-mod2</c>, commit
/// <c>ff2a5e2cf71541a23141a9b4d8cd8e8ebe34f340</c>, exactly one of the two standard files. There is no
/// path, stream or file-name input, no <c>_arb</c> variant, and no download: a missing or mismatching
/// embedded resource is a hard failure. The bytes are length- and SHA-256-checked against the compiled
/// pins before the destination file is created, and the destination is opened with
/// <see cref="FileMode.CreateNew"/> so an existing file is never overwritten or reused.
/// </para>
/// </summary>
internal static class GblRuntimeAssets
{
    internal const string SourceVersion = "6.2.192-mod2";

    internal const string SourceCommit = "ff2a5e2cf71541a23141a9b4d8cd8e8ebe34f340";

    private const long StandardAssetLength = 282_624;

    private const string PrcResourceName = "FreedomInstaller.GblRuntime.Prc.efi";
    private const string PrcFileName = "generic_superfastboot_prc.efi";
    private const string PrcSha256 = "B91DB7974DA80976BC73ADD671F4ADFB833AEA4FD0D9D7604B75CB63415FED84";

    private const string RowResourceName = "FreedomInstaller.GblRuntime.Row.efi";
    private const string RowFileName = "generic_superfastboot_row.efi";
    private const string RowSha256 = "E21F6D5FFE29113943092AC4A2A75E4FA03960831CC8855316C784B472999ABD";

    /// <summary>
    /// Verifies the embedded standard asset for <paramref name="region"/> and writes it to
    /// <c>existingOwnedEvidenceDir\&lt;fixed basename&gt;</c>. The directory must already exist; it is never
    /// created here. Only a file this invocation created is removed on failure.
    /// </summary>
    internal static async Task<VerifiedEdlFile> StageAsync(
        GblRuntimeRegion region,
        string existingOwnedEvidenceDir,
        CancellationToken ct = default)
    {
        string resourceName;
        string fileName;
        string expectedSha256;
        switch (region)
        {
            case GblRuntimeRegion.Prc:
                resourceName = PrcResourceName;
                fileName = PrcFileName;
                expectedSha256 = PrcSha256;
                break;
            case GblRuntimeRegion.Row:
                resourceName = RowResourceName;
                fileName = RowFileName;
                expectedSha256 = RowSha256;
                break;
            default:
                throw new ArgumentOutOfRangeException(
                    nameof(region), region, "Unknown GBL runtime region; no default asset exists.");
        }

        if (string.IsNullOrWhiteSpace(existingOwnedEvidenceDir))
        {
            throw new ArgumentException(
                "An existing owned evidence directory is required.", nameof(existingOwnedEvidenceDir));
        }

        ct.ThrowIfCancellationRequested();

        var directory = Path.GetFullPath(existingOwnedEvidenceDir);
        if (!Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException(
                $"The evidence directory '{directory}' does not exist; it is never created by this call.");
        }

        var bytes = new byte[StandardAssetLength];
        var assembly = typeof(GblRuntimeAssets).Assembly;
        using (var source = assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException(
                $"The embedded GBL runtime asset '{resourceName}' is missing from assembly " +
                $"'{assembly.GetName().Name}'. The single-file build must embed it; nothing is downloaded at run time."))
        {
            if (source.Length != StandardAssetLength)
            {
                throw new InvalidOperationException(
                    $"The embedded GBL runtime asset '{resourceName}' is {source.Length} bytes; " +
                    $"{StandardAssetLength} bytes are required.");
            }

            var read = 0;
            while (read < bytes.Length)
            {
                var chunk = await source.ReadAsync(bytes.AsMemory(read, bytes.Length - read), ct)
                    .ConfigureAwait(false);
                if (chunk == 0)
                {
                    throw new InvalidOperationException(
                        $"The embedded GBL runtime asset '{resourceName}' ended after {read} bytes; " +
                        $"{StandardAssetLength} bytes are required.");
                }

                read += chunk;
            }
        }

        ct.ThrowIfCancellationRequested();

        var actualSha256 = Convert.ToHexString(SHA256.HashData(bytes));
        if (!string.Equals(actualSha256, expectedSha256, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The embedded GBL runtime asset '{resourceName}' has SHA-256 {actualSha256}; " +
                $"the pinned value is {expectedSha256}.");
        }

        var path = Path.Combine(directory, fileName);
        var created = false;
        try
        {
            using (var output = new FileStream(
                path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous))
            {
                created = true;
                await output.WriteAsync(bytes, ct).ConfigureAwait(false);
                await output.FlushAsync(ct).ConfigureAwait(false);
            }
        }
        catch
        {
            if (created)
            {
                try
                {
                    File.Delete(path);
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }

            throw;
        }

        return new VerifiedEdlFile(path, StandardAssetLength, expectedSha256);
    }
}
