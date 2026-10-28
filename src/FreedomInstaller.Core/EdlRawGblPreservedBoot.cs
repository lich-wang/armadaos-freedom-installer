using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

// Immutable facts observed from the original OEM-signed vbmeta blob. An
// instance exists only after the raw blob was compared with the source claim
// and its own RSA/auth chain was verified, so validity is never a caller flag.
internal sealed record EdlRawOriginalBootSignatureFacts
{
    public string SignedVbmetaSha256 { get; init; } = string.Empty;

    public string PublicKeySha256 { get; init; } = string.Empty;

    public uint AlgorithmType { get; init; }

    public ulong RollbackIndex { get; init; }

    public uint RollbackIndexLocation { get; init; }

    public uint Flags { get; init; }

    public uint RequiredMajor { get; init; }

    public uint RequiredMinor { get; init; }

    public long SignedContentBytes { get; init; }

    public string SignedContentDigestHex { get; init; } = string.Empty;

    public string EffectiveContentDigestHex { get; init; } = string.Empty;

    internal bool OriginalSignatureValid => true;

    internal bool ContentDigestMatches =>
        string.Equals(SignedContentDigestHex, EffectiveContentDigestHex, StringComparison.OrdinalIgnoreCase);
}

internal sealed record EdlRawOriginalBootChainFacts(
    VerifiedEdlFile Original,
    string SignedVbmetaSha256,
    string PublicKeySha256,
    string BootChainPublicKeySha256);

// Owns only the new effective candidate read lease and file. The source built
// boot and the original input claim stay caller-owned and are never disposed
// or deleted here.
internal sealed class EdlRawGblPreservedBoot : IDisposable
{
    private readonly FileStream _effectiveLease;
    private int _disposed;

    internal EdlRawGblPreservedBoot(
        EdlRawBuiltBoot sourceBuiltBoot,
        VerifiedEdlFile originalBoot,
        VerifiedEdlFile effectiveCandidate,
        EdlRawOriginalBootSignatureFacts originalSignatureFacts,
        long payloadBytes,
        string payloadSha256,
        long vbmetaOffset,
        long vbmetaBytes,
        FileStream effectiveLease)
    {
        SourceBuiltBoot = sourceBuiltBoot;
        OriginalBoot = originalBoot;
        EffectiveCandidate = effectiveCandidate;
        OriginalSignatureFacts = originalSignatureFacts;
        PayloadBytes = payloadBytes;
        PayloadSha256 = payloadSha256;
        VbmetaOffset = vbmetaOffset;
        VbmetaBytes = vbmetaBytes;
        _effectiveLease = effectiveLease;
    }

    internal EdlRawBuiltBoot SourceBuiltBoot { get; }

    internal VerifiedEdlFile OriginalBoot { get; }

    internal VerifiedEdlFile EffectiveCandidate { get; }

    internal EdlRawOriginalBootSignatureFacts OriginalSignatureFacts { get; }

    internal long PayloadBytes { get; }

    internal string PayloadSha256 { get; }

    internal long VbmetaOffset { get; }

    internal long VbmetaBytes { get; }

    internal bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    internal async Task RevalidateAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        cancellationToken.ThrowIfCancellationRequested();

        await SourceBuiltBoot.RevalidateAsync(cancellationToken).ConfigureAwait(false);

        await Task.Run(
            () =>
            {
                ObjectDisposedException.ThrowIf(IsDisposed, this);
                EdlRawBootBuilder.VerifyHeldOutput(
                    _effectiveLease,
                    EffectiveCandidate,
                    "GBL effective boot",
                    cancellationToken);
            },
            cancellationToken).ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();
        ObjectDisposedException.ThrowIf(IsDisposed, this);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            _effectiveLease.Dispose();
        }
        catch (IOException)
        {
            // Best-effort lease release only; the host owns the work directory.
        }
        catch (ObjectDisposedException)
        {
            // Best-effort lease release only; the host owns the work directory.
        }

        try
        {
            File.Delete(EffectiveCandidate.Path);
        }
        catch (IOException)
        {
            // Best-effort cleanup only; the host owns the work directory.
        }
        catch (UnauthorizedAccessException)
        {
            // Best-effort cleanup only; the host owns the work directory.
        }
    }
}
