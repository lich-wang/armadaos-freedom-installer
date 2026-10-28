using System;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// The typed EDL raw boot tool set one direct install owns: an independent lease acquired from the caller's
/// <see cref="EdlRawBootTools"/>, held until this instance is disposed.
/// </summary>
/// <remarks>
/// A direct install never takes over the caller's loader. <see cref="LoadAsync"/> asks that loader for a lease of
/// its own through the internal <c>AcquireAsync</c> entry, so the pins stay in one place and no
/// <see cref="VerifiedEdlFile"/> claim is accepted here. Every instance owns exactly the lease it acquired: it
/// never disposes the caller's tools, never deletes a tool file and never starts a process.
/// <para>
/// <see cref="AcquireAsync"/> hands out a further independent child lease for a longer-lived owner, and
/// <see cref="RevalidateAsync"/> rehashes the held bytes rather than trusting an earlier read. Legacy
/// maintenance, support and toolbox materials are deliberately absent: this type carries only the two typed
/// tools.
/// </para>
/// </remarks>
public sealed class InternalInstallDirectAssets : IDisposable
{
    private readonly EdlRawBootTools _tools;

    private int _disposed;

    /// <summary>
    /// Private constructor: an instance only exists around a lease that was already acquired and verified, so
    /// no caller can assemble one from its own claims.
    /// </summary>
    private InternalInstallDirectAssets(EdlRawBootTools tools)
    {
        _tools = tools;
    }

    /// <summary>True once this instance's own lease has been released.</summary>
    public bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    /// <summary>
    /// The leased tool pair. Reading it after <see cref="Dispose"/> is refused, because the handles it held are
    /// already closed.
    /// </summary>
    /// <exception cref="ObjectDisposedException">This instance has already been disposed.</exception>
    internal EdlRawBootTools Tools
    {
        get
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);
            return _tools;
        }
    }

    /// <summary>
    /// Acquires an independent verified lease from the caller's loader and wraps it as the direct install asset
    /// set.
    /// </summary>
    /// <remarks>
    /// The null, disposed and pre-cancelled guards run before anything is acquired. If the token is cancelled
    /// after the lease was acquired but before it is handed back, that just-acquired lease is disposed and the
    /// cancellation is rethrown, so a refused load owns nothing. The caller's tools are never disposed here.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="tools"/> is null.</exception>
    /// <exception cref="ObjectDisposedException"><paramref name="tools"/> has already been disposed.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    /// <exception cref="InvalidOperationException">A held tool no longer matches its compiled pin.</exception>
    public static Task<InternalInstallDirectAssets> LoadAsync(
        EdlRawBootTools tools,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tools);

        cancellationToken.ThrowIfCancellationRequested();

        return LoadCoreAsync(tools, cancellationToken);
    }

    /// <summary>
    /// Acquires a further lease, independent of this instance, for a caller that needs its own lifetime.
    /// </summary>
    /// <exception cref="ObjectDisposedException">This instance has already been disposed.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    internal Task<InternalInstallDirectAssets> AcquireAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        cancellationToken.ThrowIfCancellationRequested();

        return AcquireCoreAsync(cancellationToken);
    }

    /// <summary>Rechecks the held bytes of this instance's own lease against the compiled pins.</summary>
    /// <exception cref="ObjectDisposedException">This instance has already been disposed.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    /// <exception cref="InvalidOperationException">A held tool no longer matches its compiled pin.</exception>
    internal Task RevalidateAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        cancellationToken.ThrowIfCancellationRequested();

        return _tools.RevalidateAsync(cancellationToken);
    }

    /// <summary>
    /// Releases only the lease this instance owns. Idempotent: it never disposes the caller's tools, never
    /// deletes a tool file and never touches another instance's handles.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _tools.Dispose();
    }

    // ---------------------------------------------------------------- acquisition body

    private static async Task<InternalInstallDirectAssets> LoadCoreAsync(
        EdlRawBootTools tools,
        CancellationToken cancellationToken)
    {
        EdlRawBootTools acquired = await tools.AcquireAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            // The caller may cancel between the lease arriving and the handoff; nothing may stay owned then.
            cancellationToken.ThrowIfCancellationRequested();
        }
        catch
        {
            acquired.Dispose();
            throw;
        }

        return new InternalInstallDirectAssets(acquired);
    }

    private async Task<InternalInstallDirectAssets> AcquireCoreAsync(CancellationToken cancellationToken)
    {
        EdlRawBootTools acquired = await _tools.AcquireAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
        }
        catch
        {
            acquired.Dispose();
            throw;
        }

        return new InternalInstallDirectAssets(acquired);
    }
}
