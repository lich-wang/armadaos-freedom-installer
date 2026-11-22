using System;
using System.IO;
using System.Threading;

namespace FreedomInstaller.Core;

/// <summary>
/// Byte contract for the kShim runtime that implements the mirrored
/// TB322FC/TB323FU/TB710FU Linux update policy. The exact literal is retained by the
/// used on-device update gate; it is a compatibility proof only, not
/// authentication, a device proof or a boot authorization.
/// </summary>
internal static class LinuxRuntimeContract
{
    internal const string MirrorMarkerText = "ARMADA_LINUX_MIRROR_V1";

    private static readonly byte[] MirrorMarker = "ARMADA_LINUX_MIRROR_V1"u8.ToArray();

    /// <summary>
    /// Only the new-system mirrored policy boards require the marker. The set follows Freedom's
    /// MIRROR_POLICY_MODELS (models.py); TB710FU joined it with the native mirrored boot_a/boot_b updater, so a
    /// TB710FU runtime built before that lacks the marker and is refused.
    /// </summary>
    internal static bool RequiresMirrorMarker(string? model) =>
        string.Equals(model, "TB322FC", StringComparison.Ordinal) ||
        string.Equals(model, "TB323FU", StringComparison.Ordinal) ||
        string.Equals(model, "TB710FU", StringComparison.Ordinal);

    internal static void RequireMirrorMarker(
        string path, string model, string role, CancellationToken cancellationToken)
    {
        if (!RequiresMirrorMarker(model))
            return;

        using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 64 * 1024, FileOptions.SequentialScan);
        RequireMirrorMarker(stream, model, role, cancellationToken);
    }

    internal static void RequireMirrorMarker(
        Stream stream, string model, string role, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!RequiresMirrorMarker(model))
            return;
        if (!stream.CanSeek)
            throw new ArgumentException("The runtime stream must be seekable.", nameof(stream));

        stream.Position = 0;
        if (!ContainsMarker(stream, cancellationToken))
        {
            throw new InvalidDataException(
                $"{role}: runtime for {model} is missing the {MirrorMarkerText} compatibility marker");
        }
        stream.Position = 0;
    }

    private static bool ContainsMarker(Stream stream, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[64 * 1024];
        byte[] carry = new byte[MirrorMarker.Length - 1];
        int carryCount = 0;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0)
                return false;

            int windowLength = carryCount + read;
            byte[] window = new byte[windowLength];
            carry.AsSpan(0, carryCount).CopyTo(window);
            buffer.AsSpan(0, read).CopyTo(window.AsSpan(carryCount));
            if (window.AsSpan().IndexOf(MirrorMarker) >= 0)
                return true;

            int keep = Math.Min(carry.Length, window.Length);
            window.AsSpan(window.Length - keep).CopyTo(carry);
            carryCount = keep;
        }
    }
}
