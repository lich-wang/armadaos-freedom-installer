using System;

namespace FreedomInstaller.Core;

/// <summary>
/// The one fail-closed write gate for a model that is registered for identification, its 9008 tool profile
/// and read-only validation, but whose install, boot maintenance, uninstall and global restore write routes
/// are not open yet.
/// <para>
/// Today that is exactly <c>TB710FU</c> (Lenovo Xiaoxin Pad Pro GT, SM8650): its bootloader stays locked and the
/// locked-bootloader signing route is a separate change. The gate never throws for TB322FC or TB323FU, so their
/// behaviour is unchanged.
/// </para>
/// <para>
/// Two layers use it. The App entry points check <see cref="IsWriteRoutePending"/> on the identified model and
/// stop before entering 9008. The Core write back ends (install, install backup, boot maintenance, uninstall,
/// global restore) call <see cref="RequireWriteRoute"/> before their first device write as a backstop; some of
/// them only receive a client that is already in 9008, so that layer does not by itself keep the tablet out of
/// 9008. The historical-identity read refuses a TB710FU backup the same way.
/// </para>
/// </summary>
public static class DeviceModelRoutes
{
    /// <summary>The canonical model whose write routes are still pending.</summary>
    public const string Tb710fuModel = "TB710FU";

    /// <summary>Stable code carried at the start of the refusal message.</summary>
    public const string RoutePendingCode = "MODEL_ROUTE_PENDING";

    /// <summary>
    /// True when <paramref name="model"/> names a model whose write routes are not open. The comparison
    /// ignores case only, so every casing of TB710FU is held back; nothing is trimmed or prefix-matched.
    /// </summary>
    public static bool IsWriteRoutePending(string? model) =>
        string.Equals(model, Tb710fuModel, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Throws before any write work when <paramref name="model"/> names a model whose write routes are not
    /// open. Never throws for any other value; unknown models are left to the existing exact model checks.
    /// </summary>
    /// <exception cref="InvalidOperationException">The model's write route is pending.</exception>
    public static void RequireWriteRoute(string? model)
    {
        if (IsWriteRoutePending(model))
        {
            throw new InvalidOperationException(
                RoutePendingCode
                + ": TB710FU 的安装、维护、卸载与恢复写入路线尚未开放，本次不会写入设备。");
        }
    }

    /// <summary>
    /// True when the internal install route (device check, install backup, direct install) of
    /// <paramref name="model"/> is not open. The TB710FU install route is open: it writes only boot and the new
    /// Linux partitions and keeps the device's AVB metadata (see <c>DirectTrustMode.AospPreserved</c>).
    /// Boot maintenance, uninstall and global restore stay behind <see cref="IsWriteRoutePending"/>.
    /// </summary>
    public static bool IsInstallRoutePending(string? model) => false;

    /// <summary>Install-route counterpart of <see cref="RequireWriteRoute"/>.</summary>
    public static void RequireInstallRoute(string? model)
    {
        if (IsInstallRoutePending(model))
        {
            RequireWriteRoute(model);
        }
    }

    /// <summary>True when <paramref name="exception"/> is the refusal thrown by <see cref="RequireWriteRoute"/>.</summary>
    public static bool IsRouteRefusal(Exception? exception) =>
        exception is InvalidOperationException
        && exception.Message.StartsWith(RoutePendingCode + ":", StringComparison.Ordinal);
}
