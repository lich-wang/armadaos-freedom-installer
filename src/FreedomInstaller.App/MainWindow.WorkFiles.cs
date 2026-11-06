using System;
using System.IO;
using FreedomInstaller.Core;

namespace FreedomInstaller.App;

public partial class MainWindow
{
    private InstallerWorkSession? _workSession;
    private string TemporaryWorkRoot => (_workSession ??= new InstallerWorkSession(
        Environment.GetEnvironmentVariable("FREEDOM_WORK_ROOT")
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ArmadaOS Freedom", "Work"))).DirectoryPath;

    private void SaveWorkLogOnClose()
    {
        if (_workSession is null) return;
        try
        {
            File.WriteAllLines(Path.Combine(_workSession.DirectoryPath, "installer.log"),
                System.Linq.Enumerable.Select(_localizedLogRows, row => row.Row.Text));
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private void CleanWorkFilesOnClose(bool preserveRecovery)
    {
        if (_workSession is null || preserveRecovery || _internalInstallOperationActive
            || _userdataUninstallOperationActive || _bootMaintenanceOperationActive) return;
        try
        {
            // Closing an idle window releases file leases only; it sends no device command.
            _userdataUninstallBackend?.Dispose();
            _userdataUninstallMenu?.Dispose();
            _userdataUninstallOriginal?.Dispose();
            _bootMaintenanceBackend?.Dispose();
            _internalInstallBackend?.Dispose();
            _internalInstallAssets?.Dispose();
            _internalInstallNativeTools?.Dispose();
            _internalInstallArtifacts?.Dispose();
            _internalInstallPackage?.Dispose();
            _internalInstallBackup?.Dispose();
            _internalInstallEdlTools?.Dispose();
            _workSession.Complete(false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            // Keep the owned directory when a lease cannot be released or a receipt cannot be saved.
            System.Diagnostics.Trace.WriteLine("Installer work cleanup: " + exception.Message);
        }
    }
}
