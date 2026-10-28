using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace FreedomInstaller.App;

internal enum DriverInstallOutcome
{
    Completed,
    Cancelled,
    RebootRequired,
    Failed,
}

internal record DriverInstallResult(DriverInstallOutcome Outcome, int? ExitCode, string? Error);

internal static class WindowsDriverInstaller
{
    private const int ErrorCancelled = 1223;
    private const int RebootRequiredExitCode = 3010;

    internal static async Task<DriverInstallResult> InstallAsync(QualcommDriverFiles files)
    {
        if (!OperatingSystem.IsWindows()
            || RuntimeInformation.OSArchitecture != Architecture.X64
            || RuntimeInformation.ProcessArchitecture != Architecture.X64)
        {
            return Failure("Driver installation requires a native Windows x64 process.");
        }

        try
        {
            BundledQualcommDriver.ValidateFiles(files);
        }
        catch (Exception error)
        {
            return Failure($"Bundled driver package validation failed: {Describe(error)}");
        }

        // SpecialFolder.System maps to the real System32 only because the guard above
        // already rejected emulated x86 / ARM64 processes.
        string pnputilPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "pnputil.exe");

        if (string.IsNullOrWhiteSpace(pnputilPath)
            || !Path.IsPathFullyQualified(pnputilPath)
            || !File.Exists(pnputilPath))
        {
            return Failure("System pnputil.exe could not be located.");
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = pnputilPath,
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        startInfo.ArgumentList.Add("/add-driver");
        startInfo.ArgumentList.Add(files.InfPath);
        startInfo.ArgumentList.Add("/install");

        Process? process = null;
        try
        {
            process = Process.Start(startInfo);
            if (process is null)
            {
                return Failure("pnputil.exe could not be started.");
            }

            await process.WaitForExitAsync().ConfigureAwait(false);

            int exitCode = process.ExitCode;
            return InterpretExitCode(exitCode);
        }
        catch (Exception error)
        {
            return InterpretStartFailure(error);
        }
        finally
        {
            process?.Dispose();
        }
    }

    internal static DriverInstallResult InterpretExitCode(int exitCode)
    {
        switch (exitCode)
        {
            case 0:
                return new DriverInstallResult(DriverInstallOutcome.Completed, 0, null);
            case RebootRequiredExitCode:
                return new DriverInstallResult(DriverInstallOutcome.RebootRequired, RebootRequiredExitCode, null);
            default:
                return new DriverInstallResult(
                    DriverInstallOutcome.Failed,
                    exitCode,
                    $"pnputil.exe exited with code {exitCode}.");
        }
    }

    internal static DriverInstallResult InterpretStartFailure(Exception error)
    {
        ArgumentNullException.ThrowIfNull(error);

        if (error is Win32Exception win32 && win32.NativeErrorCode == ErrorCancelled)
        {
            return new DriverInstallResult(DriverInstallOutcome.Cancelled, null, null);
        }

        return new DriverInstallResult(DriverInstallOutcome.Failed, null, Describe(error));
    }

    private static DriverInstallResult Failure(string error)
    {
        return new DriverInstallResult(DriverInstallOutcome.Failed, null, error);
    }

    private static string Describe(Exception error)
    {
        return string.IsNullOrWhiteSpace(error.Message) ? error.GetType().Name : error.Message;
    }
}
