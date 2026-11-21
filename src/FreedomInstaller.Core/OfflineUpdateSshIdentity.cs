#nullable enable
namespace FreedomInstaller.Core;

using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

/// <summary>Result of ensuring a dedicated offline-upgrade SSH client key exists.</summary>
public sealed record OfflineUpdateSshIdentity(string IdentityFile, OfflineUpdateSshKey PublicKey);

public static class OfflineUpdateSshIdentityStore
{
    private const string PrivateKeyName = "installer_ed25519";
    private const string PublicKeySuffix = ".pub";
    private const string LockFileName = ".identity.lock";
    private const int MaxPrivateKeyBytes = 65536;
    private static readonly TimeSpan KeygenTimeout = TimeSpan.FromSeconds(20);

    public static async Task<OfflineUpdateSshIdentity> EnsureAsync(
        string directory,
        ICommandRunner runner,
        string? keygenExecutable = null,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(directory);
        ArgumentNullException.ThrowIfNull(runner);
        token.ThrowIfCancellationRequested();

        string exe = ResolveKeygenExecutable(keygenExecutable);
        string dir = ValidateAndNormalizeDirectory(directory);
        EnsureDirectory(dir);

        string privatePath = Path.Combine(dir, PrivateKeyName);
        string publicPath = privatePath + PublicKeySuffix;
        string lockPath = Path.Combine(dir, LockFileName);

        CheckNotReparseOrDirectory(lockPath, "Lock file");
        using FileStream lockStream = OpenLock(lockPath);

        CheckNotReparseOrDirectory(publicPath, "Public key");
        FileAttributes? privAttr = CheckNotReparseOrDirectory(privatePath, "Private key");
        bool privateExists = privAttr.HasValue;
        bool publicExists = File.Exists(publicPath);

        if (!privateExists && publicExists)
            throw new IOException($"Incomplete SSH identity in '{dir}': public key exists without private key.");

        if (!privateExists)
        {
            token.ThrowIfCancellationRequested();
            await RunKeygenAsync(runner, exe, new[] { "-q", "-t", "ed25519", "-N", "", "-C", "armada-offline-installer", "-f", privatePath }, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
        }

        CheckNotReparseOrDirectory(publicPath, "Public key");
        ValidatePrivateKeyFile(privatePath);
        ApplySecurity(privatePath, isDir: false, newlyCreated: !privateExists);

        token.ThrowIfCancellationRequested();
        OfflineUpdateSshKey publicKey = await DerivePublicKeyAsync(runner, exe, privatePath, token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();

        return new OfflineUpdateSshIdentity(privatePath, publicKey);
    }

    private static string ValidateAndNormalizeDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            throw new ArgumentException("Directory must be an absolute, fully-qualified path.", nameof(path));
        ValidateNoForbiddenChars(path);
        string full = Path.GetFullPath(path);
        string root = Path.GetPathRoot(full)!;
        if (string.Equals(full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                          root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                          OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new IOException("Identity directory must not be a filesystem root.");
        return full;
    }

    private static void ValidateNoForbiddenChars(string path)
    {
        if (path.IndexOfAny(new[] { '\n', '\r', '\0', '"', '%' }) >= 0 || path.Contains("${", StringComparison.Ordinal))
            throw new ArgumentException("Path contains forbidden characters (CRLF, NUL, quote, '%', or '${').");
    }

    private static FileAttributes? CheckNotReparseOrDirectory(string path, string desc)
    {
        try
        {
            var attrs = File.GetAttributes(path);
            if ((attrs & FileAttributes.ReparsePoint) != 0)
                throw new IOException($"{desc} '{path}' is a reparse point or link.");
            if ((attrs & FileAttributes.Directory) != 0)
                throw new IOException($"{desc} '{path}' is a directory; expected regular file.");
            return attrs;
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            if (new FileInfo(path).LinkTarget != null)
                throw new IOException($"{desc} '{path}' is a dangling symlink.");
            return null;
        }
    }

    private static void EnsureDirectory(string dir)
    {
        bool newlyCreated = false;
        try
        {
            var attrs = File.GetAttributes(dir);
            if ((attrs & FileAttributes.ReparsePoint) != 0)
                throw new IOException($"Directory '{dir}' is a reparse point.");
            if ((attrs & FileAttributes.Directory) == 0)
                throw new IOException($"Directory path '{dir}' exists but is not a directory.");
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            if (new DirectoryInfo(dir).LinkTarget != null)
                throw new IOException($"Directory '{dir}' is a dangling symlink.");
            Directory.CreateDirectory(dir);
            newlyCreated = true;
            if ((File.GetAttributes(dir) & FileAttributes.ReparsePoint) != 0)
                throw new IOException($"Directory '{dir}' was created as a reparse point.");
        }
        ApplySecurity(dir, isDir: true, newlyCreated: newlyCreated);
    }

    private static void ApplySecurity(string path, bool isDir, bool newlyCreated = false)
    {
        if (!OperatingSystem.IsWindows())
        {
            var mode = isDir ? UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                             : UnixFileMode.UserRead | UnixFileMode.UserWrite;
            if (isDir) new DirectoryInfo(path).UnixFileMode = mode;
            else File.SetUnixFileMode(path, mode);
            return;
        }
        ApplyWindowsAcl(path, isDir, newlyCreated);
    }

    [SupportedOSPlatform("windows")]
    private static void ApplyWindowsAcl(string path, bool isDir, bool newlyCreated)
    {
        using WindowsIdentity currentIdentity = WindowsIdentity.GetCurrent();
        SecurityIdentifier currentSID = (SecurityIdentifier)currentIdentity.User!;
        FileSystemSecurity sec = isDir ? new DirectoryInfo(path).GetAccessControl() : new FileInfo(path).GetAccessControl();
        var owner = sec.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        bool elevatedCreation = newlyCreated &&
            owner?.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) == true &&
            new WindowsPrincipal(currentIdentity).IsInRole(WindowsBuiltInRole.Administrator);
        if (owner != currentSID && !elevatedCreation)
            throw new IOException($"Path '{path}' is not owned by current user.");

        if (isDir)
        {
            var dSec = new DirectorySecurity();
            dSec.SetOwner(currentSID);
            dSec.SetAccessRuleProtection(true, false);
            dSec.AddAccessRule(new FileSystemAccessRule(currentSID, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(path).SetAccessControl(dSec);
        }
        else
        {
            var fSec = new FileSecurity();
            fSec.SetOwner(currentSID);
            fSec.SetAccessRuleProtection(true, false);
            fSec.AddAccessRule(new FileSystemAccessRule(currentSID, FileSystemRights.FullControl, AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(fSec);
        }
    }

    private static FileStream OpenLock(string lockPath)
    {
        try { return new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
        catch (Exception ex) { throw new IOException($"Failed to acquire identity lock '{lockPath}': {ex.Message}", ex); }
    }

    private static string ResolveKeygenExecutable(string? candidate)
    {
        candidate = !string.IsNullOrWhiteSpace(candidate) ? candidate : OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "OpenSSH", "ssh-keygen.exe")
            : OperatingSystem.IsMacOS()
                ? "/usr/bin/ssh-keygen" // macOS ships OpenSSH in the sealed system volume.
                : throw new IOException("ssh-keygen executable must be explicitly provided on non-Windows.");
        if (!Path.IsPathFullyQualified(candidate))
            throw new ArgumentException($"ssh-keygen executable must be absolute and fully-qualified: '{candidate}'.");
        ValidateNoForbiddenChars(candidate);
        string full = Path.GetFullPath(candidate);
        var attrs = CheckNotReparseOrDirectory(full, "ssh-keygen") ?? throw new IOException($"ssh-keygen not found: '{full}'.");
        return full;
    }

    private static void ValidatePrivateKeyFile(string path)
    {
        CheckNotReparseOrDirectory(path, "Private key");
        var info = new FileInfo(path);
        if (info.Length <= 0 || info.Length > MaxPrivateKeyBytes)
            throw new IOException($"Private key '{path}' size invalid ({info.Length} bytes; expected 1-{MaxPrivateKeyBytes}).");
    }

    private static async Task<ProcessResult> RunKeygenAsync(ICommandRunner runner, string exe, string[] args, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        ProcessResult res = await runner.RunAsync(new ProcessCommand(exe, args, KeygenTimeout), token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        if (res.ExitCode != 0)
            throw new IOException($"ssh-keygen failed ({res.ExitCode}): {SanitizeStderr(res.StandardError)}");
        return res;
    }

    private static async Task<OfflineUpdateSshKey> DerivePublicKeyAsync(ICommandRunner runner, string exe, string privatePath, CancellationToken token)
    {
        ProcessResult res = await RunKeygenAsync(runner, exe, new[] { "-y", "-P", "", "-f", privatePath }, token).ConfigureAwait(false);
        string outText = res.StandardOutput;
        if (outText.EndsWith("\r\n", StringComparison.Ordinal)) outText = outText[..^2];
        else if (outText.EndsWith('\n') || outText.EndsWith('\r')) outText = outText[..^1];

        if (outText.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0)
            throw new IOException("Derived public key contains unexpected control characters.");

        string[] parts = outText.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
            throw new IOException("Derived public key format invalid from ssh-keygen.");

        return OfflineUpdateSshEnrollment.ParsePublicKey($"{parts[0]} {parts[1]}");
    }

    private static string SanitizeStderr(string? stderr)
    {
        if (string.IsNullOrWhiteSpace(stderr)) return "no details";
        string s = stderr.Trim();
        if (s.Length > 256) s = string.Concat(s.AsSpan(0, 256), "…");
        return s.Replace('\n', ' ').Replace('\r', ' ');
    }
}
