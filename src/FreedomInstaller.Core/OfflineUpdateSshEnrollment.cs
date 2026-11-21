using System.Security.Cryptography;
using System.Text;

namespace FreedomInstaller.Core;

public sealed record OfflineUpdateSshKey(string PublicKey, string Fingerprint);

public sealed record OfflineUpdateSshHostCandidate(OfflineUpdateUsbEndpoint Endpoint, OfflineUpdateSshKey HostKey);

/// <summary>
/// Helper for the offline-update USB SSH enrollment flow. This type only obtains a
/// CANDIDATE host key for user fingerprint comparison; it never writes to
/// known_hosts, never modifies StrictHostKeyChecking or password policy, never
/// generates keys, and never persists anything.
/// </summary>
public static class OfflineUpdateSshEnrollment
{
    private const string KeyType = "ssh-ed25519";
    private const int MaxPublicKeyChars = 4096;
    private const int MaxScanOutputChars = 16 * 1024;
    private const int DiagnosticsLimit = 2048;
    private static readonly TimeSpan KeyScanTimeout = TimeSpan.FromSeconds(20);

    /// <summary>Expected USB gadget host and port as emitted by ssh-keyscan.</summary>
    private const string ExpectedHost = "172.16.42.1";
    private const int ExpectedPort = 22;

    /// <summary>
    /// Parses and strictly validates an ssh-ed25519 public key blob
    /// ("ssh-ed25519 &lt;base64&gt;") and computes its SHA256 fingerprint
    /// (standard base64, padding stripped). Returns the canonical single-space form.
    /// </summary>
    public static OfflineUpdateSshKey ParsePublicKey(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (value.Length == 0)
            throw NewInvalid("Public key is empty.");
        if (value.Length > MaxPublicKeyChars)
            throw NewInvalid($"Public key exceeds the {MaxPublicKeyChars}-character limit.");

        foreach (var c in value)
        {
            if (c > 127)
                throw NewInvalid("Public key must be ASCII.");
            if (c == '\0')
                throw NewInvalid("Public key must not contain null characters.");
            if (char.IsControl(c) && c != '\t')
                throw NewInvalid("Public key must not contain control characters.");
        }

        var fields = value.Split(' ', '\t');
        if (fields.Length != 2)
            throw NewInvalid("Public key must contain exactly two fields: key type and base64 blob.");
        if (fields[0].Length == 0 || fields[1].Length == 0)
            throw NewInvalid("Public key fields must not be empty.");
        if (fields[0] != KeyType)
            throw NewInvalid($"Unsupported key type '{fields[0]}'; only {KeyType} is accepted.");

        var blobField = fields[1];
        byte[] wire;
        try
        {
            wire = Convert.FromBase64String(blobField);
        }
        catch (FormatException ex)
        {
            throw NewInvalid("Public key blob is not valid base64.", ex);
        }

        // Strict canonical base64: reject embedded whitespace or any non-canonical
        // encoding that FromBase64String tolerates but we must not round-trip.
        if (!string.Equals(Convert.ToBase64String(wire), blobField, StringComparison.Ordinal))
            throw NewInvalid("Public key blob is not canonical base64.");

        ValidateEd25519Wire(wire);

        var fingerprint = "SHA256:" + Convert.ToBase64String(SHA256.HashData(wire)).TrimEnd('=');
        return new OfflineUpdateSshKey($"{KeyType} {blobField}", fingerprint);
    }

    /// <summary>
    /// Builds the fixed argv for the on-device authorization helper. The canonical
    /// key (type + [A-Za-z0-9+/=] only) cannot escape the single-quoted argument.
    /// No private key material is involved.
    /// </summary>
    public static string BuildAuthorizationCommand(string publicKey)
    {
        var key = ParsePublicKey(publicKey);
        return $"/usr/bin/python3 -I /usr/libexec/armada/armada-authorize-installer '{key.PublicKey}'";
    }

    /// <summary>
    /// Parses ssh-keyscan output restricted to the expected USB endpoint
    /// 172.16.42.1:22, ed25519 only. Duplicate identical lines are accepted; zero
    /// keys, distinct keys, any other host/port/key type, options fields, or
    /// trailing garbage are rejected. No fallback, no trust decision.
    /// </summary>
    public static OfflineUpdateSshKey ParseHostKeyScanOutput(string output)
    {
        ArgumentNullException.ThrowIfNull(output);

        if (output.Length > MaxScanOutputChars)
            throw NewInvalid($"ssh-keyscan output exceeds the {MaxScanOutputChars}-character limit.");

        // Normal CRLF tool output is fine.
        var normalized = output.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');

        OfflineUpdateSshKey? key = null;
        foreach (var rawLine in normalized.Split('\n'))
        {
            var line = rawLine.Trim(' ', '\t');
            if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal))
                continue;

            var fields = line.Split(' ', '\t');
            if (fields.Length != 3)
                throw NewInvalid("ssh-keyscan line must contain exactly host, key type, and blob fields.");

            var host = fields[0];
            var bracketed = $"[{ExpectedHost}]:{ExpectedPort}";
            if (host != ExpectedHost && host != bracketed)
                throw NewInvalid($"ssh-keyscan line is for an unexpected host '{host}'; expected {ExpectedHost}:{ExpectedPort}.");

            var candidate = ParsePublicKey($"{fields[1]} {fields[2]}");

            if (key is null)
            {
                key = candidate;
            }
            else if (!string.Equals(key.PublicKey, candidate.PublicKey, StringComparison.Ordinal))
            {
                throw NewInvalid("ssh-keyscan output contains distinct host keys; refusing to choose.");
            }
        }

        if (key is null)
            throw NewInvalid("ssh-keyscan output contained no usable host key lines.");

        return key;
    }

    /// <summary>
    /// Discovers the single offline-update USB endpoint, then runs ssh-keyscan
    /// exactly once against the fixed endpoint to obtain a CANDIDATE host key for
    /// user fingerprint comparison. Nothing is written, stored, or trusted here.
    /// </summary>
    public static async Task<OfflineUpdateSshHostCandidate> DiscoverUsbHostAsync(
        ICommandRunner runner,
        string? powerShellExecutable = null,
        string? keyScanExecutable = null,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(runner);
        token.ThrowIfCancellationRequested();

        var endpoint = await OfflineUpdateUsbDiscovery.FindSingleAsync(runner, powerShellExecutable, token)
            .ConfigureAwait(false);

        token.ThrowIfCancellationRequested();

        var executable = ResolveKeyScanExecutable(keyScanExecutable);
        var command = new ProcessCommand(
            executable,
            new[] { "-4", "-T", "5", "-t", "ed25519", "-p", "22", endpoint.Host },
            KeyScanTimeout);

        var result = await runner.RunAsync(command, token).ConfigureAwait(false);

        if (result.ExitCode != 0)
        {
            var rawError = result.StandardError ?? string.Empty;
            var sanitized = new StringBuilder(rawError.Length);
            foreach (var ch in rawError)
            {
                if (!char.IsControl(ch) || ch == '	')
                    sanitized.Append(ch);
            }
            var diagnostics = sanitized.ToString().Trim();
            if (diagnostics.Length > DiagnosticsLimit)
                diagnostics = diagnostics[^DiagnosticsLimit..];
            throw new IOException(
                $"ssh-keyscan failed with exit code {result.ExitCode} against {ExpectedHost}:{ExpectedPort}. {diagnostics}");
        }

        var hostKey = ParseHostKeyScanOutput(result.StandardOutput ?? string.Empty);
        return new OfflineUpdateSshHostCandidate(endpoint, hostKey);
    }

    private static void ValidateEd25519Wire(byte[] wire)
    {
        // Wire format: u32be(len=11) "ssh-ed25519" u32be(len=32) 32-byte key.
        const int TypeLength = 11, KeyLength = 32, ExpectedLength = 4 + TypeLength + 4 + KeyLength;

        if (wire.Length != ExpectedLength)
            throw NewInvalid($"ed25519 wire blob must be exactly {ExpectedLength} bytes, got {wire.Length}.");
        if (ReadUInt32BE(wire, 0) != TypeLength)
            throw NewInvalid("ed25519 wire blob has an invalid type-length prefix.");
        if (!Encoding.ASCII.GetBytes(KeyType).AsSpan().SequenceEqual(wire.AsSpan(4, TypeLength)))
            throw NewInvalid("ed25519 wire blob type string does not match the declared key type.");
        if (ReadUInt32BE(wire, 4 + TypeLength) != KeyLength)
            throw NewInvalid("ed25519 wire blob has an invalid key-length prefix.");
    }

    private static uint ReadUInt32BE(byte[] buffer, int offset) =>
        ((uint)buffer[offset] << 24) | ((uint)buffer[offset + 1] << 16) |
        ((uint)buffer[offset + 2] << 8) | buffer[offset + 3];

    private static string ResolveKeyScanExecutable(string? keyScanExecutable)
    {
        if (keyScanExecutable is not null)
        {
            if (string.IsNullOrWhiteSpace(keyScanExecutable))
                throw new ArgumentException("ssh-keyscan executable must not be empty.", nameof(keyScanExecutable));
            if (keyScanExecutable.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0)
                throw new ArgumentException("ssh-keyscan executable must not contain newline or null characters.", nameof(keyScanExecutable));
            if (!Path.IsPathFullyQualified(keyScanExecutable))
                throw new ArgumentException("ssh-keyscan executable must be a fully qualified path.", nameof(keyScanExecutable));
            if (!File.Exists(keyScanExecutable))
                throw new IOException($"ssh-keyscan executable was not found at '{keyScanExecutable}'.");
            return keyScanExecutable;
        }

        if (OperatingSystem.IsMacOS())
        {
            // macOS ships OpenSSH in the sealed system volume.
            const string macPath = "/usr/bin/ssh-keyscan";
            if (!File.Exists(macPath))
                throw new IOException($"The default ssh-keyscan executable was not found at '{macPath}'.");
            return macPath;
        }

        if (!OperatingSystem.IsWindows())
            throw new IOException("No default ssh-keyscan executable is available on this platform; supply the absolute path explicitly.");

        var defaultPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "OpenSSH", "ssh-keyscan.exe");
        if (!Path.IsPathFullyQualified(defaultPath))
            throw new IOException("The default ssh-keyscan path could not be resolved to a fully qualified path.");
        if (!File.Exists(defaultPath))
            throw new IOException($"The default ssh-keyscan executable was not found at '{defaultPath}'.");
        return defaultPath;
    }

    private static InvalidDataException NewInvalid(string message, Exception? inner = null) =>
        new(message, inner);
}
