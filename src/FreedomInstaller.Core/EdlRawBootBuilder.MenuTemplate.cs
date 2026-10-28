// native project-menu Android-base replacement primitive. This partial reuses only the
// existing fixed helpers (composite decode, menu parse, unpack hashing/config reads, claim leases,
// native runner, packed-raw validation and the AVB footer leaf reader). It stages one owned child,
// drives the real pinned packer/unpacker, proves the repack by a self-unpack and records factual
// observations only. No OEM payload authentication, no hardware, loader, TF or bootability acceptance
// and no trust claim is made anywhere in this file.
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FreedomInstaller.Core;

/// <summary>
/// One completed template replacement. Owns exactly its own unique child directory and the two held
/// read-only output streams; disposing closes the streams and deletes only that child. It never
/// touches the inputs, the chosen parent or any sibling, and makes no acceptance claim.
/// </summary>
internal sealed class CurrentBootTemplatePayload : IDisposable
{
    private readonly FileStream? _packedStream;

    private readonly FileStream? _reportStream;

    private int _disposed;

    internal CurrentBootTemplatePayload(
        string directoryPath,
        VerifiedEdlFile packedRaw,
        FileStream packedStream,
        string templateBootSha256,
        string originalBaseSha256,
        string replacementBaseSha256,
        uint entryCount,
        uint defaultIndex,
        IReadOnlyDictionary<string, string> preservedPayloadSha256,
        VerifiedEdlFile verificationReport,
        FileStream reportStream)
    {
        DirectoryPath = directoryPath;
        PackedRaw = packedRaw;
        _packedStream = packedStream;
        TemplateBootSha256 = templateBootSha256;
        OriginalBaseSha256 = originalBaseSha256;
        ReplacementBaseSha256 = replacementBaseSha256;
        EntryCount = entryCount;
        DefaultIndex = defaultIndex;
        PreservedPayloadSha256 = preservedPayloadSha256;
        VerificationReport = verificationReport;
        _reportStream = reportStream;
    }

    internal string DirectoryPath { get; }

    internal VerifiedEdlFile PackedRaw { get; }

    internal string TemplateBootSha256 { get; }

    internal string OriginalBaseSha256 { get; }

    internal string ReplacementBaseSha256 { get; }

    internal uint EntryCount { get; }

    internal uint DefaultIndex { get; }

    internal IReadOnlyDictionary<string, string> PreservedPayloadSha256 { get; }

    internal VerifiedEdlFile VerificationReport { get; }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        Close(_packedStream);
        Close(_reportStream);
        EdlRawBootBuilder.TryDeleteOwnedChild(DirectoryPath);
    }

    private static void Close(FileStream? stream)
    {
        if (stream is null)
        {
            return;
        }

        try
        {
            stream.Dispose();
        }
        catch (IOException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }
}

public static partial class EdlRawBootBuilder
{
    private const string TemplateChildPrefix = "edl-boot-menu-template-";

    private const string TemplateSourceRawFileName = "source.raw";

    private const string TemplateSourceUnpackDirectoryName = "unpacked-source";

    private const string TemplateVerifyDirectoryName = "verify";

    /// <summary>
    /// Replaces only the Android base payload of one project-menu template and returns the result with
    /// its own staged child. The menu (entry count, default, UTF-8 labels, entry flags, alias paths,
    /// extra payloads) is preserved byte-for-byte by construction and proven by a native self-unpack.
    /// </summary>
    /// <exception cref="ArgumentNullException">An input is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The budget is not positive.</exception>
    /// <exception cref="OperationCanceledException">The token is already cancelled.</exception>
    internal static Task<CurrentBootTemplatePayload> ReplaceTemplateAndroidBaseAsync(
        VerifiedEdlFile templateBoot,
        VerifiedEdlFile replacementAndroidBase,
        long provenMaxRawBytes,
        EdlRawBootTools tools,
        ICommandRunner runner,
        string chosenParent,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(templateBoot);
        ArgumentNullException.ThrowIfNull(replacementAndroidBase);
        ArgumentNullException.ThrowIfNull(tools);
        ArgumentNullException.ThrowIfNull(runner);
        if (provenMaxRawBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(provenMaxRawBytes));
        }

        if (string.IsNullOrWhiteSpace(chosenParent))
        {
            throw new ArgumentException("chosen parent is empty", nameof(chosenParent));
        }

        ct.ThrowIfCancellationRequested();
        return Task.Run(
            () => ReplaceTemplateCoreAsync(
                templateBoot, replacementAndroidBase, provenMaxRawBytes, tools, runner, chosenParent, ct),
            ct);
    }

    private static async Task<CurrentBootTemplatePayload> ReplaceTemplateCoreAsync(
        VerifiedEdlFile templateBoot,
        VerifiedEdlFile replacementAndroidBase,
        long provenMaxRawBytes,
        EdlRawBootTools tools,
        ICommandRunner runner,
        string chosenParent,
        CancellationToken ct)
    {
        string parent = RequirePlainDirectory(chosenParent, "template chosen parent");
        string child = Path.Combine(parent, TemplateChildPrefix + Guid.NewGuid().ToString("N"));
        if (Directory.Exists(child))
        {
            throw new IOException("owned template directory already exists: " + child);
        }

        Directory.CreateDirectory(child);
        bool success = false;

        var leases = new List<HeldLease>();
        EdlRawBootTools? owned = null;
        FileStream? packedStream = null;
        FileStream? reportStream = null;
        try
        {
            owned = await tools.AcquireAsync(ct).ConfigureAwait(false);
            HeldLease template = OpenClaimLease("template_boot", templateBoot, ct);
            leases.Add(template);
            HeldLease replacement = OpenClaimLease("replacement_android_base", replacementAndroidBase, ct);
            leases.Add(replacement);

            // Source footer metadata: real RSA authentication of the AVB leaf metadata only. The signed
            // payload digest is deliberately never compared; it may be stale for a project GBL wrapper
            // and no OEM payload proof is claimed.
            var templateMeta = AvbNodeReadFooterLeafMetadata(template.Stream, template.Claim.Length, ct);
            string templateMetadataSha256 = AvbNodeSha256Hex(templateMeta.Blob);
            string templateKeySha256 = templateMeta.SourcePublicKeySha256;

            // Decode the whole project composite under the class cap only: the source may be an older
            // template whose raw exceeds the new candidate budget; only the new raw must fit the budget.
            (byte[] sourceRaw, string sourceRawSha) = CurrentBootDecodeComposite(template.Stream, MaxOriginalKernelBytes, ct);
            CurrentBootMenuFacts sourceMenu = CurrentBootParseMenu(sourceRaw, ct);

            string sourceRawPath = Path.Combine(child, TemplateSourceRawFileName);
            WriteNewFile(sourceRawPath, sourceRaw, "decoded template composite", ct);
            string sourceUnpackedDir = Path.Combine(child, TemplateSourceUnpackDirectoryName);
            await RunNativeAsync(
                    runner, owned.Unpacker.Path,
                    new[] { sourceRawPath, sourceUnpackedDir }, child,
                    "native template unpack step", ct)
                .ConfigureAwait(false);
            if (!Directory.Exists(sourceUnpackedDir))
            {
                throw new InvalidDataException("native template unpack step did not create the unpack directory");
            }

            string[] sourceConfigLines =
                CurrentBootReadConfigLines(Path.Combine(sourceUnpackedDir, UnpackedConfigFileName), ct);
            Dictionary<string, (long Length, string Sha256)> sourceFiles =
                CurrentBootHashUnpacked(sourceUnpackedDir, ct);
            if (!sourceFiles.TryGetValue(BaseImageFileName, out (long Length, string Sha256) originalBase))
            {
                throw new InvalidDataException("template unpack is missing the " + BaseImageFileName + " payload");
            }

            if (originalBase.Length <= 0)
            {
                throw new InvalidDataException("template unpack carries an empty " + BaseImageFileName + " payload");
            }

            // Copy the unpacked tree (config.cfg and every payload; aliases are config references, not
            // separate files) and replace ONLY the base payload with the verified replacement bytes.
            string repackDir = Path.Combine(child, "work", "repack");
            Directory.CreateDirectory(repackDir);
            foreach (string path in Directory.EnumerateFiles(sourceUnpackedDir))
            {
                string name = Path.GetFileName(path);
                if (string.Equals(name, BaseImageFileName, StringComparison.Ordinal))
                {
                    continue;
                }

                File.Copy(path, Path.Combine(repackDir, name), overwrite: false);
            }

            long replacementBytes;
            string replacementSha256;
            string newBasePath = Path.Combine(repackDir, BaseImageFileName);
            using (FileStream newBase = CreateNew(newBasePath, "replacement " + BaseImageFileName + " payload"))
            {
                replacement.Stream.Position = 0;
                using (IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
                {
                    CopyTo(replacement.Stream, newBase, hash, ct);
                    newBase.Flush(true);
                    replacementBytes = newBase.Length;
                    replacementSha256 = ToHex(hash.GetHashAndReset());
                }
            }

            if (replacementBytes != replacement.Claim.Length ||
                !string.Equals(replacementSha256, replacement.Claim.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("copied replacement base differs from its verified claim");
            }

            await RunNativeAsync(
                    runner, owned.Packer.Path,
                    new[] { UnpackedConfigFileName }, repackDir,
                    "native template pack step", ct)
                .ConfigureAwait(false);

            string packedPath = Path.Combine(repackDir, RepackedRawFileName);
            if (!File.Exists(packedPath))
            {
                throw new InvalidDataException("native template pack step did not produce " + RepackedRawFileName);
            }

            long packedBytes;
            string packedSha256;
            using (FileStream packed = OpenRead(packedPath, "template packed raw"))
            {
                packedBytes = packed.Length;
                ValidatePackedRaw(packed, packedBytes, provenMaxRawBytes);
                packedSha256 = HashStreamSha256(packed, ct);
            }

            CurrentBootMenuFacts newMenu = CurrentBootParseMenu(File.ReadAllBytes(packedPath), ct);

            string verifyDir = Path.Combine(child, TemplateVerifyDirectoryName);
            await RunNativeAsync(
                    runner, owned.Unpacker.Path,
                    new[] { packedPath, verifyDir }, child,
                    "native template self-unpack step", ct)
                .ConfigureAwait(false);
            if (!Directory.Exists(verifyDir))
            {
                throw new InvalidDataException("native template self-unpack step did not create the verify directory");
            }

            string[] verifyConfigLines =
                CurrentBootReadConfigLines(Path.Combine(verifyDir, UnpackedConfigFileName), ct);
            if (verifyConfigLines.Length != sourceConfigLines.Length)
            {
                throw new InvalidDataException("template self-unpack config line count differs from the template config");
            }

            for (int index = 0; index < sourceConfigLines.Length; index++)
            {
                if (!string.Equals(verifyConfigLines[index], sourceConfigLines[index], StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "template self-unpack config line " + index.ToString(CultureInfo.InvariantCulture)
                        + " differs from the template config");
                }
            }

            if (newMenu.EntryCount != sourceMenu.EntryCount ||
                newMenu.DefaultBefore != sourceMenu.DefaultBefore ||
                newMenu.EntryNames.Count != sourceMenu.EntryNames.Count)
            {
                throw new InvalidDataException("repacked template menu facts differ from the template menu");
            }

            for (int index = 0; index < sourceMenu.EntryNames.Count; index++)
            {
                if (!string.Equals(newMenu.EntryNames[index], sourceMenu.EntryNames[index], StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "repacked template entry name at index " + index.ToString(CultureInfo.InvariantCulture)
                        + " differs from the template");
                }
            }

            Dictionary<string, (long Length, string Sha256)> verifyFiles = CurrentBootHashUnpacked(verifyDir, ct);
            if (verifyFiles.Count != sourceFiles.Count)
            {
                throw new InvalidDataException("template self-unpack payload file count differs from the template unpack");
            }

            foreach (KeyValuePair<string, (long Length, string Sha256)> entry in verifyFiles)
            {
                if (!sourceFiles.ContainsKey(entry.Key))
                {
                    throw new InvalidDataException("template self-unpack produced unexpected payload '" + entry.Key + "'");
                }
            }

            foreach (KeyValuePair<string, (long Length, string Sha256)> entry in sourceFiles)
            {
                if (!verifyFiles.TryGetValue(entry.Key, out (long Length, string Sha256) actual))
                {
                    throw new InvalidDataException("template self-unpack lost payload '" + entry.Key + "'");
                }

                if (string.Equals(entry.Key, BaseImageFileName, StringComparison.Ordinal))
                {
                    continue;
                }

                if (actual.Length != entry.Value.Length ||
                    !string.Equals(actual.Sha256, entry.Value.Sha256, StringComparison.Ordinal))
                {
                    throw new InvalidDataException("template self-unpack changed payload '" + entry.Key + "'");
                }
            }

            (long verifyBaseLength, string verifyBaseSha256) = verifyFiles[BaseImageFileName];
            if (verifyBaseLength != replacementBytes ||
                !string.Equals(verifyBaseSha256, replacementSha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "repacked " + BaseImageFileName + " payload is not exactly the replacement base");
            }

            var preserved = new Dictionary<string, string>(verifyFiles.Count, StringComparer.Ordinal);
            foreach (KeyValuePair<string, (long Length, string Sha256)> entry in verifyFiles)
            {
                if (string.Equals(entry.Key, BaseImageFileName, StringComparison.Ordinal))
                {
                    continue;
                }

                preserved.Add(entry.Key, entry.Value.Sha256);
            }

            VerifyClaim(template.Stream, template.Claim, "template_boot", ct);
            VerifyClaim(replacement.Stream, replacement.Claim, "replacement_android_base", ct);
            await owned.RevalidateAsync(ct).ConfigureAwait(false);

            string reportPath = Path.Combine(child, ReportFileName);
            long reportBytes;
            using (FileStream report = CreateNew(reportPath, "template verification report"))
            {
                using (Utf8JsonWriter writer = new(report, new JsonWriterOptions { Indented = true }))
                {
                    WriteTemplateReport(
                        writer, template, replacementAndroidBase, replacementBytes, replacementSha256,
                        templateMetadataSha256, templateKeySha256, sourceRawSha, sourceMenu, newMenu,
                        originalBase, packedPath, packedBytes, packedSha256, provenMaxRawBytes,
                        verifyBaseLength, verifyBaseSha256, preserved, sourceConfigLines.Length);
                }

                report.Flush(true);
                reportBytes = report.Length;
            }

            string reportSha256 = HashFileSha256(reportPath, ct);
            var packedClaim = new VerifiedEdlFile(packedPath, packedBytes, packedSha256);
            var reportClaim = new VerifiedEdlFile(reportPath, reportBytes, reportSha256);
            try
            {
                packedStream = OpenHeldOutput(packedClaim, "template packed raw", ct);
                reportStream = OpenHeldOutput(reportClaim, "template verification report", ct);
                var result = new CurrentBootTemplatePayload(
                    child,
                    packedClaim,
                    packedStream,
                    template.Claim.Sha256,
                    originalBase.Sha256,
                    replacementSha256,
                    newMenu.EntryCount,
                    newMenu.DefaultBefore,
                    new ReadOnlyDictionary<string, string>(preserved),
                    reportClaim,
                    reportStream);

                // Ownership of both handles and of the child directory transfers together, atomically,
                // at this exact point; after it the outer finally must not close or delete anything.
                packedStream = null;
                reportStream = null;
                success = true;
                return result;
            }
            finally
            {
                CloseQuietly(packedStream);
                CloseQuietly(reportStream);
            }
        }
        finally
        {
            // Closes every stream before any deletion; only this call's own leases, own tool copy and
            // own child are released. Inputs, the caller's tools owner, the parent and siblings stay.
            CloseQuietly(packedStream);
            CloseQuietly(reportStream);
            foreach (HeldLease lease in leases)
            {
                CloseQuietly(lease.Stream);
            }

            owned?.Dispose();
            if (!success)
            {
                TryDeleteOwnedChild(child);
            }
        }
    }

    private static void WriteTemplateReport(
        Utf8JsonWriter writer,
        HeldLease template,
        VerifiedEdlFile replacementClaim,
        long replacementBytes,
        string replacementSha256,
        string templateMetadataSha256,
        string templateKeySha256,
        string sourceRawSha256,
        CurrentBootMenuFacts sourceMenu,
        CurrentBootMenuFacts newMenu,
        (long Length, string Sha256) originalBase,
        string packedPath,
        long packedBytes,
        string packedSha256,
        long provenMaxRawBytes,
        long verifyBaseLength,
        string verifyBaseSha256,
        IReadOnlyDictionary<string, string> preserved,
        int configLineCount)
    {
        writer.WriteStartObject();
        writer.WriteStartObject("templateBoot");
        writer.WriteString("path", template.Claim.Path);
        writer.WriteNumber("length", template.Claim.Length);
        writer.WriteString("sha256", template.Claim.Sha256);
        writer.WriteEndObject();
        writer.WriteStartObject("replacementAndroidBase");
        writer.WriteString("path", replacementClaim.Path);
        writer.WriteNumber("claimedLength", replacementClaim.Length);
        writer.WriteString("claimedSha256", replacementClaim.Sha256);
        writer.WriteNumber("copiedLength", replacementBytes);
        writer.WriteString("copiedSha256", replacementSha256);
        writer.WriteEndObject();
        writer.WriteStartObject("sourceFooterMetadata");
        writer.WriteString("blobSha256", templateMetadataSha256);
        writer.WriteString("sourcePublicKeySha256", templateKeySha256);
        writer.WriteBoolean("metadataSignatureAuthenticated", true);
        writer.WriteBoolean("payloadDigestVerified", false);
        writer.WriteString("payloadDigest", "not-verified-may-be-stale");
        writer.WriteEndObject();
        writer.WriteStartObject("sourceComposite");
        writer.WriteString("rawSha256", sourceRawSha256);
        writer.WriteNumber("entryCount", sourceMenu.EntryCount);
        writer.WriteNumber("defaultIndex", sourceMenu.DefaultBefore);
        writer.WriteEndObject();
        writer.WriteStartObject("originalBase");
        writer.WriteNumber("length", originalBase.Length);
        writer.WriteString("sha256", originalBase.Sha256);
        writer.WriteEndObject();
        writer.WriteStartObject("repackedRaw");
        writer.WriteString("path", packedPath);
        writer.WriteNumber("length", packedBytes);
        writer.WriteString("sha256", packedSha256);
        writer.WriteNumber("budgetMaxRawBytes", provenMaxRawBytes);
        writer.WriteEndObject();
        writer.WriteStartObject("selfUnpackProof");
        writer.WriteNumber("configLineCount", configLineCount);
        writer.WriteNumber("payloadFileCount", preserved.Count + 1);
        writer.WriteStartObject("baseImage");
        writer.WriteNumber("length", verifyBaseLength);
        writer.WriteString("sha256", verifyBaseSha256);
        writer.WriteBoolean("equalsReplacement", true);
        writer.WriteEndObject();
        writer.WriteBoolean("allOtherPayloadsUnchanged", true);
        writer.WriteBoolean("configLinesPreserved", true);
        writer.WriteEndObject();
        writer.WriteStartObject("menu");
        writer.WriteNumber("entryCount", newMenu.EntryCount);
        writer.WriteNumber("defaultIndex", newMenu.DefaultBefore);
        writer.WriteStartArray("entryNames");
        foreach (string name in newMenu.EntryNames)
        {
            writer.WriteStringValue(name);
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
        writer.WriteStartObject("preservedPayloadSha256");
        foreach (KeyValuePair<string, string> entry in preserved)
        {
            writer.WriteString(entry.Key, entry.Value);
        }

        writer.WriteEndObject();
        writer.WriteStartObject("nativeSteps");
        writer.WriteStartArray("commands");
        WriteNativeStep(writer, "unpacker(source.raw, unpacked-source)", 0);
        WriteNativeStep(writer, "packer(config.cfg) in work/repack with Output=RepackedKernel", 0);
        WriteNativeStep(writer, "unpacker(repacked raw, verify)", 0);
        writer.WriteEndArray();
        writer.WriteBoolean("selfUnpackVerified", true);
        writer.WriteEndObject();
        writer.WriteStartObject("claims");
        writer.WriteBoolean("oemPayloadAuthenticated", false);
        writer.WriteBoolean("hardwareAcceptanceClaimed", false);
        writer.WriteBoolean("tfAcceptanceClaimed", false);
        writer.WriteBoolean("bootabilityClaimed", false);
        writer.WriteEndObject();
        writer.WriteEndObject();
    }

    private static void WriteNativeStep(Utf8JsonWriter writer, string command, int exitCode)
    {
        writer.WriteStartObject();
        writer.WriteString("command", command);
        writer.WriteNumber("exitCode", exitCode);
        writer.WriteEndObject();
    }
}
