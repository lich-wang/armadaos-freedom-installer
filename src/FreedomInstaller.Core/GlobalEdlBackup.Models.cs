using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json.Serialization;

namespace FreedomInstaller.Core;

/// <summary>
/// One observation of the local verification pass: the fixed stage name, the role and LUN being verified,
/// and the byte counters of that stage. The values are informational only; they never gate the result.
/// </summary>
public sealed record GlobalEdlProgress(
    string Stage,
    string? Role,
    int? Lun,
    long CompletedBytes,
    long TotalBytes);

/// <summary>
/// The manifest (schema 1 or 2) of one original-layout global backup. Every value is read back from
/// <c>manifest.json</c> and validated against the actual files; nothing here is trusted on its own.
/// Every member is required, so a missing property is a parse failure instead of an assumed default.
/// </summary>
internal sealed class GlobalEdlManifest
{
    [JsonRequired]
    public int SchemaVersion { get; set; } = 2;

    [JsonRequired]
    public string State { get; set; } = string.Empty;

    [JsonRequired]
    public GlobalEdlIdentity Identity { get; set; } = null!;

    [JsonRequired]
    public DateTimeOffset CreatedUtc { get; set; }

    [JsonRequired]
    public long ChunkBytes { get; set; } = GlobalEdlBackup.ChunkBytes;

    [JsonRequired]
    public long RawBytes { get; set; }

    [JsonRequired]
    public long CompressedBytes { get; set; }

    [JsonRequired]
    public List<GlobalEdlLun> Luns { get; set; } = new();

    [JsonRequired]
    public List<GlobalEdlRegion> Regions { get; set; } = new();
}

/// <summary>Geometry of one UFS LUN: sector size, sector count and the GPT disk GUID of that LUN.</summary>
internal sealed class GlobalEdlLun
{
    [JsonRequired]
    public int Lun { get; set; }

    [JsonRequired]
    public int SectorSize { get; set; }

    [JsonRequired]
    public long TotalSectors { get; set; }

    [JsonRequired]
    public string DiskGuid { get; set; } = string.Empty;
}

/// <summary>
/// One captured region of a LUN: a GPT fragment or exactly one partition, with its absolute sector span and
/// the sequential GZip chunks that hold its raw bytes.
/// </summary>
internal sealed class GlobalEdlRegion
{
    [JsonRequired]
    public string Role { get; set; } = string.Empty;

    [JsonRequired]
    public string Kind { get; set; } = string.Empty;

    [JsonRequired]
    public int Lun { get; set; }

    [JsonRequired]
    public long StartSector { get; set; }

    [JsonRequired]
    public long SectorCount { get; set; }

    [JsonRequired]
    public int SectorSize { get; set; }

    [JsonRequired]
    public int? PartitionNumber { get; set; }

    [JsonRequired]
    public string? PartitionName { get; set; }

    [JsonRequired]
    public string? PartUuid { get; set; }

    [JsonRequired]
    public List<GlobalEdlChunk> Chunks { get; set; } = new();
}

/// <summary>One compressed chunk of a region; offsets are relative to the region start.</summary>
internal sealed class GlobalEdlChunk
{
    [JsonRequired]
    public string FileName { get; set; } = string.Empty;

    [JsonRequired]
    public long OffsetBytes { get; set; }

    [JsonRequired]
    public long RawBytes { get; set; }

    [JsonRequired]
    public string RawSha256 { get; set; } = string.Empty;

    [JsonRequired]
    public long CompressedBytes { get; set; }

    [JsonRequired]
    public string CompressedSha256 { get; set; } = string.Empty;
}

/// <summary>
/// A fully verified, locally opened global backup set. Only <see cref="GlobalEdlBackup.OpenAsync"/> can create
/// one, and it is only created after every manifest claim has been proven against the files on disk.
/// <para>
/// The set keeps read-only leases on <c>manifest.json</c>, its sidecar and every chunk file until
/// <see cref="Dispose"/>, so a concurrent writer cannot change the bytes under a reader. The manifest and the
/// decoded GPT tables are internal: a public caller can read the summary numbers but can never replace the
/// manifest or hand in a set that was not verified here.
/// </para>
/// </summary>
public sealed class GlobalEdlBackupSet : IDisposable
{
    private readonly ReadOnlyCollection<FileStream> _leases;
    private bool _disposed;

    internal GlobalEdlBackupSet(
        string directoryPath,
        string manifestPath,
        string manifestSha256,
        GlobalEdlManifest manifest,
        IReadOnlyDictionary<int, GptTable> tables,
        long rawBytes,
        long compressedBytes,
        int partitionCount,
        IReadOnlyList<FileStream> leases)
    {
        DirectoryPath = directoryPath;
        ManifestPath = manifestPath;
        ManifestSha256 = manifestSha256;
        Identity = manifest.Identity;
        RawBytes = rawBytes;
        CompressedBytes = compressedBytes;
        PartitionCount = partitionCount;
        Manifest = manifest;
        Tables = new ReadOnlyDictionary<int, GptTable>(
            new Dictionary<int, GptTable>(tables));
        _leases = new ReadOnlyCollection<FileStream>(new List<FileStream>(leases));
    }

    /// <summary>Absolute directory that holds the manifest, its sidecar and every chunk file.</summary>
    public string DirectoryPath { get; }

    /// <summary>Absolute path of the verified <c>manifest.json</c>.</summary>
    public string ManifestPath { get; }

    /// <summary>Uppercase SHA-256 of the exact <c>manifest.json</c> bytes that were verified.</summary>
    public string ManifestSha256 { get; }

    /// <summary>Identity recorded by the backup that produced this set.</summary>
    public GlobalEdlIdentity Identity { get; }

    /// <summary>Total raw bytes of every captured region, GPT fragments included.</summary>
    public long RawBytes { get; }

    /// <summary>Total compressed bytes of every chunk file.</summary>
    public long CompressedBytes { get; }

    /// <summary>Number of captured partitions; the twelve GPT fragments are not counted.</summary>
    public int PartitionCount { get; }

    /// <summary>The verified manifest, shared with the sibling restore workflow inside this assembly.</summary>
    internal GlobalEdlManifest Manifest { get; }

    /// <summary>The six decoded original GPT tables, keyed by LUN, shared with the sibling workflow.</summary>
    internal IReadOnlyDictionary<int, GptTable> Tables { get; }

    internal void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(GlobalEdlBackupSet));
        }
    }

    /// <summary>Releases every read-only lease. Calling twice is harmless.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        foreach (FileStream lease in _leases)
        {
            lease.Dispose();
        }
    }
}
