// U4b: factual progress payload and safe transfer observer for the uninstall
// backend. Stage keys only; a throwing display observer never fails the NVM
// operation and never becomes a durable authority.
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace FreedomInstaller.Core;

/// <summary>
/// One factual uninstall progress point: a stage key, the optional role it
/// belongs to, the optional transfer phase and the observed byte counters.
/// No readiness, permission or success claim is carried.
/// </summary>
public sealed record EdlUninstallProgress(
    string Stage,
    string? Role,
    EdlTransferPhase? Phase,
    long CompletedBytes,
    long TotalBytes);

public sealed partial class EdlUninstallBackend
{
    /// <summary>Stage keys only; never product prose.</summary>
    private static class Stages
    {
        public const string Preparing = "preparing";
        public const string PreflightMenu = "preflight-menu";
        public const string WritingMenu = "writing-menu";
        public const string VerifyingMenu = "verifying-menu";
        public const string WritingGpt = "writing-gpt";
        public const string Reading = "reading";
        public const string InitializingAndroid = "initializing-android";
        public const string WritesVerified = "writes-verified";
    }

    private void ReportStage(
        string stage,
        string? role = null,
        long completedBytes = 0,
        long totalBytes = 0,
        EdlTransferPhase? phase = null)
    {
        IProgress<EdlUninstallProgress>? observer = _progress;
        if (observer is null)
        {
            return;
        }

        try
        {
            observer.Report(new EdlUninstallProgress(stage, role, phase, completedBytes, totalBytes));
        }
        catch
        {
            // A throwing display observer must never fail a device operation.
        }
    }

    /// <summary>
    /// A fresh, absolute durable transfer log prefix inside this backend's own backup
    /// directory. The legacy route has no current-menu context and returns
    /// null, keeping its previous relative-log shape. Raw log-write failures remain
    /// real errors; only display observers are ever swallowed.
    /// </summary>
    private string? TransferLogPrefix(string role)
    {
        if (_currentMenu is null)
        {
            return null;
        }

        string directory = Path.Combine(_backupDirectory, "logs");
        Directory.CreateDirectory(directory);
        return Path.Combine(directory, role + "-" + Guid.NewGuid().ToString("N"));
    }

    private static void SafeReportStage(IProgress<EdlUninstallProgress>? observer, string stage)
    {
        if (observer is null)
        {
            return;
        }

        try
        {
            observer.Report(new EdlUninstallProgress(stage, null, null, 0, 0));
        }
        catch
        {
            // Display-only; the factory outcome never depends on the observer.
        }
    }

    /// <summary>
    /// Maps the real EdlTransferProgress direction/phase/counter stream onto a
    /// stage key plus role. Returns null when no observer is present so the
    /// device call keeps its original no-progress shape.
    /// </summary>
    private IProgress<EdlTransferProgress>? TransferAdapter(string stage, string role) =>
        _progress is null ? null : new EdlTransferProgressAdapter(this, stage, role);

    private sealed class EdlTransferProgressAdapter : IProgress<EdlTransferProgress>
    {
        private readonly EdlUninstallBackend _owner;
        private readonly string _stage;
        private readonly string _role;

        internal EdlTransferProgressAdapter(EdlUninstallBackend owner, string stage, string role)
        {
            _owner = owner;
            _stage = stage;
            _role = role;
        }

        public void Report(EdlTransferProgress value)
        {
            if (value is null)
            {
                return;
            }

            try
            {
                _owner.ReportStage(_stage, _role, value.CompletedBytes, value.TotalBytes, value.Phase);
            }
            catch
            {
                // A throwing observer is a display failure only.
            }
        }
    }
}
