using System;
using System.IO;

namespace FreedomInstaller.Core;

/// <summary>Owns one application's generated work, never the selected backup or source package.</summary>
public sealed class InstallerWorkSession
{
    public InstallerWorkSession(string root)
    {
        string id = Guid.NewGuid().ToString("N");
        string fullRoot = Path.GetFullPath(root);
        DirectoryPath = Path.Combine(fullRoot, "sessions", id);
        RecordsDirectory = Path.Combine(fullRoot, "records", id);
        Directory.CreateDirectory(DirectoryPath);
    }

    public string DirectoryPath { get; }
    public string RecordsDirectory { get; }

    public void Complete(bool preserveRecovery)
    {
        if (preserveRecovery || !Directory.Exists(DirectoryPath)) return;
        // Save readable receipts before removing images, readbacks and extracted tools.
        CopyReports(new DirectoryInfo(DirectoryPath));
        DeleteOwnedTree(new DirectoryInfo(DirectoryPath));
    }

    private void CopyReports(DirectoryInfo directory)
    {
        if ((directory.Attributes & FileAttributes.ReparsePoint) != 0) return;
        foreach (FileInfo file in directory.GetFiles())
        {
            if ((file.Attributes & FileAttributes.ReparsePoint) != 0) continue;
            string extension = file.Extension.ToLowerInvariant();
            if (extension is not (".json" or ".jsonl" or ".log" or ".txt")) continue;
            string destination = Path.Combine(RecordsDirectory, Path.GetRelativePath(DirectoryPath, file.FullName));
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            file.CopyTo(destination, overwrite: true);
        }
        foreach (DirectoryInfo child in directory.GetDirectories()) CopyReports(child);
    }

    private void DeleteOwnedTree(DirectoryInfo directory)
    {
        string relative = Path.GetRelativePath(DirectoryPath, directory.FullName);
        if (Path.IsPathRooted(relative) || relative == ".." || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new IOException("Refusing cleanup outside the owned installer session.");
        if ((directory.Attributes & FileAttributes.ReparsePoint) == 0)
        {
            foreach (FileInfo file in directory.GetFiles()) file.Delete();
            foreach (DirectoryInfo child in directory.GetDirectories()) DeleteOwnedTree(child);
        }
        directory.Delete();
    }
}
