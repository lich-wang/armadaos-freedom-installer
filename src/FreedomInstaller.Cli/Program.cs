using System.Security.Cryptography;
using FreedomInstaller.Core;

namespace FreedomInstaller.Cli;

/// <summary>
/// Command line internal install. The steps and the Core calls are the ones the WPF pages make, in the same
/// order: device check, 9008 entry and install backup, package import and partition plan, direct preparation,
/// and the confirmed execution. Every decision and check stays in Core; this file only wires the steps,
/// supplies the platform services (endpoint discovery, tool paths) and asks the user to confirm.
/// </summary>
internal static class Program
{
    private const string Usage = """
        用法 / Usage:
          freedom-installer devices [--adb PATH]
          freedom-installer check --serial SERIAL [--adb PATH] [--fastboot PATH]
          freedom-installer backup --serial SERIAL --edl-tools ZIP --work DIR [--adb PATH] [--fastboot PATH]
          freedom-installer install --serial SERIAL --edl-tools ZIP --package BUNDLE
                                    --packer PATH --unpacker PATH --work DIR
                                    [--android-gib N] [--adb PATH] [--fastboot PATH]

          check     第 1 步设备检查（只读；可能重启到 fastboot 再回到 Android）。
          backup    第 1 步检查 → 进入 9008 → 读取安装备份（只读），然后复位回系统。
          install   完整内部安装：检查 → 进入 9008 并备份 → 导入系统包、规划分区 → 准备 → 确认后写入。
                    写入前要求输入确认码；--work 下保存备份与证据，请勿删除。
        """;

    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help")
        {
            Console.WriteLine(Usage);
            return args.Length == 0 ? 2 : 0;
        }

        Options options;
        try
        {
            options = Options.Parse(args.Skip(1).ToArray());
        }
        catch (ArgumentException exception)
        {
            Console.Error.WriteLine(exception.Message);
            Console.Error.WriteLine(Usage);
            return 2;
        }

        using var cancel = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancel.Cancel();
        };

        try
        {
            return args[0] switch
            {
                "devices" => await DevicesAsync(options, cancel.Token),
                "check" => await CheckAsync(options, cancel.Token) is null ? 1 : 0,
                "backup" => await BackupOnlyAsync(options, cancel.Token),
                "install" => await InstallAsync(options, cancel.Token),
                _ => throw new ArgumentException("未知命令: " + args[0]),
            };
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("已取消。");
            return 130;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            Console.Error.WriteLine("失败: " + exception.Message);
            return 1;
        }
    }

    // ------------------------------------------------------------------ steps

    private static async Task<int> DevicesAsync(Options options, CancellationToken token)
    {
        var transport = new DeviceTransport(options.Adb, options.Fastboot, new ProcessRunner());
        foreach (ConnectedDevice device in await transport.ListDevicesAsync(token))
        {
            Console.WriteLine($"{device.Serial}\t{device.ConnectionState}");
        }

        return 0;
    }

    /// <summary>Step 1, the same check the install page runs before it opens the backup step.</summary>
    private static async Task<InternalDeviceCheckResult?> CheckAsync(Options options, CancellationToken token)
    {
        string serial = options.Require(options.Serial, "--serial");
        var check = new InternalInstallDeviceCheck(options.Adb, options.Fastboot, new ProcessRunner());
        var progress = new Progress<InternalDeviceCheckProgress>(report =>
            Console.WriteLine($"  [检查] {report.Stage}{(report.Detail is null ? string.Empty : ": " + report.Detail)}"));

        Console.WriteLine("第 1 步：设备检查（只读；可能重启到 fastboot 再回到 Android）…");
        InternalDeviceCheckResult result = await check.CheckAsync(serial, progress, token);

        DeviceIdentity? identity = result.Android?.Identity;
        Console.WriteLine($"  型号 {identity?.Model ?? "?"}，固件 {identity?.Firmware?.DisplayId ?? "?"}，" +
                          $"SoC 序列号 {result.Android?.SocSerial ?? "?"}");
        Console.WriteLine($"  fastboot product {result.FastbootProduct ?? "?"}，锁定状态 {result.FastbootLockState}，" +
                          $"OTA {result.OtaState}，返回 Android {result.AndroidReturn}");

        bool passed = result.Succeeded
            && result.AndroidReturn == AndroidReturnState.Verified
            && identity is not null
            && !string.IsNullOrWhiteSpace(identity.Model)
            && !string.IsNullOrWhiteSpace(identity.Serial)
            && !string.IsNullOrWhiteSpace(identity.Firmware?.DisplayId)
            && !string.IsNullOrWhiteSpace(result.Android?.SocSerial);
        if (!passed)
        {
            Console.Error.WriteLine($"  检查未通过（失败阶段 {result.FailedStage?.ToString() ?? "无"}）。");
            return null;
        }

        Console.WriteLine("  检查通过。");
        return result;
    }

    private static async Task<int> InstallAsync(Options options, CancellationToken token)
    {
        string edlArchive = options.RequireFile(options.EdlTools, "--edl-tools");
        string package = options.RequireFile(options.Package, "--package");
        string packer = options.RequireFile(options.Packer, "--packer");
        string unpacker = options.RequireFile(options.Unpacker, "--unpacker");
        string work = Path.GetFullPath(options.Require(options.Work, "--work"));
        Directory.CreateDirectory(work);

        IEdlEndpointDiscovery discovery = CreateDiscovery();
        var runner = new ProcessRunner();
        var transport = new DeviceTransport(options.Adb, options.Fastboot, runner);

        InternalDeviceCheckResult check = await CheckAsync(options, token)
            ?? throw new InvalidOperationException("第 1 步检查未通过，未进入 9008。");
        AndroidMaintenanceIdentity expected = check.Android!;
        using EdlToolchain tools = await LoadToolchainAsync(edlArchive, work, token);
        (EdlClient client, InternalBackupSet backupSet) =
            await EnterEdlAndBackupAsync(options, check, tools, work, discovery, runner, transport, token);
        using InternalBackupSet backup = backupSet;

        // Step 3: the system package and the partition plan.
        Console.WriteLine("第 3 步：导入系统包…");
        string packageWork = Path.Combine(work, "package");
        Directory.CreateDirectory(packageWork);
        using ImportedPackage imported = await PackageImporter.ImportAsync(
            package, expected.Identity.Model, InstallationTarget.Internal, packageWork, token);
        if (!imported.Validation.IsValid || imported.Validation.Storage is null)
        {
            throw new InvalidOperationException(
                "系统包校验未通过: " + string.Join("；", imported.Validation.Reasons));
        }

        PackageStorage storage = imported.Validation.Storage;
        AndroidAllocationRange range = InternalPartitionPlanner.GetAndroidRange(backup.Tables[0], storage);
        long androidGiB = options.AndroidGiB ?? AskAndroidGiB(range);
        if (androidGiB < range.MinimumGiB || androidGiB > range.MaximumGiB)
        {
            throw new ArgumentException($"Android 大小必须在 {range.MinimumGiB}–{range.MaximumGiB} GiB 之间。");
        }

        Console.WriteLine($"  Android 保留 {androidGiB} GiB，生成分区方案…");
        using InternalArtifactSet artifacts = await InternalInstallArtifacts.PrepareAsync(
            backup, androidGiB, storage, work, token);

        // Step 4: the native boot tools and the direct preparation.
        Console.WriteLine("第 4 步：准备（构建 boot、核对全部输入，不写设备）…");
        using EdlRawBootTools nativeTools = await LoadNativeToolsAsync(packer, unpacker, work, token);
        using InternalInstallDirectAssets assets = await InternalInstallDirectAssets.LoadAsync(nativeTools, token);
        var services = new InternalInstallServices(new EdlEntry(options.Adb, runner, discovery), runner, discovery, options.Adb);
        using InternalInstallBackend backend = await InternalInstallBackend.CreatePreparedAsync(
            check, client, backup, artifacts, imported, assets, services, work, token);

        InternalInstallPrepared prepared = backend.Prepared;
        PrintPrepared(prepared);

        // Step 5: the same two confirmations the install page asks for.
        Console.WriteLine();
        Console.WriteLine("将要写入设备：分区表、boot_b、boot_a、misc 与 Linux 分区；Android 的 userdata 会被清空。");
        Console.Write($"输入确认码 {prepared.ConfirmationId} 以继续（其他任何输入都会退出）: ");
        if (!string.Equals(Console.ReadLine()?.Trim(), prepared.ConfirmationId, StringComparison.Ordinal))
        {
            Console.WriteLine("未确认，没有写入任何内容。");
            return 1;
        }

        Console.Write("确认清空 Android 用户数据？输入 ERASE: ");
        if (!string.Equals(Console.ReadLine()?.Trim(), "ERASE", StringComparison.Ordinal))
        {
            Console.WriteLine("未确认，没有写入任何内容。");
            return 1;
        }

        var installProgress = new Progress<InternalInstallProgress>(report => Console.WriteLine($"  [写入] {report}"));
        InternalInstallResult result = await backend.ExecuteAsync(
            prepared.ConfirmationId, userdataEraseConfirmed: true, installProgress, token);

        Console.WriteLine($"结果: {result.Outcome}，写入状态 {result.WriteState}，" +
                          $"最后确认的阶段 {result.LastVerifiedStage?.ToString() ?? "无"}，" +
                          $"已校验的槽位 {string.Join(",", result.VerifiedSlots)}");
        Console.WriteLine($"证据目录: {prepared.EvidenceDirectory}");
        // The direct route ends in InstallationCompleted (every write read back, slots verified, normal reset
        // accepted); Completed is the both-OS acceptance of the other routes. Anything else is a failure.
        return result.Outcome is InternalInstallOutcome.Completed or InternalInstallOutcome.InstallationCompleted
            ? 0
            : 1;
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>
    /// Step 2 of the install page: the trusted profile and toolchain of this model, a fresh Android read that
    /// must still match the step 1 result, the single 9008 entry and the install backup.
    /// </summary>
    private static async Task<(EdlClient Client, InternalBackupSet Backup)> EnterEdlAndBackupAsync(
        Options options,
        InternalDeviceCheckResult check,
        EdlToolchain tools,
        string work,
        IEdlEndpointDiscovery discovery,
        ICommandRunner runner,
        DeviceTransport transport,
        CancellationToken token)
    {
        AndroidMaintenanceIdentity expected = check.Android!;
        EdlDeviceProfile profile = EdlDeviceProfiles.FindByModel(expected.Identity.Model)
            ?? throw new InvalidOperationException($"没有型号 {expected.Identity.Model} 的可信 9008 配置。");
        if (!profile.IsComplete || !profile.SupportsIdentity(expected.Identity))
        {
            throw new InvalidOperationException($"可信配置 {profile.ProfileId} 不支持这台平板的身份。");
        }

        if (!ReferenceEquals(tools.Profile, profile))
        {
            throw new InvalidOperationException(
                $"9008 工具归档的配置 {tools.ProfileId} 与这台平板（{profile.ProfileId}）不符。");
        }

        DeviceIdentity freshIdentity = await transport.ReadAdbIdentityAsync(expected.Identity.Serial, token);
        var maintenance = new MaintenanceEntry(options.Adb, options.Fastboot, runner);
        AndroidMaintenanceIdentity fresh = await maintenance.ReadAndroidAsync(freshIdentity, token);
        if (!SameAndroid(expected, fresh) || !profile.SupportsIdentity(fresh.Identity))
        {
            throw new InvalidOperationException("重新读取到的平板与第 1 步结果不一致，未进入 9008。");
        }

        Console.WriteLine("第 2 步：重启进入 9008…");
        EdlEntryResult entered = await new EdlEntry(options.Adb, runner, discovery)
            .EnterAsync(fresh, tools.Profile, token);
        Console.WriteLine($"  9008 设备 {entered.Endpoint.DeviceInstanceId}，总线序列号 {entered.BusSerialHex}");
        var client = new EdlClient(tools, entered, runner, discovery);

        Console.WriteLine("  读取安装备份（只读）…");
        var backupProgress = new Progress<InternalBackupProgress>(report => Console.WriteLine($"  [备份] {report}"));
        InternalBackupSet backup = await InternalInstallBackup.CreateAsync(client, work, backupProgress, token);
        Console.WriteLine($"  备份目录: {backup.DirectoryPath}");
        return (client, backup);
    }

    /// <summary>Read-only run of steps 1 and 2; the tablet is reset out of 9008 afterwards.</summary>
    private static async Task<int> BackupOnlyAsync(Options options, CancellationToken token)
    {
        string edlArchive = options.RequireFile(options.EdlTools, "--edl-tools");
        string work = Path.GetFullPath(options.Require(options.Work, "--work"));
        Directory.CreateDirectory(work);

        IEdlEndpointDiscovery discovery = CreateDiscovery();
        var runner = new ProcessRunner();
        var transport = new DeviceTransport(options.Adb, options.Fastboot, runner);

        InternalDeviceCheckResult check = await CheckAsync(options, token)
            ?? throw new InvalidOperationException("第 1 步检查未通过，未进入 9008。");
        using EdlToolchain tools = await LoadToolchainAsync(edlArchive, work, token);
        (EdlClient client, InternalBackupSet backup) =
            await EnterEdlAndBackupAsync(options, check, tools, work, discovery, runner, transport, token);
        using (backup)
        {
            Console.WriteLine("复位，退出 9008…");
            await client.ResetAsync(token);
        }

        Console.WriteLine("完成：没有写入任何分区。");
        return 0;
    }


    private static IEdlEndpointDiscovery CreateDiscovery()
    {
        if (OperatingSystem.IsMacOS())
        {
            return new MacEdlEndpointDiscovery();
        }

        if (OperatingSystem.IsWindows())
        {
            return new WindowsEdlEndpointDiscovery();
        }

        throw new PlatformNotSupportedException("9008 设备发现目前只支持 macOS 与 Windows。");
    }

    private static async Task<EdlToolchain> LoadToolchainAsync(string archivePath, string work, CancellationToken token)
    {
        string root = Path.Combine(work, "edl-tools");
        Directory.CreateDirectory(root);
        await using FileStream archive = File.OpenRead(archivePath);
        return await EdlToolchain.LoadAsync(archive, root, token);
    }

    /// <summary>
    /// Copies the two packers into a fresh material directory, makes them executable and hands Core only a claim;
    /// Core rechecks them against its compiled pins and holds read leases, as for the embedded Windows tools.
    /// </summary>
    private static async Task<EdlRawBootTools> LoadNativeToolsAsync(
        string packer, string unpacker, string work, CancellationToken token)
    {
        string directory = Path.Combine(work, "native-tools", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        VerifiedEdlFile packerClaim = await StageAsync(packer, Path.Combine(directory, Path.GetFileName(packer)), token);
        VerifiedEdlFile unpackerClaim = await StageAsync(unpacker, Path.Combine(directory, Path.GetFileName(unpacker)), token);
        return await EdlRawBootTools.LoadAsync(packerClaim, unpackerClaim, token);
    }

    private static async Task<VerifiedEdlFile> StageAsync(string source, string destination, CancellationToken token)
    {
        await using (FileStream input = File.OpenRead(source))
        await using (FileStream output = new(destination, FileMode.CreateNew, FileAccess.Write))
        {
            await input.CopyToAsync(output, token);
        }

        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(destination, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        await using FileStream staged = File.OpenRead(destination);
        string sha256 = Convert.ToHexString(await SHA256.HashDataAsync(staged, token)).ToLowerInvariant();
        return new VerifiedEdlFile(destination, staged.Length, sha256);
    }

    private static bool SameAndroid(AndroidMaintenanceIdentity expected, AndroidMaintenanceIdentity fresh) =>
        string.Equals(expected.Identity.Serial, fresh.Identity.Serial, StringComparison.Ordinal)
        && string.Equals(expected.Identity.Model, fresh.Identity.Model, StringComparison.Ordinal)
        && string.Equals(expected.Identity.Firmware?.DisplayId, fresh.Identity.Firmware?.DisplayId, StringComparison.Ordinal)
        && string.Equals(expected.SocSerial, fresh.SocSerial, StringComparison.OrdinalIgnoreCase);

    private static long AskAndroidGiB(AndroidAllocationRange range)
    {
        Console.Write($"给 Android 保留多少 GiB（{range.MinimumGiB}–{range.MaximumGiB}）: ");
        string? text = Console.ReadLine();
        return long.TryParse(text?.Trim(), out long value)
            ? value
            : throw new ArgumentException("请输入整数 GiB。");
    }

    private static void PrintPrepared(InternalInstallPrepared prepared)
    {
        Console.WriteLine("准备完成，将要执行的安装：");
        Console.WriteLine($"  配置 {prepared.ProfileId}，Android 序列号 {prepared.AndroidSerial}，SoC {prepared.SocSerial}");
        Console.WriteLine($"  Android 固件 {prepared.AndroidBuild}，当前槽位 {prepared.CurrentSlot}，锁定状态 {prepared.FastbootLockState}");
        Console.WriteLine($"  引导信任方式 {prepared.BootTrustMode}");
        Console.WriteLine($"  Android 保留 {prepared.AndroidGiB} GiB，Linux 根分区 {prepared.LinuxRootBytes / (1L << 30)} GiB，" +
                          $"备份区 {prepared.BoardBackupBytes / (1L << 20)} MiB");
        Console.WriteLine($"  系统包指纹 {prepared.PackageFingerprint}");
        Console.WriteLine($"  分区方案 {prepared.ArtifactPlanSha256}");
        Console.WriteLine($"  备份 {prepared.BackupDirectory}");
        Console.WriteLine($"  证据 {prepared.EvidenceDirectory}");
    }

    // ------------------------------------------------------------------ options

    private sealed class Options
    {
        public string Adb { get; private set; } = FindOnPath("adb");
        public string Fastboot { get; private set; } = FindOnPath("fastboot");
        public string? Serial { get; private set; }
        public string? EdlTools { get; private set; }
        public string? Package { get; private set; }
        public string? Packer { get; private set; }
        public string? Unpacker { get; private set; }
        public string? Work { get; private set; }
        public long? AndroidGiB { get; private set; }

        public static Options Parse(string[] args)
        {
            var options = new Options();
            for (int index = 0; index < args.Length; index++)
            {
                string name = args[index];
                string Value() => index + 1 < args.Length
                    ? args[++index]
                    : throw new ArgumentException("缺少参数值: " + name);

                switch (name)
                {
                    case "--adb": options.Adb = Path.GetFullPath(Value()); break;
                    case "--fastboot": options.Fastboot = Path.GetFullPath(Value()); break;
                    case "--serial": options.Serial = Value(); break;
                    case "--edl-tools": options.EdlTools = Value(); break;
                    case "--package": options.Package = Value(); break;
                    case "--packer": options.Packer = Value(); break;
                    case "--unpacker": options.Unpacker = Value(); break;
                    case "--work": options.Work = Value(); break;
                    case "--android-gib":
                        options.AndroidGiB = long.TryParse(Value(), out long gib)
                            ? gib
                            : throw new ArgumentException("--android-gib 需要整数。");
                        break;
                    default: throw new ArgumentException("未知参数: " + name);
                }
            }

            return options;
        }

        public string Require(string? value, string name) =>
            string.IsNullOrWhiteSpace(value) ? throw new ArgumentException("缺少 " + name) : value;

        public string RequireFile(string? value, string name)
        {
            string path = Path.GetFullPath(Require(value, name));
            return File.Exists(path) ? path : throw new ArgumentException($"{name} 指定的文件不存在: {path}");
        }

        private static string FindOnPath(string tool)
        {
            foreach (string directory in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
                         .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                string candidate = Path.Combine(directory, OperatingSystem.IsWindows() ? tool + ".exe" : tool);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }

            return tool;
        }
    }
}
