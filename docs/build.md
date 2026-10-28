# 构建安装助手

使用 .NET 10 SDK。Windows 界面使用 WPF，发布目标是 `win-x64`，自包含单 EXE；在 Linux Docker 中交叉构建时，项目已启用 Windows targeting。

## 外部输入

下列输入通过 MSBuild 属性传入。文件放在源码目录之外，路径使用构建环境中的绝对路径。发布不会自动下载或生成这些文件；缺少必需输入时会停止。

| 属性 | 内容 |
| --- | --- |
| `BundledPlatformToolsArchive` | 官方 Windows platform-tools ZIP |
| `BundledEdlArchive` | TB322FC 的 9008 工具归档 |
| `BundledEdlG5Archive` | TB323FU 的独立 9008 工具归档 |
| `BundledQualcommDriverArchive` | 已签名的 Qualcomm USB 驱动 ZIP |
| `BundledEdlRawPacker` | `MultiBootKernelPatcher.exe` |
| `BundledEdlRawUnpacker` | `UnpackTool.exe` |
| `BundledAvbSigningKey` | AOSP 公开的 AVB RSA4096 测试材料 |
| `BundledGblPrcEfi` | 标准 PRC GBL EFI |
| `BundledGblRowEfi` | 标准 ROW GBL EFI |

工具格式和校验常量分别见 `EdlToolchain`、`EdlRawBootTools`、`BundledQualcommDriver`、`EdlRawBootBuilder.AvbSigning` 与 `Gbl/GblRuntimeAssets`。GBL 的来源与版本见 [第三方声明](GblRuntime-NOTICE.txt)。测试签名材料不是 OEM 私钥，不能替换成其他来源的密钥。

源码仓库不包含这些二进制输入、设备备份或 Linux 系统镜像。公开分发外部输入时需遵守对应上游许可证。

## 发布

在 SDK 容器内，将仓库作为当前目录，将上述输入只读挂载到 `/inputs`，输出目录挂载到 `/output`。文件名与下例对应时运行：

```sh
dotnet publish src/FreedomInstaller.App/FreedomInstaller.App.csproj \
  -c Release -r win-x64 --self-contained true -o /output \
  -p:UseSharedCompilation=false \
  -p:BundledPlatformToolsArchive=/inputs/platform-tools.zip \
  -p:BundledEdlArchive=/inputs/edl.zip \
  -p:BundledEdlG5Archive=/inputs/edl-g5.zip \
  -p:BundledQualcommDriverArchive=/inputs/qualcomm-driver.zip \
  -p:BundledEdlRawPacker=/inputs/MultiBootKernelPatcher.exe \
  -p:BundledEdlRawUnpacker=/inputs/UnpackTool.exe \
  -p:BundledAvbSigningKey=/inputs/avb-test-key.pem \
  -p:BundledGblPrcEfi=/inputs/gbl-prc.efi \
  -p:BundledGblRowEfi=/inputs/gbl-row.efi
```

输出为 `/output/FreedomInstaller.App.exe`。安装器内置所需 .NET 运行库；最终用户无需另装 SDK。该 EXE 不包含 Linux 系统安装包。

## 测试

Core 测试可在 Linux SDK 容器中运行；例如只验证恢复区描述符：

```sh
dotnet test tests/FreedomInstaller.Core.Tests/FreedomInstaller.Core.Tests.csproj \
  -c Release --filter FullyQualifiedName~BootSettingsRegion \
  -p:BundledAvbSigningKey=/inputs/avb-test-key.pem
```

设备通信、引导打包和驱动测试另需对应工具输入。主要环境变量包括 `EDL_TOOLCHAIN_TEST_BUNDLE_PATH`、`EDL_TOOLCHAIN_G5_TEST_BUNDLE_PATH`、`QUALCOMM_DRIVER_TEST_ARCHIVE`、`EDL_RAW_PACKER_PATH`、`EDL_RAW_UNPACKER_PATH`、`EDL_RAW_LINUX_PACKER_PATH`、`EDL_RAW_LINUX_UNPACKER_PATH`、`G5_PUBLIC_ABL_PATH` 和 `G5_LOADER_FIXTURE_ROOT`。将 `EDL_CLIENT_TEST_WORK_ROOT` 与 `TEST_ARTIFACT_ROOT` 指向容器内可写、空间充足的测试目录。

测试使用合成分区与受控进程接口，不能代替真实平板的安装和启动验证。需要真实历史日志的测试必须显式提供其输入，不能将缺失输入当成已验证。