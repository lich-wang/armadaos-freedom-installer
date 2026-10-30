# 构建安装助手

需要 .NET 10 SDK、Python 3.10 或更新版本。安装器使用 WPF，发布目标是 Windows x64、自包含单 EXE；支持在 Linux Docker 中交叉构建。系统镜像单独提供，不嵌入安装器。

## 下载与构建

[0.7.6 程序与构建素材](https://github.com/mydanyi/armadaos-freedom-installer/releases/tag/build-inputs-v0.7.6)同时提供安装器 EXE、九项构建输入、修改版工具源码和 `SHA256SUMS.txt`。直接使用程序只需下载 EXE；开发者使用本仓库源码。

在仓库根目录运行：

```sh
python3 maintenance/fetch_build_inputs.py --output-dir /inputs

dotnet publish src/FreedomInstaller.App/FreedomInstaller.App.csproj \
  -c Release -r win-x64 --self-contained true -o /output \
  -p:UseSharedCompilation=false \
  -p:BundledBuildInputsProps=/inputs/build-inputs.props
```

`/inputs` 和 `/output` 是示例绝对路径，请换成可写的构建目录或 Docker 挂载目录。Windows 可用 `py -3` 代替 `python3`，并使用实际的 Windows 绝对路径；PowerShell 中将多行命令合为一行即可。

下载器按照 [build-inputs.json](../maintenance/build-inputs.json) 校验每个文件的字节数和 SHA-256，全部通过后生成 `build-inputs.props`。已有正确文件会复用；下载失败或校验不符会退出，不会生成一套缺失素材的发布配置。只校验已有输入：

```sh
python3 maintenance/fetch_build_inputs.py --output-dir /inputs --verify-only
```

输出为 `/output/FreedomInstaller.App.exe`，内置 .NET 运行库，最终用户不需要 SDK。`BundledBuildInputsProps` 必须使用绝对路径；也可手动传入下列九项 MSBuild 属性。

| 属性 | 素材 |
| --- | --- |
| `BundledPlatformToolsArchive` | Windows platform-tools 37.0.1 |
| `BundledEdlArchive` | 四代 TB322FC 的 9008 工具包 |
| `BundledEdlG5Archive` | 五代 TB323FU 的独立 9008 工具包 |
| `BundledEdlTb710fuArchive` | TB710FU 的独立 9008 工具归档（可选，不在 `build-inputs.json` 中） |
| `BundledQualcommDriverArchive` | Qualcomm 2.1.5.2 AMD64 驱动包 |
| `BundledEdlRawPacker` | 修改版 `MultiBootKernelPatcher.exe` |
| `BundledEdlRawUnpacker` | 修改版 `UnpackTool.exe` |
| `BundledAvbSigningKey` | AOSP 公开 AVB RSA4096 测试材料 |
| `BundledGblPrcEfi` | GBL 6.2.192-mod2 PRC EFI |
| `BundledGblRowEfi` | GBL 6.2.192-mod2 ROW EFI |

TB710FU 归档可以不提供：未内置归档时 TB710FU 的 9008 流程会提示缺少工具并停止；设置了路径但文件不存在时发布仍会停止。归档格式与其他型号相同：根目录 `manifest.json`（`schemaVersion` 为 1，`profileId` 为 `tb710fu-9008-495`，`model` 为 `TB710FU`，`androidBuild` 为加载器来源 `TB710FU/ZUXOS_1.5.04.495_WITHOUT_UBL/EDL/xbl_s_devprg_ns.melf`，`hardwareId` 为 `003050E100400000`），共用角色（`tools/edl-ng.exe`、`tools/libusb-1.0.dll`、`tools/LICENSE.txt`、Python 嵌入包与 `scripts/` 下的四个脚本）及其既有固定校验值，外加唯一的加载器 `tools/tb710fu/firehose.melf`（1573224 字节，SHA-256 `ad4689b1c52458250d46829ee46a89ec974e69f8e82eee8d4950427919e0b9eb`）。

## 修改底层工具

修改版源码直接保存在仓库中，下载或克隆后即可编辑，不需要从维护者电脑寻找文件：

- [`tools/edl-ng`](../tools/edl-ng)：基于 strongtz/edl-ng v1.6.0、提交 `834f91ea2d2dfc7b6337af0e8e54d5ea93e037f4`，包含 Firehose XML/原始数据边界处理、五代 Sahara XML 多镜像加载及无需加载器的 `identify` 命令。保留 MIT 许可。
- [`tools/boot-packers`](../tools/boot-packers)：基于 Project-Aloha/DualBootKernelPatcher 提交 `2276163d066596cb0750e76cbfeec5c193b1779f` 的修改快照，包含 PayloadFrom 别名及 DTB 对齐支持。相同实现也保存在系统仓库 `packages/kshim-tools/vendor/packer`。保留 GPL 和 inih BSD 许可。

构建 Windows edl-ng，在装有 .NET 9 或更新 SDK 的 Linux 容器内运行：

```sh
sh tools/build-edl-ng.sh /output/edl-ng
```

该脚本生成自包含 Windows x64 单文件，保留 CLI 项目自身的裁剪设置。首次构建需要从 NuGet 恢复依赖；离线构建需预先准备对应缓存。编译器、SDK、运行库版本会影响文件哈希，重新构建不承诺与已发布二进制逐字节一致。

构建 Windows boot 打包工具，需要 CMake、Make 与 `x86_64-w64-mingw32-gcc-posix`，已采用 MinGW GCC 13 POSIX 构建：

```sh
sh tools/build-boot-packers.sh /build/boot-packers /output/boot-packers
```

只生成打包与解包工具，不构建 ARM64 shim。`inih` 源码已经包含，无需额外初始化子模块。

修改、重编译工具后，需要同步更新对应的固定长度与哈希：`EdlToolchain`、`EdlRawBootTools`、`maintenance/package_edl.py` 以及构建素材清单。原有 pin 保证已发布组件一致，不应通过删除校验来替换工具。应重新打包、测试并发布新的素材版本。

## 重建四代和五代 9008 工具包

下载的两个 EDL ZIP 已含各自完整素材：修改版客户端、libusb、嵌入式 Python、AVB/GPT 脚本及本型号加载器。先分别解压到 `/materials/g4`、`/materials/g5`。两者不可混用加载器。

四代示例：

```sh
python3 maintenance/package_edl.py --profile tb322fc \
  --client /materials/g4/tools/edl-ng.exe \
  --usb-library /materials/g4/tools/libusb-1.0.dll \
  --license /materials/g4/tools/LICENSE.txt \
  --python-zip /materials/g4/python/python-3.14.8-embed-amd64.zip \
  --avb /materials/g4/scripts/avb_stock.py \
  --avb-cli /materials/g4/scripts/avb_stock_cli.py \
  --gpt /materials/g4/scripts/portable_gpt.py \
  --gpt-cli /materials/g4/scripts/edl_gpt_cli.py \
  --firehose /materials/g4/tools/firehose.melf \
  --output /output/edl-g4.zip
```

五代使用同样的八个公共参数，路径改为 `/materials/g5`，另将 `--profile` 设为 `tb323fu`，用 `--loader-root /materials/g5/tools/g5` 代替 `--firehose`。该目录中的 XML 及八个镜像必须完整。输出 ZIP、manifest 和 SHA-256 文件均不会覆盖已有文件。

## 来源与许可

各素材的完整字节数、SHA-256、版本、来源与下载地址保存在 [build-inputs.json](../maintenance/build-inputs.json)。这些修改版工具不是上游同名 Release 原件。

Qualcomm 驱动为未经改动的 2.1.5.2（2023-08-24）AMD64 文件：`qcser.inf`、`qcser.cat`、`serial/amd64/qcusbser.sys`，目录签名为 Microsoft Windows Hardware Compatibility Publisher。素材取自 Windows DriverStore，不能冒称是找到的官方公开下载包。驱动及 G4/G5 设备加载器保留厂商权利，安装器的 GPL 许可不替代其许可。

GBL 使用固定公开版本，详见 [GBL 声明](GblRuntime-NOTICE.txt)。AOSP 测试签名材料来自 Android AVB 官方测试数据，不是 OEM 私钥或设备所有者的私人密钥。platform-tools、Python 和其他第三方组件保留各自许可。

## 测试

```sh
python3 -B -m unittest discover -s maintenance/tests -p 'test_*build_inputs.py'
python3 -B -m unittest discover -s maintenance/tests -p 'test_package_edl.py'

dotnet test tests/FreedomInstaller.Core.Tests/FreedomInstaller.Core.Tests.csproj \
  -c Release -p:BundledBuildInputsProps=/inputs/build-inputs.props

dotnet test tools/edl-ng/QCEDL.NET.Tests/QCEDL.NET.Tests.csproj -c Release
```

EDL 包测试使用 `EDL_TOOLCHAIN_TEST_BUNDLE_PATH` 和 `EDL_TOOLCHAIN_G5_TEST_BUNDLE_PATH` 指定两代工具包；驱动测试使用 `QUALCOMM_DRIVER_TEST_ARCHIVE`。其他涉及真实历史日志或原生工具的测试需提供其声明的输入，不能将缺失输入视为已验证。编译和合成测试不代替平板实测。
