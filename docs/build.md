# 从源码构建安装助手

本仓库包含修改版工具的源码、构建脚本、上游版本关系，以及必要的厂商预编译文件。默认流程不下载本项目的依赖合集 Release，也不需要维护者电脑上的文件。

## 一次完整构建

安装 Docker 并使用 Linux 容器。在仓库根目录运行以下两条命令；Linux shell 和 Windows PowerShell 均可使用：

```sh
docker build -f tools/installer-builder.Dockerfile -t armada-installer-builder tools
docker run --rm -v "${PWD}:/src" -v "${PWD}/artifacts:/work" armada-installer-builder python3 -B maintenance/build_installer.py --work-dir /work/build --output-dir /work/publish
```

产物为 `artifacts/publish/FreedomInstaller.App.exe`，Windows x64 自包含单 EXE。最终用户不需要另装 .NET SDK；Linux 系统镜像仍由系统仓库单独生成。

首次构建需要联网下载官方组件和 NuGet 包。后续构建复用经过哈希校验的下载缓存，每次仍从源码编译修改版工具。构建镜像固定为 .NET SDK 10.0.402 / Ubuntu 24.04 AMD64，安装 CMake、Make、Python 和 MinGW POSIX 编译器。

已有相同工具链的 Linux 环境也可运行：

```sh
python3 -B maintenance/build_installer.py --work-dir /work/build --output-dir /work/publish
```

工作目录和输出目录应使用绝对路径。编译产物、缓存和日志不应提交到源码仓库。

## macOS 版

在 Apple 芯片的 Mac 上安装 .NET SDK 10 和 Xcode 命令行工具（`xcode-select --install`），在仓库根目录运行：

```sh
python3 -B maintenance/build_installer_macos.py --work-dir "$PWD/artifacts/build-macos" --output-dir "$PWD/artifacts/publish-macos"
```

产物为 `artifacts/publish-macos/ArmadaOS Freedom Installer.app`，未签名、未公证，首次打开时需在“系统设置 → 隐私与安全性”中确认。脚本复用 Windows 构建的清单、厂商文件与下载校验：edl-ng 编译为 osx-arm64，打包工具用 `tools/build-boot-packers-macos.sh` 编为通用二进制，libusb 取自同一个已固定哈希的 LibUsbDotNet 包中的 `runtimes/osx-arm64/native/libusb-1.0.dylib`，再按本次产物生成固定哈希，用 `package_edl.py --platform macos-arm64` 制作各型号 9008 工具包（不含 Python）。

## 构建流程

1. 校验仓库内的厂商加载器、驱动及 AOSP 公开测试素材。
2. 从固定官方地址下载平台工具、嵌入式 Python、LibUsbDotNet 官方包、libusb 许可原文和上游 GBL EFI，核对长度与 SHA-256。
3. 编译 `tools/edl-ng` 与 `tools/boot-packers`，生成三个 Windows 工具。
4. 从本次工具产物生成编译时固定哈希，分别制作四代、五代与 TB710FU 的 9008 工具包，并从仓库原始驱动文件制作驱动归档。
5. 生成 MSBuild 输入配置，编译并打包单 EXE。

每次构建会生成 `build/build-record.json`，记录源码文件哈希、上游提交、本次工具哈希和产物路径。程序使用编进程序集的本次哈希校验工具，运行时不接受外部配置覆盖。修改工具源码后重新完整构建即可，无需手工替换旧二进制的哈希常量。

## 组件与版本关系

固定版本、URL、长度、SHA-256 和源代码位置见 [maintenance/build-inputs.json](../maintenance/build-inputs.json)。

| 组件 | 来源与处理方式 |
| --- | --- |
| 修改版 edl-ng | 源码在 `tools/edl-ng`，基于 strongtz/edl-ng v1.6.0、提交 `834f91ea2d2dfc7b6337af0e8e54d5ea93e037f4`；包含 Firehose 数据边界处理、Sahara 多镜像加载及 identify 命令。构建脚本为 `tools/build-edl-ng.sh`。 |
| 修改版 boot 打包／解包工具 | 源码在 `tools/boot-packers`，基于 Project-Aloha/DualBootKernelPatcher 提交 `2276163d066596cb0750e76cbfeec5c193b1779f`；包含 PayloadFrom 别名和 DTB 对齐支持。构建脚本为 `tools/build-boot-packers.sh`，inih 源码已包含。 |
| AVB / GPT 脚本 | 直接使用仓库 `maintenance/` 中的四份 Python 源文件。 |
| platform-tools | Google 官方固定版本 37.0.1 Windows ZIP。 |
| Python | python.org 官方 3.14.8 Windows AMD64 嵌入式 ZIP。 |
| libusb DLL | 从 LibUsbDotNet 3.0.167-alpha 官方 NuGet 包提取 Windows x64 文件，与原安装器使用的 DLL 内容一致。 |
| GBL EFI | 从 miner7222/gbl_root_baldur 的 6.2.192-mod2 固定版本取得 PRC / ROW 文件；源码仓库与提交记录在清单中。 |
| 四代、五代、TB710FU 加载器 | 原件分别在 `vendor/qualcomm/g4`、`vendor/qualcomm/g5`、`vendor/qualcomm/tb710fu`，各自独立打包。TB710FU 的加载器取自 ZUXOS 1.5.04.495 免解锁补充包的 `EDL/xbl_s_devprg_ns.melf`。 |
| Qualcomm 驱动 | 2.1.5.2 AMD64 原始文件在 `vendor/qualcomm/driver`，保留签名和 `serial/amd64` 目录结构。 |
| AOSP 测试素材 | 官方公开的 RSA4096 测试文件在 `vendor/aosp`，附官方出处、哈希和上游许可原文。 |

厂商素材保持原始字节，Git 不转换其行尾；特别是五代加载 XML、驱动 INF 与签名目录文件。各开源组件保留自己的许可文件与原作者声明。

## 分步构建与验证

只准备工具、包、固定哈希和 MSBuild 配置：

```sh
python3 -B maintenance/build_installer.py --work-dir /work/build --prepare-only
```

随后可使用该次配置编译：

```sh
dotnet publish src/FreedomInstaller.App/FreedomInstaller.App.csproj -c Release -r win-x64 --self-contained true -p:BundledBuildInputsProps=/work/build/build-inputs.props -o /work/publish
```

只下载或校验官方组件：

```sh
python3 -B maintenance/fetch_build_inputs.py --output-dir /work/downloads
python3 -B maintenance/fetch_build_inputs.py --output-dir /work/downloads --verify-only
```

构建相关 Python 测试：

```sh
python3 -B -m unittest discover -s maintenance/tests -p test_fetch_build_inputs.py
python3 -B -m unittest discover -s maintenance/tests -p test_package_edl.py
python3 -B -m unittest discover -s maintenance/tests -p test_build_installer.py
```

Core 的工具测试需要使用本次 `build-record.json` 中的工具和两个包，并传入同一份 `BundledBuildInputsProps`。涉及真实历史日志的测试仍需其声明的外部输入。编译与合成测试不代替平板安装、签名链和系统启动的真机验收。
