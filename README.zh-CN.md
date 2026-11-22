# ArmadaOS Freedom 安装助手

[English](README.md) · **简体中文**

**把 ArmadaOS Freedom 装进你的平板，并在需要时完成备份、维护与恢复。**

ArmadaOS Freedom 安装助手是 [ArmadaOS Freedom](https://github.com/ArmadaOS-Freedom/armadaos-freedom) 的电脑端配套工具，为受支持的 ARM 安卓平板提供系统安装、离线升级、备份与维护。

支持 **Windows x64** 和 **Apple 芯片 macOS**，提供中英文界面及明暗主题，具体功能因平台与机型而异。

**免费软件，谨防被骗。**

## 主要功能

- **安装 Freedom**：按引导将系统安装到平板的机身存储。
- **离线升级**：使用匹配的更新包，为已运行 Freedom 的平板升级系统。
- **安卓更新维护**：在安卓更新前准备，并在更新后修复引导。
- **卸载 Linux**：移除 Linux，将存储空间归还 Android。
- **备份与恢复**：通过独立入口完成 9008 全局备份和恢复。

## 支持设备

| 设备 | 型号 | 当前支持 |
|---|---|---|
| 联想拯救者 Y700 四代 | TB322FC | 机身安装、维护、卸载、离线升级、全局备份与恢复 |
| 联想拯救者 Y700 五代 | TB323FU | 机身安装、维护、卸载、离线升级、全局备份与恢复 |
| 联想小新 Pad Pro GT | TB710FU | 机身安装、全局备份与只读校验；维护、卸载与全局恢复的写入路线已实现（只重签 boot，保留设备的 AVB 元数据），**尚未逐项真机验证，暂未开放** |

**Windows 版**与 **macOS 版**（Apple 芯片）功能相同。TB710FU 的维护、卸载和全局恢复在真机验证前暂未开放，TF／microSD 卡系统安装也暂不提供。

不同机型的固件和启动链要求，请查看[机型说明](https://github.com/ArmadaOS-Freedom/armadaos-freedom/blob/main/README.zh-CN.md#设备支持)，并按安装助手检查结果操作。离线升级需要匹配的 Freedom 系统、设备端更新服务和更新包；全局备份要求尚未安装 Linux 的原始分区布局。

## 开始使用

准备适合电脑平台的安装助手，以及单独提供的匹配系统包。完成环境检测后连接平板，选择需要的功能，按助手引导操作。**Y700 四代与五代使用平板长边的 USB-C 接口连接电脑。**

**安装、重新分区及卸载初始化会清除相关个人数据，请另外备份照片和应用数据。** 程序生成的恢复备份不包含个人文件的完整副本。

## 开发

<details>
<summary>从源码构建</summary>

Windows 与 macOS 的构建步骤及所需组件见[构建说明](docs/build.md)。

</details>

## 交流与反馈

问题请在 [Issues](https://github.com/ArmadaOS-Freedom/armadaos-freedom-installer/issues) 反馈，附上平板型号、电脑系统、安装助手版本、失败的操作及相关日志。

- **作者与中文交流**：[单翼的哔哩哔哩](https://space.bilibili.com/258786)。
- **QQ 粉丝大群**：487945399
- **QQ 粉丝二群**：332038419
- **海外联系**：[mydanyi@qq.com](mailto:mydanyi@qq.com)

相关项目：[ArmadaOS Freedom](https://github.com/ArmadaOS-Freedom/armadaos-freedom) · [组织首页](https://github.com/ArmadaOS-Freedom)

## 许可证

源码按 [GPL-3.0](LICENSE) 提供，第三方组件、驱动和设备加载器保留各自的许可证与声明。
