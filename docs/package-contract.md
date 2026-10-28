# 安装包与尾部恢复区

## 职责

[armadaos-freedom](https://github.com/mydanyi/armadaos-freedom) 负责 Linux 镜像、型号适配、启动器和 9008 系统包生产。本仓库负责 Windows 交互、设备与备份校验、实际布局规划、A/B 引导处理、9008 写入和回读。

系统包的当前格式、参数和构建入口以[系统仓库的打包文档](https://github.com/mydanyi/armadaos-freedom/blob/main/docs/edl-package.md)为准：统一包 `bundle.json` schema 2 将共用内容存放一次；各型号 `package.json` schema 2 声明 `edl-raw-v1` 的压缩分区镜像及型号运行时。导入器检查声明、长度、哈希和目标型号。

## ARMADA_BACKUP

恢复区由安装器使用目标平板本机备份生成，不由通用镜像携带其他设备的备份。固定长度为 2147483648 字节。新备份及新建恢复镜像均排除 userdata、rawdump、metadata 的分区内容，分区表中的布局信息仍保留。复用旧电脑备份时会校验原文件并保留原始清单，但不将其中的 metadata 内容放进新恢复镜像；电脑上的原备份不被改写。

| 区域 | 内容 |
| --- | --- |
| 前 64 KiB | JSON 头、布局和压缩载荷校验信息 |
| 紧接头部 | gzip 压缩的 tar：原始恢复文件、清单、安装记录与 GPT |
| 中间剩余部分 | 零填充 |
| 最后 64 KiB（v3） | 4 KiB 不可变描述符、两个 4 KiB 可变设置槽及保留区 |

v3 的描述符绑定恢复分区 UUID、安装 UUID、型号和载荷边界。恢复校验仍验证压缩载荷、描述符及保留区；设置槽可被启动器交替更新，不能因此将完整恢复资料判定为损坏。v2 则继续要求载荷后的区域全部为零。

完整字节协议及各型号启动器支持范围见[启动器存储设置](https://github.com/mydanyi/armadaos-freedom/blob/main/devices/lenovo-tb323fu/boot/kshim-success-source/docs/storage-settings.md)。目录名不代表所有型号都启用了相同功能。

对应代码：`InternalInstallArtifacts` 负责生成和验证，`BootSettingsRegion` 定义 v3 设置区，`InternalInstallPreparationContext` 在写入前绑定备份与安装计划。`maintenance/BackupSettingsUpgrade` 是旧 v2 镜像的离线升级准备工具，仅输出经校验的修改区域，不直接刷写设备。