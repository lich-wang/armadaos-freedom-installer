# 统一安装包结构

统一包将多个型号放在同一个归档中，共用内容只存一份。当前 9008 包由[系统仓库](https://github.com/mydanyi/armadaos-freedom/blob/main/docs/edl-package.md)生成。

## 当前结构

- 根目录 `bundle.json`：`schemaVersion` 为 2，`bundleId` 为 `armadaos-freedom`，包含系统包版本和型号列表。
- `common/boot/kernel.img`、`common/boot/initramfs.img`：共用内核和 initramfs。
- `common/images/linux-boot.ext4.gz`、`common/images/linux-root.btrfs.gz`：共用压缩分区镜像。
- `models/TB322FC/`、`models/TB323FU/`：各型号的 `package.json`、runtime 和 normal/diagnostic 启动文件。

`packages[]` 中每项以 `deviceModel` 指定型号，以 `directory` 指定型号目录；`sharedFiles[]` 将 `common/` 内的 `source` 映射到所选型号暂存目录的 `destination`。例如 `common/images/linux-root.btrfs.gz` 映射为 `images/linux-root.btrfs.gz`。

统一包的 schema 与单型号清单的 schema 是两个独立版本。当前单型号清单使用 schema 2、部署类型 `edl-raw-v1`。旧 schema 1 统一包没有 `sharedFiles`，仍可导入；具体包是否可以安装还需通过对应部署格式的校验。

## 导入规则

安装器按已经识别的目标型号选择包，不从文件名猜型号。型号、目录不得重复；清单的型号及版本必须与统一包声明一致。共用映射不得覆盖型号目录已有文件，也不能指向 `package.json`。

导入仅提取所选型号及其声明的共用文件，保留原始清单字节，然后检查长度、SHA-256、型号与安装目标。不同型号的启动组件不会因共用镜像而互换。

归档格式根据内容识别：支持 ZIP/ZIP64、7z、RAR 和 TAR 及常见压缩 TAR。支持原始数字分卷（`.001`、`.002` 等）及原生 RAR 分卷；所有分卷放在同一目录，选择第一卷。当前系统流水线输出 ZIP，按 1900 MiB 切分，不重新压缩；安装器直接按卷读取，不先拼成另一份完整文件。

带密码的归档、非法路径、符号链接、重复或冲突条目会被拒绝。提取文件只能写入本次创建的暂存目录；失败或取消时清理该目录，原归档保持不变。嵌套的压缩分区镜像在导入阶段只作为文件提取，交给后续安装流程处理。

ZIP 使用 .NET 自带的 `System.IO.Compression`；其他格式使用 SharpCompress。许可证见 [SharpCompress-LICENSE.txt](SharpCompress-LICENSE.txt)。
