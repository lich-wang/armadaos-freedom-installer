# ArmadaOS Freedom Installer

**English** · [简体中文](README.zh-CN.md)

**Install ArmadaOS Freedom on your tablet, with tools for backup, maintenance, and recovery when you need them.**

ArmadaOS Freedom Installer is the desktop companion to [ArmadaOS Freedom](https://github.com/ArmadaOS-Freedom/armadaos-freedom). It brings installation, offline upgrades, backups, and maintenance together for supported ARM Android tablets.

The app runs on **Windows x64** and **Apple silicon macOS**, with English and Simplified Chinese interfaces and light and dark themes. Feature availability differs by platform and device.

**This installer is free. Beware of scams.**

## Main features

- **Install Freedom**: Follow the assistant to install the system to the tablet's internal storage.
- **Upgrade offline**: Use a matching update package to upgrade a tablet already running Freedom.
- **Maintain Android boot support**: Prepare for an Android update and repair afterward.
- **Uninstall Linux**: Remove Linux and return its storage space to Android.
- **Back up and recover**: Dedicated Qualcomm 9008 / EDL backup and restore tools.

## Supported devices

| Device | Model | Current support |
|---|---|---|
| Lenovo Legion Y700 Gen 4 | TB322FC | Internal installation, maintenance, uninstall, offline upgrade, global backup and restore |
| Lenovo Legion Y700 Gen 5 | TB323FU | Internal installation, maintenance, uninstall, offline upgrade, global backup and restore |
| Lenovo Xiaoxin Pad Pro GT | TB710FU | Internal installation, global backup and read-only checks; the maintenance, uninstall and global restore write routes are implemented (only boot is re-signed; the device's AVB metadata is kept) but **not yet verified on a device, so they stay closed** |

**Windows** and **macOS** (Apple silicon) offer the same features. TB710FU maintenance, uninstall and global restore stay closed until they are verified on a device, and system installation to a TF / microSD card is not currently offered.

Firmware and boot-chain requirements depend on the model. See the [device guides](https://github.com/ArmadaOS-Freedom/armadaos-freedom#device-support) and follow the installer's checks. Offline upgrades require a compatible Freedom system, update service, and package; global backup requires the original partition layout before Linux installation.

## Getting started

Prepare the installer for your computer and the matching system package, which is supplied separately. Complete the environment checks, connect the tablet, and follow the assistant for the task you want to perform. **Y700 Gen 4 and Gen 5 must use the USB-C port on the tablet's long edge.**

**Installation, repartitioning, and uninstall initialization erase the affected personal data. Back up photos and app data separately.** Recovery backups do not contain a complete copy of your personal files.

## Development

<details>
<summary>Building from source</summary>

See the [build guide](docs/build.md) for the Windows and macOS build steps and required components.

</details>

## Community and feedback

Report problems through [Issues](https://github.com/ArmadaOS-Freedom/armadaos-freedom-installer/issues), including your tablet model, computer OS, installer version, the operation that failed, and relevant logs.

- **Author and Chinese-speaking community**: [Danyi on Bilibili](https://space.bilibili.com/258786).
- **Main QQ fan group**: 487945399
- **Second QQ fan group**: 332038419
- **International contact**: [mydanyi@qq.com](mailto:mydanyi@qq.com)

Related projects: [ArmadaOS Freedom](https://github.com/ArmadaOS-Freedom/armadaos-freedom) · [Organization homepage](https://github.com/ArmadaOS-Freedom)

## License

Source code is provided under [GPL-3.0](LICENSE). Third-party components, drivers, and device loaders retain their own licenses and notices.
