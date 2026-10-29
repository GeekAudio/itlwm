# AirportItlwm-Tahoe

Intel AX201 的 macOS Tahoe 原生 Wi-Fi 驱动，基于 OpenIntelWireless/itlwm。

## Release 与开发状态

- **GitHub Release：2.4.0 / Test059。** Release 只包含 `AirportItlwm-Tahoe.zip` 二进制包；下方的安装说明和设备范围针对这个版本。
- **开发源码：Test079。** 新增引导后的安全配对与接收收尾处理，尚待实机验证。Test078 的两段短测通过，但后段发生断链和 watchdog；没有数据回包或 AirDrop 文件收件证明。开发源码不属于现有 Release 压缩包，详见[接收路径分析](developer-tools/RX-DATA-PATH.md)。

## Test059 Release 适用范围

- 本次发布：2.4.0 / Test059。
- 实测系统：macOS 26.7.2，build 25G332，x86_64。
- 实测网卡：AX201，PCI 8086:7AF0，子设备 8086:0074。本包只匹配这组设备。
- 使用系统 Wi-Fi 菜单，可扫描、连接和使用私有地址。支持已实现的开放网络及 WPA2-PSK；WPA3-only、企业认证暂不支持。

## 依赖

通过 OpenCore 注入。Wi-Fi 无需额外 kext、HelliPort 或 OCLP，不修改系统卷；保留系统自带 IO80211Family 和 IOSkywalkFamily，不为本驱动添加 Kernel → Block。

蓝牙独立安装 OpenIntelWireless 的 IntelBluetoothFirmware 和适用于当前系统的 BlueToolFixup，本包不含蓝牙驱动。

## 安装

1. 解压 `AirportItlwm-Tahoe.zip`，把 `AirportItlwm.kext` 放到 `EFI/OC/Kexts/`。
2. 禁用同一网卡的其他 AirportItlwm / itlwm 条目。
3. 在 `config.plist → Kernel → Add` 添加以下条目，保存后重启。

| 字段 | 值 |
| --- | --- |
| BundlePath | AirportItlwm.kext |
| ExecutablePath | Contents/MacOS/AirportItlwm |
| PlistPath | Contents/Info.plist |
| Enabled | true |
| Arch | x86_64 |
| MinKernel | 25.6.0 |
| MaxKernel | 25.6.0 |

这些版本字段不能代替系统 build 检查。此版本使用私有系统接口，其他系统版本或网卡尚未验证。

## Test059 发布验证记录

普通 Wi-Fi 可扫描和连接，支持私有地址。Test059 的发布复查曾记录一次发送超时并自动恢复；长期稳定性、睡眠恢复和即时热点不在该次验收范围内。

Test059 不支持 AirDrop 或接力。AWDL 实验属于后续开发源码。

## Release 下载与源码

在本仓库 Releases 下载 `AirportItlwm-Tahoe.zip`。它与本次实机使用的 Test059 驱动一致，保留原有构建标识。

构建步骤见 [AirportItlwm-Tahoe-README.md](AirportItlwm-Tahoe-README.md)。Release 只提供二进制压缩包，校验值列在发布说明；开发源码按 Git 分支管理。

基于 [OpenIntelWireless/itlwm](https://github.com/OpenIntelWireless/itlwm)，遵循 GPL-2.0；Intel 固件许可见 `iwlwifi-firmware-license`。上游代码和固件保留各自版权及许可。
