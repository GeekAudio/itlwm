# AirportItlwm-Tahoe

Intel AX201 的 macOS Tahoe 原生 Wi-Fi 驱动，基于 OpenIntelWireless/itlwm。

## 适用范围

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

## 当前状态

普通 Wi-Fi 已可连接。本次启动确认 Test059 已加载、私有地址正常；发布复查中捕获到一次发送超时，驱动复位后自动恢复。长期稳定、睡眠恢复和即时热点仍在验证。

AirDrop 和接力不作为此版本支持功能。AWDL 仍在开发，包内不含手动无线诊断工具。

## 下载与源码

在本仓库 Releases 下载 `AirportItlwm-Tahoe.zip`。它与本次实机使用的 Test059 驱动一致，保留原有构建标识。

对应源码另附 `AirportItlwm-Tahoe-Source.zip`；校验值见 `SHA256SUMS.txt`。

基于 [OpenIntelWireless/itlwm](https://github.com/OpenIntelWireless/itlwm)，遵循 GPL-2.0；Intel 固件许可见 `iwlwifi-firmware-license`。上游代码和固件保留各自版权及许可。
