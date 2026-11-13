# AirportItlwm-Tahoe

让 Intel AX201 在 macOS Tahoe 使用系统原生 Wi-Fi，基于 [OpenIntelWireless/itlwm](https://github.com/OpenIntelWireless/itlwm) 开发。通过 OpenCore 加载，无需 HeliPort 或 OCLP，不修改系统卷。

[下载驱动](https://github.com/GeekAudio/itlwm/releases/tag/tahoe-2.4.0) · [安装](#安装opencore) · [开发源码](https://github.com/GeekAudio/itlwm/tree/codex/tahoe-test095)

## 版本

| 版本 | 用途 | 当前状态 |
| --- | --- | --- |
| **2.4.0 / Test059** | 已发布的 Wi-Fi 驱动 | 下载文件为 `AirportItlwm-Tahoe.zip`，支持范围见下表 |
| **Test120** | 开发与诊断 | 已加载并完成一轮受控接收诊断；未发布到 Release |

开发进度更新于 **2026-11-03**。Test120 本轮接收窗口正常关闭、资源已释放，但未收到测试 UDP；新增的失败清理分支尚未触发。

## 适用范围

目前只在一台机器上验证，**本发布包只匹配下列设备**。

| 项目 | 范围 |
| --- | --- |
| 系统 | macOS 26.7.2，build `25G332`，x86_64 |
| 网卡 | Intel AX201，PCI `8086:7AF0`，子设备 `8086:0074` |
| 网络认证 | 开放网络、WPA2-Personal（PSK） |
| 其他系统、网卡 | 尚未验证；上游支持的设备不等于本包支持 |
| WPA3-only、企业认证 | 暂不支持 |

用 `sw_vers -productVersion` 和 `sw_vers -buildVersion` 查看系统版本。本驱动使用系统私有接口，不能只按“macOS 26”判断兼容性。

## 功能状态

✅ 已有实测　⚠️ 可用但仍有问题　🚧 开发中　— 尚未验收

| 功能 | 已发布 Test059 | 开发版已记录状态 |
| --- | --- | --- |
| 系统 Wi-Fi 菜单、扫描、连接、获取 IP | ✅ | ⚠️ 普通联网可用；扫描和菜单状态仍有异常 |
| 私有 Wi-Fi 地址 | ✅ | 保留支持，未逐项复验 |
| 快速切换网络（A → B → A） | — | ⚠️ 偶发无法加入、菜单不显示已连接网络 |
| 长时间联网、密钥更新 | ⚠️ 出现过发送超时并自动恢复 | ⚠️ 仍在排查断链和恢复，短时观察通过不代表长期稳定 |
| 睡眠与唤醒 | — | — 当前暂停测试 |
| 即时热点 | — | ⚠️ 手机能开启热点，Mac 扫描并加入的过程仍会失败 |
| 原生 awdl0 数据接收 | 不作为发布功能 | 🚧 Test119 收到受控 OpenWrt UDP；Test120 未复现，尚未证明 iPhone 数据回包 |
| 双向 AirDrop | 不支持 | 🚧 尚未打通文件传输 |
| 接力、通用剪贴板 | 不列为支持功能 | — 尚未完成独立验收 |

设备互相可见、驱动报告发出数据，都不等于 AirDrop 传输成功。

## 组件与依赖

| 组件 | 用途 | 依赖 |
| --- | --- | --- |
| `AirportItlwm.kext` | Intel Wi-Fi | OpenCore；系统自带 `IO80211Family`、`IOSkywalkFamily` |
| Intel 蓝牙组件（另装） | 固件加载与系统蓝牙兼容 | 见下方官方安装说明，本发布包不包含蓝牙组件 |

Wi-Fi 本身不依赖 Lilu 或额外辅助 kext。保留系统 Wi-Fi 框架，不为此驱动添加 `Kernel → Block`。

如果使用 Intel 蓝牙，按 [OpenIntelWireless 官方说明](https://openintelwireless.github.io/IntelBluetoothFirmware/FAQ.html#what-additional-steps-should-i-do-to-make-bluetooth-work-on-macos-monterey-and-newer)配置 `IntelBluetoothFirmware`、`IntelBTPatcher`、`BlueToolFixup` 及 Lilu；在 Tahoe 上不要加载 `IntelBluetoothInjector`。具体版本需适配当前系统，蓝牙能发现设备也不代表 AirDrop 数据通路已完成。

## 安装（OpenCore）

以下步骤针对已发布的 **Test059**。

1. 下载并解压 [AirportItlwm-Tahoe.zip](https://github.com/GeekAudio/itlwm/releases/download/tahoe-2.4.0/AirportItlwm-Tahoe.zip)。
2. 将 `AirportItlwm.kext` 放入 `EFI/OC/Kexts/`。
3. 禁用同一网卡的其他 `itlwm` / `AirportItlwm` 条目，在 `config.plist → Kernel → Add` 添加下面的配置。
4. 保存后重启，在系统 Wi-Fi 菜单扫描并连接网络。

| 字段 | 值 |
| --- | --- |
| BundlePath | `AirportItlwm.kext` |
| ExecutablePath | `Contents/MacOS/AirportItlwm` |
| PlistPath | `Contents/Info.plist` |
| Enabled | `true` |
| Arch | `x86_64` |
| MinKernel | `25.6.0` |
| MaxKernel | `25.6.0` |

`MinKernel` / `MaxKernel` 限制的是 Darwin 内核版本，不能代替上面的系统 build 检查。

## 验证与反馈

先确认扫描、连接、获取 IP 和实际联网，再测试开关 Wi-Fi、切换已知网络和持续联网。AirDrop 目前仍是开发目标。

反馈问题时附上系统 build、网卡 PCI ID、驱动 Test 编号、发生时间和具体操作，例如“连接 B 后立即切回 A”。日志中的 SSID、MAC 地址、设备标识和密码请先移除。

## 源码与构建

- **复现发布包：**使用 [Test059 对应源码](https://github.com/GeekAudio/itlwm/tree/0b292eb0f304079eb11f10d8659489f8ded3762d)和[该提交的构建说明](https://github.com/GeekAudio/itlwm/blob/0b292eb0f304079eb11f10d8659489f8ded3762d/AirportItlwm-Tahoe-README.md)，需要完整 Xcode、Python 3 和 MacKernelSDK。
- **参与开发：**查看[开发分支](https://github.com/GeekAudio/itlwm/tree/codex/tahoe-test095)与[数据接收路径说明](https://github.com/GeekAudio/itlwm/blob/codex/tahoe-test095/developer-tools/RX-DATA-PATH.md)。实验诊断与普通 Wi-Fi 安装分开。
- Release 附件只提供二进制压缩包，校验值见[发布说明](https://github.com/GeekAudio/itlwm/releases/tag/tahoe-2.4.0)；源码通过 Git 提交和分支保存。

## 许可

基于 [OpenIntelWireless/itlwm](https://github.com/OpenIntelWireless/itlwm)，遵循 [GPL-2.0](LICENSE)。Intel 固件条款见 [iwlwifi-firmware-license](iwlwifi-firmware-license)，上游代码和固件保留各自版权及许可。
