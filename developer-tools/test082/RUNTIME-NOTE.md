# Test082 本轮实测

- 已加载 Test082，归档和运行 UUID 匹配。
- 五分钟观察共 60 个样本，链路、IPv4 一直有效，watchdog 与复位计数没有增加。仅验这段窗口，未测睡眠和开关。
- 网关和三次绑定 Wi-Fi 接口的 HTTPS 完整成功。原请求使用合成 DNS 地址而连接超时；测试指定真实解析地址后通过，系统 DNS、代理和路由未改。
- MCC 通知、请求、返回和应用代次闭合。149 原始标志为 `0x741`，缺少主动扫描 ACTIVE 位，驱动映射为 PASSIVE。当前保守策略据此拦住 RX149 实验；这不证明硬件禁止被动接收。
- awdl0 常驻，软件队列接纳计数 13→15；无线完成和真实 RX 交付均为 0。AirDrop 文件收发未验收。

本轮固定 40 项：5 通过、3 部分、32 未覆盖，无新增历史验收项。未重复 P2P 创建或无线驻留实验，因此没有继承上一轮对应结果。

## 下一个修复点

STA 保护时长的单位缺陷仍在当前版本。OpenBSD 已有对应修复：新 API 直接序列化 TU，关联路径使用九个 beacon 间隔，零间隔默认 900 TU。[上游修复提交](https://github.com/openbsd/src/commit/a08da3bef5a4ce043b2281c6b0800e04855ac47e)。下一候选将验证真实 AUTH 调用和 24 字节命令；本轮没有替换驱动，也未把请求时长当作固件实际占用时间。

## 官方调试资料

[Intel 调试指南](https://intel.github.io/Intel-wireless/troubleshooting/)强调驱动信息、驱动日志和固件错误转储。[Linux Wireless 调试指南](https://wireless.docs.kernel.org/en/latest/en/users/drivers/iwlwifi/debugging.html)补充主机与固件交互 tracing、队列停滞时的转储，并建议按问题选择调试输出。Linux 的 devcoredump、debugfs 和 trace-cmd 需要在 macOS 驱动中找到对应实现；不能直接套用命令，也不能把错误计数或旁路抓包称为完整固件转储。
