# Test134：组播数据队列准入

**实机资源准入与安全撤销已通过。** Test134 的 MULTICAST 站点及 TID0 未安装队列得到固件确认，随后完成精确撤销；没有提交数据帧。下一版 [Test135](../test135/README.md) 接入 Discovery RX，先验证现有系统 QM 路径。

## 这次纠正什么

此前把受控 UDP 的成功用于推进真实服务发现，但两者的发送资源不同。需要先证明系统查询所用的路径成立，不能靠接收埋点补足这个缺口。

| 路径 | 当前资源 | 已有证据 | 缺口 |
| --- | --- | --- | --- |
| PSF/MIF 管理帧 | GENERAL_PURPOSE / TID15 | 历史管理帧实验 | 不代表数据发送约定 |
| Test132 受控 UDP | LINK / TID0 | 双包发送完成、受控回包进入 awdl0、资源释放 | 不代表真实 mDNS 或 AirDrop |
| 系统 mDNS 查询 | 旧实现仍走 GENERAL_PURPOSE / TID15 | 本地输出与候选生成 | 该固件组合的有效性未证实 |
| 新组播数据原型 | MULTICAST / TID0，独立资源 | 固件接受申请，精确撤销通过 | 尚未安装发送队列或提交数据 |

公开 Linux v6.1 实现将组播数据绑定 `STA_MULTICAST`，内部站点地址是 `03:00:00:00:00:00`，22000 系列使用 TID0。该实现只直接支持 AP/ADHOC；不能据此宣称 P2P_DEVICE 上必然可用，也不能断言旧路径必然被固件丢弃。

## 首轮只验证资源申请与释放

显式管理员触发后，创建独立站点并等待 ADD_STA 回执，再请求 TID0 队列。合法分配回执仅代表固件接受资源；队列保持未安装，不写入生产 `sc->txq`，不启动无线会话、不发 PSF/MIF、不提交数据 doorbell。

随后按精确身份执行撤销，分别记录操作结果和清理结果。未知回执保留资源所有权；完整确认后才能释放外层 MAC。现有 Wi-Fi、管理队列和已验证的 LINK 路径保持独立。

通过标准：站点接受、队列接受、没有数据提交、资源及外层 MAC 释放均有匹配回执。单纯返回 0 或资源字段变空不算通过。

已完成整包构建、88 项生产编译组合和独立复核。生产函数的 ASan/UBSan 测试覆盖成功、拒绝、未知回执及清理失败；这些是离线验证。后续实机只证明资源准入及撤销，不证明该资源能传输真实数据。

## 后续顺序

1. 资源准入和撤销已验证；保留该原型，不直接切换生产发送资源。
2. Test135 先用现有 GP/TID15、flags7 验证真实系统 QM，接入独立接收桥。
3. 根据同包发送完成、对端接收及回复证据，再决定优先级或组播队列对照。
4. 服务回复进入 awdl0 并被系统 DNS-SD 解析后，再验证 AirDrop 协商和文件传输。

每一项都有独立结果，受控数据、服务发现和文件传输不互相替代。联网冒烟和睡眠继续跳过；开机 ALIVE 超时仍未修复。

参考：[站点类型](https://github.com/torvalds/linux/blob/v6.1/drivers/net/wireless/intel/iwlwifi/fw/api/sta.h)、[组播站点与队列申请](https://github.com/torvalds/linux/blob/v6.1/drivers/net/wireless/intel/iwlwifi/mvm/sta.c)、[数据发送选择](https://github.com/torvalds/linux/blob/v6.1/drivers/net/wireless/intel/iwlwifi/mvm/tx.c)。
