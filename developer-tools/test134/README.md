# Test134：组播数据队列准入

**已部署，等待重启验证。** 当前运行仍是 Test132；Test134 默认不触发实验。Test133 的接收桥候选保留，但先暂停部署，补核真实 mDNS 的发送路径。

## 这次纠正什么

此前把受控 UDP 的成功用于推进真实服务发现，但两者的发送资源不同。需要先证明系统查询所用的路径成立，不能靠接收埋点补足这个缺口。

| 路径 | 当前资源 | 已有证据 | 缺口 |
| --- | --- | --- | --- |
| PSF/MIF 管理帧 | GENERAL_PURPOSE / TID15 | 历史管理帧实验 | 不代表数据发送约定 |
| Test132 受控 UDP | LINK / TID0 | 双包发送完成、受控回包进入 awdl0、资源释放 | 不代表真实 mDNS 或 AirDrop |
| 系统 mDNS 查询 | 旧实现仍走 GENERAL_PURPOSE / TID15 | 本地输出与候选生成 | 该固件组合的有效性未证实 |
| 新组播数据原型 | MULTICAST / TID0，独立资源 | 待验证 | 首先检查固件是否接受，再考虑发送 |

公开 Linux v6.1 实现将组播数据绑定 `STA_MULTICAST`，内部站点地址是 `03:00:00:00:00:00`，22000 系列使用 TID0。该实现只直接支持 AP/ADHOC；不能据此宣称 P2P_DEVICE 上必然可用，也不能断言旧路径必然被固件丢弃。

## 首轮只验证资源申请与释放

显式管理员触发后，创建独立站点并等待 ADD_STA 回执，再请求 TID0 队列。合法分配回执仅代表固件接受资源；队列保持未安装，不写入生产 `sc->txq`，不启动无线会话、不发 PSF/MIF、不提交数据 doorbell。

随后按精确身份执行撤销，分别记录操作结果和清理结果。未知回执保留资源所有权；完整确认后才能释放外层 MAC。现有 Wi-Fi、管理队列和已验证的 LINK 路径保持独立。

通过标准：站点接受、队列接受、没有数据提交、资源及外层 MAC 释放均有匹配回执。单纯返回 0 或资源字段变空不算通过。

已完成整包构建、88 项生产编译组合和独立复核。生产函数的 ASan/UBSan 测试覆盖成功、拒绝、未知回执及清理失败；这些只证明离线行为，固件支持仍待实测。

## 后续顺序

1. 资源准入和撤销成立。
2. 安装独立组播队列，发送一笔真实 awdl0 mDNS 查询，核对发送完成和对端接收。
3. 对端回复进入接收桥和 awdl0，系统 DNS-SD 获得服务记录。
4. 验证 AirDrop 协商及真实文件传输。

每一项都有独立结果，受控数据、服务发现和文件传输不互相替代。联网冒烟和睡眠继续跳过；开机 ALIVE 超时仍未修复。

参考：[站点类型](https://github.com/torvalds/linux/blob/v6.1/drivers/net/wireless/intel/iwlwifi/fw/api/sta.h)、[组播站点与队列申请](https://github.com/torvalds/linux/blob/v6.1/drivers/net/wireless/intel/iwlwifi/mvm/sta.c)、[数据发送选择](https://github.com/torvalds/linux/blob/v6.1/drivers/net/wireless/intel/iwlwifi/mvm/tx.c)。
