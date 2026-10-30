# Test087 接收入口观察

本版用于区分“固件没有送来 RX_MPDU”和“数据已到驱动，但 owner 条件不满足”。这是开发诊断版，尚不代表 AirDrop 可用。

- 同一条接收路径记录：RX 中断、ring drain、通知校验、MPDU 分发、缓冲分配、MPDU 入口、owner 首个拒绝原因和原记录器结果。
- 延续 Test086 已启用的数据输入实验。原有 owner 判断只执行一次；本版不增加接收、过滤、PHY 配置或发送权限。
- 手动触发后的数值观察最多持续 4 秒，原 149 频道接收窗口仍是 100 毫秒。普通 END 不结束数值观察；停止或复位会提前关闭。
- 149 频道与非 149 类各保留最多 8 个 MPDU 样本；后者也包含频道未知的样本。样本只含数值元数据，不保存帧内容；丢样和截断单独计数。
- 关闭后发布 `NativeRxPreOwnerSnapshot`。采集工具保存连续三次原始数据和哈希，确认一致后再解码；缺失字段不会按零补齐。

## 如何读结果

| 观察结果 | 可以定位到的范围 |
| --- | --- |
| 中断、drain 有增长，MPDU 分发为零 | 本次窗口没有看到 RX_MPDU 通知；普通 STA 流量不能证明 149 收包 |
| MPDU 分发有增长，入口不足 | 对照 addbuf/copy 失败与采样丢失，检查进入 MPDU 前的路径 |
| 入口有增长，owner 通过为零 | 查看首个失败原因，并区分 149、STA 和未知频道 |
| owner 通过但原记录器拒绝 | 检查原记录器的所有权同步、容量和状态 |
| 原生数据输入或 listener 仍为零 | 尚未打通真实回包，不能据此宣布 AirDrop 成功 |

4 秒总量不能直接与 100 毫秒 owner 计数相减当作丢包率。单包归属还要核对时间、频道、ring slot 和通知身份；本版中断和通知只保留各阶段总量，带时间戳的样本限于 MPDU 入口。通知 qid、host ring 与物理 PHY 不是同一概念，149 频道样本也不自动等于 AWDL 数据。

## 离线检查

```sh
python3 native/tests/test087_owner_reason.py
python3 native/tests/test087_preowner_observation.py
python3 native/tests/test087_build_profile.py
python3 developer-tools/test087/tests/test_preowner_wire.py
```

这些检查不加载驱动，也不触发无线诊断。加载身份、Wi-Fi 稳定性和真实入站数据需在 Test087 重启后另行验证。
