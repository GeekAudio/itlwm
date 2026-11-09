# Test133：原生 Discovery RX 离线候选

**状态：离线构建与独立复核完成，尚未部署或做实机验证。** 完整 Xcode 构建、80 项生产源码编译组合、Discovery RX 策略与 7 项生产桥接 ASan/UBSan 场景，以及既有 RX149、Directed、QM 回归通过。首次 ALIVE 失败记录已合入最终构建；不改变等待时长或自动重试。

## 设计范围

Test133 为原生服务发现输入准备独立 RX ring，供后续真实 mDNS 查询与应答接入；它不复用 RX149 接收实验，也不依赖固定 nonce 作为对端身份。

授权身份绑定真实 QM query token 和 doorbell、peer incarnation 与 PSF/MIF revisions、四个 epochs、ifindex 与 ifnet incarnation、源/本机 MAC、MCC revision、channel 6 及真实 ROC START/deadline。主门采样还要求当前 owner、epochs、peer、MCC、START、无 END 和精确的 query TX ownership ticket。输入描述符需匹配 channel 6、有效 MAC1 decode、原始且未保护/未聚合的帧及预期源 MAC；接收截止为 ROC deadline 与 query doorbell 后 100 ms 的较早者。END、过期、身份变化及未知/取消/停止状态都会关闭准入；资源释放要求匹配当前会话并确认接收队列静默。

## 证据边界

当前实机结果仍是 Test132：13 项通过、7 项部分通过、20 项未覆盖。Test133 尚未部署、加载或运行。开机 ALIVE 等待超时仍会复现；首个 1 秒等待窗没有锁存 ALIVE，现有证据无法区分固件未启动与 RX/IRQ 未送达。Test133 已加入该失败的持久数值诊断，不代表问题已修复。Test132 的受控 UDP 双包不等同于真实 mDNS/Bonjour 服务发现，也不证明 AirDrop 收件。

输入授权在线程主门下重新核验并取票，`ifnet_input` 在主门外执行。输入调用、原始返回值及成功次数单独记录；`SameWindowCommitted` 只表示已准入窗口内完成、未见已发布的 END／撤权，不表示回调结束时再次采样全部 peer 状态。

首次 ALIVE 记录只在完整发布后置有效，后续成功不会覆盖。寄存器读取掩码仅表示执行过读取，不代表固件健康。GitNexus 查询未解析相关新符号（索引过期、FTS 关闭），影响范围由人工调用链复核补足。
