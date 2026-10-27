# P2P 单帧发送与 Wi-Fi 稳定性诊断

Test029 已实机收到 TX status=1，描述符、队列和站点清理完成。返回的帧序号为 0，提交值为 64；调度队列索引为 1，与期望一致。序号仅描述无线帧，不再作为 DMA 所有权条件；队列、generation、长度、帧类型、TID 和调度索引校验保留。

本轮驻留 START status=1、END status=0，表示结束通知已到但完整驻留未成功，不能据 TX 成功掩盖。之后一次真实 Wi-Fi 关闭/开启、保存网络自动重连，以及前后六次接口绑定的 1 MB HTTP 请求通过。尚未实现 awdl0、对端收帧或 AirDrop 传输。

Test027 起使用管理员手动触发，每次启动最多一次；不在自动关联后自行探测。以下保留早期版本的定位过程。

此版本延续 Test019 已实机通过的 P2P MAC、独立 PHY/binding 和 Session Protection 开始/结束通知。在稳定 Wi-Fi 关联后，每次启动只运行一次。

## 本轮范围

1. 为 P2P 设备建立独立广播 station 和固件动态 TX 队列。
2. 等 100 ms 驻留的 START 通知后，在主命令门内重验状态并发送一帧诊断 Action。
3. 校验固件 TX completion 的队列、描述符、帧长度及状态；帧序列单独记录。
4. 等驻留 END 和实际 TX completion，完成 TXPATH_FLUSH、REMOVE_STA 后再释放队列内存。

诊断帧使用私有 P2P 地址、本地实验标识和 `ITL-P2P-PROBE` 文本；它不是 Apple AWDL 帧。广播发送成功也不证明 iPhone 收到。没有创建 awdl0，不代表 AirDrop 可传文件。

## 故障行为

命令超时、响应身份不匹配或缺少实际发送完成时保留 DMA 和队列。此启动内不重试、不软复位这些资源，防止悬空 DMA。必要时下一次正常重启恢复。原 Wi-Fi 私有地址和既有上网连接不由探针改写。

## 验证

Test020 已实机确认 Wi-Fi 正常，但在前置检查返回 EOPNOTSUPP，未发帧并已正常清理。原因是错误要求 DATA_PATH/0x17 v1；随驱动提供的 QuZ-a0-hr-b0-68 固件没有此命令，只提供 LONG/SCD_QUEUE_CFG v2。

Test021 改用固件实际提供的 24 字节队列分配命令。旧接口没有独立队列 REMOVE 命令，队列随站点删除。代码仍要求实际发送完成、排空响应和站点删除确认，不把命令成功等同于 DMA 已结束。新预检会记录具体拒绝项和固件版本；离线测试直接解析实际 ucode 的 CMD_VERSIONS。

同一测试还发现 fw68 没有设置旧 DQA capability bit 12。该位约束旧静态队列，不能作为 22000 系列 TVQM 的条件；本版保留它的真实遥测值，按硬件系列和实际命令版本判断 TVQM 支持，不伪造 capability。

Test021 实机仍未发帧：拒绝掩码为 3，实际 TX_CMD 是 v10/notif7，传输系列不是 22000。此前 QuZ/22000 固件测试覆盖错了本机路径。PCI 7AF0 对应 So 传输配置；HR2 无线部分虽然使用 AX201 名称，传输配置却属于 AX210 系列。

Test022 严格按已知配对选发送格式：22000/v9/notif7 使用 20 字节 gen2 头，AX210/v10/notif7 使用 28 字节 gen3 头。gen3 同时调整 flags/offload 字段宽度、802.11 头位置和 TFD 长度。旧队列分配及回收流程不变。诊断新增实际 family、命令格式、所选固件文件名和硬件标识，避免再从商品名称推断协议。

Test022 实机确认加载了 so-a0-hr-b0-68、AX210 传输系列和 gen3 格式，预检通过。发送资源创建返回 EIO，探针没有发帧；驻留及 MAC 清理完成，Wi-Fi 的三次接口绑定 HTTPS 请求通过。该版只保存清理后的状态，无法区分 ADD_STA 拒绝和队列分配拒绝。

Test023 修正管理队列的固件 TID：主机内部管理槽位是 8，SCD_QUEUE_CFG 命令和 flush 响应应使用 15。依据是官方 [iwl_mvm_tvqm_enable_txq](https://github.com/torvalds/linux/blob/v6.8/drivers/net/wireless/intel/iwlwifi/mvm/sta.c#L788-L840) 的转换。它是已确认的协议差异，尚不能断言就是 Test022 的实机 EIO 原因。新增建站原始状态、队列响应及最后一次创建步骤记录，保留失败点，不再被清理后的空资源状态覆盖。

`NativeP2PTxSetupStep`：1 准备 PHY/binding，2 创建诊断帧，3 协议预检拒绝，4 预留 station ID，5 ADD_STA，6 分配 TX 队列；`NativeP2PTxSetupResult` 是该步骤实际返回值。未执行的命令没有对应响应记录。

Test023 实机记录为 ADD_STA status=1，队列响应 flags=1、qid=4、write_pointer=0，创建步骤 6 返回 EIO，没有发帧。该 EIO 是本地 `flags != 0` 检查产生的；不能当作固件已确认拒绝。Linux 和 FreeBSD 的同接口分配器忽略这个字段，按有效响应、队列号和写指针接纳。此前凭非零 flags 判断队列不存在并释放 DMA 的假设不成立，原先“安全清理”的标签不足以证明固件资源已结束。

Test024 保留原始 flags 遥测，移除仅凭 flags 的拒绝和释放。只有完整命令响应、合法队列号/写指针、无本地所有权冲突时才安装队列；异常或不确定结果继续保留 DMA。发送完成还校验固件管理 TID 15，不能拿主机内部槽位 8 的响应回收描述符。资源仍需实际完成、flush 和 REMOVE_STA 确认才能释放。

Wi-Fi 稳定性并行验证：Test023 的约 100 秒窗口中，6 次绑定 en1 的 1 MB HTTPS 请求全部成功，就绪/地址正常，重置和开关计数没有增加。这不是极限测速或长稳证明。开窗前已有 40 次关闭重试和 Busy 结果，下一版区分 P2P 资源保留与状态任务队列 Busy，禁止靠强制 reset 绕过。开关测试脚本现在分别记录无线电开关和保存网络重新关联；仅开关成功而没有恢复链路/IPv4，不再算整个循环通过。睡眠恢复和新网络连接仍待实机验证。

两条路径的共同状态也需要复位：只有 P2P worker 已结束、队列和 station 明确不存在、MAC/binding/PHY 全部释放时，才允许在既有固件复位路径更新站点登记的 generation。任何 pending/active/unknown 资源均阻止此更新，不能用软件 generation 变化替代 DMA 已结束的证明。

编译与离线故障注入只能证明代码和资源处理路径；重启后还需按实际二进制 UUID、TX/Session 遥测、Wi-Fi 连通性确认。早期测试记录不能替代最新版本的实机结果。

固件接口对照 Linux 官方 iwlwifi 的 [队列分配](https://github.com/torvalds/linux/blob/v6.8/drivers/net/wireless/intel/iwlwifi/queue/tx.c)、[版本分流](https://github.com/torvalds/linux/blob/v6.8/drivers/net/wireless/intel/iwlwifi/mvm/ops.c) 和 [广播站点生命周期](https://github.com/torvalds/linux/blob/v6.8/drivers/net/wireless/intel/iwlwifi/mvm/sta.c)。未引入其他 macOS fork 的实现。
