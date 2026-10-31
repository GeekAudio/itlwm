window.TEST_RECORDS = [
  {
    "id": "record-test092-runtime-boot1793402509",
    "version": "25G332-Test092",
    "label": "Test092本轮复验",
    "tone": "warning",
    "date": "2026-10-31",
    "state": "Test092本轮40项：通过4、部分1、未覆盖34、回退1；Test093已部署，等待重启。",
    "summary": "初始5分钟联网观察通过，随后无操作Wi-Fi链路自行中断；AWDL数据回包和AirDrop没有成功证据。",
    "evidence": [
      "Test092已加载；当前40项只统计Test092实测，Test093开发/构建/部署不增加运行通过项。",
      "初始300.087秒/60样本链路观察与绑定Wi-Fi的联网请求通过；08:04无用户操作时Group2_OUTPUT返回0（仅入队），1.017秒后RX deauth reason 16/GROUP_TIMEOUT，RUN转AUTH并掉线。后置20.433秒/5样本观察失败；reset与watchdog计数未增加。",
      "受控发送器16/16次本机send()完成；唯一149/MAC index 1 owner-qualified帧是FC 0x80管理帧，不是AWDL数据帧，也没有PHY1归属证据。",
      "Native AWDL data RX/receipt为0；awdl0 UDP listener收到0个数据报。没有真实iPhone↔Mac AirDrop文件传输结果。",
      "Test093合并电源通知READY与revision去重（不更改真实READY/GET行为），加入Wi-Fi断开来源、私有地址/扫描耗时trace，并记录不含密钥或包体的pre-enqueue数值快照。 构建源提交 d332dbb9a75a9c7eb18aaea6bec4424e4b4685b8，二进制SHA-256 8903a98cc61d2663ef041238b11b9c3588762506d1f0245e57335863f60b4eed。 部署凭据匹配构建和验证回执，EFI回读检查通过，保留了完整备份；未自动重启、未触发射频。"
    ],
    "blockers": [
      "Wi-Fi无操作掉线仍未归因；关闭响应慢、开启状态闪动和扫描列表延迟仍待修复。",
      "没有AWDL数据输入receipt、native awdl0回包或双向AirDrop实测通过证据。"
    ],
    "next": [
      "完成Test093电源READY与revision去重、Wi-Fi断开来源/私有地址/扫描耗时trace及pre-enqueue数值快照的合并验证。",
      "只有Test093的build、validation和EFI部署读回回执哈希全部匹配后，才标记已部署并提示重启。",
      "重启后先复测Wi-Fi稳定性；再以真实数据接收receipt和手机↔Mac文件结果分别验收AWDL/AirDrop。"
    ]
  }
];
