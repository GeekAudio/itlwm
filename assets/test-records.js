window.TEST_RECORDS = [
  {
    "id": "record-test122-runtime-boot1793681053",
    "version": "25G332-Test122",
    "label": "Test122：发送侧新增3条状态记录；Intel数据接收仍未打通。",
    "tone": "warning",
    "date": "2026-11-03",
    "state": "Test122本轮：5项通过 · 5项部分通过 · 0项未通过 · 30项未覆盖",
    "short_summary": "路由器见状态候选；无线发送和接收仍未证明",
    "summary": "Test122 Intel侧受控149频道窗口仍只见2条Beacon、未见AWDL Data。随后路由器侧独立状态尾窗中，4次本地发送调用完成、观察到4条outgoing及3条OTHERHOST发送状态候选，另有1条radiotap无效；分类不完整。候选没有逐包时间戳，帧内也没有本轮token，尚不能确认是否属于本轮，也不能确认它代表实际RF发射；本轮未取得原始固件TXS、MAC ACK或对端收件证据。awdl0接收仍为0；Wi-Fi保持On/Ready，用户手动切网后恢复，联网冒烟与睡眠按要求跳过。",
    "evidence": [
      "149频道接收窗口START/END均观测并接受，最终State 7/released；Intel侧见2条Beacon，没有AWDL Data，awdl0接收仍为0。",
      "路由器侧独立尾窗中4次本地发送完成，monitor观察到4条outgoing及3条OTHERHOST发送状态候选（TX_FLAGS分别为1/1/0，retries均为0）；另有1条radiotap无效，分类不完整。",
      "候选没有逐包时间戳，发送帧不含本轮token；尚不能确认是否属于本轮，也尚未取得原始固件TXS、MAC ACK、对端收件或AirDrop证据；候选也未确认对应实际RF发射。",
      "临时monitor已清理；WAN/LAN及无线持久配置未变。Wi-Fi reset、watchdog和固件错误快照均未增加。",
      "本轮未写EFI；联网冒烟和睡眠按用户要求跳过；本轮12项离线工具验证通过（不计入40项实机验收）。",
      "发送状态尾窗后的短只读复查中，en1保持On/active并有IPv4；复位、watchdog与固件错误快照计数未增加。短窗不代表长期稳定通过。"
    ],
    "blockers": [
      "Intel接收观测仍没有完整AWDL Data帧；具体缺失原因尚未确认。",
      "发送状态候选本轮归属尚未确认，尚未取得原始固件TXS、MAC ACK或对端接收证据；原生回包和AirDrop未验证。"
    ],
    "next": [
      "给测试帧加入本轮唯一标记并记录逐包观察时间，先确认状态记录对应同一帧，再对照接收上下文。",
      "继续确认完整AWDL Data是否进入Intel接收观测；之后再检查过滤、解码和ifnet交付。"
    ]
  }
];
