window.TEST_RECORDS = [
  {
    "id": "record-test100-runtime-1793502966",
    "version": "25G332-Test100",
    "label": "Test100本轮实测",
    "tone": "warning",
    "date": "2026-11-01",
    "state": "40项：8通过、4部分、28未覆盖、0项明确判为未通过",
    "summary": "Test100本次启动固定40项截至当前：8项通过、4项部分通过、28项未覆盖、0项明确判为未通过。身份与联网、149频道ROC START/END、MIF来源归属与解析接纳、awdl0常驻及IPv6链路本地状态有本轮证据。Wi-Fi 300.269秒和诊断后60.281秒被动窗口通过；GTK自然密钥观察仍在进行，尚未出现自然更新；睡眠按要求跳过。OpenWrt本地send及PACKET_OUTGOING回显不证明RF；Intel侧没有AWDL数据/ifnet回执，AirDrop仍未验证。0项未通过只表示当前没有被明确判fail，不代表长期稳定或端到端功能已验收。",
    "evidence": [
      "候选与PCI识别匹配；认证、IPv4、网关、DNS、en1 HTTPS通过。",
      "W0 300.269秒和诊断后60.281秒被动Wi-Fi窗口通过，计数无增量；自然GTK周期未出现，睡眠按要求跳过。",
      "149频道同owner ROC START/END通过；MIF Action来源归属、解析和队列接纳通过，未验证具体外部iPhone身份。",
      "OpenWrt 4次本地send与4个精确PACKET_OUTGOING回显；无PID/cookie TXS、ACK或RF证明，跨时钟映射未校准。",
      "同一RX descriptor含host/GP2/TSF时钟值，但缺该硬件样本的误差界。awdl0 30.480秒/7次快照保持UP/RUNNING并有IPv6路由；无AWDL数据/ifnet回执。",
      "纯被动GTK观察仍在运行，尚未出现自然密钥更新；睡眠按要求跳过。"
    ],
    "blockers": [
      "AWDL数据帧进入原生ifnet仍无直接证据。",
      "本地send和PACKET_OUTGOING回显不能证明真实无线发射；没有TXS/ACK/peer收件。",
      "GTK自然密钥周期正在观察，尚未完成；睡眠恢复按要求跳过。",
      "没有完成任何方向的AirDrop文件收件和哈希校验。"
    ],
    "next": [
      "继续核对Intel真实数据RX到ifnet入口及OpenWrt硬件TX状态来源。",
      "用独立纯被动窗口验证自然GTK周期；睡眠继续跳过。"
    ]
  }
];
