window.TEST_RECORDS = [
  {
    "id": "record-test100-runtime-1793502966",
    "version": "25G332-Test100",
    "label": "Test100本轮实测",
    "tone": "warning",
    "date": "2026-11-01",
    "state": "40项：8通过、4部分、28未覆盖、0项明确判为未通过",
    "summary": "Test100本次启动固定40项：8通过、4部分、28未覆盖、0项明确判为未通过。身份与联网、149频道ROC、MIF控制帧接纳、awdl0常驻和IPv6链路本地有本轮证据。两个短Wi-Fi窗口通过；自然GTK更新后的30秒没有掉线，发送完成身份仍不匹配。真实AWDL数据尚未进入ifnet，双向AirDrop未打通。睡眠按要求跳过；未覆盖不是失败。",
    "evidence": [
      "候选与PCI识别匹配；认证、IPv4、网关、DNS、en1 HTTPS通过。",
      "W0 300.269秒和诊断后60.281秒被动Wi-Fi窗口通过，计数无增量；自然GTK周期未出现，睡眠按要求跳过。",
      "149频道同owner ROC START/END通过；MIF Action来源归属、解析和队列接纳通过，未验证具体外部iPhone身份。",
      "OpenWrt 4次本地send与4个精确PACKET_OUTGOING回显；无PID/cookie TXS、ACK或RF证明，跨时钟映射未校准。",
      "同一RX descriptor含host/GP2/TSF时钟值，但缺该硬件样本的误差界。awdl0 30.480秒/7次快照保持UP/RUNNING并有IPv6路由；无AWDL数据/ifnet回执。",
      "12:04捕获自然GTK更新；随后30秒、31个样本保持链路与IP，无新增watchdog、复位或固件错误。提交、doorbell和回收侧车指向同一host槽位，但TX_RSP帧头身份仍不匹配，完成回报未闭合；一次稳定窗口不代表问题已彻底修复。",
      "后续公网对照：强制绑定Wi-Fi和有线接口访问同一HTTPS站点均超时；默认路由请求返回200，绑定Wi-Fi接口的网关检查通过。不能据此归因Intel掉线，也不把默认路由成功算成Wi-Fi公网验收。"
    ],
    "blockers": [
      "AWDL数据帧进入原生ifnet仍无直接证据。",
      "本地send和PACKET_OUTGOING回显不能证明真实无线发射；没有TXS/ACK/peer收件。",
      "没有完成任何方向的AirDrop文件收件和哈希校验。",
      "自然GTK后30秒未掉线，但TX_RSP完成身份仍不匹配；睡眠按要求跳过。"
    ],
    "next": [
      "核对密钥回复的完成记录索引和帧头读取时机。",
      "使用新工具区分未知包头、软件完成和空口发送；继续查固件P2P_DEVICE的数据接收限制。"
    ]
  }
];
