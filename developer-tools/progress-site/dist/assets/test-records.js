window.TEST_RECORDS = [
  {
    "id": "record-test124-test124-runtime",
    "version": "25G416-Test124",
    "label": "Test124：受控单包原生输入已见；发送完成与清理未闭环",
    "tone": "warning",
    "date": "2026-11-09",
    "state": "Test124 实机诊断：9项通过 · 5项部分通过 · 1项未通过 · 25项未覆盖",
    "short_summary": "一个匹配返回到达同一awdl0 socket；固件完成、清理与AirDrop未证明",
    "summary": "Test124在频道6执行一次受控单包诊断。OpenWrt AF_PACKET monitor排除PACKET_OUTGOING后匹配一个数据帧；对端解析器匹配请求并本地发送一次回复。同一个awdl0绑定IPv6 socket收到一个匹配返回，ifnet_delivery_proven=true。延迟IORegistry刷新在同一启动、运行身份与generation下确认Captured=Decoded=Delivered=1、inputResult=0，捕获和输入均位于100 ms租约内。firmwareAttempt、completion、cleanupAck、radioACK、peer_receipt_proven、over_air_delivery_proven、AirDrop均为false。helper exit 2 / wait_cleanup / ETIMEDOUT，HAL quarantine，ResourcesAbsent=false。初次路由恢复失败后由watchdog恢复，幂等只读校验确认radio0 AP ch6/20、radio1与四项配置哈希未变；WAN/LAN未改。en1为UP并有IP但未关联AP，默认路由en0；联网冒烟与睡眠跳过。",
    "evidence": [
      "AF_PACKET monitor排除PACKET_OUTGOING后匹配一个请求；对端解析器request_matched=true、reply_local_send=true。该现场解析结果不替代正式peer_receipt_proven。",
      "同一个awdl0绑定IPv6 socket收到一个匹配返回，ifnet_delivery_proven=true。",
      "延迟IORegistry刷新在同一启动、运行身份与generation下记录Captured=Decoded=Delivered=1、inputResult=0；捕获与输入均在100 ms租约内。即时计数0是旧快照。",
      "helper exit 2，phase=wait_cleanup，原因为ETIMEDOUT；HAL quarantine且ResourcesAbsent=false。firmwareAttempt、completion、cleanupAck、radioACK、peer_receipt_proven、over_air_delivery_proven与AirDrop均为false。",
      "首次router restore exit 1（ubus Not found）；watchdog随后恢复。幂等restore为只读校验并确认radio0 AP ch6/20、radio1及四项配置哈希不变；最终无active/lock，WAN/LAN未改。",
      "en1为UP并有IP但未关联AP，默认路由en0；联网冒烟及睡眠跳过。"
    ],
    "blockers": [
      "固件发送完成、radio ACK、正式peer receipt和空口交付未证明。",
      "helper在wait_cleanup超时并进入HAL quarantine；cleanupAck与ResourcesAbsent未成立。",
      "IPv6邻居发现、Bonjour、分享服务握手、持续双向传输和AirDrop均未覆盖。"
    ],
    "next": [
      "按Test124现有结果单独复核生命周期清理/timeout终态；不将失败的清理门禁折叠成成功。",
      "25G416-Test125仍是未部署离线候选；其构建和复核不改变本轮实测计数。"
    ]
  }
];
