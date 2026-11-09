window.TEST_RECORDS = [
  {
    "id": "record-test126-runtime",
    "version": "25G416-Test126",
    "label": "Test126：同代许可已通过，单包已从 awdl0 发出并收到匹配返回；发送完成与安全释放仍未通过。",
    "tone": "warning",
    "date": "2026-11-09",
    "state": "Test126 本轮：9项通过 · 5项部分通过 · 1项未通过 · 25项未覆盖",
    "short_summary": "同代许可恢复，单包回包确认；TX完成与清理仍受阻",
    "summary": "本轮越过Test125的驻留前许可阻塞。原生UDP提交8字节，驱动触发一次门铃；对端匹配本轮请求，Mac在100 ms租约内捕获、解码并交付1个匹配返回。350 ms完成等待耗尽后进入隔离，未取得精确TX completion和完整资源回收证明。受控单包不等于持续AWDL或AirDrop。",
    "evidence": [
      "25G416-Test126身份核对通过，awdl0常驻；联网冒烟和睡眠未执行。",
      "MCC来源、请求、响应和应用均为当前代次5；CHUB notice=10、完整51项频道表。频道6同一会话START/END均观察到。",
      "UDP8字节errno0，门铃1；peer匹配本轮请求，Mac收到1个相同nonce返回，约45.3 ms。",
      "Captured=Decoded=Delivered=1，ifnet inputResult=0，捕获及交付均位于100 ms租约内。",
      "精确TX completion缺失；END后仍等待至350 ms预算耗尽，最终Result60，CleanupAck和ResourcesAbsent均0。",
      "首条restore命令非零；watchdog恢复后幂等只读复验通过。两频恢复/保持，四份配置hash未变，无临时guard或进程。",
      "没有radio ACK、正式空口收件、持续收发或AirDrop文件传输证明。复位计数前后保持5，不代表长期Wi-Fi稳定。"
    ],
    "blockers": [
      "缺少本次descriptor的精确TX completion；尚不能区分固件产出、dispatch或payload匹配问题。",
      "350 ms等待耗尽，安全隔离保留可能仍被固件持有的资源。",
      "持续AWDL、原生邻居发现、mDNS和AirDrop尚未验收。"
    ],
    "next": [
      "下一步核清发送完成事件：复用现有接收/完成记录，按本轮身份保留dispatch前的候选与拒绝原因。保持350 ms预算、精确匹配和DMA保护；本次启动不再追加发包。"
    ]
  }
];
