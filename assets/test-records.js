window.TEST_RECORDS = [
  {
    "id": "record-test121-runtime",
    "version": "25G332-Test121",
    "label": "Test121：系统接口可见，但 Wi-Fi 初始化未保持 READY；Test122 修复候选待重启验收。",
    "tone": "warning",
    "date": "2026-11-03",
    "state": "Test121本轮：1项通过 · 0项部分通过 · 1项未通过 · 38项未覆盖",
    "short_summary": "Wi-Fi 初始化失败；Test122 已部署待重启",
    "summary": "Test121 已加载，系统仍列出 en1，但接口处于 Off/inactive。日志显示 READY 曾出现，之后地址重启 quiesce 被拒绝，接口仅保留 UP、READY 清零，上层等待超时。当前源码复核发现 stop/INIT 转换把 gate 持有误当作 workloop 线程身份；Test122 改为验证 gate ownership。本轮未测试 AWDL、即时热点或 AirDrop；Test122 尚无启动实测。",
    "evidence": [
      "Test121 加载身份已核对，系统列出 en1；当前接口为 Off/inactive。",
      "Wi-Fi 初始化链路曾达到 READY；随后地址重启 quiesce 返回 Busy，状态退回 UP-only，READY 为 0，最终电源等待超时。",
      "没有 watchdog、固件错误或硬件错误触发；本轮不能据此判断路由器问题。",
      "源代码复核找到 stop/INIT gate 的线程身份检查与 runAction 持 gate 语义不符；Test122 候选修正为 gate ownership 检查。",
      "本轮没有进行 AWDL、149 频道、即时热点或 AirDrop 诊断。"
    ],
    "blockers": [
      "Test121 的 Wi-Fi 初始化/地址重启恢复失败，需先在 Test122 验证 gate 修复。",
      "AWDL 真实数据输入和原生 awdl0 回包本轮未测试。",
      "即时热点与双向 AirDrop 尚未完成端到端验收。"
    ],
    "next": [
      "重启进入 Test122，确认 Wi-Fi READY、扫描和连接稳定；先完成短时稳定性观察。",
      "Wi-Fi 基线通过后，再单独验证 AWDL 接收入口与原生 awdl0 数据回包；本轮未做 AirDrop 发送。"
    ]
  }
];
