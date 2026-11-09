window.TEST_RECORDS = [
  {
    "id": "record-test125-runtime",
    "version": "25G416-Test125",
    "label": "Test125已加载；本轮在驻留开始前被频道许可门禁拒绝，原生UDP未发出，发送完成修补尚未测到。",
    "tone": "warning",
    "date": "2026-11-09",
    "state": "Test125 本轮：3项通过 · 1项部分通过 · 0项未通过 · 36项未覆盖",
    "short_summary": "驻留前置条件拒绝；原生UDP未发出",
    "summary": "本轮只确认Test125加载、原生接口及本次诊断前后状态。频道许可发布记录为旧代，内核在驻留前返回EOPNOTSUPP；没有UDP发送、数据回包或AirDrop证据。Test124的单包返回保留在开发时间线，不计入Test125本轮；未覆盖不代表能力回退。",
    "evidence": [
      "25G416-Test125身份核对通过；awdl0已绑定并运行。",
      "驻留START之前，EOPNOTSUPP；native_udp_attempted=false，未测到END/TX_RSP修补。",
      "驱动当前代次5，发布source/response/applied代次3。已定位周期发布不在主gate而直接返回；内部同代许可是否完整仍待核实。",
      "路由器恢复exit 0，四项配置哈希不变，监控接口和临时guard已清；驱动复位计数保持5。",
      "Test124曾有同awdl0 socket匹配返回，但固件完成与清理未闭环。本轮未重复该通路，不宣称能力回退。",
      "周期发布改走非阻塞main gate，沿用生命周期锁；保留真实响应代次和现有发射门禁。离线回归与主配置编译通过。",
      "联网冒烟和睡眠继续跳过；本轮未进行AirDrop文件传输。"
    ],
    "blockers": [
      "MCC发布记录落后当前驱动代次。",
      "Test125发送完成等待修补尚未获得实机验证。",
      "真实原生收发、持续调度和AirDrop未闭环。"
    ],
    "next": [
      "先修正MCC快照发布并核清当前代真实许可。修补仅离线验证，未部署；本轮不再重复ARM，也不需要立即重启。"
    ]
  }
];
