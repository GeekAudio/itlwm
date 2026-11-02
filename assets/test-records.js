window.TEST_RECORDS = [
  {
    "id": "record-test120-runtime-1793646250",
    "version": "25G332-Test120",
    "label": "Test120：Wi-Fi链路与局域网短窗正常；公网请求两接口均超时；149频道窗口未见AWDL数据候选，AirDrop未证明。",
    "tone": "warning",
    "date": "2026-11-03",
    "state": "Test120本轮：5项通过 · 5项部分通过 · 0项未通过 · 30项未覆盖",
    "short_summary": "Test120实测保留；Test121已部署待重启",
    "summary": "Test120加载身份已核对。5分钟Wi-Fi被动窗口和2分钟接收后重叠观察中，en1链路/IP与复位、固件错误、watchdog计数稳定；本地网关可达，但公网HTTPS在en0与en1均超时。149频道接收START/END正常，owner-qualified观察中AWDL数据候选为0、监听器为0；没有ifnet输入、对端收包或AirDrop证据。切网时Wi-Fi关闭/重开表现仍未解释。",
    "evidence": [
      "Test120身份和en1接口已核对。5分钟观察中链路、IP及计数稳定，en1可达本地网关；公网HTTPS在en0/en1均超时。切网关闭/重开表现仍未解释。",
      "Test120的149频道有界窗口START/END均正常，终态State7。硬件/主机时钟映射与连续多频道调度未测试。",
      "本轮覆盖了149频道接收观察入口，但没有AWDL数据候选、应用监听器数据报或ifnet交付。",
      "原生awdl0常驻已确认；本轮未证明驱动发送队列或无线包交付原生ifnet。",
      "awdl0的RUNNING及IPv6链路本地地址已确认；邻居可达、UDP输出接纳和Bonjour应答未覆盖。"
    ],
    "blockers": [
      "切网开关闪动根因未闭合。",
      "149频道窗口无数据候选，实际无线发射和回包待证。",
      "SAE/PMF、即时热点与双向AirDrop未完成实机验收。"
    ],
    "next": [
      "先验证普通联网、A→B→A切换与定向扫描，再按实际频道条件采集149收包；睡眠继续跳过。新兼容代码和界面状态记录均待实机验证。",
      "Test121已写入内置EFI，等待重启；当前仍运行Test120。"
    ]
  }
];
