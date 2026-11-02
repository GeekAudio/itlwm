window.TEST_RECORDS = [
  {
    "id": "record-test120-runtime-1793646250",
    "version": "25G332-Test120",
    "label": "Test120：接收窗口正常收尾；本轮未收到受控数据，切网显示仍待修复。",
    "tone": "warning",
    "date": "2026-11-03",
    "state": "Test120本轮：5项通过 · 5项部分通过 · 0项未通过 · 30项未覆盖",
    "short_summary": "正常释放已验证；同频道接收无数据候选，需继续对照",
    "summary": "Test120加载身份已核对。5分钟Wi-Fi被动窗口和约2分钟联合观察中链路/IP及故障计数稳定；本地网关可达，但两接口对两个公网HTTPS地址均超时。149频道START/END正常、资源已释放，应用监听器未收到数据。切网时关闭再开启的表现仍未解释。",
    "evidence": [
      "Test120加载身份已核对；en1与awdl0存在，awdl0有IPv6链路本地地址。",
      "5分钟局域链路观察与约2分钟联合观察中链路/IP保持、故障计数无增量；不能判定公网联网通过。",
      "149频道START/END正常；State7、Exercise0、Remove0、ResourceMayExist0。新增失败END清理分支未触发。",
      "入口有99条MPDU观察，owner-qualified38条，AWDL数据候选0；captured/decoded/delivered均0，应用监听器0数据报。",
      "路由器4次本地write完成；监听记录容量8、溢出29，实际空口发送与ACK未证明。"
    ],
    "blockers": [
      "用户报告切网出现关闭再开启；样本中请求电源保持On，根因尚未确定。",
      "Test120 STA与接收都在149；历史Test119 STA36/ROC149曾收到受控UDP。包与地址相同，但频道差异尚不构成因果证明。",
      "原生发送、iPhone数据回包与双向AirDrop尚未完成。"
    ],
    "next": [
      "优先用相同数据包做STA/ROC同频道与异频道有界对照，并验证路由器实际空口发射。",
      "下一候选暂未排定；睡眠继续跳过，WAN/LAN配置保持不变。"
    ]
  }
];
