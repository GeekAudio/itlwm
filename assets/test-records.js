window.TEST_RECORDS = [
  {
    "id": "record-test122-runtime-boot1793681053",
    "version": "25G332-Test122",
    "label": "Test122：Wi-Fi已恢复；受控RX工具离线核验通过，真实AWDL数据未验证。",
    "tone": "warning",
    "date": "2026-11-03",
    "state": "Test122本轮：3项通过 · 5项部分通过 · 0项未通过 · 32项未覆盖",
    "short_summary": "Wi-Fi已恢复；RX工具离线通过，实机数据待测",
    "summary": "Test122已启动，Wi-Fi保持On/Ready并在手动切网后恢复；联网冒烟按用户要求跳过。受控AWDL RX工具11项离线核验通过，Test122/awdl0及149频道目标身份已核对；本轮尚未启动RF，真实AWDL数据接收、ifnet回包和AirDrop未验证。",
    "evidence": [
      "Test122加载身份、Wi-Fi On/Ready及手动切网后恢复已核对。",
      "联网冒烟按用户要求跳过；长时稳定观察和睡眠恢复本轮未覆盖。",
      "受控RX工具11项离线核验通过，其中10项初轮通过，修正测试路径断言后定向项目通过。",
      "Test122 metadata/UUID、awdl0与149频道目标身份已核对；本轮没有启动RF。",
      "离线工具和身份核对不证明真实RX、原生ifnet回包或AirDrop成功。"
    ],
    "blockers": [
      "真实AWDL数据接收、原生ifnet回包和AirDrop尚未实测。",
      "本轮没有RF诊断；离线工具核验不计入40项功能验收。"
    ],
    "next": [
      "执行绑定Test122的149频道有界接收诊断，确认真实RX是否到达驱动和原生ifnet。",
      "依据真实接收证据再推进数据回包和双向AirDrop验收。"
    ]
  }
];
