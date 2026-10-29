window.TEST_RECORDS = [
  {
    "id": "record-test072",
    "version": "25G332-Test072",
    "label": "本轮验证记录",
    "state": "Wi-Fi稳定性回退；awdl0运行但数据路径未测",
    "tone": "warning",
    "date": "2026-10-29",
    "summary": "Test072加载身份已核对；en1快照时仍关联，awdl0为up/running并有IPv6链路本地地址。watchdog从2增至4、复位从13增至25，稍后seq5/reset30继续增加，用户确认未手动操作。DataTx trace为空，累计Accepted计数不能证明本轮发送；本轮没有RF、browse、claim、对端回包或AirDrop验证。",
    "evidence": [
      "本启动已核对Test072加载UUID；Wi-Fi快照时en1仍关联并具有IPv4。",
      "用户确认没有手动切换网络或让电脑睡眠；watchdog和reset计数随后增加，Wi-Fi稳定性本轮回退。",
      "原生awdl0处于up/running且有IPv6链路本地地址；不代表对端可达或数据已交付。",
      "Test072 DataTx trace预检为空；旧的累计Accepted计数没有本轮票据，不能当成成功发送。",
      "本轮未运行RF、native browse或boot claim；Test071历史peer帧不计入当前40项。",
      "独立源码发现普通Tahoe TX_RSP路径被跳过、generic fallback未执行；Test073修复已部署，等待重启验证。"
    ],
    "blockers": [
      "同一启动出现新的TX watchdog与reset增长，尚未证明普通Wi-Fi稳定。",
      "本轮没有同包发送票据、对端数据回包或原生ifnet收包证据。",
      "普通Tahoe TX_RSP回报分支存在源码阻碍；Test073已部署，等待重启验证。",
      "本轮没有AirDrop文件收件证据。"
    ],
    "next": [
      "重启进入Test073，先验证普通TX回报、回收与Wi-Fi稳定性；无新增watchdog/reset后，再执行新启动唯一一次AWDL收发诊断。",
      "本轮通过率只含Test072实测，不计Test073离线或部署结果。"
    ]
  }
];
