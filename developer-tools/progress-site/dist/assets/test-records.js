window.TEST_RECORDS = [
{
  "id": "record-test122-runtime-boot1793681053",
  "version": "25G332-Test122",
  "label": "Test122：149频道接收窗口正常收尾；尚无完整 AWDL Data 帧进入接收观测。",
  "tone": "warning",
  "date": "2026-11-03",
  "state": "Test122本轮：5项通过 · 5项部分通过 · 0项未通过 · 30项未覆盖",
  "short_summary": "窗口正常收尾；首个缺失层在完整数据帧进入接收观测之前",
  "summary": "Test122受控149频道接收窗口已完成：START/END均观测并被接受，最终State 7/released。Intel侧见2条Beacon，没有AWDL candidate或完整Data帧；native listener/capture/decode/ifnet均无可关联数据。OpenWrt tap记录4条outgoing，但没有RF TXS/ACK证明。当前断点在完整Data帧到达接收观测之前，filter-match不可用，不能归因于Intel过滤或BSD拒绝。Wi-Fi保持On/Ready，用户手动切网后恢复；联网冒烟按要求跳过。",
  "evidence": [
    "受控149频道窗口的START/END均观测并被接受，最终State 7/released；清理正常。",
    "Intel侧观察到2条Beacon；没有AWDL candidate或完整Data帧，filter-match不可用。",
    "4次本地发送调用显示完成；OpenWrt tap记录4条outgoing，无RF TXS/ACK证明。",
    "native listener、capture、decode、ifnet均无可关联数据；不能据此归因驱动过滤或BSD输入拒绝。",
    "Wi-Fi仍为On/Ready，手动切网后恢复；联网冒烟按用户要求跳过。",
    "本轮12项离线工具验证通过；这是工具检查，不计入40项实机功能验收。"
  ],
  "blockers": [
    "完整AWDL Data帧尚未进入接收观测；具体缺失原因未定位。",
    "没有RF TXS/ACK或对端接收证明；原生回包和AirDrop未验证。"
  ],
  "next": [
    "核对同一帧从本地发送到Intel接收观测入口的证据，先确认完整Data帧到达。",
    "帧到达后再分别检查过滤、解码、原生ifnet交付和对端应答。"
  ]
}
];
