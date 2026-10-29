window.TEST_RECORDS = [
  {
    "id": "record-test074",
    "version": "25G332-Test074",
    "label": "本轮验证记录",
    "state": "awdl0挂接与IPv6点快照通过；Wi-Fi稳定性待测",
    "tone": "working",
    "date": "2026-10-29",
    "summary": "本次启动已核对Test074身份；en1单次快照显示已关联并有IPv4，awdl0已挂接、UP/RUNNING并有IPv6链路本地地址。本轮仅为只读点快照，Wi-Fi稳定性、公网请求、空口、对端回包和AirDrop均未测试。前一次Test074启动的54.285秒断链及后续watchdog/reset变化只记入开发时间线，不计入本轮结果。",
    "evidence": [
      "已核对Test074加载身份；系统当前识别en1无线接口，接口处于活动状态。",
      "单次快照显示en1已关联并有IPv4；未做120秒稳定性观察，也未验证经Wi-Fi的公网请求。",
      "当前原生awdl0已挂接并处于UP/RUNNING；挂接地址校验和最终就绪记录通过。",
      "当前awdl0自动处于RUNNING并有可用IPv6链路本地地址。",
      "本轮没有执行120秒观察、RF、browse、boot claim或AirDrop测试。"
    ],
    "blockers": [
      "单次关联/IP快照不能证明Wi-Fi持续稳定或经Wi-Fi公网可达。",
      "本轮没有AWDL空口收发、对端回包、Bonjour或AirDrop文件收件证明。",
      "本轮没有执行对象停止、最终释放或睡眠恢复测试。"
    ],
    "next": [
      "重启进入Test075后先做Wi-Fi稳定性观察，再确认awdl0挂接和自动IPv6；通过前置条件后再安排一次AWDL收发诊断。",
      "私有Wi-Fi地址、开关和睡眠恢复仍需分别验收。"
    ]
  }
];
