window.TEST_RECORDS = [
  {
    "id": "record-test094-runtime-boot1793419191",
    "version": "25G332-Test094",
    "label": "Test094本轮复验",
    "tone": "warning",
    "date": "2026-10-31",
    "state": "Test094本轮40项：通过4、部分3、未覆盖33、回退0。",
    "summary": "Test094 boot 1793419191：Wi-Fi基线、绑定en1网关与公网HTTPS通过；地址更新后仍有READY短降。",
    "evidence": [
      "309.731秒/61样本中en1持续UP/RUNNING、链路active且有IPv4，所选故障计数无增量。绑定en1的网关探测5/5通过，TLS HTTPS返回200。",
      "OFF约66ms完成并保持关闭20秒；ON约622ms完成，系统最终恢复连接和扫描。ON后地址更新触发两次重启，READY状态短暂下降。本轮没有执行AWDL收发或AirDrop测试。"
    ],
    "blockers": [
      "地址更新后的READY短降和扫描时延仍待定位；睡眠恢复本轮未测。12:04:20是否仍处于手动开关过程不确定，不归类为无人操作掉线。",
      "本轮未进行149频道、AWDL数据收发或AirDrop诊断。"
    ],
    "next": [
      "Test095的Group2序号修复已推送b3b721d；有界电源通知改动仍在合并，尚未构建或部署。"
    ]
  }
];
