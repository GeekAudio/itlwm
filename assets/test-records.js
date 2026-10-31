window.TEST_RECORDS = [
  {
    "id": "record-test093-runtime-boot1793407011",
    "version": "25G332-Test093",
    "label": "Test093本轮复验",
    "tone": "warning",
    "date": "2026-10-31",
    "state": "Test093本轮40项：通过6、部分2、未覆盖31、回退1。",
    "summary": "Test093 boot 1793407011：当前验收6通过、2部分、31未覆盖、1回退；以当前启动直接证据为准。",
    "evidence": [
      "本轮40项：6通过、2部分、31未覆盖、1回退。Test093确认149频道ROC START/END及安全回收；Wi-Fi基线通过，但后续出现真实watchdog和无人操作时链路丢失。AWDL数据回包与AirDrop仍无通过证据。"
    ],
    "blockers": [
      "开启Wi-Fi后出现重复重启和一次真实发送watchdog；09:04还发生一次用户未操作的链路丢失。",
      "149频道驻留与管理Beacon已验证，但原生AWDL数据输入、UDP回包及AirDrop传输仍未通过。"
    ],
    "next": [
      "Test094已备份部署；可以重启后核对加载身份、Wi-Fi开关与持续运行，再验证149数据接收和awdl0交付。当前记录仍是Test093实测。"
    ]
  }
];
