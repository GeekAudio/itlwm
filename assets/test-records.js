window.TEST_RECORDS = [
  {
    "id": "record-test095-runtime-boot1793422729",
    "version": "25G332-Test095",
    "label": "Test095本轮复验",
    "tone": "warning",
    "date": "2026-10-31",
    "state": "Test095本轮40项：通过6、部分3、未覆盖30、本轮未通过1。",
    "summary": "首段无人操作观察出现链路/IP短断；开关后独立窗口及en1联网检查通过，但不覆盖前述断链。ROC开始/结束验收通过；149频道仅收到一个非AWDL Beacon管理帧，没有AWDL数据，原生ifnet回包与AirDrop未证实。",
    "evidence": [
      "首段305.042秒/61样本期间出现无人操作链路/IP中断，Requested/Ready保持开启，复位、watchdog和固件错误计数没有增加。 后续第二次reason16与首次相隔3600.14秒，GTK key ID变化；Group2实际发送完成仍未知。",
      "开关后独立304.969秒/61样本窗口与RX后60.971秒/13样本观察稳定；前者窗口内网关、DNS、TLS检查通过。各窗口分开统计，不合并为连续稳定。",
      "同一owner/代次ROC驻留95.162ms。149频道一个管理Beacon不是AWDL数据；late-read为315/315数字copy但末16项在ROC END后，不能关联窗口内MPDU。原3秒collector仍unknown。",
      "Test096已完成Group2 1024槽位跟踪、电源停止并发保护与ROC接收关联的合并构建和独立复核，备份后部署。当前仍运行Test095，Test096尚未实机验收。"
    ],
    "blockers": [
      "修复Wi-Fi无人操作短断；内部两次地址重启，尚不能确认界面全过程无回跳；补长期运行和睡眠恢复验证。",
      "接通ROC窗口内completion-to-MPDU同次关联；不能使用END之后的16条晚读样本切换生产索引。",
      "原生awdl0数据交付、对端回包及双向AirDrop没有本轮通过证据。"
    ],
    "next": [
      "重启验收Test096；按40项清单记录结果与阻塞，长稳覆盖至少65分钟及小时GTK周期，开关、睡醒、即时热点独立验证；同一次有界ROC并行采集RX、ifnet和手机日志。"
    ]
  }
];
