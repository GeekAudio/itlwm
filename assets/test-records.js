window.TEST_RECORDS = [
  {
    "id": "record-test096-runtime-boot1793443560",
    "version": "25G332-Test096",
    "label": "Test096本轮实测",
    "tone": "warning",
    "date": "2026-10-31",
    "state": "Test096本轮40项：通过6、部分6、未通过1、阻塞16、未测试11",
    "summary": "普通Wi-Fi受控恢复后，en1 gateway/DNS/TLS通过。明确失败：same-boot reason16关联丢失及W6睡醒错误，后续恢复不清除此结论。149 RX未观测到目标数据MPDU；ROC内只有SessionProtection END控制通知。",
    "evidence": [
      "普通Wi-Fi受控恢复与联网检查通过。",
      "whole-boot稳定性与W6睡醒本轮未通过；386.956秒短窗不计为长稳通过。",
      "149 RX未观测到目标数据MPDU；host AWDL TX关闭，peer/ifnet/AirDrop未证实。"
    ],
    "blockers": [
      "Wi-Fi稳定性失败待处理。",
      "RX数据到ifnet及peer证据未覆盖。",
      "host TX配置关闭，发送与AirDrop项目受阻。"
    ],
    "next": [
      "按8阶段依赖继续记录；保留未覆盖和阻塞状态。"
    ]
  }
];
