window.TEST_RECORDS = [
  {
    "id": "record-test123-test122-kernel-runtime",
    "version": "25G332-Test122",
    "label": "Test123：离线记录复核通过；现场终态仍待修正",
    "tone": "warning",
    "date": "2026-11-03",
    "state": "Test122本轮：5项通过 · 5项部分通过 · 0项未通过 · 30项未覆盖",
    "short_summary": "同一发送记录离线校验通过；现场汇总仍未验证，不代表RF发送",
    "summary": "Test123工具启动握手修复后，本启动执行149频道有界采集窗口；同owner START/END有效，边界约94.996 ms。接收窗口有24条149入口，其中12条有效FC分类控制帧、12条short MPDU；Data、QoS、AWDL-BSSID候选为0，24条filter-match结果均不可用。不能据此说被过滤或归因RF/过滤/bridge。同一原始发送记录与对应的536B帧集合离线重放校验通过，但现场汇总仍标记未验证；parser绑定错位只是待查可能，根因未确认。该复核不证明实际空口发送。awdl0 listener收到0个载荷。三次post生命周期State10/exercise_failed_cleaned且已清理；旧State7-only门禁漏识别失败终态并折叠为unknown。不能归因Intel接收；AirDrop未验证，Test122内核未改，未写EFI。",
    "evidence": [
      "本轮同一启动观察到有效149频道START与END；START剩余约98.734 ms、GO时约95.179 ms，START→END同owner边界约94.996 ms。此项只证明有界窗口起止。",
      "有效接收窗口有24条149频道入口记录：12条有效FC分类控制帧、12条short MPDU；Data、QoS、AWDL-BSSID候选均为0，24条filter-match结果均不可用。不能说帧已被过滤，也不能归因RF、过滤或bridge。",
      "同一原始发送记录与对应的536B帧集合在当前Test123校验器下独立离线重放通过；现场汇总仍报告sender_record_unvalidated。parser绑定错位仅为待查可能，根因未证实；此项不证明实际RF发送。radiotap_unsupported124不是本次校验不一致的原因。",
      "awdl0 listener已就绪但收到0个datagram；未取得原生载荷回包、ifnet交付或对端收件证据。",
      "三次post生命周期均为State10/exercise_failed_cleaned，EndSeen=1、ResourceMayExist=0、RemoveResult=0、RecoveryAttempted=1且清理完成；旧T087 State7-only门禁漏识别State10失败终态。",
      "采集后只读快照显示en1 active/IPv4、awdl0 active/IPv6LL；这不是联网冒烟或长期稳定性验收。",
      "Test123启动握手已修复，77项离线验证通过；手机侧诊断日志采集完成；本轮未做AirDrop文件传输。Test122内核未改、未写EFI；联网冒烟和睡眠按要求跳过。"
    ],
    "blockers": [
      "有效接收窗口未见Data或AWDL-BSSID候选；filter-match不可用，不能据此认定过滤或归因RF/bridge。",
      "同一原始sender记录离线重放通过，但现场汇总仍未验证；parser绑定错位尚未证实，State10失败终态被旧State7-only门禁漏报。",
      "awdl0载荷回包、对端收件与双向AirDrop仍未验证。"
    ],
    "next": [
      "离线修正/复核现场parser绑定与State10终态映射；parser绑定错位仍待证实。",
      "本轮不在当前启动重试；按首缺层安排后续AWDL接收验证。"
    ]
  }
];
