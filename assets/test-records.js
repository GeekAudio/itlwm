window.TEST_RECORDS = [
  {
    "id": "record-test077",
    "version": "25G332-Test077",
    "label": "本轮验证记录",
    "state": "Test077 本轮 6/40 项通过（15%），7 项部分验证；7条控制事件唯一匹配，数据回包未证实。",
    "tone": "working",
    "date": "2026-10-29",
    "summary": "Test077 新启动实测：诊断前后各约125秒 Wi-Fi观察均保持en1关联、UP/RUNNING与IPv4，复位5→5，无新增watchdog、固件或硬件错误；默认路由为en0，未验证en1公网请求。OpenWrt 20秒捕获2218包，含155条Action和151条Apple vendor Action。7条驱动控制RX事件按序列控制字段和MPDU长度唯一匹配，含6条PSF-like subtype 0及1条已接纳AWDL subtype 3/MIF；peer count=1且运行时MIF绑定有效。没有payload或源/目的地址关联，窗口重叠未证明，监听只覆盖channel 6。当前Qm TX无PCAP数据帧精确匹配，数据RX捕获、解码、交付均为0。current-AW trace不完整；coordinator汇总输出异常，单次额度已消耗。无对端数据回包或AirDrop收件证明。",
    "evidence": [
      "Wi-Fi：诊断前 125.134 秒、后 125.233 秒被动观察均保持 en1 关联、UP/RUNNING 与 IPv4；复位 5→5，无新增 watchdog、固件或硬件错误。默认路由为 en0，本轮没有验证 en1 公网请求或吞吐。",
      "发送：原生 Qm 查询在驱动 TX trace 中有当前 token 绑定，编码、提交、完成、成功各 1；固件未回显完整身份，不能据此证明空口或对端收到。",
      "监听与归因：OpenWrt 20秒捕获2218包，155条Action、151条Apple vendor Action；7条驱动控制RX事件按sequence control和MPDU长度唯一匹配。接收窗口与browse时序重叠未证明，且监听只覆盖channel 6。",
      "控制接收：6条PSF-like subtype 0事件、1条被接纳的AWDL subtype 3/MIF事件唯一匹配；peer count=1、PSF revision=2、MIF revision=1，运行时MIF绑定有效。没有payload/地址关联，不证明指定iPhone身份。",
      "数据通路：当前Qm查询有驱动编码、提交、完成、成功各1，但PCAP无按帧控制/序列/长度精确匹配的数据帧；数据RX捕获、解码和交付均为0。",
      "诊断器：数据记录已落盘，但最终汇总打印因参数错误退出；coordinator complete=false。单次启动 claim 已消耗，不允许重试。",
      "AirDrop：没有对端数据回包、Bonjour 服务应答、双向文件收件或文件哈希校验。"
    ],
    "blockers": [
      "两段约 125 秒的被动 Wi-Fi 观察稳定；仍需较长时间运行、睡眠恢复、开关回连、私有地址轮换，以及绑定 en1 的公网请求验证。",
      "控制帧归因已完成；仍需在覆盖相应频道和窗口的独立观察中关联Qm数据帧、发送/接收时序与对端来源。",
      "修复收集器汇总输出参数；补齐当前 AW trace 发布字段，再在新启动准备下一轮。",
      "AWDL RX控制事件已确认，但数据RX捕获、解码、ifnet交付均为0；需继续核对数据帧 descriptor、过滤和输入路径。",
      "仍需证明 Bonjour 对端服务应答及双向 AirDrop 文件完整性。"
    ],
    "next": [
      "修复current-AW trace与诊断汇总输出；再按受控的完整频道/窗口证据闭环Qm数据回包、原生ifnet与AirDrop。"
    ]
  }
];
