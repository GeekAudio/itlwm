window.TEST_RECORDS = [
  {
    "id": "record-test071",
    "version": "25G332-Test071",
    "label": "本轮验证记录",
    "state": "本机QM获空口支持；查询对应窗口回包待证",
    "tone": "working",
    "date": "2026-10-29",
    "summary": "Test071前后各约124秒Wi-Fi观察保持关联，复位和固件错误未增加。驱动记录8个PSF、1个同源MIF，MIF在900ms窗口中段解析并入表；PCAP中的本机AirDrop目标QM查询由有效校验和、目标PTR及驱动计数交叉支持，但无精确DataTx票据关联。本轮未建立与该查询对应的窗口内数据回包或Bonjour应答；PCAP覆盖不完整，不能判定对端未响应。Mac侧数据RX/ifnet交付和AirDrop传输仍待证。 后续同一启动在开发期出现一次发送watchdog与Wi-Fi自行断开，已纳入Test072排查；没有据此擅自延长超时或更改队列回收策略。 Test072已部署并保留整份EFI备份，当前仍运行Test071；Test072等待重启验收，尚未新增实测通过项。",
    "evidence": [
      "Test071此前两段约124秒短测通过；后续开发期被动观察在47.726秒停止，Wi-Fi自行断开，复位计数5→6并新增一次发送watchdog。用户确认未切换网络或睡眠。具体队列/回报/flush计时原因尚未证明，不能将短测通过外推长期稳定。",
      "驱动RX trace记录8个PSF和1个同源MIF；MIF在900ms驻留中段解析、解码并成功入表。",
      "本机address_advertisement记录PSF与MIF各自候选、advertised、submitted、completed、succeeded各1；PSF严格匹配PCAP 1/1，MIF匹配0/1。",
      "PCAP中的本机AirDrop目标QM查询校验和有效，驱动计数为1/1/1/1；未建立精确DataTx票据和查询对应的窗口内回包关联。",
      "PCAP覆盖不完整，缺少关联回包不能判定对端未响应；Mac侧AWDL数据RX、解码和ifnet交付及文件传输仍未证。"
    ],
    "blockers": [
      "后续开发期出现一次发送watchdog和Wi-Fi自行断开，用户确认没有手动网络或睡眠操作；尚无具体队列或恢复根因。",
      "尚未建立与本轮QM查询对应的窗口内AWDL数据回包或Bonjour应答；PCAP覆盖不完整，不能判定对端未响应。",
      "Bonjour浏览约3.1秒后提前结束，20秒窗口未完成；此零回调不代表完整窗口无响应。",
      "本轮没有AirDrop文件收件；设备可见和控制/查询帧成功不等于文件传输。"
    ],
    "next": [
      "Test072已部署待重启；重启后先核对加载身份、Wi-Fi与awdl0。",
      "本轮只记录新启动的真实证据；离线构建和部署不计入17/40实测通过率。"
    ]
  }
];
