window.TEST_RECORDS = [
  {
    "id": "record-test078",
    "version": "25G332-Test078",
    "label": "本轮验证记录",
    "tone": "working",
    "date": "2026-10-29",
    "state": "Test078：7/40 项通过（17.5%），7 项部分验证，26 项未覆盖；历史完整验收净新增 0。",
    "summary": "Test078 已在本机启动，Wi-Fi 在诊断前后两段约124秒观察中保持关联，复位计数未变，未新增watchdog或固件错误；未测试Wi-Fi公网或睡眠恢复。原生awdl0保持运行，2条真实内核输出进入软件队列。本轮进入仅发MIF的bootstrap路径，数据查询未提交。驱动收到并解析1条MIF和4条PSF，但没有AWDL数据回包或AirDrop收件证明。",
    "evidence": [
      "加载与接口：Test078构建身份匹配；en1保持关联和地址，awdl0保持UP/RUNNING及IPv6链路本地配置。",
      "Wi-Fi：诊断前124.474秒、后124.604秒观察通过，复位计数5→5，未新增watchdog或固件/硬件错误。默认路由走有线，不能据此宣称Wi-Fi公网正常。",
      "P2P控制：本轮MAC上下文ADD/REMOVE命令完成；广播station与独立queue身份未单独验收。",
      "控制帧：PSF和MIF各报告一次本机固件发送成功；接收trace解析并接纳1条MIF、4条PSF。控制帧不代替对端数据收件。",
      "数据发送：软件队列接纳2条内核输出；bootstrap分支拦住数据提交，所有查询分类的发送尝试和QM提交均为0。",
      "数据接收：23条完整v3 descriptor，21条管理帧、2条MPDU过短；Data和AWDL数据候选均为0。OpenWrt频道6约20秒采集1392包，未见AWDL Data候选；不证明其他频道或对端未发射。",
      "诊断器：本轮最终汇总正常完成，路由器monitor已清理且AP配置未改变。CurrentAW保留收尾时未排空标记，后续RX trace已排空；两者是不同时间的记录。",
      "AirDrop：没有原生ifnet真实无线输入、对端服务应答或双向文件收件证明。"
    ],
    "blockers": [
      "仅发MIF的引导阶段没有转入正常配对数据阶段。",
      "本机MIF完成时，旧对端MIF已超过代码允许的时效上界约9.6毫秒；后续PSF不能单独授权旧MIF。",
      "CurrentAW最终快照没有反映后来完成的RX排空；需修复发布时序。"
    ],
    "next": [
      "取得新鲜、同源的MIF/PSF配对并走完整时序与最终提交检查；同时独立刺激RX，沿descriptor、候选、decode和ifnet定位。",
      "原始日志与PCAP保留在本机；继续分别验证Wi-Fi公网、长时间运行和睡眠恢复。"
    ]
  }
];
