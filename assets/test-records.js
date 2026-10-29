window.TEST_RECORDS = [
  {
    "id": "record-test073",
    "version": "25G332-Test073",
    "label": "本轮验证记录",
    "state": "Wi-Fi短测稳定；原生awdl0常驻未通过",
    "tone": "warning",
    "date": "2026-10-29",
    "summary": "Test073加载身份已核对。en1在125.196秒观察期间保持关联并有IPv4，reset保持5，watchdog、固件和硬件错误计数没有新增。HTTP 200使用en0默认路由，不能作为Wi-Fi公网验收。 生命周期记录见到一次注册、启动、BSD出现和停止释放；本次最终awdl0不存在，DataAttached=0、Closing=1、LinkReady=0，后续NotReady，常驻与IPv6未建立。本轮未运行RF、browse或boot claim；数据发送trace仅为完整空预检，没有发送或AirDrop证明。",
    "evidence": [
      "Test073加载身份已核对；en1在125.196秒观察期间保持关联并有IPv4。",
      "reset保持5；watchdog、固件和硬件错误计数没有新增。",
      "HTTP 200经en0默认路由返回，不计为Wi-Fi专属公网请求。",
      "生命周期flags见到临时注册、启动、BSD出现、停止和释放；常驻阶段NotReady。",
      "当前awdl0未枚举，DataAttached=0、Closing=1、LinkReady=0。",
      "本轮未运行RF、browse或boot claim；完整空DataTx预检不是发送证据。"
    ],
    "blockers": [
      "当前没有常驻awdl0或其IPv6链路本地地址。",
      "本轮没有AWDL对端数据回包、Bonjour应答或AirDrop文件收件证据。",
      "默认系统HTTPS请求走en0，尚未证明Wi-Fi接口自身的公网连通性。"
    ],
    "next": [
      "重启进入Test074，先核对数据桥挂接阶段和原始结果、awdl0常驻及Wi-Fi基线；前置条件通过后，再执行新启动唯一一次AWDL收发诊断。",
      "本轮通过率只含Test073实测，不计Test074离线或部署结果。"
    ]
  }
];
