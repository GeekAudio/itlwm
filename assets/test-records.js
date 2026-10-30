window.TEST_RECORDS = [
  {
    "id": "record-test092-runtime-boot1793402509",
    "version": "25G332-Test092",
    "label": "Test092本轮实测",
    "tone": "warning",
    "date": "2026-10-31",
    "state": "Test092本轮40项：通过4、部分2、未覆盖34、未通过0；历史覆盖单独保留。",
    "summary": "en1联网和5分钟观察通过；Wi-Fi关闭等待、开机状态闪动和扫描慢尚未解决。",
    "evidence": [
      "Test092加载身份匹配；en1保持UP/RUNNING、active并有IPv4。",
      "300.085秒/60样本被动观察期间reset、stop和watchdog计数不变。绑定en1的网关HTTP与两次Apple HTTPS请求均返回200；HTTPS固定目标IP，DNS未测。",
      "一次关闭请求总耗时14.035秒，超时记录约12.029秒；Apple80211SetPower关机调用约0.030秒。开机请求总耗时0.636秒。关闭前的等待还需沿disassociate/leave阶段定位。",
      "用户报告关闭Wi-Fi时状态栏响应慢、开启期间短暂关开、已知网络连接快而扫描列表出现慢。15条AutoJoin扫描结果耗时0.019–6.412秒、中位2.057秒；3次Code 37回退旧缓存。系统列表刷新尚未与WCL generation逐项关联。",
      "awdl0本地UP/RUNNING与链路本地IPv6通过；本轮没有接收诊断、数据包交付或AirDrop测试。"
    ],
    "blockers": [
      "Wi-Fi关机前置等待、状态闪动和扫描列表延迟仍待修复；当前没有证据把14秒等待归因于驱动关机重试。",
      "RX149 profile已启用，但安全恢复路径、对端无线包、原生awdl0数据交付和AirDrop均未在本轮验证。"
    ],
    "next": [
      "定位disassociate/leave阶段的关机前置等待及内部私有地址更新引发的电源状态通知；不能关闭私有地址。",
      "增加按WCL generation汇总的扫描请求、HAL接纳、首末Beacon和终态计时，并关联系统列表刷新请求。",
      "下一候选版本尚未指定。"
    ]
  }
];
