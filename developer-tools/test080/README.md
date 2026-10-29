# Test080 RX149 采集工具源码快照

此目录保存 Test080 单次、接收观察用工具及其本地 Python 依赖。默认运行协调器只显示计划，不启动采集；采集器没有 `--arm` 时会退出，不读取系统状态、不占用启动次数。真实采集需要原本授权的 macOS、AirportItlwm、OpenWrt 管理环境和匹配的私有构建元数据；元数据、密钥、二进制、日志和抓包未包含在这里。此快照不是即插即用的公开驱动包，也不承诺在其它设备上可运行。

离线 mock 测试：

```sh
python3 -m unittest tools.test_test080_receive149_once tools.test_run_test080_router_observation_once -v
```

`NativeP2PPeer*` 的合成 MAC 字符串只用于测试脱敏，不是现场数据；`198.18.0.0/15` 是依赖代码中的 RFC 2544 特殊用途地址段。来源与副本逐文件 SHA-256 见 `SOURCE-MANIFEST.json`。
