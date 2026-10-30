# Test084 开发工具

本目录是 Test084 的工具源码快照，包含频道 149 接收观察器、OpenWrt 协调器、运行依赖和离线 mock 测试。不包含 kext、固件、私有构建或部署回执、现场日志、PCAP 或 EFI 配置。

运行 31 项离线测试：

```sh
python3 -m unittest discover -s tools -p 'test_test084_receive149_once.py'
python3 -m unittest discover -s tools -p 'test_run_test084_router_observation_once.py'
python3 -m unittest discover -s tests -p 'test084_rx_entry_guard.py'
```

前两组分别覆盖采集器（22 项）和协调器（6 项）；第三组包含 3 项 RX trace/RXEntry mock。公开测试只验证工具对稳定快照、DISCOV 配置 2 和输入缺失/无效情况的处理。私有元数据生成器测试未复制到公开快照。

对应 Test084 驱动通过离线构建、签名校验和 394 个生产输入的源码冻结。离线产物标识见 `SOURCE-MANIFEST.json`。该 kext 尚未加载或实机验证；RXEntry 观测窗口完整不代表接收到帧，也不证明对端收件或 AirDrop 成功。
