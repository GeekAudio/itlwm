# Test086 开发工具

本目录收录 Test086 的 RX-only helper、采集器、OpenWrt coordinator、必要依赖和离线 mock 测试。这里不包含 kext、固件、构建产物、EFI、私有构建或部署元数据、现场回执、日志或抓包；来源和 SHA-256 见 `SOURCE-MANIFEST.json`。

从本目录运行离线 mock：

```sh
python3 -m unittest discover -s tools -p 'test_*test086*.py'
python3 -m unittest discover -s tests -p 'test086_rx_entry_guard.py'
```

私有 metadata generator 依赖的断言未放入公开快照；RX-entry guard 仅移除了 generator 导入和 metadata-only 断言，运行时 RX 检查均保留。

这些源码和离线 mock 不证明驱动已加载、空口收到数据、ifnet 输入被上层消费、对端已收到数据或 AirDrop 成功。Test086 的实机状态需以独立运行时证据为准。

离线复核已保存的 Test086 报告（不会读取现场设备或覆盖原始文件）：

```sh
python3 tools/review_test086_saved_window.py --native-report <saved-native.json> --coordinator-report <saved-coordinator.json> --output <new-review.json>
python3 -m unittest discover -s tools -p 'test_review_test086_saved_window.py'
```

复核只对显式列入白名单的 RX trace U32 字段应用严格有界的负数解码；未发布的接收回执仍记为未知，不会提升数据验收。
