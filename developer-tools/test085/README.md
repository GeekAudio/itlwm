# Test085 开发工具

本目录用于发布 Test085 的 helper、collector、coordinator、必要运行依赖和离线 mock 测试源码。快照不包含 kext、固件、私有构建或部署元数据、现场回执、PCAP/PCAPNG、EFI 内容或设备标识；文件来源和 SHA-256 记录在 `SOURCE-MANIFEST.json`。

从公开副本运行离线 mock：

```sh
python3 -m unittest discover -s tools -p 'test_*test085*.py'
python3 -m unittest discover -s tests -p 'test085_rx_entry_guard.py'
```

私有 metadata generator 专用测试未纳入快照；RX-entry guard 只移除了未使用的 generator import，保留全部运行时断言。

源码快照和 mock 测试不证明驱动已加载、发生过空口收发、对端已收到数据或 AirDrop 成功。Test085 的实机状态以单独的 runtime 验证为准。
