# Test083 开发工具

本目录包含 149 频道接收观察器、启动协调器、所需 Python 依赖和离线 mock 测试。这里仅有工具源码，不包含 kext、固件包、现场运行记录或私有构建资料。

运行全部离线测试：

```sh
python3 -m unittest discover -s tools -p 'test_*.py'
python3 -m unittest discover -s tests -p 'test083_rx_trace_guard.py'
```

第一组包含 28 项既有 mock 测试；第二组包含 3 项 Test083 RX trace 完整性测试。RX trace 完整性由生产者关闭状态、schema、三次稳定读取及匹配的偶数 seqlock 版本共同判定，不依赖驱动未发布的 `SnapshotComplete` 字段。

采集器会严格解析有界的 `NativeHcmdRxTrace` 二进制快照，并保留序号、丢弃和完整性信息。解码结果只用于诊断关联，不代表射频发送、对端接收或 AirDrop 成功。

本快照中的 31 项离线 mock 测试已通过。对应驱动已通过完整构建、签名校验和 15 组兼容编译，产物标识见清单；驱动加载、149 接收和 AirDrop 仍待实机验证。
