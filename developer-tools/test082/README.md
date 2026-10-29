# Test082 开发工具

这里保存 Test082 的 149 频道接收观察工具、必要依赖和离线 mock 测试。默认只显示计划；运行采集需要独立的构建元数据、接收端就绪门和人工授权。

运行离线测试：

```sh
python3 -m unittest discover -s tools -p 'test_*.py'
```

Test082 已通过离线构建、签名检查和 21 项工具测试，本目录只保存开发工具源码。快照保留 `NativeMCC` 与 `NativeStaTx` 的数值字段；地址类及其他非数值诊断字段会被过滤。离线测试不代表驱动已加载、无线接收成功或 AirDrop 可用。

本轮 [RUNTIME-NOTE.md](RUNTIME-NOTE.md)
