# Test096 接收记录采集

在现有有界接收诊断结束后运行，只读取驱动属性，不会再次触发无线诊断或写入 EFI。工具核对当前启动、已加载 UUID 和原采集结果，再用独立的 START/END 记录关联同一次接收窗口；缺失或不匹配时记为未知。

```sh
python3 developer-tools/test096-integration/collect_after_capture.py \
  --capture /path/to/native-controlled-capture-private.json \
  --build /path/to/test096-build-private.json \
  --out /path/to/roc-correlation-private.json
```

记录完整不代表全空口覆盖；没有记录也不能直接判为没有回包。原始采集文件保留，新增结果单独写入私有文件。
