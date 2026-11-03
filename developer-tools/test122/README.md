# Test122 收包诊断工具

Test122 复用 Test121 的单次 RX149 诊断流程，并绑定 Test122 自己的构建、源码冻结、部署和 UUID 收据。OpenWrt 发射端使用 Test121 已离线验证的二进制；工具会核对原始 Test121 构建收据、Test122 复用收据及二进制哈希，明确标为复用，不声称重新编译或 RF 验证。

默认只显示计划，不接触路由器、不发射、不写 EFI：

```sh
python3 developer-tools/test122/coordinate_test122_rx149.py --plan
```

运行前需由准备流程生成私有的 disarmed bundle、OpenWrt `wlan7` 身份和本机 `awdl0` 身份，并通过 Test122 handoff、加载 UUID、启动代次及资源释放门禁。显式 `--run` 才进入单次受控收包流程；完成后不可重试。睡眠测试保持关闭。

测试保持当前 STA 网络。只有运行时实际记录 STA 信道与接收信道后才可作信道对比；未知信道记为未知，不通过改网验证149信道。
