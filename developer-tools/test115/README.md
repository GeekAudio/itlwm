# Test115

发送前核对当前 HAL 窗口，失败后按已提交会话的状态清理。仍只允许一次 UDP 发送，窗口最多 100 ms；实际发送、回包和 AirDrop 分开验收。

`coordinate_test115.py` 不加 `--run` 时只检查配置，不操作设备。
