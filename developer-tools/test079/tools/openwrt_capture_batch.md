# 多窗口 OpenWrt 被动采集

`run_openwrt_capture_batch.py` 将已有的 `openwrt_capture_once.py` 串行运行多次。每个窗口都重新检查 AP 状态、单独创建 monitor、采集、清理并核对 AP/UCI 状态；任一窗口失败或超时，批次立即停止，不自动重试。每个窗口保存在独立目录，已有 PCAP 和报告会保留。

默认只打印计划，不连接路由器、不创建文件。实际采集必须显式加 `--capture`，并提供已由用户建立且已认证的 OpenSSH ControlMaster socket。工具不会安装路由器软件、改配置或启动 Mac 侧采集。

在包含 `tools/` 的目录执行；本仓库的工具快照目录为 `developer-tools/test078/`。AP 参数应填写你自己预检得到的值。

```sh
python3 tools/run_openwrt_capture_batch.py \
  --host root@router.lan \
  --control-path /private/tmp/your-openwrt-control.sock \
  --ap wlan0 --ap wlan1 \
  --expect-ap wlan0:0:6:2437:20 \
  --expect-ap wlan1:1:36:5180:160 \
  --interface wlan0 \
  --windows 2 --duration 12 --interval 3 --total-budget 150 \
  --output-dir /private/tmp
```

确认计划后，添加 `--capture` 才会启动采集。限制为每窗 12–20 秒、每窗最多 4096 包、最多 8 窗、间隔最多 30 秒、累计预算最多 600 秒；默认 3 窗。结果位于新建的 `openwrt-capture-batch-<id>/`，包含 `batch.json`、每窗的 `window.json`、helper 结果和 PCAP。成功只说明每个本地窗口通过 helper 的 AP/清理和文件校验，不证明抓到 AWDL 帧或对端收发。

离线测试（不会运行 SSH 或抓包）：

```sh
python3 tools/test_openwrt_capture_batch.py
```
