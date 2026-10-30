# mt76 NULL-vif 修复

这里保存一组针对 OpenWrt `mt76` 提交 `8f301a5c` 的双文件回移植补丁：在 `mt76_connac2_mac_tx_rate_val()` 和 `mt76_calculate_default_rate()` 中，先检查 `vif`，再访问其私有数据。有效 VIF 的 PHY/context 选择和速率表行为保持原样。

## 源码补丁

先准备该提交的 mt76 源码目录。离线验证会核对四个源文件的 SHA-256，将两份补丁应用到临时副本，再用 ASan/UBSan 测 NULL 和非 NULL 路径；它不会改你的源码目录。

```sh
python3 tools/validate_source_patch.py --mt76-source /path/to/mt76
```

需要 Python 3.10 或更新版本、Git 和带 ASan/UBSan 的 Clang。要手动应用补丁，先在目标源码目录运行 `git apply --check`，再把 `patches/*.patch` 一起应用，并从匹配的 OpenWrt 构建树同时重建 `mt76.ko` 和 `mt76-connac-lib.ko`。只应用其中一份不完整。

## 离线 ELF 候选

生成器只接受 `PATCH-MANIFEST.json` 中 SHA-256 完全匹配的两个原始 ELF 输入。它仅替换目标函数内经校验的 AArch64 指令字，不包含原始模块，也不做 Kbuild、签名、安装或加载。

```sh
tmp="$(mktemp -d)"
python3 tools/build_offline_candidates.py \
  --core /path/to/original/mt76.ko \
  --connac /path/to/original/mt76-connac-lib.ko \
  --out-dir "$tmp/candidates"
```

可选的 Unicorn 模拟器会验证生成候选的函数指令路径；它需要 Unicorn 2.1.4：

```sh
python3 -m pip install unicorn==2.1.4
python3 tools/simulate_elf_candidates.py \
  --core-input /path/to/original/mt76.ko \
  --connac-input /path/to/original/mt76-connac-lib.ko \
  --core-candidate "$tmp/candidates/mt76.ko.offline-candidate" \
  --connac-candidate "$tmp/candidates/mt76-connac-lib.ko.offline-candidate" \
  --manifest "$tmp/candidates/candidate-manifest.json" \
  --report "$tmp/simulation.json"
```

候选只针对清单中的原始 ELF；其他内核、工具链或模块构建不适用。若另行进行临时试载，模块只能放在路由器 RAM 临时目录 `/tmp` 并通过单独审阅的回滚流程加载；不要覆盖 `/lib/modules` 或写入持久存储。本目录不包含路由器控制脚本。

## 验证边界

`python3 -m unittest discover -s tests` 检查本目录的 SHA-256 清单和文件范围。源码验证与 Unicorn 模拟都是离线证据，不是目标内核 ABI/模块包验证。真实 Intel 接收、AWDL 数据回包和 AirDrop 仍未由这些补丁或模拟证明。

文件校验：

```sh
shasum -a 256 -c SHA256SUMS.txt
```

补丁按仓库根目录 GPL-2.0 许可分发；上游 mt76 文件及派生代码的版权和许可仍适用。
