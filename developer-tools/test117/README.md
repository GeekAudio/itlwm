# Test117 菜单扫描取证

这一版修补切网后的连接状态通知，并记录菜单扫描与加入请求。菜单列表和快速切换边界仍需实机验证。采集器只读元数据，不启动扫描，也不改网络设置；不需要管理员验证。

重启后先核对 Test117 的加载 UUID，再分别保持系统设置 Wi-Fi 页、状态栏 Wi-Fi 菜单打开，各采一次。`--phase` 只是人工标记，不会替你打开界面。

```sh
python3 collect_menu_scan.py --out /path/to/new-private-directory --phase menu --expect-uuid ACTUAL_LOADED_UUID
```

每次使用一个新目录；结果保留在本机。不要把“扫描完成”直接记成“菜单已显示网络”。
