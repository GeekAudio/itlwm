# 开发进度网站

`dist/` 是可直接浏览的 GitHub Pages 静态站。页面只展示当前开发重点、运行与候选版本、40 项本轮验收和下一步。点击验收项可查看实测依据；历史时间线保留在源数据中，不再占用首页。

页面内容来自 `dist/data.js`，通过率由当前 40 项结果计算。未覆盖不算失败，通过率也不是项目完成率；候选构建或部署不计入实机验收。

`templates/index.html`、`dist/assets/site.css` 和 `dist/assets/site.js` 是页面源文件。`tools/refresh_data.py` 从私有验收记录投影公开字段；`tools/render_site.py` 把数据、样式与脚本内嵌成同一份 HTML，避免缓存混用。两份入口 `index.html` 与 `milestones.html` 保持一致。

每次访问、后退返回或重新切回页面，都会检查最新发布。发现新版本后自动更新；离线或发布尚未同步时会提示状态并提供重试。GitHub Pages 的服务器缓存头由平台管理。

`tools/publish_github_pages.py` 按文件白名单发布，并核对公开文件哈希。生成和发布依赖本地工作区与私有验收源数据，这份源码不包含凭据和私有日志。`SOURCE-MANIFEST.json` 保存公开源码的文件哈希。
