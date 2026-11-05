# M2 输入与特征提取验证

日期：2026-11-05。关联 PLAN 1.3 / R01、R02、R08 / Issue #3。

## 已实现的行为

- Python 源码或原始 HTTP 请求可通过文件/粘贴提交、载入示例、查看脱敏预览与规则证据；保留 M1 动效控制与响应式界面。
- 鉴权业务接口 `POST /api/v1/artifacts?filename=...&input_type=source|http` 接受原始 UTF-8 请求体，浏览器直接发送 File/Blob，未引入 multipart 依赖。成功返回 201 和快照预览。`GET /api/v1/artifacts/{uuid}` 返回同一快照的脱敏预览。
- 独立于原始名称的随机私有存储键、独占写入、原始字节 SHA-256 校验；拒绝路径/不支持后缀/二进制/无效编码/空文件/超限/链接目录，失败不保留本次快照。
- 原文 AST 与未脱敏 HTTP 规范化字段仅用于服务端内存规则匹配；公开字段、证据、特征和未来模型分块均使用脱敏视图。
- 启发式规则覆盖 CWE-79/89/78，提供源码行号或 HTTP 稳定字段 ID 与位置元数据；解析失败、规则上限和证据摘录均明确标识。
- 单文件 2 MiB、原文与规范化内容 80,000 字符、每块 12,000 字符、重叠 1,000 字符、最多 8 块。M2 一次上传一个快照；单任务 10 文件/10 MiB 的组合限制将在 M3 创建任务时执行，当前没有开放任务 API。

## 实际执行与结果

| 命令 / 检查 | 本地结果 |
| --- | --- |
| `conda run --no-capture-output -n AegisForge python scripts/check.py` | pip check、Ruff、格式、141 后端测试通过 / 1 跳过、冻结检查、前端类型、14 前端测试及生产构建通过 |
| `conda run -n AegisForge python evaluation/datasets.py freeze` | 从真实输入生成 180 样例及元数据哈希 |
| `conda run -n AegisForge python evaluation/datasets.py check` | 完整冻结一致性通过；未运行保留集检测 |
| `PLAYWRIGHT_CHANNEL=chrome` 后运行 `npm --prefix frontend run test:e2e` | 2 场景通过：服务连接/动效，上传/三类源码线索/HTTP 风险/脱敏/非法输入/手机布局 |

Python 使用 Anaconda `AegisForge` 环境（3.13.18），浏览器为实际安装的 Chrome。Windows 因宿主不允许创建 symlink 跳过 1 项；Linux CI 应执行该测试。远端 CI 结果与 PR 链接在 [Issue #3](https://github.com/visibychen/AegisForge/issues/3) 更新。

关键复现与修正：脱敏不再改坏 `def run(cmd, token=None)`；密码表单里的 SQLi 仍有风险线索且原值不回显；三层 URL 编码最多解两次；Unicode 特殊换行明确拒绝；12,000 字符行加 LF 可分块；超长参数不再造成 500；2 MB 单行在解析前立即拒绝；f-string 表达式内凭据也有回归测试。源码和 HTTP 从未执行或重放。

截图：[桌面](screenshots/m2-input-desktop.png)、[手机](screenshots/m2-input-mobile.png)。

实际检查 1440/850/590/390/375/374/360 px 七档宽度，稳定布局均无横向溢出。检查曾发现 AntD 按钮波纹在尺寸变化的一帧内保留旧坐标，输入区已关闭这层额外波纹；原有受控工作台动效保留。截图先回到顶部并关闭下拉菜单，避免固定导航的滚动截图偏移。

## 数据冻结与解释边界

源码 120 例（开发 48 / 保留 72），HTTP 60 例（开发 24 / 保留 36）。家族、标签、锚点、许可和 AI 来源均登记；反改名结构检查不允许跨家族结构重复。同一家族的安全/漏洞配对允许仅有安全字面量差别。18 个未来受控修复例每类 6 个，登记状态为 planned，M4 才提供 runner/正常回归/安全断言/参考修复。

开发集规则调试统计：源码 24 TP / 23 TN / 1 FP；HTTP 12 TP / 11 TN / 1 FP。这不是独立评测。保留集由同一 AI 作者编写，划分非随机，人工核对仍 pending；正式准确率与真实 LLM 实验留待后续验收。

脱敏为尽力而为，未知命名、非常规编码、拼接秘密仍可能漏出；同权限恶意进程的文件竞态不在本地单用户威胁范围。崩溃留下的孤儿快照尚无回收器。JSON 字段暂无线列原始映射，其他 HTTP 字段保留脱敏名称与数值位置。规则没有完整的跨函数污点追踪，可能误报/漏报。

非阻断提示仍存在：Starlette TestClient 的 httpx 迁移警告、前端构建单块约 605 kB 的体积提示。没有调整警告阈值或把它们记作测试失败。M3 及真实模型接入按用户要求暂缓、未实现；M4 修复加分项仍保留在 PLAN。
