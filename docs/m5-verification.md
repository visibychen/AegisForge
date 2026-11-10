# M5 验证记录

日期：2026-11-10，分支feat/6-web-workbench，基于M4 PR14，Refs #6。实现及验收进展以本记录和Issue #6为准，不自动合并前序PR。

## 范围与协作

总览、历史状态/编号/CWE/等级筛选分页、逻辑移出、发现的服务端筛选与分面、纯文本证据/键盘导航、原文候选对比、修复历史、源代码无关JSON/可读Markdown报告。创新含证据导航、修复说明卡、长源码窗口和报告完整性凭证。三阶段同一Claude会话四次成功调用，Sonnet5.5/high，最终由Codex优化；[记录](collaboration-2026-11-10.md)。

## 已执行与实际边界

- 主机Python均在Anaconda AegisForge / Python3.13.18。第二阶段独立测试320后端passed/1本机symlink skip、46前端passed、tsc通过。
- 最终优化加入报告摘要/篡改/严格解析、并发快照、归档候选与来源差异、超过300条修复计数、2501行证据和跨窗口键盘测试。最终`python scripts/check.py`通过：325后端passed/1本机symlink skip、48前端passed，Ruff/格式/类型/构建/冻结完整性通过。GitHub CI另见Issue #6，不将未执行的场景算通过。
- 本机浏览器初次连接/输入/任务三个旧场景通过；新工作台联调发现并修复按钮汉字间距造成的可访问名称问题，补充网络失败重试和父任务重试后归档状态刷新。
- 本机Windows默认8000/18000端口被系统拒绝绑定，采用28000的隔离测试API和临时库；Vite默认仍8000，可用AEGISFORGE_DEV_API_PORT指定回环端口。本机出现间歇代理连接超时，DockerDesktop启动后退出且服务权限不足，**不记录本机Docker动态验收通过**。
- GitHub新增Workbench Compose E2E：干净Ubuntu、固定镜像、实际迁移和独立API/worker/控制器、Playwright默认场景、隔离探测、无源码报告校验。与本机验证分开记录，以实际CI为据。仅fake、没有模型密钥，真实模型显式场景跳过。原M4三类真实DeepSeek证据保留，本轮不额外消费模型预算。

## 安全及数据规则

移出历史后任务/发现/修复各入口404，不重置调用预算；活动任务/修复/动态验证拒绝移出。快照仍按ID可预览，明确不是擦除。旧候选可读但新验证409，排队中的旧请求由runner终结；已完成旧结果保留。报告默认不含证据/源码/参数名/文件名/模型自由文本，限4MiB，截断显式；JSON摘要可用`python scripts/verify_report.py report.json`核对，MD展示的摘要不覆盖MD文字，均非签名。完整边界见[ADR0004](decisions/0004-m5-history-and-reports.md)。

冻结开发/保留集未变；M6准确率、性能、正式18例修复实验和人工标注复核仍待完成。M7课程模板报告/查重/最终发布未代做。物理快照回收另行设计。
