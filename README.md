# 铸盾 AegisForge

基于大语言模型的 Web 代码漏洞智能检测与修复系统。

An LLM-powered platform for web code vulnerability detection, remediation, and fix validation.

项目面向网络空间安全技术课程设计，计划覆盖 XSS、SQL 注入和命令注入/执行风险，提供从代码/HTTP 输入、特征提取、智能分析到候选补丁和修复验证的 Web 工作流程。

## 当前状态

**M0：计划与项目管理基线已建立，产品功能尚未实现。** 当前没有可启动的应用，后续按计划逐阶段补充安装、配置和使用说明。

- [实施与验收计划](PLAN.md)：系统框架、必做加分项、阶段交付、测试数据及验收门槛。
- [课程要求与评分映射](docs/requirements.md)：原始要求的项目化追踪。
- [协作规范](CONTRIBUTING.md)：Git、GitHub Issues、PR 与检查流程。
- [GitHub 计划总跟踪 #1](https://github.com/visibychen/AegisForge/issues/1)：M1–M7 的任务、依赖与验收进度。
- [GitHub 仓库](https://github.com/visibychen/AegisForge)。

## 核心交付范围

- 上传 Python Web 源码或原始 HTTP 请求文本，提取特征并调用 LLM。
- 展示漏洞类型、风险等级、定位证据和修复建议。
- **加分项必做**：生成候选修复、展示代码差异、执行静态复检和受控样例动态验证。
- 保存历史、导出脱敏报告，交付可复现环境、完整代码和课程报告。

首版完整支持范围为 Python/Flask 风格源码。HTTP 请求包仅用于离线攻击特征与风险分析，不能单凭请求确认服务端漏洞或生成未知源码补丁。任意上传源码不在主机执行，动态验证仅适用于登记的隔离样例。

## 计划技术栈

React / TypeScript / Vite；Python 3.13 / FastAPI / Pydantic；SQLite / SQLAlchemy；独立 worker；可替换 LLM provider；pytest / Playwright；Docker 受控验证。

## 后续推进

当前应从 PLAN 的 **[M1 工程骨架与协议（#2）](https://github.com/visibychen/AegisForge/issues/2)** 开始，通过阶段 Issue、功能分支和 PR 留存实现与测试证据。范围或技术调整须同步更新 PLAN。
