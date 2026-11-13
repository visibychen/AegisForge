# 铸盾 AegisForge

基于大语言模型的 Web 代码漏洞智能检测与修复系统。

An LLM-powered platform for web code vulnerability detection, remediation, and fix validation.

项目面向网络空间安全技术课程设计，计划覆盖 XSS、SQL 注入和命令注入/执行风险，提供从代码/HTTP 输入、特征提取、智能分析到候选补丁和修复验证的 Web 工作流程。

## 当前状态

**M3 智能检测闭环已实现并通过本地验证，待 PR 集成。** 支持 Python/离线 HTTP 输入、规则/模型/联合策略、DeepSeek 真实分析、独立 worker、持久任务、取消/重试及最小结果页。模型失败保留已有证据并明确标为部分完成；修复和动态验证留待 M4。

M1 科技流动视觉继续保留。M3 按用户分工完成三阶段、同一 Claude 会话四次真实调用，并在审查中提出和落实创新：逐块覆盖账本、可下载检测凭证。验证包含三类真实 DeepSeek 开发演示；详见 [M3 验证](docs/m3-verification.md)、[设计](docs/m3-design.md)和 [协作记录](docs/collaboration-2026-11-07.md)。冻结的 120 源码/60 HTTP 样例仍保持原划分，人工标注复核 pending，正式准确率评测留待 M6。

- [实施与验收计划](PLAN.md)：系统框架、必做加分项、阶段交付、测试数据及验收门槛。
- [课程要求与评分映射](docs/requirements.md)：原始要求的项目化追踪。
- [协作规范](CONTRIBUTING.md)：Git、GitHub Issues、PR 与检查流程。
- [GitHub 计划总跟踪 #1](https://github.com/visibychen/AegisForge/issues/1)：M1–M7 的任务、依赖与验收进度。
- [GitHub 仓库](https://github.com/visibychen/AegisForge)。
- [系统设计初稿](docs/design.md)、[M1 验证记录](docs/m1-verification.md)与 [Anaconda 环境约定](AGENT.md)。

## 核心交付范围

- 上传 Python Web 源码或原始 HTTP 请求文本，提取特征并调用 LLM。
- 展示漏洞类型、风险等级、定位证据和修复建议。
- **加分项必做**：生成候选修复、展示代码差异、执行静态复检和受控样例动态验证。
- 保存历史、导出脱敏报告，交付可复现环境、完整代码和课程报告。

首版完整支持范围为 Python/Flask 风格源码。HTTP 请求包仅用于离线攻击特征与风险分析，不能单凭请求确认服务端漏洞或生成未知源码补丁。任意上传源码不在主机执行，动态验证仅适用于登记的隔离样例。

## 计划技术栈

React / TypeScript / Vite；Python 3.13 / FastAPI / Pydantic；SQLite / SQLAlchemy；独立 worker；可替换 LLM provider；pytest / Playwright；Docker 受控验证。

## 环境与安装

Python 必须使用 **Anaconda/conda 的 `AegisForge` 环境**，基线 Python 3.13；Node.js 使用 24.x。本机环境已创建。请在支持 `conda` 的终端（例如 Anaconda Prompt）进入仓库根目录后操作。

新机器首次创建环境：

```text
conda env create --file environment.yml
```

已有环境在声明变化时更新并重新激活，勿重复创建或删除其他环境：

```text
conda env update -n AegisForge --file environment.yml
conda activate AegisForge
```

安装开发/测试库、前端依赖并初始化：

```text
conda run -n AegisForge python -m pip install -r backend/requirements-dev.lock
npm --prefix frontend ci
conda run -n AegisForge python scripts/dev.py init
conda run -n AegisForge python scripts/dev.py migrate
```

`init` 生成被 Git 忽略的 `.env` 和随机访问令牌，不覆盖已有文件。环境设置 `PYTHONNOUSERSITE=1` 隔离用户级包，`PYTHONUTF8=1` 保持中文编码一致；所有 Python 安装、迁移和检查均在该环境执行，不向 base/系统 Python 安装库。

## 本地启动

在第一个终端运行后端：

```text
conda run --no-capture-output -n AegisForge python scripts/dev.py api
```

在第二个终端运行独立 worker：

```text
conda run --no-capture-output -n AegisForge python scripts/dev.py worker
```

在第三个终端运行前端：

```text
npm --prefix frontend run dev
```

打开 [Web 工作台](http://127.0.0.1:5173/)。从本地 `.env` 查看 `AEGISFORGE_API_TOKEN`，在工作台输入以连接服务；令牌仅保留在页面内存。保存输入后，在“检测任务”选择策略和模型、创建任务。API 只入队，须运行 worker；fake 会明确标为部分完成，规则模式不会调用模型。任务链接可刷新恢复，重新连接后查看发现、覆盖、凭证及旧尝试摘要。后端 [健康检查](http://127.0.0.1:8000/health)公开存活，[API 文档](http://127.0.0.1:8000/docs)描述接口。

接受 UTF-8/UTF-8 BOM：源码 `.py`，HTTP `.http/.req/.txt`；单文件最多 2 MiB，任务最多 10 文件/10 MiB、80,000 字符/8 块。原始快照仅存在被 Git 忽略的私有目录，预览使用尽力而为的脱敏。当前完整服务密钥出现在输入时拒绝保存/分析。HTTP 不重放，源码不执行。

![M3 检测与覆盖账本](docs/screenshots/m3-scan-desktop.png)

## DeepSeek 配置

密钥 **只设为 OS 环境变量 `AEGISFORGE_DEEPSEEK_API_KEY`**，不要写进 `.env`、源码、命令参数或页面。另设非秘密的 `AEGISFORGE_MODEL_MODE=real`，可选 `AEGISFORGE_DEEPSEEK_MODEL=deepseek-flash`（默认）或 `deepseek-v4-pro`。密钥格式须为 16–256 位字母、数字、点、下划线或连字符。未配置/格式不合规时只公开 fake 别名。

本机已安全配置 Windows 用户环境变量。`scripts/dev.py api/worker` 只为对应子进程导入它们，兼容先前已打开的终端；其他平台或直接运行 `python -m app.worker` 时需确保进程继承同一环境。Claude 启动不导入该密钥。用户环境变量并非阻止同用户其他进程读取的隔离机制。

默认单次模型超时 60 秒、每次任务尝试总时限 180 秒（跨租约恢复保持起点）；任务累计最多 32 次、每数据库部署每 UTC 日最多 64 次外部调用。`AEGISFORGE_MAX_MODEL_CALLS`、`AEGISFORGE_DAILY_MODEL_CALLS` 可调；这些是次数上限，不是金额上限。手动重试最多两次且不清零累计调用，按当前配置重跑全部块并归档原结果/凭证。排队后模型/提示词等方案变化时拒绝执行，提示重试。

已验证的有界真实开发演示（默认三例；会调用付费服务）：

```text
conda run --no-capture-output -n AegisForge python scripts/deepseek_smoke.py
```

它仅加载开发样例，临时数据库与安全摘要写入被忽略的 `data/`；不保存原始模型正文，不执行源码，不访问保留集标签。它采用进程内 worker 验证真实适配链；独立 CLI 与浏览器另有离线验证。

## 检查与测试

运行现阶段已实现的完整检查（依赖一致性、Ruff、后端测试、前端类型/交互测试和构建）：

```text
conda run --no-capture-output -n AegisForge python scripts/check.py
```

仅检查后端：

```text
conda run --no-capture-output -n AegisForge python scripts/check.py --backend-only
```

浏览器冒烟测试需先按上述方式启动服务并生成 `.env`。已安装 Google Chrome 时，可在 PowerShell 使用：

```powershell
$env:PLAYWRIGHT_CHANNEL = 'chrome'
npm --prefix frontend run test:e2e
```

当前三个浏览器场景覆盖连接/动效、上传/脱敏/规则/HTTP 边界、任务/独立 worker/模拟模式/重试/刷新/凭证下载及手机布局。浏览器测试固定选 fake，不消费真实模型预算；真实三类演示由上述脚本单独验证，修复 E2E 留待 M4/M5。其他平台可安装 Playwright Chromium。

`scripts/check.py` 也校验 [冻结清单](samples/freeze.json)。开发代码仅使用 `samples/dev/`；保留集只作完整性、语法和解析预算检查，正式检测评测留待 M6。18 个受控修复例已预登记，实际隔离测试留待 M4。不要为适配规则结果改写保留标签或静默重新冻结。

## 依赖与后续推进

`environment.yml` 管理 conda 运行时，`backend/pyproject.toml` 声明 Python 库范围，`backend/requirements*.lock` 记录精确版本，前端由 `package-lock.json` 锁定。Python 锁文件由同一 conda 环境中的 pip-tools 生成；依赖调整同步声明、锁文件、测试及 PLAN。

**[M2 #3](https://github.com/visibychen/AegisForge/issues/3)** 与 **[M3 #4](https://github.com/visibychen/AegisForge/issues/4)** 的实现与本地验收已完成，PR 集成状态以 Issue 为准。M3 分支堆叠在仍待审的 M2 PR #12 上，避免重复审查前序改动。修复与验证加分项仍在 M4 必须交付，最终真实模型对比留待 M6。
