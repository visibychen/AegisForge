# M1 工程骨架验证记录

日期：2026-11-03。关联：Issue #2 / PLAN 1.1。此记录仅覆盖工程基础，不代表整个课程项目通过最终验收。

## 环境与依赖

本机 Anaconda 创建名为 `AegisForge` 的独立环境，Python 3.13.18；解释器、pip 与库均属于该环境。设置 `PYTHONNOUSERSITE=1` 后，`python -m pip check` 通过，不再读取 Windows 用户级包；中文编码统一为 UTF-8。Node.js 24.11.1，npm 11.6.2。

主要 Python 版本：FastAPI 0.162.0、Pydantic 2.14.2、SQLAlchemy 2.1.6、Alembic 1.20.1；前端 React 19.3.1、Ant Design 6.6.8、Vite 8.3.5、TypeScript 7.0.2。精确依赖以锁文件为准。

## 实际检查与结果

| 命令/检查 | 结果 | 验证范围 |
| --- | --- | --- |
| conda 环境解释器/pip 检查 | 通过 | 同名环境，Python 3.13.18，用户级包隔离 |
| `python scripts/dev.py init` | 通过 | 创建本地配置及随机令牌，不在日志输出秘密 |
| `python scripts/dev.py migrate` | 通过 | SQLite 数据库升级；重复迁移保持正确 |
| `python scripts/check.py` | 通过 | pip check、Ruff、后端、前端类型/测试/构建的统一入口 |
| 后端 pytest | **20 项通过** | 鉴权、健康、错误、CORS、OpenAPI、schema、fake 边界及迁移/持久化 |
| 前端 Vitest | **4 项通过** | 范围提示、显式连接、错误令牌、离线状态与令牌不持久化 |
| TypeScript + Vite 构建 | 通过 | 类型正确并生成生产静态资源 |
| `npm --prefix frontend run test:e2e`，Chrome channel | **1 项通过** | 真实前后端、错误/正确令牌、健康、模拟模式、令牌清空、390px 无横向溢出 |
| 真实 HTTP `/health` | 200 / status=ok | 实际监听在本地 8000 端口 |
| npm 安装审计 | 0 已知漏洞 | 安装时报告，不替代 M6 完整依赖安全审计 |

表中全部 Python 命令均使用 `conda run -n AegisForge` 执行。普通测试使用临时数据库，未读取用户上传、未调用真实模型、未执行不可信代码。

数据库用例包含：迁移与 ORM schema 比较、升级/回滚/重建、外键开启、关联文件删除限制、任务级联删除、非法状态拒绝、重连后的数据与 UTC 时间保持。模型协议用例拒绝伪造 verified、错误 CWE、重复输入、无效行号/哈希和超范围置信度。

## 界面核对

浏览器检查桌面 1440px 和手机 390px 宽度，未发现裁切、重叠或横向溢出。截图令牌已清空，没有密钥、真实模型结果或用户输入。

- [桌面工作台](screenshots/m1-workspace-desktop.png)。
- [手机工作台](screenshots/m1-workspace-mobile.png)。

## CI 与已知限制

GitHub Actions 配置包括 Windows/Linux 后端 conda 环境检查，以及 Linux 前端安装、类型、测试和构建。真实运行状态以 M1 PR 的检查与 Issue #2 中的证据链接为准，不能把仅存在 workflow 文件算作远端运行成功。

当前锁定的 Starlette TestClient 对 httpx 兼容路径发出 1 条弃用提示；20 项测试均通过，后续模型适配/依赖更新时评估迁移。前端单入口资源约 501 kB（gzip 约 164 kB），构建有分块体积提示；M5 随页面分拆与编辑器按需加载优化。两者均保留事实，未隐藏警告或调高阈值。

M1 未实现上传、规则检测、真实 LLM、worker 执行、候选补丁和动态验证。这些能力保持不可用，不将 fake 空发现解释为安全。后续仍须满足 PLAN 的全部加分项、真实评测和最终交付要求。
