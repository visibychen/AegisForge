# AegisForge 工作约定

- 本文件适用于整个仓库。所有项目文件、工具命令与生成物以本仓库为工作根目录，不在父目录创建项目文件。
- 开始实施前阅读 `PLAN.md`、`README.md`，确认当前阶段、依赖及对应 GitHub Issue。后续工作围绕 PLAN 推进。
- 课程修复加分项已列为必须交付：候选补丁、diff、复检和受控样例动态验证不得降级为仅给文字建议。
- 功能状态与测试结果必须真实。fake provider 不能充当真实 LLM 验收；语法/复检无报警不能充当动态验证通过。
- 在完成功能或改变范围、架构、接口、测试阈值时同步更新 PLAN、相关文档和 Issue 证据。架构重大调整写入 `docs/decisions/`。
- M0 建立空仓库基线；之后按 Issue 开分支并通过 PR 管理变更。遵循 `CONTRIBUTING.md`，不强推共享历史，不撤销无关用户改动。
- 根据实际变更运行必要检查；安全、解析、模型输出、补丁和状态流转须有有意义的测试。不为纯文档或样式变更编写机械测试。
- 不执行上传源码、模型返回代码或任意请求包。动态测试仅通过 PLAN 定义的固定样例 runner；不把 Docker 权限交给 API/worker。
- 不提交 `.env`、密钥、原始用户上传、运行数据库、Cookie、Authorization、私有模型日志或开发机私有路径。
- **Python 必须由 Anaconda/conda 管理，统一使用名为 `AegisForge` 的环境，Python 基线为 3.13。** 不得把项目依赖安装到 base、系统 Python、其他项目环境或另建 venv/uv 环境。
- Python 命令、测试、迁移、依赖安装及锁文件生成都须在该环境执行：先 `conda activate AegisForge`，或使用 `conda run -n AegisForge ...`。优先用 `python -m pip`，禁止无法确认归属的裸 `pip`。
- `environment.yml` 管理 conda 运行时；Python 库声明在 `backend/pyproject.toml`，精确版本记录在 `backend/requirements*.lock`，通过该 conda 环境中的 pip 安装。环境或依赖变化同步这些文件和 README；Node 依赖使用 npm 锁文件。
- 环境固定设置 `PYTHONNOUSERSITE=1`，隔离 Windows 用户级 Python 包；设置 `PYTHONUTF8=1` 统一中文编码。不得通过启用用户 site-packages 绕过缺失依赖。
- 新的启动/检查命令必须实际验证后才写为可用。用户提到的 `AGENT.md` 作为本文件的入口说明，一并保留 Anaconda 约束。
- 未获得用户明确要求时，不启动子代理或并行代理任务。
