# ADR 0001 使用 Anaconda 管理 Python 环境

日期：2026-11-03。状态：采用。关联：M1 / Issue #2。

用户明确要求使用 Anaconda，并建立名为 `AegisForge` 的环境。项目保留原计划的 Python 3.13 基线，使用本机已有 Anaconda 创建独立环境，不修改 base 或其他项目环境。

`environment.yml` 声明 conda 运行时。Web 与测试库在该环境中使用 `python -m pip` 安装，声明于 `backend/pyproject.toml`，由 pip-tools 生成 `requirements.lock` 和 `requirements-dev.lock`。安装与检查显式使用 `conda run -n AegisForge`，或确认激活后执行。禁止另建 venv/uv 环境及向全局 Python 安装项目依赖。

Python 依赖锁定版本，conda 的 Python 限定到 3.13 系列，具体补丁版本随可用安全维护版本解析；本机实际版本在 M1 验收记录登记。跨平台以 Windows 和 Linux CI 的锁文件安装与测试结果为依据。CI 使用 conda 创建同名环境，遵守相同的依赖安装流程。

该决定替代 PLAN 1.0 中的 uv.lock 设想，不改变课程范围、修复加分项或最终测试阈值。

本机首次依赖检查发现 Python 默认可见用户级 site-packages，导致新环境读入无关包的元数据。环境因此设置 `PYTHONNOUSERSITE=1` 隔离用户包，并设置 `PYTHONUTF8=1` 统一中文编码；这两项在 environment.yml 和现有环境中同时配置。项目检查脚本验证用户包隔离已启用。

参考：[Conda 环境管理](https://docs.conda.io/projects/conda/en/stable/user-guide/tasks/manage-environments.html)。
