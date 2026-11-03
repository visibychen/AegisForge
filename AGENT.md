# AegisForge 环境与代理说明

本仓库完整工作约定见 [AGENTS.md](AGENTS.md)，后续实施遵循 [PLAN.md](PLAN.md)。

Python 环境必须使用 **Anaconda/conda**，环境名称固定为 **`AegisForge`**，Python 版本基线为 **3.13**。所有 Python 库的安装、运行、迁移和测试均在此环境内执行；禁止安装到 base、系统 Python、其他项目环境或另建 venv/uv 环境。

使用 `conda activate AegisForge` 后执行命令，或显式使用 `conda run -n AegisForge python ...`；安装库使用该环境内的 `python -m pip`。运行时声明保存在 `environment.yml`，项目库与版本锁保存在 `backend/pyproject.toml` 和 `backend/requirements*.lock`。
