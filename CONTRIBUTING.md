# 项目协作与实施规范

本项目以 [PLAN.md](PLAN.md) 作为实施与验收依据。每次推进明确需求编号（R01–R08）、阶段（M0–M7）及 GitHub Issue，不跳过修复与验证加分项。

## 工作流程

1. 查看 Git 状态和当前 PLAN 阶段，认领或建立有范围、依赖、验收标准的 Issue。
2. 从最新 `main` 建立功能分支，例如 `feat/2-project-foundation`；主题使用简短英文，编号取实际 Issue。
3. 小步实现，提交相关测试、设计说明和必要文档；不混入无关格式调整。
4. 运行与变更匹配的检查，在 Issue/PR 中记录命令、结果和未完成检查。
5. 发起 PR，写明 PLAN/需求编号、最终行为、验证证据与限制。阶段未全部完成时使用 `Refs #N`。
6. 检查通过并完成集成后同步更新 PLAN 和阶段 Issue。满足阶段全部完成条件才关闭 Issue；后续新阶段继续使用分支和 PR。

M0 因远端为空，允许首个计划基线提交直接初始化 `main`。之后的正常产品开发遵循上述流程。不能将未执行的测试、缺失的真实模型结果或无 Docker 的验证写成通过。

## 提交约定

使用 `feat:`、`fix:`、`test:`、`docs:`、`chore:` 前缀，说明具体变更，并引用关联 Issue。例如：

```text
feat: validate Python uploads and redact request secrets (Refs #3)
test: cover patch conflicts and source hash mismatches (Refs #5)
docs: record detection evaluation protocol (Refs #7)
```

示例编号仅说明格式，不代表已建立的真实任务。

## 检查与证据

M0 只检查文档一致性、相对链接、管理模板、敏感数据与 `git diff --check`。M1 已建立统一检查入口和 GitHub Actions。所有 Python 工作使用 Anaconda/conda 的 `AegisForge` 环境（3.13），禁止使用 base/系统 Python 或额外 venv/uv 环境；运行 `conda run -n AegisForge python scripts/check.py`，细节见 README。未实现脚本不能写成已可运行。

后续 PR 按影响范围运行后端、前端或 E2E 检查。真实 LLM 评测需有配置和预算，普通 PR CI 使用 fake provider。隔离执行、任务状态、输入处理及补丁逻辑必须覆盖正反例。

## 计划变更与发布

范围、技术选型或验收门槛变化先说明原因与影响，更新 PLAN 变更记录。不得为掩盖未通过的实验降低门槛。重要架构调整记录 ADR。

只有 PLAN 最终清单全部通过后才发布 `v1.0.0`。发布保留真实限制、未完成项与证据链接；课程查重报告按用户及课程要求交付，不将其个人信息默认公开。
