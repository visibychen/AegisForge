# M6 实验后优化设计（第 2 轮实现，待 Codex 实测）

2026-11-11，Refs #7。本文件说明第二轮 Claude 修改的设计、边界与**尚未证实**之处。所有结论以 Codex 实际运行的测试和付费开发验证为准；本文件不声明任何测试通过。

## 先说明解释边界（必须保留）

- 下列 A 节的提示词与校验诊断改动，是在**看过保留集基线结果之后**做的检测/修复行为改动。原 108 例保留集已暴露，改动后的任何保留集数字只能称**事后开发评测**，不得称独立保留评测，更不得回填或覆盖 `evaluation/results/` 中的正式基线。
- 通用安全上下文提示（A.2）只来自通用原理和开发样例类别，没有使用保留样例的 ID、标签、源码、候选或隐藏测试，也没有按置信度或来源过滤发现、没有调阈值。
- AI 编写标签的 human_review 仍为 pending；机器运行不等于人工复核。
- 基线失败原因（输出拒绝、精确原文冲突）的**根因尚未证实**：下文的行寻址是对"模型数不准全局行号"这一假设的结构性处理，其效果必须由开发集 A/B 验证。

## A. 行寻址、精确预检与带事实的纠错（analysis-1.2 / repair-1.2）

动机（已证实的事实）：基线 695 次调用中 66 次 `MODEL_INVALID_OUTPUT`，去重后 65 个 `location_mismatch`、1 个 `evidence`（Codex 按 call_records 去重）。`location_mismatch` 的含义（`deepseek.py::_ground_source`）是证据原文在源码中存在，但声明行范围与它不相交。原提示把源码放进无行号 JSON 字符串，要求模型自己数行号。修复侧 54 次中 14 个 `PATCH_CONFLICT`，其中 12 个来自四个样例的三轮重复；这是系统性迹象，**不是**"temperature=0 保证确定"的证明，具体原因（末行无换行、空白、数行错误等）未证实。

改动：

1. **`llm/prompts.py`（analysis-1.2）**：源码输入由 `content` 改为 `lines: [{"n": 全局行号, "text": 原行}]`，系统提示说明 `n` 只是标签、不属于代码或证据、证据取自 `text` 并以 `n` 声明起止行。HTTP 保持精确 `fields` 与 `content`，不虚构源码位置。wire 版本仍为 1.1，服务端所有校验不变。
2. **通用安全上下文**（`CONTEXT_GUIDANCE`）：HTML 文本/属性/URL 与 JavaScript 字符串上下文不同，仅 HTML 转义在脚本或 JS 字符串中不足；SQL 值绑定与标识符白名单、`int()` 只保证数字；命令执行中参数数组与 `shell=False`，显式 `sh -c`/`bash -c` 会解释字符串，`shlex.quote`/`int()` 的作用；要求说明不可信输入与汇点。
3. **`llm/deepseek.py`**：`OutputRejected` 增加仅含整数/固定词的 `detail`（`str(error)` 仍是类别）；`location_mismatch` 与 `ambiguous_evidence` 的纠错提示给出证据真实所在行。**拒绝条件完全不变**——声明范围必须与证据相交，唯一证据在别处**仍被拒绝**，没有"忽略行号"。纠错仍最多 1 次。`ProviderError.detail` 带出最后一次拒绝的事实。
4. **`llm/repair.py`（repair-1.2）**：修复输入给 `lines`，每行 `text` 保留真实换行，末行是否有换行如实呈现；`old_text` 要求等于所列行 `text` 的拼接。系统提示加入 JS 字符串上下文用 JSON 编码、合法输入含引号/撇号必须继续工作、必要时显式 shell 逐值 `shlex.quote`。`decode_repair` 在已有的一次纠错循环内调用与 `apply_edits` **同源**的 `check_edits` 预检。
5. **`services/patches.py`**：新增 `check_edits`（范围、顺序、`old_text` 逐字相等、换行保留）与 `EditRejected(category, detail)`；`apply_edits` 改为调用同一函数，仍是最终权威。`detail` 仅含整数和固定词（如 `trailing_whitespace_only`、`exact_text_at_lines_3`、`last_line_has_no_line_ending`），不含源码。
6. **`services/repairs.py`**：模型复检的账本版本及预算 factory 默认版本改用 `PROMPT_VERSION` 常量，使契约、账本与实际提示一致；修复失败时把 `{category, detail}` 持久为 `checks["patch_diagnostic"]`，**不保存**原始 wire、源码或密钥。

行为变化（需知）：真实模型路径下，原本直接 `PATCH_CONFLICT` 的失败会先得到一次带事实的纠错；仍失败时 `error_code` 为 `MODEL_INVALID_OUTPUT`（类别在 `patch_diagnostic`），与基线中的 `PATCH_CONFLICT` 编码不同。直接 `apply_edits` 的路径（含模拟模型）仍抛原来的 `PATCH_*` 码。

## B. 可审计门禁、子额度与证据

- **`evaluation/budget.py`**：同一持久账本 `data/m6-model-budget.sqlite` 的全局上限（≤1000，只记录一次、不可改）不变。新增命名**子额度**：`ExperimentBudget(path, limit, scope, allowance)`；跨线程/进程原子（`BEGIN IMMEDIATE`），重启后用量保留，不可改大；新 scope 只能从"既未使用也未被其他 scope 承诺"的全局余量划拨，换名无法凭空得到新额度；旧的 795 条预留（scope 为 NULL）照常计入全局。首次打开旧库会 `ALTER TABLE calls ADD COLUMN scope`。
- **`evaluation/gate.py`**：`verify_*` 从原始逐任务/逐尝试行重算所有分组指标、阈值标志、成功判定与计数，对账 JSON、CSV、候选包/控制文件 SHA-256、冻结清单（可选 `plan`）；`*_requirements` 按课程阈值给出逐项结果。**记录完整性与数值达标是两个独立结论。**
- **`scripts/m6_verify.py`**：只读审计；记录完整且一致返回 0（即使数值未达标），缺文件/篡改/少行返回 1。
- **`scripts/acceptance.py`**：严格验收；0 = 记录有效且全部门槛满足，1 = 记录有效但未达标，2 = 记录无效。覆盖范围：检测（精确率/召回率 ≥0.85、每类召回 ≥0.8、HTTP F1 ≥0.85）、修复（≥45/54 且每类 ≥12/18）、标签人工复核状态。性能/覆盖/依赖审计/资源探针/浏览器仅列出各自已记录的 `passed`，**未重算**。不豁免任何课程门槛。
- **`scripts/m6_validate.py candidates`**：区分 `execution_complete`（54 例齐备、无候选缺失、无环境错误）与 `passed`（数值阈值）；未完整返回 2，`--compare` 与已提交结果逐例比对动态裁决与固定测试，漂移返回 3，数值未达标仅在 `--require-threshold` 时返回 1。成功判定与审计共用 `gate.candidate_success`。
- **`ci.yml`**：普通 CI 对 54 个冻结候选真实容器重放并与提交记录比对（候选包不得缺失，不再 `hashFiles` 静默跳过）；新增 `m6-records`（记录完整性，无阈值）；`m6-acceptance` 仅 `workflow_dispatch` 手动运行，未达标时按设计失败，不设为默认 PR 门禁，没有 `continue-on-error`。
- **浏览器证据**：`playwright.config.ts` 按浏览器隔离 `outputDir`，`ci_workbench.py` 每次运行后把截图改名保存到 `frontend/test-results/evidence/<browser>-*.png`（解决 Chromium 截图被第二次运行清理、`foundation-*` 同名覆盖）。原始 Playwright JSON 只写入忽略的 `data/`，摘要只含 expected/skipped/unexpected/flaky 四个整数、`GITHUB_SHA`、`GITHUB_RUN_ID`；`browsers` 只列实际启动的浏览器。
- **`scripts/evaluate.py`**：增加 `--scope/--allowance` 与 `dev-ab`（仅开发集平衡子集的事后诊断，强制子额度）。
- **模块 C `scripts/analyze_detection.py`**：零预算、不改动原结果。把基线中每个发现分类为 TP 或具体类型的 FP（安全样例上、重复、位置错、CWE 错），按引擎来源/CWE/证据状态汇总，并给出"若采用某策略"的反事实表。**反事实表是事后探索**，不得据此在保留集上宣称改进。基线记录未保存 contributors 的 `confidence`，无法回填。

## C. 键盘与依赖

- **`SourceLines.tsx`**：光标有唯一权威（ref），按键处理读写 ref，因此同一批次内的 N→Enter、以及提交与被动 effect 之间到达的按键，都作用于上一键产生的位置；受控 `focusLine/focusKey/content` 变化在**渲染阶段**重置光标，早于任何布局 effect 或事件处理。Enter 在全部标记中查找（光标刚跨过 500 行窗口时仍有效）。保持绝对行号、全局 N/P、纯文本和 500 行 DOM 窗口。
- **`deploy/validator/requirements.in`**：`flask==3.1.3`（GHSA-68rp-wp8r-4726，低危，3.1.3 修复）。**`requirements.lock` 未改，也没有伪造哈希**，Codex 需在 conda 环境中重新生成/核对锁后再验收。

## 必须由 Codex 验证的事项

1. 后端：`python -m pytest backend/tests/test_m6_prompts.py backend/tests/test_m6_patches.py backend/tests/test_m6_budget.py backend/tests/test_m6_gate.py backend/tests/test_deepseek.py backend/tests/test_repairs.py backend/tests/test_evaluation.py backend/tests/test_m4_stage2.py backend/tests/test_m4_review.py`，再跑全量与 Ruff。重点：prompt 版本改变后既有回执/契约/覆盖测试是否需要更新期望。
2. 前端：`npm --prefix frontend test`（含 `M6Keyboard`、`M5Review`、`Workbench`）、`typecheck`、`build`。
3. 门禁脚本（在 AegisForge 环境）：`python scripts/m6_verify.py` 应返回 0；`python scripts/acceptance.py` 应返回 1（数值未达标）；篡改副本应返回 1/2。
4. 付费开发验证只用子额度，例如先备份账本文件再运行：`python scripts/evaluate.py dev-ab --run dev-ab-new-prompt --split dev --execute-real --scope dev-ab-new --allowance 96 --strategy hybrid --per-group 4`。旧提示一臂需在旧提交的工作树中运行（本脚本只依赖 `run_detection`），并使用不同的 `--run` 与 `--scope`，两臂合计不得超过剩余额度。
5. 修复候选复测应单独计划并标记事后诊断；`evaluation/experiment.py` 的 `generate_repairs` 只持久化固定的 `checks` 键，若要在 `repair.json` 中保留 `patch_diagnostic`，需 Codex 另行修改该文件（不在本轮授权范围）。

## 仍未证实

- 行寻址是否真正降低 `location_mismatch` 与 `PATCH_CONFLICT`、是否改变召回/精确率、输入 token 增加多少。
- 四个重复冲突样例的共同原因。
- JS 字符串上下文的两个候选业务回归能否由提示改善。
- 子额度并发在多进程下的锁等待行为、旧库 `ALTER TABLE` 在 Windows 上的表现。
- `m6-records` 与 `m6-acceptance` 在 GitHub 环境中的实际结果。
