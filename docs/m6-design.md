# M6 实验后优化设计

2026-11-12新增的可达定义/语义复核/同流合并与版本化诊断见[ADR0005](decisions/0005-m6-semantic-adjudication.md)和[本轮质量记录](m6-quality-2026-11-12.md)。以下为11月11日历史设计及当时结论。

2026-11-11，Refs #7。A–C及“待验证”列表保留第二轮Claude交接时的设计和不确定性；第三轮后的最终状态见末节及[测试报告](test-report.md)。没有把交接时的推断当成已运行证据。

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
- **第二轮交接时`deploy/validator/requirements.in`**：`flask==3.1.3`（GHSA-68rp-wp8r-4726，低危，3.1.3修复）。Claude当时未改锁，之后Codex已在conda中实际重新生成精确哈希锁并审计。

## 第二轮交接时待验证的事项

1. 后端：`python -m pytest backend/tests/test_m6_prompts.py backend/tests/test_m6_patches.py backend/tests/test_m6_budget.py backend/tests/test_m6_gate.py backend/tests/test_deepseek.py backend/tests/test_repairs.py backend/tests/test_evaluation.py backend/tests/test_m4_stage2.py backend/tests/test_m4_review.py`，再跑全量与 Ruff。重点：prompt 版本改变后既有回执/契约/覆盖测试是否需要更新期望。
2. 前端：`npm --prefix frontend test`（含 `M6Keyboard`、`M5Review`、`Workbench`）、`typecheck`、`build`。
3. 门禁脚本（在 AegisForge 环境）：`python scripts/m6_verify.py` 应返回 0；`python scripts/acceptance.py` 应返回 1（数值未达标）；篡改副本应返回 1/2。
4. 付费开发验证只用子额度，例如先备份账本文件再运行：`python scripts/evaluate.py dev-ab --run dev-ab-new-prompt --split dev --execute-real --scope dev-ab-new --allowance 96 --strategy hybrid --per-group 4`。旧提示一臂需在旧提交的工作树中运行（本脚本只依赖 `run_detection`），并使用不同的 `--run` 与 `--scope`，两臂合计不得超过剩余额度。
5. 修复候选复测应单独计划并标记事后诊断；`evaluation/experiment.py` 的 `generate_repairs` 只持久化固定的 `checks` 键，若要在 `repair.json` 中保留 `patch_diagnostic`，需 Codex 另行修改该文件（不在本轮授权范围）。

## 第二轮交接时尚未证实

- 行寻址是否真正降低 `location_mismatch` 与 `PATCH_CONFLICT`、是否改变召回/精确率、输入 token 增加多少。
- 四个重复冲突样例的共同原因。
- JS 字符串上下文的两个候选业务回归能否由提示改善。
- 子额度并发在多进程下的锁等待行为、旧库 `ALTER TABLE` 在 Windows 上的表现。
- `m6-records` 与 `m6-acceptance` 在 GitHub 环境中的实际结果。

## 第三轮后最终实现与已验证边界

- `analysis-1.3`补充Flask常量模板/上下文、Markup方法参数转义、命令解释与数据参数的通用语义。只发静态文本，严格原文/行号/输出校验不变；未增加按样例、来源或置信度过滤。`repair-1.2`保留。12例定向开发回归TP9/FP1/FN0，无输出拒绝；不构成独立保留验收。原48例A/B和18例后续修复的协议指纹保持1.2历史版本，不覆盖重跑。
- 修复诊断实际18个全部生成，固定容器综合通过15个，3个业务/安全失败保留；14次基线PATCH_CONFLICT的具体线协议根因依然未被证明。行寻址及预检是结构性改进，不能把小样本结果泛化为不会冲突。
- `candidate_success`必须有三个固定测试名/真实布尔结果且状态一致，delta两个引擎的introduced必须是明确空列表；缺失不是干净复检。审计逐字段对账候选束，绑定登记ID/CWE、候选哈希、固定测试、镜像/runner摘要与冻结V/S源码摘要，重算控制accepted。真实Docker重放仍是运行证据，不将JSON自洽视为真实性证明。
- `m6_freeze_guard.py`核对预调优提交`e527d91fe49fd1e0991c15f2a3e2b9d3d7d9be20`中的samples及所有原baseline。普通记录CI取完整Git历史运行；不是密码签名，修改守卫本身仍需代码审查。
- 无scope预留也必须避开已承诺子额度，原子并发测试验证；全局不超过1000。未加入额度retire/释放API，当前无需释放；最终942次，两个命名scope剩余仍被保护。`remaining()`为显示用快照，真正准入在事务中决定。
- `core_accepted`只指核心实验，辅助记录损坏退出2且不回显。历史人工标志与当时manifest核对，人工身份不能由程序验证；本次历史pending保留。人工复核附件及新的独立保留集属于后续验收，未伪造完成。
- 光标在渲染期重置state、layout effect同步ref，事件同步写ref；未在渲染期写ref。保留两项原失败断言并各补StrictMode版本，6个键盘压力用例均实际通过。
- Flask精确锁3.1.3及45个包的升级后审计已实测；原3.1.2报告不回写。`m6-records`在GitHub已实际通过；严格数值CLI仍返回1，手动严格CI未声称已运行。最终浏览器/全量CI证据见测试报告。

后续可选创新：AST中性static_facts、独立人工复核附件、子额度退役、细化新增风险等级及更广的框架语义，均不在本次已完成声明内。性能100次读API与另10次提交仍分开，未重新付费运行性能实验。

最终浏览器CI因Ubuntu源DNS无法安装系统库，Codex改为实际核验digest的官方Playwright镜像（版本与项目1.64.1精确匹配），保留host Node24、非root UID、cap-drop和无Docker socket/模型key；host网络仅连接本机受信服务。与固定候选隔离容器分开。运行43041838326中七项常规CI全通过，Chromium5通过/1显式skip、Firefox1通过且无波动，10张截图同时留存；严格数值作业仍未运行，本地strict依然not_accepted。详细来源与保留失败见测试报告。
