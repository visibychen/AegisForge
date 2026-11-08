# M4 候选补丁与验证设计（实施中）

日期：2026-11-08。Refs #5，PLAN R05/R06；基于待审 M3 PR #13，新分支 feat/5-repair-validation。

按用户要求完成三轮：Codex开发/Claude审核错误并提出创新；Claude修复并实现创新/Codex审核及提出改进；双方多次实际讨论后Codex最终优化。Claude继续原会话，固定claude-sonnet-5-5与high，运行期间不并发修改文件。

修复绑定发现ID、源快照SHA-256和原检测凭证。模型仅可返回有界行编辑和原文，服务端生成候选及unified diff，原输入不覆盖。首版限单块Python源码，含脱敏替换的源码拒绝自动修复，避免把凭据占位符写回程序。HTTP明确source_required。

修复使用独立repair记录与持久作业，复用模型调用元数据及日预算；scan领取只处理scan作业，repair领取维护自身状态，不改写父检测。每个候选独立，生成、语法/补丁、规则、LLM复检分别留证，fake不宣称真实修复。取消和租约失效阻止终态发布。

动态验证只由受信独立CLI runner执行，不导入模型密钥、不接受模型给定命令/镜像/测试路径。匹配预登记开发样例的原始哈希后，使用固定镜像、固定入口与冻结安全/业务测试；候选只能替换源码。Docker网络关闭、非root、只读根目录、cap-drop、no-new-privileges、CPU/内存/PID/tmpfs/输出/时间限制，无Docker socket或主机私有目录挂载。缺Docker或工具失败记error，不写passed。

M4开发与三类真实闭环仅使用开发样例；M2预登记18个保留集修复例及其冻结标签不用于提示词调优，正式18例实验留M6。动态通过只表示固定测试集通过，不宣称无其他漏洞；普通上传始终缺动态证据，标unverified。

第一轮验收：编辑原文/越界/重叠/秘密/语法，HTTP边界，队列/取消/租约，真实/fake与复检状态；容器参数及拒绝任意源码执行；三类开发例检测→真实模型补丁→静态/LLM复检→固定安全与业务测试。审查阶段还须提出可验收创新，并在后续轮实现。

## 第二阶段（Claude 实现，待 Codex 实测）

以下为实现意图与设计取舍；任何“通过”都只能在 Codex 实际运行后记录。

### 修复门禁账本与变更影响镜头（创新）

- **发现差异**：`services/patch_review.py` 按原文与候选的真实行差异（`difflib.SequenceMatcher`，而非模型声称的编辑范围）建立行映射，把候选后的发现分为 `persisting`（目标仍在）、`preexisting`（同文件另一处原有问题）、`introduced`（基线无法解释）。基线是父检测对该快照已保存的合并发现并上规则对原文的重算。解决了“同文件两处同 CWE 修一处永远失败”“同 CWE 新位置不被发现”“模型发现被当作新增”。
- **结构保持**：对前后 AST 比较定义（含嵌套）、参数、装饰器：删除/改名、改签名、改装饰器、新增 `eval/exec/compile/__import__/pickle/marshal/yaml.load`、超过 60% 的整体重写（仅对 ≥40 行文件）直接拒绝并报 `PATCH_SCOPE`，原因保存在 `checks.impact` 中。`os.system/os.popen/shell=True` 新增、远离漏洞的非导入编辑、函数被掏空等只给提示，不拒绝。没有任何定义的小脚本不会被机械拒绝。
- **门禁账本**：每个检查是一行（语法、补丁、结构、规则目标/新增、模型目标/新增、动态安全/业务），状态 `passed/failed/skipped/pending/error`。裁决规则：任一失败→`failed`；否则任一错误→`error`；否则全部通过且为真实模式→`passed`；其余→`unverified`。fake 模式恒为 `unverified`，不运行规则对比，模型复检失败也是 `unverified`。已确定的静态失败优先于动态工具错误。
- **补丁自检**：diff 对不以换行结尾的行输出 `\ No newline at end of file`；服务端用严格的 unified-diff 应用器回放 diff，必须逐字节还原候选，否则 `PATCH_DIFF_MISMATCH`。替换文本必须保留行结束（`PATCH_NEWLINE`），候选须满足快照字符规则（无 CR/控制字符/行分隔符/中途 BOM，`PATCH_ENCODING`），`schema_version` 为 `Literal`。

### 分阶段保存、预算与租约

- 生成并通过补丁与规则复检后，候选与证据先落库（仍为 running）；模型复检失败、超时或返回不完整时，候选以 `unverified` 保留，`checks.review` 记录原因。发布前再检查父任务状态、`retries` 与锚点，发现父检测已重试则为 `REPAIR_STALE` 且不可下载或申请验证。
- 同一发现同时只有一个排队/运行中的修复（重复请求复用），累计最多 3 个；真实模型修复创建前预检本任务与服务器日预算至少还能覆盖一次生成加一次复检。
- 心跳与 M3 一致：瞬时存储错误不退出，超过半个租约才停止；租约恢复时把遗留 `started` 调用标为 `interrupted` 并写 `finished_at`。**总时限 180 秒仍锚定首次开始时间**：经过时间包含 worker 停机与租约恢复间隔，不重新给 180 秒，避免崩溃循环无限延长。

### 动态验证可信边界

- 容器内分为两个进程：`harness.py`（driver）持有全部断言与浏览器；`target.py` 只加载候选并在容器回环地址上提供 HTTP，所有标准流关闭。driver 在运行候选之前调用 `prctl(PR_SET_DUMPABLE, 0)`，使同 uid 的 target 无法读取其 `/proc/<pid>/mem|environ|fd`；无法设置则以退出码 3 失败（不运行候选）。候选输出不进入判分通道；driver 只打印唯一一行 JSON，并回显宿主经 stdin 一次性传入的随机 nonce 与候选文件 SHA-256。
- XSS 用真实导航（`page.goto`）而非 `set_content`，浏览器自行遵守候选的 `Content-Type`；SQLi 在安全测试后只读核对数据库未被破坏；CMDi 的 `ping` 桩记录 argv，仅对文档保留地址 `192.0.2.77` 返回非零，因此写死 True/False 或不调用 ping 的候选无法同时通过两个业务测试，攻击载荷必须作为单个 argv 或被拒绝。
- 宿主严格校验：恰好一行、固定键集合、固定测试名与顺序、布尔类型、nonce 与候选哈希、退出码与整体结论一致；空输出（`VALIDATION_NO_RESULT`）、超限、超时、镜像过期、环境异常使用互不相同的错误码并一律记 `error`，不会成为通过或失败的伪造。
- 动态记录绑定 `run_id`、请求/开始/结束时间、源/候选 SHA-256、测试集与登记表哈希、镜像 id 与 driver 指纹，并附完整性摘要；`passed/failed` 只有在摘要、候选哈希、源哈希都匹配时才被采信，否则门禁为 `error`。摘要是防误改/随手改的完整性记录，**不是数字签名**，不防御能同时改写记录与摘要的数据库写入者。
- 运行状态机有界：`running` 超过 120 秒视为 runner 崩溃，下一次运行前改为 `VALIDATION_INTERRUPTED`；未知样例记 `CONTROLLED_SAMPLE_REQUIRED` 而不循环；重复申请在 pending/running 时拒绝；pending 可取消，running 通过 `cancel_requested` 由 runner 1 秒内轮询并回收容器。
- 容器带 `org.aegisforge.validation=1` 标签与 `aegisforge-validation-` 名称前缀，runner 启动只清扫同时满足两者的孤儿；`docker rm` 失败也会回收本地 CLI 子进程。
- 限制说明：代码路径隔离（API/worker 不导入 Docker）不等于 OS 权限隔离；同一 Windows 用户下的进程仍可能有 Docker 权限，OS 层隔离留待最终部署阶段。Chromium 因 `cap-drop ALL` 与 no-new-privileges 以 `--no-sandbox` 运行，依赖容器边界。
- 指纹范围现在包含 `Dockerfile`、`requirements.lock`、`harness.py`、`target.py`、`ping_stub.py`（`validator_fingerprint()` 为构建脚本与 runner 的唯一来源）。**旧镜像必须重新构建**，否则 `VALIDATOR_IMAGE_STALE`。

### 待 Codex 实测

后端 pytest（含 `test_m4_review.py` 七个原红测试、`test_patch_review.py`、`test_m4_stage2.py`）、Ruff、前端 typecheck/Vitest；`python scripts/build_validator.py` 后三类开发例容器实测，确认 driver 不被候选读取/伪造；原脆弱版本（源码例的 V 版）在 `failed`，安全版在 `passed`。
