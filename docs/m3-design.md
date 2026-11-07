# M3 智能检测设计

日期：2026-11-07。关联 PLAN / R03、R04、R07 / Issue #4。三阶段协作与本地验收已完成，PR 集成待审；见 [验证记录](m3-verification.md)。

## 模型与密钥

接入 DeepSeek 固定 HTTPS Chat Completions 地址，仅开放 `fake` / `deepseek` 服务端模型别名，不接收浏览器指定 endpoint。默认 `deepseek-flash`、关闭思考模式、JSON Output；模型配置可选择服务器支持的 `deepseek-v4-pro`。选型核对 [模型文档](https://api-docs.deepseek.com/quick_start/pricing/)、[JSON 模式](https://api-docs.deepseek.com/guides/json_mode/)、[思考开关](https://api-docs.deepseek.com/guides/thinking_mode/)。

密钥仅从进程环境变量 `AEGISFORGE_DEEPSEEK_API_KEY` 读取；它不是 dotenv 配置字段，不从 `.env` 加载。Windows 启动助手仅为 API/worker 导入用户环境变量，兼容已打开的终端；Claude bridge 显式移除该变量。源码、样例、交接、浏览器、数据库和日志不包含密钥。模型列表鉴权及三类真实开发演示已通过，证据见验证记录；不代表正式准确率评测。

模型输出限制 128 KiB、4,096 输出 token、单次总耗时默认 60 秒；网络/429/5xx 最多重试两次，无效结构最多纠正一次，总计受任务最多 32 次调用预算限制。空白 JSON（即使 finish_reason=stop）、重复键、非有限数字、截断、伪造 UUID/行号/HTTP 字段/来源/verified 状态均不能被当作成功。证据须逐字出现在脱敏输入中；模型说明与建议再次脱敏，不用自由文本脱敏器重写已核对的源码证据。

## 持久队列与处理

迁移 `0002_detection` 新增发现、调用元数据和任务结果/取消/重试/租约所有者字段，保留 `0001` 不变。API 只入队，独立单 worker 运行静态规则和模型。SQLite `BEGIN IMMEDIATE` 原子领取，租约默认 60 秒、每秒心跳，所有发布必须核对租约标识。过期租约最多执行三次；取消持久化，手动重试最多两次。每次外部调用前写入 ModelCall 元数据，重启/手动重试仍累计预算，记录不含原始模型正文。

队列最多 10 个排队/运行作业，创建/重试每分钟最多 20 个。创建前检查快照完整性、最多 10 文件/10 MiB、合计 80,000 字符/8 块。扫描所有预算内分块，不只扫描规则命中的代码。rules 不调用模型；llm 不传规则提示；hybrid 保留两者。模型失败时保留规则发现并标记 partial，fake 不能宣称真实 LLM 完成。

## 第二阶段调整（Claude 实现，Codex 已实测）

- **线协议分离（analysis-1.1）**：模型只输出 `app/llm/wire.py` 中的 `WireResult`（`schema_version=1.1`、findings、warnings），禁止额外键；来源、mode、完成性、artifact、证据截断与最终严重性均由服务端决定，服务端把通过校验的模型输出转换为 `sources=['llm']` 的 `Finding`。模型声称 `rule`/`verified`/`sources` 等一律为 `schema` 失败，不放宽来源校验。规则提示只给模型 `cwe`、位置与 300 字符证据，不含内部来源元数据。
- **稳定失败类别**：每次外部调用记录 `failure_category`（envelope/truncated/json/schema/incomplete/provenance/location/field/evidence/evidence_weak/ambiguous_evidence/span/credential），只含类别不含输入、原始正文或请求头（迁移 `0003_attempts`）。`finish_reason≠stop` 记为 `MODEL_OUTPUT_TRUNCATED`，不再浪费纠正调用；纠正提示只告诉模型失败类别。
- **证据定位**：源码证据须含至少一个 3 字符以上标识符且去空白后 ≥6 字符；服务端在声明范围内查找逐字证据，唯一命中则把位置精确收窄到证据实际首尾行，多处不同命中拒绝（`ambiguous_evidence`），超过 30 行拒绝（`span`）。HTTP 证据可为字段全文；局部引用须含字母数字。代价：模型只引用单个符号或省略号式证据会被拒并记 partial，依赖纠正一次。
- **合并**：完全链接分组（新成员须与组内每一成员重叠），宽区间不能串联两个独立 sink；主位置取成员交集，主说明优先取确定性规则；主严重性按 `severity-1.0`（源码 potential=high，HTTP attack_indicator=medium、potential=low），各来源原始判断保留在 contributors，不同即标 `severity_disagreement`。发现按数值位置写入 `position` 并据此分页。
- **健壮性**：每个分块的未知 provider/存储异常只使该块失败并保留已完成的规则与已验证结果；任务级未知异常以 partial（有发现时）发布。短事务对 SQLite `OperationalError` 有界重试 3 次；心跳瞬时故障不退出 worker，连续失败超过半个租约即停止执行；终态仅当前有效租约可发布。异常原文不回显。
- **预算与重试**：单任务 32 次跨尝试累计保留；新增服务器每 UTC 日 64 次调用次数上限（`AEGISFORGE_DAILY_MODEL_CALLS`，次数而非费用）。创建/重试前预检剩余调用至少覆盖每块一次，否则拒绝并保留原结果。重试不再删除旧发现：旧摘要入 `attempts`（最多 3 条），旧发现按 `attempt` 保留，可 `GET .../findings?attempt=N` 查看。
- **创新：逐分块覆盖台账**：任务摘要 `coverage` 为每个分块记录规则状态（ran / ast_unavailable / not_requested）与模型状态（pending / succeeded / simulated / failed + 错误码与失败类别 / not_requested）及模型发现数；前端显示缺口数并提示“无发现只对已覆盖区域有意义”。价值：把“部分完成”落到具体行区间，支撑报告中的分析范围与“空结果≠安全”；代价：摘要随分块数线性增长（≤8 块）；局限：只描述是否被分析，不衡量分析质量。

## 结果与页面

同文件/CWE/重叠行或同 HTTP 字段合并发现，保留每条来源判断；严重性冲突独立标记。任务、发现、调用元数据、分页历史、取消与重试均经 Bearer 鉴权。输入页可累积快照，检测区选择策略与模型、轮询、按 URL 中任务 ID 恢复查看、展开各来源判断；刷新需重新输入会话令牌。所有源码、模型内容按文本渲染。

不执行源码、请求或模型代码；M4 候选修复/动态验证尚未开放。M3 调试和真实演示只使用开发样例，保留集仅运行冻结完整性校验，不读取其检测结果调规则或提示词。人工标注复核仍为后续验收边界。

## 第三阶段收敛（双方两次真实讨论、Codex 实现）

新增 `0004_receipts`，不改写先前迁移。每个 attempt 保存白名单 `plan_json` 和持久的 `attempt_started_at`。创建时生成输入摘要与方案摘要；worker 重算校验，模型/提示词/输出参数/解析或脱敏版本变化时返回 `ANALYSIS_CONFIG_CHANGED`，在模型初始化/记账之前停止。历史旧任务无凭证时为 `ANALYSIS_PLAN_MISSING`，显式重试生成新凭证。

输入摘要只绑定类型与原始 SHA-256，排除随机 ID，保留重复输入的数量；方案摘要额外绑定规范化内容、字段和分块的哈希、范围、策略、模型别名/名称、prompt/wire/parser/redaction/rule/severity 版本及系统提示词摘要、输出参数。凭证不含源码、文件名、私有路径、密钥、标签或模型自由文本。超时/次数/租约等操作限额不参与方案摘要；计划限额另存 `limits`，其中本次尝试总时限固定，其他运行限额按进程当前配置执行。

任务详情包含凭证，前端可展开摘要并下载凭证与去文件名的覆盖条目；不新增导出接口、不下载完整任务 JSON。重试在同一事务归档旧摘要、旧凭证并生成新方案，旧发现仍可按 attempt 读取。凭证没有数字签名，不证明检测正确；供应商可能滚动更新模型，不能保证相同摘要得到相同输出。选择依据见 [ADR 0002](decisions/0002-m3-analysis-receipts.md)。

密钥格式限定无须 JSON 转义的 `[A-Za-z0-9._-]{16,256}`；不合规不开放 deepseek。上传与存量快照读取精确检查完整服务密钥，覆盖 BOM/CRLF、文件名、解析后 HTTP 私有字段，命中即拒绝；不检测前缀，不依赖 sk 通用模式。Provider 对最终 UTF-8 请求体检查后才 reserve，并发送同一份 bytes；字段/规则提示/系统及纠正提示均在检查范围。通用脱敏仍是启发式，不能保证发现任意未知/编码/拼接的其他凭据。

总时限默认 180 秒，首次 claim 固定开始时刻；租约恢复不能重置它。规则/模型循环受 deadline 约束；超时取消在途请求，调用记为 cancelled，当前覆盖块记 `TASK_TIMEOUT`，保留已核对发现并在 timeout 块外发布 partial/failed。用户取消优先。同步解析、数据库锁等待和最终发布有界但不能被 asyncio 强制抢占，截止属于协作式取消，可能超过阈值少量清理时间。规则覆盖只在 detect 返回后标记 ran；未运行块保持 pending，并计入缺口。rules-only 明确标记没有模型分析。

新增 `location_mismatch` 区分“证据存在但定位错误”和“证据编造”，仍拒绝范围之外的定位。未实现增量重试、人工复核队列。配置漂移后重试仍占手动次数，是保留分歧；免费刷新留 M5 提案。供应商模型标识指纹与 M4 发现锚点留后续设计，未冒充已实现功能。
