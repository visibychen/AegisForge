# M3 智能检测设计（实施中）

日期：2026-11-07。关联 PLAN / R03、R04、R07 / Issue #4。当前为 Codex 第一轮实现，最终结果以实际审查和验证为准。

## 模型与密钥

接入 DeepSeek 固定 HTTPS Chat Completions 地址，仅开放 `fake` / `deepseek` 服务端模型别名，不接收浏览器指定 endpoint。默认 `deepseek-flash`、关闭思考模式、JSON Output；模型配置可选择服务器支持的 `deepseek-v4-pro`。选型核对 [模型文档](https://api-docs.deepseek.com/quick_start/pricing/)、[JSON 模式](https://api-docs.deepseek.com/guides/json_mode/)、[思考开关](https://api-docs.deepseek.com/guides/thinking_mode/)。

密钥仅从进程环境变量 `AEGISFORGE_DEEPSEEK_API_KEY` 读取；它不是 dotenv 配置字段，不从 `.env` 加载。Windows 启动助手仅为 API/worker 导入用户环境变量，兼容已打开的终端；Claude bridge 不导入它。源码、样例、交接、浏览器、数据库和日志不包含密钥。当前仅模型列表的鉴权连接已验证，真实三类检测演示尚未运行。

模型输出限制 128 KiB、4,096 输出 token、单次总耗时默认 60 秒；网络/429/5xx 最多重试两次，无效结构最多纠正一次，总计受任务最多 32 次调用预算限制。空白 JSON（即使 finish_reason=stop）、重复键、非有限数字、截断、伪造 UUID/行号/HTTP 字段/来源/verified 状态均不能被当作成功。证据须逐字出现在脱敏输入中；模型说明与建议再次脱敏，不用自由文本脱敏器重写已核对的源码证据。

## 持久队列与处理

迁移 `0002_detection` 新增发现、调用元数据和任务结果/取消/重试/租约所有者字段，保留 `0001` 不变。API 只入队，独立单 worker 运行静态规则和模型。SQLite `BEGIN IMMEDIATE` 原子领取，租约默认 60 秒、每秒心跳，所有发布必须核对租约标识。过期租约最多执行三次；取消持久化，手动重试最多两次。每次外部调用前写入 ModelCall 元数据，重启/手动重试仍累计预算，记录不含原始模型正文。

队列最多 10 个排队/运行作业，创建/重试每分钟最多 20 个。创建前检查快照完整性、最多 10 文件/10 MiB、合计 80,000 字符/8 块。扫描所有预算内分块，不只扫描规则命中的代码。rules 不调用模型；llm 不传规则提示；hybrid 保留两者。模型失败时保留规则发现并标记 partial，fake 不能宣称真实 LLM 完成。

## 第二阶段调整（Claude 实现，待 Codex 实测）

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
