# M2 输入接入、特征提取与评测数据设计

> 状态：M2 三轮实现与 Codex 审查完成，本地测试和数据冻结已实际通过。证据见 [M2 验证记录](m2-verification.md)；M3 按用户最新指示暂缓、未开始。

## 1. 公开视图与私有视图

| 视图 | 内容 | 去向 |
| --- | --- | --- |
| 公开（已脱敏） | `content`、`fields`、`field_meta`、`features`、`chunks`、规则 `evidence`、展示名 | API 预览、前端、后续模型输入、日志与导出 |
| 私有（仅内存） | 源码原文 AST（`private_tree`）、HTTP 未脱敏规范化值（`private_fields`） | 仅规则匹配；`build_preview` 不读取，禁止序列化 |

- 源码规则基于**原文** AST；证据取自脱敏视图的**同号行**。源码脱敏只改写字符串字面量、f-string 字面量片段与注释，并强制保持换行数，故行号一致且代码结构不被破坏。
- 公开特征单独标记 Flask 请求输入来源（含导入别名）、调用与关注 sink、字符串构造及全局行号；语法失败时提供明确的文本调用线索，不能冒充 AST 规则发现。输入页可展开查看前 30 项，不把参数化查询等合法 sink 直接当作漏洞。
- 非敏感上下文的 f-string：逐个字面量片段（`FSTRING_MIDDLE`）脱敏；若分词器偏移与原文不符（如 `{{` 转义），且整段 f-string 主体含可识别凭据，则保守遮盖整段主体，行数不变。不对所有字面量整体遮盖，以保留 SQL/HTML 构造证据。
- Codex 最终审查补上表达式内嵌字符串的反例（如 `f"{'Bearer credential'}"`）：若片段改写后主体仍含可识别凭据，保守遮盖该主体，避免遗漏表达式里的字面量。
- 认证方案：`Bearer`/`Token` 后 ≥8 字符一律遮盖（含纯字母）；`Basic` 在值呈 base64 形态（长度为 4 的倍数或含数字/`+/=`）时遮盖；`Digest` 后跟参数列表时遮盖其余部分。代价：英文说明文字（如 “Token refreshed”、“Basic workflow”）可能被误遮，只影响展示/模型文本，不影响规则（规则基于原文 AST）。
- HTTP 规则匹配私有规范化值；敏感字段命中时证据为 `[REDACTED]（敏感字段命中攻击特征，原值不展示）`，不编造原文。
- 脱敏为尽力而为：变量名无提示、跨表达式拼接或非常规编码的秘密仍可能漏出；不对“脱敏完备”作承诺。

## 2. 边界与预算

- 预算在任何正则之前检查：≤80,000 字符、单行 ≤12,000；HTTP 头行 ≤8,192、≤100 个头、≤1,000 字段、JSON ≤32 层。所有脱敏正则锚定词边界并限定量词，保持线性。
- 分块（inputs-1.2）：按行切分、块内以 LF 连接且块尾不带 LF，每块 ≤12,000 字符（与 `AnalysisRequest` 上限一致），覆盖全部行、行号为全局行号、重叠 ≤1,000 字符；不可能前进时显式 `LINE_BUDGET` 拒绝，绝不产生空块。
- 拒绝：孤立 CR、U+0085/U+2028/U+2029、控制字符；HTTP 的 multipart/XML/其他正文类型、分块传输、重复头、Content-Length 非数字或与正文不符（允许 LF/CRLF 与末尾换行两种计数）。
- URL 解码总计 ≤2 次（含首次），超过时字段 `decode_limited` 并给出警告。`field_meta` 记录部位、脱敏后的名称、解码次数及原始行/列区间（仅数字，不含原值）。JSON 字段只有路径，没有原始列区间。
- 上传在线程池中完成解析；提交前完整生成并序列化预览，任何失败都不会落盘或入库。
- 规则线索上限 100，超限返回 `rule_findings_truncated=true` 与警告；AST 不可用时显式警告“源码规则未运行”。
- 证据：规则证据是脱敏原文的前 4,000 字符摘录，超长时 `evidence_truncated=true`，不拼接任何省略文字；前端以独立标签“证据已截断”显示。模型生成的发现此字段应为 false（M3 校验）。行级映射；列级高亮留待 M5。
- 文件系统：`data_dir` 与 `artifacts` 不得为符号链接/junction，快照独占创建，POSIX 下 `O_NOFOLLOW` 读取并校验常规文件。**不防御**同一系统用户下的恶意进程竞争。写盘后、提交前崩溃可能留下孤儿文件，尚无回收任务。
- 失败清理只移除本次成功创建的文件，随机键碰撞或独占创建失败不会删除既有快照；外层 Content-Length 在整数转换前校验格式和位数。

## 3. 规则（rules-1.1）

- 源码：导入别名解析、模块常量与函数内赋值解析（≤3 跳）、按类别的净化函数、常量字典白名单查找、`Markup(...).format`。全部迭代遍历。
- HTTP 模式与 rules-1.0 保持一致。M2 第 3 轮未改动任何规则逻辑（仅新增 `evidence_truncated` 输出字段）；保留集编写过程中没有对其运行检测。
- 开发集样本级结果（Codex 实测）：源码 24 TP / 23 TN / 1 FP（SRC-XSS-07-S，跨函数生成式），HTTP 12 TP / 11 TN / 1 FP（HTTP-CMDI-03-N，Markdown 反引号）；未为迁就规则修改任何标签。
- 已知局限：跨函数数据流、生成式/推导式、未列出的 sink（如 `asyncio.create_subprocess_shell`、`bash -c` argv）。

## 4. 数据协议（PLAN 7.2）

- `samples/dev/`：48 源码（每 CWE 8 对）+ 24 HTTP（每类 4 攻击 + 4 同家族正常）。
- `samples/holdout/`：严格依据预登记 `catalog.json` 编写的 72 源码（每 CWE 12 对）+ 36 HTTP（每类 6 攻击 + 6 同家族正常）；`manifest.json` 记录标签、行范围与锚点，家族、维度与标签未改动。
- `samples/holdout/controlled_repairs.json`：从保留集源码漏洞例中每类预登记 6 个、共 18 个受控修复样例，状态 `planned`；M4 才补固定容器测试、正常输入、安全回归断言与人工参考修复。它们同时属于检测测试集，不作为新增独立样本。
- 反“改名伪造家族”：AST 规范化指纹（标识符重编号、常量抹除、保留 API 与结构）跨家族相同即失败；同一家族的正反例允许仅字面量不同（如模板去掉 `|safe`）。家族维度元组在同 CWE 内唯一。
- 划分由作者指定：保留集刻意包含开发集未出现的模式。样例作者与规则作者同为 AI 助手（Claude），独立性仅限“未看到评测结果”；`human_review` 一律 `pending`，只有用户本人核对后才能修改。
- 冻结：`samples/freeze.json` 锁定元数据（dev/holdout manifest、families、catalog、受控修复登记）、全部 bundle 文件与 180 个输入的 SHA-256（LF 规范化后计算，避免 Git 换行转换影响）。正式 `check` 默认要求冻结存在且一致；`--structure-only` 仅用于冻结前。重新冻结须显式 `--refreeze` 并记录原因。
- 冻结前先做完整结构校验；校验失败保留原锁，成功后原子替换冻结文件。测试在临时副本验证篡改检测、显式重新冻结、失败保留和 CRLF/LF 一致性，不修改正式保留集。
- 访问规则：开发代码只能调用 `load_dev_samples`。验证器对保留集只做完整性、语法与解析预算检查，不运行检测或评测；任何据保留集结果调整规则/提示词的行为都会使其失去独立评测资格（PLAN 7.2）。

## 5. 执行命令（Anaconda AegisForge 环境，仓库根目录）

```powershell
conda run -n AegisForge python evaluation/datasets.py check --structure-only  # 冻结前结构检查
conda run -n AegisForge python evaluation/datasets.py freeze                  # 生成 samples/freeze.json 与 dev/hashes.json
conda run -n AegisForge python evaluation/datasets.py check                   # 正式检查（要求冻结一致）
conda run -n AegisForge python evaluation/dev_rules_report.py                 # 仅开发集的规则样本级统计
```

M2 数据冻结完成条件：上述 `freeze` 由实际运行生成并在任何 M3 提示词调优之前提交；人工核对仍为 pending，须如实报告。
