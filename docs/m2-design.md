# M2 输入接入、特征提取与开发数据设计（第 2 轮草案）

> 状态：M2 第 2/3 轮由 Claude 实现，测试与运行结果以 Codex 实际执行为准；本文不记录未执行的结果。

## 1. 公开视图与私有视图

| 视图 | 内容 | 去向 |
| --- | --- | --- |
| 公开（已脱敏） | `content`、`fields`、`field_meta`、`features`、`chunks`、规则 `evidence`、展示名 | API 预览、前端、后续模型输入、日志与导出 |
| 私有（仅内存） | 源码原文 AST（`private_tree`）、HTTP 未脱敏规范化值（`private_fields`） | 仅规则匹配；`build_preview` 不读取，禁止序列化 |

- 源码规则基于**原文** AST；证据取自脱敏视图的**同号行**。源码脱敏只改写字符串字面量、f-string 主体与注释，并强制保持换行数，故行号一致且代码结构不被破坏（修复 `def run(cmd, token=None)` 被改坏而规则静默为 0 的问题）。
- HTTP 规则匹配私有规范化值；敏感字段命中时证据为 `[REDACTED]（敏感字段命中攻击特征，原值不展示）`，不编造原文。
- 脱敏为尽力而为：识别凭据名（按单词/驼峰切分）、赋值/比较/字典键上下文、已知密钥格式（PEM、AKIA、ghp_、sk-、xox、JWT）、Basic/Bearer、URL userinfo、HTTP matrix 参数与长不透明路径段。变量名无提示、跨表达式拼接或非常规编码的秘密仍可能漏出；不对“脱敏完备”作承诺。

## 2. 边界与预算

- 预算在任何正则之前检查：≤80,000 字符、单行 ≤12,000；HTTP 头行 ≤8,192、≤100 个头、≤1,000 字段、JSON ≤32 层。所有脱敏正则锚定词边界并限定量词，保持线性。
- 拒绝：孤立 CR、U+0085/U+2028/U+2029、控制字符；HTTP 的 multipart/XML/其他正文类型、分块传输、重复头、Content-Length 非数字或与正文不符（允许 LF/CRLF 与末尾换行两种计数）。
- URL 解码总计 ≤2 次（含 `parse` 本身），超过时字段 `decode_limited` 并给出警告。`field_meta` 记录部位、脱敏后的名称、解码次数及原始行/列区间（仅数字，不含原值）。
- 上传在线程池中完成解析；提交前完整生成并序列化预览，任何失败都不会落盘或入库，因此不会产生“永久 500”的快照。
- 规则线索上限 100，超限返回 `rule_findings_truncated=true` 与警告；AST 不可用时显式警告“源码规则未运行”。
- 文件系统：`data_dir` 与 `artifacts` 不得为符号链接/junction，快照独占创建，POSIX 下 `O_NOFOLLOW` 读取并校验常规文件。**不防御**同一系统用户下的恶意进程竞争（本地单用户课程演示的威胁模型之外）。写盘后、提交前崩溃可能留下孤儿文件，尚无回收任务。

## 3. 规则（rules-1.1）

- 源码：导入别名解析、模块常量与函数内一跳（≤3 跳）赋值解析、按类别的净化函数（XSS 的 escape 不能净化 SQL）、常量字典白名单查找、`Markup(...).format`。去除 `ast.unparse`，全部迭代遍历，`1 << n` 不再误报。
- HTTP 模式与 rules-1.0 **保持一致**：只允许依据开发集调整，避免向保留集家族靠拢。
- 已知局限：跨函数数据流、生成式/推导式、未列出的 sink（如 `asyncio.create_subprocess_shell`、`bash -c` argv）。开发集中刻意包含规则会误报/漏报的困难例。

## 4. 数据协议（PLAN 7.2）

- `samples/dev/`：48 源码（每 CWE 8 漏洞/8 安全，一对一个家族）+ 24 HTTP（每类 4 攻击，12 正常，与攻击同家族）。`manifest.json` 记录标签、行范围、锚点；`families.json` 记录家族维度与 `distinctness_note`。
- `samples/holdout/catalog.json`：预登记 36 个源码家族（每 CWE 12 对）与 18 个 HTTP 家族（每类 6 攻击 + 6 正常），共 72 + 36 例的标签；**内容尚未编写**（status=planned）。
- 反“改名伪造家族”：验证器对源码做 AST 规范化指纹（标识符重编号、常量抹除、保留 API 与结构），跨家族或同家族正反例指纹相同即失败；家族维度元组在同 CWE 内必须唯一。
- 划分由作者指定而非随机：保留集刻意包含开发集未出现的模式，用于衡量泛化；作者与规则作者相同，独立性仅限“未看到评测结果”。`human_review` 一律为 `pending`，只有用户本人核对后才能修改。
- 哈希由脚本从实际字节计算，绝不手写。M3/M4 只能调用 `load_dev_samples`。

## 5. 执行命令（Anaconda AegisForge 环境，仓库根目录）

```powershell
conda run -n AegisForge python evaluation/datasets.py lock-dev   # 首次生成 samples/dev/hashes.json
conda run -n AegisForge python evaluation/datasets.py check      # 结构、划分、指纹、哈希
conda run -n AegisForge python evaluation/dev_rules_report.py    # 仅开发集的规则样本级统计
```

M2 数据冻结完成条件：第 3 轮写入保留集内容并锁定哈希，且在任何 M3 提示词调优之前提交。此前 M2 不得标记为完成。
