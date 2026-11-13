# M4 三阶段协作记录

2026-11-08，Refs #5。使用用户指定的 gpt-to-claude skill，继续原会话 `988b1845-c19b-4822-8b1b-2dfda07796c6`，没有新建或替换。四次成功 CLI 调用均 resumed/same_session=true；第三阶段有两次双方真实交流，不把内部工具循环数算作协作轮数。

Claude 子进程固定 `ANTHROPIC_MODEL=claude-sonnet-5-5`、`CLAUDE_CODE_EFFORT_LEVEL=high`。原生 assistant 记录已核对实际模型 claude-sonnet-5-5；high 由官方配置环境变量指定，不伪称已取得供应商逐请求 effort 回执。CLI 2.1.302。每次交接均先简介课程项目、PLAN 范围、已有实现、审查和创新要求，剔除 DeepSeek key，仅传必要文件入口。Claude 无 Shell/网络/子代理，第二阶段仅额外开放 Edit/Write；Codex 顺序接手测试与最终修改。

| 阶段 | 成功调用 ID | 实际工作与 Codex 核实 |
| --- | --- | --- |
| 1 Codex 开发，Claude 审 | `4c324563-762c-4d7d-a616-fc495c7e2848` | 初稿 c7b7f07：受限编辑、候选/diff、持久作业、复检、最小 UI 和容器 runner。Claude 指出复检失败丢候选、同 CWE 原有/新增风险误判、fake 裁决、diff 换行与线协议等缺陷，并提出“修复门禁账本 + 变更影响镜头”。Codex 读实现并以 fc5f75a 的七个红测试复现问题，另验证父重试期间的锚点失效。 |
| 2 Claude 开发，Codex 审与创新提案 | `19584724-74a1-4ad3-a40c-7280058648a8` | Claude 实现两阶段候选保存、AST 结构审查、门禁、差异分类、预算/租约和 driver/target 分进程等，ec67bb1。Codex 独立运行 295 后端通过/1 平台跳过、25 前端通过；七个红测试转绿。再次找出不等长替换块复用一个基线漏洞的问题，用新增红测试复现；提出轻量执行契约、候选进程限制与部署权限隔离。 |
| 3A 实际讨论 | `74f409d7-aaae-4c7e-8e3a-e8ab233fb66f` | 讨论一对一槽位、移动代码证据指纹、seccomp 的实际可用性、watchdog、孤儿误删、候选重复落库与契约。Codex 在固定容器中验证 libseccomp 可加载且 self-kill 探测被拒，澄清 SQLi 原始撇号业务失败是待检缺陷。 |
| 3B 复核与收敛，Codex 最终优化 | `f7e5743c-fd59-41b5-a174-b9d7456275e8` | Claude 实读开发 SQLi 与 delta，撤回“原 V 业务必须全过”的要求；接受 V 暴露安全失败、参考 S 全过的验收。补充候选可控文件的 FIFO/符号链接/大小边界、契约生成前捕获、5 秒回收边际及同 UID 局限。双方收敛后，Codex 实现最终代码、Compose、实际动态/真实模型/浏览器验收。 |

第一、二、3A、3B 调用分别约 443、1120、172、130 秒。Claude 正常工作期间持续等待，没有主动中断或因默认短超时换会话。结束后 status 为 active、busy=false、last_run=success。

最终修正包括：一对一风险匹配、执行契约、候选 artifact 复用、25 秒看门狗、导入前 guard、受限文件读取、逐测试异常、年龄受限清扫、75 秒陈旧记录恢复，以及真正无 Docker 权限的 API/worker 部署。Codex 实测再发现并修复 Windows/daemon 挂载路径转换和 API 冷启动直接写修复时的数据库初始化问题；均有回归验证。

实际开发例三类真实修复均通过，外部模型请求为三次检测 + 六次生成/复检；另一次真实浏览器 XSS 闭环为三次请求，共 12 次 Chat Completions，没有将静态、fake 或规则命中冒充真实模型结果。最终 driver 异常隔离调整后，复用原三个真实候选再验，零额外模型请求。

范围取舍：不加 0006、不加同数据库信任域的 HMAC；执行契约记录本次实际配置，不许诺未来排队执行不漂移或确定性输出。同 UID 的补充 seccomp 与 --no-sandbox Chromium 仍有残余风险，明确写在 ADR。后续“修复解释卡”导出作为 M5 创新提案，不宣称已经交付。18 个冻结保留例的正式实验仍留 M6。详见 [M4 验证](m4-verification.md)、[ADR 0003](decisions/0003-m4-controlled-validation.md)。
