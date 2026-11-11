# M6 三轮协作记录

用户要求先完成测试与实验，再基于结果使用gpt-to-claude、Sonnet5.5/high协作三轮最终优化。先执行完整冻结基线，得到检测Precision均值0.59218、修复36/54等实际未达标结果；基线完成后才开始Claude调用。模型预算795/1000，余205，任何优化验证继续共用原持久账本。完整实测见[test-report.md](test-report.md)。

原Session988b1845-c19b-4822-8b1b-2dfda07796c6，doctor/status认证有效、active且busy=false。CLI2.1.302，子进程明确配置claude-sonnet-5-5/high；原生assistant元数据已核对本轮实际模型为claude-sonnet-5-5，high只按配置声明、不伪造逐请求effort回执。凭证未传Claude，不读认证配置/.env/data；正常工作未中断。调用上限设43200秒以容纳持续工作，轮询返回不等于中断CLI。

## 第一轮：Claude只读审核，Codex核实

真实成功调用50affc6f-8252-4dd5-84a3-016bd087fd92，resumed/same_session=true，耗时412.572秒，37次内部工具循环（不是37轮协作），permission_denials空。

Claude审核实现与结果，指出位置错配几乎覆盖全部模型输出拒绝、重复样例的PATCH_CONFLICT、子额度缺失、实验数值与执行状态混在CI、截图被第二次Playwright清理、性能读请求口径等问题。提出行寻址输入/精确预检纠错、可审计门禁/子额度、零预算误报归因报告等模块，建议保持严格原文及行号校验，不用置信度过滤来事后抬高基线。

Codex实际核实：

- 逐条读取695个去重调用记录：66个MODEL_INVALID_OUTPUT中65个location_mismatch、1个evidence。Claude的91次Grep命中混有coverage重复，不能当调用数；已用实际账本纠正。
- 14个PATCH_CONFLICT的分布与审核一致，但缺少原始wire记录，只能确认重复失败，不能确认具体偏移/换行原因。temperature=0也不保证云模型确定性，不将三轮重复失败称为确定性证明。
- Claude对键盘初始光标的解释引用旧版useState(1)。git show7bc4a73与当前SourceLines逐字相同，M5就已经按focusLine初始化；反驳“本轮已修改初始值”及其对原始失败的确定性归因。新增M6Keyboard两个独立压力用例，实际运行2 failed：同一输入突发的N/Enter，以及controlled focus提交后被动effect前的P/Enter，均激活旧位置。确认残留同步问题，但不伪称它已完全解释最初偶发测试。
- 三轮基线中动态passed且被保守新增风险统计拒绝的记录为0，36个动态通过均计成功；保守判据没有改变本次36/54，但后续按严重性评价的能力局限仍应声明。
- 性能100次是读API、POST另10次提交，须明确分开口径。截图artifact确实只留下Firefox，与第二次运行清理目录一致。

第二轮将据上述确认、反驳和未证实项交接，不提前记录后续成功。原samples与baseline结果不改，检测优化后的开发验证不再声称独立保留评测。

## 第二轮：Claude 实现，Codex 交叉验证

原会话 `988b1845-c19b-4822-8b1b-2dfda07796c6`，run `5bf8777f-4b3c-487a-8b4c-9821ce3a81c6`；实际成功恢复、same_session=true、1125.063 秒、100 个内部工具循环、permission_denials=[]。模型原生记录为 claude-sonnet-5-5，high 由启动环境配置。内部循环不计作双方协作轮数。

Claude 实现行寻址与精确编辑预检、带事实的单次纠错、命名子额度、记录审计与严格验收分离、误报归因模块、键盘同步和分浏览器证据。Codex 在 Anaconda AegisForge 实际测试：366 后端通过/1 个 Windows symlink 跳过，52 前端通过，类型/构建/迁移/冻结清单检查通过；两个第一轮新增的确定性红测均转绿。新增后续防御测试另行记录。

Codex 发现并修正：审计错误绑定了日志派生控制文件，改为真正被修复记录哈希绑定的 `m6-controls-final-baseline.json`；CSV 核对应忽略行顺序并拒绝重复/错误数字；开发抽样分组须含 CWE 并以全部计划样本为分母；补充有界、拒绝重复键与非有限数的证据读取。记录审计实际返回 0（20 项），严格验收返回 1，未达标仍是源码精确率、修复总数、SQLi 修复及人工标签复核。没有放宽数值门槛。

Codex 通过 pip-tools 实际重新生成 validator 锁，将 Flask 3.1.2 升至 3.1.3；未手写哈希，旧依赖审计保留。通用提示补充 HTML script 内 JSON 编码还须转义小于号。

付费事后验证：固定开发子集两臂各 48 例，经真实上传 API/队列/worker，99 次实际调用。旧渲染器臂 47/48 模型完整、2 次 location_mismatch；新提示臂 48/48 完整、无无效输出。源码 TP=12 均不变，FP=5→3，Precision=0.705882→0.8，Recall=1；HTTP 两臂 TP12/FP1/FN0。仅一轮小规模开发诊断，旧臂是当前运行时配历史渲染器，不代表完整历史产品复现，也不证明单项改动因果。证据 `m6-postdev-ab.json`。

另对历史第 2 轮正确检测的 18 个目标生成后续候选，36 次调用，18 个均成功生成；这是暴露结果后的条件修复诊断，不能替代首次候选 36/54 基线。动态裁决待 CI 固定容器实测。全局调用累计 930/1000（含重试），仍用同一持久账本。

第三轮尚待动态证据及最终审查，未预先记作完成。
