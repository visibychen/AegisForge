# M6 测试与实验报告

日期：2026-11-11，Refs #7，[PR #16](https://github.com/visibychen/AegisForge/pull/16)。冻结基线实验与三轮Claude协作均已完成；M6正式数值验收未通过。协议见[m6-protocol.md](m6-protocol.md)。

## 环境及可复现性

基线工具提交41a1b03，检测实现逐文件摘要、提示词/规则版本、依赖锁、数据清单摘要、模型参数和每次统计均保存于[完整检测摘要](../evaluation/results/m6-detection-baseline.json)。原M2数据未改：72源码、36 HTTP保留例；其中18受控漏洞属于72例，未额外当成独立检测样本。标签与安全配对是AI编写，human_review仍pending，结果为暂定标签上的课程实验，不能冒充独立人工金标准。

本机Windows x64、AMD Ryzen 9 7845HX（12核心/24线程）、内存33592209408字节、Anaconda AegisForge / Python3.13.18。模型DeepSeek deepseek-flash，temperature=0、thinking disabled、每次输出至多4096token、默认60秒调用/180秒任务期限；不支持seed记N/A。只向官方固定HTTPS endpoint发送公开合成源码/HTTP脱敏视图，无站点扫描或请求重放。调用并行度3、每例独立DB与单worker，模型费用无账单依据记N/A。

全流程共享持久预留1000次硬上限（用户明确授权，含重试）。原始模型输出/运行库/凭证保留在忽略目录，不发布。源码静态解析，候选只能在固定Docker容器执行；本机Docker引擎不可用，动态实验与干净部署验收在GitHub Ubuntu中真实运行。

## 检测实验：冻结基线

实际上传API→任务队列→worker→校验/合并→查询结果，规则1轮、LLM与联合各3轮，总756任务、648真实模型检测任务。耗用695次外部调用：625成功响应、66无效输出、4传输失败；失败保留在分母，没有fake补齐。输入942559token、输出110723token。[整数及指标CSV](../evaluation/results/m6-detection-baseline.csv)。

| 策略/轮次 | 源码TP/FP/FN | Precision | Recall | F1 | 源码任务失败 | HTTP TP/FP/FN |
| --- | --- | --- | --- | --- | --- | --- |
| 规则/1 | 30/10/6 | 0.7500 | 0.8333 | 0.7895 | 0/72 | 6/0/12 |
| LLM/1 | 32/19/4 | 0.6275 | 0.8889 | 0.7356 | 5/72 | 18/0/0 |
| LLM/2 | 32/20/4 | 0.6154 | 0.8889 | 0.7273 | 6/72 | 18/0/0 |
| LLM/3 | 33/22/3 | 0.6000 | 0.9167 | 0.7253 | 4/72 | 18/0/0 |
| 联合/1 | 35/24/1 | 0.5932 | 0.9722 | 0.7368 | 3/72 | 18/0/0 |
| 联合/2 | 36/24/0 | 0.6000 | 1.0000 | 0.7500 | 2/72 | 18/0/0 |
| 联合/3 | 35/25/1 | 0.5833 | 0.9722 | 0.7292 | 3/72 | 18/0/0 |

联合源码三轮均值Precision=0.5921845574、Recall=0.9814814815；累计TP=106、FP=73、FN=2。每类Recall均值：XSS=1、SQLi=0.9444444444、CMDi=1。**Precision未达到0.85，检测总门槛未通过**，不降低阈值、不只挑最佳一轮。LLM/联合HTTP各轮P/R/F1均1，规则HTTP F1=0.5。HTTP只评价攻击特征，不证明服务端漏洞。

安全源码被报警比例：规则9/36；LLM各轮16/36、15/36、16/36；联合19/36、18/36、19/36。高召回与大量误报并存，后续协作要分析安全上下文、启发式/模型分歧和严格输出拒绝，不能把所有风险线索称为已确认漏洞。

## 固定动态基线

[首次控制实验](../evaluation/results/m6-controls-initial.json)保留：XSS Cookie载荷含空白未正确传输，原版未复现，整项CI失败。正式候选生成前改为无空白Cookie载荷，不改源码或期望；[复跑36个控制](../evaluation/results/m6-controls-baseline.json)全部accepted，18原版安全断言失败且主要业务通过，18安全配对全部检查通过。[运行43019168996](https://github.com/visibychen/AegisForge/actions/runs/43019168996)六项CI通过。

原版引号/JavaScript字符串业务缺陷保留。SQL数字输入的参考版本对非法表达式可能返回500，测试只判断未越查询边界，不能据此宣称错误处理完善；后续应单独改进。命令例中外部实用程序使用固定离线stub，实际shell仍运行，安全由无害标记与正常调用观测判定；不等于验证真实外部工具的全部语义。浏览器驱动真实执行HTML/脚本，保留M4隔离及同UID/Chromium禁沙箱局限。

三轮54次首次修复申请已完成：38个候选、14个PATCH_CONFLICT、2个TARGET_NOT_DETECTED；生成与模型复检另耗90次请求。公开合成[首次候选束](../evaluation/results/m6-baseline-candidates.json)只供固定容器测试，不在主机导入执行。[完整动态结果](../evaluation/results/m6-repairs-baseline.json)：各轮12/18、13/18、11/18，总36/54；XSS16/18、SQLi8/18、CMDi12/18，38候选中36动态通过、2个XSS脚本字符串候选业务回归失败。**总数未到45/54，SQLi未到12/18，基线修复门槛未通过。** 未检出/生成失败/缺动态证据均留在分母，没有重选后续候选回填。

候选观察暂采用保守判据：模型复检必须完成，任何等级新增风险均阻止计为成功（比PLAN只限制新增high/critical更严格）；原产品复检位置增量没有保留severity，不能伪称已按等级精确判定。该统计约束和改进方案交由后续协作审查，原36/54结果保留。

动态CI真实运行见[43022170175](https://github.com/visibychen/AegisForge/actions/runs/43022170175)。该提交前端、两平台后端、M4对抗/控制、Chromium完整流程与Firefox核心冒烟均通过，M6实验作业因未达到修复数值门槛退出1；不是未运行，也不把实验失败掩盖为通过。[资源实测](../evaluation/results/m6-resources-baseline.json)：128MiB限制下768MiB分配被OOM终止137，32进程限制在30个子进程后EAGAIN，根文件系统拒写、tmpfs可写、无Docker socket/外网、UID65532，三项均accepted。

已校验下载artifact ZIP摘要：受控实验`2f49616a55a338e6ec064c1dab690458c02aa351386d5ddb7ed5814aa3eaa241`，浏览器`96ff93acab6f2b78d6eb0ced185b773209aaef3e73af09433002285c6003517e`。只白名单提取永久证据。[浏览器摘要](../evaluation/results/m6-browsers-baseline.json)、[Firefox桌面](screenshots/m6-firefox-desktop.png)、[手机](screenshots/m6-firefox-mobile.png)均保留；第二次Playwright执行清理输出目录，导致本次artifact没有保留先前Chromium截图，此证据管线问题留待协作修复。

## 性能、覆盖与依赖

- [API负载](../evaluation/results/m6-performance-api.json)：实际回环HTTP、假模型、10并发/100请求，p50=70.0354ms、p95=157.3846ms、最大296.7315ms、非预期错误0；10并发任务提交全为202，达到p95<500ms。数据与模型延迟分开，未把此结果推广到公网部署。
- [连续真实任务](../evaluation/results/m6-performance-live.json)：同一DB/单worker按顺序运行5个91字节开发源码任务，服务3091/4001/2496/2321/4907ms，全部完整，均≤120秒；另耗5次调用，纳入同一1000次账本。
- [50KiB边界](../evaluation/results/m6-performance-boundary.json)：51200字节、5分块全部处理，真实模型完整完成，服务12113ms；额外5调用，全部基线与性能合计795/1000次，剩余205次用于实验后的优化验证。
- 原基线后端325passed/1本机符号链接skip；核心服务/解析/规则分支626/724=86.4641%，语句1778/1919=92.6524%，合并覆盖90.9572%，达到核心分支≥80%目标。覆盖不是安全保证。
- 原本机前端47passed/1failed，证据导航N紧接Enter未切换2/2；GitHub同提交前端通过，作为时序相关问题保留待审。后续修复不能靠拉长等待或删除断言掩盖。
- [npm审计](../evaluation/results/m6-npm-audit-baseline.json)：0已知漏洞。[Python精确锁审计](../evaluation/results/m6-python-audit-baseline.json)：45个锁定包版本全部查到，其中验证镜像Flask3.1.2命中GHSA-68rp-wp8r-4726（低危、3.1.3修复）；这是同一公告的两个别名，不是两个独立漏洞。来源：[Flask官方公告](https://github.com/pallets/flask/security/advisories/GHSA-68rp-wp8r-4726)、[PyPI JSON协议](https://docs.pypi.org/api/json/)。扫描只覆盖Python/npm已知公告，OS库和未知漏洞不在覆盖中。

## 后续协作与验收状态

先完成全部基线实验，再完成Sonnet5.5/high同会话三轮协作，[记录及独立核实](collaboration-2026-11-11.md)。按结果优化后，原保留集已暴露，后续数字是事后诊断；独立质量验收须新的未暴露样本和人工复核，不能将改进结果回填基线。

- [开发A/B](../evaluation/results/m6-postdev-ab.json)：两臂各48例，99调用；当前运行时配历史渲染器对比新提示，不是完整旧产品复现。模型完整47→48、行号拒绝2→0，源码TP12不变、FP5→3，P约0.706→0.8，R均1；HTTP均TP12/FP1/FN0。只运行一轮。
- [最终定向开发回归](../evaluation/results/m6-postdev-final.json)：analysis-1.3，12个事后选择的开发例，12调用、模型完整12/12，TP9/FP1/FN0，P0.9/R1。9个漏洞目标全检出，3个原误报中仍1个误报；样本量/选择方式不同，不能与48例结果直接对比推断总体准确性。
- [后续修复诊断](../evaluation/results/m6-posthoc-repairs.json)：历史第2轮18个正确检测目标各申请后续候选，36调用，18生成；固定Docker全部运行，15/18综合通过，XSS6/6、SQLi4/6、CMDi5/6。SQLI-12业务失败，SQLI-17/CMDI-20安全失败。`passed=null`且`course_acceptance_evaluated=false`，不替代首次36/54。ZIP与运行来源见协作记录。
- 最终累计942/1000次调用（795基线/性能 +99开发A/B +36后续修复 +12最终开发回归），输入1277786/输出149765token；已停止付费调优。预留子额度仍计入同一全局上限，重启不清零。保留未用58次不表示可绕开已分配scope。
- 键盘同步、精确补丁预检/单次纠错、子额度原子保护、严谨记录核对和分浏览器证据管线已实现。普通CI分别检查固定54次真实重放一致与记录完整性；严格数值验收仍实际返回1，未达项为源码P、修复总数、SQLi修复数和人工复核。没有降低指标；`core_accepted`也只表示脚本列出的核心门槛，不是全矩阵声明。
- [升级后依赖审计](../evaluation/results/m6-python-audit-final.json)：实际重新生成Flask3.1.3哈希锁，45个精确版本均checked、无已知公告，保留原3.1.2低危发现。一次包查询网络失败后仅重查该包；没有把unavailable当无漏洞。

M7课程模板报告、查重与最终发布仍未开始；M6正式验收与Issue #7保持未完成，不能发布v1.0.0。

## 最终本地检查

第三轮最终修改后，Anaconda AegisForge内实际运行`scripts/check.py`：**377后端passed、1本机symlink skip，54前端passed**；依赖一致性、Ruff/格式、迁移、冻结数据、TypeScript和生产构建均通过。原先两项确定性键盘红测及新增StrictMode版本保持断言并通过。Starlette的httpx弃用提示与Vite约654kB压缩前JS包体提示仍存在，均未阻断检查，不宣称已消除性能风险。

`m6_freeze_guard.py`实际返回0，原samples及baseline相对调优前提交无改动。[最终记录审计](../evaluation/results/m6-records-final.json)23项通过、退出0；[最终严格核心验收](../evaluation/results/m6-acceptance-final.json)退出1、not_accepted，四项未达如上。损坏/非有限/重复键记录、伪造动态passed、缺引擎delta、错误登记/CWE、候选/镜像/测试绑定和子额度并发均有回归测试。密钥只在OS环境及必要子进程内存，发布前按当前真实key字节检查全部待提交文件，未发现泄漏。
