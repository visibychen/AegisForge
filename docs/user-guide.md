# AegisForge 使用指南

本指南对应 M6 完成版本和 M7 报告。系统面向本地单用户，完整支持 Python/Flask 风格源码与离线 HTTP 请求特征分析。真实实验结果及限制见[课程报告源稿](reports/course-report.md)和[M6完成记录](m6-completion.md)。

## 准备与启动

主机 Python 统一在 Anaconda 的 `AegisForge` 环境运行。新机器按[README](../README.md#环境与安装)安装 Python/Node 锁定依赖，不使用系统 Python 或额外虚拟环境。

```text
conda env create --file environment.yml
conda activate AegisForge
python -m pip install -r backend/requirements-dev.lock
npm --prefix frontend ci
python scripts/dev.py init
python scripts/dev.py migrate
```

已有环境使用 `conda env update -n AegisForge --file environment.yml`。`init` 创建被 Git 忽略的 `.env` 和本地访问令牌，不覆盖已有文件。主机设置 `PYTHONNOUSERSITE=1`、`PYTHONUTF8=1`。

分别在三个终端启动：

```text
conda run --no-capture-output -n AegisForge python scripts/dev.py api
conda run --no-capture-output -n AegisForge python scripts/dev.py worker
npm --prefix frontend run dev
```

打开 [本地工作台](http://127.0.0.1:5173/)，输入 `.env` 中的本地 API 访问令牌。令牌仅在页面内存中，刷新后重新连接。`queued` 持续不变时检查 worker 是否运行。不要同时让本机进程与 Compose 操作同一个运行数据库。

## 真实模型配置

默认 fake 用于离线展示和普通 CI，页面明确显示模拟/部分完成。真实检测需在操作系统环境设置 `AEGISFORGE_DEEPSEEK_API_KEY`，并让 API/worker 继承它；密钥不能放在 `.env`、源文件、命令参数或前端。

非秘密配置为 `AEGISFORGE_MODEL_MODE=real`，模型默认 `deepseek-flash`。启动器只向必要子进程导入已配置的环境，不把模型密钥交给受控 runner。真实调用含纠错、网络重试及修复复检，会消耗调用额度。任务32次、部署每日64次是默认调用次数上限，不能当成金额预算。M6实验另有全项目1000次账本，已用992次；不要新建账本绕过额度。

## 输入与检测

1. 选择 Python 源码或 HTTP 文本，上传文件或粘贴内容。源码接受 `.py`；请求文本接受 `.http/.req/.txt`，编码为 UTF-8或起始BOM。
2. 点击“保存并预览特征”，检查脱敏预览和规则线索。文件最多2MiB，任务最多10文件/10MiB，分析上限80,000字符/8块。
3. 选择 rules、llm 或 hybrid 及模型，创建任务。rules 不调用模型；fake 不会产生真实模型结论。
4. 查看覆盖账本、错误类别、CWE、风险等级及建议；按位置导航并展开来源判断。`partial` 或覆盖缺口不能按空结果判安全。

HTTP请求只离线解析，不发送到目标站点；攻击特征不等于确认后台漏洞。源码、请求和模型文本均不会由 API/worker 执行。

## 候选与动态验证

对支持的单块 Python 快照，在发现处申请候选修复，检查 diff、原文/候选、门禁和说明卡，再下载补丁。原输入不覆盖。含脱敏替换或不支持范围的源码不自动修改；只有HTTP时需要补充对应源码。

普通源码保留静态/模型复检状态。只有按原始摘要登记的受控示例可以申请动态验证。需要可用的 Docker Linux engine，优先采用[README中的Compose隔离部署](../README.md#m4-候选补丁与受控验证部署)：

```text
conda run --no-capture-output -n AegisForge python scripts/build_validator.py
conda run --no-capture-output -n AegisForge python scripts/deploy.py build
conda run --no-capture-output -n AegisForge python scripts/deploy.py up
npm --prefix frontend run dev
```

已有本机 API/worker 需先停止。若仅作本机开发，可用 `python scripts/dev.py validator` 启动独立 runner；同一Windows用户不构成OS权限隔离，不能替代Compose验收。申请后长期pending应检查runner；工具失败为error，无动态证据是unverified。通过仅表示固定安全与业务测试通过。不得在主机导入或运行候选束。

## 历史与导出

历史支持编号、状态、CWE、等级筛选和分页，旧尝试及候选可以查看。父检测重试后，旧候选不能重新申请动态验证。报告默认无源码、文件名、HTTP私密字段和模型自由文本。

```text
conda run --no-capture-output -n AegisForge python scripts/verify_report.py report.json
```

此命令核对导出JSON的内容摘要，不证明漏洞判断正确，也不是数字签名。“移出历史”保留账务与共享输入，是逻辑移出；输入仍可能按ID预览，不是物理擦除。活动任务需先结束。

## 故障处理

| 表现或错误码 | 处理 |
| --- | --- |
| 401或刷新后断开 | 重新输入本地API令牌，不在URL传令牌 |
| 队列不动 | 确认独立worker、数据库与配置一致 |
| MODEL_INVALID_OUTPUT | 查看失败类别；保留严格校验，不把错误回答当发现 |
| ANALYSIS_CONFIG_CHANGED | 按当前配置显式重试，旧凭证保留 |
| PATCH_CONFLICT | 核对源码快照及精确原文，不直接粘贴模型全文覆盖 |
| source_required | 提供对应源码，HTTP文本无法确定后台补丁 |
| 动态error/pending | 检查Docker、固定镜像和独立runner；未运行不算通过 |
| 预算不足 | 停止调用并核对账务，不删除DB或换账本清零 |

## 课程证据核对

```text
conda run -n AegisForge python scripts/m6_freeze_guard.py
conda run -n AegisForge python scripts/acceptance.py --profile course-delivery-v1
```

课程profile按功能与证据验收，默认strict入口保留原自设数值参考目标，未达返回1属于已披露结论。本指南不会触发付费实验；重跑真实实验需另行核对剩余额度。查重证明仍须由课程认可渠道提供。
