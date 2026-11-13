# ADR 0003：M4 修复门禁与受控执行边界

日期：2026-11-08。状态：已实施；关联 PLAN R05/R06、Issue #5。

## 决策

候选修复是不可变输入的派生快照，绑定发现、源码 SHA-256、父检测方案与 attempt。只接受有限行编辑；服务端生成并回放 unified diff，校验语法、结构、规则与模型复检。发现差异按证据指纹优先、行映射次选，一对一消耗基线槽位；新增报告不能自动视为补丁导致，也不能直接忽略。先保存候选，再做有界模型复检，复检失败保留候选及未验证原因。

修复门禁账本展示每项检查的真实状态。全部静态、真实模型及动态安全/业务检查通过才能为 passed；普通上传缺动态证据为 unverified，fake 永远不是真实修复。执行契约放在 checks_json，生成前捕获实际配置，失败仍保留，成功补充候选/diff 哈希；不新增 0006，不加入 HMAC。契约及动态结果的摘要用于完整性核对，不是签名，不防御拥有数据库写权限的攻击者。

动态仅匹配三个登记开发样例的原始哈希。固定入口、固定镜像指纹、固定测试名，模型不可指定命令/镜像/断言。测试不发给模型；原 V 版须暴露安全失败，参考 S 版必须全部通过。SQLi 原 V 的撇号业务用例本来就失败，应如实保留。冻结的 18 个保留例供 M6 正式实验，本阶段不读取其源码/标签调优。

## 执行与资源

- Compose 将 API/worker 放入无 Docker CLI/socket、UID 1000、只读根目录、无 capabilities、no-new-privileges 的应用容器。模型密钥仅以环境变量交给 API/worker；迁移和验证控制器不持有它。
- 验证控制器是持有 Docker socket 的受信进程，权限等同宿主 Docker 管理员；不把它当作不可信代码沙箱。所有 SQLite 访问进程在 Linux 容器内共享 data，避免主机 Windows 与容器混用 WAL。候选挂载路径来自控制器自身的 data 挂载检查，不来自 API/数据库输入；Docker Desktop 的 Windows Source 转为固定 VM 挂载前缀。
- 每个候选在独立容器运行：无网络、UID 65532、只读根目录及单个候选挂载、cap-drop ALL、no-new-privileges、1 CPU、512 MiB、128 MiB noexec tmpfs、宿主 30 秒、输出 16 KiB。CMDi/SQLi 为 64 PID，**XSS 为 128 PID**。
- 调整 XSS 的依据：同一固定 Chromium 156 环境中，浏览器启动后 pids.current=57；64 PID 下后续 guard 探测退出 3，128 下退出 0。128 下原版可复现 XSS，参考安全版及真实修复通过。调整的是浏览器容量，安全与业务断言均未放宽。
- driver 不导入候选，启动即设 PR_SET_DUMPABLE=0；target 子进程关闭标准流，导入前加载 libseccomp，禁止已知跨进程信号、ptrace、process_vm、pidfd 等通道，并自检。driver 的 nonce 只从 stdin 接收，不放入 argv/env；只有 driver 写唯一结果行。宿主核对 nonce、源码哈希、协议、固定测试及退出码。
- driver 设置完整 25 秒看门狗；候选阶段超时留失败测试，可信环境初始化失败为 error。候选可控日志读取拒绝 FIFO/符号链接，限 1 MiB，测试异常逐项处理。无限循环实测约 28.4 秒完成宿主回收。清扫仅删除本项目标签/前缀/运行 ID 且创建超过 60 秒的容器，75 秒恢复过期数据库 running 记录。

## 局限与后续

本地同 Windows 用户分进程启动只有代码路径隔离，不能声称 API 没有 OS Docker 权限；动态部署验收应使用 Compose。主机 Python 仍使用 Anaconda AegisForge，镜像是独立固定 Python 3.13 运行时，不向主机安装包。Linux 首次绑定空 data 目录需提前使 UID 1000 可写。

driver/target 仍是同 UID，seccomp 是补充已知通道的黑名单，不能覆盖未来内核接口；Chromium 使用 --no-sandbox，依赖容器边界。固定测试可以检出本次样例问题，无法证明任意敌意 Python 或浏览器漏洞利用链安全，也无法证明候选没有其他漏洞。Docker 权限、数据库写权限与宿主用户仍属于可信域。独立 UID、结构化修复解释卡/报告导出和正式修复率实验留待 M5/M6。
