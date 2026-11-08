# M4 协作记录（实施中）

用户指定三轮开发与交叉审查，每轮必须检查错误并提出新模块/优化。第一轮Codex开发、Claude审；第二轮Claude修复并实现自己的创新、Codex审；第三轮两次以上真实交流后Codex最终优化。不模拟双方对话，不将内部工具循环计为双方轮数。

项目沿用原会话988b1845-c19b-4822-8b1b-2dfda07796c6，doctor/status确认active、busy=false。每次仅为Claude子进程指定ANTHROPIC_MODEL=claude-sonnet-5-5、CLAUDE_CODE_EFFORT_LEVEL=high，剔除DeepSeek密钥，不更改用户全局配置；模型结果还须核对原生调用记录。依据[官方配置文档](https://code.claude.com/docs/en/model-config)。

第一轮初稿：源码发现/哈希锚点、有界原文编辑与diff、不可变候选、持久repair作业/LLM复检、取消与预算、最小前端与下载、独立固定开发样例容器runner。新增迁移0005重建jobs约束，实测M3调用记录保留。Docker基础镜像按digest固定，11个容器依赖版本和PyPI SHA-256已锁定，浏览器运行于受控容器。

Codex已运行：后端226passed/1本机symlink跳过，Ruff/format与TypeScript通过。前端旧边界文案断言发现一次不匹配，已恢复“模型失败会明确标记部分完成”并保留M4说明，待重跑。镜像构建正在进行，尚未记录动态或真实修复通过。保留集源码/标签不用于M4调优；18例正式实验不冒充开发演示。

轮次记录、Claude结论、Codex实证及剩余分歧随实际调用补充。
