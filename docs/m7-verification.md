# M7 课程报告与发布准备验证

2026-11-13，Refs #8。用户要求重新仔细阅读两份原始教学文件后撰写报告，随后明确当前为最终版，授权直接完成PR与发布，查重由作者后续自行补齐。课程查重要求继续披露，不作为本次工程Release的阻塞项，不生成虚假查重证明。

## 内容与来源核对

已重新阅读《课程设计要求.md》和《课程实践报告模板及评分标准（2026秋）.docx》，并渲染查看原模板全部5页。原Word SHA-256为`1148e7f9ad6cafe2cf900d0b529747c387fcfba97c54abf02cd2c01c23e62f23`，原件保持不变。评分为10/30/15/20/10/15，正文宋体五号、三级标题及参考文献规范按原模板明示文字执行。

[源稿](reports/course-report.md)合并详细设计与实现报告，九章、参考文献和两个附录，包含模块、系统配置、架构/流程、代码接口、数据库概念/逻辑设计、安全分析、安装使用、真实检测/修复/性能和失败解释。四幅代码绘制的设计图、四幅已有界面截图；截图明确M4真实演示与M6 fake界面区别。16个Word表格包含原封面/评分表和14个报告数据/设计表。

逐项核对实际模型、API路由、原始字节上传方式、数据库七表、队列状态与修复边界；没有将计划中的Monaco或独立Validation表写成已实现功能。七条参考文献通过MITRE、NIST、ICLR论文原文、作者/机构页面和预印本原文核对，正文使用平排编号。

原始联合源码P约59.22%/R约98.15%、首次36/54、定向11/12及单项1/1、加强后续候选18/18各自保留分母与解释；旧重建回归不称为新模型实验，单人复核不称为双人复现。报告无新增模型调用，累计仍992/1000。

## Word构建与版式

所有主机Python均在Anaconda `AegisForge`，报告工具依赖单列于`scripts/reports/requirements.txt`，不改应用运行依赖锁。Word由原模板构建，保留学校封面、评分文字/空评分栏、A4页面和原页码控件；姓名学号从忽略目录读取。公开副本不含个人封面信息。

本机没有LibreOffice，实际运行打包`render_docx.py`确认该后端缺失后，使用任务本地适配器调用同一renderer的流程，以Microsoft Word COM转换、PyMuPDF栅格化。未改技能文件。目录和页码由Word刷新，处理其内置TOC样式ID规范化，并恢复模板受保护包部件。最终私有与公开Word均31页，导出前PDF仅供内部检查；最终恢复后的DOCX再次独立渲染。

结构核查包括：

- 原模板SHA未变；三个节的纸张、边距、栏和正文页码起点与原件一致。
- 12个受保护部件逐字节一致：主题、字体表、编号、Web设置、脚注/尾注、页眉/两个页脚、自定义/应用元数据及包根关系。
- 除明确编辑的标题样式外，原有其他样式语义保留；原关系不变，所有新图片关系和段落/字符/表格样式引用均能解析。
- 原评分表连续文字一致，8幅图齐备；无XXXX、日期示范、目录占位、乱码字体及字段错误；个人封面与用户提供信息一致。
- 最终渲染核对目录页码、表格跨页重复表头、截图重点、中文字体、边界及空页；内部PNG/PDF不入Git或Release。

## 实际检查

以下均在本次实际执行，报告没有据此声称重新完成付费实验：

```text
python -m pip check
python -m ruff check --config backend/pyproject.toml scripts/reports
python -m ruff format --check --config backend/pyproject.toml scripts/reports
python scripts/m6_freeze_guard.py
python scripts/acceptance.py --profile course-delivery-v1 --output data/m7-report/course-profile.json
```

依赖、Ruff/格式、冻结历史均通过；课程profile27项检查均满足，返回`course_delivery_accepted_with_limitations`。M6的产品/controller和依赖锁未改变，既有513本机后端/1平台skip、56前端及远端514/514是M6结果，不冒称本次文档重跑。报告PR会再运行普通/课程CI，结果在PR和发布记录补充。

## 集成与发布口径

已核对PR #11–#16最新头提交的历史CI全部success，按顺序重定向main并以merge保留原提交历史，不squash掉冻结实验引用。集成后main `69cf0ebb7a58f603a11660f7025404d1db773d22`的文件树与M6头`7642e23`完全一致。随后提交报告PR，绿色后合并和发布v1.0.0，详见[发布说明](release-v1.0.0.md)。

个人Word、cover.json、运行数据和发布用临时包留在Git忽略目录。公开Word匿名封面、固定标签的源码包、交付摘要和SHA-256清单在Release提供；上传摘要及标签目标提交另核对。查重由作者后续经认可渠道补齐，Issue #8不再因缺该材料阻塞工程发布，但不能声称课程查重已达标。
