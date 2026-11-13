# M7 课程报告

[正文源稿](course-report.md)合并软件工程详细设计与实现报告，按原课程模板组织九章、参考文献和两份附录。四幅原创模块/架构/流程/数据库图由生成器绘制；四幅界面图使用仓库已有真实截图，在 Word 中显示局部，正文标明历史版本和 fake/真实模式。原始实验、事后诊断及后续候选结果分开报告。

封面姓名、学号和教师从本机忽略目录读取，公开源稿不含个人封面信息。含个人信息的最终 Word 保存在 `data/m7-report/AegisForge课程实践报告.docx`，不提交 Git。内部 PDF/PNG 用于排版检查，不作为课程交付附件发布。

## 生成 Word

主机 Python 仍使用 Anaconda `AegisForge`。报告工具依赖独立于后端运行库：

```text
conda run -n AegisForge python -m pip install -r scripts/reports/requirements.txt
```

保留课程提供的原始 `课程实践报告模板及评分标准（2026秋）.docx`，不覆盖它。生成器检查原模板 SHA-256，以原文件构建封面、完整评分表和正文；模板不同需先重新检查，不自动接受未知版式。

在忽略目录 `data/m7-report/cover.json` 写入 `name`、`student_id`、`teacher`、`date`，不要提交实际个人信息。未提供封面JSON时，生成器保留待填写字段。

在仓库根目录、Windows且安装Microsoft Word的环境执行已验证命令：

```text
conda run --no-capture-output -n AegisForge python scripts/reports/build_course_report.py --template "../课程实践报告模板及评分标准（2026秋）.docx" --output "data/m7-report/AegisForge课程实践报告.docx" --cover-json data/m7-report/cover.json --refresh-word --qa-pdf data/m7-report/final-native.pdf
```

`--refresh-word` 通过隐藏的 Word COM 实例刷新目录和页码，再恢复原模板的受保护包部件并规范化关系/样式ID，不保留Word对其他部件的改写。首次生成后应重新渲染最终DOCX并逐页检查；不能仅凭导出前的PDF判断恢复后的文件版式。无Word时可不加刷新参数生成，但须在Word中刷新字段和完成视觉检查后才能交付。

生成器不会调用模型或导入/执行样例。需要中文字体绘图；Windows使用系统微软雅黑/黑体，Linux可使用Noto CJK。重新生成会更新源稿目录下四幅设计图。

## 尚待课程提交前处理

- 阅读并确认报告正文符合本人实际实践，按课程要求披露辅助工具使用。
- 经课程认可渠道取得**低于15%**的真实查重报告，与课程报告一并提交；本仓库没有代替该证明。
- 用户已于2026-11-13授权直接完成PR集成与v1.0.0工程发布，查重由作者之后补齐；发布过程按[交付说明](../release-v1.0.0.md)核对，不将查重写为通过。

具体写作、版式和证据核查见[M7验证记录](../m7-verification.md)，操作说明见[用户指南](../user-guide.md)。Issue #8 保持进行中。
