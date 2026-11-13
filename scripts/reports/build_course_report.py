"""Build the course report from the retained university template and Markdown.

No model/network calls, project imports or sample execution are performed.
Personal cover data is read only from an explicitly supplied ignored JSON file.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from docx import Document
from docx.enum.style import WD_STYLE_TYPE
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor
from lxml import etree
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[2]
REFERENCE_SHA = "1148e7f9ad6cafe2cf900d0b529747c387fcfba97c54abf02cd2c01c23e62f23"
PRESERVE = {
    "word/theme/theme1.xml",
    "word/fontTable.xml",
    "word/numbering.xml",
    "word/webSettings.xml",
    "word/footnotes.xml",
    "word/endnotes.xml",
    "word/header1.xml",
    "word/footer1.xml",
    "word/footer2.xml",
    "docProps/custom.xml",
    "docProps/app.xml",
    "_rels/.rels",
}
BODY_WIDTH_CM = 14.65


def xml_element(tag, **attrs):
    el = OxmlElement(tag)
    for key, value in attrs.items():
        el.set(qn("w:" + key), str(value))
    return el


def font_for(size, bold=False):
    # Diagrams use an explicit CJK font. No fallback to boxes/missing glyphs.
    font_dir = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
    paths = [font_dir / ("msyhbd.ttc" if bold else "msyh.ttc"), font_dir / "simhei.ttf"]
    paths += [Path("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc")]
    for path in paths:
        if path.is_file():
            return ImageFont.truetype(str(path), size)
    raise SystemExit("A CJK font is required to draw report diagrams.")


def diagram(path, size, boxes, edges, notes=()):
    canvas = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(canvas)
    regular, bold = font_for(28), font_for(31, True)
    for points, label in edges:
        draw.line(points, fill="#344453", width=3)
        x, y = points[-1]
        px, py = points[-2]
        if x > px:
            arrow = [(x, y), (x - 13, y - 7), (x - 13, y + 7)]
        elif x < px:
            arrow = [(x, y), (x + 13, y - 7), (x + 13, y + 7)]
        elif y > py:
            arrow = [(x, y), (x - 7, y - 13), (x + 7, y - 13)]
        else:
            arrow = [(x, y), (x - 7, y + 13), (x + 7, y + 13)]
        draw.polygon(arrow, fill="#344453")
        if label:
            p0, p1 = points[0], points[1]
            mid = ((p0[0] + p1[0]) / 2, (p0[1] + p1[1]) / 2)
            draw.text((mid[0] + 3, mid[1] - 33), label, font=regular, fill="black")
    for rect, title, lines in boxes:
        draw.rounded_rectangle(rect, radius=9, fill="#F3F6F8", outline="#455767", width=2)
        x0, y0, x1, _ = rect
        draw.text(((x0 + x1) / 2, y0 + 14), title, font=bold, fill="black", anchor="mt")
        for i, line in enumerate(lines):
            draw.text(
                ((x0 + x1) / 2, y0 + 60 + i * 38), line, font=regular, fill="#15212A", anchor="mt"
            )
    for x, y, text in notes:
        draw.text((x, y), text, font=regular, fill="#243743")
    path.parent.mkdir(parents=True, exist_ok=True)
    canvas.save(path, dpi=(220, 220))


def make_diagrams(folder):
    diagram(
        folder / "modules.png",
        (1500, 650),
        [
            ((470, 15, 1030, 135), "铸盾 AegisForge", ["检测  修复  验证  证据管理"]),
            ((25, 235, 475, 390), "输入接入", ["上传 / 粘贴 / 示例", "编码、脱敏与不可变快照"]),
            (
                (525, 235, 975, 390),
                "特征与检测",
                ["AST / HTTP / 规则 / LLM", "证据校验、同流合并与复核"],
            ),
            ((1025, 235, 1475, 390), "任务调度", ["持久队列、租约与心跳", "取消、重试与调用账务"]),
            (
                (25, 465, 475, 620),
                "候选修复",
                ["精确编辑、diff与结构检查", "规则 / 模型复检与门禁"],
            ),
            ((525, 465, 975, 620), "受控验证", ["登记案例与固定镜像", "安全回归与业务回归"]),
            (
                (1025, 465, 1475, 620),
                "工作台与证据",
                ["定位、历史、筛选与导出", "覆盖账本、凭证与说明卡"],
            ),
        ],
        [
            ([(750, 135), (750, 180), (250, 180), (250, 235)], ""),
            ([(750, 135), (750, 235)], ""),
            ([(750, 180), (1250, 180), (1250, 235)], ""),
            ([(495, 180), (495, 430), (250, 430), (250, 465)], ""),
            ([(750, 390), (750, 465)], ""),
            ([(1000, 180), (1000, 430), (1250, 430), (1250, 465)], ""),
        ],
    )
    diagram(
        folder / "architecture.png",
        (1500, 900),
        [
            ((30, 40, 460, 180), "React 浏览器", ["输入、状态、证据与候选"]),
            ((550, 40, 980, 180), "FastAPI 接口", ["鉴权、校验与持久入队"]),
            ((550, 300, 980, 440), "SQLite 与受限存储", ["任务、账务、快照与结果"]),
            ((550, 560, 980, 745), "独立 worker", ["规则与模型检测", "候选修复与静态复检"]),
            (
                (1080, 560, 1470, 745),
                "DeepSeek HTTPS",
                ["脱敏输入与结构化输出", "密钥仅在服务端环境"],
            ),
            ((30, 300, 460, 440), "受信验证 runner", ["固定样例、摘要与nonce"]),
            (
                (30, 560, 460, 745),
                "固定 Docker 容器",
                ["driver 与待测 target", "无网络 / 非root / 资源上限"],
            ),
        ],
        [
            ([(460, 110), (550, 110)], ""),
            ([(765, 180), (765, 300)], ""),
            ([(765, 440), (765, 560)], ""),
            ([(980, 650), (1080, 650)], ""),
            ([(550, 370), (460, 370)], ""),
            ([(245, 440), (245, 560)], ""),
        ],
        [
            (
                60,
                815,
                "执行边界：API / worker 无 Docker 权限；普通上传不执行；只有登记样例进入容器。",
            )
        ],
    )
    diagram(
        folder / "workflow.png",
        (1500, 1070),
        [
            ((400, 20, 1100, 135), "接收输入", ["格式 / 大小 / 编码 / 凭据校验"]),
            ((400, 200, 1100, 315), "保存快照与分析方案", ["特征提取、分块、哈希和版本绑定"]),
            ((400, 380, 1100, 495), "持久入队并由 worker 领取", ["核对租约、方案与累计调用预算"]),
            (
                (30, 565, 680, 715),
                "规则 / LLM 检测",
                ["校验原文与位置，合并并保存覆盖", "失败区域保留 partial 与原因"],
            ),
            (
                (820, 565, 1470, 715),
                "申请候选修复",
                ["绑定发现与原快照，执行精确编辑", "diff回放、语法 / 结构 / 增量复检"],
            ),
            (
                (820, 800, 1470, 950),
                "仅登记样例进入固定容器",
                ["安全与业务回归均运行", "未运行 / 工具错误不能判通过"],
            ),
            (
                (30, 800, 680, 950),
                "展示历史与导出报告",
                ["区分检测、候选和动态证据", "保留失败与未验证状态"],
            ),
        ],
        [
            ([(750, 135), (750, 200)], ""),
            ([(750, 315), (750, 380)], ""),
            ([(750, 495), (750, 530), (355, 530), (355, 565)], ""),
            ([(680, 640), (820, 640)], ""),
            ([(1145, 715), (1145, 800)], ""),
            ([(820, 875), (680, 875)], ""),
            ([(355, 715), (355, 800)], ""),
        ],
        [(70, 1000, "HTTP 缺源码：source_required；普通源码：只做静态与模型复检；不会自动执行。")],
    )
    diagram(
        folder / "database.png",
        (1500, 1060),
        [
            (
                (30, 30, 460, 210),
                "Artifact 快照",
                ["PK id / unique storage_key", "sha256 / input_type / size"],
            ),
            (
                (550, 30, 980, 210),
                "TaskArtifact 关联",
                ["PK scan_id + artifact_id", "两个字段均为FK"],
            ),
            (
                (1070, 30, 1470, 210),
                "ScanTask 任务",
                ["PK id / status / retries", "plan / result / deleted_at"],
            ),
            (
                (30, 350, 460, 530),
                "Finding 发现",
                ["PK id / FK scan_id", "FK artifact_id / attempt"],
            ),
            (
                (550, 350, 980, 530),
                "Job 作业",
                ["PK id / FK scan_id", "unique idempotency_key", "lease_token / lease_until"],
            ),
            (
                (1070, 350, 1470, 530),
                "ModelCall 调用",
                ["PK id / FK scan_id, job_id", "status / tokens / duration"],
            ),
            (
                (350, 720, 1150, 925),
                "Repair 修复",
                [
                    "PK id / FK scan_id, finding_id, source_id",
                    "unique FK job_id / FK candidate_id (可空)",
                    "source_sha256 / edits / diff / checks / dynamic",
                ],
            ),
        ],
        [
            ([(460, 120), (550, 120)], "1:N"),
            ([(980, 120), (1070, 120)], "N:1"),
            ([(245, 210), (245, 350)], "1:N"),
            ([(1270, 210), (1270, 275), (765, 275), (765, 350)], "1:N"),
            ([(1270, 210), (1270, 350)], "1:N"),
            ([(980, 440), (1070, 440)], "1:N"),
            ([(245, 530), (245, 650), (480, 650), (480, 720)], "1:N"),
            ([(765, 530), (765, 720)], "1:0..1"),
            ([(60, 210), (15, 210), (15, 980), (750, 980), (750, 925)], ""),
        ],
        [
            (
                50,
                1005,
                "Repair 的 source_id / candidate_id 关联 Artifact；scan_id 关联 ScanTask。",
            )
        ],
    )


def set_font(obj, name="宋体", size=10.5, bold=False):
    obj.font.name = "Times New Roman"
    obj.font.size = Pt(size)
    obj.font.bold = bold
    obj.font.color.rgb = RGBColor(0, 0, 0)
    props = obj._element.get_or_add_rPr()
    fonts = props.find(qn("w:rFonts"))
    if fonts is None:
        fonts = xml_element("w:rFonts")
        props.insert(0, fonts)
    for attr in list(fonts.attrib):
        if "Theme" in attr or "theme" in attr:
            del fonts.attrib[attr]
    for key, value in {
        "ascii": "Times New Roman",
        "hAnsi": "Times New Roman",
        "eastAsia": name,
        "cs": "Times New Roman",
    }.items():
        fonts.set(qn("w:" + key), value)
    color = props.find(qn("w:color"))
    if color is not None:
        for key in list(color.attrib):
            if key != qn("w:val"):
                del color.attrib[key]
    szcs = props.find(qn("w:szCs"))
    if szcs is None:
        szcs = xml_element("w:szCs")
        props.append(szcs)
    szcs.set(qn("w:val"), str(int(size * 2)))


def configure_styles(doc):
    for name, font, size, bold in [
        ("Report Body", "宋体", 10.5, False),
        ("Title", "黑体", 20, False),
        ("Heading 1", "黑体", 12, False),
        ("Heading 2", "黑体", 10.5, False),
        ("Heading 3", "宋体", 10.5, False),
        ("Report Caption", "宋体", 9, False),
        ("Report Code", "宋体", 9, False),
        ("Report Reference", "宋体", 9, False),
    ]:
        if name not in doc.styles:
            doc.styles.add_style(name, WD_STYLE_TYPE.PARAGRAPH)
        style = doc.styles[name]
        set_font(style, font, size, bold)
        pf = style.paragraph_format
        pf.space_before = Pt(0)
        pf.space_after = Pt(0)
        pf.line_spacing = Pt(20 if name == "Report Body" else 19)
        pf.first_line_indent = Pt(21 if name in {"Report Body", "Heading 3"} else 0)
        pf.left_indent = Pt(0)
        pf.right_indent = Pt(0)
        pf.widow_control = True
        pf.keep_together = name.startswith("Heading")
        pf.keep_with_next = name.startswith("Heading")
        pf.page_break_before = False
        # Explicit text guidance in the reference overrides its placeholder runs.
        if name == "Heading 1":
            pf.space_before, pf.space_after = Pt(13), Pt(13)
        elif name == "Heading 2":
            pf.space_before, pf.space_after = Pt(7), Pt(3)
        elif name == "Heading 3":
            pf.space_before = Pt(4)
        elif name == "Report Code":
            pf.line_spacing = Pt(13)
        elif name == "Report Reference":
            pf.line_spacing, pf.space_after = Pt(14), Pt(5)
        style.element.get_or_add_pPr().append(xml_element("w:snapToGrid", val="0"))
    for name in ("toc 1", "toc 2"):
        if name not in doc.styles:
            doc.styles.add_style(name, WD_STYLE_TYPE.PARAGRAPH, builtin=True)
        style = doc.styles[name]
        set_font(style, "宋体", 10.5)
        style.paragraph_format.line_spacing = Pt(22)
        style.paragraph_format.space_after = Pt(0)
        style.paragraph_format.space_before = Pt(0)
        style.paragraph_format.first_line_indent = Pt(0)
        style.paragraph_format.left_indent = Pt(21 if name == "toc 2" else 0)
        style.element.get_or_add_pPr().append(xml_element("w:snapToGrid", val="0"))


def add_text(doc, text, style="Report Body"):
    p = doc.add_paragraph(style=style)
    p.add_run(text)
    return p


def table(doc, lines):
    cells = [[c.strip() for c in line.strip().strip("|").split("|")] for line in lines]
    cells = [cells[0], *cells[2:]]
    n = len(cells[0])
    # Most tables need one short label and a wider explanatory column.
    ratios = {
        3: [0.24, 0.26, 0.50],
        4: [0.21, 0.18, 0.20, 0.41],
        5: [0.24, 0.19, 0.19, 0.19, 0.19],
        7: [0.24, 0.09, 0.09, 0.09, 0.17, 0.16, 0.16],
    }
    widths = ratios.get(n, [1 / n] * n)
    if n == 4 and all(x in cells[0] for x in ["类别", "预定尝试"]):
        widths = [0.28, 0.24, 0.24, 0.24]
    if n == 3 and "分值" in cells[0]:
        widths = [0.25, 0.10, 0.65]
    if n == 3 and cells[0][0] == "方法与路径":
        widths = [0.48, 0.26, 0.26]
    t = doc.add_table(rows=0, cols=n)
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    t.autofit = False
    props = t._tbl.tblPr
    borders = xml_element("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        borders.append(xml_element("w:" + edge, val="single", sz="4", color="D9D9D9"))
    props.append(borders)
    margins = xml_element("w:tblCellMar")
    for edge in ("top", "left", "bottom", "right"):
        margins.append(xml_element("w:" + edge, w="70", type="dxa"))
    props.append(margins)
    for col, ratio in zip(t.columns, widths, strict=True):
        col.width = Cm(BODY_WIDTH_CM * ratio)
    for ri, record in enumerate(cells):
        row = t.add_row()
        row._tr.get_or_add_trPr().append(xml_element("w:cantSplit"))
        if ri == 0:
            row._tr.get_or_add_trPr().append(xml_element("w:tblHeader"))
        for ci, (cell, value) in enumerate(zip(row.cells, record, strict=True)):
            cell.width = Cm(BODY_WIDTH_CM * widths[ci])
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            p = cell.paragraphs[0]
            p.paragraph_format.first_line_indent = Pt(0)
            p.paragraph_format.line_spacing = Pt(14)
            p.paragraph_format.space_after = Pt(2)
            p.paragraph_format.space_before = Pt(2)
            p.paragraph_format.keep_with_next = False
            p.paragraph_format.widow_control = True
            p.alignment = (
                WD_ALIGN_PARAGRAPH.CENTER
                if ri == 0 or (len(value) <= 14 and n >= 4)
                else WD_ALIGN_PARAGRAPH.LEFT
            )
            set_font(p.add_run(value), "黑体" if ri == 0 else "宋体", 9, ri == 0)
            if ri == 0:
                cell._tc.get_or_add_tcPr().append(xml_element("w:shd", fill="EDF0F2"))
    spacer = doc.add_paragraph()
    spacer.paragraph_format.first_line_indent = Pt(0)
    spacer.paragraph_format.line_spacing = Pt(5)
    spacer.paragraph_format.space_after = Pt(0)


def picture(doc, markdown_path, caption, source_dir):
    raw, _, crop = markdown_path.partition("#crop=")
    path = (source_dir / raw).resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError("Report figure must be inside the repository")
    with Image.open(path) as img:
        width, height = img.size
    p = doc.add_paragraph()
    p.paragraph_format.first_line_indent = Pt(0)
    p.paragraph_format.line_spacing = 1
    p.paragraph_format.space_before = Pt(5)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.keep_with_next = True
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    rect = (0, 0, 1, 1) if not crop else tuple(float(x) for x in crop.split(","))
    left, top, right, bottom = rect
    ratio = (height * (bottom - top)) / (width * (right - left))
    display_width = BODY_WIDTH_CM
    if ratio * display_width > 17.5:
        display_width = 17.5 / ratio
    shape = p.add_run().add_picture(
        str(path), width=Cm(display_width), height=Cm(display_width * ratio)
    )
    shape._inline.docPr.set("descr", caption)
    if crop:
        blipfill = shape._inline.find(".//" + qn("pic:blipFill"))
        src = OxmlElement("a:srcRect")
        for attr, value in zip(
            ("l", "t", "r", "b"), (left, top, 1 - right, 1 - bottom), strict=True
        ):
            src.set(attr, str(round(value * 100000)))
        blipfill.insert(1, src)
    c = add_text(doc, caption, "Report Caption")
    c.alignment = WD_ALIGN_PARAGRAPH.CENTER
    c.paragraph_format.space_after = Pt(5)


def add_toc(doc):
    p = add_text(doc, "目录", "Title")
    p.paragraph_format.page_break_before = True
    set_font(p.runs[0], "黑体", 14)
    p = doc.add_paragraph()
    p.paragraph_format.first_line_indent = Pt(0)
    run = p.add_run()
    run._r.append(xml_element("w:fldChar", fldCharType="begin"))
    code = xml_element("w:instrText")
    code.set(qn("xml:space"), "preserve")
    code.text = ' TOC \\o "1-2" \\h \\z \\u '
    run._r.append(code)
    run._r.append(xml_element("w:fldChar", fldCharType="separate"))
    p.add_run("目录由 Word 字段更新")
    p.add_run()._r.append(xml_element("w:fldChar", fldCharType="end"))
    # The section break is attached to this paragraph after adding the field.
    return p


def fill_cover(doc, info):
    paragraphs = list(doc.paragraphs)
    title = paragraphs[5]
    title.clear()
    title.style = doc.styles["Title"]
    title.paragraph_format.line_spacing = Pt(30)
    title.paragraph_format.space_after = Pt(0)
    title.paragraph_format.first_line_indent = Pt(0)
    for i, text in enumerate(["铸盾 AegisForge", "基于 LLM 的 Web 代码漏洞", "智能检测与修复系统"]):
        if i:
            title.add_run().add_break(WD_BREAK.LINE)
        set_font(title.add_run(text), "黑体", 20)
    cover = doc.tables[0]
    for row, value in zip(
        cover.rows,
        [
            info.get("name", "待填写"),
            info.get("student_id", "待填写"),
            "网络空间安全技术",
            info.get("teacher", "待填写"),
        ],
        strict=True,
    ):
        cell = row.cells[-1]
        p = cell.paragraphs[0]
        old = deepcopy(p._p.pPr)
        p.clear()
        if old is not None:
            p._p.remove(p._p.pPr)
            p._p.insert(0, old)
        set_font(p.add_run(value), "宋体", 16)
    for p in paragraphs:
        if "二〇二六年" in p.text:
            # clear() preserves pPr including the required section break.
            p.clear()
            set_font(p.add_run(info.get("date", "二〇二六年 十一月 十三日")), "宋体", 16)
            break
    # The title expands from one placeholder line to three; recover equal height
    # from empty cover slots, leaving the university/table/date anchors stable.
    blanks = [p for p in paragraphs[6:14] if not p.text]
    for p in blanks[:2]:
        p.paragraph_format.line_spacing = Pt(1)
        p.paragraph_format.space_after = Pt(0)


def refresh_fields(output, pdf):
    """Refresh Word fields without keeping Word's changes to opaque ZIP parts."""
    before = output.read_bytes()
    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ROOT / "scripts/reports/word_export.ps1"),
            "-InputDocx",
            str(output),
            "-OutputPdf",
            str(pdf),
            "-UpdateFields",
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    rel_ns = "http://schemas.openxmlformats.org/package/2006/relationships"
    doc_ns = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    with ZipFile(BytesIO(before)) as base, ZipFile(output) as updated:

        def signatures(archive):
            rels = etree.fromstring(archive.read("word/_rels/document.xml.rels"))
            return {
                el.get("Id"): (el.get("Type"), el.get("Target"), el.get("TargetMode"))
                for el in rels.findall("{" + rel_ns + "}Relationship")
            }

        base_rels, updated_rels = signatures(base), signatures(updated)
        reverse = {v: k for k, v in base_rels.items()}
        mapping = {k: reverse[v] for k, v in updated_rels.items() if v in reverse}
        content = etree.fromstring(updated.read("word/document.xml"))
        for el in content.iter():
            for attr, value in list(el.attrib.items()):
                if attr.startswith("{" + doc_ns + "}"):
                    if value not in mapping:
                        raise RuntimeError("Word introduced an unmapped document relationship")
                    el.set(attr, mapping[value])
        # Word normalizes built-in style IDs (for example toc1 -> TOC1).
        # Bind its cached field paragraphs back to the preserved base styles.
        styles = etree.fromstring(base.read("word/styles.xml"))
        native_styles = etree.fromstring(updated.read("word/styles.xml"))
        ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
        by_name = {
            el.find(qn("w:name")).get(qn("w:val")).casefold(): el.get(qn("w:styleId"))
            for el in styles.findall("w:style", ns)
        }
        used_ids = {el.get(qn("w:styleId")) for el in styles.findall("w:style", ns)}
        style_mapping, additions = {}, []
        for el in native_styles.findall("w:style", ns):
            style_id = el.get(qn("w:styleId"))
            name = el.find(qn("w:name")).get(qn("w:val")).casefold()
            if name in by_name:
                style_mapping[style_id] = by_name[name]
            else:
                new_id = style_id
                while new_id in used_ids:
                    new_id += "Extra"
                used_ids.add(new_id)
                style_mapping[style_id] = new_id
                addition = deepcopy(el)
                addition.set(qn("w:styleId"), new_id)
                additions.append(addition)
        style_refs = {
            qn("w:" + name) for name in ("pStyle", "rStyle", "tblStyle", "basedOn", "next", "link")
        }
        for root in (content, *additions):
            for el in root.iter():
                if el.tag in style_refs:
                    val = el.get(qn("w:val"))
                    if val in style_mapping:
                        el.set(qn("w:val"), style_mapping[val])
        styles.extend(additions)
        style_xml = etree.tostring(styles, encoding="UTF-8", xml_declaration=True, standalone=True)
        xml = etree.tostring(content, encoding="UTF-8", xml_declaration=True, standalone=True)
        rebuilt = BytesIO()
        with ZipFile(rebuilt, "w", ZIP_DEFLATED) as result:
            for name in base.namelist():
                value = (
                    xml
                    if name == "word/document.xml"
                    else style_xml
                    if name == "word/styles.xml"
                    else base.read(name)
                )
                result.writestr(name, value)
    output.write_bytes(rebuilt.getvalue())
    print("Word fields refreshed; preserved template package parts restored.")
    # Parsing validates the export response without publishing private path data.
    print(f"Native Word layout: {json.loads(completed.stdout)['Pages']} pages.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--source", type=Path, default=ROOT / "docs/reports/course-report.md")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cover-json", type=Path)
    parser.add_argument("--refresh-word", action="store_true")
    parser.add_argument("--qa-pdf", type=Path)
    args = parser.parse_args()
    if Path(sys.prefix).name.casefold() != "aegisforge":
        raise SystemExit("Run this tool in the Anaconda AegisForge environment.")
    if hashlib.sha256(args.template.read_bytes()).hexdigest() != REFERENCE_SHA:
        raise SystemExit(
            "Template differs from the reviewed reference. Inspect it before authoring."
        )
    output = args.output.resolve()
    if not output.is_relative_to(ROOT) or output.suffix.lower() != ".docx":
        raise SystemExit("Output must stay inside AegisForge.")
    if args.cover_json and not args.cover_json.resolve().is_relative_to(ROOT / "data"):
        raise SystemExit("Keep personal cover data in the ignored data directory.")
    if args.cover_json and not output.is_relative_to(ROOT / "data"):
        raise SystemExit("Keep the report with personal cover data inside ignored data/.")
    if args.refresh_word and (
        args.qa_pdf is None or not args.qa_pdf.resolve().is_relative_to(ROOT / "data")
    ):
        raise SystemExit("--refresh-word needs an internal --qa-pdf path inside data/.")
    source = args.source.resolve()
    if not source.is_relative_to(ROOT):
        raise SystemExit("Report source and generated diagrams must stay inside AegisForge.")
    make_diagrams(source.parent / "figures")
    doc = Document(args.template)
    configure_styles(doc)
    info = {} if not args.cover_json else json.loads(args.cover_json.read_text(encoding="utf-8"))
    fill_cover(doc, info)
    body = doc._element.body
    blocks = list(body)
    # Keep the original cover and complete scoring table. Reuse section 2 for
    # the contents page, and the original section 3/page counter for the report.
    second_break = deepcopy(blocks[28].find(qn("w:pPr")))
    for el in list(body)[27:-1]:
        body.remove(el)
    # Remove blank paragraphs immediately preceding the scoring table to avoid
    # the reference's accidental blank third page.
    for el in blocks[22:26]:
        if el.getparent() is body:
            body.remove(el)
    toc_p = add_toc(doc)
    sect = second_break.find(qn("w:sectPr"))
    toc_p._p.get_or_add_pPr().append(sect)
    lines = source.read_text(encoding="utf-8").splitlines()
    i, references = 0, False
    while i < len(lines):
        line = lines[i].strip()
        if not line:
            i += 1
            continue
        if line.startswith("```"):
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                p = add_text(doc, lines[i], "Report Code")
                p.paragraph_format.keep_with_next = not (
                    i + 1 < len(lines) and lines[i + 1].startswith("```")
                )
                i += 1
            i += 1
            continue
        if line.startswith("|"):
            buf = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                buf.append(lines[i])
                i += 1
            table(doc, buf)
            continue
        match = re.fullmatch(r"!\[(.*?)\]\((.*?)\)", line)
        if match:
            picture(doc, match[2], match[1], source.parent)
        elif line.startswith("### "):
            text = re.sub(r"^(\d+)\s+", r"\1．", line[4:])
            add_text(doc, text, "Heading 3")
        elif line.startswith("## "):
            text = re.sub(r"^([一二三四五六七八九十]+)\s+", r"（\1）", line[3:])
            add_text(doc, text, "Heading 2")
        elif line.startswith("# "):
            text = line[2:]
            references = text == "参考文献"
            text = re.sub(r"^([一二三四五六七八九十]+)\s+", r"\1、", text)
            add_text(doc, text, "Heading 1")
        elif re.match(r"表(?:\d+|[AB]\d+)\s", line):
            p = add_text(doc, line, "Report Caption")
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.keep_with_next = True
            p.paragraph_format.space_before = Pt(5)
            p.paragraph_format.space_after = Pt(3)
        else:
            add_text(doc, line, "Report Reference" if references else "Report Body")
        i += 1
    settings = doc.settings.element
    update = settings.find(qn("w:updateFields"))
    if update is None:
        settings.append(xml_element("w:updateFields", val="true"))
    else:
        update.set(qn("w:val"), "true")
    doc.core_properties.author = ""
    doc.core_properties.last_modified_by = ""
    doc.core_properties.title = "铸盾 AegisForge 基于LLM的Web代码漏洞智能检测与修复系统"
    doc.core_properties.subject = "网络空间安全技术课程实践报告"
    doc.core_properties.comments = ""
    stream = BytesIO()
    doc.save(stream)
    # python-docx is used for substantial body construction, not to reconstruct
    # opaque reference parts. Restore all preserve-only ZIP members byte-for-byte.
    output.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(args.template) as original, ZipFile(stream) as built:
        with ZipFile(output, "w", ZIP_DEFLATED) as result:
            for name in built.namelist():
                result.writestr(name, original.read(name) if name in PRESERVE else built.read(name))
            for name in original.namelist():
                if name not in built.namelist():
                    result.writestr(name, original.read(name))
    print(f"Built {output.name}; {len(doc.paragraphs)} paragraphs, {len(doc.tables)} tables.")
    if not args.cover_json:
        print("Cover has placeholders. Personal data was not supplied.")
    if args.refresh_word:
        refresh_fields(output, args.qa_pdf.resolve())


if __name__ == "__main__":
    main()
