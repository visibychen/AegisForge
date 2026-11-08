"""Static impact review of a candidate patch plus the repair gate ledger.

Nothing here executes uploaded or model code. Three questions are answered from text only:

1. *Which findings changed?*  Before/after findings are matched through a line map built from
   the real original-vs-candidate diff (never from the model's claimed edit ranges), so a
   second vulnerability of the same CWE elsewhere is neither a "failed target" nor invisible.
2. *Did the patch keep the program's shape?*  Definitions, signatures and decorators must stay;
   forbidden dynamic calls may not appear; whole-file rewrites are refused.
3. *Which gates passed?*  Every check becomes one explicit gate (passed / failed / skipped /
   pending / error) so "unverified" always has a visible reason.
"""

import ast
import difflib
from collections import Counter
from dataclasses import dataclass, field

from app.core.errors import DomainError
from app.rules.detector import Scope

MAX_DISTANCE = 15  # lines between an edit and the target before it is called "far"
WIDE_MIN_LINES = 40  # whole-file rewrite checks only apply to files at least this long
WIDE_REFUSE = 0.6
WIDE_WARN = 0.4
FORBIDDEN_ADDED = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "pickle.load",
        "pickle.loads",
        "marshal.load",
        "marshal.loads",
        "yaml.load",
    }
)
RISKY_ADDED = frozenset(
    {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}
)
STATIC_GATES = (
    "syntax",
    "patch",
    "structure",
    "target_rules",
    "new_rules",
    "target_model",
    "new_model",
)
DYNAMIC_GATES = ("dynamic_security", "dynamic_business")
GATE_LABELS = {
    "syntax": "语法校验",
    "patch": "补丁可应用（diff 回放一致）",
    "structure": "结构保持与改动范围",
    "target_rules": "目标漏洞已消除（规则）",
    "new_rules": "未引入新风险（规则）",
    "target_model": "目标漏洞已消除（模型复检）",
    "new_model": "未引入新风险（模型复检）",
    "dynamic_security": "受控动态验证：安全回归",
    "dynamic_business": "受控动态验证：业务回归",
}
TOOL_ERRORS = frozenset(
    {"TASK_TIMEOUT", "REPAIR_INTERNAL", "LEASE_EXHAUSTED", "ANALYSIS_CONFIG_CHANGED"}
)


class PatchScopeError(DomainError):
    def __init__(self, impact: dict):
        super().__init__("PATCH_SCOPE", "候选改动超出允许范围，详见变更影响。", 422)
        self.impact = impact


@dataclass
class LineMap:
    reverse: dict[int, int] = field(default_factory=dict)  # new line -> old line (unchanged)
    blocks: list[tuple[int, int, int, int]] = field(default_factory=list)  # o1,o2,n1,n2 (1-based)


def build_line_map(old: str, new: str) -> LineMap:
    matcher = difflib.SequenceMatcher(None, old.splitlines(), new.splitlines(), autojunk=False)
    line_map = LineMap()
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for offset in range(i2 - i1):
                line_map.reverse[j1 + offset + 1] = i1 + offset + 1
        else:
            line_map.blocks.append((i1 + 1, i2, j1 + 1, j2))
    return line_map


def old_lines_for(line_map: LineMap, start: int, end: int) -> set[int]:
    """Original lines that new lines start..end descend from (empty: purely inserted code)."""
    result: set[int] = set()
    for number in range(start, end + 1):
        if number in line_map.reverse:
            result.add(line_map.reverse[number])
            continue
        for o1, o2, n1, n2 in line_map.blocks:
            if n1 <= number <= n2:
                if o2 >= o1 and o2 - o1 == n2 - n1:
                    result.add(o1 + number - n1)  # equal-sized rewrite: line-for-line
                else:
                    result.update(range(o1, o2 + 1))
                break
    return result


def locations(findings, source: str) -> list[tuple]:
    """(cwe, start, end, source) for source-kind findings given as models or plain dicts."""
    result = []
    for item in findings:
        data = item if isinstance(item, dict) else item.model_dump(mode="json")
        location = data["location"]
        if location.get("kind") == "source":
            result.append((data["cwe"], location["start_line"], location["end_line"], source))
    return result


PATCH_REVIEW_VERSION = "patch-review-1.0"


def _slots(items):
    # Parent results and a fresh rule pass are separate channels; take the maximum
    # multiplicity, so re-running a rule cannot manufacture extra baseline capacity.
    positions = {}
    for cwe, start, end, source in items:
        positions.setdefault((cwe, start, end), Counter())[source] += 1
    slots = []
    for (cwe, start, end), channels in sorted(positions.items()):
        engines = set().union(*(set(c.removeprefix("parent:").split("+")) for c in channels))
        for _ in range(max(channels.values())):
            for group in slots:
                if (
                    group[0] == cwe
                    and not group[3] & engines
                    and group[1] <= end
                    and start <= group[2]
                ):
                    group[1], group[2] = max(group[1], start), min(group[2], end)
                    group[3].update(engines)
                    break
            else:
                slots.append([cwe, start, end, set(engines)])
    return slots


def finding_delta(baseline, target, after, line_map: LineMap, old_source="", new_source="") -> dict:
    """One-to-one matching. A prior risk can never explain two post-patch risks."""
    old, current = _slots(baseline), _slots(after)
    remaining, matched = set(range(len(old))), {}
    old_lines, new_lines = old_source.splitlines(), new_source.splitlines()

    def fingerprint(slot, lines):
        return " ".join("\n".join(lines[slot[1] - 1 : slot[2]]).split())

    def choose(index, choices):
        origin = old_lines_for(line_map, current[index][1], current[index][2])
        pick = min(
            choices,
            key=lambda i: (
                not any(old[i][1] <= line <= old[i][2] for line in origin),
                old[i][1],
                i,
            ),
        )
        remaining.remove(pick)
        matched[index] = pick

    # Exact evidence survives moves; prefer the mapped original when duplicate statements exist.
    if old_source and new_source:
        for index, slot in enumerate(current):
            text = fingerprint(slot, new_lines)
            choices = [
                i
                for i in remaining
                if old[i][0] == slot[0] and text and fingerprint(old[i], old_lines) == text
            ]
            if choices:
                choose(index, choices)
    for index, slot in enumerate(current):
        if index in matched:
            continue
        origin = old_lines_for(line_map, slot[1], slot[2])
        choices = [
            i
            for i in remaining
            if old[i][0] == slot[0] and any(old[i][1] <= line <= old[i][2] for line in origin)
        ]
        if choices:
            choose(index, choices)
    persisting, preexisting, introduced = [], [], []
    cwe, first, last = target
    for index, slot in enumerate(current):
        item = {
            "cwe": slot[0],
            "start_line": slot[1],
            "end_line": slot[2],
            "sources": sorted(slot[3]),
        }
        if index not in matched:
            item["unchanged_line"] = all(n in line_map.reverse for n in range(slot[1], slot[2] + 1))
            introduced.append(item)
        else:
            prior = old[matched[index]]
            (
                persisting
                if prior[0] == cwe and prior[1] <= last and first <= prior[2]
                else preexisting
            ).append(item)
    return {
        "target_resolved": not persisting,
        "persisting": persisting,
        "preexisting": preexisting,
        "introduced": introduced,
    }


def _definitions(tree: ast.Module) -> dict[str, tuple[dict, ast.AST]]:
    found: dict[str, tuple[dict, ast.AST]] = {}
    stack: list[tuple[ast.AST, str]] = [(tree, "")]
    while stack:
        node, prefix = stack.pop()
        children = list(ast.iter_child_nodes(node))
        for child in reversed(children):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                name, key, count = prefix + child.name, prefix + child.name, 1
                while key in found:
                    count += 1
                    key = f"{name}#{count}"
                signature = {
                    "kind": type(child).__name__,
                    "args": ast.dump(child.args) if not isinstance(child, ast.ClassDef) else "",
                    "bases": [ast.dump(b) for b in child.bases]
                    if isinstance(child, ast.ClassDef)
                    else [],
                    "decorators": [ast.dump(d) for d in child.decorator_list],
                }
                found[key] = (signature, child)
                stack.append((child, name + "."))
            else:
                stack.append((child, prefix))
    return found


def _imports(tree: ast.Module) -> tuple[set[int], set[str]]:
    lines, names = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import | ast.ImportFrom):
            lines.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
            module = getattr(node, "module", None) or ""
            names.update(f"{module}.{alias.name}".strip(".") for alias in node.names)
    return lines, names


def _call_counts(tree: ast.Module) -> Counter:
    scope, counts = Scope(tree), Counter()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            counts[scope.canonical(node.func)] += 1
            for keyword in node.keywords:
                if (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                ):
                    counts["shell=True"] += 1
    return counts


def _short(names, limit=12) -> list[str]:
    return [str(name)[:80] for name in sorted(names)[:limit]]


def _function_shape(node: ast.AST) -> tuple[int, int]:
    statements = sum(isinstance(n, ast.stmt) for n in ast.walk(node))
    returns = sum(isinstance(n, ast.Return) and n.value is not None for n in ast.walk(node))
    return statements, returns


def review_structure(old: str, new: str, target_start: int, target_end: int, line_map=None):
    """Footprint and structure report. ``violations`` refuse the patch, ``warnings`` do not."""
    line_map = line_map or build_line_map(old, new)
    old_tree, new_tree = ast.parse(old), ast.parse(new)
    old_defs, new_defs = _definitions(old_tree), _definitions(new_tree)
    violations, warnings = [], []
    removed = [name for name in old_defs if name not in new_defs]
    changed_signature = [
        name
        for name, (sig, _) in old_defs.items()
        if name in new_defs
        and (sig["args"] != new_defs[name][0]["args"] or sig["bases"] != new_defs[name][0]["bases"])
    ]
    changed_decorators = [
        name
        for name, (sig, _) in old_defs.items()
        if name in new_defs and sig["decorators"] != new_defs[name][0]["decorators"]
    ]
    if removed:
        violations.append("removed_definition")
    if changed_signature:
        violations.append("signature_changed")
    if changed_decorators:
        violations.append("decorator_changed")

    before_calls, after_calls = _call_counts(old_tree), _call_counts(new_tree)
    forbidden = [n for n in FORBIDDEN_ADDED if after_calls[n] > before_calls[n]]
    risky = [n for n in RISKY_ADDED if after_calls[n] > before_calls[n]]
    if forbidden:
        violations.append("forbidden_call_added")
    if risky:
        warnings.append("risky_call_added")
    if after_calls["shell=True"] > before_calls["shell=True"]:
        warnings.append("shell_true_added")

    total = max(len(old.splitlines()), 1)
    changed_old = sum(max(o2 - o1 + 1, 0) for o1, o2, _, _ in line_map.blocks)
    changed_new = sum(max(n2 - n1 + 1, 0) for _, _, n1, n2 in line_map.blocks)
    ratio = max(changed_old, changed_new) / total
    if total >= WIDE_MIN_LINES and ratio > WIDE_REFUSE:
        violations.append("wide_rewrite")
    elif total >= WIDE_MIN_LINES and ratio > WIDE_WARN:
        warnings.append("wide_change")

    old_import_lines, old_imports = _imports(old_tree)
    new_import_lines, new_imports = _imports(new_tree)
    nearest, far_code = 0 if not line_map.blocks else None, False
    for o1, o2, n1, n2 in line_map.blocks:
        low, high = (o1, o2) if o2 >= o1 else (o1, o1)
        distance = max(0, target_start - high, low - target_end)
        nearest = distance if nearest is None else min(nearest, distance)
        import_only = all(n in new_import_lines for n in range(n1, n2 + 1)) and all(
            o in old_import_lines for o in range(o1, o2 + 1)
        )
        if distance > MAX_DISTANCE and not import_only:
            far_code = True
    if far_code:
        warnings.append("far_edit")

    for name, (_, node) in old_defs.items():
        if name in new_defs and node.lineno <= target_start <= (node.end_lineno or node.lineno):
            if isinstance(node, ast.ClassDef):
                continue
            before, after = _function_shape(node), _function_shape(new_defs[name][1])
            if before[0] >= 6 and after[0] * 2 < before[0]:
                warnings.append("function_gutted")
            if before[1] > 0 and after[1] == 0:
                warnings.append("return_removed")
    return {
        "total_lines": total,
        "changed_lines": changed_old,
        "added_lines": changed_new,
        "change_ratio": round(ratio, 3),
        "hunks": len(line_map.blocks),
        "distance": nearest or 0,
        "removed": _short(removed),
        "signature_changed": _short(changed_signature),
        "decorator_changed": _short(changed_decorators),
        "forbidden_added": _short(forbidden),
        "risky_added": _short(risky),
        "imports_added": _short(new_imports - old_imports),
        "violations": violations,
        "warnings": list(dict.fromkeys(warnings)),
    }


def summarize(checks: dict) -> dict:
    """Derive the legacy aggregate keys and the static_passed flag from rules/model deltas."""
    delta = checks.get("delta") or {}
    rules, model = delta.get("rules"), delta.get("model")
    parts = [part for part in (rules, model) if part]
    checks["target_remaining"] = any(not part["target_resolved"] for part in parts)
    checks["new_findings"] = [item for part in parts for item in part["introduced"]]
    checks["preexisting"] = [item for part in parts for item in part["preexisting"]]
    checks["llm_complete"] = model is not None
    gates = {g["id"]: g["state"] for g in build_gates(checks, {}, None)}
    checks["static_passed"] = all(gates[name] == "passed" for name in STATIC_GATES)
    return checks


def _places(items, limit=4) -> str:
    return "、".join(f"{i['cwe']} 第{i['start_line']}行" for i in items[:limit])


def build_gates(checks: dict, dynamic: dict, binding) -> list[dict]:
    """One explicit gate per check. ``binding`` is False when dynamic evidence does not match."""
    simulated = checks.get("mode") == "fake"
    has_candidate = checks.get("syntax") == "passed"
    delta, review, impact = (
        checks.get("delta") or {},
        checks.get("review") or {},
        checks.get("impact"),
    )
    gates: list[dict] = []

    def add(key, state, detail=""):
        gates.append({"id": key, "label": GATE_LABELS[key], "state": state, "detail": detail})

    add("syntax", "passed" if has_candidate else "skipped", "" if has_candidate else "未生成候选")
    patched = (
        has_candidate and checks.get("patch") == "passed" and checks.get("roundtrip") == "passed"
    )
    add("patch", "passed" if patched else "skipped", "" if patched else "未生成候选")
    if not impact:
        add("structure", "skipped", "未生成候选")
    elif impact["violations"]:
        add("structure", "failed", "、".join(impact["violations"]))
    else:
        add(
            "structure",
            "passed",
            "提示：" + "、".join(impact["warnings"]) if impact["warnings"] else "",
        )

    def delta_gates(kind, part, unavailable):
        target, new = f"target_{kind}", f"new_{kind}"
        if simulated:
            add(target, "skipped", "模拟流程，未修改源码")
            add(new, "skipped", "模拟流程，未修改源码")
        elif part is None:
            state = "pending" if unavailable == "pending" else "skipped"
            add(target, state, unavailable if unavailable != "pending" else "复检进行中")
            add(new, state, unavailable if unavailable != "pending" else "复检进行中")
        else:
            add(
                target,
                "passed" if part["target_resolved"] else "failed",
                "" if part["target_resolved"] else "仍存在：" + _places(part["persisting"]),
            )
            add(
                new,
                "failed" if part["introduced"] else "passed",
                "复检新报告（可能既有漏检或上下文影响）：" + _places(part["introduced"])
                if part["introduced"]
                else (
                    "另有原有问题：" + _places(part["preexisting"]) if part["preexisting"] else ""
                ),
            )

    delta_gates("rules", delta.get("rules"), "未生成候选")
    status = review.get("status")
    if status == "pending":
        delta_gates("model", None, "pending")
    elif status == "failed":
        delta_gates("model", None, f"模型复检未完成（{review.get('error') or 'UNKNOWN'}）")
    elif status == "complete":
        delta_gates("model", delta.get("model"), "")
    else:
        delta_gates("model", None, "未进行模型复检")

    def dynamic_gate(key, prefix):
        state = dynamic.get("status")
        if state in (None, "cancelled"):
            add(key, "skipped", "未请求受控动态验证" if state is None else "动态验证已取消")
        elif state in ("pending", "running"):
            add(key, "pending", "等待独立验证 runner" if state == "pending" else "验证运行中")
        elif state == "error":
            add(key, "error", dynamic.get("error_code") or "VALIDATION_ENVIRONMENT")
        elif binding is False:
            add(key, "error", "验证记录与当前候选不一致或已被改动")
        else:
            tests = [t for t in dynamic.get("tests", []) if t["name"].startswith(prefix)]
            if not tests:
                add(key, "error", "缺少对应测试")
            elif all(t["passed"] for t in tests):
                add(key, "passed")
            else:
                add(key, "failed", "、".join(t["name"] for t in tests if not t["passed"]))

    dynamic_gate("dynamic_security", "security_")
    dynamic_gate("dynamic_business", "business_")
    return gates


def verdict_for(status: str, error_code, checks: dict, gates: list[dict]) -> str:
    if checks.get("mode") == "fake" or status in {"queued", "running", "cancelled"}:
        return "unverified"
    if status == "failed":
        if error_code and (error_code.startswith("MODEL_") or error_code in TOOL_ERRORS):
            return "error"
        return "unverified" if error_code == "REPAIR_STALE" else "failed"
    states = [gate["state"] for gate in gates]
    if "failed" in states:
        return "failed"
    if "error" in states:
        return "error"
    return "passed" if all(state == "passed" for state in states) else "unverified"
