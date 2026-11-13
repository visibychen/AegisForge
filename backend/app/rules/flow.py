"""Structural sinks and bounded def-use reachability shared by merging and adjudication.

A *structural* sink is a call/return of the kind a category is about (an SQL execute, a command
launcher, an HTML-producing return or call) regardless of whether its data is tainted. Callee
identity uses the same rules as detection (``Semantics.loose``); proofs additionally require a
trusted name. Reachability follows reaching definitions only (never "any earlier text").
"""

import ast

from app.rules.detector import (
    EXEC_ARGV,
    SHELL_ALWAYS,
    SHELL_OPTIONAL,
    SQL_METHODS,
    SQL_TEXT,
    sink_name,
)
from app.rules.semantics import Element, Guard, Semantics

CATEGORY = {"CWE-79": "xss", "CWE-89": "sqli", "CWE-78": "cmdi"}
MAX_REACH_STEPS = 4000


def structural_sink(node: ast.AST, category: str, sem: Semantics) -> bool:
    if category == "xss" and isinstance(node, ast.Return):
        return node.value is not None
    if not isinstance(node, ast.Call):
        return False
    name = sink_name(node, sem)
    if name is None:
        return False
    short = name.rsplit(".", 1)[-1]
    method = node.func.attr if isinstance(node.func, ast.Attribute) else None
    if category == "sqli":
        return method in SQL_METHODS or name in SQL_TEXT
    if category == "cmdi":
        return name in SHELL_ALWAYS or name in SHELL_OPTIONAL or name in EXEC_ARGV
    return short in {"render_template_string", "Markup", "make_response"}


def sinks_overlapping(tree, sem, category, start, end) -> list[ast.AST]:
    """Outermost structural sinks whose lines overlap ``start..end``."""
    found = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.Call, ast.Return))
        and node.lineno <= end
        and (node.end_lineno or node.lineno) >= start
        and structural_sink(node, category, sem)
    ]
    inner = set()
    for node in found:
        for child in ast.walk(node):
            if child is not node:
                inner.add(id(child))
    return [node for node in found if id(node) not in inner]


def sink_inputs(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.Return):
        return [node.value]
    return [*node.args, *(keyword.value for keyword in node.keywords)]


def assignment_markers(tree, start, end) -> tuple[set, ast.AST | None]:
    """Definitions created by assignments lying wholly within ``start..end`` (and their owner)."""
    markers, owners = set(), set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            continue
        if node.lineno < start or (node.end_lineno or node.lineno) > end:
            continue
        if isinstance(node, ast.AugAssign):
            markers.add(id(node))
        elif node.value is not None:
            markers.add(id(node.value))
            if isinstance(node.value, (ast.Tuple, ast.List)):
                markers.update(id(element) for element in node.value.elts)
        owners.add(id(node))
    return markers, owners


FOLLOW = (ast.AST, Guard, Element)


def reaches(sem: Semantics, expressions, markers: set) -> bool | None:
    """Whether any expression's value may come from a ``markers`` definition (None: unknown)."""
    stack = list(expressions)
    seen: set = set()
    steps = 0
    while stack:
        steps += 1
        if steps > MAX_REACH_STEPS:
            return None  # exhausted: neither "reaches" nor "does not reach" is claimed
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if id(node) in markers:
            return True
        if isinstance(node, Guard):
            stack.extend(node.inner)
        elif isinstance(node, Element):
            stack.append(node.iterable)
        elif isinstance(node, ast.Name):
            stack.extend(d for d in sem.defs(node.id, node) if isinstance(d, FOLLOW))
        elif isinstance(node, ast.AugAssign):
            stack.append(node.value)
            if isinstance(node.target, ast.Name):
                defs = sem.defs(node.target.id, node)
                stack.extend(d for d in defs if isinstance(d, FOLLOW))
        elif isinstance(node, ast.AST):
            stack.extend(ast.iter_child_nodes(node))
    return False


def downstream_sinks(tree, sem, category, start, end) -> list[ast.AST] | None:
    """Structural sinks fed by assignments in ``start..end`` (None: the range is not a feeder).

    A feeder range contains assignments and no structural sink of the category itself. All
    sinks of the category in the same function are checked, so a value feeding two sinks is
    reported as two (never silently collapsed into one).
    """
    if sinks_overlapping(tree, sem, category, start, end):
        return None
    markers, owners = assignment_markers(tree, start, end)
    if not markers:
        return None
    statements = [n for n in ast.walk(tree) if id(n) in owners]
    owner_set = {sem.owner.get(s) for s in statements}
    if len(owner_set) != 1:
        return None
    owner = owner_set.pop()
    candidates = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.Call, ast.Return))
        and sem.owner.get(node) is owner
        and structural_sink(node, category, sem)
    ]
    inner = set()
    for node in candidates:
        for child in ast.walk(node):
            if child is not node:
                inner.add(id(child))
    fed = []
    for node in candidates:
        if id(node) in inner:
            continue
        verdict = reaches(sem, sink_inputs(node), markers)
        if verdict is None:
            return None  # cannot tell which sinks are fed: no claim at all
        if verdict:
            fed.append(node)
    return fed


def terminal_sink(tree, sem, category, start, end):
    """One structural operation, or a constructor/assignment feeding exactly one operation."""
    if sem.exhausted:
        return None
    overlap = sinks_overlapping(tree, sem, category, start, end)
    if len(overlap) > 1:
        return None
    if not overlap:
        fed = downstream_sinks(tree, sem, category, start, end)
        return fed[0] if fed is not None and len(fed) == 1 else None
    sink = overlap[0]
    # Markup and SQL expression constructors are propagation points, not distinct executions.
    name = sink_name(sink, sem) if isinstance(sink, ast.Call) else None
    constructor = name in SQL_TEXT or (
        category == "xss" and name is not None and name.rsplit(".", 1)[-1] == "Markup"
    )
    if not constructor:
        return sink
    parent = sem.parent.get(sink)
    while parent is not None and not isinstance(parent, ast.stmt):
        parent = sem.parent.get(parent)
    if not isinstance(parent, (ast.Assign, ast.AnnAssign)):
        return sink
    markers = {id(parent.value)}
    candidates = [
        n
        for n in ast.walk(tree)
        if isinstance(n, (ast.Call, ast.Return))
        and sem.owner.get(n) is sem.owner.get(sink)
        and structural_sink(n, category, sem)
        and n is not sink
    ]
    fed = []
    for target in candidates:
        result = reaches(sem, sink_inputs(target), markers)
        if result is None:
            return None
        if result:
            fed.append(target)
    outer = [n for n in fed if not any(n is not p and n in ast.walk(p) for p in fed)]
    return outer[0] if len(outer) == 1 else sink
