"""Bounded intraprocedural name semantics shared by rules, adjudication and same-flow merging.

Nothing here executes code. The analysis walks the AST of the original source once and records,
for every statement, which definitions of each local name can reach it:

* a direct (unconditional) assignment kills earlier definitions of that name;
* branches, loops (which may run zero times), ``try`` and ``match`` join their paths, so a
  conditional or loop-body assignment never erases a definition that is still reachable;
* a few early-exit *guards* (``if not V(x): abort/return/raise``) constrain ``x`` on the
  fall-through path only, and any later reassignment replaces the guarded definition;
* anything not understood (unknown statements, ``global``/``nonlocal``, closures, walrus,
  unreachable code) is conservative: it adds definitions or yields ``UNKNOWN``.

Names used as callees are trusted (e.g. as ``subprocess.run`` or ``int``) only when every reaching
definition is the same import, or when the name is an unbound builtin. Parameters, local
assignments and local ``def``s shadow imports and builtins.
"""

import ast
import builtins
import re
from dataclasses import dataclass

try:  # Python 3.11+: the regex parser lives in re._parser
    import re._constants as sre_constants
    import re._parser as sre_parse
except ImportError:  # pragma: no cover - older runtimes
    import sre_constants
    import sre_parse

BUILTINS = frozenset(dir(builtins))
CATEGORIES = ("xss", "sqli", "cmdi")
MUTATING_METHODS = frozenset(
    {
        "add",
        "update",
        "append",
        "extend",
        "insert",
        "clear",
        "pop",
        "popitem",
        "remove",
        "discard",
        "setdefault",
        "sort",
        "reverse",
        "difference_update",
        "intersection_update",
        "symmetric_difference_update",
        "__setitem__",
        "__delitem__",
        "__ior__",
        "__iadd__",
    }
)
# Characters that may change the meaning of a value at a sink (ASCII only; validated values
# must not contain any of them). SQL is stricter: only digit-only patterns are accepted.
DANGEROUS = {
    "cmdi": frozenset(" \t\n\r\x0b\x0c;&|$`<>(){}[]*?!~#'\"\\=%^,"),
    "xss": frozenset("<>\"'&`=/:;() \t\n\r\\"),
}
DIGITS = frozenset("0123456789")
ABORT_CALLS = frozenset({"flask.abort", "werkzeug.exceptions.abort"})


@dataclass(frozen=True)
class Param:
    """A function parameter: caller-controlled, always untrusted."""


@dataclass(frozen=True)
class Unknown:
    """A binding we do not model (def, class, except-as, with-as, unbound name, ...)."""


@dataclass(frozen=True)
class Import:
    name: str


@dataclass(frozen=True)
class Element:
    """One element of an iterable (a ``for`` target)."""

    iterable: ast.AST


@dataclass(frozen=True)
class Guard:
    """The value of ``inner`` after an early-exit guard proved it safe for ``safe_for``."""

    safe_for: frozenset
    inner: frozenset


PARAM, UNKNOWN = Param(), Unknown()
OWNER_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
MAX_STATE_ENTRIES = 100_000


def _join(left, right):
    if left is None:
        return right
    if right is None:
        return left
    merged = dict(left)
    for name, defs in right.items():
        merged[name] = merged.get(name, frozenset()) | defs
    return merged


def _iter_children(node):
    """Child nodes in the same scope (stops at nested functions, lambdas and classes)."""
    for child in ast.iter_child_nodes(node):
        if not isinstance(child, (*OWNER_TYPES, ast.ClassDef)):
            yield child


class Semantics:
    def __init__(self, tree: ast.Module):
        self.tree = tree
        self.parent: dict[ast.AST, ast.AST] = {}
        self.owner: dict[ast.AST, ast.AST | None] = {}
        self.statement: dict[ast.AST, ast.stmt] = {}
        self.before: dict[ast.stmt, dict | None] = {}
        self.locals: dict[ast.AST | None, set] = {None: set()}
        self.params: dict[ast.AST, set] = {}
        self.all_defs: dict[ast.AST | None, dict] = {None: {}}
        self.mutated: set[str] = set()
        self.imports: dict[str, str] = {}
        self.state_entries = 0
        self.exhausted = False
        self._index()
        self._block(tree.body, {}, None)
        for owner in list(self.params):
            if isinstance(owner, ast.Lambda):
                continue
            state = {name: frozenset({PARAM}) for name in self.params[owner]}
            self._block(owner.body, state, owner)

    # --- indexing ---------------------------------------------------------------------------

    def _index(self):
        stack = [(self.tree, None, None)]
        while stack:
            node, owner, stmt = stack.pop()
            self.owner[node] = owner
            if isinstance(node, ast.stmt):
                stmt = node
            if stmt is not None:
                self.statement[node] = stmt
            if isinstance(node, OWNER_TYPES):
                self.params[node] = {a.arg for a in self._arguments(node.args)}
                self.locals[node] = set(self.params[node])
                self.all_defs[node] = {name: {PARAM} for name in self.params[node]}
                if not isinstance(node, ast.Lambda):
                    self._bind_name(owner, node.name, UNKNOWN)
                for child in ast.iter_child_nodes(node):
                    inner = child in getattr(node, "body", []) or child is getattr(
                        node, "body", None
                    )
                    self.parent[child] = node
                    stack.append((child, node if inner else owner, None if inner else stmt))
                continue
            if isinstance(node, ast.ClassDef):
                self._bind_name(owner, node.name, UNKNOWN)
            self._collect_binding(node, owner)
            for child in ast.iter_child_nodes(node):
                self.parent[child] = node
                stack.append((child, owner, stmt))

    @staticmethod
    def _arguments(arguments):
        every = arguments.posonlyargs + arguments.args + arguments.kwonlyargs
        return every + [a for a in (arguments.vararg, arguments.kwarg) if a]

    def _bind_name(self, owner, name, definition):
        self.locals.setdefault(owner, set()).add(name)
        self.all_defs.setdefault(owner, {}).setdefault(name, set()).add(definition)

    def _collect_binding(self, node, owner):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if isinstance(node, ast.Import):
                    local = alias.asname or alias.name.split(".")[0]
                    full = alias.name if alias.asname else local
                elif node.module and node.level == 0:
                    local, full = alias.asname or alias.name, f"{node.module}.{alias.name}"
                else:
                    local, full = alias.asname or alias.name, None
                self._bind_name(owner, local, Import(full) if full else UNKNOWN)
                if owner is None and full:
                    self.imports.setdefault(local, full)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                self.mutated.add(name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                self._collect_target(target, node.value, owner)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and node.value is not None:
            if isinstance(node.target, ast.Name):
                self._bind_name(
                    owner, node.target.id, node if isinstance(node, ast.AugAssign) else node.value
                )
                if isinstance(node, ast.AugAssign):
                    self.mutated.add(node.target.id)
            else:
                self._mark_mutation(node.target)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self._collect_target(node.target, Element(node.iter), owner)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    self._collect_target(item.optional_vars, UNKNOWN, owner)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            self._bind_name(owner, node.name, UNKNOWN)
        elif isinstance(node, ast.NamedExpr):
            self._bind_name(owner, node.target.id, node.value)
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._bind_name(owner, target.id, UNKNOWN)
                else:
                    self._mark_mutation(target)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in MUTATING_METHODS:
                self._mark_mutation(node.func.value)
        elif isinstance(node, ast.MatchAs | ast.MatchStar) and getattr(node, "name", None):
            self._bind_name(owner, node.name, UNKNOWN)

    def _collect_target(self, target, value, owner):
        if isinstance(target, ast.Name):
            self._bind_name(owner, target.id, value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._collect_target(element, value, owner)
        elif isinstance(target, ast.Starred):
            self._collect_target(target.value, value, owner)
        else:
            self._mark_mutation(target)

    def _mark_mutation(self, target):
        while isinstance(target, (ast.Attribute, ast.Subscript)):
            target = target.value
        if isinstance(target, ast.Name):
            self.mutated.add(target.id)

    # --- flow ---------------------------------------------------------------------------------

    def _block(self, statements, state, owner):
        for stmt in statements:
            cost = 1 + len(state or {})
            if self.exhausted or self.state_entries + cost > MAX_STATE_ENTRIES:
                self.exhausted = True
                self.before[stmt] = None
                return None
            self.state_entries += cost
            self.before[stmt] = state
            if state is None:
                continue  # unreachable: recorded as None so lookups stay conservative
            state = self._statement(stmt, state, owner)
        return state

    def _statement(self, stmt, state, owner):
        state = dict(state)
        for node in self._same_statement_nodes(stmt):
            if isinstance(node, ast.NamedExpr):  # never kills: it may not have run
                state[node.target.id] = state.get(node.target.id, frozenset()) | {node.value}
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                self._bind(target, stmt.value, state)
        elif isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                self._bind(stmt.target, stmt.value, state)
        elif isinstance(stmt, ast.AugAssign):
            if isinstance(stmt.target, ast.Name):
                state[stmt.target.id] = frozenset({stmt})
        elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
            entry, out = state, state
            for _ in range(2):  # zero, one or more iterations
                body_in = dict(entry)
                if not isinstance(stmt, ast.While):
                    self._bind(stmt.target, Element(stmt.iter), body_in)
                body_out = self._block(stmt.body, body_in, owner)
                out = _join(out, body_out)
                entry = _join(entry, body_out)
            return self._block(stmt.orelse, out, owner) if stmt.orelse else out
        elif isinstance(stmt, ast.If):
            body = self._block(stmt.body, dict(state), owner)
            if stmt.orelse:
                other = self._block(stmt.orelse, dict(state), owner)
            elif body is None:
                other = self._guarded(stmt.test, state, owner)
            else:
                other = state
            return _join(body, other)
        elif isinstance(stmt, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            body = self._block(stmt.body, dict(state), owner)
            # An exception may leave the body after any statement: join every point reached.
            anywhere = _join(state, body)
            for inner_stmt in ast.walk(ast.Module(body=stmt.body, type_ignores=[])):
                if isinstance(inner_stmt, ast.stmt) and self.owner.get(inner_stmt) is owner:
                    anywhere = _join(anywhere, self.before.get(inner_stmt))
            result = self._block(stmt.orelse, body, owner) if stmt.orelse and body else body
            for handler in stmt.handlers:
                inner = dict(anywhere)
                if handler.name:
                    inner[handler.name] = frozenset({UNKNOWN})
                result = _join(result, self._block(handler.body, inner, owner))
            if stmt.finalbody:
                start = result if result is not None else anywhere
                final = self._block(stmt.finalbody, dict(start), owner)
                return final if result is not None else None
            return result
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                if item.optional_vars is not None:
                    self._bind(item.optional_vars, item.context_expr, state)
            return self._block(stmt.body, state, owner)
        elif isinstance(stmt, ast.Match):
            result = state
            for case in stmt.cases:
                inner = dict(state)
                for node in ast.walk(case.pattern):
                    name = getattr(node, "name", None)
                    if isinstance(node, (ast.MatchAs, ast.MatchStar)) and name:
                        inner[name] = frozenset({UNKNOWN})
                result = _join(result, self._block(case.body, inner, owner))
            return result
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            state[stmt.name] = frozenset({UNKNOWN})
        elif isinstance(stmt, (ast.Import, ast.ImportFrom)):
            for alias in stmt.names:
                if isinstance(stmt, ast.Import):
                    local = alias.asname or alias.name.split(".")[0]
                    full = alias.name if alias.asname else local
                elif stmt.module and stmt.level == 0:
                    local, full = alias.asname or alias.name, f"{stmt.module}.{alias.name}"
                else:
                    local, full = alias.asname or alias.name, None
                state[local] = frozenset({Import(full) if full else UNKNOWN})
        elif isinstance(stmt, ast.Delete):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    state[target.id] = frozenset({UNKNOWN})
        elif isinstance(stmt, (ast.Return, ast.Raise)):
            return None
        elif isinstance(stmt, ast.Expr) and self._is_abort(stmt.value):
            return None
        return state

    def _same_statement_nodes(self, stmt):
        """Expression nodes evaluated by this statement itself (not nested statement bodies)."""
        roots = []
        for field, value in ast.iter_fields(stmt):
            if field in {"body", "orelse", "finalbody", "handlers", "cases"}:
                continue
            roots.extend(value if isinstance(value, list) else [value])
        stack = [r for r in roots if isinstance(r, ast.AST)]
        while stack:
            node = stack.pop()
            yield node
            stack.extend(_iter_children(node))

    def _bind(self, target, value, state):
        if isinstance(target, ast.Name):
            state[target.id] = frozenset({value})
        elif isinstance(target, (ast.Tuple, ast.List)):
            values = value.elts if isinstance(value, (ast.Tuple, ast.List)) else None
            starred = any(isinstance(e, ast.Starred) for e in target.elts)
            if (
                values is not None
                and not starred
                and len(values) == len(target.elts)
                and not any(isinstance(v, ast.Starred) for v in values)
            ):
                for element, item in zip(target.elts, values, strict=True):
                    self._bind(element, item, state)
            else:
                for element in target.elts:
                    self._bind(element, value, state)  # each name gets the whole value
        elif isinstance(target, ast.Starred):
            self._bind(target.value, value, state)

    def _is_abort(self, node):
        return isinstance(node, ast.Call) and self.trusted(node.func) in ABORT_CALLS

    def _guarded(self, test, state, owner):
        """Fall-through state after ``if <test>: <exit>`` (only recognised forms constrain)."""
        tests = (
            test.values if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or) else [test]
        )
        guarded = dict(state)
        for item in tests:
            fact = self._guard_fact(item)
            if fact is None:
                continue
            name, safe_for = fact
            defs = guarded.get(name)
            if defs:  # only a local with known reaching definitions can be constrained
                guarded[name] = frozenset({Guard(frozenset(safe_for), frozenset(defs))})
        return guarded

    def _guard_fact(self, test):
        # if x not in CONSTANT_COLLECTION: exit
        if (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.NotIn)
            and isinstance(test.left, ast.Name)
            and self.constant_collection(test.comparators[0])
        ):
            return test.left.id, CATEGORIES
        # if not <validator>(x): exit     /    if <validator>(x) is None: exit
        call = None
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            call = test.operand
        elif (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Is)
            and isinstance(test.comparators[0], ast.Constant)
            and test.comparators[0].value is None
        ):
            call = test.left
        if not isinstance(call, ast.Call):
            return None
        return self._validator(call)

    def _validator(self, call):
        func = call.func
        # x.isdigit() and friends on a plain local name
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and not call.args
            and not call.keywords
        ):
            if func.attr in {"isdigit", "isdecimal"}:
                return func.value.id, CATEGORIES
            if func.attr in {"isalnum", "isalpha", "isnumeric"}:
                return func.value.id, ("xss", "cmdi")
        pattern, flags, subject = None, 0, None
        if self.trusted(func) == "re.fullmatch" and len(call.args) >= 2:
            pattern = self.constant_string(call.args[0])
            subject = call.args[1]
            if len(call.args) > 2 or call.keywords:
                flags = None
        elif isinstance(func, ast.Attribute) and func.attr == "fullmatch" and len(call.args) == 1:
            compiled = self.compiled_pattern(func.value)
            if compiled is not None:
                pattern, flags = compiled
                subject = call.args[0]
        if pattern is None or flags is None or not isinstance(subject, ast.Name):
            return None
        safe_for = regex_safety(pattern, flags)
        return (subject.id, safe_for) if safe_for else None

    # --- lookups ------------------------------------------------------------------------------

    def enclosing(self, owner):
        node = self.parent.get(owner)
        while node is not None and not isinstance(node, OWNER_TYPES):
            node = self.parent.get(node)
        return node

    def defs(self, name: str, node: ast.AST) -> frozenset:
        """Definitions of ``name`` that can reach the use ``node``."""
        if self.exhausted:
            return frozenset({UNKNOWN})
        owner = self.owner.get(node)
        current = owner
        while current is not None:
            if name in self.locals.get(current, ()):
                if isinstance(current, ast.Lambda) or current is not owner:
                    return frozenset(self.all_defs[current].get(name) or {UNKNOWN})
                state = self.before.get(self.statement.get(node))
                found = state.get(name) if state else None
                return frozenset(found) if found else frozenset({UNKNOWN})
            current = self.enclosing(current)
        if name in self.locals[None]:
            if owner is None:
                state = self.before.get(self.statement.get(node))
                found = state.get(name) if state else None
                if found:
                    return frozenset(found)
            return frozenset(self.all_defs[None].get(name) or {UNKNOWN})
        return frozenset({UNKNOWN})

    def bound(self, name: str, node: ast.AST) -> bool:
        current = self.owner.get(node)
        while current is not None:
            if name in self.locals.get(current, ()):
                return True
            current = self.enclosing(current)
        return name in self.locals[None]

    def trusted(self, func: ast.AST) -> str | None:
        """Dotted name of a callee, only if its root is an unshadowed import or builtin."""
        if self.exhausted:
            return None
        parts = []
        node = func
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return None
        root = node.id
        if root in self.mutated:
            return None
        if not self.bound(root, node):
            base = root if root in BUILTINS else None
        else:
            defs = self.defs(root, node)
            names = {d.name for d in defs if isinstance(d, Import)}
            base = (
                names.pop()
                if len(names) == 1 and all(isinstance(d, Import) for d in defs)
                else None
            )
        if base is None:
            return None
        return ".".join([base, *reversed(parts)])

    def loose(self, func: ast.AST) -> str | None:
        """Name for *sink detection*: trusted names, plus names whose root is never bound.

        Partial snippets often call ``make_response`` or ``os.system`` without an import; such
        unbound roots keep their textual name so detection stays recall-oriented. A root that is
        bound to anything other than one import (a parameter, local or local def) yields None.
        Sanitizers and proofs must use :meth:`trusted` instead.
        """
        name = self.trusted(func)
        if name is not None:
            return name
        parts = []
        node = func
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name) and not self.bound(node.id, node):
            return ".".join([node.id, *reversed(parts)])
        return None

    def canonical(self, func: ast.AST) -> str:
        """Legacy, alias-only name (used for counting calls in patch review; never trusted)."""
        parts = []
        node = func
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        root = node.id if isinstance(node, ast.Name) else "?"
        return ".".join([self.imports.get(root, root), *reversed(parts)])

    def single_module_value(self, node):
        """The only module-level value bound to a never-mutated module name, else None."""
        if not isinstance(node, ast.Name) or node.id in self.mutated:
            return None
        if self.bound(node.id, node) and self.owner.get(node) is not None:
            current = self.owner.get(node)
            while current is not None:
                if node.id in self.locals.get(current, ()):
                    return None  # a local shadows the module name
                current = self.enclosing(current)
        values = self.all_defs[None].get(node.id) or set()
        if len(values) != 1:
            return None
        value = next(iter(values))
        return value if isinstance(value, ast.expr) else None

    def constant_string(self, node):
        for _ in range(8):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return node.value
            if not isinstance(node, ast.Name) or node.id in self.mutated:
                return None
            values = self.defs(node.id, node)
            if len(values) != 1:
                return None
            value = next(iter(values))
            if not isinstance(value, ast.expr):
                return None
            node = value
        return None

    def constant_collection(self, node) -> bool:
        value = node if isinstance(node, (ast.Set, ast.List, ast.Tuple, ast.Dict)) else None
        if value is None:
            value = self.single_module_value(node)
        if isinstance(value, ast.Call) and self.trusted(value.func) == "frozenset" and value.args:
            value = value.args[0]
        if isinstance(value, ast.Dict):
            items = value.keys
        elif isinstance(value, (ast.Set, ast.List, ast.Tuple)):
            items = value.elts
        else:
            return False
        return bool(items) and all(
            isinstance(item, ast.Constant) and isinstance(item.value, (str, int)) for item in items
        )

    def constant_dict(self, node) -> bool:
        value = self.single_module_value(node)
        return isinstance(value, ast.Dict) and all(
            isinstance(v, ast.Constant) for v in value.values
        )

    def compiled_pattern(self, node):
        value = self.single_module_value(node)
        if not isinstance(value, ast.Call) or self.trusted(value.func) != "re.compile":
            return None
        if not value.args or value.keywords or len(value.args) > 2:
            return None
        pattern = self.constant_string(value.args[0])
        if pattern is None:
            return None
        flags = 0
        if len(value.args) == 2:
            flag_name = (
                self.trusted(value.args[1]) if isinstance(value.args[1], ast.Attribute) else None
            )
            if flag_name in {"re.I", "re.IGNORECASE"}:
                flags = re.IGNORECASE
            elif flag_name in {"re.A", "re.ASCII"}:
                flags = re.ASCII
            else:
                return None
        return pattern, flags


def regex_safety(pattern: str, flags: int) -> tuple:
    """Categories a value fully matching ``pattern`` is safe for, or () when not provable.

    Only character classes, literals, repetition, groups and alternation are understood. ``.``,
    negated classes, look-arounds, back references and anything else make the result unknown.
    """
    try:
        parsed = sre_parse.parse(pattern, flags)
    except (re.error, TypeError, ValueError, OverflowError, RecursionError):
        return ()
    chars: set[str] = set()
    non_ascii = [False]
    only_digit_category = [True]

    def add_category(category):
        if category == sre_constants.CATEGORY_DIGIT:
            chars.update(DIGITS)
            non_ascii[0] = non_ascii[0] or not flags & re.ASCII
            return True
        if category == sre_constants.CATEGORY_WORD:
            only_digit_category[0] = False
            chars.update("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
            non_ascii[0] = non_ascii[0] or not flags & re.ASCII
            return True
        return False  # whitespace and negated categories are not accepted

    def walk(items, depth=0):
        if depth > 50:
            return False
        for op, argument in items:
            if op is sre_constants.LITERAL:
                chars.add(chr(argument))
            elif op is sre_constants.IN:
                for sub_op, sub_arg in argument:
                    if sub_op is sre_constants.LITERAL:
                        chars.add(chr(sub_arg))
                    elif sub_op is sre_constants.RANGE:
                        low, high = sub_arg
                        if high - low > 0x10000:
                            return False
                        for code in range(low, min(high, 0x7F) + 1):
                            chars.add(chr(code))
                        if high > 0x7F:
                            non_ascii[0] = True
                    elif sub_op is sre_constants.CATEGORY:
                        if not add_category(sub_arg):
                            return False
                    else:
                        return False  # NEGATE and anything unexpected
            elif op is sre_constants.CATEGORY:
                if not add_category(argument):
                    return False
            elif op in (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT):
                if not walk(argument[2], depth + 1):
                    return False
            elif op is sre_constants.SUBPATTERN:
                if not walk(argument[-1], depth + 1):
                    return False
            elif op is sre_constants.BRANCH:
                for alternative in argument[1]:
                    if not walk(alternative, depth + 1):
                        return False
            elif op is sre_constants.AT:
                continue
            else:
                return False  # ANY, NOT_LITERAL, ASSERT, GROUPREF, ...
        return True

    if not walk(parsed):
        return ()
    if flags & re.IGNORECASE:
        chars |= {c.swapcase() for c in chars}
    ascii_chars = {c for c in chars if ord(c) < 0x80}
    safe = [c for c, bad in DANGEROUS.items() if not ascii_chars & bad]
    if ascii_chars and ascii_chars <= DIGITS and not non_ascii[0] and only_digit_category[0]:
        safe.append("sqli")
    return tuple(sorted(safe))


# --- template contexts ------------------------------------------------------------------------

# Attributes in which an HTML-escaped, quoted value is plain text (never URL, script or style).
SAFE_ATTRIBUTES = frozenset(
    {
        "class",
        "id",
        "title",
        "alt",
        "name",
        "value",
        "placeholder",
        "lang",
        "dir",
        "for",
        "label",
        "width",
        "height",
        "colspan",
        "rowspan",
        "aria-label",
    }
)
_ATTRIBUTE = re.compile(r"([^\s\"'>/=]+)\s*=\s*$")


def hole_contexts(pieces: list[str]) -> list[str]:
    """Context of each hole between literal ``pieces`` of an HTML template.

    Returns one of: ``text``, ``attr-safe`` (quoted value of a plain attribute), ``script``
    (JavaScript code, outside any string), or ``unsafe`` for everything else (unquoted or
    dangerous attributes, JS strings, styles, comments, tags).
    """
    contexts = []
    prefix = ""
    for piece in pieces[:-1]:
        prefix += piece
        contexts.append(_context_at(prefix))
        prefix += "\x00"  # the hole itself: an opaque value
    return contexts


def _context_at(prefix: str) -> str:
    lower = prefix.lower()
    if lower.rfind("<!--") > lower.rfind("-->"):
        return "unsafe"
    for tag in ("script", "style", "textarea", "title", "noscript", "iframe", "template"):
        start, end = lower.rfind("<" + tag), lower.rfind("</" + tag)
        if start > end:
            close = lower.find(">", start)
            if close == -1:
                return "unsafe"  # inside the opening tag itself
            if tag != "script":
                return "unsafe"
            return _script_context(prefix[close + 1 :])
    open_tag, close_tag = lower.rfind("<"), lower.rfind(">")
    if open_tag <= close_tag:
        return "text"
    inside = prefix[open_tag:]
    quote, value_start = None, None
    for index, char in enumerate(inside):
        if quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote, value_start = char, index
    if quote is None:
        return "unsafe"  # tag name, attribute name or unquoted value
    name = _ATTRIBUTE.search(inside[:value_start])
    if name and name.group(1).lower() in SAFE_ATTRIBUTES:
        return "attr-safe"
    return "unsafe"


def _script_context(body: str) -> str:
    quote, escaped = None, False
    for char in body:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in "\"'`":
            quote = char
        elif char == "\x00":
            continue
    return "unsafe" if quote else "script"


_PERCENT = re.compile(r"%(?:\(([^)]*)\))?[-#0 +]*(?:\*|\d+)?(?:\.(?:\*|\d+))?[diouxXeEfFgGcrsa%]")


def percent_pieces(template: str):
    """Literal pieces and hole names of a ``%`` template (``None`` names are positional)."""
    pieces, names, last = [], [], 0
    for match in _PERCENT.finditer(template):
        if match.group(0).endswith("%") and match.group(0) == "%%":
            continue
        pieces.append(template[last : match.start()])
        names.append(match.group(1))
        last = match.end()
    pieces.append(template[last:])
    return [p.replace("%%", "%") for p in pieces], names


def format_pieces(template: str):
    """Literal pieces and field names of a ``str.format`` template, or None if unusual."""
    pieces, names, buffer, index = [], [], [], 0
    while index < len(template):
        char = template[index]
        if char == "{" and template.startswith("{{", index):
            buffer.append("{")
            index += 2
        elif char == "}" and template.startswith("}}", index):
            buffer.append("}")
            index += 2
        elif char == "{":
            end = template.find("}", index)
            if end == -1:
                return None
            pieces.append("".join(buffer))
            buffer = []
            names.append(template[index + 1 : end])
            index = end + 1
        elif char == "}":
            return None
        else:
            buffer.append(char)
            index += 1
    pieces.append("".join(buffer))
    return pieces, names
