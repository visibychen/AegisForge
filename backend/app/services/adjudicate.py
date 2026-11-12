"""Static semantic adjudication of merged findings (adjudication-1.2).

Every source finding, whatever its origin (rules, model or both), is checked the same way: its
location must map to exactly one structural sink of its CWE (or to assignments feeding exactly one
such sink), and that sink must satisfy one of the narrow, documented criteria below. Only then is
the finding *refuted* — moved out of the reported list into a bounded, visible summary with the
criterion's fixed name. Everything else is kept unchanged ("not refuted" never means "verified
vulnerable", and "refuted" never means "verified safe": it is a static, criterion-specific
argument about the code that was analysed).

Not used: confidence, source/engine, sample IDs, labels or any learned threshold.

Criteria:
* ``sql_text_has_no_untrusted_part``: the SQL text argument is built only from constants, values
  under a recognised guard, trusted casts or comprehension-generated fixed tokens (rules-1.2
  shape); bound parameters may carry untrusted values, known mutations invalidate this proof.
* ``shell_command_has_no_untrusted_part``: a constant shell command string.
* ``quoted_or_validated_shell_operands``: a restricted known data program with independently
  quoted/validated operands and no shell control structure (POSIX shell semantics assumed).
* ``argv_has_no_untrusted_part``: a trusted subprocess launcher without a shell whose whole
  argument vector is constant; input/stdin and executable overrides are excluded.
* ``argv_data_operands``: a launcher without a shell, a constant program from a small list of
  tools that never execute their operands, and every untrusted element either after a literal
  ``--`` or starting with a constant prefix that cannot begin an option.
* ``markup_escapes_plain_values``: ``Markup(CONST).format(...)``/``Markup(CONST) % ...`` where
  every hole is in HTML text or a quoted plain attribute and every argument is provably a plain
  ``str`` (never Markup or an unknown object that may implement ``__html__``).
* ``autoescaped_constant_template``: ``flask.render_template_string(CONST, k=v...)`` where the
  template has no ``{% %}``/``{# #}``, every ``{{ name }}`` has no filter and sits in HTML text or a
  quoted plain attribute, every keyword value is provably a plain ``str``, and the module never
  touches autoescape settings.
* ``json_encoded_in_script_data``: a constant ``%``/``format``/f-string template whose holes are
  either constants or ``json.dumps(...).replace("<", "\\u003c")`` placed in JavaScript code
  context (not inside a JS string).
"""

import ast
import posixpath
import re
import shlex

from app.rules.detector import (
    EXEC_ARGV,
    MARKUP,
    SHELL_ALWAYS,
    SHELL_OPTIONAL,
    SQL_KEYWORDS,
    _argument,
    argv_elements,
    program_name,
    shape,
    shell_requested,
)
from app.rules.flow import CATEGORY, downstream_sinks, sinks_overlapping
from app.rules.semantics import (
    Semantics,
    format_pieces,
    hole_contexts,
    percent_pieces,
)

ADJUDICATION_VERSION = "adjudication-1.2"
CRITERIA = frozenset(
    {
        "sql_text_has_no_untrusted_part",
        "shell_command_has_no_untrusted_part",
        "argv_has_no_untrusted_part",
        "argv_data_operands",
        "markup_escapes_plain_values",
        "autoescaped_constant_template",
        "json_encoded_in_script_data",
        "markup_of_constant_text",
        "quoted_or_validated_shell_operands",
    }
)
MAX_LISTED = 100
# Tools whose operands are data (files, hosts, URLs, archives); none of them executes an operand.
DATA_OPERAND_TOOLS = frozenset(
    {
        "du",
        "wc",
        "ls",
        "cat",
        "head",
        "tail",
        "stat",
        "file",
        "sha256sum",
        "sha1sum",
        "md5sum",
        "ping",
        "ping6",
        "traceroute",
        "tracepath",
        "nslookup",
        "dig",
        "host",
        "whois",
        "curl",
        "unzip",
    }
)
REQUEST_GETTERS = {"args", "form", "headers", "cookies", "values"}
JINJA_HOLE = re.compile(r"\{\{(.*?)\}\}", re.S)
JINJA_SIMPLE = re.compile(r"\s*[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\s*")
HTML_SAFE_CONTEXTS = {"text", "attr-safe"}


def adjudicate(entries: list[dict], parsed_by_id: dict) -> tuple[list[dict], dict]:
    """Split merged entries into (kept, summary). Never raises: errors keep the finding."""
    kept, refuted, rules = [], [], {}
    cache: dict = {}
    for entry in entries:
        verdict = None
        try:
            verdict = _judge(entry, parsed_by_id, cache)
        except (RecursionError, ValueError, TypeError, AttributeError, KeyError):
            verdict = None  # an analysis problem never removes a finding
        if verdict is None:
            kept.append(entry)
            continue
        rules[verdict] = rules.get(verdict, 0) + 1
        finding = entry["finding"]
        location = finding["location"]
        refuted.append(
            {
                "artifact_id": str(location["artifact_id"]),
                "cwe": finding["cwe"],
                "start_line": location["start_line"],
                "end_line": location["end_line"],
                "sources": list(finding.get("sources", [])),
                "contributors": entry.get("contributors", []),
                "criterion": verdict,
            }
        )
    summary = {
        "version": ADJUDICATION_VERSION,
        "examined": len(entries),
        "kept": len(kept),
        "refuted": len(refuted),
        "by_criterion": dict(sorted(rules.items())),
        "refuted_findings": refuted[:MAX_LISTED],
        "truncated": len(refuted) > MAX_LISTED,
        "note": "静态反证只针对所列判据，不代表输入已验证安全；未被反证的发现保持原状。",
    }
    return kept, summary


def _judge(entry, parsed_by_id, cache):
    finding = entry["finding"]
    location = finding["location"]
    category = CATEGORY.get(finding.get("cwe"))
    if location.get("kind") != "source" or category is None:
        return None
    key = str(location["artifact_id"])
    parsed = parsed_by_id.get(key)
    tree = getattr(parsed, "private_tree", None)
    if tree is None:
        return None
    if key not in cache:
        cache[key] = Semantics(tree)
    sem = cache[key]
    if sem.exhausted:
        return None
    start, end = location["start_line"], location["end_line"]
    sinks = sinks_overlapping(tree, sem, category, start, end)
    if not sinks:
        sinks = downstream_sinks(tree, sem, category, start, end) or []
    if len(sinks) != 1:
        return None  # zero or several candidate sinks: nothing is claimed
    return prove(sinks[0], category, sem, tree)


def prove(sink, category, sem: Semantics, tree) -> str | None:
    if category == "sqli":
        return _prove_sql(sink, sem)
    if category == "cmdi":
        return _prove_command(sink, sem)
    return _prove_html(sink, sem, tree)


def _prove_sql(sink, sem):
    if not isinstance(sink, ast.Call):
        return None
    query = _argument(sink, SQL_KEYWORDS)
    if query is None:
        return None
    if not _plain_guard_dependencies(query, sem):
        return None
    return None if shape("sqli", query, sem).tainted else "sql_text_has_no_untrusted_part"


def _plain_guard_dependencies(node, sem):
    from app.rules.semantics import Guard

    todo, seen = [node], set()
    while todo and len(seen) <= 4000:
        value = todo.pop()
        if id(value) in seen:
            continue
        seen.add(id(value))
        if isinstance(value, Guard):
            if not all(isinstance(d, ast.expr) and _plain_str(d, sem) for d in value.inner):
                return False
        elif isinstance(value, ast.Name):
            todo.extend(sem.defs(value.id, value))
        elif isinstance(value, ast.AST):
            todo.extend(ast.iter_child_nodes(value))
    return not todo


def _prove_command(sink, sem):
    if not isinstance(sink, ast.Call):
        return None
    name = sem.trusted(sink.func)
    if name is None:
        return None  # a shadowed or unknown launcher is never trusted
    shell = shell_requested(sink)
    if shell is None:
        return None
    if name in SHELL_ALWAYS or (name in SHELL_OPTIONAL and shell):
        command = _argument(sink, {"args", "cmd", "command"})
        # Quoting a sh -c/awk program does not stop that program being interpreted. Until a
        # complete command-context proof is available, refute shell findings only for constants.
        if command is None:
            return None
        if sem.constant_string(command) is not None:
            return "shell_command_has_no_untrusted_part"
        return _prove_shell_data(command, sem)
    if name not in EXEC_ARGV or shell:
        return None
    if any(keyword.arg in {"executable", "preexec_fn", "env"} for keyword in sink.keywords):
        return None
    values = argv_elements(sink, name, sem)
    if values is None:
        return None
    if any(k.arg in {"input", "stdin"} for k in sink.keywords):
        return None  # an interpreter can read a program from stdin even with constant argv
    program = program_name(values[0], sem)
    if program is None:
        return None
    tainted = [shape("cmdi", value, sem).tainted for value in values]
    if all(sem.constant_string(value) is not None for value in values):
        return "argv_has_no_untrusted_part"
    if tainted[0] or program not in DATA_OPERAND_TOOLS:
        return None  # unknown programs (awk, find, git, convert, ...) may execute operands
    flags = [sem.constant_string(value) for value in values]
    for index in range(1, len(values)):
        if not tainted[index]:
            continue
        if "--" in flags[1:index]:
            continue  # after the end-of-options marker every element is an operand
        previous = flags[index - 1]
        option_value = previous is not None and previous.startswith("-") and previous != "--"
        if not option_value and _constant_non_option_prefix(values[index], sem):
            continue
        return None
    return "argv_data_operands"


def _constant_non_option_prefix(node, sem):
    """The element starts with a constant, non-empty prefix that does not begin with '-'."""
    first = None
    if isinstance(node, ast.JoinedStr) and node.values:
        first = node.values[0]
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        first = node.left
        while isinstance(first, ast.BinOp) and isinstance(first.op, ast.Add):
            first = first.left
    text = sem.constant_string(first) if first is not None else None
    return bool(text) and not text.startswith("-")


# --- HTML ---------------------------------------------------------------------------------


def _single_value(node, sem, hops=3):
    """Follow a name through single reaching definitions (bounded)."""
    while isinstance(node, ast.Name) and hops > 0:
        defs = sem.defs(node.id, node)
        if len(defs) != 1:
            return None
        candidate = next(iter(defs))
        if not isinstance(candidate, ast.expr):
            return None
        node, hops = candidate, hops - 1
    return node


def _plain_str(node, sem, hops=4) -> bool:
    """Provably a plain ``str`` (not Markup, not an object that may implement __html__)."""
    if hops < 0:
        return False
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        if isinstance(node.op, ast.Mod):
            return _plain_str(node.left, sem, hops - 1)
        return _plain_str(node.left, sem, hops - 1) and _plain_str(node.right, sem, hops - 1)
    if isinstance(node, ast.Name):
        defs = sem.defs(node.id, node)
        return bool(defs) and all(
            isinstance(d, ast.expr) and _plain_str(d, sem, hops - 1) for d in defs
        )
    if isinstance(node, ast.Call):
        name = sem.trusted(node.func)
        if name == "str":
            # __str__ may legally return a str subclass (including Markup). Unknown objects
            # cannot prove plain-string escaping merely by being wrapped in str(...).
            return not node.keywords and (
                not node.args or (len(node.args) == 1 and _plain_str(node.args[0], sem, hops - 1))
            )
        if (
            name
            and name.startswith("flask.request.")
            and name.rsplit(".", 2)[-2] in REQUEST_GETTERS
            and name.endswith(".get")
        ):
            return all(_plain_str(argument, sem, hops - 1) for argument in node.args[1:]) and all(
                k.arg == "default" and _plain_str(k.value, sem, hops - 1) for k in node.keywords
            )
        return False
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute):
        owner = node.value
        return (
            owner.attr in REQUEST_GETTERS
            and isinstance(owner.value, ast.Name)
            and sem.trusted(owner.value) == "flask.request"
        )
    return False


def _json_script_value(node, sem, hops=3) -> bool:
    node = _single_value(node, sem, hops) if isinstance(node, ast.Name) else node
    allowed = {
        "<": "\\u003c",
        ">": "\\u003e",
        "&": "\\u0026",
        "\u2028": "\\u2028",
        "\u2029": "\\u2029",
    }
    escaped_lt = False
    for _ in range(8):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "replace"
            and len(node.args) == 2
            and not node.keywords
        ):
            break
        old, new = (sem.constant_string(argument) for argument in node.args)
        if old not in allowed or new != allowed[old]:
            return False  # no unescape/undo or arbitrary post-encoding transformations
        escaped_lt |= old == "<"
        node = node.func.value
    return (
        escaped_lt
        and isinstance(node, ast.Call)
        and sem.trusted(node.func) == "json.dumps"
        and len(node.args) == 1
        and all(
            k.arg == "ensure_ascii"
            and isinstance(k.value, ast.Constant)
            and type(k.value.value) is bool
            for k in node.keywords
        )
    )


def _template(node, sem):
    """(pieces, hole arguments) of a constant template expression, or None."""
    if isinstance(node, ast.JoinedStr):
        pieces, holes, buffer = [], [], ""
        for value in node.values:
            if isinstance(value, ast.Constant):
                buffer += value.value
            else:
                if value.format_spec is not None or value.conversion not in (-1, None):
                    return None
                pieces.append(buffer)
                buffer = ""
                holes.append(value.value)
        pieces.append(buffer)
        return pieces, holes
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        text = sem.constant_string(node.left)
        if text is None:
            return None
        pieces, names = percent_pieces(text)
        if any(name is not None for name in names):
            return None
        values = node.right.elts if isinstance(node.right, ast.Tuple) else [node.right]
        return (pieces, list(values)) if len(values) == len(names) else None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format" and not node.keywords:
            text = sem.constant_string(node.func.value)
            parsed = format_pieces(text) if text is not None else None
            if parsed is None or any(name not in ("",) for name in parsed[1]):
                return None
            pieces, names = parsed
            return (pieces, list(node.args)) if len(node.args) == len(names) else None
    return None


def _prove_markup(node, sem):
    """Markup(CONST).format(...) / Markup(CONST) % ... with plain-str values in HTML text."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr != "format" or node.keywords:
            return None
        receiver = node.func.value
        arguments = list(node.args)
        template_kind = "format"
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        receiver = node.left
        arguments = node.right.elts if isinstance(node.right, ast.Tuple) else [node.right]
        template_kind = "percent"
    else:
        return None
    if not (
        isinstance(receiver, ast.Call)
        and sem.trusted(receiver.func) in MARKUP
        and len(receiver.args) == 1
    ):
        return None
    text = sem.constant_string(receiver.args[0])
    if text is None:
        return None
    if template_kind == "format":
        parsed = format_pieces(text)
        if parsed is None or any(name != "" for name in parsed[1]):
            return None
        pieces, names = parsed
    else:
        pieces, names = percent_pieces(text)
        if any(name is not None for name in names):
            return None
    if len(names) != len(arguments):
        return None
    if not all(context in HTML_SAFE_CONTEXTS for context in hole_contexts(pieces)):
        return None
    if not all(_plain_str(argument, sem) for argument in arguments):
        return None
    return "markup_escapes_plain_values"


def _touches_autoescape(tree) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in {"autoescape", "jinja_options"}:
            return True
        if isinstance(node, ast.keyword) and node.arg in {"autoescape", "jinja_options"}:
            return True
    return False


def _prove_template(node, sem, tree):
    if not isinstance(node, ast.Call) or sem.trusted(node.func) != "flask.render_template_string":
        return None
    if len(node.args) != 1 or any(keyword.arg is None for keyword in node.keywords):
        return None
    text = sem.constant_string(node.args[0])
    if text is None or "{%" in text or "{#" in text or _touches_autoescape(tree):
        return None
    pieces, last = [], 0
    for match in JINJA_HOLE.finditer(text):
        if not JINJA_SIMPLE.fullmatch(match.group(1)):
            return None  # filters (|safe, custom), calls and expressions are not modelled
        pieces.append(text[last : match.start()])
        last = match.end()
    pieces.append(text[last:])
    if not all(context in HTML_SAFE_CONTEXTS for context in hole_contexts(pieces)):
        return None
    if not all(_plain_str(keyword.value, sem) for keyword in node.keywords):
        return None
    return "autoescaped_constant_template"


def _prove_json_script(node, sem):
    parsed = _template(node, sem)
    if parsed is None:
        return None
    pieces, holes = parsed
    contexts = hole_contexts(pieces)
    used = False
    for context, hole in zip(contexts, holes, strict=True):
        if isinstance(hole, ast.Constant) or sem.constant_string(hole) is not None:
            continue
        if context == "script" and _json_script_value(hole, sem):
            used = True
            continue
        return None
    return "json_encoded_in_script_data" if used else None


def _prove_html(sink, sem, tree):
    if isinstance(sink, ast.Return):
        value = _single_value(sink.value, sem) or sink.value
    else:
        value = sink
    if isinstance(value, ast.Call) and sem.trusted(value.func) == "flask.render_template_string":
        return _prove_template(value, sem, tree)
    if isinstance(value, ast.Call) and sem.trusted(value.func) in MARKUP:
        argument = value.args[0] if len(value.args) == 1 and not value.keywords else None
        if argument is not None and sem.constant_string(argument) is not None:
            return "markup_of_constant_text"
        return None
    return _prove_markup(value, sem) or _prove_json_script(value, sem)


def _alternatives(node, sem):
    pending, values, seen = [(node, 0)], [], set()
    while pending:
        current, depth = pending.pop()
        if depth > 8 or len(seen) > 32:
            return []
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, ast.Name):
            definitions = sem.defs(current.id, current)
            if not definitions or any(not isinstance(d, ast.expr) for d in definitions):
                return []
            pending.extend((d, depth + 1) for d in definitions)
        else:
            values.append(current)
    return values


def _prove_shell_data(node, sem):
    from app.rules.semantics import Guard

    choices = _alternatives(node, sem)
    if not choices:
        return None
    for choice in choices:
        if (
            isinstance(choice, ast.Call)
            and sem.trusted(choice.func) == "shlex.join"
            and len(choice.args) == 1
            and not choice.keywords
        ):
            vectors = _alternatives(choice.args[0], sem)
            if not vectors:
                return None
            for vector in vectors:
                if not isinstance(vector, (ast.List, ast.Tuple)) or not vector.elts:
                    return None
                program = program_name(vector.elts[0], sem)
                if program not in DATA_OPERAND_TOOLS | {"ffmpeg"}:
                    return None
                flags = [sem.constant_string(v) for v in vector.elts]
                for i, value in enumerate(vector.elts[1:], 1):
                    if sem.constant_string(value) is not None:
                        continue
                    operand = "--" in flags[1:i] or _constant_non_option_prefix(value, sem)
                    operand |= program == "ffmpeg" and flags[i - 1] == "-i"
                    if not operand:
                        return None
            continue
        template = _template(choice, sem)
        if template is None:
            leaves, todo = [], [choice]
            while todo:
                item = todo.pop()
                if isinstance(item, ast.BinOp) and isinstance(item.op, ast.Add):
                    todo.extend([item.right, item.left])
                else:
                    leaves.append(item)
            pieces, holes = [""], []
            for leaf in leaves:
                text = sem.constant_string(leaf)
                if text is not None:
                    pieces[-1] += text
                else:
                    holes.append(leaf)
                    pieces.append("")
        else:
            pieces, holes = template
        if not holes or any(any(c in p for c in ";|&`$()\r\n\\") for p in pieces):
            return None
        try:
            tokens = shlex.split("AEGIS_DATA".join(pieces))
            if not tokens or posixpath.basename(tokens[0]) not in (
                DATA_OPERAND_TOOLS | {"pg_dump", "varnishadm"}
            ):
                return None
            prefix = ""
            for i, hole in enumerate(holes):
                prefix += pieces[i]
                if not prefix or not prefix[-1].isspace():
                    return None
                shlex.split(prefix)
                if pieces[i + 1] and not pieces[i + 1][0].isspace():
                    return None
                quoted = (
                    isinstance(hole, ast.Call)
                    and sem.trusted(hole.func) == "shlex.quote"
                    and len(hole.args) == 1
                    and not hole.keywords
                )
                guarded = isinstance(hole, ast.Name) and all(
                    isinstance(d, Guard)
                    and "cmdi" in d.safe_for
                    and all(isinstance(v, ast.expr) and _plain_str(v, sem) for v in d.inner)
                    for d in sem.defs(hole.id, hole)
                )
                if not quoted and not guarded:
                    return None
                prefix += "AEGIS_DATA"
        except ValueError:
            return None
    return "quoted_or_validated_shell_operands"
