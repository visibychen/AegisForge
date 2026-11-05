"""Dataset manifests: loading, validation and freezing (standard library + backend parser).

Run from the repository root inside the AegisForge conda environment:

    python evaluation/datasets.py check                   # full contract incl. freeze (CI)
    python evaluation/datasets.py check --structure-only  # same checks, freeze not required
    python evaluation/datasets.py freeze                  # write samples/freeze.json (once)
    python evaluation/datasets.py freeze --refreeze       # deliberate, documented re-freeze
    python evaluation/datasets.py lock-dev                # refresh samples/dev/hashes.json only

Access rule: development code (rules, prompts, M3/M4) may call ``load_dev_samples`` only.
Holdout files are read here solely for integrity checks (structure, syntax, parser budget);
no detector or evaluation runs on them in this module.
Hashes are computed over text with LF line endings so Git newline conversion cannot break them.
"""

import argparse
import ast
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
DEV = SAMPLES / "dev"
HOLDOUT = SAMPLES / "holdout"
HASH_LOCK = DEV / "hashes.json"
FREEZE = SAMPLES / "freeze.json"
REGISTRY = HOLDOUT / "controlled_repairs.json"
METADATA = [
    DEV / "manifest.json",
    DEV / "families.json",
    HOLDOUT / "catalog.json",
    HOLDOUT / "manifest.json",
    REGISTRY,
]
DELIMITER = "#@@ sample "
CWES = ("CWE-79", "CWE-89", "CWE-78")
SOURCE_DIMENSIONS = ("input_source", "sink", "construct", "flow", "safe_strategy")
HTTP_DIMENSIONS = ("location", "technique", "encoding", "normal_counterpart")
EXPECTED = {
    # per CWE: source (vulnerable, safe) and http (attack, normal total over all CWEs)
    "dev": {"source": (8, 8), "http": (4, 12)},
    "test": {"source": (12, 12), "http": (6, 18)},
}
CONTROLLED_PER_CWE = 6


def read_bundle(path: Path, kind: str) -> dict[str, str]:
    """Split a bundle into samples; each sample starts at its first non-blank line."""
    samples: dict[str, list[str]] = {}
    current = None
    for line in path.read_text(encoding="utf-8").split("\n"):
        if line.startswith(DELIMITER):
            current = line[len(DELIMITER) :].strip()
            if current in samples:
                raise ValueError(f"{path.name}: duplicate sample {current}")
            samples[current] = []
        elif line.startswith("#@@"):
            continue
        elif current is not None:
            samples[current].append(line)
    result = {}
    for sample_id, lines in samples.items():
        text = "\n".join(lines).strip("\n") + "\n"
        if kind == "http" and "\n\n" not in text:
            text += "\n"  # header-only request: restore the terminating blank line
        result[sample_id] = text
    return result


def _load_split(directory: Path) -> tuple[dict, dict[str, str]]:
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    contents: dict[str, str] = {}
    for kind, bundles in manifest["bundles"].items():
        for relative in bundles:
            for sample_id, text in read_bundle(directory / relative, kind).items():
                if sample_id in contents:
                    raise ValueError(f"duplicate sample id {sample_id}")
                contents[sample_id] = text
    return manifest, contents


def load_dev_samples() -> tuple[dict, dict[str, str]]:
    """Development split only: (manifest, {sample_id: text})."""
    return _load_split(DEV)


def _load_holdout() -> tuple[dict, dict[str, str]]:
    """Validator-only access to the holdout; never import this from development code."""
    return _load_split(HOLDOUT)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _text_hash(path: Path) -> str:
    return sha256(path.read_text(encoding="utf-8"))  # universal newlines -> LF


class _Normalize(ast.NodeTransformer):
    """Rename identifiers and erase literal values; keep API/attribute names and structure."""

    def __init__(self):
        self.names: dict[str, str] = {}

    def alias(self, name: str) -> str:
        return self.names.setdefault(name, f"v{len(self.names)}")

    def visit_Name(self, node):
        node.id = self.alias(node.id)
        return node

    def visit_arg(self, node):
        node.arg, node.annotation = self.alias(node.arg), None
        return node

    def visit_FunctionDef(self, node):
        node.name = self.alias(node.name)
        self.generic_visit(node)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        node.name = self.alias(node.name)
        self.generic_visit(node)
        return node

    def visit_Constant(self, node):
        return ast.copy_location(ast.Constant(value=type(node.value).__name__), node)


def fingerprint(source: str) -> str:
    tree = _Normalize().visit(ast.parse(source))
    return hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest()


def _check_families(families: list[dict], split: str, errors: list[str]) -> None:
    per_kind = Counter()
    for family in families:
        fid = family.get("id", "?")
        if family.get("split") != split:
            errors.append(f"{fid}: split must be {split}")
        if family.get("kind") not in {"source", "http"} or family.get("cwe") not in CWES:
            errors.append(f"{fid}: invalid kind or cwe")
            continue
        names = SOURCE_DIMENSIONS if family["kind"] == "source" else HTTP_DIMENSIONS
        if set(family.get("dimensions", {})) != set(names):
            errors.append(f"{fid}: dimensions must be exactly {names}")
        if not str(family.get("distinctness_note", "")).strip():
            errors.append(f"{fid}: distinctness_note is required")
        per_kind[(family["kind"], family["cwe"])] += 1
    pairs, attacks = EXPECTED[split]["source"][0], EXPECTED[split]["http"][0]
    for cwe in CWES:
        if per_kind[("source", cwe)] != pairs:
            errors.append(f"{split}: expected {pairs} source families for {cwe}")
        if per_kind[("http", cwe)] != attacks:
            errors.append(f"{split}: expected {attacks} http families for {cwe}")


def _members(family: dict) -> dict[str, str | None]:
    """{sample_id: label} (dev families list ids only, so labels are None there)."""
    return {
        (m["id"] if isinstance(m, dict) else m): (m.get("label") if isinstance(m, dict) else None)
        for m in family["members"]
    }


def _parser():
    backend = str(ROOT / "backend")
    if backend not in sys.path:
        sys.path.insert(0, backend)
    from app.core.errors import DomainError
    from app.parsers.inputs import parse_input

    return parse_input, DomainError


def _check_split(split, manifest, contents, families, prints, errors) -> list[dict]:
    """Shared per-sample checks; returns the records. ``prints`` spans both splits."""
    if manifest.get("split") != split:
        errors.append(f"{split}: manifest split must be {split}")
    if manifest.get("provenance", {}).get("human_review") != "pending":
        errors.append(
            f"{split}: provenance.human_review must stay 'pending' until a person reviews"
        )
    records = manifest["samples"]
    if sorted(r["id"] for r in records) != sorted(contents):
        errors.append(f"{split}: manifest samples and bundle samples differ")
    by_family = {f["id"]: f for f in families}
    counts = Counter()
    for record in records:
        rid = record["id"]
        family = by_family.get(record["family"])
        members = _members(family) if family else {}
        if rid not in members:
            errors.append(f"{rid}: family missing or does not list the sample")
            continue
        if members[rid] is not None and members[rid] != record["label"]:
            errors.append(f"{rid}: label differs from the registered catalog")
        if record["kind"] != family["kind"]:
            errors.append(f"{rid}: kind differs from family")
        counts[(record["kind"], record["cwe"], record["label"])] += 1
        if record["label"] in {"vulnerable", "attack"} and record["cwe"] != family["cwe"]:
            errors.append(f"{rid}: CWE differs from family")
        text = contents.get(rid, "")
        if record["kind"] == "source":
            try:
                digest = fingerprint(text)
            except SyntaxError as exc:
                errors.append(f"{rid}: not valid Python ({exc.msg})")
                continue
            other = prints.get(digest)
            if other and other[1] != record["family"]:
                errors.append(f"{rid}: same structure as {other[0]} in another family")
            prints.setdefault(digest, (rid, record["family"]))
            lines = text.split("\n")
            if record["label"] == "vulnerable":
                start, end = record["lines"]
                window = "\n".join(lines[start - 1 : end])
                if not (1 <= start <= end <= len(lines)) or record["anchor"] not in window:
                    errors.append(f"{rid}: anchor not inside labelled lines {start}-{end}")
            elif record["lines"] is not None:
                errors.append(f"{rid}: safe samples carry no line range")
        else:
            if record["label"] == "attack" and record["anchor"] not in text:
                errors.append(f"{rid}: anchor not found in request")
            if record["label"] == "normal" and record["cwe"] is not None:
                errors.append(f"{rid}: normal requests carry no CWE")
    vulnerable, safe = EXPECTED[split]["source"]
    attack, normal = EXPECTED[split]["http"]
    for cwe in CWES:
        if counts[("source", cwe, "vulnerable")] != vulnerable:
            errors.append(f"{split}: expected {vulnerable} vulnerable {cwe} samples")
        if counts[("source", cwe, "safe")] != safe:
            errors.append(f"{split}: expected {safe} safe {cwe} samples")
        if counts[("http", cwe, "attack")] != attack:
            errors.append(f"{split}: expected {attack} attack {cwe} requests")
    if counts[("http", None, "normal")] != normal:
        errors.append(f"{split}: expected {normal} normal requests")
    return records


def _check_parsing(records, contents, errors) -> None:
    """Every sample must pass the real input parser and budgets (no detection is run)."""
    try:
        parse_input, domain_error = _parser()
    except ImportError as exc:
        errors.append(f"backend parser unavailable: {exc}")
        return
    for record in records:
        try:
            parsed = parse_input(record["kind"], contents[record["id"]])
        except domain_error as exc:
            errors.append(f"{record['id']}: rejected by parser ({exc.code})")
            continue
        if record["kind"] == "source" and parsed.private_tree is None:
            errors.append(f"{record['id']}: AST unavailable")


def _check_registry(holdout_records, errors) -> None:
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    vulnerable = {
        r["id"]: r["cwe"]
        for r in holdout_records
        if r["kind"] == "source" and r["label"] == "vulnerable"
    }
    per_cwe = Counter()
    for entry in registry.get("samples", []):
        if vulnerable.get(entry["id"]) != entry.get("cwe"):
            errors.append(f"controlled repair {entry['id']}: not a holdout vulnerable sample")
        if entry.get("status") != "planned":
            errors.append(f"controlled repair {entry['id']}: status must stay 'planned' until M4")
        per_cwe[entry.get("cwe")] += 1
    if len({entry["id"] for entry in registry.get("samples", [])}) != sum(per_cwe.values()):
        errors.append("controlled repairs: duplicate ids")
    for cwe in CWES:
        if per_cwe[cwe] != CONTROLLED_PER_CWE:
            errors.append(f"controlled repairs: expected {CONTROLLED_PER_CWE} for {cwe}")


def _freeze_payload() -> dict:
    dev_manifest, dev = load_dev_samples()
    holdout_manifest, holdout = _load_holdout()
    files = list(METADATA)
    files += [DEV / p for ps in dev_manifest["bundles"].values() for p in ps]
    files += [HOLDOUT / p for ps in holdout_manifest["bundles"].values() for p in ps]
    return {
        "algorithm": "sha256 over UTF-8 text with LF line endings; samples as split by read_bundle",
        "files": {path.relative_to(ROOT).as_posix(): _text_hash(path) for path in sorted(files)},
        "samples": {
            "dev": {key: sha256(text) for key, text in sorted(dev.items())},
            "test": {key: sha256(text) for key, text in sorted(holdout.items())},
        },
    }


def _diff(locked: dict, actual: dict) -> list[str]:
    return sorted(key for key in set(locked) | set(actual) if locked.get(key) != actual.get(key))


def validate(require_freeze: bool = True, verify_locks: bool = True) -> tuple[list[str], list[str]]:
    """Return (errors, notes). Errors mean the dataset contract is broken."""
    errors: list[str] = []
    notes: list[str] = []
    dev_manifest, dev = load_dev_samples()
    dev_families = json.loads((DEV / "families.json").read_text(encoding="utf-8"))["families"]
    catalog = json.loads((HOLDOUT / "catalog.json").read_text(encoding="utf-8"))
    test_families = catalog["families"]
    _check_families(dev_families, "dev", errors)
    _check_families(test_families, "test", errors)

    all_families = dev_families + test_families
    family_ids = Counter(f["id"] for f in all_families)
    errors += [f"family id reused: {fid}" for fid, n in family_ids.items() if n > 1]
    shapes = Counter(
        (f["kind"], f["cwe"], tuple(sorted(f["dimensions"].items()))) for f in all_families
    )
    errors += [f"duplicate family dimensions: {key}" for key, n in shapes.items() if n > 1]
    member_ids = Counter(sample for f in all_families for sample in _members(f))
    errors += [f"sample id reused across families: {i}" for i, n in member_ids.items() if n > 1]
    for family in test_families:
        expected = ["safe", "vulnerable"] if family["kind"] == "source" else ["attack", "normal"]
        if sorted(_members(family).values()) != expected:
            errors.append(f"{family['id']}: holdout members must be {expected}")

    prints: dict[str, tuple[str, str]] = {}
    dev_records = _check_split("dev", dev_manifest, dev, dev_families, prints, errors)
    _check_parsing(dev_records, dev, errors)
    if catalog.get("status") != "authored" or not (HOLDOUT / "manifest.json").exists():
        errors.append("holdout must be authored (catalog status 'authored' and manifest present)")
        return errors, notes
    holdout_manifest, holdout = _load_holdout()
    holdout_records = _check_split("test", holdout_manifest, holdout, test_families, prints, errors)
    _check_parsing(holdout_records, holdout, errors)
    _check_registry(holdout_records, errors)

    if verify_locks and HASH_LOCK.exists():
        locked = json.loads(HASH_LOCK.read_text(encoding="utf-8"))["sha256"]
        changed = _diff(locked, {key: sha256(text) for key, text in dev.items()})
        if changed:
            errors.append(f"samples/dev/hashes.json mismatch: {changed[:10]}")
    if verify_locks and FREEZE.exists():
        locked = json.loads(FREEZE.read_text(encoding="utf-8"))
        actual = _freeze_payload()
        for section in ("files",):
            changed = _diff(locked.get(section, {}), actual[section])
            if changed:
                errors.append(f"freeze mismatch in {section}: {changed[:10]}")
        for split in ("dev", "test"):
            changed = _diff(locked.get("samples", {}).get(split, {}), actual["samples"][split])
            if changed:
                errors.append(f"freeze mismatch in {split} samples: {changed[:10]}")
    elif require_freeze:
        errors.append("samples/freeze.json missing: run `python evaluation/datasets.py freeze`")
    else:
        notes.append("dataset not frozen yet (structure-only check)")
    return errors, notes


def lock_dev() -> Path:
    _, contents = load_dev_samples()
    payload = {
        "algorithm": "sha256 over UTF-8 bytes of each sample as produced by read_bundle",
        "sha256": {sample_id: sha256(text) for sample_id, text in sorted(contents.items())},
    }
    HASH_LOCK.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")
    return HASH_LOCK


def freeze(refreeze: bool = False) -> list[str]:
    """Write samples/freeze.json after full structural validation. Returns errors."""
    if FREEZE.exists() and not refreeze:
        return ["samples/freeze.json already exists; use --refreeze only for a documented change"]
    # A failed validation must leave the previous freeze intact. Explicit re-freezing
    # validates structure against the new data, rather than against the old hash lock.
    errors, _ = validate(require_freeze=False, verify_locks=False)
    if errors:
        return errors
    lock_dev()
    temporary = FREEZE.with_suffix(".json.tmp")
    try:
        temporary.write_text(
            json.dumps(_freeze_payload(), indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        temporary.replace(FREEZE)
    finally:
        temporary.unlink(missing_ok=True)
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["check", "freeze", "lock-dev"])
    parser.add_argument("--structure-only", action="store_true", help="do not require freeze")
    parser.add_argument("--refreeze", action="store_true", help="overwrite an existing freeze")
    args = parser.parse_args()
    if args.command == "lock-dev":
        print(f"Wrote {lock_dev().relative_to(ROOT)}")
        return 0
    if args.command == "freeze":
        errors = freeze(args.refreeze)
        if errors:
            print("\n".join(["Refusing to freeze:", *errors]))
            return 1
        print(f"Wrote {FREEZE.relative_to(ROOT)} and {HASH_LOCK.relative_to(ROOT)}")
        return 0
    errors, notes = validate(require_freeze=not args.structure_only)
    for note in notes:
        print("NOTE:", note)
    for error in errors:
        print("ERROR:", error)
    print("dataset check:", "FAILED" if errors else "passed")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
