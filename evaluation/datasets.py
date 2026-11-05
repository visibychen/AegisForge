"""Dataset manifests: loading, validation and hash freezing (standard library only).

Run from the repository root inside the AegisForge conda environment:

    python evaluation/datasets.py check        # validate dev + holdout catalog (+ hash lock)
    python evaluation/datasets.py lock-dev     # write samples/dev/hashes.json from real bytes

Access rule: development code (rules, prompts, M3/M4) may call ``load_dev_samples`` only.
The holdout catalog is read here solely to validate split integrity; never tune on it.
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
DELIMITER = "#@@ sample "
CWES = ("CWE-79", "CWE-89", "CWE-78")
SOURCE_DIMENSIONS = ("input_source", "sink", "construct", "flow", "safe_strategy")
HTTP_DIMENSIONS = ("location", "technique", "encoding", "normal_counterpart")
EXPECTED = {
    "dev": {"source": (8, 8), "http": (4, 12)},  # per CWE: (vulnerable|attack, safe); normal total
    "test": {"source": (12, 12), "http": (6, 18)},
}


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


def load_dev_samples() -> tuple[dict, dict[str, str]]:
    """Development split only: (manifest, {sample_id: text})."""
    manifest = json.loads((DEV / "manifest.json").read_text(encoding="utf-8"))
    contents: dict[str, str] = {}
    for kind, bundles in manifest["bundles"].items():
        for relative in bundles:
            for sample_id, text in read_bundle(DEV / relative, kind).items():
                if sample_id in contents:
                    raise ValueError(f"duplicate sample id {sample_id}")
                contents[sample_id] = text
    return manifest, contents


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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
    vulnerable, normal = EXPECTED[split]["source"][0], EXPECTED[split]["http"][0]
    for cwe in CWES:
        if per_kind[("source", cwe)] != vulnerable:
            errors.append(f"{split}: expected {vulnerable} source families for {cwe}")
        if per_kind[("http", cwe)] != normal:
            errors.append(f"{split}: expected {normal} http families for {cwe}")


def _member_labels(family: dict) -> list[str]:
    members = family["members"]
    if members and isinstance(members[0], dict):
        return sorted(member["label"] for member in members)
    return []


def validate(
    require_hash_lock: bool = True, check_lock: bool = True
) -> tuple[list[str], list[str]]:
    """Return (errors, notes). Errors mean the dataset contract is broken."""
    errors: list[str] = []
    notes: list[str] = []
    manifest, contents = load_dev_samples()
    dev_families = json.loads((DEV / "families.json").read_text(encoding="utf-8"))["families"]
    holdout = json.loads((HOLDOUT / "catalog.json").read_text(encoding="utf-8"))
    test_families = holdout["families"]
    _check_families(dev_families, "dev", errors)
    _check_families(test_families, "test", errors)

    all_families = dev_families + test_families
    family_ids = Counter(f["id"] for f in all_families)
    errors += [f"family id reused: {fid}" for fid, n in family_ids.items() if n > 1]
    shapes = Counter(
        (f["kind"], f["cwe"], tuple(sorted(f["dimensions"].items()))) for f in all_families
    )
    errors += [f"duplicate family dimensions: {key}" for key, n in shapes.items() if n > 1]

    member_ids = Counter()
    for family in test_families:
        labels = _member_labels(family)
        expected = ["safe", "vulnerable"] if family["kind"] == "source" else ["attack", "normal"]
        if labels != expected:
            errors.append(f"{family['id']}: holdout members must be {expected}")
        member_ids.update(member["id"] for member in family["members"])
    for family in dev_families:
        member_ids.update(family["members"])
    errors += [f"sample id reused across families: {i}" for i, n in member_ids.items() if n > 1]

    by_family = {f["id"]: f for f in dev_families}
    records = manifest["samples"]
    if manifest.get("provenance", {}).get("human_review") != "pending":
        errors.append("dev provenance.human_review must stay 'pending' until a person reviews")
    if sorted(r["id"] for r in records) != sorted(contents):
        errors.append("manifest samples and bundle samples differ")
    counts = Counter()
    prints: dict[str, tuple[str, str]] = {}
    for record in records:
        rid = record["id"]
        family = by_family.get(record["family"])
        if family is None or rid not in family["members"]:
            errors.append(f"{rid}: family missing or does not list the sample")
            continue
        if record["kind"] != family["kind"]:
            errors.append(f"{rid}: kind differs from family")
        text = contents.get(rid, "")
        counts[(record["kind"], record["cwe"], record["label"])] += 1
        if record["label"] in {"vulnerable", "attack"} and record["cwe"] != family["cwe"]:
            errors.append(f"{rid}: CWE differs from family")
        if record["kind"] == "source":
            try:
                digest = fingerprint(text)
            except SyntaxError as exc:
                errors.append(f"{rid}: not valid Python ({exc.msg})")
                continue
            other = prints.get(digest)
            if other:
                errors.append(f"{rid}: structurally identical to {other[0]} (rename-only variant)")
            prints[digest] = (rid, record["family"])
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
    vulnerable, safe = EXPECTED["dev"]["source"]
    attack, normal = EXPECTED["dev"]["http"]
    for cwe in CWES:
        if counts[("source", cwe, "vulnerable")] != vulnerable:
            errors.append(f"dev: expected {vulnerable} vulnerable {cwe} samples")
        if counts[("source", cwe, "safe")] != safe:
            errors.append(f"dev: expected {safe} safe {cwe} samples")
        if counts[("http", cwe, "attack")] != attack:
            errors.append(f"dev: expected {attack} attack {cwe} requests")
    if counts[("http", None, "normal")] != normal:
        errors.append(f"dev: expected {normal} normal requests")

    if HASH_LOCK.exists() and check_lock:
        locked = json.loads(HASH_LOCK.read_text(encoding="utf-8"))["sha256"]
        actual = {sample_id: sha256(text) for sample_id, text in contents.items()}
        changed = sorted(k for k in set(locked) | set(actual) if locked.get(k) != actual.get(k))
        if changed:
            errors.append(f"dev hash lock mismatch: {changed[:10]}")
    elif require_hash_lock and check_lock:
        errors.append(
            "samples/dev/hashes.json missing: run `python evaluation/datasets.py lock-dev`"
        )
    else:
        notes.append("dev hash lock not present (structure-only validation)")

    holdout_files = [p for p in HOLDOUT.iterdir() if p.name != "catalog.json"]
    if holdout.get("status") == "planned":
        notes.append(
            "holdout contents not authored yet (status=planned): M2 dataset freeze incomplete"
        )
        if holdout_files:
            errors.append("holdout status is 'planned' but content files exist")
    return errors, notes


def lock_dev() -> Path:
    _, contents = load_dev_samples()
    payload = {
        "algorithm": "sha256 over UTF-8 bytes of each sample as produced by read_bundle",
        "sha256": {sample_id: sha256(text) for sample_id, text in sorted(contents.items())},
    }
    HASH_LOCK.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return HASH_LOCK


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["check", "lock-dev"])
    args = parser.parse_args()
    if args.command == "lock-dev":
        # Re-locking is an explicit act (e.g. after an intentional dev edit); structure must pass.
        errors, _ = validate(require_hash_lock=False, check_lock=False)
        if errors:
            print("\n".join(["Refusing to lock an invalid dataset:", *errors]))
            return 1
        print(f"Wrote {lock_dev().relative_to(ROOT)}")
        return 0
    errors, notes = validate()
    for note in notes:
        print("NOTE:", note)
    for error in errors:
        print("ERROR:", error)
    print("dataset check:", "FAILED" if errors else "passed")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
