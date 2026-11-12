"""Recompute a versioned diagnostic, without granting it formal course acceptance.

The manifest binds source-free detections, synthetic candidates and real Docker observations.
Old baseline auditing remains separate. Paths, schedules, candidate hashes, metrics, integer
denominators and every success flag are checked; no candidate is imported or executed here.
"""

import hashlib
import re
import subprocess
from pathlib import Path

from evaluation.experiment import load_data
from evaluation.gate import (
    ROOT,
    candidate_success,
    canon,
    control_validity,
    file_hash,
    read_json,
    registered_cases,
    test_outcomes,
)
from evaluation.metrics import evaluate


def _bound_file(entry):
    if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
        raise ValueError("Invalid evidence binding")
    path = ROOT / entry["path"]
    if not path.resolve().is_relative_to((ROOT / "evaluation/results").resolve()):
        raise ValueError("Evidence outside the versioned result directory")
    value = read_json(path)
    if file_hash(path) != entry["sha256"]:
        raise ValueError("Evidence hash differs")
    return path, value


def _verify_code(protocol):
    files = protocol["runtime_files"] | protocol["orchestrator_files"]
    if not isinstance(files, dict) or not 1 <= len(files) <= 200:
        raise ValueError("Invalid runtime fingerprint")
    for name, digest in files.items():
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"(?:backend/app|evaluation|scripts)/[A-Za-z0-9_./-]+\.py", name)
            or ".." in name.split("/")
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise ValueError("Invalid runtime file")
        result = subprocess.run(
            ["git", "show", f"{protocol['code_sha']}:{name}"],
            cwd=ROOT,
            capture_output=True,
            timeout=10,
            check=False,
        )
        if (
            result.returncode != 0
            or hashlib.sha256(result.stdout.replace(b"\r\n", b"\n")).hexdigest() != digest
        ):
            raise ValueError("Recorded code differs from Git history")


def verify_run(path: Path):
    """Invalid records return a closed verdict with no contents/prose in diagnostics."""
    try:
        manifest = read_json(path)
        if (
            manifest.get("schema_version") != "m6-diagnostic-run-1.0"
            or manifest.get("course_acceptance_evaluated") is not False
            or manifest.get("human_review") != "pending"
        ):
            raise ValueError("Diagnostic scope required")
        files = manifest["files"]
        if set(files) != {"detection", "bundle", "dynamic", "controls"}:
            raise ValueError("Four evidence bindings required")
        bound = {name: _bound_file(entry) for name, entry in files.items()}
        detection, bundle, dynamic, controls = [
            bound[n][1] for n in ("detection", "bundle", "dynamic", "controls")
        ]
        protocol = detection["protocol"]
        if protocol != bundle["protocol"] or protocol["schema_version"] != "m6-targeted-1.0":
            raise ValueError("Protocol differs")
        if (
            protocol["course_acceptance_evaluated"] is not False
            or protocol["human_review"] != "pending"
            or protocol["rounds"] != 1
        ):
            raise ValueError("Not a single-round diagnostic")
        code = protocol["code_sha"]
        if not isinstance(code, str) or not re.fullmatch(r"[0-9a-f]{40}", code):
            raise ValueError("Missing code identity")
        _verify_code(protocol)
        for evidence in (detection, bundle):
            budget = evidence["budget"]
            if (
                type(budget["reservations"]) is not int
                or budget["ceiling"] != 1000
                or not protocol["starting_reservations"] <= budget["reservations"] <= 1000
            ):
                raise ValueError("Global model ceiling differs")
        registered = registered_cases()
        ids = protocol["case_ids"]
        if (
            not isinstance(ids, list)
            or not ids
            or len(ids) != len(set(ids))
            or not set(ids) <= set(registered)
        ):
            raise ValueError("Unregistered or duplicate target")
        expected = [ident[:-1] + label for ident in ids for label in ("V", "S")]
        if protocol["sample_ids"] != expected or protocol["repair_denominator"] != len(ids):
            raise ValueError("Schedule differs")
        if protocol["detection_tasks"] != len(expected):
            raise ValueError("Detection denominator differs")
        frozen, contents = load_data()
        records = {r["id"]: r for r in frozen["samples"]}
        hashes = {ident: hashlib.sha256(contents[ident].encode()).hexdigest() for ident in expected}
        if protocol["sample_hashes"] != hashes:
            raise ValueError("Fixture differs")
        if protocol["dataset_sha256"] != file_hash(ROOT / "samples/freeze.json"):
            raise ValueError("Frozen dataset differs")
        rows = detection["records"]
        if (
            len(rows) != len(expected)
            or {r["sample_id"] for r in rows} != set(expected)
            or any(r["strategy"] != "hybrid" or r["repeat"] != 1 for r in rows)
        ):
            raise ValueError("Detection rows differ")
        metrics = evaluate([records[ident] for ident in expected], rows)
        if canon(metrics) != detection["evaluation"]:
            raise ValueError("Detection metrics differ")
        origin = bundle["rows"]
        if (
            len(origin) != len(ids)
            or {r["sample_id"] for r in origin} != set(ids)
            or any(r["repeat"] != 1 or r["first_candidate"] is not True for r in origin)
        ):
            raise ValueError("Candidate schedule differs")
        for row in origin:
            if row["cwe"] != registered[row["sample_id"]]["cwe"]:
                raise ValueError("Candidate label differs")
            source = row.get("candidate_source")
            if source is not None and (
                not isinstance(source, str)
                or len(source) > 24000
                or hashlib.sha256(source.encode()).hexdigest() != row["candidate_sha256"]
            ):
                raise ValueError("Candidate hash differs")
        valid = control_validity(controls)
        if dynamic["bundle_sha256"] != file_hash(bound["bundle"][0]):
            raise ValueError("Dynamic bundle differs")
        if dynamic["controls_sha256"] != file_hash(bound["controls"][0]):
            raise ValueError("Dynamic controls differ")
        observed = dynamic["rows"]
        if len(observed) != len(ids) or {r["sample_id"] for r in observed} != set(ids):
            raise ValueError("Dynamic schedule differs")
        origins = {r["sample_id"]: r for r in origin}
        for row in observed:
            original = origins[row["sample_id"]]
            if any(
                row.get(k) != v
                for k, v in original.items()
                if k not in {"candidate_source", "success"}
            ):
                raise ValueError("Original static checks differ")
            if "candidate_source" in original and test_outcomes(row.get("dynamic") or {}) is None:
                raise ValueError("Candidate lacks real dynamic outcomes")
            expected_success = candidate_success(row, valid.get(row["sample_id"], False))
            if type(row.get("success")) is not bool or row["success"] != expected_success:
                raise ValueError("Success flag differs")
        total = sum(r["success"] for r in observed)
        by_cwe = {
            cwe: sum(r["success"] for r in observed if r["cwe"] == cwe)
            for cwe in ("CWE-79", "CWE-89", "CWE-78")
        }
        if (
            type(dynamic["denominator"]) is not int
            or type(dynamic["successes"]) is not int
            or dynamic["denominator"] != len(ids)
            or bundle["denominator"] != len(ids)
            or dynamic["successes"] != total
            or dynamic["by_cwe"] != by_cwe
            or dynamic["passed"] is not None
            or dynamic["course_acceptance_evaluated"] is not False
            or dynamic["execution_complete"] is not True
        ):
            raise ValueError("Diagnostic totals or scope differ")
        return {
            "verdict": "diagnostic_only",
            "integrity_ok": True,
            "course_acceptance_evaluated": False,
            "human_review": "pending",
            "run": manifest["run_id"],
            "code_sha": code,
            "detection": metrics["metrics"]["source"]["micro"],
            "repairs": {"successes": total, "denominator": len(ids), "by_cwe": by_cwe},
            "note": "Exposed-case diagnostic; does not satisfy the three-round course gate.",
        }
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        RecursionError,
        subprocess.TimeoutExpired,
    ):
        return {
            "verdict": "records_invalid",
            "integrity_ok": False,
            "course_acceptance_evaluated": False,
            "note": "Invalid diagnostic bindings, schedule, counts or outcomes; contents withheld.",
        }
