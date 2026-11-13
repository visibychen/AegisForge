import importlib.util
import json
import shutil
from pathlib import Path
from uuid import uuid4

import pytest
from app.parsers.inputs import parse_input
from app.rules.detector import detect

ROOT = Path(__file__).resolve().parents[2]
_path = ROOT / "evaluation" / "datasets.py"
_spec = importlib.util.spec_from_file_location("aegis_datasets", _path)
datasets = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(datasets)


def test_dataset_structure_splits_registry_and_family_distinctness():
    # Integrity only: holdout samples are parsed, never detected. The freeze itself is enforced
    # by `python evaluation/datasets.py check` (no --structure-only) in scripts/check.py.
    errors, _ = datasets.validate(require_freeze=False)
    assert errors == []


def test_rule_smoke_runs_on_dev_samples_only():
    manifest, contents = datasets.load_dev_samples()
    assert manifest["split"] == "dev"
    for record in manifest["samples"]:
        parsed = parse_input(record["kind"], contents[record["id"]])
        detect(uuid4(), record["kind"], parsed)


@pytest.fixture
def corpus_copy(tmp_path, monkeypatch):
    source_root = datasets.ROOT
    shutil.copytree(source_root / "samples", tmp_path / "samples")
    for name in ("SAMPLES", "DEV", "HOLDOUT", "HASH_LOCK", "FREEZE", "REGISTRY"):
        monkeypatch.setattr(
            datasets, name, tmp_path / getattr(datasets, name).relative_to(source_root)
        )
    monkeypatch.setattr(
        datasets,
        "METADATA",
        tuple(tmp_path / p.relative_to(source_root) for p in datasets.METADATA),
    )
    monkeypatch.setattr(datasets, "ROOT", tmp_path)
    return tmp_path


def test_frozen_corpus_detects_change_and_requires_explicit_refreeze(corpus_copy):
    path = datasets.DEV / "source" / "xss.bundle.txt"
    path.write_text(path.read_text(encoding="utf-8") + "\n# integrity probe\n", encoding="utf-8")
    errors, _ = datasets.validate()
    assert any("freeze mismatch" in item for item in errors)
    assert datasets.freeze()
    assert datasets.freeze(refreeze=True) == []
    assert datasets.validate()[0] == []


def test_failed_refreeze_preserves_the_previous_lock(corpus_copy):
    before = datasets.FREEZE.read_bytes()
    path = datasets.DEV / "manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["samples"][0]["lines"] = [99999, 99999]
    path.write_text(json.dumps(manifest), encoding="utf-8")
    assert datasets.freeze(refreeze=True)
    assert datasets.FREEZE.read_bytes() == before


def test_freeze_is_stable_across_windows_line_endings(corpus_copy):
    for path in (datasets.DEV / "manifest.json", datasets.DEV / "source" / "xss.bundle.txt"):
        text = path.read_text(encoding="utf-8")
        path.write_bytes(text.replace("\n", "\r\n").encode("utf-8"))
    assert datasets.validate()[0] == []
