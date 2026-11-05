import importlib.util
from pathlib import Path
from uuid import uuid4

from app.parsers.inputs import parse_input
from app.rules.detector import detect

ROOT = Path(__file__).resolve().parents[2]
_path = ROOT / "evaluation" / "datasets.py"
_spec = importlib.util.spec_from_file_location("aegis_datasets", _path)
datasets = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(datasets)


def test_dataset_structure_splits_and_family_distinctness():
    # Hash freezing is enforced by `python evaluation/datasets.py check` in scripts/check.py.
    errors, _ = datasets.validate(require_hash_lock=False)
    assert errors == []


def test_every_dev_sample_is_accepted_by_the_parsers():
    manifest, contents = datasets.load_dev_samples()
    for record in manifest["samples"]:
        parsed = parse_input(record["kind"], contents[record["id"]])
        detect(uuid4(), record["kind"], parsed)
        if record["kind"] == "source":
            assert parsed.private_tree is not None, record["id"]
