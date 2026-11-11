"""Sub-allowances live inside the one persistent global ceiling; they never replace or reset it."""

import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from app.core.config import Settings  # noqa: E402
from app.core.errors import DomainError  # noqa: E402
from app.llm.prompts import PROMPT_VERSION  # noqa: E402

from evaluation.budget import ExperimentBudget  # noqa: E402


def attempt(budget, count):
    done, refused = 0, []
    for _ in range(count):
        try:
            budget.reserve("job")
            done += 1
        except DomainError as error:
            refused.append(error.code)
    return done, refused


def test_a_scope_stops_at_its_allowance_while_the_global_ceiling_still_counts_everyone(tmp_path):
    path = tmp_path / "budget.db"
    scoped = ExperimentBudget(path, 10, "dev-ab", 3)
    assert attempt(scoped, 5) == (3, ["EXPERIMENT_ALLOWANCE"] * 2)
    assert scoped.remaining() == 0
    plain = ExperimentBudget(path, 10)  # an unscoped caller only sees the global ceiling
    assert plain.remaining() == 7
    assert attempt(plain, 9) == (7, ["EXPERIMENT_BUDGET"] * 2)
    summary = plain.summary()
    assert summary["reservations"] == 10 and summary["scopes"] == {
        "dev-ab": {"allowance": 3, "used": 3}
    }


def test_restart_keeps_usage_and_neither_rename_nor_resize_creates_fresh_budget(tmp_path):
    path = tmp_path / "budget.db"
    first = ExperimentBudget(path, 10, "dev-ab", 4)
    assert attempt(first, 3)[0] == 3
    again = ExperimentBudget(path, 10, "dev-ab", 4)
    assert again.remaining() == 1 and attempt(again, 3) == (1, ["EXPERIMENT_ALLOWANCE"] * 2)
    with pytest.raises(ValueError, match="sub-allowance"):
        ExperimentBudget(path, 10, "dev-ab", 5)
    with pytest.raises(ValueError, match="change"):
        ExperimentBudget(path, 9, "dev-ab", 4)
    # A new name may only draw on what is neither used nor promised: 10 - 4 used - 0 unspent = 6.
    with pytest.raises(DomainError) as refused:
        ExperimentBudget(path, 10, "renamed", 7)
    assert refused.value.code == "EXPERIMENT_ALLOWANCE"
    other = ExperimentBudget(path, 10, "renamed", 6)
    assert other.remaining() == 6
    with pytest.raises(DomainError):
        ExperimentBudget(path, 10, "third", 1)  # everything is used or promised now


def test_unspent_allowance_of_one_scope_is_not_available_to_a_second(tmp_path):
    path = tmp_path / "budget.db"
    ExperimentBudget(path, 10, "a", 6)
    with pytest.raises(DomainError):
        ExperimentBudget(path, 10, "b", 5)
    assert ExperimentBudget(path, 10, "b", 4).remaining() == 4


def test_unscoped_history_counts_and_invalid_scopes_are_refused(tmp_path):
    path = tmp_path / "budget.db"
    baseline = ExperimentBudget(path, 10)
    assert attempt(baseline, 8)[0] == 8  # like the 795 reservations made before scopes existed
    with pytest.raises(DomainError):
        ExperimentBudget(path, 10, "late", 3)
    assert ExperimentBudget(path, 10, "late", 2).remaining() == 2
    for scope, size in (("Upper", 1), ("", 1), ("x" * 65, 1), ("ok", 0), ("ok", 11), ("ok", True)):
        with pytest.raises(ValueError):
            ExperimentBudget(path, 10, scope, size)
    with pytest.raises(ValueError, match="both"):
        ExperimentBudget(path, 10, "only-name")


def test_scope_allowance_is_atomic_across_threads(tmp_path):
    path = tmp_path / "budget.db"
    ExperimentBudget(path, 20, "race", 4)

    def worker(_):
        # every worker opens its own handle, as separate processes would
        return attempt(ExperimentBudget(path, 20, "race", 4), 3)[0]

    with ThreadPoolExecutor(max_workers=6) as pool:
        assert sum(pool.map(worker, range(6))) == 4
    assert ExperimentBudget(path, 20, "race", 4).summary()["scopes"]["race"]["used"] == 4


def test_a_database_from_before_scopes_is_migrated_without_losing_reservations(tmp_path):
    path = tmp_path / "budget.db"
    with closing(sqlite3.connect(path)) as db:
        db.executescript(
            "CREATE TABLE settings (id INTEGER PRIMARY KEY CHECK(id=1), ceiling INTEGER NOT NULL);"
            "CREATE TABLE calls (id INTEGER PRIMARY KEY, job TEXT NOT NULL, started TEXT NOT NULL,"
            " status TEXT NOT NULL, duration_ms INTEGER, input_tokens INTEGER,"
            " output_tokens INTEGER, failure_category TEXT);"
            "INSERT INTO settings VALUES (1, 10);"
            "INSERT INTO calls(job, started, status) VALUES ('old', 't', 'succeeded');"
            "INSERT INTO calls(job, started, status) VALUES ('old', 't', 'MODEL_INVALID_OUTPUT');"
        )
    budget = ExperimentBudget(path, 10, "after", 8)
    assert budget.summary()["reservations"] == 2 and budget.remaining() == 8
    with pytest.raises(DomainError):
        ExperimentBudget(path, 10, "too-big", 1)


def test_factory_ledger_version_defaults_to_the_contract_constant(tmp_path):
    budget = ExperimentBudget(tmp_path / "budget.db", 5, "fx", 2)
    local = SimpleNamespace(reserve=lambda chars: "1", finish=lambda *args: None)
    provider = budget.factory("job-1")(Settings(_env_file=None), local)
    provider.reserve(10)
    with closing(sqlite3.connect(tmp_path / "budget.db")) as db:
        job, scope = db.execute("SELECT job, scope FROM calls").fetchone()
    assert job == f"job-1:{PROMPT_VERSION}" and scope == "fx"
