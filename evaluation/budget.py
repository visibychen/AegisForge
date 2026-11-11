"""A durable, cross-thread/process reservation ceiling for all M6 model requests.

The global ceiling (at most 1000, recorded once and never changeable) bounds every request of every
experiment, including retries. A *scope* is a named sub-allowance inside that ceiling for a later,
smaller experiment: it is also durable and cross-process, can only be created from the part of the
global ceiling that is neither used nor promised to another scope, and can never be enlarged by
restarting or by choosing another name. Reservations made before scopes existed (scope NULL) simply
count against the global ceiling.
"""

import re
import sqlite3
from contextlib import closing, contextmanager
from datetime import UTC, datetime

SCOPE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
SCHEMA = (
    "CREATE TABLE IF NOT EXISTS settings "
    "(id INTEGER PRIMARY KEY CHECK(id=1), ceiling INTEGER NOT NULL); "
    "CREATE TABLE IF NOT EXISTS calls (id INTEGER PRIMARY KEY, job TEXT NOT NULL, "
    "started TEXT NOT NULL, status TEXT NOT NULL, duration_ms INTEGER, "
    "input_tokens INTEGER, output_tokens INTEGER, failure_category TEXT); "
    "CREATE TABLE IF NOT EXISTS allowances (scope TEXT PRIMARY KEY, "
    "allowance INTEGER NOT NULL CHECK(allowance > 0), created TEXT NOT NULL);"
)


class ExperimentBudget:
    def __init__(self, path, limit=1000, scope=None, allowance=None):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("M6 authorization is at most 1000 calls including retries")
        if (scope is None) != (allowance is None):
            raise ValueError("A sub-allowance needs both a scope name and an allowance")
        if scope is not None and (
            not isinstance(scope, str)
            or not SCOPE.fullmatch(scope)
            or type(allowance) is not int
            or not 1 <= allowance <= limit
        ):
            raise ValueError("Invalid sub-allowance scope or size")
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self.connect()) as db:
            db.executescript(SCHEMA)  # executescript commits by itself; keep it outside BEGIN
        with self._transaction() as db:
            if "scope" not in {row[1] for row in db.execute("PRAGMA table_info(calls)")}:
                db.execute("ALTER TABLE calls ADD COLUMN scope TEXT")  # older rows stay NULL
            db.execute("INSERT OR IGNORE INTO settings VALUES (1,?)", (limit,))
            ceiling = db.execute("SELECT ceiling FROM settings WHERE id=1").fetchone()[0]
            if limit != ceiling:
                raise ValueError("Cannot change the recorded experiment budget")
        self.limit, self.scope, self.allowance = limit, scope, allowance
        if scope is not None:
            self._register(scope, allowance)

    def connect(self):
        return sqlite3.connect(self.path, timeout=30)

    @contextmanager
    def _transaction(self):
        """One immediate (write-locking) transaction on a connection that is always closed."""
        with closing(self.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
            except BaseException:
                db.rollback()
                raise
            db.commit()

    def _register(self, scope, allowance):
        from app.core.errors import DomainError

        with self._transaction() as db:
            row = db.execute("SELECT allowance FROM allowances WHERE scope=?", (scope,)).fetchone()
            if row is not None:
                if row[0] != allowance:
                    raise ValueError("Cannot change the recorded sub-allowance")
                return
            reserved = db.execute("SELECT COUNT(*) FROM calls").fetchone()[0]
            used = dict(
                db.execute(
                    "SELECT scope, COUNT(*) FROM calls WHERE scope IS NOT NULL GROUP BY scope"
                )
            )
            promised = sum(
                max(size - used.get(name, 0), 0)
                for name, size in db.execute("SELECT scope, allowance FROM allowances")
            )
            if allowance > self.limit - reserved - promised:
                raise DomainError(
                    "EXPERIMENT_ALLOWANCE", "全局上限内没有足够的未分配调用名额。", 429
                )
            db.execute(
                "INSERT INTO allowances(scope, allowance, created) VALUES (?,?,?)",
                (scope, allowance, datetime.now(UTC).isoformat()),
            )

    def reserve(self, job):
        from app.core.errors import DomainError

        with self._transaction() as db:
            if db.execute("SELECT COUNT(*) FROM calls").fetchone()[0] >= self.limit:
                raise DomainError("EXPERIMENT_BUDGET", "M6模型调用硬上限已到达。", 429)
            if self.scope is not None:
                used = db.execute("SELECT COUNT(*) FROM calls WHERE scope=?", (self.scope,))
                if used.fetchone()[0] >= self.allowance:
                    raise DomainError("EXPERIMENT_ALLOWANCE", "本实验的子额度已用完。", 429)
            elif self._unallocated(db) <= 0:
                raise DomainError("EXPERIMENT_ALLOWANCE", "剩余调用名额已分配给命名实验。", 429)
            return db.execute(
                "INSERT INTO calls(job,started,status,scope) VALUES (?,?,?,?)",
                (job, datetime.now(UTC).isoformat(), "reserved", self.scope),
            ).lastrowid

    def finish(self, ident, status, duration, usage, category):
        with self._transaction() as db:
            db.execute(
                "UPDATE calls SET status=?,duration_ms=?,input_tokens=?,output_tokens=?,"
                "failure_category=? WHERE id=?",
                (
                    status,
                    duration,
                    usage.get("prompt_tokens"),
                    usage.get("completion_tokens"),
                    category,
                    ident,
                ),
            )

    def remaining(self):
        """Calls this budget object may still reserve (its scope allowance if it has one)."""
        with closing(self.connect()) as db:
            left = self.limit - db.execute("SELECT COUNT(*) FROM calls").fetchone()[0]
            if self.scope is not None:
                used = db.execute("SELECT COUNT(*) FROM calls WHERE scope=?", (self.scope,))
                left = min(left, self.allowance - used.fetchone()[0])
            else:
                left = self._unallocated(db)
        return max(left, 0)

    def _unallocated(self, db):
        used = dict(db.execute("SELECT scope, COUNT(*) FROM calls GROUP BY scope"))
        promised = sum(
            max(size - used.get(name, 0), 0)
            for name, size in db.execute("SELECT scope, allowance FROM allowances")
        )
        return self.limit - sum(used.values()) - promised

    def summary(self):
        with closing(self.connect()) as db:
            rows = db.execute("SELECT status,COUNT(*) FROM calls GROUP BY status").fetchall()
            values = db.execute(
                "SELECT COUNT(*),SUM(input_tokens),SUM(output_tokens) FROM calls"
            ).fetchone()
            used = dict(
                db.execute(
                    "SELECT scope, COUNT(*) FROM calls WHERE scope IS NOT NULL GROUP BY scope"
                )
            )
            scopes = {
                name: {"allowance": size, "used": used.get(name, 0)}
                for name, size in db.execute("SELECT scope, allowance FROM allowances")
            }
        return {
            "ceiling": self.limit,
            "reservations": values[0],
            "input_tokens": values[1],
            "output_tokens": values[2],
            "statuses": dict(rows),
            "scopes": scopes,
            "fees": None,
            "fees_note": "N/A: no provider invoice/rate receipt; tokens are not currency",
        }

    def factory(self, job):
        def create(settings, local):
            from app.llm.prompts import PROMPT_VERSION
            from app.llm.repair import RepairProvider

            ids = {}

            def reserve(chars):
                ident = self.reserve(job + ":" + getattr(local, "version", PROMPT_VERSION))
                try:
                    local_id = local.reserve(chars)
                except Exception:
                    self.finish(ident, "local_reservation_rejected", 0, {}, None)
                    raise
                ids[local_id] = ident
                return local_id

            def finish(ident, status, duration, size, usage, category):
                try:
                    local.finish(ident, status, duration, size, usage, category)
                finally:
                    self.finish(ids[ident], status, duration, usage, category)

            return RepairProvider(settings, reserve, finish)

        return create
