"""A durable, cross-thread/process reservation ceiling for all M6 model requests."""

import sqlite3
from datetime import UTC, datetime


class ExperimentBudget:
    def __init__(self, path, limit=1000):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("M6 authorization is at most 1000 calls including retries")
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript(
                "CREATE TABLE IF NOT EXISTS settings "
                "(id INTEGER PRIMARY KEY CHECK(id=1), ceiling INTEGER NOT NULL); "
                "CREATE TABLE IF NOT EXISTS calls (id INTEGER PRIMARY KEY, job TEXT NOT NULL, "
                "started TEXT NOT NULL, status TEXT NOT NULL, duration_ms INTEGER, "
                "input_tokens INTEGER, output_tokens INTEGER, failure_category TEXT);"
            )
            db.execute("INSERT OR IGNORE INTO settings VALUES (1,?)", (limit,))
            ceiling = db.execute("SELECT ceiling FROM settings WHERE id=1").fetchone()[0]
            if limit != ceiling:
                raise ValueError("Cannot change the recorded experiment budget")
        self.limit = limit

    def connect(self):
        return sqlite3.connect(self.path, timeout=30)

    def reserve(self, job):
        from app.core.errors import DomainError

        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT COUNT(*) FROM calls").fetchone()[0] >= self.limit:
                raise DomainError("EXPERIMENT_BUDGET", "M6模型调用硬上限已到达。", 429)
            return db.execute(
                "INSERT INTO calls(job,started,status) VALUES (?,?,?)",
                (job, datetime.now(UTC).isoformat(), "reserved"),
            ).lastrowid

    def finish(self, ident, status, duration, usage, category):
        with self.connect() as db:
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

    def summary(self):
        with self.connect() as db:
            rows = db.execute("SELECT status,COUNT(*) FROM calls GROUP BY status").fetchall()
            values = db.execute(
                "SELECT COUNT(*),SUM(input_tokens),SUM(output_tokens) FROM calls"
            ).fetchone()
        return {
            "ceiling": self.limit,
            "reservations": values[0],
            "input_tokens": values[1],
            "output_tokens": values[2],
            "statuses": dict(rows),
            "fees": None,
            "fees_note": "N/A: no provider invoice/rate receipt; tokens are not currency",
        }

    def factory(self, job):
        def create(settings, local):
            from app.llm.repair import RepairProvider

            ids = {}

            def reserve(chars):
                ident = self.reserve(job + ":" + getattr(local, "version", "analysis-1.1"))
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
