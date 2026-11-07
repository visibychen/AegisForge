from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from app.core.errors import DomainError
from app.models import Job, ModelCall, ScanTask
from app.services.queue import CallLedger, claim, publish, transaction, utcnow
from app.services.scans import change_scan
from sqlalchemy import select
from sqlalchemy.orm import Session
from tests.test_scans import create


def test_concurrent_claim_has_one_owner_and_stale_owner_cannot_publish(api):
    scan_id = create(api).json()["scan"]["id"]
    engine, settings = api.app.state.engine, api.app.state.settings
    with ThreadPoolExecutor(max_workers=3) as pool:
        leases = list(pool.map(lambda _: claim(engine, settings), range(3)))
    assert sum(lease is not None for lease in leases) == 1
    old = next(lease for lease in leases if lease)
    with transaction(engine) as session:
        session.get(Job, old.job_id).lease_until = utcnow() - timedelta(seconds=1)
    new = claim(engine, settings)
    assert new.scan_id == scan_id and new.token != old.token
    with pytest.raises(DomainError, match="LEASE_LOST"):
        publish(engine, old, "completed", {}, [])
    publish(engine, new, "completed", {}, [])


def test_call_reservations_survive_manual_retry_and_crash_recovery(api):
    scan_id = create(api).json()["scan"]["id"]
    engine, settings = api.app.state.engine, api.app.state.settings
    settings.max_model_calls = 1
    lease = claim(engine, settings)
    ledger = CallLedger(engine, settings, lease)
    call_id = ledger.reserve(20)
    with transaction(engine) as session:
        session.get(Job, lease.job_id).lease_until = utcnow() - timedelta(seconds=1)
    replacement = claim(engine, settings)
    with Session(engine) as session:
        assert session.get(ModelCall, call_id).status == "interrupted"
    publish(engine, replacement, "failed", {}, [])
    change_scan(engine, settings, scan_id, "retry")
    new_ledger = CallLedger(engine, settings, claim(engine, settings))
    with pytest.raises(DomainError, match="MODEL_CALL_BUDGET"):
        new_ledger.reserve(20)


def test_expired_leases_stop_after_three_attempts(api):
    scan_id = create(api).json()["scan"]["id"]
    engine, settings = api.app.state.engine, api.app.state.settings
    for _ in range(3):
        lease = claim(engine, settings)
        assert lease is not None
        with transaction(engine) as session:
            session.get(Job, lease.job_id).lease_until = utcnow() - timedelta(seconds=1)
    assert claim(engine, settings) is None
    with Session(engine) as session:
        scan = session.get(ScanTask, scan_id)
        assert scan.status == "failed" and scan.error_code == "LEASE_EXHAUSTED"
        assert session.scalar(select(Job)).attempts == 3
