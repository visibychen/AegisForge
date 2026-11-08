import json
import subprocess
from datetime import UTC
from pathlib import Path

import pytest
from app.core.errors import DomainError
from app.validation.registry import (
    ROOT,
    VALIDATOR_FILES,
    load_cases,
    match_case,
    validator_fingerprint,
)
from app.validation.runner import (
    NAME_PREFIX,
    PROJECT_LABEL,
    cleanup,
    command,
    run_container,
    sweep_orphans,
)


def test_registered_cases_match_the_frozen_development_samples():
    hashes = json.loads((ROOT / "samples" / "dev" / "hashes.json").read_text("utf-8"))["sha256"]
    cases = load_cases()
    assert {case["id"] for case in cases} == {"xss-01", "sqli-01", "cmdi-01"}
    for case in cases:
        assert hashes[case["sample_id"]] == case["source_sha256"]


def test_every_validator_input_is_fingerprinted_copied_and_not_ignored():
    context = ROOT / "deploy" / "validator"
    dockerfile = (context / "Dockerfile").read_text("utf-8")
    ignore = (context / ".dockerignore").read_text("utf-8")
    assert len(validator_fingerprint()) == 64
    for name in VALIDATOR_FILES:
        assert (context / name).is_file()
        assert name in dockerfile or name == "Dockerfile"
        assert name == "Dockerfile" or "!" + name in ignore


def test_container_is_labelled_and_receives_the_nonce_over_stdin_only():
    args = command("sha256:" + "a" * 64, NAME_PREFIX + "x", "xss-01", Path("c.py"), "r" * 32)
    assert "-i" in args and PROJECT_LABEL in args
    assert not any("nonce" in str(arg).lower() for arg in args)


def test_orphan_sweep_is_label_scoped_and_ignores_malformed_ids(monkeypatch):
    calls = []

    def fake(args, **_kwargs):
        from datetime import datetime, timedelta
        from types import SimpleNamespace

        calls.append(args)
        if args[1] == "ps":
            return SimpleNamespace(stdout="abcdef123456\n123456abcdef\nnot-an-id;rm -rf\n")
        if args[1] == "inspect":
            now = datetime.now(UTC)

            def record(ident, seconds):
                return {
                    "Id": ident,
                    "Name": "/" + NAME_PREFIX + ident,
                    "Created": (now - timedelta(seconds=seconds)).isoformat(),
                    "Config": {
                        "Labels": {
                            "org.aegisforge.validation": "1",
                            "org.aegisforge.validation-run": "a" * 32,
                        }
                    },
                }

            return SimpleNamespace(
                stdout=json.dumps([record("abcdef123456", 90), record("123456abcdef", 5)])
            )
        return SimpleNamespace(stdout="")

    monkeypatch.setattr("app.validation.runner.subprocess.run", fake)
    assert sweep_orphans({"PATH": "x"}) == 1
    listing, inspection, removal = calls
    assert f"label={PROJECT_LABEL}" in listing and f"name={NAME_PREFIX}" in listing
    assert inspection == ["docker", "inspect", "abcdef123456", "123456abcdef"]
    assert removal == ["docker", "rm", "-f", "abcdef123456"]


def test_cleanup_reaps_the_local_process_even_when_docker_rm_fails(monkeypatch):
    def failing(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("docker", 10)

    class Process:
        killed = waited = False

        def poll(self):
            return None

        def kill(self):
            self.killed = True

        def wait(self, timeout=None):
            self.waited = True

    monkeypatch.setattr("app.validation.runner.subprocess.run", failing)
    process = Process()
    cleanup(process, "aegisforge-validation-x", {})
    assert process.killed and process.waited


def test_runner_command_has_fixed_isolation_and_only_candidate_mount():
    args = command(
        "sha256:" + "a" * 64, "aegisforge-validation-test", "xss-01", Path("candidate.py")
    )
    assert args[args.index("--network") + 1] == "none"
    assert args[args.index("--user") + 1] == "65532:65532"
    assert args[args.index("--cap-drop") + 1] == "ALL"
    assert args[args.index("--pids-limit") + 1] == "128"
    assert args[args.index("--memory") + 1] == "512m"
    assert "--read-only" in args and "no-new-privileges:true" in args
    assert sum(arg == "--mount" for arg in args) == 1
    assert "readonly" in args[args.index("--mount") + 1]
    assert all("docker.sock" not in str(arg) for arg in args)


def test_unregistered_sources_and_non_image_ids_are_refused():
    with pytest.raises(DomainError, match="CONTROLLED_SAMPLE_REQUIRED"):
        match_case("0" * 64)
    with pytest.raises(DomainError, match="VALIDATOR_IMAGE"):
        command("arbitrary-image:latest", "name", "xss-01", Path("candidate.py"))


def test_missing_docker_is_environment_error_and_credentials_are_removed(api, monkeypatch):
    monkeypatch.setenv("AEGISFORGE_DEEPSEEK_API_KEY", "synthetic-key-not-for-docker")

    def unavailable(*_args, **kwargs):
        assert "AEGISFORGE_DEEPSEEK_API_KEY" not in kwargs["env"]
        raise FileNotFoundError("private-path-and-secret")

    monkeypatch.setattr("app.validation.runner.subprocess.run", unavailable)
    result = run_container(api.app.state.settings, "x=1", {"id": "xss-01"})
    assert result["status"] == "error" and "private" not in str(result)
