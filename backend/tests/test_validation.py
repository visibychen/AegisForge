from pathlib import Path

import pytest
from app.core.errors import DomainError
from app.validation.registry import match_case
from app.validation.runner import command, run_container


def test_runner_command_has_fixed_isolation_and_only_candidate_mount():
    args = command(
        "sha256:" + "a" * 64, "aegisforge-validation-test", "xss-01", Path("candidate.py")
    )
    assert args[args.index("--network") + 1] == "none"
    assert args[args.index("--user") + 1] == "65532:65532"
    assert args[args.index("--cap-drop") + 1] == "ALL"
    assert args[args.index("--pids-limit") + 1] == "64"
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
