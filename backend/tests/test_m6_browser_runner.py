"""Keep the trusted UI browser container distinct from the candidate execution runner."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import ci_workbench  # noqa: E402


def test_browser_command_pins_image_and_forwards_only_explicit_browser_configuration(monkeypatch):
    monkeypatch.setenv("AEGISFORGE_DEEPSEEK_API_KEY", "synthetic-host-secret")
    monkeypatch.setenv("PRIVATE_HOST_VALUE", "not-forwarded")
    args = ci_workbench.browser_command(
        "firefox",
        "/workspace/data/report.json",
        "/opt/node24/bin/node",
        "1001:1001",
        "tests/e2e/foundation.spec.ts",
    )
    assert ci_workbench.BROWSER_IMAGE in args and "@sha256:" in ci_workbench.BROWSER_IMAGE
    assert "--network=host" in args and "--rm" in args and "--init" in args
    assert "--cap-drop=ALL" in args and "--security-opt=no-new-privileges" in args
    assert "/opt/node24/bin/node:/usr/local/bin/node:ro" in args
    assert "PLAYWRIGHT_BROWSER=firefox" in args and "AEGISFORGE_DEEPSEEK_API_KEY=" in args
    text = " ".join(args)
    assert "synthetic-host-secret" not in text and "not-forwarded" not in text
    assert "docker.sock" not in text and "--env-file" not in args and "--privileged" not in args
    assert args[-1] == "tests/e2e/foundation.spec.ts"
    with pytest.raises(ValueError):
        ci_workbench.browser_command("unregistered", "x", "node", "1001:1001")


def test_playwright_upgrade_requires_an_explicit_matching_image_update(tmp_path, monkeypatch):
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend/package.json").write_text(
        json.dumps(
            {
                "devDependencies": {"@playwright/test": "different-version"},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(ci_workbench, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="verified browser image"):
        ci_workbench.browser_image()
