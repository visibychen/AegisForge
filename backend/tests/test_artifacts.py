from pathlib import Path

import pytest


def upload(api, raw=b"print('hello')", filename="example.py", kind="source"):
    return api.post(
        "/api/v1/artifacts",
        params={"filename": filename, "input_type": kind},
        content=raw,
        headers={"Content-Type": "application/octet-stream"},
    )


def test_upload_snapshot_preview_auth_and_tamper(api):
    raw = b'api_key = "PRIVATE_FIXTURE"\nprint(1)'
    response = upload(api, raw)
    assert response.status_code == 201, response.text
    artifact = response.json()["artifact"]
    assert "PRIVATE_FIXTURE" not in response.text
    assert "storage_key" not in artifact
    assert api.get(f"/api/v1/artifacts/{artifact['id']}").json()["artifact"] == artifact
    folder = api.app.state.settings.data_dir / "artifacts"
    path = next(folder.iterdir())
    assert path.read_bytes() == raw
    path.write_bytes(b"tampered")
    result = api.get(f"/api/v1/artifacts/{artifact['id']}")
    assert result.status_code == 409
    api.headers.pop("Authorization")
    assert upload(api).status_code == 401


@pytest.mark.parametrize(
    "filename", ["../bad.py", "C:\\bad.py", "x/evil.py", "evil.zip", "bad\x00.py"]
)
def test_invalid_names_leave_no_snapshot(api, filename):
    assert upload(api, filename=filename).status_code == 422
    assert not list(Path(api.app.state.settings.data_dir).glob("artifacts/*"))


def test_stream_size_limit_and_bad_encoding(api):
    api.app.state.settings.max_file_bytes = 16
    assert upload(api, b"a" * 17).status_code == 413
    assert upload(api, b"\xff").status_code == 422


def test_http_upload_preview_is_offline_and_redacted(api):
    result = upload(
        api,
        b"GET /?q=%3Cscript%3E HTTP/1.1\nHost: example.invalid\nCookie: HIDDEN\n\n",
        "request.http",
        "http",
    )
    assert result.status_code == 201
    assert "HIDDEN" not in result.text
    assert result.json()["artifact"]["rule_findings"][0]["evidence_status"] == "attack_indicator"
