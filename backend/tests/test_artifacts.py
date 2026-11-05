import os
from pathlib import Path

import pytest


def upload(api, raw=b"print('hello')", filename="example.py", kind="source"):
    return api.post(
        "/api/v1/artifacts",
        params={"filename": filename, "input_type": kind},
        content=raw,
        headers={"Content-Type": "application/octet-stream"},
    )


def snapshots(api):
    return list(Path(api.app.state.settings.data_dir).glob("artifacts/*"))


def test_upload_snapshot_preview_auth_and_tamper(api):
    raw = b'api_key = "PRIVATE_FIXTURE"\nprint(1)'
    response = upload(api, raw)
    assert response.status_code == 201, response.text
    artifact = response.json()["artifact"]
    assert "PRIVATE_FIXTURE" not in response.text
    assert "storage_key" not in artifact
    assert api.get(f"/api/v1/artifacts/{artifact['id']}").json()["artifact"] == artifact
    path = next((api.app.state.settings.data_dir / "artifacts").iterdir())
    assert path.read_bytes() == raw
    path.write_bytes(b"tampered")
    result = api.get(f"/api/v1/artifacts/{artifact['id']}")
    assert result.status_code == 409
    api.headers.pop("Authorization")
    assert upload(api).status_code == 401


@pytest.mark.parametrize(
    "filename",
    ["../bad.py", "C:\\bad.py", "x/evil.py", "evil.zip", "bad\x00.py", "evil\u202eyp.py"],
)
def test_invalid_names_leave_no_snapshot(api, filename):
    assert upload(api, filename=filename).status_code == 422
    assert not snapshots(api)


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
    artifact = result.json()["artifact"]
    assert artifact["rule_findings"][0]["evidence_status"] == "attack_indicator"
    assert artifact["rule_findings_truncated"] is False
    assert artifact["field_meta"]["query.0"]["decode_passes"] == 1


@pytest.mark.parametrize(
    ("raw", "filename", "kind"),
    [
        ("GET /?" + "k" * 300 + "=%3Cscript%3E HTTP/1.1\nHost: a\n\n", "long.http", "http"),
        ("def f(x):\n    return ('<p>'\n" + "+x\n" * 20_000 + ")\n", "deep.py", "source"),
        ("import os\n" + "os.system(x)\n" * 150, "many.py", "source"),
    ],
)
def test_hostile_but_valid_inputs_never_create_unreadable_snapshots(api, raw, filename, kind):
    response = upload(api, raw.encode(), filename, kind)
    assert response.status_code == 201, response.text
    artifact = response.json()["artifact"]
    assert api.get(f"/api/v1/artifacts/{artifact['id']}").status_code == 200


@pytest.mark.parametrize(
    "raw",
    [
        b"POST / HTTP/1.1\nContent-Type: multipart/form-data; boundary=x\n\n--x\nsecret\n",
        b"POST / HTTP/1.1\nContent-Length: 2\nContent-Type: text/plain\n\nabcdef",
        b"GET / HTTP/1.1\nHost: a\rCookie: x\n\n",
    ],
)
def test_rejected_http_leaves_no_snapshot(api, raw):
    assert upload(api, raw, "request.http", "http").status_code == 422
    assert not snapshots(api)


def test_linked_artifact_directory_is_refused(api, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    link = Path(api.app.state.settings.data_dir) / "artifacts"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not permitted on this host")
    assert upload(api).status_code == 409
    assert not list(outside.iterdir())
