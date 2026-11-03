from app.core.config import Settings
from app.main import create_app
from fastapi.testclient import TestClient
from pydantic import SecretStr


def client(token="local-test-token"):
    settings = Settings(_env_file=None, api_token=SecretStr(token))
    return TestClient(create_app(settings), raise_server_exceptions=False)


def test_health_is_public_and_request_id_is_generated():
    response = client().get("/health", headers={"X-Request-ID": "untrusted"})
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["request_id"] == response.headers["X-Request-ID"]
    assert response.headers["X-Request-ID"] != "untrusted"
    assert response.headers["Cache-Control"] == "no-store"


def test_capabilities_requires_token_and_does_not_expose_configuration():
    api = client()
    for headers in [{}, {"Authorization": "Bearer incorrect"}]:
        response = api.get("/api/v1/capabilities", headers=headers)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "UNAUTHORIZED"
        assert "local-test-token" not in response.text
    response = api.get("/api/v1/capabilities", headers={"Authorization": "Bearer local-test-token"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["model_mode"] == "fake"
    assert payload["analysis_available"] is False
    assert payload["repair_available"] is False
    assert payload["supported_input_types"] == []
    assert not {"api_token", "database_url", "data_dir"} & payload.keys()


def test_unconfigured_token_fails_closed():
    response = client("").get("/api/v1/capabilities")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "SERVICE_NOT_CONFIGURED"


def test_not_found_is_a_structured_error():
    response = client().post("/api/v1/scans", json={"secret": "do-not-echo"})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "HTTP_ERROR"
    assert "do-not-echo" not in response.text


def test_unexpected_failure_does_not_expose_internal_details():
    api = client()

    @api.app.get("/test-error")
    def explode():
        raise RuntimeError("private-credential-and-local-path")

    response = api.get("/test-error")
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "INTERNAL_ERROR"
    assert response.json()["request_id"] == response.headers["X-Request-ID"]
    assert "private-credential" not in response.text


def test_cors_does_not_allow_arbitrary_origins():
    api = client()
    denied = api.options(
        "/api/v1/capabilities",
        headers={"Origin": "https://untrusted.example", "Access-Control-Request-Method": "GET"},
    )
    assert "Access-Control-Allow-Origin" not in denied.headers
    allowed = api.options(
        "/api/v1/capabilities",
        headers={"Origin": "http://127.0.0.1:5173", "Access-Control-Request-Method": "GET"},
    )
    assert allowed.headers["Access-Control-Allow-Origin"] == "http://127.0.0.1:5173"


def test_openapi_documents_authorization_and_capability_contract():
    schema = client().get("/openapi.json").json()
    route = schema["paths"]["/api/v1/capabilities"]["get"]
    assert route["security"] == [{"HTTPBearer": []}]
    assert {"200", "401", "503"} <= route["responses"].keys()
