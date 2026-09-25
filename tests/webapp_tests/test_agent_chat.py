import pytest


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    monkeypatch.setenv("VULNSCOUT_AGENT_ENABLED", "1")
    monkeypatch.delenv("VULNSCOUT_MCP_SERVER_PATH", raising=False)
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    from src.bin.webapp import create_app

    app = create_app()
    app.config.update(TESTING=True, SCAN_FILE=str(scan_file))
    return app.test_client()


def test_agent_is_opt_in(client, monkeypatch):
    monkeypatch.delenv("VULNSCOUT_AGENT_ENABLED")
    response = client.get("/api/agent")
    assert response.status_code == 404


def test_agent_rejects_remote_requests(client):
    response = client.get("/api/agent", environ_overrides={"REMOTE_ADDR": "192.0.2.1"})
    assert response.status_code == 403


def test_agent_rejects_non_local_host(client):
    response = client.get("/api/agent", headers={"Host": "example.org"})
    assert response.status_code == 403
    response = client.delete("/api/agent/conversation", headers={"Host": "[::1]:7275"})
    assert response.status_code == 200


def test_agent_rejects_foreign_origin(client):
    response = client.post("/api/agent/messages", json={"message": "Hello"},
                           headers={"Origin": "https://example.org"})
    assert response.status_code == 403


def test_message_requires_text_and_configured_mcp(client):
    assert client.post("/api/agent/messages", json=["Hello"]).status_code == 400
    assert client.post("/api/agent/messages", json={"message": ""}).status_code == 400
    assert client.post("/api/agent/messages", json={"message": "Hello", "allow_writes": "yes"}).status_code == 400
    response = client.post("/api/agent/messages", json={"message": "Hello"})
    assert response.status_code == 503
    assert "VULNSCOUT_MCP_SERVER_PATH" in response.get_json()["error"]
    assert response.headers["Cache-Control"] == "no-store"


def test_context_rejects_malformed_and_unbounded_rows(client):
    for context in ({"page": "unknown"}, {"page": "vulnerabilities", "view": {"visibleVulnerabilityIds": ["CVE-1"] * 101}},
                    {"page": "review", "view": {"visibleCount": -1}}):
        response = client.post("/api/agent/messages", json={"message": "Assess", "context": context})
        assert response.status_code == 400


def test_page_selections_pass_validation_before_mcp_setup(client):
    context = {"page": "scans", "projectId": "project", "view": {
        "section": "scan history", "visibleScanIds": ["scan-id"],
        "selectedScanTypes": ["grype"], "selectedRefreshTypes": ["nvd"],
        "refreshMode": "custom", "hideEmptyScans": False,
        "excludeKernel": True, "excludeNative": True,
    }}
    response = client.post("/api/agent/messages", json={"message": "Review scans", "context": context})
    assert response.status_code == 503
    assert "VULNSCOUT_MCP_SERVER_PATH" in response.get_json()["error"]


def test_large_project_scope_uses_count_without_partial_ids(client):
    response = client.post("/api/agent/messages", json={
        "message": "Summarize", "context": {"page": "ai", "variantCount": 85, "view": {
            "selectedProjectName": "AgentDemo", "selectedVariantName": "Sample",
            "exportCategory": "all", "enabledExportDocuments": ["spdx2"],
        }},
    })
    assert response.status_code == 503
    assert "VULNSCOUT_MCP_SERVER_PATH" in response.get_json()["error"]
    invalid = client.post("/api/agent/messages", json={
        "message": "Summarize", "context": {"page": "ai", "variantCount": -1},
    })
    assert invalid.status_code == 400


def test_new_conversation_does_not_clear_authentication(client):
    result = client.delete("/api/agent/conversation").get_json()
    assert result["messages"] == []
    assert result["usage"]["cost"] is None
    assert client.post("/api/agent/auth", json=["invalid"]).status_code == 400
    assert client.post("/api/agent/auth", json={"token": "invalid"}).status_code == 400


def test_status_uses_real_copilot_runtime(client):
    response = client.get("/api/agent")
    assert response.status_code == 200
    assert response.get_json()["configured"] is False
    assert isinstance(response.get_json()["authenticated"], bool)
    assert response.get_json()["token_connected"] is False
    assert response.get_json()["messages"] == []
    assert response.headers["Set-Cookie"].startswith("vulnscout_agent=")


def test_models_use_signed_in_account(client):
    response = client.get("/api/agent/models")
    assert response.status_code == 200
    assert any(model["id"] == "auto" for model in response.get_json()["models"])


def test_selected_model_persists_without_sending(client):
    assert client.post("/api/agent/model", json={"model": "nonexistent-model"}).status_code == 400
    assert client.post("/api/agent/model", json={"model": "auto"}).get_json()["model"] == "auto"
    assert client.get("/api/agent").get_json()["model"] == "auto"