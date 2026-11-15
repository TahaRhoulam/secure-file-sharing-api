import pytest
from fastapi.testclient import TestClient
from app import main


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "test.db")
    return TestClient(main.app)


def auth(client, username):
    password = "a-long-password-123"
    assert client.post("/register", json={"username": username, "password": password}).status_code == 201
    token = client.post("/login", json={"username": username, "password": password}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_end_to_end(client):
    alice = auth(client, "alice")
    bob = auth(client, "bob")
    uploaded = client.post("/files", headers=alice,
                           files={"file": ("note.txt", b"hello", "text/plain")})
    assert uploaded.status_code == 201
    file_id = uploaded.json()["id"]
    assert len(client.get("/files", headers=alice).json()) == 1
    assert client.get(f"/files/{file_id}", headers=bob).status_code == 404
    assert client.get(f"/files/{file_id}", headers=alice).content == b"hello"
    shared = client.post(f"/files/{file_id}/share", headers=alice,
                         json={"expires_in_seconds": 60})
    assert shared.status_code == 200
    link = shared.json()["download_path"]
    assert client.get(link).content == b"hello"
    assert client.delete(f"/files/{file_id}", headers=alice).status_code == 204
    assert client.get(link).status_code == 404


def test_auth_and_validation(client):
    assert client.get("/files").status_code == 401
    assert client.post("/register", json={"username": "ab", "password": "short"}).status_code == 422
    headers = auth(client, "testuser")
    assert client.post("/register", json={"username": "testuser",
                       "password": "a-long-password-123"}).status_code == 409
    assert client.post("/files", headers=headers,
                       files={"file": ("big.bin", b"x" * (2 * 1024 * 1024 + 1))}).status_code == 413
    assert client.post("/files/1/share", headers=headers,
                       json={"expires_in_seconds": 1}).status_code == 422
