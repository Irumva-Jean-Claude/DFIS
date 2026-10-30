import os, tempfile
_d = tempfile.mkdtemp()
os.environ.update(DFIS_DATA_DIR=_d, DFIS_DATABASE_URL=f"sqlite:///{_d}/t.db", DFIS_ADMIN_USERNAME="admin",
                  DFIS_ADMIN_PASSWORD="AdminPass12345",
                  DFIS_SECRET_KEY="test-secret-key-for-tests-only-0123456789", DFIS_MAX_UPLOAD_MB="1")
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


def login(c, u, p):
    r = c.post("/api/v1/auth/login", json={"username": u, "password": p})
    return r


def H(c, u, p):
    return {"Authorization": "Bearer " + login(c, u, p).json()["access_token"]}


@pytest.fixture(scope="session")
def admin(client):
    return H(client, "admin", "AdminPass12345")


@pytest.fixture(scope="session")
def users(client, admin):
    out = {}
    for name, role in (("lead1", "lead"), ("lead2", "lead"), ("rev1", "reviewer"), ("ana1", "analyst")):
        r = client.post("/api/v1/users", headers=admin, json={"username": name, "full_name": name.title(), "email": "", "role": role, "password": "Passw0rd12345"})
        assert r.status_code == 201, r.text
        out[name] = H(client, name, "Passw0rd12345")
    return out
