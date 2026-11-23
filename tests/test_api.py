"""End-to-end API tests for ECDAT."""

import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

import pytest
from fastapi.testclient import TestClient

from main import app
from app.db.session import init_db


@pytest.fixture(scope="function", autouse=True)
def setup_database():
    """Initialize database before each test."""
    init_db()
    yield


@pytest.fixture
def client():
    return TestClient(app)


def test_health_check(client):
    """Test health endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_create_project(client):
    """Test creating a project."""
    response = client.post(
        "/api/projects",
        json={
            "name": "Test Project",
            "description": "Test description",
            "business_criticality": 3,
            "data_lifetime_years": 5.0,
            "migration_time_years": 3.0,
            "exposure": "internal",
            "sources": [],
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Test Project"
    assert "id" in data
    return data["id"]


def test_list_projects(client):
    """Test listing projects."""
    response = client.get("/api/projects")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_get_project(client):
    """Test getting a specific project."""
    # First create a project
    create_response = client.post(
        "/api/projects",
        json={
            "name": "Test Project 2",
            "description": "Test",
            "business_criticality": 3,
            "data_lifetime_years": 5.0,
            "migration_time_years": 3.0,
            "exposure": "internal",
            "sources": [],
        },
    )
    project_id = create_response.json()["id"]
    
    # Get the project
    response = client.get(f"/api/projects/{project_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == project_id
    assert data["name"] == "Test Project 2"


def test_create_scan(client):
    """Test creating a scan."""
    # First create a project
    create_response = client.post(
        "/api/projects",
        json={
            "name": "Scan Test Project",
            "description": "For scanning",
            "business_criticality": 3,
            "data_lifetime_years": 5.0,
            "migration_time_years": 3.0,
            "exposure": "internal",
            "sources": [],
        },
    )
    project_id = create_response.json()["id"]
    
    # Create a scan
    response = client.post(
        "/api/scans",
        json={
            "project_id": project_id,
            "source_type": "local_dir",
            "source_location": str(Path(__file__).parent.parent / "fixtures" / "vulnerable-project"),
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["project_id"] == project_id
    assert data["status"] == "queued"
    assert "id" in data


def test_list_scans(client):
    """Test listing scans."""
    response = client.get("/api/scans")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_list_assets(client):
    """Test listing crypto assets."""
    response = client.get("/api/assets")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_list_findings(client):
    """Test listing findings."""
    response = client.get("/api/findings")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
