from fastapi.testclient import TestClient
from src.api.api import app

client = TestClient(app)


def test_extract_features_ip_url():
    response = client.post(
        "/extract_features",
        json={
            "url": "http://192.168.0.1/login"
        }
    )

    data = response.json()

    assert response.status_code == 200
    assert data["features"]["match_url_01"] == 1
    assert "URL-01" in data["matched_rules"]


def test_extract_features_normal_url():
    response = client.post(
        "/extract_features",
        json={
            "url": "http://example.com"
        }
    )

    data = response.json()

    assert response.status_code == 200
    assert data["features"]["match_url_01"] == 0


def test_email_invalid_from():
    response = client.post(
        "/extract_features",
        json={
            "email_ctx": {
                "from_addr": "invalidemail",
                "subject": "Hello",
                "body_text": "Test email"
            }
        }
    )

    data = response.json()

    assert response.status_code == 200
    assert data["features"]["match_email_01"] == 1