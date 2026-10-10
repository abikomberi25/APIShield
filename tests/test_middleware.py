"""Tests for SecurityGatewayMiddleware."""

from fastapi.testclient import TestClient


def test_middleware_adds_response_time_header_to_health(client: TestClient) -> None:
    """Verify that SecurityGatewayMiddleware appends X-Response-Time-Ms to /health."""
    response = client.get("/health")
    assert response.status_code == 200
    assert "x-response-time-ms" in response.headers

    header_val = response.headers["x-response-time-ms"]
    duration = float(header_val)
    assert duration >= 0.0


def test_middleware_adds_header_to_error_responses(client: TestClient) -> None:
    """Verify that SecurityGatewayMiddleware appends X-Response-Time-Ms to 404 responses."""
    response = client.get("/nonexistent-endpoint")
    assert response.status_code == 404
    assert "x-response-time-ms" in response.headers
    assert float(response.headers["x-response-time-ms"]) >= 0.0


def test_middleware_does_not_mutate_body(client: TestClient) -> None:
    """Verify that SecurityGatewayMiddleware preserves the response payload intact."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
