import asyncio

import httpx

from app.main import create_app


def test_health_endpoint() -> None:
    """The health endpoint should respond with an ok status."""

    app = create_app()

    async def request() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.get("/api/v1/health")

    response = asyncio.run(request())

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
