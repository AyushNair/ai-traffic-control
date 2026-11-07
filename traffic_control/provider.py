"""OpenAI-compatible upstream adapter and provider extension contract."""
from __future__ import annotations

from typing import Any, Protocol

import httpx
from fastapi.responses import JSONResponse, Response


class ProviderAdapter(Protocol):
    """Provider implementations translate gateway calls to upstream APIs."""
    async def chat_completions(self, payload: dict[str, Any]) -> Response: ...
    async def list_models(self) -> Response: ...
    @property
    def provider_name(self) -> str: ...


class OpenAICompatibleProvider:
    """Real upstream adapter for providers exposing OpenAI-compatible routes."""
    def __init__(self, settings: Any):
        self.settings = settings

    @property
    def provider_name(self) -> str:
        try:
            return httpx.URL(self.settings.upstream_base_url).host or "configured provider"
        except Exception:
            return "configured provider"

    def _url(self, route: str) -> str:
        return f"{self.settings.upstream_base_url.rstrip('/')}/{route.lstrip('/')}"

    async def chat_completions(self, payload: dict[str, Any]) -> Response:
        if not self.settings.api_key:
            return JSONResponse(status_code=503, content={"error": {"type": "provider_not_configured", "message": "Configure an upstream API key in AI Traffic Control before forwarding requests."}})
        headers = {"Authorization": f"Bearer {self.settings.api_key}", "Content-Type": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
                upstream = await client.post(self._url("chat/completions"), json=payload, headers=headers)
            if upstream.status_code >= 400:
                return JSONResponse(status_code=upstream.status_code, content={"error": {"type": "upstream_error", "message": "The configured upstream provider rejected the request. Check provider settings and upstream status."}})
            allowed_headers = {key: value for key, value in upstream.headers.items() if key.lower() in {"content-type", "retry-after"}}
            return Response(content=upstream.content, status_code=upstream.status_code, headers=allowed_headers)
        except httpx.TimeoutException:
            return JSONResponse(status_code=504, content={"error": {"type": "upstream_timeout", "message": "The upstream provider did not respond before the configured timeout."}})
        except httpx.HTTPError:
            return JSONResponse(status_code=502, content={"error": {"type": "upstream_connection_error", "message": "Could not connect to the configured provider endpoint."}})

    async def list_models(self) -> Response:
        if not self.settings.api_key:
            return JSONResponse(status_code=503, content={"error": {"type": "provider_not_configured", "message": "Configure an upstream API key to retrieve provider models."}})
        try:
            async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
                upstream = await client.get(self._url("models"), headers={"Authorization": f"Bearer {self.settings.api_key}"})
            return Response(content=upstream.content, status_code=upstream.status_code,
                            media_type=upstream.headers.get("content-type", "application/json"))
        except httpx.TimeoutException:
            return JSONResponse(status_code=504, content={"error": {"type": "upstream_timeout", "message": "The upstream provider did not respond before the configured timeout."}})
        except httpx.HTTPError:
            return JSONResponse(status_code=502, content={"error": {"type": "upstream_connection_error", "message": "Could not connect to the configured provider endpoint."}})
