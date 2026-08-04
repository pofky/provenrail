"""Thin transport to the ingest API.

Accepts any object with httpx-compatible ``.post`` / ``.get`` (httpx.Client in
production, FastAPI TestClient in tests), so the SDK has no hard network dependency.
"""

from __future__ import annotations

from typing import Any


class IngestClient:
    def __init__(self, base_url: str, write_token: str, http: Any | None = None):
        self.base_url = base_url.rstrip("/")
        self.write_token = write_token
        if http is None:
            import httpx
            http = httpx.Client(base_url=self.base_url, timeout=10.0)
            self._owns_http = True
        else:
            self._owns_http = False
        self._http = http

    def _url(self, path: str) -> str:
        # TestClient ignores base_url joining quirks; build a clean path either way.
        if getattr(self._http, "base_url", None):
            return path
        return f"{self.base_url}{path}"

    def ingest(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        resp = self._http.post(
            self._url("/v1/ingest"),
            json={"records": records},
            headers={"Authorization": f"Bearer {self.write_token}"},
        )
        if resp.status_code >= 400:
            raise RuntimeError(f"ingest failed {resp.status_code}: {resp.text}")
        return resp.json()

    def close(self) -> None:
        if self._owns_http:
            self._http.close()


def provision_account(base_url: str, label: str | None = None, http: Any | None = None) -> dict[str, Any]:
    """Create an account and return {account_id, api_key}. The key is shown only once."""
    own = False
    if http is None:
        import httpx
        http = httpx.Client(base_url=base_url.rstrip("/"), timeout=10.0)
        own = True
    try:
        path = "/v1/accounts" if getattr(http, "base_url", None) else f"{base_url.rstrip('/')}/v1/accounts"
        resp = http.post(path, json={"label": label})
        if resp.status_code >= 400:
            raise RuntimeError(f"account creation failed {resp.status_code}: {resp.text}")
        return resp.json()
    finally:
        if own:
            http.close()


def provision_stream(base_url: str, label: str | None = None, http: Any | None = None,
                     api_key: str | None = None) -> dict[str, Any]:
    """Create a new stream and return its tokens. Returns dict with stream_id and *_token."""
    own = False
    if http is None:
        import httpx
        http = httpx.Client(base_url=base_url.rstrip("/"), timeout=10.0)
        own = True
    try:
        path = "/v1/streams" if getattr(http, "base_url", None) else f"{base_url.rstrip('/')}/v1/streams"
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        resp = http.post(path, json={"label": label}, headers=headers)
        if resp.status_code >= 400:
            raise RuntimeError(f"provision failed {resp.status_code}: {resp.text}")
        return resp.json()
    finally:
        if own:
            http.close()
