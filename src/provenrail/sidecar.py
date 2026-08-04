"""Out-of-process capture sidecar: a recording reverse proxy in front of the model API.

Why this exists
---------------
In-process capture (the SDK, the drop-in instrumenters) is the easiest to adopt, but it shares
the agent's address space: a hostile or prompt-injected agent can simply not call the logger.
The honest boundary has always been "completeness is never claimed" (README).

The sidecar narrows that gap. The agent points its model client's base URL at this proxy instead
of at the provider. The proxy forwards every request to the real API and records the call to the
off-box sink from a SEPARATE process the agent does not control. To avoid being recorded, the
agent now has to avoid the proxy entirely, which means not getting a model response at all (when
egress is locked to the proxy) or reconfiguring infrastructure it does not own. That is a real,
marketable step up from "skip one function call".

Honest boundary (still load-bearing)
-------------------------------------
The sidecar does NOT by itself prove completeness. Its guarantee is only as strong as the egress
control around it: if the agent can open a direct socket to the provider, it can bypass the
proxy. The deployment contract is "force all model egress through the sidecar" (network policy,
firewall, no outbound 443 except to the sidecar). With that, capture becomes mandatory; without
it, the sidecar is a strong default, not a proof. We never overstate this.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import Request

# Hop-by-hop and body-framing headers we must not copy verbatim when re-emitting a response,
# since we re-read and re-frame the body ourselves.
_DROP_RESPONSE_HEADERS = {
    "content-length", "content-encoding", "transfer-encoding", "connection",
    "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "upgrade",
}
_DROP_REQUEST_HEADERS = {"host", "content-length", "accept-encoding", "connection"}


def infer_provider(upstream: str) -> str:
    host = upstream.split("://", 1)[-1].split("/", 1)[0].lower()
    if "openai" in host:
        return "openai"
    if "anthropic" in host:
        return "anthropic"
    if "googleapis" in host or "generativelanguage" in host:
        return "google"
    return host or "http"


def _json_or_text(raw: bytes) -> Any:
    if not raw:
        return ""
    try:
        return json.loads(raw)
    except Exception:
        try:
            return raw.decode("utf-8", "replace")
        except Exception:
            return {"bytes": len(raw)}


def model_from_body(raw: bytes) -> str:
    body = _json_or_text(raw)
    if isinstance(body, dict) and isinstance(body.get("model"), str):
        return body["model"]
    return "unknown"


def is_model_call(method: str, raw: bytes) -> bool:
    """A model call is a POST whose JSON body names a model and carries a prompt-shaped field.
    This stays provider-agnostic (OpenAI chat/responses, Anthropic messages, etc.)."""
    if method.upper() != "POST":
        return False
    body = _json_or_text(raw)
    if not isinstance(body, dict) or "model" not in body:
        return False
    return any(k in body for k in ("messages", "prompt", "input", "contents"))


def _normalize_usage(resp: Any) -> dict[str, str] | None:
    """Map OpenAI / Anthropic usage shapes to a common {input, output} (strings, like the SDK)."""
    if not isinstance(resp, dict):
        return None
    u = resp.get("usage")
    if not isinstance(u, dict):
        return None
    inp = u.get("input_tokens", u.get("prompt_tokens"))
    out = u.get("output_tokens", u.get("completion_tokens"))
    if inp is None and out is None:
        return None
    norm: dict[str, str] = {}
    if inp is not None:
        norm["input"] = str(inp)
    if out is not None:
        norm["output"] = str(out)
    return norm


def _usage_from_sse(text: str) -> dict[str, str] | None:
    """Best-effort: pull a usage object out of an SSE stream's data lines (OpenAI include_usage,
    Anthropic message_delta). Returns None if none is present; we never fabricate token counts."""
    best: dict[str, str] | None = None
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            obj = json.loads(payload)
        except Exception:
            continue
        u = _normalize_usage(obj) or _normalize_usage(obj.get("message", {}) if isinstance(obj, dict) else {})
        if u:
            best = u
    return best


def create_sidecar_app(recorder, upstream: str, *, provider: str | None = None,
                       client: Any | None = None, session_meta: dict | None = None,
                       fail_closed: bool = False):
    """Build the recording reverse proxy.

    recorder    : a FlightRecorder (already configured against the sink).
    upstream    : the real provider base URL (e.g. https://api.openai.com).
    client      : an httpx.AsyncClient to forward with (injected in tests); created if omitted.
    fail_closed : if True, a model call whose record cannot be written returns 502 instead of
                  being forwarded uninstrumented. Maximum assurance; default is fail-open so a
                  sink blip never takes the agent down. Only meaningful with a synchronous sink.
    """
    from contextlib import asynccontextmanager

    import httpx
    from fastapi import FastAPI
    from fastapi.responses import Response, StreamingResponse

    upstream = upstream.rstrip("/")
    provider = provider or infer_provider(upstream)
    owns_client = client is None
    fwd: Any = client or httpx.AsyncClient(base_url=upstream, timeout=300.0)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        recorder.start(session_meta or {"sidecar": True, "provider": provider,
                                        "upstream": upstream})
        try:
            yield
        finally:
            recorder.seal()
            recorder.close()
            if owns_client:
                await fwd.aclose()

    app = FastAPI(title="Provenrail Sidecar", version="0.1.0", lifespan=lifespan)

    @app.get("/__fr_sidecar/health")
    def health():
        return {"ok": True, "provider": provider, "upstream": upstream,
                "stream_id": recorder.stream_id}

    def _record(model: str, req: Any, resp: Any, usage: dict | None) -> bool:
        try:
            recorder.record_model_call(provider, model, request=req, response=resp, usage=usage)
            return True
        except Exception:
            return False

    @app.api_route("/{path:path}",
                   methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    async def proxy(path: str, request: Request):
        body = await request.body()
        req_headers = {k: v for k, v in request.headers.items()
                       if k.lower() not in _DROP_REQUEST_HEADERS}
        upstream_req = fwd.build_request(request.method, "/" + path,
                                         params=request.query_params,
                                         headers=req_headers, content=body)
        resp = await fwd.send(upstream_req, stream=True)
        out_headers = [(k, v) for k, v in resp.headers.items()
                       if k.lower() not in _DROP_RESPONSE_HEADERS]
        ctype = resp.headers.get("content-type", "")
        model_call = is_model_call(request.method, body)
        model = model_from_body(body) if model_call else "unknown"
        req_repr = _json_or_text(body)

        if "text/event-stream" in ctype:
            collected: list[bytes] = []

            async def tee():
                try:
                    async for chunk in resp.aiter_bytes():
                        collected.append(chunk)
                        yield chunk
                finally:
                    await resp.aclose()
                    if model_call:
                        text = b"".join(collected).decode("utf-8", "replace")
                        _record(model, req_repr, text, _usage_from_sse(text))

            return StreamingResponse(tee(), status_code=resp.status_code,
                                     headers=dict(out_headers), media_type=ctype)

        raw = await resp.aread()
        await resp.aclose()
        if model_call:
            resp_repr = _json_or_text(raw)
            ok = _record(model, req_repr, resp_repr, _normalize_usage(resp_repr))
            if fail_closed and not ok:
                return Response('{"error":"flight recorder: call could not be recorded"}',
                                status_code=502, media_type="application/json")
        return Response(content=raw, status_code=resp.status_code,
                        headers=dict(out_headers), media_type=ctype)

    return app
