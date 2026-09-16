import os
import asyncio
import secrets
from ipaddress import ip_address
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator
from .service import Store, ServiceError
from .runners.providers import MODELS, DemoRunner, LiveRunner

HOSTS = {f"{h}:{p}" for h in ("localhost", "127.0.0.1") for p in (8000, 5173, 8011)}
ORIGINS = {f"http://{h}" for h in HOSTS}


def local_peer(client):
    if client is None:
        return False
    try:
        address = ip_address(client.host)
        mapped = getattr(address, "ipv4_mapped", None)
        return (mapped or address).is_loopback
    except ValueError:
        return False


class RunInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    prompt: str = Field(min_length=1, max_length=4000)
    models: list[Literal["gpt", "gemini", "claude"]] = Field(min_length=1, max_length=3)

    @field_validator("prompt")
    @classmethod
    def nonempty(cls, value):
        if not value.strip():
            raise ValueError("empty")
        return value

    @field_validator("models")
    @classmethod
    def unique(cls, value):
        if len(set(value)) != len(value):
            raise ValueError("duplicate")
        return value


def create_app(mode=None, runner=None):
    mode = mode or os.environ.get("UNION_MODE", "live")
    if mode not in {"demo", "live"}:
        raise ValueError("UNION_MODE must be demo or live")
    if runner is None:
        if mode == 'demo':
            runner = DemoRunner(os.environ.get('UNION_DEMO_SCENARIO', 'normal'))
        else:
            from .runners.codex import CodexAdapter, preflight
            from .runners.agy import AgyAdapter, MODEL_IDS, policy_verified, preflight as agy_preflight
            # Missing/changed executable, credential metadata or firewall => closed.
            checks = preflight()
            adapters = {'gpt': CodexAdapter()} if checks and all(v is True for v in checks.values()) else {}
            if policy_verified() and agy_preflight():
                adapters.update({model: AgyAdapter(model) for model in MODEL_IDS})
            runner = LiveRunner(adapters)
    store = Store(runner, mode)
    token = secrets.token_urlsafe(32)

    def available(model):
        return model in MODELS and (mode == "demo" or
               isinstance(store.runner, LiveRunner) and store.runner.available(model))

    @asynccontextmanager
    async def lifespan(app):
        async def sweep():
            while True:
                await asyncio.sleep(30)
                store.cleanup()
        janitor = asyncio.create_task(sweep())
        try:
            yield
        finally:
            janitor.cancel()
            await asyncio.gather(janitor, return_exceptions=True)
            await store.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = store

    @app.middleware("http")
    async def guard(request: Request, call_next):
        # This application has no supported reverse proxy or remote clients.
        # Do not trust a localhost Host header as proof of a local connection.
        if not local_peer(request.client) or any(
            name == "forwarded" or name.startswith("x-forwarded-")
            for name in request.headers
        ):
            return JSONResponse({"error": "origin_rejected"}, status_code=403)
        if any(len(request.headers.getlist(name)) > 1 for name in
               ("host", "origin", "x-union-token", "content-type", "sec-fetch-site")):
            return JSONResponse({"error": "origin_rejected"}, status_code=403)
        host = request.headers.get("host", "")
        origin = request.headers.get("origin")
        if host not in HOSTS or (origin is not None and
                                (origin not in ORIGINS or origin != f"http://{host}")):
            return JSONResponse({"error": "origin_rejected"}, status_code=403)
        if request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"error": "origin_rejected"}, status_code=403)
        if request.method not in {"GET", "HEAD"}:
            if request.headers.get("content-type", "").split(";")[0].strip() != "application/json":
                return JSONResponse({"error": "json_required"}, status_code=415)
            supplied_token = request.headers.get("x-union-token", "")
            if not supplied_token.isascii() or not secrets.compare_digest(supplied_token, token):
                return JSONResponse({"error": "session_expired"}, status_code=403)
            # Bound the body while reading; Content-Length alone is insufficient.
            body = bytearray()
            async for chunk in request.stream():
                if len(body) + len(chunk) > 32768:
                    return JSONResponse({"error": "input_limit"}, status_code=413)
                body.extend(chunk)
            request._body = bytes(body)
        response = await call_next(request)
        response.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
        return response

    @app.exception_handler(ServiceError)
    async def service_error(request, exc):
        return JSONResponse({"error": exc.code}, status_code=exc.status)

    @app.exception_handler(RequestValidationError)
    async def input_error(request, exc):
        return JSONResponse({"error": "invalid_input"}, status_code=422)

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "mode": mode, "csrf_token": token,
                "live_ready": mode == "live" and all(available(model) for model in MODELS)}

    @app.get("/api/models")
    async def models():
        return [{"id": key, **value, "mode": mode, "available": available(key),
                 "model_verified": mode == "live" and available(key),
                 "blocker": None if available(key) else "security_unverified"} for key, value in MODELS.items()]

    @app.post("/api/runs", status_code=201)
    async def create(data: RunInput):
        # Check every selection before allocating a run or starting any task.
        if any(not available(model) for model in data.models):
            raise ServiceError("provider_unavailable", 503)
        return await store.create(data.prompt, data.models)

    @app.get("/api/runs/{key}")
    async def get(key: str):
        return store.get(key)

    @app.post("/api/runs/{key}/models/{model}/retry")
    async def retry(key: str, model: str):
        store.get(key)  # Preserve missing/expired-run errors without mutation.
        if not available(model):
            raise ServiceError("provider_unavailable", 503)
        return await store.retry(key, model)

    dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    if dist.exists():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        @app.get("/")
        async def index():
            return FileResponse(dist / "index.html")

    return app


app = create_app()
