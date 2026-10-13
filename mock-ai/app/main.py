"""Stand-in for the protected AI application.

GET  /health            -> {"status": "ok"}
POST /v1/ai/chat        -> canned assistant reply; echoes the security headers it received
POST /v1/ai/leak-test   -> replies with whatever `reply` the caller asks for (outbound tests, Stage 7);
                           `allowed_identifiers` is returned in X-Security-Allowed-Identifiers, the
                           header a real app uses to tell the gateway what this user may see
GET  /v1/ai/models      -> a request with no user text (proxy pass-through tests)
"""

import json
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="Mock AI app")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "mock-ai"}


@app.post("/v1/ai/chat")
async def chat(request: Request) -> dict[str, Any]:
    body = await request.json()
    message = body.get("message", "") if isinstance(body, dict) else ""
    return {
        "reply": f"Mock assistant received {len(str(message))} characters.",
        # Echo what the gateway told us, so tests can see it end to end.
        "security": {
            "request_id": request.headers.get("x-security-request-id"),
            "decision": request.headers.get("x-security-decision"),
            "restricted": request.headers.get("x-security-restricted") == "true",
        },
        # Must always be False: the gateway never forwards its own credentials.
        "received_gateway_credentials": bool(
            request.headers.get("authorization") or request.headers.get("x-api-key")
        ),
    }


@app.post("/v1/ai/leak-test")
async def leak_test(request: Request) -> JSONResponse:
    body = await request.json()
    body = body if isinstance(body, dict) else {}
    headers = {}
    if isinstance(body.get("allowed_identifiers"), dict):
        headers["x-security-allowed-identifiers"] = json.dumps(body["allowed_identifiers"])
    return JSONResponse({"reply": str(body.get("reply", ""))}, headers=headers)


@app.get("/v1/ai/models")
def models() -> dict[str, list[str]]:
    return {"models": ["mock-model-1"]}
