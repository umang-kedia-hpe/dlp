import os
import threading
import time
import logging
from fastapi import FastAPI, Request, Response
import httpx
from contextlib import asynccontextmanager

# Import shared DLP logic
from utilkit import load_patterns, inspect_data

POLICY_PATH = os.environ["DLP_POLICY_PATH"]
WATCH_INTERVAL = float(os.getenv("DLP_WATCH_INTERVAL", "10"))
UPSTREAM_PORT = os.environ["UPSTREAM_PORT"]
UPSTREAM_URL = f"http://localhost:{UPSTREAM_PORT}"


# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("dlp-ingress")

# Shared, thread-safe policy storage
DLP_PATTERNS = []
DLP_PATTERNS_LOCK = threading.Lock()

def watch_policies():
    last_mtime = None
    while True:
        try:
            mtime = os.path.getmtime(POLICY_PATH)
            if mtime != last_mtime:
                with DLP_PATTERNS_LOCK:
                    global DLP_PATTERNS
                    DLP_PATTERNS = load_patterns(POLICY_PATH)
                logger.info("DLP policies reloaded")
                last_mtime = mtime
        except Exception as e:
            logger.warning(f"Policy watch error: {e}")
        time.sleep(WATCH_INTERVAL)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load policies at startup
    with DLP_PATTERNS_LOCK:
        global DLP_PATTERNS
        try:
            DLP_PATTERNS = load_patterns(POLICY_PATH)
            logger.info("DLP policies loaded at startup")
        except Exception as e:
            logger.error(f"Failed to load DLP policies at startup: {e}")
            DLP_PATTERNS = []
    # Start watcher thread
    watcher = threading.Thread(target=watch_policies, daemon=True)
    watcher.start()
    yield

app = FastAPI(lifespan=lifespan)

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy(request: Request, path: str):
    body = await request.body()
    body_str = body.decode("utf-8", errors="ignore")
    with DLP_PATTERNS_LOCK:
        findings, masked_body = inspect_data(body_str, DLP_PATTERNS)
    if any(action == "block" for _, action in findings):
        logger.info(f"Blocked request: found {', '.join(label for label, _ in findings)}")
        return Response(
            content=f"Blocked by DLP: found {', '.join(label for label, _ in findings)}",
            status_code=403
        )
    url = f"{UPSTREAM_URL}/{path}"
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")}
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.request(
                method=request.method,
                url=url,
                headers=headers,
                content=masked_body.encode("utf-8")
            )
    except Exception as e:
        logger.error(f"Error forwarding request: {e}")
        return Response(content="Upstream error", status_code=502)
    with DLP_PATTERNS_LOCK:
        resp_findings, masked_resp = inspect_data(resp.text, DLP_PATTERNS)
    if any(action == "block" for _, action in resp_findings):
        logger.info(f"Blocked response: found {', '.join(label for label, _ in resp_findings)}")
        return Response(
            content=f"Response blocked by DLP: found {', '.join(label for label, _ in resp_findings)}",
            status_code=403
        )
    if any(action == "mask" for _, action in resp_findings):
        logger.info(f"Masked response: found {', '.join(label for label, action in resp_findings if action == 'mask')}")
    response_headers = {k: v for k, v in resp.headers.items() if k.lower() != "content-length"}
    return Response(
        content=masked_resp.encode("utf-8"),
        status_code=resp.status_code,
        headers=response_headers
    )