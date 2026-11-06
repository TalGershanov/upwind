# Run: gunicorn -k uvicorn.workers.UvicornWorker -w 2 -b 0.0.0.0:8000 --access-logfile - api.main:app
import asyncio
import logging
import socket
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse

from dal.db_config import create_history_store
from logic.email_parser import EmailParseError, parse_email
from logging_config import setup_logging
from logic.indicators import analyze as analyze_email

logger = logging.getLogger(__name__)
MAX_BYTES = 5 * 1024 * 1024
IMDS = 'http://169.254.169.254/latest'


def _instance_id() -> str:
    """EC2 instance id via IMDSv2; hostname if unavailable."""
    try:
        with httpx.Client(timeout=1.0) as c:
            r = c.put(f'{IMDS}/api/token', headers={
                'X-aws-ec2-metadata-token-ttl-seconds': '60'})
            r.raise_for_status()
            r = c.get(f'{IMDS}/meta-data/instance-id',
                      headers={'X-aws-ec2-metadata-token': r.text})
            r.raise_for_status()
            return r.text
    except Exception:
        return socket.gethostname()


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    if not hasattr(app.state, 'store'):
        app.state.store = create_history_store()
    if not hasattr(app.state, 'instance_id'):
        app.state.instance_id = await run_in_threadpool(_instance_id)
    yield


app = FastAPI(lifespan=lifespan)


@app.middleware('http')
async def add_instance_id(request, call_next):
    response = await call_next(request)
    response.headers['X-Instance-Id'] = request.app.state.instance_id
    return response


@app.get('/')
async def index():
    return FileResponse(Path(__file__).parent / 'static/index.html')


@app.post('/api/analyze')
async def analyze(file: UploadFile):
    data = await file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise HTTPException(413, 'File too large (max 5 MB)')
    if not data:
        raise HTTPException(400, 'Empty file')
    store = app.state.store
    try:
        return await run_in_threadpool(
            lambda: analyze_email(parse_email(data), store))
    except EmailParseError:
        raise HTTPException(400, 'Could not parse email') from None


@app.get('/health')
async def health():
    return {'status': 'ok'}


@app.get('/health/deep')
async def health_deep():
    try:
        await asyncio.wait_for(run_in_threadpool(app.state.store.ping), 3)
    except Exception:
        logger.exception('Deep health check failed')
        return JSONResponse({'db': 'error'}, status_code=503)
    return {'db': 'ok'}
