import os
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.responses import Response
from prometheus_client import generate_latest, REGISTRY
import secrets

router = APIRouter(tags=["metrics"])

METRICS_USERNAME = "admin"
METRICS_PASSWORD = os.getenv("METRICS_PASSWORD", "metrics2026")

security = HTTPBasic()

def verify_metrics(credentials: HTTPBasicCredentials = Depends(security)):
    if not (secrets.compare_digest(credentials.username, METRICS_USERNAME) and
            secrets.compare_digest(credentials.password, METRICS_PASSWORD)):
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Basic"})
    return True

@router.get("/metrics", dependencies=[Depends(verify_metrics)])
async def get_metrics():
    return Response(generate_latest(REGISTRY), media_type="text/plain")
