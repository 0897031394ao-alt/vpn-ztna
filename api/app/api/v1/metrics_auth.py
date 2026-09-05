from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets

security = HTTPBasic()

# Настройте логин и пароль (можно вынести в переменные окружения)
METRICS_USERNAME = "admin"
METRICS_PASSWORD = "metrics2026"

def verify_metrics_access(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username, METRICS_USERNAME)
    correct_password = secrets.compare_digest(credentials.password, METRICS_PASSWORD)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return True
