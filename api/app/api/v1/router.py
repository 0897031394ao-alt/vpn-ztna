from fastapi import APIRouter

from app.api.v1 import auth, peers, groups, resources, policies, tenants, debug, users
from app.api.v1 import access  # новый импорт

api_router = APIRouter()

api_router.include_router(auth.router)
api_router.include_router(peers.router)
api_router.include_router(groups.router)
api_router.include_router(resources.router)
api_router.include_router(policies.router)
api_router.include_router(tenants.router)
api_router.include_router(debug.router)
api_router.include_router(users.router)
api_router.include_router(access.router)  # новая строка
