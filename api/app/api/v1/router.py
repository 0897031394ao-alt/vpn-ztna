from fastapi import APIRouter

from app.api.v1 import auth, peers, groups, resources, policies, tenants, debug

api_router = APIRouter()

api_router.include_router(auth.router)
api_router.include_router(peers.router)
api_router.include_router(groups.router)
api_router.include_router(resources.router)
api_router.include_router(policies.router)
api_router.include_router(tenants.router)
api_router.include_router(debug.router)
