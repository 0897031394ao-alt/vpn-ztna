from fastapi import APIRouter, HTTPException

from app.services.wg_client import wg_agent_client, WgAgentError

router = APIRouter(prefix="/debug/wg", tags=["debug-wg"])


@router.get("/peers")
async def debug_list_peers():
    """Вернуть список peer'ов из wg-agent."""
    try:
        peers = await wg_agent_client.list_peers()
        return peers
    except WgAgentError as e:
        raise HTTPException(status_code=502, detail=str(e))
