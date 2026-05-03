#!/usr/bin/env python3
"""Defense-related API routes (lockdown, mitigation mode, blocked IPs)."""
from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List
from datetime import datetime
import logging

from zenith.api.routes import _shared

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/status", summary="Get current defense posture")
async def get_defense_status() -> Dict[str, Any]:
    """Return current defense state (lockdown, mitigation mode, blocked IPs)."""
    return {
        "lockdown_active": _shared.defense_state["lockdown_active"],
        "lockdown_activated_at": _shared.defense_state["lockdown_activated_at"],
        "mitigation_mode": _shared.defense_state["mitigation_mode"],
        "blocked_ips": _shared.defense_state["blocked_ips"],
        "blocked_processes": _shared.defense_state["blocked_processes"],
    }

@router.post("/lockdown", summary="Activate system lockdown")
async def activate_lockdown() -> Dict[str, Any]:
    """
    Activate emergency system lockdown. In production this would invoke
    iptables rules / kill suspicious PIDs. Here we record the state and
    return success so the UI can confirm the action.
    """
    if _shared.defense_state["lockdown_active"]:
        return {
            "status": "already_active",
            "activated_at": _shared.defense_state["lockdown_activated_at"],
        }

    _shared.defense_state["lockdown_active"] = True
    _shared.defense_state["lockdown_activated_at"] = datetime.utcnow().isoformat()
    logger.warning("SYSTEM LOCKDOWN ACTIVATED via API")
    return {
        "status": "activated",
        "activated_at": _shared.defense_state["lockdown_activated_at"],
        "message": "Lockdown protocol active. All suspicious traffic will be blocked.",
    }

@router.post("/lockdown/release", summary="Release system lockdown")
async def release_lockdown() -> Dict[str, Any]:
    """Release an active lockdown."""
    if not _shared.defense_state["lockdown_active"]:
        return {"status": "not_active"}
    _shared.defense_state["lockdown_active"] = False
    _shared.defense_state["lockdown_activated_at"] = None
    logger.info("System lockdown released via API")
    return {"status": "released"}

@router.post("/mitigation/{mode}", summary="Set mitigation mode")
async def set_mitigation_mode(mode: str) -> Dict[str, Any]:
    """Set mitigation mode: monitor | block | kill."""
    mode = mode.lower().strip()
    if mode not in {"monitor", "block", "kill"}:
        raise HTTPException(status_code=400, detail="Invalid mode. Use monitor|block|kill.")
    _shared.defense_state["mitigation_mode"] = mode
    return {"status": "ok", "mode": mode}

@router.post("/block-ip/{ip}", summary="Add IP to blocklist")
async def block_ip(ip: str) -> Dict[str, Any]:
    """Block an IP address (record only; actual iptables rule requires root)."""
    if ip not in _shared.defense_state["blocked_ips"]:
        _shared.defense_state["blocked_ips"].append(ip)
    return {"status": "ok", "blocked_ips": _shared.defense_state["blocked_ips"]}

@router.delete("/block-ip/{ip}", summary="Remove IP from blocklist")
async def unblock_ip(ip: str) -> Dict[str, Any]:
    """Remove an IP from the blocklist."""
    if ip in _shared.defense_state["blocked_ips"]:
        _shared.defense_state["blocked_ips"].remove(ip)
    return {"status": "ok", "blocked_ips": _shared.defense_state["blocked_ips"]}
