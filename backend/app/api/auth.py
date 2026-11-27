"""Optional Dashboard Passcode Lock & Multi-User RBAC REST endpoints."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from app.api.deps import AppServices, get_services


router = APIRouter(prefix="/api/auth", tags=["auth"])


class PasscodeRequest(BaseModel):
    passcode: str = Field(..., min_length=6, max_length=128)


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=40)
    password: str = Field(..., min_length=6, max_length=128)
    role: Literal["viewer", "analyst", "admin"] = "viewer"


class UserLoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=40)
    password: str = Field(..., min_length=6, max_length=128)


@router.get("/status")
async def auth_status(
    x_netsentinel_token: str | None = Header(default=None),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    actor = services.auth_manager.get_actor(x_netsentinel_token)
    return {
        "lock_enabled": services.auth_manager.enabled,
        "authenticated": actor is not None,
        "actor": actor,
    }


@router.post("/setup")
async def setup_passcode(
    payload: PasscodeRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    if services.auth_manager.enabled:
        raise HTTPException(status_code=409, detail="Passcode lock is already enabled")
    try:
        res = await services.auth_manager.enable_passcode(payload.passcode)
        await services.db.append_audit_log(
            actor="owner", role="admin", action="enable_passcode_lock"
        )
        return res
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/login")
async def login(
    payload: PasscodeRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    token = services.auth_manager.login(payload.passcode)
    if token is None:
        raise HTTPException(status_code=401, detail="Invalid passcode")
    await services.db.append_audit_log(actor="owner", role="admin", action="login_passcode")
    return {"authenticated": True, "token": token, "role": "admin"}


@router.post("/user-login")
async def user_login(
    payload: UserLoginRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    res = await services.auth_manager.login_user(payload.username, payload.password)
    if res is None:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    await services.db.append_audit_log(
        actor=res["username"], role=res["role"], action="user_login"
    )
    return {"authenticated": True, **res}


@router.post("/logout")
async def logout(
    x_netsentinel_token: str | None = Header(default=None),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    services.auth_manager.logout(x_netsentinel_token)
    return {"authenticated": False}


@router.post("/disable")
async def disable_passcode(
    payload: PasscodeRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    try:
        res = await services.auth_manager.disable_passcode(payload.passcode)
        await services.db.append_audit_log(
            actor="owner", role="admin", action="disable_passcode_lock"
        )
        return res
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@router.get("/users")
async def list_users(
    x_netsentinel_token: str | None = Header(default=None),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    if not services.auth_manager.has_min_role(x_netsentinel_token, "admin"):
        raise HTTPException(status_code=403, detail="Admin role required")
    return {"users": await services.db.list_users()}


@router.post("/users")
async def create_user(
    payload: CreateUserRequest,
    x_netsentinel_token: str | None = Header(default=None),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    if not services.auth_manager.has_min_role(x_netsentinel_token, "admin"):
        raise HTTPException(status_code=403, detail="Admin role required")
    actor = services.auth_manager.get_actor(x_netsentinel_token) or {"username": "admin", "role": "admin"}
    try:
        user = await services.auth_manager.create_user(
            payload.username, payload.password, payload.role
        )
    except Exception as exc:
        if "UNIQUE" in str(exc).upper():
            raise HTTPException(status_code=409, detail="Username already exists") from exc
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await services.db.append_audit_log(
        actor=actor["username"],
        role=actor["role"],
        action="create_user",
        target=user["username"],
        detail=f"role={user['role']}",
    )
    return user


@router.delete("/users/{username}")
async def delete_user(
    username: str,
    confirm: bool = False,
    x_netsentinel_token: str | None = Header(default=None),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    if not services.auth_manager.has_min_role(x_netsentinel_token, "admin"):
        raise HTTPException(status_code=403, detail="Admin role required")
    if not confirm:
        raise HTTPException(status_code=400, detail="Confirmation required (confirm=true)")
    actor = services.auth_manager.get_actor(x_netsentinel_token) or {"username": "admin", "role": "admin"}
    deleted = await services.db.delete_user(username.strip().lower())
    if not deleted:
        raise HTTPException(status_code=404, detail="User not found")
    await services.db.append_audit_log(
        actor=actor["username"], role=actor["role"], action="delete_user", target=username
    )
    return {"deleted": True, "username": username}
