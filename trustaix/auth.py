"""Bearer-token authentication and role checks for TrustAIX."""

import os
import secrets
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import yaml
from fastapi import HTTPException, Request, status


class Role(StrEnum):
    DEVELOPER = "developer"
    AUDITOR = "auditor"
    ADMIN = "admin"


@dataclass(frozen=True)
class Principal:
    key_id: str
    tenant_id: str
    role: Role


class AuthService:
    def __init__(self, enabled: bool, credentials: dict[str, Principal] | None = None) -> None:
        self.enabled = enabled
        self.credentials = credentials or {}
        if enabled and not self.credentials:
            raise ValueError("Authentication is enabled but no usable API keys were loaded.")

    @classmethod
    def from_environment(cls) -> "AuthService":
        enabled = os.getenv("TRUSTAIX_AUTH_ENABLED", "false").lower() in {"1", "true", "yes"}
        if not enabled:
            return cls(enabled=False)

        config_path = os.getenv("TRUSTAIX_AUTH_CONFIG")
        if not config_path:
            raise ValueError(
                "Set TRUSTAIX_AUTH_CONFIG to a private access configuration file when auth is enabled."
            )
        return cls(enabled=True, credentials=_load_credentials(config_path))

    def authenticate(self, token: str | None) -> Principal:
        if not self.enabled:
            return Principal(key_id="local-development", tenant_id="default", role=Role.ADMIN)
        if not token:
            raise _auth_error("A Bearer token or X-API-Key header is required.")

        for candidate, principal in self.credentials.items():
            if secrets.compare_digest(candidate, token):
                return principal
        raise _auth_error("The API key is invalid.")


def principal_from_request(request: Request) -> Principal:
    from trustaix.main import auth_service

    authorization = request.headers.get("Authorization", "")
    bearer = authorization[7:].strip() if authorization.lower().startswith("bearer ") else None
    return auth_service.authenticate(bearer or request.headers.get("X-API-Key"))


def require_roles(*allowed_roles: Role):
    def dependency(request: Request) -> Principal:
        principal = principal_from_request(request)
        if principal.role not in allowed_roles:
            allowed = ", ".join(role.value for role in allowed_roles)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"message": f"This endpoint requires one of: {allowed}."},
            )
        return principal

    return dependency


def _load_credentials(path: str | Path) -> dict[str, Principal]:
    with Path(path).open(encoding="utf-8") as stream:
        document = yaml.safe_load(stream) or {}
    entries = document.get("api_keys") if isinstance(document, dict) else None
    if not isinstance(entries, list):
        raise ValueError("Authentication configuration must contain an api_keys list.")

    credentials: dict[str, Principal] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Each api_keys item must be a mapping.")
        key_id = entry.get("id")
        tenant_id = entry.get("tenant_id")
        token_env = entry.get("token_env")
        try:
            role = Role(entry.get("role"))
        except (TypeError, ValueError) as error:
            raise ValueError("Each API key must use developer, auditor, or admin role.") from error
        if not all(isinstance(value, str) and value for value in (key_id, tenant_id, token_env)):
            raise ValueError("Each API key needs non-empty id, tenant_id, and token_env values.")
        token = os.getenv(token_env)
        if not token:
            continue
        if token in credentials:
            raise ValueError("Duplicate token values are not allowed.")
        credentials[token] = Principal(key_id=key_id, tenant_id=tenant_id, role=role)
    return credentials


def _auth_error(message: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"message": message},
        headers={"WWW-Authenticate": "Bearer"},
    )
