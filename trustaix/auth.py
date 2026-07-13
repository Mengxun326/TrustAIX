"""Bearer-token authentication and role checks for TrustAIX."""

import os
import secrets
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import yaml
import httpx
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
    def __init__(
        self,
        enabled: bool,
        credentials: dict[str, Principal] | None = None,
        introspection_url: str | None = None,
        introspection_client_id: str | None = None,
        introspection_client_secret: str | None = None,
    ) -> None:
        self.enabled = enabled
        self.credentials = {_token_digest(token): principal for token, principal in (credentials or {}).items()}
        self.introspection_url = introspection_url
        self.introspection_client_id = introspection_client_id
        self.introspection_client_secret = introspection_client_secret
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
        return cls(
            enabled=True,
            credentials=_load_credentials(config_path),
            introspection_url=os.getenv("TRUSTAIX_OIDC_INTROSPECTION_URL"),
            introspection_client_id=os.getenv("TRUSTAIX_OIDC_CLIENT_ID"),
            introspection_client_secret=os.getenv("TRUSTAIX_OIDC_CLIENT_SECRET"),
        )

    def authenticate(self, token: str | None) -> Principal:
        if not self.enabled:
            return Principal(key_id="local-development", tenant_id="default", role=Role.ADMIN)
        if not token:
            raise _auth_error("A Bearer token or X-API-Key header is required.")

        digest = _token_digest(token)
        for candidate, principal in self.credentials.items():
            if secrets.compare_digest(candidate, digest):
                return principal
        if self.introspection_url:
            return self._introspect(token)
        raise _auth_error("The API key is invalid.")

    def _introspect(self, token: str) -> Principal:
        try:
            response = httpx.post(
                self.introspection_url,
                data={"token": token},
                auth=(self.introspection_client_id or "", self.introspection_client_secret or ""),
                timeout=4.0,
            )
            response.raise_for_status()
            claims = response.json()
        except httpx.HTTPError as error:
            raise _auth_error("The OIDC identity provider could not validate the token.") from error
        if not isinstance(claims, dict) or not claims.get("active"):
            raise _auth_error("The OIDC token is inactive.")
        try:
            role = Role(claims.get("trustaix_role", claims.get("role")))
        except ValueError as error:
            raise _auth_error("OIDC token lacks a valid TrustAIX role claim.") from error
        subject = claims.get("sub")
        tenant = claims.get("trustaix_tenant", claims.get("tenant_id"))
        if not isinstance(subject, str) or not isinstance(tenant, str):
            raise _auth_error("OIDC token lacks subject or tenant claims.")
        return Principal(key_id=subject, tenant_id=tenant, role=role)


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
        token_envs = entry.get("token_envs", [])
        try:
            role = Role(entry.get("role"))
        except (TypeError, ValueError) as error:
            raise ValueError("Each API key must use developer, auditor, or admin role.") from error
        env_names = [token_env] if isinstance(token_env, str) and token_env else token_envs
        if not all(isinstance(value, str) and value for value in (key_id, tenant_id)) or not env_names:
            raise ValueError("Each API key needs id, tenant_id, and token_env or token_envs values.")
        if not isinstance(env_names, list) or not all(isinstance(name, str) and name for name in env_names):
            raise ValueError("token_envs must be a non-empty list of environment-variable names.")
        for env_name in env_names:
            token = os.getenv(env_name)
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


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
