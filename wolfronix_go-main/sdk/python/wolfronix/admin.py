"""
WolfronixAdmin — Enterprise Client Management.
Uses X-Admin-Key authentication (not user auth).

Mirrors the TypeScript ``WolfronixAdmin`` class.

Example::

    from wolfronix import WolfronixAdmin, WolfronixAdminConfig

    admin = WolfronixAdmin(WolfronixAdminConfig(
        base_url="https://wolfronix-server:9443",
        admin_key="your-admin-api-key",
        insecure=True,
    ))

    # Register a client with managed Supabase connector
    result = await admin.register_client({
        "client_id": "acme_corp",
        "client_name": "Acme Corporation",
        "db_type": "supabase",
        "db_config": '{"supabase_url": "https://xxx.supabase.co", "supabase_service_key": "eyJ..."}',
    })
    print("Wolfronix key:", result.wolfronix_key)
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional, Union
from urllib.parse import quote

import httpx

from .errors import WolfronixError
from .types import (
    DeactivateClientResponse,
    EnterpriseClient,
    ListClientsResponse,
    RegisterClientRequest,
    RegisterClientResponse,
    UpdateClientRequest,
    UpdateClientResponse,
    WolfronixAdminConfig,
)


class WolfronixAdmin:
    """
    Admin client for managing enterprise clients.

    Uses ``X-Admin-Key`` header authentication.
    """

    def __init__(self, config: WolfronixAdminConfig):
        self._base_url = config.base_url.rstrip("/")
        self._admin_key = config.admin_key
        self._timeout = config.timeout / 1000.0  # Convert ms → seconds
        self._insecure = config.insecure

    async def _request(
        self,
        method: str,
        endpoint: str,
        body: Optional[Any] = None,
    ) -> Any:
        url = f"{self._base_url}{endpoint}"
        headers: Dict[str, str] = {
            "X-Admin-Key": self._admin_key,
            "Accept": "application/json",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"

        async with httpx.AsyncClient(
            verify=not self._insecure,
            timeout=httpx.Timeout(self._timeout),
        ) as client:
            resp = await client.request(
                method,
                url,
                headers=headers,
                content=json.dumps(body) if body else None,
            )

        if not resp.is_success:
            error_body: Dict[str, Any] = {}
            try:
                error_body = resp.json()
            except Exception:
                pass
            raise WolfronixError(
                error_body.get("error", f"Request failed with status {resp.status_code}"),
                "ADMIN_REQUEST_ERROR",
                resp.status_code,
                error_body,
            )

        return resp.json()

    async def register_client(
        self, params: Union[RegisterClientRequest, Dict[str, Any]]
    ) -> RegisterClientResponse:
        """
        Register a new enterprise client.

        For managed connectors (supabase, mongodb, mysql, firebase, postgresql),
        provide ``db_type`` + ``db_config``.
        For custom APIs, use ``db_type="custom_api"`` + ``api_endpoint``.
        """
        if isinstance(params, RegisterClientRequest):
            body = {
                "client_id": params.client_id,
                "client_name": params.client_name,
                "db_type": params.db_type,
            }
            if params.db_config:
                body["db_config"] = params.db_config
            if params.api_endpoint:
                body["api_endpoint"] = params.api_endpoint
            if params.api_key:
                body["api_key"] = params.api_key
        else:
            body = params

        resp = await self._request("POST", "/api/v1/enterprise/register", body)
        return RegisterClientResponse(
            status=resp.get("status", ""),
            client_id=resp.get("client_id", ""),
            wolfronix_key=resp.get("wolfronix_key", ""),
            db_type=resp.get("db_type", ""),
            message=resp.get("message", ""),
            connector=resp.get("connector"),
            api_endpoint=resp.get("api_endpoint"),
        )

    async def list_clients(self) -> ListClientsResponse:
        """List all registered enterprise clients."""
        resp = await self._request("GET", "/api/v1/enterprise/clients")
        raw_clients = resp.get("clients") or []
        clients = [
            EnterpriseClient(
                id=c.get("id", 0),
                client_id=c.get("client_id", ""),
                client_name=c.get("client_name", ""),
                api_endpoint=c.get("api_endpoint", ""),
                api_key=c.get("api_key", ""),
                wolfronix_key=c.get("wolfronix_key", ""),
                db_type=c.get("db_type", ""),
                db_config=c.get("db_config", ""),
                user_count=c.get("user_count", 0),
                is_active=c.get("is_active", True),
                created_at=c.get("created_at", ""),
                updated_at=c.get("updated_at", ""),
            )
            for c in raw_clients
        ]
        return ListClientsResponse(clients=clients, count=resp.get("count", len(clients)))

    async def get_client(self, client_id: str) -> EnterpriseClient:
        """Get details for a specific client."""
        resp = await self._request(
            "GET", f"/api/v1/enterprise/clients/{quote(client_id, safe='')}"
        )
        return EnterpriseClient(
            id=resp.get("id", 0),
            client_id=resp.get("client_id", ""),
            client_name=resp.get("client_name", ""),
            api_endpoint=resp.get("api_endpoint", ""),
            api_key=resp.get("api_key", ""),
            wolfronix_key=resp.get("wolfronix_key", ""),
            db_type=resp.get("db_type", ""),
            db_config=resp.get("db_config", ""),
            user_count=resp.get("user_count", 0),
            is_active=resp.get("is_active", True),
            created_at=resp.get("created_at", ""),
            updated_at=resp.get("updated_at", ""),
        )

    async def update_client(
        self, client_id: str, params: Union[UpdateClientRequest, Dict[str, Any]]
    ) -> UpdateClientResponse:
        """Update a client's configuration."""
        if isinstance(params, UpdateClientRequest):
            body: Dict[str, Any] = {}
            if params.api_endpoint is not None:
                body["api_endpoint"] = params.api_endpoint
            if params.db_type is not None:
                body["db_type"] = params.db_type
            if params.db_config is not None:
                body["db_config"] = params.db_config
        else:
            body = params

        resp = await self._request(
            "PUT", f"/api/v1/enterprise/clients/{quote(client_id, safe='')}", body
        )
        return UpdateClientResponse(
            status=resp.get("status", ""),
            message=resp.get("message", ""),
        )

    async def deactivate_client(self, client_id: str) -> DeactivateClientResponse:
        """Deactivate (soft-delete) a client. Their wolfronix_key will stop working."""
        resp = await self._request(
            "DELETE", f"/api/v1/enterprise/clients/{quote(client_id, safe='')}"
        )
        return DeactivateClientResponse(
            status=resp.get("status", ""),
            message=resp.get("message", ""),
        )

    async def health_check(self) -> bool:
        """Check server health."""
        try:
            await self._request("GET", "/health")
            return True
        except Exception:
            return False
