"""API module"""

from api.client import CheckMKClient
from api.exceptions import (
    CheckMKAPIError,
    CheckMKAuthenticationError,
    CheckMKConnectionError,
    CheckMKError,
    CheckMKNotFoundError,
    CheckMKPermissionError,
    CheckMKValidationError,
)
from api.legacy_client import LegacyCheckMKClient


def create_client(config) -> CheckMKClient:
    """Factory: returns LegacyCheckMKClient for 1.6.x, CheckMKClient otherwise."""
    client = CheckMKClient(config)
    if client.is_legacy and client._legacy_webapi_url:
        return LegacyCheckMKClient(config, client._legacy_webapi_url)
    return client


__all__ = [
    "CheckMKClient",
    "LegacyCheckMKClient",
    "create_client",
    "CheckMKError",
    "CheckMKConnectionError",
    "CheckMKAuthenticationError",
    "CheckMKPermissionError",
    "CheckMKValidationError",
    "CheckMKNotFoundError",
    "CheckMKAPIError",
]
