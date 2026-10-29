"""OAuth 2.1 resource server support for ``mcp-warden serve``.

People sign in with the organization's identity provider; their MCP client sends
the resulting JWT access token. mcp-warden checks its signature against the
issuer's published keys, its issuer, audience, expiry and scopes, and records the
user from a claim (``sub`` by default). Clients find the authorization server
through the Protected Resource Metadata document (RFC 9728) that ``serve``
publishes, as the MCP authorization spec requires.

Needs ``pip install 'mcp-warden[oauth]'``.
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.request
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

log = logging.getLogger("mcp_warden")

METADATA_PATH = "/.well-known/oauth-protected-resource"
ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "ES256", "ES384", "EdDSA")


class OAuthUnavailable(RuntimeError):
    pass


class InvalidToken(Exception):
    """The token is missing, malformed, expired, or not for this resource."""


class InsufficientScope(Exception):
    def __init__(self, required: list[str]):
        super().__init__("token lacks scope " + " ".join(required))
        self.required = required


@dataclass
class OAuthConfig:
    issuer: str
    audience: str  # this resource's URL, as the authorization server puts it in `aud`
    scopes: list[str] = field(default_factory=list)
    user_claim: str = "sub"
    jwks_uri: str | None = None

    def metadata_url(self) -> str:
        """Where RFC 9728 says clients look for this resource's metadata."""
        parts = urlsplit(self.audience)
        path = parts.path.rstrip("/")
        return f"{parts.scheme}://{parts.netloc}{METADATA_PATH}{path}"

    def metadata(self) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "resource": self.audience,
            "authorization_servers": [self.issuer],
            "bearer_methods_supported": ["header"],
        }
        if self.scopes:
            doc["scopes_supported"] = list(self.scopes)
        return doc


def discovery_urls(issuer: str) -> list[str]:
    """RFC 8414 and OpenID Connect discovery locations for an issuer."""
    parts = urlsplit(issuer)
    base, path = f"{parts.scheme}://{parts.netloc}", parts.path.rstrip("/")
    return [
        f"{base}/.well-known/oauth-authorization-server{path}",
        f"{base}/.well-known/openid-configuration{path}",
        f"{issuer.rstrip('/')}/.well-known/openid-configuration",
    ]


def _fetch_json(url: str, timeout: float = 10.0) -> Any:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


class OAuthValidator:
    def __init__(self, config: OAuthConfig):
        try:
            import jwt
        except ImportError as exc:
            raise OAuthUnavailable(
                "OAuth needs PyJWT; run: pip install 'mcp-warden[oauth]'"
            ) from exc
        self.config = config
        self._jwt = jwt
        self._jwks: Any = None
        self._lock = threading.Lock()

    def _jwks_client(self) -> Any:
        with self._lock:
            if self._jwks is None:
                uri = self.config.jwks_uri or self._discover_jwks_uri()
                self._jwks = self._jwt.PyJWKClient(uri, cache_keys=True, lifespan=3600)
            return self._jwks

    def _discover_jwks_uri(self) -> str:
        for url in dict.fromkeys(discovery_urls(self.config.issuer)):
            try:
                doc = _fetch_json(url)
            except (OSError, ValueError) as exc:
                log.debug("discovery at %s failed: %s", url, exc)
                continue
            if isinstance(doc, dict) and isinstance(doc.get("jwks_uri"), str):
                return str(doc["jwks_uri"])
        raise InvalidToken(f"cannot discover the signing keys of {self.config.issuer}")

    def validate(self, token: str) -> str:
        """Return the user a valid access token belongs to."""
        jwt = self._jwt
        try:
            key = self._jwks_client().get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token,
                key,
                algorithms=list(ALGORITHMS),
                audience=self.config.audience,
                issuer=self.config.issuer,
                options={"require": ["exp", "iss", "aud"]},
                leeway=30,
            )
        except (jwt.PyJWTError, jwt.PyJWKClientError, ValueError) as exc:
            raise InvalidToken(str(exc)) from exc
        granted = claims.get("scope", claims.get("scp", ""))
        granted = set(granted.split() if isinstance(granted, str) else granted or [])
        missing = [s for s in self.config.scopes if s not in granted]
        if missing:
            raise InsufficientScope(self.config.scopes)
        user = claims.get(self.config.user_claim)
        if not isinstance(user, str) or not user:
            raise InvalidToken(f"token has no '{self.config.user_claim}' claim")
        return user
