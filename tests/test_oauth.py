"""OAuth 2.1 resource server mode of mcp-warden serve."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from test_serve import INIT, call, make_server, raw, rpc  # noqa: F401

from mcp_warden.http_transport import StreamableHTTP
from mcp_warden.oauth import (
    InsufficientScope,
    InvalidToken,
    OAuthConfig,
    OAuthValidator,
    discovery_urls,
)
from mcp_warden.policy import PolicyError
from mcp_warden.servers import ClientSpec, load_oauth, token_digest

AUDIENCE = "https://warden.example.com/mcp"


class FakeIdP(ThreadingHTTPServer):
    """Publishes OpenID discovery and a JWKS, and signs tokens with its key."""

    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _IdPHandler)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        self.jwks = {"keys": [{**jwk, "kid": "k1", "use": "sig", "alg": "RS256"}]}
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def issuer(self):
        return f"http://127.0.0.1:{self.server_address[1]}/realms/acme"

    def token(self, key=None, **overrides):
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "aud": AUDIENCE,
            "sub": "u-123",
            "email": "alice@example.com",
            "scope": "openid mcp",
            "iat": now,
            "exp": now + 300,
            **overrides,
        }
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, key or self.key, algorithm="RS256", headers={"kid": "k1"})


class _IdPHandler(BaseHTTPRequestHandler):
    server: FakeIdP

    def log_message(self, *args):
        pass

    def do_GET(self):
        base = f"http://127.0.0.1:{self.server.server_address[1]}"
        if self.path == "/.well-known/openid-configuration/realms/acme":
            body = {"issuer": self.server.issuer, "jwks_uri": f"{base}/certs"}
        elif self.path == "/certs":
            body = self.server.jwks
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def idp():
    server = FakeIdP()
    yield server
    server.shutdown()


def config(idp, **kwargs):
    return OAuthConfig(issuer=idp.issuer, audience=AUDIENCE, **kwargs)


def test_validator_accepts_and_rejects(idp):
    validator = OAuthValidator(config(idp, scopes=["mcp"], user_claim="email"))
    assert validator.validate(idp.token()) == "alice@example.com"
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bad = [
        idp.token(aud="https://other.example.com/mcp"),
        idp.token(iss="https://evil.example.com"),
        idp.token(exp=int(time.time()) - 120),
        idp.token(exp=None),
        idp.token(key=other_key),
        idp.token(email=None),
        "not-a-jwt",
    ]
    for token in bad:
        with pytest.raises(InvalidToken):
            validator.validate(token)
    with pytest.raises(InsufficientScope):
        validator.validate(idp.token(scope="openid"))
    # Azure AD style list of scopes in `scp`.
    assert validator.validate(idp.token(scope=None, scp=["mcp"])) == "alice@example.com"


def test_discovery_urls():
    assert discovery_urls("https://idp.example.com/realms/acme") == [
        "https://idp.example.com/.well-known/oauth-authorization-server/realms/acme",
        "https://idp.example.com/.well-known/openid-configuration/realms/acme",
        "https://idp.example.com/realms/acme/.well-known/openid-configuration",
    ]


def test_serve_with_oauth(idp, make_server, tmp_path):  # noqa: F811
    validator = OAuthValidator(config(idp, scopes=["mcp"], user_claim="email"))
    server = make_server(oauth=validator, clients=[ClientSpec("ci", token_digest("ci-token"))])
    metadata_url = "https://warden.example.com/.well-known/oauth-protected-resource/mcp"

    status, headers, _ = raw(server.url, body=INIT)
    assert status == 401
    assert headers["WWW-Authenticate"] == f'Bearer resource_metadata="{metadata_url}"'

    base = server.url.rsplit("/", 1)[0]
    status, _, doc = raw(base + "/.well-known/oauth-protected-resource/mcp", method="GET")
    assert status == 200
    assert doc == {
        "resource": AUDIENCE,
        "authorization_servers": [idp.issuer],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp"],
    }

    expired = {"Authorization": f"Bearer {idp.token(exp=int(time.time()) - 120)}"}
    status, headers, _ = raw(server.url, body=INIT, headers=expired)
    assert status == 401 and 'error="invalid_token"' in headers["WWW-Authenticate"]
    no_scope = {"Authorization": f"Bearer {idp.token(scope='openid')}"}
    status, headers, _ = raw(server.url, body=INIT, headers=no_scope)
    assert (
        status == 403 and 'error="insufficient_scope", scope="mcp"' in headers["WWW-Authenticate"]
    )

    alice = StreamableHTTP(server.url, {"Authorization": f"Bearer {idp.token()}"})
    rpc(alice, INIT)
    rpc(alice, call(1, "local__read_file", path="a.txt"))
    # A fresh token for the same user keeps the session; another user cannot use it.
    alice.headers["Authorization"] = f"Bearer {idp.token()}"
    assert rpc(alice, {"jsonrpc": "2.0", "id": 2, "method": "ping"})["result"] == {}
    bob = {
        "Authorization": f"Bearer {idp.token(email='bob@example.com')}",
        "Mcp-Session-Id": alice.session_id,
    }
    assert (
        raw(server.url, body={"jsonrpc": "2.0", "id": 3, "method": "ping"}, headers=bob)[0] == 404
    )

    # Static client tokens still work next to OAuth.
    ci = StreamableHTTP(server.url, {"Authorization": "Bearer ci-token"})
    assert rpc(ci, INIT)["result"]["serverInfo"]["name"] == "mcp-warden"

    records = [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text().splitlines()]
    calls = [r for r in records if r["event"] == "tool_call"]
    assert [r["user"] for r in calls] == ["alice@example.com"]


def test_load_oauth(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_URL", "https://warden.example.com/mcp")
    cfg = tmp_path / "servers.yaml"
    cfg.write_text(
        "servers: {a: {command: x}}\n"
        "oauth:\n"
        "  issuer: https://login.example.com/realms/acme\n"
        "  audience: ${WARDEN_URL}\n"
        "  scopes: [mcp]\n"
        "  user_claim: email\n"
    )
    oauth = load_oauth(cfg)
    assert oauth.audience == "https://warden.example.com/mcp"
    assert oauth.scopes == ["mcp"] and oauth.user_claim == "email" and oauth.jwks_uri is None
    cfg.write_text("servers: {a: {command: x}}\n")
    assert load_oauth(cfg) is None


@pytest.mark.parametrize(
    "body, error",
    [
        ("oauth: {audience: 'https://w/mcp'}\n", "issuer is required"),
        ("oauth: {issuer: 'http://idp.example.com', audience: 'https://w/mcp'}\n", "https"),
        ("oauth: {issuer: 'https://i', audience: 'https://w', scopes: mcp}\n", "list"),
    ],
)
def test_load_oauth_rejects_bad_config(tmp_path, body, error):
    cfg = tmp_path / "servers.yaml"
    cfg.write_text("servers: {a: {command: x}}\n" + body)
    with pytest.raises(PolicyError, match=error):
        load_oauth(cfg)
