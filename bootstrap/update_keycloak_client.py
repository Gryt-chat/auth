#!/usr/bin/env python3
import json
import os
import time
import urllib.parse
import urllib.request


def env(name: str, default: str | None = None) -> str:
    v = os.getenv(name)
    if v is None or v.strip() == "":
        if default is None:
            raise RuntimeError(f"Missing required env var: {name}")
        return default
    return v.strip()


def split_csv(value: str) -> list[str]:
    parts = [p.strip() for p in value.split(",")]
    return [p for p in parts if p]


def http_request(method: str, url: str, headers: dict[str, str] | None = None, body: bytes | None = None) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def wait_for_keycloak(base_url: str, realm: str, timeout_s: int = 120) -> None:
    started = time.time()
    url = f"{base_url}/realms/{realm}/.well-known/openid-configuration"
    while True:
        status, _ = http_request("GET", url)
        if status == 200:
            return
        if time.time() - started > timeout_s:
            raise RuntimeError(f"Keycloak not ready after {timeout_s}s (last status {status})")
        time.sleep(3)


def get_admin_token(base_url: str, username: str, password: str) -> str:
    token_url = f"{base_url}/realms/master/protocol/openid-connect/token"
    data = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": username,
            "password": password,
        }
    ).encode("utf-8")
    status, body = http_request(
        "POST",
        token_url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=data,
    )
    if status != 200:
        raise RuntimeError(f"Failed to get admin token (HTTP {status}): {body.decode('utf-8', errors='replace')}")
    payload = json.loads(body.decode("utf-8"))
    return payload["access_token"]


def kc_get_json(base_url: str, path: str, token: str) -> object:
    status, body = http_request(
        "GET",
        f"{base_url}{path}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    if status != 200:
        raise RuntimeError(f"GET {path} failed (HTTP {status}): {body.decode('utf-8', errors='replace')}")
    return json.loads(body.decode("utf-8"))


def kc_put_json(base_url: str, path: str, token: str, payload: object) -> None:
    body = json.dumps(payload).encode("utf-8")
    status, resp = http_request(
        "PUT",
        f"{base_url}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        body=body,
    )
    if status not in (200, 204):
        raise RuntimeError(f"PUT {path} failed (HTTP {status}): {resp.decode('utf-8', errors='replace')}")


def ensure_contains(existing: list[str] | None, desired: list[str]) -> tuple[list[str], bool]:
    out = list(existing or [])
    changed = False
    for v in desired:
        if v not in out:
            out.append(v)
            changed = True
    return out, changed


def main() -> None:
    base_url = env("KEYCLOAK_BASE_URL", "http://keycloak:8080")
    realm = env("KEYCLOAK_REALM", "gryt")
    client_id = env("KEYCLOAK_CLIENT_ID", "gryt-web")
    admin_user = env("KEYCLOAK_ADMIN_USERNAME", "admin")
    admin_pass = env("KEYCLOAK_ADMIN_PASSWORD", "admin")

    desired_redirects = split_csv(
        env(
            "KEYCLOAK_VALID_REDIRECT_URIS",
            "https://gryt.chat/*,https://app.gryt.chat/*,https://beta.gryt.chat/*,https://gryt.example.com/*,http://localhost:3666/*,http://localhost:3667/*,http://127.0.0.1:15738/*,gryt://auth/callback",
        )
    )
    desired_origins = split_csv(
        env(
            "KEYCLOAK_WEB_ORIGINS",
            "https://gryt.chat,https://app.gryt.chat,https://beta.gryt.chat,https://gryt.example.com,http://localhost:3666,http://localhost:3667,http://127.0.0.1:15738",
        )
    )

    print(f"[bootstrap] waiting for keycloak: {base_url} realm={realm}")
    wait_for_keycloak(base_url, realm)

    print("[bootstrap] getting admin token")
    token = get_admin_token(base_url, admin_user, admin_pass)

    print(f"[bootstrap] locating client {client_id}")
    clients = kc_get_json(base_url, f"/admin/realms/{realm}/clients?clientId={urllib.parse.quote(client_id)}", token)
    if not isinstance(clients, list) or len(clients) == 0:
        raise RuntimeError(f"Client not found: {client_id}")
    client_uuid = clients[0]["id"]

    client = kc_get_json(base_url, f"/admin/realms/{realm}/clients/{client_uuid}", token)
    if not isinstance(client, dict):
        raise RuntimeError("Unexpected client representation")

    redirects, redirects_changed = ensure_contains(client.get("redirectUris"), desired_redirects)
    origins, origins_changed = ensure_contains(client.get("webOrigins"), desired_origins)

    if redirects_changed:
        client["redirectUris"] = redirects
    if origins_changed:
        client["webOrigins"] = origins

    if redirects_changed or origins_changed:
        print("[bootstrap] updating client with missing redirectUris/webOrigins")
        kc_put_json(base_url, f"/admin/realms/{realm}/clients/{client_uuid}", token, client)
        print("[bootstrap] updated successfully")
    else:
        print("[bootstrap] already up-to-date; no changes needed")


if __name__ == "__main__":
    main()

