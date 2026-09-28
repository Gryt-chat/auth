#!/usr/bin/env python3
# Turns on the OAuth device grant for gryt-web through the admin API, for linking a device.
# Read-modify-write on the client, safe to run twice. Never through gryt-realm.json.
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

# Names from Keycloak's OAuth2DeviceConfig. All three are strings.
DESIRED = {
    "oauth2.device.authorization.grant.enabled": "true",
    "oauth2.device.code.lifespan": os.getenv("GRYT_DEVICE_CODE_LIFESPAN", "300"),
    "oauth2.device.polling.interval": os.getenv("GRYT_DEVICE_POLLING_INTERVAL", "5"),
}


def env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, "").strip()
    if value:
        return value
    if default is None:
        sys.exit(f"[device-grant] missing {name}")
    return default


def call(method: str, url: str, token: str | None = None, body: bytes | None = None,
         content_type: str = "application/json") -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if body is not None:
        req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def device_attributes(client: dict) -> dict:
    attrs = client.get("attributes") or {}
    return {name: attrs.get(name) for name in DESIRED}


def main() -> None:
    base = env("KC_URL", "http://keycloak:8080").rstrip("/")
    realm = env("GRYT_REALM", "gryt")
    client_id = env("GRYT_CLIENT_ID", "gryt-web")
    dry_run = "--dry-run" in sys.argv

    form = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": env("GRYT_KEYCLOAK_ADMIN_USERNAME"),
        "password": env("GRYT_KEYCLOAK_ADMIN_PASSWORD"),
    }).encode()
    status, body = call("POST", f"{base}/realms/master/protocol/openid-connect/token", body=form,
                        content_type="application/x-www-form-urlencoded")
    if status != 200:
        sys.exit(f"[device-grant] admin token refused (HTTP {status}): {body.decode(errors='replace')}")
    token = json.loads(body)["access_token"]

    q = urllib.parse.quote(client_id)
    status, body = call("GET", f"{base}/admin/realms/{realm}/clients?clientId={q}", token)
    found = json.loads(body) if status == 200 else []
    if not found:
        sys.exit(f"[device-grant] client {client_id} not found in realm {realm} (HTTP {status})")
    path = f"{base}/admin/realms/{realm}/clients/{found[0]['id']}"

    status, body = call("GET", path, token)
    if status != 200:
        sys.exit(f"[device-grant] GET client failed (HTTP {status})")
    client = json.loads(body)
    before = device_attributes(client)
    print(f"[device-grant] {realm}/{client_id} before: {json.dumps(before, sort_keys=True)}")

    if before == DESIRED:
        print("[device-grant] already set, nothing to do")
        return
    if dry_run:
        print(f"[device-grant] would set: {json.dumps(DESIRED, sort_keys=True)}")
        return

    client.setdefault("attributes", {}).update(DESIRED)
    status, body = call("PUT", path, token, json.dumps(client).encode())
    if status not in (200, 204):
        sys.exit(f"[device-grant] PUT client failed (HTTP {status}): {body.decode(errors='replace')}")

    status, body = call("GET", path, token)
    after = device_attributes(json.loads(body))
    print(f"[device-grant] {realm}/{client_id} after:  {json.dumps(after, sort_keys=True)}")
    if after != DESIRED:
        sys.exit("[device-grant] the PUT went through but the client doesn't show the new values")


if __name__ == "__main__":
    main()
