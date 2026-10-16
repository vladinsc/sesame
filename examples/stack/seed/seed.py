#!/usr/bin/env python3
"""Seed a Vaultwarden instance for the sesame demo, implementing the Bitwarden client crypto the `bw` CLI can't do
at registration time. Registers a bot user, stores one login item (the Grafana admin credential) in the personal
vault with a `sesame-scope` custom field, and fetches the user's API key so `bw serve` can log in read-only.

Outputs (to /out, a mounted volume): item-id.txt and bw.env. Prints no secrets to stdout.

Env: VW_URL, BOT_EMAIL, BOT_PASSWORD, ITEM_NAME, ITEM_USERNAME, ITEM_PASSWORD, ITEM_URL, ITEM_SCOPE.
"""
import base64, json, os, secrets, sys, uuid
import urllib.request, urllib.error

from cryptography.hazmat.primitives import hashes, hmac, padding, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa

VW = os.environ.get("VW_URL", "http://vaultwarden").rstrip("/")
EMAIL = os.environ.get("BOT_EMAIL", "grafanabot@demo.local")
PASSWORD = os.environ.get("BOT_PASSWORD", "bot-master-pw")
ITERS = 600000

b64 = lambda b: base64.b64encode(b).decode()


def pbkdf2(password: bytes, salt: bytes, iters: int, length: int = 32) -> bytes:
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=iters).derive(password)


def hkdf_expand(prk: bytes, info: str, length: int = 32) -> bytes:
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info.encode()).derive(prk)


def enc_string(key64: bytes, data: bytes) -> str:
    """Bitwarden EncString type 2 (AES-256-CBC + HMAC-SHA256)."""
    enc_key, mac_key = key64[:32], key64[32:64]
    iv = secrets.token_bytes(16)
    pad = padding.PKCS7(128).padder()
    ct = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    body = ct.update(pad.update(data) + pad.finalize()) + ct.finalize()
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(iv + body)
    return f"2.{b64(iv)}|{b64(body)}|{b64(h.finalize())}"


def http(method, path, body=None, token=None, form=False, headers=None):
    url = VW + path
    data, hdr = None, {"Accept": "application/json"}
    if headers:
        hdr.update(headers)
    if body is not None:
        if form:
            data = urllib.parse.urlencode(body).encode()
            hdr["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(body).encode()
            hdr["Content-Type"] = "application/json"
    if token:
        hdr["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, headers=hdr, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw.decode(errors="replace")}


def ci(d, *names):
    """Case-insensitive dict get across Vaultwarden's PascalCase/camelCase responses."""
    for n in names:
        for k in d:
            if k.lower() == n.lower():
                return d[k]
    return None


def main():
    master_key = pbkdf2(PASSWORD.encode(), EMAIL.lower().encode(), ITERS)
    mph = b64(pbkdf2(master_key, PASSWORD.encode(), 1))
    stretched = hkdf_expand(master_key, "enc") + hkdf_expand(master_key, "mac")
    user_key = secrets.token_bytes(64)
    protected_key = enc_string(stretched, user_key)

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_der = rsa_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    priv_der = rsa_key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    enc_priv = enc_string(user_key, priv_der)

    reg = {
        "name": "Grafana Bot", "email": EMAIL,
        "masterPasswordHash": mph, "masterPasswordHint": None,
        "key": protected_key, "kdf": 0, "kdfIterations": ITERS,
        "keys": {"publicKey": b64(pub_der), "encryptedPrivateKey": enc_priv},
    }
    status, resp = http("POST", "/identity/accounts/register", reg)
    if status not in (200, 204):
        status2, resp2 = http("POST", "/api/accounts/register", reg)
        if status2 not in (200, 204):
            sys.exit(f"register failed: {status} {resp} / {status2} {resp2}")

    # login (password grant). Vaultwarden wants the Auth-Email header (base64url of the email, no padding).
    auth_email = base64.urlsafe_b64encode(EMAIL.encode()).decode().rstrip("=")
    status, tok = http("POST", "/identity/connect/token", {
        "grant_type": "password", "username": EMAIL, "password": mph,
        "scope": "api offline_access", "client_id": "web",
        "deviceType": "9", "deviceIdentifier": str(uuid.uuid4()), "deviceName": "seeder",
    }, form=True, headers={"Auth-Email": auth_email})
    access = ci(tok, "access_token")
    if not access:
        sys.exit(f"login failed: {status} {tok}")

    scope = os.environ.get("ITEM_SCOPE", "projects/demo/dev")
    cipher = {
        "type": 1,
        "name": enc_string(user_key, os.environ.get("ITEM_NAME", "Grafana admin").encode()),
        "notes": None, "favorite": False,
        "login": {
            "username": enc_string(user_key, os.environ.get("ITEM_USERNAME", "admin").encode()),
            "password": enc_string(user_key, os.environ.get("ITEM_PASSWORD", "s3cret-admin").encode()),
            "uris": [{"uri": enc_string(user_key, os.environ.get("ITEM_URL", "http://localhost:3000").encode()), "match": None}],
            "totp": None,
        },
        "fields": [{
            "type": 0,
            "name": enc_string(user_key, b"sesame-scope"),
            "value": enc_string(user_key, scope.encode()),
        }],
        "organizationId": None, "folderId": None,
    }
    status, item = http("POST", "/api/ciphers", cipher, token=access)
    item_id = ci(item, "id")
    if not item_id:
        sys.exit(f"create item failed: {status} {item}")

    # user API key, for `bw serve` apikey login
    status, prof = http("GET", "/api/accounts/profile", token=access)
    uid = ci(prof, "id")
    status, keyresp = http("POST", "/api/accounts/api-key", {"masterPasswordHash": mph}, token=access)
    api_key = ci(keyresp, "apiKey")
    if not uid or not api_key:
        sys.exit(f"api-key failed: {status} {keyresp}")

    os.makedirs("/out", exist_ok=True)
    with open("/out/item-id.txt", "w") as f:
        f.write(item_id)
    with open("/out/bw.env", "w") as f:
        f.write(f"BW_URL={VW}\nBW_CLIENTID=user.{uid}\nBW_CLIENTSECRET={api_key}\nBW_PASSWORD={PASSWORD}\n")
    print("seed: item created, api key stored (item id in /out/item-id.txt)")


if __name__ == "__main__":
    main()
