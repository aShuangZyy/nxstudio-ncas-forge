#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the forged NCAS responses used by the local MITM.

It signs two well-formed RS256 JWTs with the local leaf key and writes
rules.json. The app on this code path does not fetch or verify JWKS, so the
tokens only have to be shaped correctly and carry the claims it reads.

Why "0000" and not "E0000": the client parses `response_code` and treats the
string as a failure ONLY when its first character is 'E'. Everything else
(including "0000") means success; "E1301" and friends map to error classes.
See docs/how-it-works.md.

    python scripts/mkforge.py --out rules.json --cert-dir certs
"""
import argparse
import base64
import datetime
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Placeholders: no real account identifier is shipped with this project.
SUB_USER = "00000000-0000-4000-8000-0000000000aa"
SUB_SERVICE = "00000000-0000-4000-8000-0000000000bb"
SUCCESS_CODE = "0000"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def default_cert_dir():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(here), "certs")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cert-dir", default=default_cert_dir(), help="directory holding leaf.key.pem")
    ap.add_argument("--out", default=None, help="rules.json output path (default: <repo>/rules.json)")
    ap.add_argument("--sub-user", default=SUB_USER)
    ap.add_argument("--sub-service", default=SUB_SERVICE)
    ap.add_argument("--kid", default="nx-forge-key")
    args = ap.parse_args()

    cert_dir = os.path.abspath(args.cert_dir)
    out = os.path.abspath(args.out or os.path.join(os.path.dirname(cert_dir), "rules.json"))

    with open(os.path.join(cert_dir, "leaf.key.pem"), "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    pub = key.public_key().public_numbers()

    def int_b64(i: int) -> str:
        return b64u(i.to_bytes((i.bit_length() + 7) // 8, "big"))

    jwks = {
        "keys": [{
            "kty": "RSA",
            "kid": args.kid,
            "use": "sig",
            "alg": "RS256",
            "n": int_b64(pub.n),
            "e": int_b64(pub.e),
        }]
    }

    now = datetime.datetime.now(datetime.timezone.utc)
    iat = int(now.timestamp())
    header = {"alg": "RS256", "typ": "JWT", "kid": args.kid}

    access = {
        "exp": iat + 3600,
        "iat": iat,
        "jti": "00000000-0000-4000-8000-000000000001",
        "iss": "https://auth.accounts.cld.nikon.com/auth/realms/system",
        "sub": args.sub_service,
        "typ": "Bearer",
        "azp": "ncas",
        "scope": "offline_access",
        "sid": "00000000-0000-4000-8000-000000000002",
    }
    refresh = {
        "exp": iat + 30 * 24 * 3600,
        "iat": iat,
        "jti": "00000000-0000-4000-8000-000000000003",
        "iss": "https://auth.accounts.cld.nikon.com/auth/realms/user",
        "sub": args.sub_user,
        "typ": "Offline",
        "azp": "c0005_app",
        "scope": "openid profile email offline_access",
        "sid": "00000000-0000-4000-8000-000000000004",
    }

    def sign(payload: dict) -> str:
        h = b64u(json.dumps(header, separators=(",", ":")).encode())
        p = b64u(json.dumps(payload, separators=(",", ":")).encode())
        sig = key.sign(("%s.%s" % (h, p)).encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
        return "%s.%s.%s" % (h, p, b64u(sig))

    at, rt = sign(access), sign(refresh)
    token_body = {
        "response_code": SUCCESS_CODE,
        "message": "OK",
        "access_token": at,
        "refresh_token": rt,
        "expires_in": 3600,
        "refresh_expires_in": 2592000,
        "token_type": "Bearer",
        "scope": "openid profile email offline_access",
        "service_id": "NX_STUDIO",
        "function_id": "NX_STUDIO",
    }

    rules = {"rules": [
        {
            "name": "jwks",
            "host": "auth.accounts.cld.nikon.com",
            "path_contains": "certs",
            "status": "200 OK",
            "body": json.dumps(jwks),
        },
        {
            "name": "faapi_refresh_token",
            "host": "faapi.www.accounts.cld.nikon.com",
            "path_contains": "/nxs/refresh_token",
            "status": "200 OK",
            "body": json.dumps(token_body),
        },
        {
            "name": "ncas_token_password_grant",
            "host": "auth.accounts.cld.nikon.com",
            "path_contains": "/protocol/openid-connect/token",
            "status": "200 OK",
            "body": json.dumps({
                "access_token": at,
                "refresh_token": rt,
                "expires_in": 3600,
                "refresh_expires_in": 0,
                "token_type": "Bearer",
                "scope": "offline_access",
            }),
        },
        {
            "name": "nxs_other_success",
            "host": "faapi.www.accounts.cld.nikon.com",
            "path_contains": "/nxs/",
            "status": "200 OK",
            "body": json.dumps({
                "response_code": SUCCESS_CODE,
                "message": "OK",
                "access_token": at,
                "service_id": "NX_STUDIO",
            }),
        },
    ]}
    with open(out, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=2)
    print("wrote %s" % out)
    print("access_token  :", at[:48], "...")
    print("refresh_token :", rt[:48], "...")


if __name__ == "__main__":
    main()