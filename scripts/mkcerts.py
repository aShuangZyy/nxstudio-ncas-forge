#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate a local CA + leaf certificate for the local MITM.

The CA private key never leaves this machine and is never committed:
certs/ is in .gitignore. Re-run to rotate.

    python scripts/mkcerts.py --out certs
"""
import argparse
import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HOSTS = [
    "accounts.cld.nikon.com",
    "faapi.www.accounts.cld.nikon.com",
    "*.accounts.cld.nikon.com",
    "*.cld.nikon.com",
    "accounts.cld.nikon.com.cn",
    "*.accounts.cld.nikon.com.cn",
    "*.nikon.com",
    "*.nikon.com.cn",
]


def default_out():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(here), "certs")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=default_out(), help="output directory (default: <repo>/certs)")
    ap.add_argument("--cn", default="NX-Forge-CA")
    ap.add_argument("--days", type=int, default=3650)
    args = ap.parse_args()

    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_to = now + datetime.timedelta(days=args.days)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, args.cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "local test only"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(valid_to)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False, key_cert_sign=True,
                          crl_sign=True, encipher_only=False, decipher_only=False),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOSTS[0])]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(valid_to)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in HOSTS]), critical=False)
        .add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                          data_encipherment=False, key_agreement=False, key_cert_sign=False,
                          crl_sign=False, encipher_only=False, decipher_only=False),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    payload = {
        "ca.cer": ca_cert.public_bytes(serialization.Encoding.DER),
        "ca.pem": ca_cert.public_bytes(serialization.Encoding.PEM),
        "leaf.pem": leaf_cert.public_bytes(serialization.Encoding.PEM)
        + ca_cert.public_bytes(serialization.Encoding.PEM),
        "leaf.key.pem": leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    }
    for name, data in payload.items():
        path = os.path.join(out, name)
        with open(path, "wb") as f:
            f.write(data)
        print("wrote %s (%d bytes)" % (path, len(data)))

    print("CA subject :", ca_cert.subject.rfc4514_string())
    print("CA sha1    :", ca_cert.fingerprint(hashes.SHA1()).hex())
    print("leaf SAN   :", ", ".join(HOSTS))


if __name__ == "__main__":
    main()