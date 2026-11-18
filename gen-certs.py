#!/usr/bin/env python3
"""
Generate the lab CA and the kessel leaf certificate next to this script.

  ca.key         CA private key        (server machine only, never share)
  ca.pem         CA certificate        (install on every machine that connects)
  leaf.key       leaf private key      (server machine only)
  leaf-chain.pem leaf + CA chain       (served by privsvr.py)

Run once on the server machine, then copy at least ca.pem to the clients so
they trust the same CA. install.py calls this automatically on the server when
any of the four files is missing.
"""
import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = os.path.dirname(os.path.abspath(__file__))
CA_NAME = "Parsec Lab CA"
DOMAINS = [
    "kessel-api.parsec.app",
    "kessel-ws-v2.parsec.app",
    "public.parsec.app",
    "kessel-api",
    "kessel-ws",
]


def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def write_key(path, key):
    data = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, 0o600)


def write_chain(path, certs):
    with open(path, "wb") as f:
        for cert in certs:
            f.write(cert.public_bytes(serialization.Encoding.PEM))


def main():
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = new_key()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_NAME)])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = new_key()
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DOMAINS[0])]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in DOMAINS]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    write_key(os.path.join(ROOT, "ca.key"), ca_key)
    write_chain(os.path.join(ROOT, "ca.pem"), [ca_cert])
    write_key(os.path.join(ROOT, "leaf.key"), leaf_key)
    write_chain(os.path.join(ROOT, "leaf-chain.pem"), [leaf_cert, ca_cert])
    print("wrote ca.key ca.pem leaf.key leaf-chain.pem")


if __name__ == "__main__":
    main()
