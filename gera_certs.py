from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime
import os
import ipaddress

# Garante que a pasta existe
if not os.path.exists("certs"):
    os.makedirs("certs")

def generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def save_key(key, name):
    with open(f"certs/{name}", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

def save_cert(cert, name):
    with open(f"certs/{name}", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

print("--- Gerando Certificados Completos (KeyUsage + AKI + SKI) ---")

# ==========================================
# 1. CA (Autoridade Raiz)
# ==========================================
print("1. Criando Autoridade Certificadora (CA)...")
ca_key = generate_key()
save_key(ca_key, "ca.key")

ca_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UnB"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"WhatsChatRootCA"),
])

ca_cert = x509.CertificateBuilder().subject_name(
    ca_subject
).issuer_name(
    ca_subject
).public_key(
    ca_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc)
).not_valid_after(
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None), critical=True,
).add_extension(
    x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
    critical=False
).add_extension(
    x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
    critical=False
).add_extension(
    x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,  # Permite assinar certificados
        crl_sign=True,       # Permite assinar listas de revogação
        encipher_only=False,
        decipher_only=False
    ),
    critical=True
).sign(ca_key, hashes.SHA256())

save_cert(ca_cert, "ca.crt")

# SERVIDOR
print("2. Criando Certificado do Servidor...")
server_key = generate_key()
save_key(server_key, "server.key")

server_cert = x509.CertificateBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
])).issuer_name(
    ca_subject
).public_key(
    server_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc)
).not_valid_after(
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
).add_extension(
    x509.SubjectAlternativeName([
        x509.DNSName(u"localhost"), 
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv4Address("0.0.0.0"))
    ]),
    critical=False,
).add_extension(
    x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
    critical=False
).add_extension(
    x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
    critical=False
).add_extension(

    # Permissões do Servidor
    x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True, 
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False
    ),
    critical=True
).add_extension(

    # Define que é um Servidor TLS
    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
    critical=False
).sign(ca_key, hashes.SHA256())

save_cert(server_cert, "server.crt")

# CLIENTE (Alice)
print("3. Criando Certificado do Cliente (Alice)...")
alice_key = generate_key()
save_key(alice_key, "alice.key")

alice_cert = x509.CertificateBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UnB"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"Alice"),
])).issuer_name(
    ca_subject
).public_key(
    alice_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc)
).not_valid_after(
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
).add_extension(
    x509.SubjectKeyIdentifier.from_public_key(alice_key.public_key()),
    critical=False
).add_extension(
    x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
    critical=False
).add_extension(

    # Permissões do Cliente
    x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False
    ),
    critical=True
).add_extension(

    # Define que é um Cliente TLS
    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
    critical=False
).sign(ca_key, hashes.SHA256())

save_cert(alice_cert, "alice.crt")

print("\n[SUCESSO] Certificados gerados!")