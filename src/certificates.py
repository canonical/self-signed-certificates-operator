#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utilities for generating certificates."""

import logging
from datetime import datetime, timedelta, timezone
from typing import List

from cryptography import x509
from cryptography.hazmat._oid import ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger(__name__)


def generate_private_key(
    key_size: int = 2048,
    public_exponent: int = 65537,
) -> str:
    """Generate a private key.

    Args:
        key_size (int): Key size in bytes
        public_exponent: Public exponent.

    Returns:
        str: Private Key
    """
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return key_bytes.decode().strip()


def get_certificate_request_extensions(
    authority_key_identifier: bytes,
    csr: x509.CertificateSigningRequest,
    is_ca: bool,
) -> List[x509.Extension]:
    """Generate a list of certificate extensions from a CSR and other known information.

    Args:
        authority_key_identifier (bytes): Authority key identifier
        csr (x509.CertificateSigningRequest): CSR
        is_ca (bool): Whether the certificate is a CA certificate

    Returns:
        List[x509.Extension]: List of extensions
    """
    cert_extensions_list: List[x509.Extension] = [
        x509.Extension(
            oid=ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
            value=x509.AuthorityKeyIdentifier(
                key_identifier=authority_key_identifier,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        ),
        x509.Extension(
            oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            value=x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        ),
        x509.Extension(
            oid=ExtensionOID.BASIC_CONSTRAINTS,
            critical=True,
            value=x509.BasicConstraints(ca=is_ca, path_length=None),
        ),
    ]
    sans: List[x509.GeneralName] = []
    try:
        loaded_san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans.extend(
            [x509.DNSName(name) for name in loaded_san_ext.value.get_values_for_type(x509.DNSName)]
        )
        sans.extend(
            [x509.IPAddress(ip) for ip in loaded_san_ext.value.get_values_for_type(x509.IPAddress)]
        )
        sans.extend(
            [
                x509.RegisteredID(oid)
                for oid in loaded_san_ext.value.get_values_for_type(x509.RegisteredID)
            ]
        )
    except x509.ExtensionNotFound:
        pass

    if sans:
        cert_extensions_list.append(
            x509.Extension(
                oid=ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                critical=False,
                value=x509.SubjectAlternativeName(sans),
            )
        )

    if is_ca:
        cert_extensions_list.append(
            x509.Extension(
                ExtensionOID.KEY_USAGE,
                critical=True,
                value=x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
            )
        )

    existing_oids = {ext.oid for ext in cert_extensions_list}
    for extension in csr.extensions:
        if extension.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            continue
        if extension.oid in existing_oids:
            logger.warning("Extension %s is managed by the TLS provider, ignoring.", extension.oid)
            continue
        cert_extensions_list.append(extension)

    return cert_extensions_list


def generate_certificate(
    csr: str,
    ca: str,
    ca_key: str,
    validity: int,
    is_ca: bool = False,
) -> str:
    """Generate a TLS certificate based on a CSR.

    Args:
        csr (str): CSR
        ca (str): CA Certificate
        ca_key (str): CA private key
        validity (int): Certificate validity (in days)
        is_ca (bool): Whether the certificate is a CA certificate

    Returns:
        str: Certificate
    """
    csr_object = x509.load_pem_x509_csr(csr.encode())
    subject = csr_object.subject
    ca_pem = x509.load_pem_x509_certificate(ca.encode())
    issuer = ca_pem.issuer
    private_key = serialization.load_pem_private_key(ca_key.encode(), password=None)

    certificate_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(csr_object.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity))
    )
    extensions = get_certificate_request_extensions(
        authority_key_identifier=ca_pem.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value.key_identifier,
        csr=csr_object,
        is_ca=is_ca,
    )
    for extension in extensions:
        try:
            certificate_builder = certificate_builder.add_extension(
                extval=extension.value,
                critical=extension.critical,
            )
        except ValueError as e:
            logger.warning("Failed to add extension %s: %s", extension.oid, e)

    cert = certificate_builder.sign(private_key, hashes.SHA256())  # type: ignore[arg-type]
    return cert.public_bytes(serialization.Encoding.PEM).decode().strip()


def generate_ca(
    private_key: str,
    subject: str,
    validity: int,
    country: str = "US",
) -> str:
    """Generate a CA Certificate.

    Args:
        private_key (bytes): Private key
        subject (str): Common Name that can be an IP or a Full Qualified Domain Name (FQDN).
        validity (int): Certificate validity time (in days)
        country (str): Certificate Issuing country

    Returns:
        str: CA Certificate.
    """
    private_key_object = serialization.load_pem_private_key(
        private_key.encode(),
        password=None,
    )
    subject_name = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, subject),
        ]
    )
    subject_identifier_object = x509.SubjectKeyIdentifier.from_public_key(
        private_key_object.public_key()  # type: ignore[arg-type]
    )
    subject_identifier = key_identifier = subject_identifier_object.public_bytes()
    key_usage = x509.KeyUsage(
        digital_signature=True,
        key_encipherment=True,
        key_cert_sign=True,
        key_agreement=False,
        content_commitment=False,
        data_encipherment=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(subject_name)
        .public_key(private_key_object.public_key())  # type: ignore[arg-type]
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity))
        .add_extension(x509.SubjectKeyIdentifier(digest=subject_identifier), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=key_identifier,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        )
        .add_extension(key_usage, critical=True)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key_object, hashes.SHA256())  # type: ignore[arg-type]
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode().strip()


def certificate_has_common_name(certificate: bytes, common_name: str) -> bool:
    """Return whether the certificate has the given common name."""
    loaded_certificate = x509.load_pem_x509_certificate(certificate)
    certificate_common_name = loaded_certificate.subject.get_attributes_for_oid(
        x509.oid.NameOID.COMMON_NAME  # type: ignore[reportAttributeAccessIssue]
    )[0].value

    return certificate_common_name == common_name
