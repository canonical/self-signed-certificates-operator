#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


from charm import (
    generate_ca,
    generate_certificate,
    generate_private_key,
)
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from tests.unit.certificates_helpers import (
    generate_ca as generate_ca_helper,
)
from tests.unit.certificates_helpers import (
    generate_csr as generate_csr_helper,
)
from tests.unit.certificates_helpers import (
    generate_private_key as generate_private_key_helper,
)


def test_given_no_password_when_generate_private_key_then_key_is_generated_and_loadable():
    private_key = generate_private_key()

    load_pem_private_key(data=private_key.encode(), password=None)


def test_given_key_size_provided_when_generate_private_key_then_private_key_is_generated():
    key_size = 1234

    private_key = generate_private_key(key_size=key_size)

    private_key_object = load_pem_private_key(private_key.encode(), password=None)
    assert isinstance(private_key_object, rsa.RSAPrivateKeyWithSerialization)
    assert private_key_object.key_size == key_size


def test_given_private_key_and_subject_when_generate_ca_then_ca_is_generated_correctly():
    subject = "certifier.example.com"
    private_key = generate_private_key_helper()

    certifier_pem = generate_ca(private_key=private_key, subject=subject)

    cert = x509.load_pem_x509_certificate(certifier_pem.encode())
    private_key_object = load_pem_private_key(private_key.encode(), password=None)
    certificate_public_key = cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1,
    )
    initial_public_key = private_key_object.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1,
    )

    assert cert.issuer == x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, subject),
        ]
    )
    assert cert.subject == x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, subject),
        ]
    )
    assert certificate_public_key == initial_public_key
    assert (
        x509.KeyUsage(
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
        == cert.extensions.get_extension_for_class(x509.KeyUsage).value
    )
    assert cert.extensions.get_extension_for_class(x509.KeyUsage).critical


def test_given_csr_and_ca_when_generate_certificate_then_certificate_is_generated_with_correct_subject_and_issuer():  # noqa: E501
    ca_subject = "whatever.ca.subject"
    csr_subject = "whatever.csr.subject"
    ca_key = generate_private_key_helper()
    ca = generate_ca_helper(private_key=ca_key, common_name=ca_subject)
    csr_private_key = generate_private_key_helper()
    csr = generate_csr_helper(
        private_key=csr_private_key,
        common_name=csr_subject,
    )

    certificate = generate_certificate(
        csr=csr,
        ca=ca,
        ca_key=ca_key,
    )

    certificate_object = x509.load_pem_x509_certificate(certificate.encode())
    assert certificate_object.issuer == x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, ca_subject),
        ]
    )
    subject_name_attributes = certificate_object.subject.get_attributes_for_oid(
        x509.NameOID.COMMON_NAME
    )
    assert subject_name_attributes[0] == x509.NameAttribute(x509.NameOID.COMMON_NAME, csr_subject)


def test_given_csr_and_ca_when_generate_certificate_then_certificate_is_generated_with_correct_sans():  # noqa: E501
    ca_subject = "ca.subject"
    csr_subject = "csr.subject"
    sans = ["www.localhost.com", "www.test.com"]

    ca_key = generate_private_key_helper()
    ca = generate_ca_helper(
        private_key=ca_key,
        common_name=ca_subject,
    )
    csr_private_key = generate_private_key_helper()
    csr = generate_csr_helper(
        private_key=csr_private_key,
        common_name=csr_subject,
        sans_dns=sans,
    )

    certificate = generate_certificate(csr=csr, ca=ca, ca_key=ca_key)

    cert = x509.load_pem_x509_certificate(certificate.encode())
    result_all_sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)

    result_sans_dns = sorted(result_all_sans.value.get_values_for_type(x509.DNSName))
    assert result_sans_dns == sorted(set(sans))


def test_given_private_key_when_generate_ca_then_basic_constraints_extension_is_correctly_populated():  # noqa: E501
    subject = "whatever.ca.subject"
    private_key = generate_private_key_helper()

    ca = generate_ca(
        private_key=private_key,
        subject=subject,
    )

    certificate_object = x509.load_pem_x509_certificate(ca.encode())
    basic_constraints = certificate_object.extensions.get_extension_for_class(
        x509.BasicConstraints
    )
    assert basic_constraints.value.ca is True


def test_given_certificate_created_when_generate_certificate_then_verify_public_key_then_doesnt_throw_exception():  # noqa: E501
    ca_subject = "whatever.ca.subject"
    csr_subject = "whatever.csr.subject"
    ca_key = generate_private_key_helper()
    ca = generate_ca_helper(
        private_key=ca_key,
        common_name=ca_subject,
    )
    csr_private_key = generate_private_key_helper()
    csr = generate_csr_helper(
        private_key=csr_private_key,
        common_name=csr_subject,
    )

    certificate = generate_certificate(
        csr=csr,
        ca=ca,
        ca_key=ca_key,
    )

    certificate_object = x509.load_pem_x509_certificate(certificate.encode())
    private_key_object = load_pem_private_key(ca_key.encode(), password=None)
    public_key = private_key_object.public_key()

    public_key.verify(  # type: ignore[call-arg, union-attr]
        certificate_object.signature,
        certificate_object.tbs_certificate_bytes,
        padding.PKCS1v15(),  # type: ignore[arg-type]
        certificate_object.signature_hash_algorithm,  # type: ignore[arg-type]
    )


def test_given_request_is_for_ca_certificate_when_generate_certificate_then_certificate_is_generated():  # noqa: E501
    ca_private_key = generate_private_key_helper()
    ca = generate_ca(
        private_key=ca_private_key,
        subject="my.demo.ca",
    )
    server_private_key = generate_private_key_helper()

    server_csr = generate_csr_helper(
        private_key=server_private_key,
        common_name="10.10.10.10",
        sans_dns=[],
    )

    server_cert = generate_certificate(
        csr=server_csr,
        ca=ca,
        ca_key=ca_private_key,
        is_ca=True,
    )

    loaded_server_cert = x509.load_pem_x509_certificate(server_cert.encode())

    assert (
        loaded_server_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        is True
    )
    assert (
        loaded_server_cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
        is True
    )
    assert (
        loaded_server_cert.extensions.get_extension_for_class(x509.KeyUsage).value.crl_sign is True
    )
