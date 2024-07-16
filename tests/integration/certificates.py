#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from cryptography import x509


def get_common_name_from_certificate(certificate: bytes) -> str:
    loaded_certificate = x509.load_pem_x509_certificate(certificate)
    return str(
        loaded_certificate.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME  # type: ignore[reportAttributeAccessIssue]
        )[0].value
    )
