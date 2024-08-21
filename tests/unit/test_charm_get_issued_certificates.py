# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import json
from unittest.mock import patch

import pytest
import scenario
from charms.tls_certificates_interface.v4.tls_certificates import (
    ProviderCertificate,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)

from charm import SelfSignedCertificatesCharm

TLS_LIB_PATH = "charms.tls_certificates_interface.v4.tls_certificates"


class TestCharmGetIssuedCertificates:
    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = scenario.Context(
            charm_type=SelfSignedCertificatesCharm,
        )

    def test_given_no_certificates_issued_when_get_issued_certificates_action_then_action_fails(
        self,
    ):
        state_in = scenario.State()

        action_output = self.ctx.run_action("get-issued-certificates", state=state_in)

        assert not action_output.success
        assert action_output.failure == "No certificates issued yet."

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_issued_certificates")
    def test_given_certificates_issued_when_get_issued_certificates_action_then_action_returns_certificates(  # noqa: E501
        self,
        patch_get_issued_certificates,
    ):
        ca_private_key = generate_private_key()
        ca_certificate = generate_ca(
            private_key=ca_private_key,
            common_name="example.com",
            validity=100,
        )
        requirer_private_key = generate_private_key()
        csr = generate_csr(private_key=requirer_private_key, common_name="example.com")
        certificate = generate_certificate(
            csr=csr,
            ca=ca_certificate,
            ca_private_key=ca_private_key,
            validity=100,
        )
        chain = [ca_certificate, certificate]
        revoked = False
        patch_get_issued_certificates.return_value = [
            ProviderCertificate(
                relation_id=1,
                certificate_signing_request=csr,
                certificate=certificate,
                ca=ca_certificate,
                chain=chain,
                revoked=revoked,
            )
        ]
        state_in = scenario.State(
            config={
                "ca-common-name": "example.com",
                "certificate-validity": 100,
            },
            leader=True,
        )

        action_output = self.ctx.run_action("get-issued-certificates", state=state_in)

        assert action_output.results
        output_certificate = json.loads(action_output.results["certificates"][0])
        assert output_certificate["csr"] == str(csr)
        assert output_certificate["certificate"] == str(certificate)
        assert output_certificate["ca"] == str(ca_certificate)
        assert output_certificate["chain"] == [str(ca_certificate), str(certificate)]
        assert output_certificate["revoked"] == revoked
