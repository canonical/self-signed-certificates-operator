# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


import pytest
import scenario

from charm import SelfSignedCertificatesCharm


class TestCharmGetCACertificate:
    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = scenario.Context(
            charm_type=SelfSignedCertificatesCharm,
        )

    def test_given_ca_cert_generated_when_get_ca_certificate_action_then_returns_ca_certificate(
        self,
    ):
        ca_certificate = "whatever CA certificate"
        ca_certificates_secret = scenario.Secret(
            id="0",
            label="ca-certificates",
            contents={
                0: {
                    "ca-certificate": ca_certificate,
                }
            },
            owner="app",
        )
        state_in = scenario.State(
            leader=True,
            secrets=[ca_certificates_secret],
        )

        action_output = self.ctx.run_action("get-ca-certificate", state=state_in)
        assert action_output.results
        assert action_output.results["ca-certificate"] == ca_certificate

    def test_given_ca_cert_not_generated_when_get_ca_certificate_action_then_action_fails(self):
        state_in = scenario.State(
            leader=True,
        )

        action_output = self.ctx.run_action("get-ca-certificate", state=state_in)

        assert not action_output.success
        assert action_output.failure == "Root Certificate is not yet generated"
