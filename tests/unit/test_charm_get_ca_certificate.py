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
            {
                "ca-certificate": ca_certificate,
            },
            label="ca-certificates",
            owner="app",
        )
        state_in = scenario.State(
            leader=True,
            secrets={ca_certificates_secret},
        )

        self.ctx.run(self.ctx.on.action("get-ca-certificate"), state=state_in)
        assert self.ctx.action_results
        assert self.ctx.action_results["ca-certificate"] == ca_certificate

    def test_given_ca_cert_not_generated_when_get_ca_certificate_action_then_action_fails(self):
        state_in = scenario.State(
            leader=True,
        )

        with pytest.raises(scenario.ActionFailed) as exc:
            self.ctx.run(self.ctx.on.action("get-ca-certificate"), state=state_in)

        assert exc.value.message == "Root Certificate is not yet generated"
