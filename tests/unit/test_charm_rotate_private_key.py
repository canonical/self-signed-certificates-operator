# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import patch

import pytest
import scenario

from charm import SelfSignedCertificatesCharm

TLS_LIB_PATH = "charms.tls_certificates_interface.v4.tls_certificates"


class TestCharmRotatePrivateKey:
    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = scenario.Context(
            charm_type=SelfSignedCertificatesCharm,
        )

    def test_given_not_leader_when_rotate_private_key_action_then_action_fails(self):
        state_in = scenario.State(
            leader=False,
        )

        with pytest.raises(scenario.ActionFailed) as exc:
            self.ctx.run(self.ctx.on.action("rotate-private-key"), state=state_in)

        assert exc.value.message == "This action can only be run on the leader unit."

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.revoke_all_certificates")
    def test_given_rotate_private_key_action_when_certificates_revoked_and_root_certificate_generated_then_action_succeeds(  # noqa: E501
        self,
        patch_revoke_all_certificates,
    ):
        state_in = scenario.State(
            leader=True,
        )

        self.ctx.run(self.ctx.on.action("rotate-private-key"), state=state_in)
        patch_revoke_all_certificates.assert_called_once()
        assert self.ctx.action_results
        output = self.ctx.action_results["result"]
        assert output == "New private key and CA certificate generated and stored."

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.revoke_all_certificates")
    def test_given_rotate_private_key_action_when_config_is_invalid_then_action_fails(  # noqa: E501
        self,
        patch_revoke_all_certificates,
    ):
        state_in = scenario.State(
            leader=True,
            config={
                "ca-common-name": "",
            },
        )

        with pytest.raises(scenario.ActionFailed) as exc:
            self.ctx.run(self.ctx.on.action("rotate-private-key"), state=state_in)

        assert (
            exc.value.message
            == "Private key rotation failed due to missing configuration.\
                Please check your configuration and try again.\
                Certificates have been revoked.".strip()
        )
