# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import patch

import pytest
import scenario
from ops import ActiveStatus, BlockedStatus

from charm import SelfSignedCertificatesCharm


class TestCharmCollectStatus:
    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = scenario.Context(
            charm_type=SelfSignedCertificatesCharm,
        )

    def test_given_invalid_config_when_collect_unit_status_then_status_is_blocked(self):
        state_in = scenario.State(
            config={
                "ca-common-name": "",
                "certificate-validity": "100",
            },
            leader=True,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state=state_in)

        assert state_out.unit_status == BlockedStatus(
            "The following configuration values are not valid: ['ca-common-name']"
        )

    def test_given_invalid_validity_config_when_collect_unit_status_then_status_is_blocked(self):
        state_in = scenario.State(
            config={
                "ca-common-name": "pizza.example.com",
                "certificate-validity": "0",
            },
            leader=True,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state=state_in)

        assert state_out.unit_status == BlockedStatus(
            "The following configuration values are not valid: ['certificate-validity', 'root-ca-validity']"  # noqa: E501
        )

    def test_given_root_ca_validity_config_not_twice_the_certificate_validity_when_collect_unit_status_then_status_is_blocked(  # noqa: E501
        self,
    ):
        state_in = scenario.State(
            config={
                "ca-common-name": "pizza.example.com",
                "certificate-validity": "100",
                "root-ca-validity": "0",
            },
            leader=True,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state=state_in)

        assert state_out.unit_status == BlockedStatus(
            "The following configuration values are not valid: ['certificate-validity', 'root-ca-validity']"  # noqa: E501
        )

    @patch("charm.generate_private_key")
    @patch("charm.generate_ca")
    def test_given_valid_config_when_collect_unit_status_then_status_is_active(
        self,
        patch_generate_ca,
        patch_generate_private_key,
    ):
        patch_generate_ca.return_value = "whatever CA certificate"
        patch_generate_private_key.return_value = "whatever private key"
        state_in = scenario.State(
            config={
                "ca-common-name": "pizza.example.com",
                "certificate-validity": "100",
            },
            leader=True,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state=state_in)

        assert state_out.unit_status == ActiveStatus()
