# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the capabilities advertised over the certificates relation."""

import json

import scenario

from charm import SelfSignedCertificatesCharm


class TestCapabilityAdvertisement:
    """SSC is an unrestricted CA, so it must advertise full capability support.

    These tests guard that "reality": SSC signs every CSR it receives. If the charm ever
    starts rejecting certain CSRs, ``_provider_capabilities`` must be updated to advertise
    the restriction (and matching filtering added). At that point these assertions will
    fail, forcing the advertisement to be brought back in line with what the charm does.
    """

    def _relation(self) -> scenario.Relation:
        return scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-requirer",
        )

    def test_given_leader_when_certificates_relation_changed_then_full_capabilities_advertised(
        self,
    ):
        ctx = scenario.Context(charm_type=SelfSignedCertificatesCharm)
        relation = self._relation()
        state_in = scenario.State(relations={relation}, leader=True)

        state_out = ctx.run(ctx.on.relation_changed(relation), state_in)

        capabilities = json.loads(
            state_out.get_relation(relation.id).local_app_data["capabilities"]
        )
        assert capabilities["supports_ip_sans"] is True
        assert capabilities["supports_wildcard_dns"] is True
        assert capabilities["supports_subdomain"] is True
        assert capabilities["supports_ca_certificates"] is True

    def test_given_not_leader_when_certificates_relation_changed_then_no_capabilities_written(
        self,
    ):
        ctx = scenario.Context(charm_type=SelfSignedCertificatesCharm)
        relation = self._relation()
        state_in = scenario.State(relations={relation}, leader=False)

        state_out = ctx.run(ctx.on.relation_changed(relation), state_in)

        assert "capabilities" not in state_out.get_relation(relation.id).local_app_data
