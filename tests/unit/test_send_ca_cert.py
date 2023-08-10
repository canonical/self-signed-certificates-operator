# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest

import ops
import ops.testing

from charm import CA_CERTIFICATES_SECRET_LABEL, SelfSignedCertificatesCharm


class TestSendCaCert(unittest.TestCase):
    def setUp(self):
        self.harness = ops.testing.Harness(SelfSignedCertificatesCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_leader(is_leader=True)
        self.harness.begin_with_initial_hooks()

    def test_when_relation_joins_then_ca_cert_is_advertised(self):
        self.rel_id = self.harness.add_relation(relation_name="send-ca-cert", remote_app="traefik")
        self.harness.add_relation_unit(relation_id=self.rel_id, remote_unit_name="traefik/0")
        data = self.harness.get_relation_data(self.rel_id, self.harness.charm.unit)

        ca = self.harness.charm.model.get_secret(label=CA_CERTIFICATES_SECRET_LABEL).get_content()[
            "ca-certificate"
        ]

        self.assertEqual(ca, data["ca"])
