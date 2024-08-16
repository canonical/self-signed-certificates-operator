# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import mock_open, patch

import ops
import ops.testing
from charm import CA_CERTIFICATES_SECRET_LABEL, SelfSignedCertificatesCharm


class TestSendCaCert(unittest.TestCase):
    def setUp(self):
        self.harness = ops.testing.Harness(SelfSignedCertificatesCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_leader(is_leader=True)
        self.mock_open = mock_open()
        self.patcher = patch("builtins.open", self.mock_open)
        self.patcher.start()
        self.harness.begin_with_initial_hooks()

    def tearDown(self):
        self.patcher.stop()

    def test_when_relation_join_then_ca_cert_is_advertised(self):
        # Add a few apps
        apps = ["traefik", "another"]
        rel_ids = [
            self.harness.add_relation(relation_name="send-ca-cert", remote_app=app) for app in apps
        ]
        for app, rel_id in zip(apps, rel_ids):
            self.harness.add_relation_unit(relation_id=rel_id, remote_unit_name=f"{app}/0")

        # Now make sure all the apps have the same ca
        secret = self.harness.charm.model.get_secret(
            label=CA_CERTIFICATES_SECRET_LABEL
        ).get_content()
        ca_from_secret = secret["ca-certificate"]

        for rel_id in rel_ids:
            with self.subTest(rel_id=rel_id):
                data = self.harness.get_relation_data(rel_id, self.harness.charm.unit)
                ca_from_rel_data = data["ca"]
                self.assertEqual(ca_from_secret, ca_from_rel_data)
