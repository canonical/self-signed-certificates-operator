# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import Mock, patch

import ops
import ops.testing
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

from charm import SelfSignedCertificatesCharm

TLS_LIB_PATH = "charms.tls_certificates_interface.v2.tls_certificates"


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = ops.testing.Harness(SelfSignedCertificatesCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_given_invalid_config_when_config_changed_then_status_is_blocked(self):
        key_values = {"ca-common-name": "", "certificate-validity": 100}
        self.harness.set_leader(is_leader=True)

        self.harness.update_config(key_values=key_values)

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("The following configuration values are not valid: ['ca-common-name']"),
        )

    @patch("charm.generate_private_key")
    @patch("charm.generate_password")
    @patch("charm.generate_ca")
    def test_given_valid_config_when_config_changed_then_ca_certificate_is_stored_in_juju_secret(
        self,
        patch_generate_ca,
        patch_generate_password,
        patch_generate_private_key,
    ):
        ca_certificate_string = "whatever CA certificate"
        private_key_string = "whatever private key"
        private_key_password = "banana"
        ca_certificate_bytes = ca_certificate_string.encode()
        private_key_bytes = private_key_string.encode()
        patch_generate_ca.return_value = ca_certificate_bytes
        patch_generate_password.return_value = private_key_password
        patch_generate_private_key.return_value = private_key_bytes
        key_values = {"ca-common-name": "pizza.com", "certificate-validity": 100}
        self.harness.set_leader(is_leader=True)

        self.harness.update_config(key_values=key_values)

        ca_certificates_secret = self.harness._backend.secret_get(label="ca-certificates")

        self.assertEqual(
            ca_certificates_secret["ca-certificate"],
            ca_certificate_string,
        )
        self.assertEqual(
            ca_certificates_secret["private-key-password"],
            private_key_password,
        )
        self.assertEqual(
            ca_certificates_secret["private-key"],
            private_key_string,
        )

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV2.revoke_all_certificates")
    @patch("charm.generate_private_key")
    @patch("charm.generate_password")
    @patch("charm.generate_ca")
    def test_given_valid_config_when_config_changed_then_existing_certificates_are_revoked(
        self,
        patch_generate_ca,
        patch_generate_password,
        patch_generate_private_key,
        patch_revoke_all_certificates,
    ):
        patch_generate_ca.return_value = b"whatever CA certificate"
        patch_generate_password.return_value = "password"
        patch_generate_private_key.return_value = b"whatever private key"
        key_values = {"ca-common-name": "pizza.com", "certificate-validity": 100}
        self.harness.set_leader(is_leader=True)

        self.harness.update_config(key_values=key_values)

        patch_revoke_all_certificates.assert_called()

    @patch("charm.generate_private_key")
    @patch("charm.generate_password")
    @patch("charm.generate_ca")
    def test_given_valid_config_when_config_changed_then_status_is_active(
        self,
        patch_generate_ca,
        patch_generate_password,
        patch_generate_private_key,
    ):
        patch_generate_ca.return_value = b"whatever CA certificate"
        patch_generate_password.return_value = "password"
        patch_generate_private_key.return_value = b"whatever private key"
        key_values = {"ca-common-name": "pizza.com", "certificate-validity": 100}
        self.harness.set_leader(is_leader=True)

        self.harness.update_config(key_values=key_values)

        self.assertEqual(self.harness.model.unit.status, ActiveStatus())

    def test_given_invalid_config_when_certificate_request_then_status_is_blocked(self):
        self.harness.set_leader(is_leader=True)
        key_values = {"ca-common-name": "pizza.com", "certificate-validity": 0}
        self.harness.update_config(key_values=key_values)

        self.harness.charm._on_certificate_creation_request(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus(
                "The following configuration values are not valid: ['certificate-validity']"
            ),
        )

    @patch("charm.generate_private_key")
    @patch("charm.generate_password")
    @patch("charm.generate_ca")
    def test_given_valid_config_and_unit_is_leader_when_secret_expired_then_new_ca_certificate_is_stored_in_juju_secret(  # noqa: E501
        self,
        patch_generate_ca,
        patch_generate_password,
        patch_generate_private_key,
    ):
        ca_certificate_string = "whatever CA certificate"
        private_key_string = "whatever private key"
        private_key_password = "banana"
        ca_certificate_bytes = ca_certificate_string.encode()
        private_key_bytes = private_key_string.encode()
        patch_generate_ca.return_value = ca_certificate_bytes
        patch_generate_password.return_value = private_key_password
        patch_generate_private_key.return_value = private_key_bytes
        self.harness.set_leader(is_leader=True)

        mock_secret_id = self.harness.add_model_secret(
            owner=self.harness.model.app.name,
            content={"secret": "whatever"},
        )
        revision = self.harness.get_secret_revisions(mock_secret_id)[0]

        self.harness.trigger_secret_expiration(secret_id=mock_secret_id, revision=revision)

        ca_certificates_secret = self.harness._backend.secret_get(label="ca-certificates")

        self.assertEqual(
            ca_certificates_secret["ca-certificate"],
            ca_certificate_string,
        )
        self.assertEqual(
            ca_certificates_secret["private-key-password"],
            private_key_password,
        )
        self.assertEqual(
            ca_certificates_secret["private-key"],
            private_key_string,
        )

    def test_given_root_certificate_not_yet_generated_when_certificate_request_then_status_is_waiting(  # noqa: E501
        self,
    ):
        self.harness.set_leader(is_leader=True)

        self.harness.charm._on_certificate_creation_request(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Root Certificate is not yet generated"),
        )

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV2.set_relation_certificate")
    @patch("charm.generate_certificate")
    def test_given_root_certificates_when_certificate_request_then_certificates_are_generated(
        self, patch_generate_certificate, patch_set_certificate
    ):
        self.harness.set_leader(is_leader=True)
        ca_certificate = "whatever CA certificate"
        private_key = "whatever private key"
        private_key_password = "whatever private_key_password"
        certificate = "new certificate"
        certificate_signing_request = "whatever CSR"
        relation_id = 123
        patch_generate_certificate.return_value = certificate.encode()

        self.harness._backend.secret_add(
            label="ca-certificates",
            content={
                "ca-certificate": ca_certificate,
                "private-key": private_key,
                "private-key-password": private_key_password,
            },
        )

        self.harness.charm._on_certificate_creation_request(
            event=Mock(
                relation_id=relation_id, certificate_signing_request=certificate_signing_request
            )
        )

        patch_set_certificate.assert_called_with(
            certificate="new certificate",
            ca=ca_certificate,
            chain=[ca_certificate, certificate],
            relation_id=relation_id,
            certificate_signing_request=certificate_signing_request,
        )

    @patch("charm.generate_private_key")
    @patch("charm.generate_password")
    @patch("charm.generate_ca")
    def test_given_initial_config_when_config_changed_then_stored_ca_common_name_uses_new_config(
        self,
        patch_generate_ca,
        patch_generate_password,
        patch_generate_private_key,
    ):
        initial_common_name = "common-name-initial.com"
        new_common_name = "common-name-new.com"
        ca_certificate_1_string = "whatever CA certificate 1"
        ca_certificate_2_string = "whatever CA certificate 2"
        private_key_string_1 = "whatever private key 1"
        private_key_string_2 = "whatever private key 2"
        private_key_password_1 = "banana"
        private_key_password_2 = "apple"
        ca_certificate_bytes_1 = ca_certificate_1_string.encode()
        ca_certificate_bytes_2 = ca_certificate_2_string.encode()
        private_key_bytes_1 = private_key_string_1.encode()
        private_key_bytes_2 = private_key_string_2.encode()
        patch_generate_ca.side_effect = [ca_certificate_bytes_1, ca_certificate_bytes_2]
        patch_generate_password.side_effect = [private_key_password_1, private_key_password_2]
        patch_generate_private_key.side_effect = [private_key_bytes_1, private_key_bytes_2]
        self.harness.set_leader(is_leader=True)
        self.harness.update_config(key_values={"ca-common-name": initial_common_name})

        self.harness.update_config(key_values={"ca-common-name": new_common_name})

        ca_certificates_secret = self.harness._backend.secret_get(label="ca-certificates")
        self.assertEqual(
            ca_certificates_secret["ca-certificate"],
            ca_certificate_2_string,
        )
        self.assertEqual(
            ca_certificates_secret["private-key-password"],
            private_key_password_2,
        )
        self.assertEqual(
            ca_certificates_secret["private-key"],
            private_key_string_2,
        )
