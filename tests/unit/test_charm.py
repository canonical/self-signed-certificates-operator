# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest
from datetime import datetime
from unittest.mock import Mock, patch

import ops
import ops.testing
from charm import SelfSignedCertificatesCharm
from charms.tls_certificates_interface.v3.tls_certificates import ProviderCertificate, RequirerCSR
from ops.model import ActiveStatus, BlockedStatus

TLS_LIB_PATH = "charms.tls_certificates_interface.v3.tls_certificates"


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = ops.testing.Harness(SelfSignedCertificatesCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_leader(is_leader=True)
        self.harness.begin()

    def test_given_invalid_config_when_config_changed_then_status_is_blocked(self):
        key_values = {"ca-common-name": "", "certificate-validity": 100}
        self.harness.update_config(key_values=key_values)

        self.harness.evaluate_status()

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

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV3.revoke_all_certificates")
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

        self.harness.evaluate_status()

        self.assertEqual(self.harness.model.unit.status, ActiveStatus())

    @patch("charm.certificate_has_common_name")
    @patch("charm.generate_private_key")
    @patch("charm.generate_password")
    @patch("charm.generate_ca")
    def test_given_new_common_name_when_config_changed_then_new_root_ca_is_stored(
        self,
        patch_generate_ca,
        patch_generate_password,
        patch_generate_private_key,
        patch_certificate_has_common_name,
    ):
        validity = 100
        initial_ca = "whatever initial CA certificate"
        new_ca = "whatever CA certificate"
        private_key_password = "password"
        private_key = "whatever private key"
        patch_certificate_has_common_name.return_value = False
        self.harness._backend.secret_add(
            label="ca-certificates",
            content={
                "ca-certificate": initial_ca,
                "private-key": private_key,
                "private-key-password": private_key_password,
            },
        )
        patch_generate_ca.return_value = new_ca.encode()
        patch_generate_password.return_value = private_key_password
        patch_generate_private_key.return_value = private_key.encode()

        key_values = {"ca-common-name": "pizza.com", "certificate-validity": validity}
        self.harness.set_leader(is_leader=True)

        self.harness.update_config(key_values=key_values)

        secret = self.harness.model.get_secret(label="ca-certificates")
        secret_content = secret.get_content(refresh=True)
        assert secret_content["ca-certificate"] == new_ca

    @patch("charm.certificate_has_common_name")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV3.set_relation_certificate")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV3.get_outstanding_certificate_requests")
    @patch("charm.generate_certificate")
    def test_given_outstanding_certificate_requests_when_secret_changed_then_certificates_are_generated(  # noqa: E501
        self,
        patch_generate_certificate,
        patch_get_outstanding_certificate_requests,
        patch_set_relation_certificate,
        patch_certificate_has_common_name,
    ):
        private_key = "whatever"
        private_key_password = "whatever"
        ca = "whatever CA certificate"
        requirer_csr = "whatever CSR"
        requirer_is_ca = False
        generated_certificate = "whatever certificate"
        patch_certificate_has_common_name.return_value = True
        self.harness.set_leader(is_leader=True)
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="tls-requirer"
        )
        self.harness.add_relation_unit(relation_id=relation_id, remote_unit_name="tls-requirer/0")
        patch_get_outstanding_certificate_requests.return_value = [
            RequirerCSR(
                relation_id=relation_id,
                application_name="tls-requirer",
                unit_name="tls-requirer/0",
                csr=requirer_csr,
                is_ca=requirer_is_ca,
            ),
        ]
        patch_generate_certificate.return_value = generated_certificate.encode()

        self.harness._backend.secret_add(
            label="ca-certificates",
            content={
                "ca-certificate": ca,
                "private-key": private_key,
                "private-key-password": private_key_password,
            },
        )

        self.harness.update_config()

        patch_set_relation_certificate.assert_called_with(
            certificate_signing_request=requirer_csr,
            certificate=generated_certificate,
            ca=ca,
            chain=[ca, generated_certificate],
            relation_id=relation_id,
        )

    def test_given_invalid_config_when_certificate_request_then_status_is_blocked(self):
        self.harness.set_leader(is_leader=True)
        key_values = {"ca-common-name": "pizza.com", "certificate-validity": 0}
        self.harness.update_config(key_values=key_values)
        self.harness.charm._on_certificate_creation_request(event=Mock())  # type: ignore[reportAttributeAccessIssue]

        self.harness.evaluate_status()

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

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV3.set_relation_certificate")
    @patch("charm.generate_certificate")
    def test_given_root_certificates_when_certificate_request_then_certificates_are_generated(
        self, patch_generate_certificate, patch_set_certificate
    ):
        is_ca = True
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

        self.harness.charm._on_certificate_creation_request(  # type: ignore[reportAttributeAccessIssue]
            event=Mock(
                relation_id=relation_id,
                certificate_signing_request=certificate_signing_request,
                is_ca=is_ca,
            )
        )

        patch_generate_certificate.assert_called_with(
            ca=ca_certificate.encode(),
            ca_key=private_key.encode(),
            ca_key_password=private_key_password.encode(),
            csr=certificate_signing_request.encode(),
            validity=365,
            is_ca=is_ca,
        )
        patch_set_certificate.assert_called_with(
            certificate="new certificate",
            ca=ca_certificate,
            chain=[ca_certificate, certificate],
            relation_id=relation_id,
            certificate_signing_request=certificate_signing_request,
        )

    @patch("charm.certificate_has_common_name")
    @patch("charm.generate_private_key")
    @patch("charm.generate_password")
    @patch("charm.generate_ca")
    def test_given_initial_config_when_config_changed_then_stored_ca_common_name_uses_new_config(
        self,
        patch_generate_ca,
        patch_generate_password,
        patch_generate_private_key,
        patch_certificate_has_common_name,
    ):
        patch_certificate_has_common_name.return_value = False
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

        ca_certificates_secret = self.harness.model.get_secret(label="ca-certificates")

        secret_content = ca_certificates_secret.get_content(refresh=True)
        self.assertEqual(
            secret_content["ca-certificate"],
            ca_certificate_2_string,
        )
        self.assertEqual(
            secret_content["private-key-password"],
            private_key_password_2,
        )
        self.assertEqual(
            secret_content["private-key"],
            private_key_string_2,
        )

    def test_given_no_certificates_issued_when_get_issued_certificates_action_then_action_fails(
        self,
    ):
        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("get-issued-certificates")

        self.assertEqual(e.exception.message, "No certificates issued yet.")

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV3.get_issued_certificates")
    def test_given_certificates_issued_when_get_issued_certificates_action_then_action_returns_certificates(  # noqa: E501
        self,
        patch_get_issued_certificates,
    ):
        relation_id = 123
        application_name = "tls-requirer"
        csr = "whatever csr"
        certificate = "whatever certificate"
        ca_certificate = "whatever CA certificate"
        chain = ["whatever cert 1", "whatever cert 2"]
        revoked = False
        expiry_time = datetime.now()
        expiry_notification_time = None
        self.harness.set_leader(is_leader=True)
        patch_get_issued_certificates.return_value = [
            ProviderCertificate(
                relation_id=relation_id,
                application_name=application_name,
                csr=csr,
                certificate=certificate,
                ca=ca_certificate,
                chain=chain,
                revoked=revoked,
                expiry_time=expiry_time,
                expiry_notification_time=expiry_notification_time,
            )
        ]

        action_output = self.harness.run_action("get-issued-certificates")

        expected_certificates = {
            "certificates": [
                json.dumps(
                    {
                        "relation_id": relation_id,
                        "application_name": application_name,
                        "csr": csr,
                        "certificate": certificate,
                        "ca": ca_certificate,
                        "chain": chain,
                        "revoked": revoked,
                        "expiry_time": expiry_time.isoformat(),
                        "expiry_notification_time": expiry_notification_time,
                    }
                )
            ]
        }

        self.assertEqual(action_output.results, expected_certificates)

    def test_given_ca_cert_generated_when_get_ca_certificate_action_then_returns_ca_certificate(
        self,
    ):
        self.harness.set_leader(is_leader=True)
        ca_certificate = "whatever CA certificate"

        self.harness._backend.secret_add(
            label="ca-certificates",
            content={
                "ca-certificate": ca_certificate,
                "private-key": "whatever private key",
                "private-key-password": "whatever private_key_password",
            },
        )

        action_output = self.harness.run_action("get-ca-certificate")
        expected_certificate = {
            "ca-certificate": ca_certificate,
        }

        self.assertEqual(action_output.results, expected_certificate)

    def test_given_ca_cert_not_generated_when_get_ca_certificate_action_then_action_fails(self):
        self.harness.set_leader(is_leader=True)

        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("get-ca-certificate")

        self.assertEqual(e.exception.message, "Root Certificate is not yet generated")
