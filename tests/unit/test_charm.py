# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest
from datetime import datetime, timedelta
from unittest.mock import mock_open, patch

import ops
import ops.testing
from charm import SelfSignedCertificatesCharm
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateSigningRequest,
    ProviderCertificate,
    RequirerCSR,
)
from ops.model import ActiveStatus, BlockedStatus

from tests.unit.certificates_helpers import (
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)

TLS_LIB_PATH = "charms.tls_certificates_interface.v4.tls_certificates"
CA_CERT_PATH = "/tmp/ca-cert.pem"


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = ops.testing.Harness(SelfSignedCertificatesCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_leader(is_leader=True)
        self.harness.begin()
        self.mock_open = mock_open()
        self.patcher = patch("builtins.open", self.mock_open)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def test_given_invalid_config_when_config_changed_then_status_is_blocked(self):
        key_values = {"ca-common-name": "", "certificate-validity": 100}
        self.harness.update_config(key_values=key_values)

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("The following configuration values are not valid: ['ca-common-name']"),
        )

    def test_given_invalid_validity_config_when_config_changed_then_status_is_blocked(self):
        self.harness.set_leader(is_leader=True)
        key_values = {"ca-common-name": "pizza.com", "certificate-validity": 0}

        self.harness.update_config(key_values=key_values)

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus(
                "The following configuration values are not valid: ['certificate-validity']"
            ),
        )

    @patch("charm.generate_private_key")
    @patch("charm.generate_ca")
    def test_given_valid_config_when_config_changed_then_ca_certificate_is_pushed_to_charm_container(  # noqa: E501
        self,
        patch_generate_ca,
        patch_generate_private_key,
    ):
        ca_certificate_string = "whatever CA certificate"
        private_key_string = "whatever private key"
        patch_generate_ca.return_value = ca_certificate_string
        patch_generate_private_key.return_value = private_key_string
        key_values = {
            "ca-common-name": "pizza.com",
            "certificate-validity": 100,
            "root-ca-validity": 200,
        }
        self.harness.set_leader(is_leader=True)

        self.harness.update_config(key_values=key_values)
        self.mock_open.return_value.write.assert_called_with(ca_certificate_string)

    @patch("charm.generate_private_key")
    @patch("charm.generate_ca")
    def test_given_valid_config_when_config_changed_then_ca_certificate_is_stored_in_juju_secret(
        self,
        patch_generate_ca,
        patch_generate_private_key,
    ):
        ca_certificate_string = "whatever CA certificate"
        private_key_string = "whatever private key"
        patch_generate_ca.return_value = ca_certificate_string
        patch_generate_private_key.return_value = private_key_string
        key_values = {
            "ca-common-name": "pizza.com",
            "certificate-validity": 100,
            "root-ca-validity": 200,
        }
        self.harness.set_leader(is_leader=True)

        self.harness.update_config(key_values=key_values)

        ca_certificates_secret = self.harness._backend.secret_get(label="ca-certificates")
        ca_certificates_secret_expiry = self.harness._backend.secret_info_get(
            label="ca-certificates"
        ).expires

        self.assertEqual(
            ca_certificates_secret["ca-certificate"],
            ca_certificate_string,
        )
        self.assertEqual(
            ca_certificates_secret["private-key"],
            private_key_string,
        )
        self.assertEqual(
            (ca_certificates_secret_expiry - timedelta(days=200)).date(), datetime.now().date()
        )

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.revoke_all_certificates")
    @patch("charm.generate_private_key")
    @patch("charm.generate_ca")
    def test_given_valid_config_when_config_changed_then_existing_certificates_are_revoked(
        self,
        patch_generate_ca,
        patch_generate_private_key,
        patch_revoke_all_certificates,
    ):
        patch_generate_ca.return_value = "whatever CA certificate"
        patch_generate_private_key.return_value = "whatever private key"
        key_values = {"ca-common-name": "pizza.com", "certificate-validity": 100}
        self.harness.set_leader(is_leader=True)

        self.harness.update_config(key_values=key_values)

        patch_revoke_all_certificates.assert_called()

    @patch("charm.generate_private_key")
    @patch("charm.generate_ca")
    def test_given_valid_config_when_config_changed_then_status_is_active(
        self,
        patch_generate_ca,
        patch_generate_private_key,
    ):
        patch_generate_ca.return_value = "whatever CA certificate"
        patch_generate_private_key.return_value = "whatever private key"
        key_values = {"ca-common-name": "pizza.com", "certificate-validity": 100}
        self.harness.set_leader(is_leader=True)
        self.harness.update_config(key_values=key_values)

        self.harness.evaluate_status()

        self.assertEqual(self.harness.model.unit.status, ActiveStatus())

    @patch("charm.certificate_has_common_name")
    @patch("charm.generate_private_key")
    @patch("charm.generate_ca")
    def test_given_new_common_name_when_config_changed_then_new_root_ca_is_stored(
        self,
        patch_generate_ca,
        patch_generate_private_key,
        patch_certificate_has_common_name,
    ):
        validity = 100
        initial_ca = "whatever initial CA certificate"
        new_ca = "whatever CA certificate"
        private_key = "whatever private key"
        patch_certificate_has_common_name.return_value = False
        self.harness._backend.secret_add(
            label="ca-certificates",
            content={
                "ca-certificate": initial_ca,
                "private-key": private_key,
            },
        )
        patch_generate_ca.return_value = new_ca
        patch_generate_private_key.return_value = private_key

        key_values = {"ca-common-name": "pizza.com", "certificate-validity": validity}
        self.harness.set_leader(is_leader=True)

        self.harness.update_config(key_values=key_values)

        secret = self.harness.model.get_secret(label="ca-certificates")
        secret_content = secret.get_content(refresh=True)
        assert secret_content["ca-certificate"] == new_ca

    @patch("charm.certificate_has_common_name")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_certificate")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_outstanding_certificate_requests")
    @patch("charm.generate_certificate")
    def test_given_outstanding_certificate_requests_when_secret_changed_then_certificates_are_generated(  # noqa: E501
        self,
        patch_generate_certificate,
        patch_get_outstanding_certificate_requests,
        patch_set_relation_certificate,
        patch_certificate_has_common_name,
    ):
        requirer_private_key = generate_private_key()
        provider_private_key = generate_private_key()
        provider_ca = generate_ca(
            private_key=provider_private_key,
            common_name="example.com",
        )
        requirer_csr = generate_csr(private_key=requirer_private_key, common_name="example.com")
        certificate = generate_certificate(
            csr=requirer_csr,
            ca=provider_ca,
            ca_key=provider_private_key,
        )
        patch_certificate_has_common_name.return_value = True
        self.harness.set_leader(is_leader=True)
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="tls-requirer"
        )
        self.harness.add_relation_unit(relation_id=relation_id, remote_unit_name="tls-requirer/0")
        patch_get_outstanding_certificate_requests.return_value = [
            RequirerCSR(
                relation_id=relation_id,
                certificate_signing_request=CertificateSigningRequest.from_string(requirer_csr),
            ),
        ]
        patch_generate_certificate.return_value = certificate

        self.harness._backend.secret_add(
            label="ca-certificates",
            content={
                "ca-certificate": provider_ca,
                "private-key": provider_private_key,
            },
        )

        self.harness.update_config()

        expected_provider_certificate = ProviderCertificate(
            relation_id=relation_id,
            certificate=Certificate.from_string(certificate),
            certificate_signing_request=CertificateSigningRequest.from_string(requirer_csr),
            ca=Certificate.from_string(provider_ca),
            chain=[Certificate.from_string(provider_ca), Certificate.from_string(certificate)],
        )
        patch_set_relation_certificate.assert_called_with(
            provider_certificate=expected_provider_certificate,
        )

    @patch("charm.generate_private_key")
    @patch("charm.generate_ca")
    def test_given_valid_config_and_unit_is_leader_when_secret_expired_then_new_ca_certificate_is_stored_in_juju_secret(  # noqa: E501
        self,
        patch_generate_ca,
        patch_generate_private_key,
    ):
        ca_certificate_string = "whatever CA certificate"
        private_key_string = "whatever private key"
        patch_generate_ca.return_value = ca_certificate_string
        patch_generate_private_key.return_value = private_key_string
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
            ca_certificates_secret["private-key"],
            private_key_string,
        )

    @patch("charm.certificate_has_common_name")
    @patch("charm.generate_private_key")
    @patch("charm.generate_ca")
    def test_given_initial_config_when_config_changed_then_stored_ca_common_name_uses_new_config(
        self,
        patch_generate_ca,
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
        patch_generate_ca.side_effect = [ca_certificate_1_string, ca_certificate_2_string]
        patch_generate_private_key.side_effect = [private_key_string_1, private_key_string_2]
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
            secret_content["private-key"],
            private_key_string_2,
        )

    def test_given_no_certificates_issued_when_get_issued_certificates_action_then_action_fails(
        self,
    ):
        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("get-issued-certificates")

        self.assertEqual(e.exception.message, "No certificates issued yet.")

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_issued_certificates")
    def test_given_certificates_issued_when_get_issued_certificates_action_then_action_returns_certificates(  # noqa: E501
        self,
        patch_get_issued_certificates,
    ):
        ca_private_key = generate_private_key()
        ca_certificate = generate_ca(
            private_key=ca_private_key,
            common_name="example.com",
        )
        requirer_private_key = generate_private_key()
        csr = generate_csr(private_key=requirer_private_key, common_name="example.com")
        certificate = generate_certificate(
            csr=csr,
            ca=ca_certificate,
            ca_key=ca_private_key,
        )
        chain = [ca_certificate, certificate]
        revoked = False
        cert = Certificate.from_string(certificate)
        self.harness.set_leader(is_leader=True)
        patch_get_issued_certificates.return_value = [
            ProviderCertificate(
                relation_id=1,
                certificate_signing_request=CertificateSigningRequest.from_string(csr),
                certificate=cert,
                ca=Certificate.from_string(ca_certificate),
                chain=[Certificate.from_string(c) for c in chain],
                revoked=revoked,
            )
        ]

        action_output = self.harness.run_action("get-issued-certificates")

        output_certificate = json.loads(action_output.results["certificates"][0])

        assert output_certificate["csr"] == csr
        assert output_certificate["certificate"] == certificate
        assert output_certificate["ca"] == ca_certificate
        assert output_certificate["chain"] == chain
        assert output_certificate["revoked"] == revoked

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
