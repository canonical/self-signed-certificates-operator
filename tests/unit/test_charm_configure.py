# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

from datetime import datetime, timedelta
from unittest.mock import mock_open, patch

import pytest
import scenario
from charms.tls_certificates_interface.v4.tls_certificates import (
    ProviderCertificate,
    RequirerCSR,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)

from charm import SelfSignedCertificatesCharm
from constants import (
    CA_CERTIFICATES_SECRET_LABEL,
    EXPIRING_CA_CERTIFICATES_SECRET_LABEL,
    TLS_LIB_PATH,
)


class TestCharmConfigure:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.mock_open = mock_open()
        self.patcher = patch("builtins.open", self.mock_open)
        self.patcher.start()

    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = scenario.Context(
            charm_type=SelfSignedCertificatesCharm,
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
        state_in = scenario.State(
            config={
                "ca-common-name": "pizza.example.com",
                "certificate-validity": "100",
                "root-ca-validity": "200",
            },
            leader=True,
        )

        self.ctx.run(self.ctx.on.config_changed(), state=state_in)

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

        certificate_validity = 100
        root_ca_validity = 200
        state_in = scenario.State(
            config={
                "ca-common-name": "pizza.example.com",
                "certificate-validity": str(certificate_validity),
                "root-ca-validity": str(root_ca_validity),
            },
            leader=True,
        )

        state_out = self.ctx.run(self.ctx.on.config_changed(), state=state_in)
        ca_certificates_secret = state_out.get_secret(label=CA_CERTIFICATES_SECRET_LABEL)
        content = ca_certificates_secret.tracked_content
        assert content["ca-certificate"] == ca_certificate_string
        assert content["private-key"] == private_key_string
        ca_certificates_secret_expiry = ca_certificates_secret.expire
        assert ca_certificates_secret_expiry
        expected_delta = timedelta(days=root_ca_validity - certificate_validity)
        actual_delta = ca_certificates_secret_expiry - datetime.now()
        tolerance = timedelta(seconds=1)
        assert (
            abs(actual_delta - expected_delta) <= tolerance
        ), f"Expected: {expected_delta}, but got: {actual_delta}"

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.revoke_all_certificates")
    @patch("charm.generate_private_key")
    @patch("charm.generate_ca")
    def test_given_root_certificate_not_stored_when_config_changed_then_existing_certificates_are_revoked(  # noqa: E501
        self,
        patch_generate_ca,
        patch_generate_private_key,
        patch_revoke_all_certificates,
    ):
        patch_generate_ca.return_value = "whatever CA certificate"
        patch_generate_private_key.return_value = "whatever private key"
        state_in = scenario.State(
            config={
                "ca-common-name": "pizza.example.com",
                "certificate-validity": "100",
            },
            leader=True,
            secrets=frozenset(),
        )

        self.ctx.run(self.ctx.on.config_changed(), state=state_in)

        assert patch_revoke_all_certificates.called

    @patch("charm.generate_private_key")
    @patch("charm.generate_ca")
    def test_given_new_root_ca_config_when_config_changed_then_new_root_ca_is_replaced(
        self,
        patch_generate_ca,
        patch_generate_private_key,
    ):
        ca_private_key = generate_private_key()
        initial_ca_certificate = generate_ca(
            private_key=ca_private_key,
            common_name="initial.example.com",
            validity=timedelta(days=100),
        )
        new_ca = generate_ca(
            private_key=ca_private_key,
            common_name="new.example.com",
            validity=timedelta(days=100),
        )
        patch_generate_ca.return_value = new_ca
        patch_generate_private_key.return_value = ca_private_key
        ca_certificate_secret = scenario.Secret(
            {
                "ca-certificate": str(initial_ca_certificate),
                "private-key": str(ca_private_key),
            },
            label=CA_CERTIFICATES_SECRET_LABEL,
            owner="app",
            expire=datetime.now() + timedelta(days=100),
        )
        state_in = scenario.State(
            config={
                "ca-common-name": "pizza.example.com",
                "ca-email-address": "abc@example.com",
                "ca-country-name": "CA",
                "ca-locality-name": "Montreal",
                "certificate-validity": "100",
                "root-ca-validity": "200",
            },
            leader=True,
            secrets={ca_certificate_secret},
        )

        state_out = self.ctx.run(self.ctx.on.config_changed(), state=state_in)

        ca_certificates_secret = state_out.get_secret(label=CA_CERTIFICATES_SECRET_LABEL)
        secret_content = ca_certificates_secret.latest_content
        assert secret_content is not None
        assert secret_content["ca-certificate"] == str(new_ca)
        patch_generate_ca.assert_called_with(
            private_key=ca_private_key,
            common_name="pizza.example.com",
            organization=None,
            organizational_unit=None,
            email_address="abc@example.com",
            country_name="CA",
            state_or_province_name=None,
            locality_name="Montreal",
            validity=timedelta(days=200),
        )

    @patch("charm.generate_private_key")
    @patch("charm.generate_ca")
    def test_given_root_ca_about_to_expire_then_root_ca_is_marked_expiring_and_new_one_is_generated(  # noqa: E501
        self,
        patch_generate_ca,
        patch_generate_private_key,
    ):
        initial_ca_private_key = generate_private_key()
        new_ca_private_key = generate_private_key()
        initial_ca_certificate = generate_ca(
            private_key=initial_ca_private_key,
            common_name="example.com",
            validity=timedelta(minutes=2),
        )
        new_ca_certificate = generate_ca(
            private_key=new_ca_private_key,
            common_name="example.com",
            validity=timedelta(minutes=2),
        )
        patch_generate_ca.return_value = new_ca_certificate
        patch_generate_private_key.return_value = new_ca_private_key
        ca_certificate_secret = scenario.Secret(
            {
                "ca-certificate": str(initial_ca_certificate),
                "private-key": str(initial_ca_private_key),
            },
            label=CA_CERTIFICATES_SECRET_LABEL,
            owner="app",
            expire=datetime.now() + timedelta(milliseconds=1),
        )
        state_in = scenario.State(
            config={
                "ca-common-name": "example.com",
                "root-ca-validity": "2m",
                "certificate-validity": "1m",
            },
            leader=True,
            secrets={ca_certificate_secret},
        )

        state_out = self.ctx.run(self.ctx.on.config_changed(), state=state_in)

        ca_certificates_secret = state_out.get_secret(label=CA_CERTIFICATES_SECRET_LABEL)

        secret_content = ca_certificates_secret.latest_content
        expiring_ca_certificates_secret = state_out.get_secret(
            label=EXPIRING_CA_CERTIFICATES_SECRET_LABEL
        )
        expiring_secret_content = expiring_ca_certificates_secret.latest_content
        assert expiring_secret_content is not None
        assert secret_content is not None
        assert secret_content["ca-certificate"] == str(new_ca_certificate)
        assert secret_content["private-key"] == str(new_ca_private_key)
        assert expiring_secret_content["ca-certificate"] == str(initial_ca_certificate)
        assert expiring_secret_content["private-key"] == str(initial_ca_private_key)
        assert expiring_ca_certificates_secret.expire
        tolerance = timedelta(seconds=1)
        assert (
            abs(expiring_ca_certificates_secret.expire - (datetime.now() + timedelta(minutes=1)))
            <= tolerance
        )

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_certificate")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_outstanding_certificate_requests")
    @patch("charm.generate_certificate")
    def test_given_outstanding_certificate_requests_when_config_changed_then_certificates_are_generated(  # noqa: E501
        self,
        patch_generate_certificate,
        patch_get_outstanding_certificate_requests,
        patch_set_relation_certificate,
    ):
        requirer_private_key = generate_private_key()
        provider_private_key = generate_private_key()
        provider_ca = generate_ca(
            private_key=provider_private_key,
            common_name="example.com",
            validity=timedelta(days=200),
        )
        requirer_csr = generate_csr(private_key=requirer_private_key, common_name="example.com")
        certificate = generate_certificate(
            csr=requirer_csr,
            ca=provider_ca,
            ca_private_key=provider_private_key,
            validity=timedelta(days=100),
        )
        tls_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        ca_certificate_secret = scenario.Secret(
            {
                "ca-certificate": str(provider_ca),
                "private-key": str(provider_private_key),
            },
            label=CA_CERTIFICATES_SECRET_LABEL,
            owner="app",
            expire=datetime.now() + timedelta(days=100),
        )
        patch_get_outstanding_certificate_requests.return_value = [
            RequirerCSR(
                relation_id=tls_relation.id,
                certificate_signing_request=requirer_csr,
                is_ca=False,
            ),
        ]
        patch_generate_certificate.return_value = certificate
        state_in = scenario.State(
            config={
                "ca-common-name": "example.com",
                "certificate-validity": "100",
                "root-ca-validity": "200",
            },
            leader=True,
            relations={tls_relation},
            secrets={ca_certificate_secret},
        )

        self.ctx.run(self.ctx.on.config_changed(), state=state_in)

        expected_provider_certificate = ProviderCertificate(
            relation_id=tls_relation.id,
            certificate=certificate,
            certificate_signing_request=requirer_csr,
            ca=provider_ca,
            chain=[provider_ca, certificate],
        )
        patch_set_relation_certificate.assert_called_with(
            provider_certificate=expected_provider_certificate,
        )

    @pytest.mark.skip(reason="https://github.com/canonical/operator/issues/1316")
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

        ca_certificates_secret = scenario.Secret(
            {
                "ca-certificate": "whatever initial CA certificate",
                "private-key": private_key_string,
            },
            label=CA_CERTIFICATES_SECRET_LABEL,
            owner="app",
            expire=datetime.now(),
        )
        state_in = scenario.State(
            config={
                "ca-common-name": "pizza.example.com",
                "certificate-validity": "100",
            },
            leader=True,
            secrets={ca_certificates_secret},
        )

        state_out = self.ctx.run(
            self.ctx.on.secret_expired(secret=ca_certificates_secret, revision=1), state=state_in
        )

        ca_certificates_secret = state_out.get_secret(
            label=CA_CERTIFICATES_SECRET_LABEL
        ).latest_content

        assert ca_certificates_secret is not None
        assert ca_certificates_secret["ca-certificate"] == ca_certificate_string
        assert ca_certificates_secret["private-key"] == private_key_string

    @patch("charm.generate_private_key")
    @patch("charm.generate_ca")
    def test_given_initial_config_when_config_changed_then_stored_ca_common_name_uses_new_config(
        self,
        patch_generate_ca,
        patch_generate_private_key,
    ):
        initial_ca_private_key = generate_private_key()
        new_ca_private_key = generate_private_key()
        initial_ca_certificate = generate_ca(
            private_key=initial_ca_private_key,
            common_name="common-name-initial.example.com",
            validity=timedelta(days=100),
        )
        new_ca_certificate = generate_ca(
            private_key=new_ca_private_key,
            common_name="common-name-new.example.com",
            validity=timedelta(days=100),
        )
        patch_generate_ca.return_value = new_ca_certificate
        patch_generate_private_key.return_value = new_ca_private_key

        ca_certificates_secret = scenario.Secret(
            {
                "ca-certificate": str(initial_ca_certificate),
                "private-key": str(initial_ca_private_key),
            },
            label=CA_CERTIFICATES_SECRET_LABEL,
            owner="app",
            expire=datetime.now() + timedelta(days=100),
        )
        state_in = scenario.State(
            config={
                "ca-common-name": "common-name-new.example.com",
                "certificate-validity": "100",
            },
            leader=True,
            secrets={ca_certificates_secret},
        )

        state_out = self.ctx.run(self.ctx.on.config_changed(), state=state_in)

        ca_certificates_secret = state_out.get_secret(
            label=CA_CERTIFICATES_SECRET_LABEL
        ).latest_content
        assert ca_certificates_secret is not None
        assert ca_certificates_secret["ca-certificate"] == str(new_ca_certificate)
        assert ca_certificates_secret["private-key"] == str(new_ca_private_key)

    def test_given_certificate_transfer_relations_when_configure_then_ca_cert_is_advertised(self):
        traefik_relation = scenario.Relation(
            endpoint="send-ca-cert",
            interface="certificate_transfer",
        )
        another_relation = scenario.Relation(
            endpoint="send-ca-cert",
            interface="certificate_transfer",
        )
        provider_private_key = generate_private_key()
        provider_ca = generate_ca(
            private_key=provider_private_key,
            common_name="example.com",
            validity=timedelta(days=200),
        )
        secret = scenario.Secret(
            {
                "ca-certificate": str(provider_ca),
                "private-key": str(provider_private_key),
            },
            label=CA_CERTIFICATES_SECRET_LABEL,
            owner="app",
            expire=datetime.now() + timedelta(days=100),
        )
        state_in = scenario.State(
            relations={traefik_relation, another_relation},
            secrets={secret},
            leader=True,
            config={
                "ca-common-name": "example.com",
                "certificate-validity": "100",
                "root-ca-validity": "200",
            },
        )

        state_out = self.ctx.run(self.ctx.on.config_changed(), state=state_in)

        assert state_out.get_relation(traefik_relation.id).local_unit_data["ca"] == str(
            provider_ca
        )
        assert state_out.get_relation(another_relation.id).local_unit_data["ca"] == str(
            provider_ca
        )
