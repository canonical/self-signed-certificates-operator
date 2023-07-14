#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Self Signed X.509 Certificates."""

import datetime
import logging
import secrets
from typing import Optional

from charms.tls_certificates_interface.v2.tls_certificates import (  # type: ignore[import]
    CertificateCreationRequestEvent,
    TLSCertificatesProvidesV2,
    generate_ca,
    generate_certificate,
    generate_private_key,
)
from ops.charm import CharmBase, EventBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, SecretNotFoundError, WaitingStatus

logger = logging.getLogger(__name__)


CA_CERTIFICATES_SECRET_LABEL = "ca-certificates"


class SelfSignedCertificatesCharm(CharmBase):
    """Main class to handle Juju events."""

    def __init__(self, *args):
        """Observes config change and certificate request events."""
        super().__init__(*args)
        self.tls_certificates = TLSCertificatesProvidesV2(self, "certificates")
        self.framework.observe(self.on.config_changed, self._configure_ca)
        self.framework.observe(
            self.tls_certificates.on.certificate_creation_request,
            self._on_certificate_creation_request,
        )
        self.framework.observe(self.on.secret_expired, self._configure_ca)
        self.framework.observe(self.on.get_ca_cert_action, self._on_get_ca_cert)

    @property
    def _config_root_ca_certificate_validity(self) -> int:
        """Returns Root CA certificate validity (in days).

        Returns:
            int: Certificate validity (in days)
        """
        return int(self.model.config.get("root-ca-validity"))  # type: ignore[arg-type]

    @property
    def _config_certificate_validity(self) -> int:
        """Returns certificate validity (in days).

        Returns:
            int: Certificate validity (in days)
        """
        return int(self.model.config.get("certificate-validity"))  # type: ignore[arg-type]

    @property
    def _config_ca_common_name(self) -> Optional[str]:
        """Returns the user provided common name.

         This common name should only be used when the 'generate-self-signed-certificates' config
         is set to True.

        Returns:
            str: Common name
        """
        return self.model.config.get("ca-common-name", None)

    @property
    def _root_certificate_is_stored(self) -> bool:
        """Returns whether self-signed certificate is stored Juju secret.

        Returns:
            bool: Whether certificates are stored..
        """
        try:
            self.model.get_secret(label=CA_CERTIFICATES_SECRET_LABEL)
            return True
        except SecretNotFoundError:
            return False

    def _generate_root_certificate(self) -> None:
        """Generates root certificate to be used to sign certificates.

        Stores the root certificate in a juju secret.
        If the secret is already created, we simply update its content, else we create a
        new secret.
        """
        if not self._config_ca_common_name:
            raise ValueError("CA common name should not be empty")
        private_key_password = generate_password()
        private_key = generate_private_key(password=private_key_password.encode())
        ca_certificate = generate_ca(
            private_key=private_key,
            subject=self._config_ca_common_name,
            private_key_password=private_key_password.encode(),
        )
        secret_content = {
            "private-key-password": private_key_password,
            "private-key": private_key.decode(),
            "ca-certificate": ca_certificate.decode(),
        }
        if self._root_certificate_is_stored:
            secret = self.model.get_secret(label=CA_CERTIFICATES_SECRET_LABEL)
            secret.set_content(content=secret_content)
        else:
            self.app.add_secret(
                content=secret_content,
                label=CA_CERTIFICATES_SECRET_LABEL,
                expire=datetime.timedelta(days=self._config_certificate_validity),
            )
        logger.info("Root certificates generated and stored.")

    def _configure_ca(self, event: EventBase) -> None:
        """Validates configuration and generates root certificate.

        It will revoke the certificates signed by the previous root certificate.

        Args:
            event (EventBase): Juju event
        """
        if not self.unit.is_leader():
            return
        if invalid_configs := self._invalid_configs():
            self.unit.status = BlockedStatus(
                f"The following configuration values are not valid: {invalid_configs}"
            )
            return
        self._generate_root_certificate()
        self.tls_certificates.revoke_all_certificates()
        logger.info("Revoked all previously issued certificates.")
        self.unit.status = ActiveStatus()

    def _invalid_configs(self) -> list[str]:
        """Returns list of invalid configurations.

        Returns:
            list: List of invalid config keys.
        """
        invalid_configs = []
        if not self._config_ca_common_name:
            invalid_configs.append("ca-common-name")
        if not self._config_root_ca_certificate_validity:
            invalid_configs.append("root-ca-validity")
        if not self._config_certificate_validity:
            invalid_configs.append("certificate-validity")
        return invalid_configs

    def _on_certificate_creation_request(self, event: CertificateCreationRequestEvent) -> None:
        """Handler for certificate requests.

        Args:
            event (CertificateCreationRequestEvent): Jujue event
        """
        if not self.unit.is_leader():
            return
        if invalid_configs := self._invalid_configs():
            self.unit.status = BlockedStatus(
                f"The following configuration values are not valid: {invalid_configs}"
            )
            event.defer()
            return
        if not self._root_certificate_is_stored:
            self.unit.status = WaitingStatus("Root Certificate is not yet generated")
            event.defer()
            return
        ca_certificate_secret = self.model.get_secret(label=CA_CERTIFICATES_SECRET_LABEL)
        ca_certificate_secret_content = ca_certificate_secret.get_content()
        certificate = generate_certificate(
            ca=ca_certificate_secret_content["ca-certificate"].encode(),
            ca_key=ca_certificate_secret_content["private-key"].encode(),
            ca_key_password=ca_certificate_secret_content["private-key-password"].encode(),
            csr=event.certificate_signing_request.encode(),
            validity=self._config_certificate_validity,
        ).decode()
        self.tls_certificates.set_relation_certificate(
            certificate_signing_request=event.certificate_signing_request,
            certificate=certificate,
            ca=ca_certificate_secret_content["ca-certificate"],
            chain=[ca_certificate_secret_content["ca-certificate"], certificate],
            relation_id=event.relation_id,
        )
        logger.info(f"Generated certificate for relation {event.relation_id}")

    def _on_get_ca_cert(self, event):
        if not self._root_certificate_is_stored:
            event.set_results({"result": "Root Certificate is not yet generated"})
            return
        ca_certificate_secret = self.model.get_secret(label=CA_CERTIFICATES_SECRET_LABEL)
        ca_certificate_secret_content = ca_certificate_secret.get_content()
        event.set_results({"result": ca_certificate_secret_content["ca-certificate"]})


def generate_password() -> str:
    """Generates a random string containing 64 bytes.

    Returns:
        str: Password
    """
    return secrets.token_hex(64)


if __name__ == "__main__":
    main(SelfSignedCertificatesCharm)
