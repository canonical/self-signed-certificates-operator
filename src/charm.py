#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Self Signed X.509 Certificates."""

import datetime
import logging
from typing import Optional, cast

from certificates import (
    certificate_has_common_name,
    generate_ca,
    generate_certificate,
    generate_private_key,
)
from charms.certificate_transfer_interface.v0.certificate_transfer import (
    CertificateTransferProvides,
)
from charms.tempo_k8s.v1.charm_tracing import trace_charm
from charms.tempo_k8s.v2.tracing import TracingEndpointRequirer, charm_tracing_config
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateSigningRequest,
    ProviderCertificate,
    TLSCertificatesProvidesV4,
)
from ops.charm import ActionEvent, CharmBase, CollectStatusEvent, RelationJoinedEvent
from ops.framework import EventBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, SecretNotFoundError

logger = logging.getLogger(__name__)


CA_CERTIFICATES_SECRET_LABEL = "ca-certificates"
SEND_CA_CERT_REL_NAME = "send-ca-cert"  # Must match metadata
CA_CERT_STORAGE = "certs"
CA_CERT_PATH = "/tmp/ca-cert.pem"


@trace_charm(
    tracing_endpoint="_tracing_endpoint",
    server_cert="_tracing_server_cert",
    extra_types=(TLSCertificatesProvidesV4,),
)
class SelfSignedCertificatesCharm(CharmBase):
    """Main class to handle Juju events."""

    def __init__(self, *args):
        """Observe config change and certificate request events."""
        super().__init__(*args)
        self.tls_certificates = TLSCertificatesProvidesV4(self, "certificates")
        self.tracing = TracingEndpointRequirer(self, protocols=["otlp_http"])
        self._tracing_endpoint, self._tracing_server_cert = charm_tracing_config(
            self.tracing, CA_CERT_PATH
        )

        self.framework.observe(self.on.collect_unit_status, self._on_collect_unit_status)
        self.framework.observe(self.on.update_status, self._configure)
        self.framework.observe(self.on.config_changed, self._configure)
        self.framework.observe(self.on.secret_expired, self._configure)
        self.framework.observe(self.on.secret_changed, self._configure)
        self.framework.observe(self.on.certificates_relation_changed, self._configure)
        self.framework.observe(self.on.get_ca_certificate_action, self._on_get_ca_certificate)
        self.framework.observe(
            self.on.get_issued_certificates_action, self._on_get_issued_certificates
        )
        self.framework.observe(
            self.on[SEND_CA_CERT_REL_NAME].relation_joined,
            self._on_send_ca_cert_relation_joined,
        )

    def _on_collect_unit_status(self, event: CollectStatusEvent):
        """Centralized status management for the charm."""
        if not self.unit.is_leader():
            event.add_status(BlockedStatus("Scaling is not implemented for this charm"))
            return
        if invalid_configs := self._invalid_configs():
            event.add_status(
                BlockedStatus(
                    f"The following configuration values are not valid: {invalid_configs}"
                )
            )
            return
        event.add_status(ActiveStatus())

    @property
    def _config_root_ca_certificate_validity(self) -> int:
        """Return Root CA certificate validity (in days).

        Returns:
            int: Certificate validity (in days)
        """
        return int(self.model.config.get("root-ca-validity"))  # type: ignore[arg-type]

    def _on_get_issued_certificates(self, event: ActionEvent) -> None:
        """Handle get-issued-certificates action.

        Outputs the issued certificates.

        Args:
            event (ActionEvent): Juju event.

        Returns:
            event (ActionEvent): Juju event.
        """
        certificates = self.tls_certificates.get_issued_certificates()
        if not certificates:
            event.fail("No certificates issued yet.")
            return
        results = {"certificates": [certificate.to_json() for certificate in certificates]}
        event.set_results(results)

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
        return cast(Optional[str], self.model.config.get("ca-common-name", None))

    @property
    def _root_certificate_is_stored(self) -> bool:
        """Return whether self-signed certificate is stored Juju secret.

        Returns:
            bool: Whether certificates are stored..
        """
        try:
            self.model.get_secret(label=CA_CERTIFICATES_SECRET_LABEL)
            return True
        except SecretNotFoundError:
            return False

    def _generate_root_certificate(self) -> None:
        """Generate root certificate to be used to sign certificates.

        Stores the root certificate in a juju secret.
        If the secret is already created, we simply update its content, else we create a
        new secret.
        """
        if not self._config_ca_common_name:
            raise ValueError("CA common name should not be empty")
        private_key = generate_private_key()
        ca_certificate = generate_ca(
            private_key=private_key,
            subject=self._config_ca_common_name,
            validity=self._config_root_ca_certificate_validity,
        )
        self._push_ca_cert_to_container(ca_certificate)
        secret_content = {
            "private-key": private_key,
            "ca-certificate": ca_certificate,
        }
        if self._root_certificate_is_stored:
            secret = self.model.get_secret(label=CA_CERTIFICATES_SECRET_LABEL)
            secret.set_content(content=secret_content)
        else:
            self.app.add_secret(
                content=secret_content,
                label=CA_CERTIFICATES_SECRET_LABEL,
                expire=datetime.timedelta(days=self._config_root_ca_certificate_validity),
            )
        logger.info("Root certificates generated and stored.")

    def _configure(self, event: EventBase) -> None:
        """Validate configuration and generates root certificate.

        It will revoke the certificates signed by the previous root certificate.

        Args:
            event (EventBase): Juju event
        """
        if not self.unit.is_leader():
            return
        if self._invalid_configs():
            return
        if not self._root_certificate_is_stored or not self._root_certificate_matches_config():
            self._generate_root_certificate()
            self.tls_certificates.revoke_all_certificates()
            logger.info("Revoked all previously issued certificates.")
            return
        self._send_ca_cert()
        self._process_outstanding_certificate_requests()

    def _root_certificate_matches_config(self) -> bool:
        """Return whether the stored root certificate matches with the config."""
        if not self._config_ca_common_name:
            raise ValueError("CA common name should not be empty")
        ca_certificate_secret = self.model.get_secret(label=CA_CERTIFICATES_SECRET_LABEL)
        ca_certificate_secret_content = ca_certificate_secret.get_content(refresh=True)
        ca = ca_certificate_secret_content["ca-certificate"].encode()
        return certificate_has_common_name(certificate=ca, common_name=self._config_ca_common_name)

    def _process_outstanding_certificate_requests(self) -> None:
        """Process outstanding certificate requests."""
        for request in self.tls_certificates.get_outstanding_certificate_requests():
            self._generate_self_signed_certificate(
                csr=str(request.certificate_signing_request),
                is_ca=request.certificate_signing_request.is_ca,
                relation_id=request.relation_id,
            )

    def _invalid_configs(self) -> list[str]:
        """Return list of invalid configurations.

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

    def _generate_self_signed_certificate(self, csr: str, is_ca: bool, relation_id: int) -> None:
        """Generate self-signed certificate.

        Args:
            csr (str): Certificate signing request
            is_ca (bool): Whether the certificate is a CA
            relation_id (int): Relation id
        """
        ca_certificate_secret = self.model.get_secret(label=CA_CERTIFICATES_SECRET_LABEL)
        ca_certificate_secret_content = ca_certificate_secret.get_content(refresh=True)
        certificate = generate_certificate(
            ca=ca_certificate_secret_content["ca-certificate"],
            ca_key=ca_certificate_secret_content["private-key"],
            csr=csr,
            validity=self._config_certificate_validity,
            is_ca=is_ca,
        )
        self.tls_certificates.set_relation_certificate(
            provider_certificate=ProviderCertificate(
                relation_id=relation_id,
                certificate=Certificate.from_string(certificate),
                certificate_signing_request=CertificateSigningRequest.from_string(csr),
                ca=Certificate.from_string(ca_certificate_secret_content["ca-certificate"]),
                chain=[
                    Certificate.from_string(ca_certificate_secret_content["ca-certificate"]),
                    Certificate.from_string(certificate),
                ],
            ),
        )
        logger.info("Generated certificate for relation %s", relation_id)

    def _on_get_ca_certificate(self, event: ActionEvent):
        """Handle the get-ca-certificate action.

        Args:
            event (ActionEvent): Juju event
        """
        if not self._root_certificate_is_stored:
            event.fail("Root Certificate is not yet generated")
            return
        ca_certificate_secret = self.model.get_secret(label=CA_CERTIFICATES_SECRET_LABEL)
        ca_certificate_secret_content = ca_certificate_secret.get_content(refresh=True)
        event.set_results({"ca-certificate": ca_certificate_secret_content["ca-certificate"]})

    def _on_send_ca_cert_relation_joined(self, event: RelationJoinedEvent):
        self._send_ca_cert(rel_id=event.relation.id)

    def _send_ca_cert(self, *, rel_id=None):
        """There is one (and only one) CA cert that we need to forward to multiple apps.

        Args:
            rel_id: Relation id. If not given, update all relations.
        """
        send_ca_cert = CertificateTransferProvides(self, SEND_CA_CERT_REL_NAME)
        if self._root_certificate_is_stored:
            secret = self.model.get_secret(label=CA_CERTIFICATES_SECRET_LABEL)
            secret_content = secret.get_content(refresh=True)
            ca = secret_content["ca-certificate"]
            if rel_id:
                send_ca_cert.set_certificate("", ca, [], relation_id=rel_id)
            else:
                for relation in self.model.relations.get(SEND_CA_CERT_REL_NAME, []):
                    send_ca_cert.set_certificate("", ca, [], relation_id=relation.id)
        else:
            for relation in self.model.relations.get(SEND_CA_CERT_REL_NAME, []):
                send_ca_cert.remove_certificate(relation.id)

    def _push_ca_cert_to_container(self, ca_certificate: str):
        """Store the CA certificate in the charm container.

        Args:
            ca_certificate: PEM String of the CA cert.
        """
        with open(CA_CERT_PATH, "w") as f:
            f.write(ca_certificate)


if __name__ == "__main__":
    main(SelfSignedCertificatesCharm)
