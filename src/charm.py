#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Self Signed X.509 Certificates."""

import logging
import typing
from datetime import datetime, timedelta
from typing import Iterator, Optional, cast

from charms.certificate_transfer_interface.v0.certificate_transfer import (
    CertificateTransferProvides,
)
from charms.tempo_coordinator_k8s.v0.charm_tracing import trace_charm
from charms.tempo_coordinator_k8s.v0.tracing import TracingEndpointRequirer, charm_tracing_config
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateSigningRequest,
    PrivateKey,
    ProviderCertificate,
    RequirerCertificateRequest,
    TLSCertificatesProvidesV4,
    generate_ca,
    generate_certificate,
    generate_private_key,
)
from ops.charm import ActionEvent, CharmBase, CollectStatusEvent
from ops.framework import EventBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, SecretNotFoundError

from constants import (
    CA_CERT_PATH,
    CA_CERTIFICATES_SECRET_LABEL,
    EXPIRING_CA_CERTIFICATES_SECRET_LABEL,
    SEND_CA_CERT_REL_NAME,
)

logger = logging.getLogger(__name__)


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
        configure_events = [
            self.on.update_status,
            self.on.config_changed,
            self.on.secret_changed,
            self.on.certificates_relation_changed,
            self.on.secret_expired,
        ]
        for event in configure_events:
            self.framework.observe(event, self._configure)
        self.framework.observe(self.on.get_ca_certificate_action, self._on_get_ca_certificate)
        self.framework.observe(
            self.on.get_issued_certificates_action, self._on_get_issued_certificates
        )
        self.framework.observe(
            self.on[SEND_CA_CERT_REL_NAME].relation_joined,
            self._configure,
        )
        self.framework.observe(self.on.rotate_private_key_action, self._on_rotate_private_key)

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

    def _is_ca_cert_active(self) -> bool:
        """Return whether the CA certificate is active by checking the secret expiry."""
        secret = self.model.get_secret(label=CA_CERTIFICATES_SECRET_LABEL)
        secret_info = secret.get_info()
        if not secret_info.expires:
            return False
        if secret_info.expires.tzinfo is None:
            return secret_info.expires > datetime.now()
        return secret_info.expires > datetime.now(secret_info.expires.tzinfo)

    @property
    def _config_root_ca_certificate_validity(self) -> timedelta | None:
        """Return Root CA certificate validity from the charm config as a timedelta object."""
        try:
            validity = self._parse_config_time_string(
                str(self.model.config.get("root-ca-validity", ""))
            )
        except ValueError:
            logger.warning('config option "certificate-validity" is invalid.', exc_info=True)
            return None
        return validity

    @property
    def _config_certificate_validity(self) -> timedelta | None:
        """Returns certificate validity from the charm config as a timedelta object."""
        try:
            validity = self._parse_config_time_string(
                str(self.model.config.get("certificate-validity", ""))
            )
        except ValueError:
            logger.warning('config option "certificate-validity" is invalid.', exc_info=True)
            return None
        return validity

    @property
    def _config_certificate_limit(self) -> int | None:
        """Return certificate number limit from the charm config."""
        value = self.model.config.get("certificate-limit")
        if not value or not isinstance(value, int):
            return None
        return value

    @property
    def _ca_certificate_renewal_threshold(self) -> timedelta | None:
        """Return CA certificate renewal threshold.

        Which is the time difference between the validity of the root certificate
        and issued certificates.
        For example if the CA is valid for 365 days,
        and the issued certificates are valid for 90 days,
        the renewal threshold will be 275 days.
        This is important so the CA does not expire during the issued certificate validity.
        """
        if not self._config_root_ca_certificate_validity or not self._config_certificate_validity:
            logger.warning("No root CA certificate validity or certificate validity set")
            return None
        return self._config_root_ca_certificate_validity - self._config_certificate_validity

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

    def _on_rotate_private_key(self, event: ActionEvent):
        """Handle the rotate-private-key action.

        Creates a new private key and a new CA certificate and revokes all issued certificates.

        Args:
            event (ActionEvent): Juju event
        """
        if not self.unit.is_leader():
            event.fail("This action can only be run on the leader unit.")
            return
        self.tls_certificates.revoke_all_certificates()
        logger.info("Revoked all previously issued certificates.")
        self._clean_up_juju_secret(EXPIRING_CA_CERTIFICATES_SECRET_LABEL)
        if not self._generate_root_certificate():
            event.fail(
                "Private key rotation failed due to missing configuration.\
                Please check your configuration and try again.\
                Certificates have been revoked."
            )
            return
        event.set_results({"result": "New private key and CA certificate generated and stored."})

    def _parse_config_time_string(self, time_str: str) -> timedelta:
        """Parse a given time string.

        It must be a number followed by either an
        m for minutes, h for hours, d for days or y for years.

        Args:
            time_str: the input string. Ex: "15m", "365d", "10w"
                or "10" and will be converted to days
        Returns:
            timedelta object representing the given string
        """
        if time_str.isnumeric():
            return timedelta(days=int(time_str))
        value, unit = int(time_str[:-1]), time_str[-1]
        if unit == "m":
            return timedelta(minutes=value)
        elif unit == "h":
            return timedelta(hours=value)
        elif unit == "d":
            return timedelta(days=value)
        elif unit == "w":
            return timedelta(weeks=value)
        raise ValueError(f"unsupported time string format: {time_str}")

    @property
    def _config_ca_common_name(self) -> Optional[str]:
        return cast(Optional[str], self.model.config.get("ca-common-name", None))

    @property
    def _config_ca_organization(self) -> Optional[str]:
        return cast(Optional[str], self.model.config.get("ca-organization", None))

    @property
    def _config_ca_organizational_unit(self) -> Optional[str]:
        return cast(Optional[str], self.model.config.get("ca-organizational-unit", None))

    @property
    def _config_ca_email_address(self) -> Optional[str]:
        return cast(Optional[str], self.model.config.get("ca-email-address", None))

    @property
    def _config_ca_country_name(self) -> Optional[str]:
        return cast(Optional[str], self.model.config.get("ca-country-name", None))

    @property
    def _config_ca_state_or_province_name(self) -> Optional[str]:
        return cast(Optional[str], self.model.config.get("ca-state-or-province-name", None))

    @property
    def _config_ca_locality_name(self) -> Optional[str]:
        return cast(Optional[str], self.model.config.get("ca-locality-name", None))

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

    def _generate_root_certificate(self) -> bool:
        """Generate root certificate to be used to sign certificates.

        Stores the root certificate in a juju secret.
        If the secret is already created, we simply update its content, else we create a
        new secret.

        Returns:
            bool: Whether the root certificate was generated and stored successfully.
        """
        if (
            not self._config_ca_common_name
            or not self._config_root_ca_certificate_validity
            or not self._config_certificate_validity
            or not self._ca_certificate_renewal_threshold
        ):
            logger.warning("Missing configuration for root CA certificate")
            return False
        private_key = generate_private_key()
        ca_certificate = generate_ca(
            private_key=private_key,
            common_name=self._config_ca_common_name,
            organization=self._config_ca_organization,
            organizational_unit=self._config_ca_organizational_unit,
            email_address=self._config_ca_email_address,
            country_name=self._config_ca_country_name,
            state_or_province_name=self._config_ca_state_or_province_name,
            locality_name=self._config_ca_locality_name,
            validity=self._config_root_ca_certificate_validity,
        )
        self._push_ca_cert_to_container(str(ca_certificate))
        secret_content = {
            "private-key": str(private_key),
            "ca-certificate": str(ca_certificate),
        }
        self._set_juju_secret(
            label=CA_CERTIFICATES_SECRET_LABEL,
            content=secret_content,
            expire=self._ca_certificate_renewal_threshold,
        )
        logger.info("Root certificates generated and stored.")
        return True

    def _configure(self, _: EventBase) -> None:
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
            self.tls_certificates.revoke_all_certificates()
            logger.info("Revoked all previously issued certificates.")
            self._clean_up_juju_secret(EXPIRING_CA_CERTIFICATES_SECRET_LABEL)
            self._generate_root_certificate()
            return
        if not self._is_ca_cert_active():
            logger.info("Renewing CA certificate")
            self._renew_root_certificate()
            return
        self._send_ca_cert()
        self._process_outstanding_certificate_requests()

    def _renew_root_certificate(self):
        """Generate a new active root CA certificate.

        If there is a CA certificate that is about to expire,
        move it to the expiring-ca-certificate secret.
        Generate a new active CA certificate
        """
        if not self.unit.is_leader():
            return
        self._move_active_ca_cert_to_expiring()
        self._generate_root_certificate()

    def _move_active_ca_cert_to_expiring(self):
        """Make current active CA certificate expiring.

        CA certificate is moved to the secret holding expiring CA certificates.
        The validity of the expiring CA can't be shorter than
            the validity of the issued certificates.
        """
        if (
            not self._config_ca_common_name
            or not self._config_root_ca_certificate_validity
            or not self._config_certificate_validity
            or not self._ca_certificate_renewal_threshold
        ):
            logger.warning("Missing configuration for expiring CA certificate")
            return
        try:
            current_active_ca_cert_secret = self.model.get_secret(
                label=CA_CERTIFICATES_SECRET_LABEL
            )
            current_active_ca_cert_secret_content = current_active_ca_cert_secret.get_content(
                refresh=True
            )
        except SecretNotFoundError:
            logger.warning("No active CA certificate found to move to expiring")
            return
        self._set_juju_secret(
            label=EXPIRING_CA_CERTIFICATES_SECRET_LABEL,
            content=current_active_ca_cert_secret_content,
            expire=self._config_certificate_validity,
        )

    def _set_juju_secret(self, label: str, content: dict[str, str], expire: timedelta) -> None:
        """Create or update a juju secret."""
        try:
            secret = self.model.get_secret(label=label)
            date_time_expire = datetime.now() + expire
            # TODO, Workaround for https://github.com/canonical/operator/issues/1288
            secret._backend.secret_set(
                typing.cast(str, secret.get_info().id),
                content=content,
                expire=date_time_expire,
                label=label,
            )
        except SecretNotFoundError:
            self.app.add_secret(content=content, label=label, expire=expire)

    def _root_certificate_matches_config(self) -> bool:
        """Return whether the stored root certificate matches with the config."""
        if not self._config_ca_common_name:
            raise ValueError("CA common name should not be empty")
        ca_certificate_secret = self.model.get_secret(label=CA_CERTIFICATES_SECRET_LABEL)
        ca_certificate_secret_content = ca_certificate_secret.get_content(refresh=True)
        ca = ca_certificate_secret_content["ca-certificate"]
        certificate = Certificate.from_string(ca)
        configured_root_ca_validity = (
            certificate.expiry_time - certificate.validity_start_time
            if certificate.validity_start_time and certificate.expiry_time
            else timedelta(days=0)
        )

        return (
            self._config_ca_common_name == certificate.common_name
            and self._config_ca_organization == certificate.organization
            and self._config_ca_organizational_unit == certificate.organizational_unit
            and self._config_ca_email_address == certificate.email_address
            and self._config_ca_country_name == certificate.country_name
            and self._config_ca_state_or_province_name == certificate.state_or_province_name
            and self._config_ca_locality_name == certificate.locality_name
            and self._config_root_ca_certificate_validity == configured_root_ca_validity
        )

    def _clean_up_juju_secret(self, label: str):
        """Remove the secret with the given label."""
        try:
            expiring_ca_secret = self.model.get_secret(label=label)
            expiring_ca_secret.remove_all_revisions()
        except SecretNotFoundError:
            logger.info("Secret %s not found, skipping clean up", label)
            return
        return

    def _process_outstanding_certificate_requests(self) -> None:
        """Process outstanding certificate requests."""
        requests = self.tls_certificates.get_outstanding_certificate_requests()
        if self._config_certificate_limit and self._config_certificate_limit > -1:
            requests = self._limit_requests(requests)
        for request in requests:
            self._generate_self_signed_certificate(
                csr=request.certificate_signing_request,
                is_ca=request.is_ca,
                relation_id=request.relation_id,
            )

    def _limit_requests(
        self, requests: list[RequirerCertificateRequest]
    ) -> Iterator[RequirerCertificateRequest]:
        """Limit the number of requests to the configured limit."""
        counts = {}
        for request in requests:
            counts[request.relation_id] = counts.get(request.relation_id, 0) + 1
            if counts[request.relation_id] <= self._config_certificate_limit:
                yield request

    def _invalid_configs(self) -> list[str]:
        """Return list of invalid configurations.

        Returns:
            list: List of invalid config keys.
        """
        invalid_configs = []
        if not self._config_ca_common_name:
            invalid_configs.append("ca-common-name")
        if (
            not self._config_certificate_validity
            or not self._config_root_ca_certificate_validity
            or not self._config_root_ca_certificate_validity
            >= 2 * self._config_certificate_validity
            or self._config_root_ca_certificate_validity == timedelta(days=0)
            or self._config_certificate_validity == timedelta(days=0)
        ):
            invalid_configs.append("certificate-validity")
            invalid_configs.append("root-ca-validity")
        return invalid_configs

    def _generate_self_signed_certificate(
        self, csr: CertificateSigningRequest, is_ca: bool, relation_id: int
    ) -> None:
        """Generate self-signed certificate.

        Args:
            csr (CertificateSigningRequest): Certificate signing request
            is_ca (bool): Whether the certificate is a CA
            relation_id (int): Relation id
        """
        if (
            not self._config_ca_common_name
            or not self._config_root_ca_certificate_validity
            or not self._config_certificate_validity
            or not self._ca_certificate_renewal_threshold
        ):
            logger.warning("Missing configuration for self-signed certificate")
            return
        ca_certificate_secret = self.model.get_secret(label=CA_CERTIFICATES_SECRET_LABEL)
        ca_certificate_secret_content = ca_certificate_secret.get_content(refresh=True)
        ca_certificate = Certificate.from_string(ca_certificate_secret_content["ca-certificate"])
        certificate = generate_certificate(
            ca=ca_certificate,
            ca_private_key=PrivateKey.from_string(ca_certificate_secret_content["private-key"]),
            csr=csr,
            validity=self._config_certificate_validity,
            is_ca=is_ca,
        )
        self.tls_certificates.set_relation_certificate(
            provider_certificate=ProviderCertificate(
                relation_id=relation_id,
                certificate=certificate,
                certificate_signing_request=csr,
                ca=ca_certificate,
                chain=[
                    ca_certificate,
                    certificate,
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

    def _send_ca_cert(self, *, rel_id=None):
        """There is one (and only one) CA cert that we need to forward to multiple apps.

        Args:
            rel_id: Relation id. If not given, update all relations.
        """
        if not self._root_certificate_is_stored:
            return
        send_ca_cert = CertificateTransferProvides(self, SEND_CA_CERT_REL_NAME)
        secret = self.model.get_secret(label=CA_CERTIFICATES_SECRET_LABEL)
        secret_content = secret.get_content(refresh=True)
        ca = secret_content["ca-certificate"]
        if rel_id:
            send_ca_cert.set_certificate("", ca, [], relation_id=rel_id)
        else:
            for relation in self.model.relations.get(SEND_CA_CERT_REL_NAME, []):
                send_ca_cert.set_certificate("", ca, [], relation_id=relation.id)

    def _push_ca_cert_to_container(self, ca_certificate: str):
        """Store the CA certificate in the charm container.

        Args:
            ca_certificate: PEM String of the CA cert.
        """
        with open(CA_CERT_PATH, "w") as f:
            f.write(ca_certificate)


if __name__ == "__main__":
    main(SelfSignedCertificatesCharm)
