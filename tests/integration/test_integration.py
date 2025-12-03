#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


import json
import logging
import platform
import time
from pathlib import Path

import jubilant
import pytest
import yaml
from certificate import get_common_name_from_certificate

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = str(METADATA["name"])

TLS_REQUIRER_CHARM_NAME = "tls-certificates-requirer"
CA_COMMON_NAME = "example.com"

ARCH = "arm64" if platform.machine() == "aarch64" else "amd64"
REQUIRER_CHARM_REVISION_ARM = 103
REQUIRER_CHARM_REVISION_AMD = 104


@pytest.fixture(scope="module")
def juju(request: pytest.FixtureRequest):
    with jubilant.temp_model() as juju:
        yield juju
        if request.session.testsfailed:
            log = juju.debug_log(limit=1000)
            print(log, end="")


@pytest.mark.abort_on_fail
def test_deploy(juju: jubilant.Juju, request: pytest.FixtureRequest) -> None:
    """Build the charm-under-test and deploy it."""
    charm = Path(str(request.config.getoption("--charm_path"))).resolve()

    logger.info("Deploying charms for architecture: %s", ARCH)
    juju.model_config({"arch": ARCH})
    juju.deploy(
        charm=charm,
        app=APP_NAME,
        trust=True,
        config={
            "ca-common-name": CA_COMMON_NAME,
            "root-ca-validity": "200",
            "certificate-validity": "100",
            "ca-email-address": "test@example.com",
            "ca-country-name": "US",
            "ca-state-or-province-name": "California",
            "ca-locality-name": "San Francisco",
            "ca-organization": "Example Org",
            "ca-organizational-unit": "Example Unit",
        },
        constraints={"arch": ARCH},
    )
    juju.deploy(
        charm=TLS_REQUIRER_CHARM_NAME,
        app=TLS_REQUIRER_CHARM_NAME,
        revision=REQUIRER_CHARM_REVISION_ARM if ARCH == "arm64" else REQUIRER_CHARM_REVISION_AMD,
        channel="stable",
        constraints={"arch": ARCH},
    )


@pytest.mark.abort_on_fail
def test_given_charm_is_built_when_deployed_then_status_is_active(juju: jubilant.Juju):
    _ = juju.wait(
        lambda status: jubilant.all_active(status, APP_NAME),
        error=jubilant.any_error,
    )


def test_given_tls_requirer_is_deployed_when_integrated_then_certificate_is_provided(
    juju: jubilant.Juju,
):
    juju.integrate(app1=f"{APP_NAME}:certificates", app2=f"{TLS_REQUIRER_CHARM_NAME}:certificates")
    _ = juju.wait(
        lambda status: jubilant.all_active(status, TLS_REQUIRER_CHARM_NAME),
        error=jubilant.any_error,
    )
    _ = wait_for_requirer_certificates(juju=juju, ca_common_name=CA_COMMON_NAME)


def test_given_tls_requirer_is_integrated_when_ca_common_name_config_changed_then_new_certificate_is_provided(  # noqa: E501
    juju: jubilant.Juju,
):
    new_common_name = "newexample.org"
    juju.config(app=f"{APP_NAME}", values={"ca-common-name": new_common_name})
    _ = juju.wait(
        lambda status: jubilant.all_active(status, APP_NAME, TLS_REQUIRER_CHARM_NAME),
        error=jubilant.any_error,
    )
    _ = wait_for_requirer_certificates(juju=juju, ca_common_name=new_common_name)


def test_given_tls_requirer_is_integrated_when_certificates_expires_then_new_certificate_is_provided(  # noqa: E501
    juju: jubilant.Juju,
):
    juju.config(
        app=APP_NAME,
        values={
            "root-ca-validity": "3m",
            "certificate-validity": "1m",
        },
    )
    _ = juju.wait(
        lambda status: jubilant.all_active(status, APP_NAME, TLS_REQUIRER_CHARM_NAME),
        error=jubilant.any_error,
    )

    new_common_name = "newexample.org"
    action_output = wait_for_requirer_certificates(juju=juju, ca_common_name=new_common_name)
    new_common_name_certificate = action_output.get("certificate", "")
    new_common_name_ca = action_output.get("ca-certificate", "")

    assert new_common_name_certificate

    # Wait for the certificate to expire
    time.sleep(60)

    action_output = wait_for_requirer_certificates(juju=juju, ca_common_name=new_common_name)
    renewed_certificate = action_output.get("certificate", "")
    assert renewed_certificate
    assert renewed_certificate != new_common_name_certificate
    assert action_output.get("ca-certificate", "") == new_common_name_ca

    # Wait for the CA certificate to expire
    time.sleep(120)
    action_output = wait_for_requirer_certificates(juju=juju, ca_common_name=new_common_name)
    new_certificate_with_new_ca = action_output.get("certificate", "")
    new_ca = action_output.get("ca-certificate", "")
    assert new_certificate_with_new_ca
    assert new_certificate_with_new_ca != renewed_certificate
    assert new_ca != new_common_name_ca


def test_given_charm_scaled_then_charm_does_not_crash(juju: jubilant.Juju):
    _ = juju.cli("scale-application", APP_NAME, "2")
    _ = juju.wait(
        lambda status: jubilant.all_agents_idle(status, APP_NAME, TLS_REQUIRER_CHARM_NAME),
        error=jubilant.any_error,
    )
    _ = juju.cli("scale-application", APP_NAME, "1")
    _ = juju.wait(
        lambda status: jubilant.all_agents_idle(status, APP_NAME, TLS_REQUIRER_CHARM_NAME),
        error=jubilant.any_error,
    )


def wait_for_requirer_certificates(juju: jubilant.Juju, ca_common_name: str) -> dict[str, str]:
    """Wait for the certificate to be provided to the `tls-requirer-requirer/0` unit.

    Checks that CA certificate common name is the one expected.
    Returns the certificate output from the get-certificate action if successful.
    Otherwise, times out and raises a TimeoutError.
    """
    t0 = time.time()
    timeout = 300
    while time.time() - t0 < timeout:
        logger.info("Waiting for CA certificate with common name %s", ca_common_name)
        time.sleep(5)
        action_output = run_get_certificate_action(juju)
        try:
            certificates = json.loads(action_output.get("certificates", ""))[0]
        except json.JSONDecodeError:
            continue
        ca_certificate = certificates.get("ca-certificate", "")
        certificate = certificates.get("certificate", "")
        if not ca_certificate or not certificate:
            continue
        existing_ca_common_name = get_common_name_from_certificate(ca_certificate.encode())
        if existing_ca_common_name != ca_common_name:
            logger.info("Existing CA Common Name: %s", existing_ca_common_name)
            continue
        logger.info("Certificate with CA common name %s provided", ca_common_name)
        return certificates
    raise TimeoutError("Timed out waiting for certificate")


def run_get_certificate_action(juju: jubilant.Juju) -> dict[str, str]:
    """Run `get-certificate` on the `tls-requirer-requirer/0` unit.

    Args:
        juju (jubilant.Juju): juju handle

    Returns:
        dict: Action output
    """
    result = juju.run(
        unit=f"{TLS_REQUIRER_CHARM_NAME}/0",
        action="get-certificate",
    )
    return result.results
