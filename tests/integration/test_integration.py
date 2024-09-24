#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


import json
import logging
import platform
import time
from pathlib import Path
from typing import Dict

import pytest
import yaml
from certificate import get_common_name_from_certificate
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = METADATA["name"]

TLS_REQUIRER_CHARM_NAME = "tls-certificates-requirer"
CA_COMMON_NAME = "example.com"

ARCH = "arm64" if platform.machine() == "aarch64" else "amd64"
REQUIRER_CHARM_REVISION_ARM = 103
REQUIRER_CHARM_REVISION_AMD = 104


async def wait_for_requirer_certificates(ops_test: OpsTest, ca_common_name: str) -> Dict[str, str]:
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
        action_output = await run_get_certificate_action(ops_test)
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


@pytest.fixture(scope="module")
@pytest.mark.abort_on_fail
async def deploy(ops_test: OpsTest, request):
    """Build the charm-under-test and deploy it."""
    assert ops_test.model
    charm = Path(request.config.getoption("--charm_path")).resolve()
    logger.info("Deploying charms for architecture: %s", ARCH)
    await ops_test.model.set_constraints({"arch": ARCH})
    await ops_test.model.deploy(
        charm,
        application_name=APP_NAME,
        series="jammy",
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
    await ops_test.model.deploy(
        TLS_REQUIRER_CHARM_NAME,
        application_name=TLS_REQUIRER_CHARM_NAME,
        revision=REQUIRER_CHARM_REVISION_ARM if ARCH == "arm64" else REQUIRER_CHARM_REVISION_AMD,
        channel="stable",
        constraints={"arch": ARCH},
    )


@pytest.mark.abort_on_fail
async def test_given_charm_is_built_when_deployed_then_status_is_active(
    ops_test: OpsTest,
    deploy,
):
    assert ops_test.model
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1000,
    )


async def test_given_tls_requirer_is_deployed_when_integrated_then_certificate_is_provided(
    ops_test: OpsTest,
    deploy,
):
    assert ops_test.model
    await ops_test.model.integrate(
        relation1=f"{APP_NAME}:certificates", relation2=f"{TLS_REQUIRER_CHARM_NAME}"
    )
    await ops_test.model.wait_for_idle(
        apps=[TLS_REQUIRER_CHARM_NAME],
        status="active",
        timeout=1000,
    )
    await wait_for_requirer_certificates(ops_test=ops_test, ca_common_name=CA_COMMON_NAME)


async def test_given_tls_requirer_is_integrated_when_ca_common_name_config_changed_then_new_certificate_is_provided(  # noqa: E501
    ops_test: OpsTest,
    deploy,
):
    new_common_name = "newexample.org"
    assert ops_test.model
    application = ops_test.model.applications[APP_NAME]
    assert application
    await application.set_config({"ca-common-name": new_common_name})
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME, TLS_REQUIRER_CHARM_NAME],
        status="active",
        timeout=1000,
    )

    await wait_for_requirer_certificates(ops_test=ops_test, ca_common_name=new_common_name)


async def test_given_tls_requirer_is_integrated_when_certificates_expires_then_new_certificate_is_provided(  # noqa: E501
    ops_test: OpsTest,
    deploy,
):
    new_common_name = "newexample.org"
    assert ops_test.model
    application = ops_test.model.applications[APP_NAME]
    assert application
    await application.set_config(
        {
            "root-ca-validity": "3m",
            "certificate-validity": "1m",
        }
    )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME, TLS_REQUIRER_CHARM_NAME],
        status="active",
        timeout=1000,
    )

    action_output = await wait_for_requirer_certificates(
        ops_test=ops_test, ca_common_name=new_common_name
    )
    new_common_name_certificate = action_output.get("certificate", "")
    new_common_name_ca = action_output.get("ca-certificate", "")

    assert new_common_name_certificate

    # Wait for the certificate to expire
    time.sleep(60)

    action_output = await wait_for_requirer_certificates(
        ops_test=ops_test, ca_common_name=new_common_name
    )
    renewed_certificate = action_output.get("certificate", "")
    assert renewed_certificate
    assert renewed_certificate != new_common_name_certificate
    assert action_output.get("ca-certificate", "") == new_common_name_ca

    # Wait for the CA certificate to expire
    time.sleep(120)
    action_output = await wait_for_requirer_certificates(
        ops_test=ops_test, ca_common_name=new_common_name
    )
    new_certificate_with_new_ca = action_output.get("certificate", "")
    new_ca = action_output.get("ca-certificate", "")
    assert new_certificate_with_new_ca
    assert new_certificate_with_new_ca != renewed_certificate
    assert new_ca != new_common_name_ca


async def test_given_charm_scaled_then_charm_does_not_crash(
    ops_test: OpsTest,
    deploy,
):
    assert ops_test.model
    await ops_test.model.applications[APP_NAME].scale(2)  # type: ignore
    await ops_test.model.wait_for_idle(apps=[APP_NAME], timeout=1000, wait_for_exact_units=2)
    await ops_test.model.applications[APP_NAME].scale(1)  # type: ignore
    await ops_test.model.wait_for_idle(apps=[APP_NAME], timeout=1000, wait_for_exact_units=1)


async def run_get_certificate_action(ops_test) -> Dict[str, str]:
    """Run `get-certificate` on the `tls-requirer-requirer/0` unit.

    Args:
        ops_test (OpsTest): OpsTest

    Returns:
        dict: Action output
    """
    assert ops_test.model
    tls_requirer_unit = ops_test.model.units[f"{TLS_REQUIRER_CHARM_NAME}/0"]
    action = await tls_requirer_unit.run_action(action_name="get-certificate")
    action_output = await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=240)
    return action_output
