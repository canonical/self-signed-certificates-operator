#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
from pathlib import Path

import pytest
import yaml

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = METADATA["name"]

TLS_REQUIRER_CHARM_NAME = "tls-certificates-requirer"


@pytest.fixture(scope="module")
@pytest.mark.abort_on_fail
async def build_and_deploy(ops_test):
    """Build the charm-under-test and deploy it."""
    charm = await ops_test.build_charm(".")
    await ops_test.model.deploy(
        charm,
        application_name=APP_NAME,
        series="jammy",
        trust=True,
    )
    await ops_test.model.deploy(
        TLS_REQUIRER_CHARM_NAME,
        application_name=TLS_REQUIRER_CHARM_NAME,
        channel="edge",
    )


@pytest.mark.abort_on_fail
async def test_given_charm_is_built_when_deployed_then_status_is_active(
    ops_test,
    build_and_deploy,
):
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1000,
    )


async def test_given_tls_requirer_is_deployed_and_related_then_certificate_is_created_and_passed_correctly(  # noqa: E501
    ops_test,
    build_and_deploy,
):
    await ops_test.model.add_relation(
        relation1=f"{APP_NAME}:certificates", relation2=f"{TLS_REQUIRER_CHARM_NAME}"
    )
    await ops_test.model.wait_for_idle(
        apps=[TLS_REQUIRER_CHARM_NAME],
        status="active",
        timeout=1000,
    )
    action_output = await run_get_certificate_action(ops_test)
    assert action_output["certificate"] is not None
    assert action_output["ca-certificate"] is not None
    assert action_output["chain"] is not None
    assert action_output["csr"] is not None


async def run_get_certificate_action(ops_test) -> dict:
    """Runs `get-certificate` on the `tls-requirer-requirer/0` unit.

    Args:
        ops_test (OpsTest): OpsTest

    Returns:
        dict: Action output
    """
    tls_requirer_unit = ops_test.model.units[f"{TLS_REQUIRER_CHARM_NAME}/0"]
    action = await tls_requirer_unit.run_action(
        action_name="get-certificate",
    )
    action_output = await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=240)
    return action_output
