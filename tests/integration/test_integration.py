#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
import platform
import subprocess
from pathlib import Path

import jubilant
import pytest
import yaml

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = METADATA["name"]

TLS_REQUIRER_CHARM_NAME = "tls-certificates-requirer"
CA_COMMON_NAME = "example.com"

ARCH = "arm64" if platform.machine() == "aarch64" else "amd64"
REQUIRER_CHARM_REVISION_ARM = 103
REQUIRER_CHARM_REVISION_AMD = 104


def build_charm(path: Path) -> Path:
    _ = subprocess.run(
        ["charmcraft", "pack", "--verbose"],
        check=True,
        capture_output=True,
        encoding="utf-8",
        cwd=path,
    )
    return next(path.glob("*.charm"))


@pytest.fixture(scope="module")
def juju():
    with jubilant.temp_model() as juju:
        juju.wait_timeout = 1000
        yield juju


def test_deploy(juju: jubilant.Juju, request: pytest.FixtureRequest):
    charm = Path(str(request.config.getoption("--charm_path"))).resolve()
    juju.deploy(charm, "self-signed-certificates")
    juju.wait(jubilant.all_active)
