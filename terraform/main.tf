# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

resource "juju_application" "self-signed-certificates" {
  name  = var.app_name
  model = var.model

  charm {
    name     = "self-signed-certificates"
    channel  = var.channel
    revision = var.revision
    base     = var.base
  }

  config      = var.config
  constraints = var.constraints
  units       = var.units
}
