# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

resource "juju_application" "self-signed-certificates" {
  name       = var.app_name
  model_uuid = var.model_uuid

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

resource "juju_offer" "this" {
  for_each         = var.offered_endpoints
  name             = "${var.app_name}-${each.value}"
  model_uuid       = var.model_uuid
  application_name = juju_application.self-signed-certificates.name
  endpoints        = [each.value]
}
