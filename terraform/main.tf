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

resource "juju_offer" "send_ca_cert" {
  name             = "send-ca-cert"
  model_uuid       = var.model_uuid
  application_name = var.app_name
  endpoints        = ["send-ca-cert"]
}

resource "juju_offer" "certificates" {
  name             = "certificates"
  model_uuid       = var.model_uuid
  application_name = var.app_name
  endpoints        = ["certificates"]
}
