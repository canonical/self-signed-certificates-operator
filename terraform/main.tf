# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

resource "juju_application" "self-signed-certificates" {
  name  = var.app_name
  model = var.model_name

  charm {
    name    = "self-signed-certificates"
    channel = var.channel
    base    = "ubuntu@22.04"
  }
  config = var.config
  units  = 1
}
