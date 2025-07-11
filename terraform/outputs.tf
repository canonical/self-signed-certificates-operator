# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.self-signed-certificates.name
}

output "requires" {
  value = {
    tracing = "tracing"
  }
}

output "provides" {
  value = {
    certificates = "certificates"
    send-ca-cert = "send-ca-cert"
  }
}

output "offers" {
  value = {
    send-ca-cert = juju_offer.send_ca_cert
    certificates = juju_offer.certificates
  }
}