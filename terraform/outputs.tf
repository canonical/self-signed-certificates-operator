# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.self-signed-certificates.name
}

output "application" {
  description = "The deployed Juju application."
  value       = juju_application.self-signed-certificates
}

output "offers" {
  value = {
    send-ca-cert = juju_offer.send_ca_cert
    certificates = juju_offer.certificates
  }
}

output "provides" {
  description = "Map of the endpoints the charm provides, keyed by endpoint name."
  value = {
    certificates = {
      kind     = "endpoint"
      name     = juju_application.self-signed-certificates.name
      endpoint = "certificates"
    }
    send-ca-cert = {
      kind     = "endpoint"
      name     = juju_application.self-signed-certificates.name
      endpoint = "send-ca-cert"
    }
  }
}

output "requires" {
  description = "Map of the endpoints the charm requires, keyed by endpoint name."
  value = {
    tracing = {
      kind     = "endpoint"
      name     = juju_application.self-signed-certificates.name
      endpoint = "tracing"
    }
  }
}
