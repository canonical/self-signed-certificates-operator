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
  description = "Offers created from offered_endpoints, keyed by endpoint. Each value is { kind = \"offer\", url }."
  value = {
    for endpoint, offer in juju_offer.this : endpoint => {
      kind = "offer"
      url  = offer.url
    }
  }
}
