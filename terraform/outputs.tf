# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.self-signed-certificates.name
}

# Provided integration endpoints

output "certificates_endpoint" {
  description = "Name of the endpoint provided for `tls-certificates` interface."
  value = "certificates"
}

output "send_ca_cert_endpoint" {
  description = "Name of the endpoint provided for `certificate_transfer` interface."
  value = "send-ca-cert"
}