output "certs_application_name" {
  description = "Name of the deployed application."
  value       = juju_application.self-signed-certificates.name
}