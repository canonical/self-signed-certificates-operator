resource "juju_application" "self-signed-certificates" {
  name  = "self-signed-certificates"
  model = var.model_name

  charm {
    name    = "self-signed-certificates"
    channel = var.channel
    base    = "ubuntu@22.04"
  }
  config = var.cert-config
  units  = 1
}
