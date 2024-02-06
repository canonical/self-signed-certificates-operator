variable "model_name" {
  description = "Name of Juju model to deploy application to"
  type        = string
  default     = ""
}

variable "channel" {
  description = "The channel to use when deploying a charm "
  type        = string
  default     = "beta"
}

variable "cert-config" {
  description = "Additional configuration for the Self-Signed-Certificates"
  default     = {}
}
