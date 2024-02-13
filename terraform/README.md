# Self Signed Certificates Terraform module

This folder contains a base [Terraform][Terraform] module for the `self-signed-certificats` charm.

The module uses the [Terraform Juju provider][Terraform Juju provider] to model the charm deployment onto any Kubernetes environment managed by [Juju][Juju].

The base module is not intended to be deployed in separation (it is possible though), but should rather serve as a building block for higher level modules.

## Module structure

- **main.tf** - Defines the Juju application to be deployed.
- **variables.tf** - Allows customization of the deployment. Except for exposing the deployment options (Juju model name, channel or application name) also models the charm configuration.
- **output.tf** - Responsible for integrating the module with other Terraform modules, primarily by defining potential integration endpoints (charm integrations), but also by exposing the application name.
- **terraform.tf** - Defines the Terraform provider.

## Pre-requisites

The following tools needs to be installed and should be running in the environment. Please [set up your environment][set-up-environment] before deployment.

- A Kubernetes cluster
- Juju
- Juju controller bootstrapped onto the K8s cluster
- Terraform

## Using Grafana-agent-k8s base module in higher level modules

If you want to use `self-signed-certificates` base module as part of your Terraform module, import it like shown below.

```text
module "self-signed-certificates {
  source = "git::https://github.com/canonical/self-signed-certificates-operator//terraform"
  
  model_name = "juju_model_name"
  (Customize configuration variables here if needed)
}
```

Create the integrations, for instance:

```text
resource "juju_integration" "amf-certificates" {
  model = var.model_name

  application {
    name     = module.amf.app_name
    endpoint = module.amf.certificates_endpoint
  }

  application {
    name     = module.self-signed-certificates.app_name
    endpoint = module.self-signed-certificates.certificates_endpoint
  }
}
```

The complete list of available integrations can be found [here][self-signed-certificates-integrations].

[Terraform]: https://www.terraform.io/
[Terraform Juju provider]: https://registry.terraform.io/providers/juju/juju/latest
[Juju]: https://juju.is
[self-signed-certificates-integrations]: https://charmhub.io/self-signed-certificates/integrations
[set-up-environment]: [https://discourse.charmhub.io/t/set-up-your-development-environment-with-microk8s-for-juju-terraform-provider/13109#prepare-development-environment-2]