# Self Signed Certificates Terraform module

This folder contains a root [Terraform][Terraform] module for the `self-signed-certificats` charm.

The module uses the [Terraform Juju provider][Terraform Juju provider] to model the charm deployment onto any Kubernetes environment managed by [Juju][Juju].

The root module is not intended to be deployed in separation (it is possible though), but should rather serve as a building block for higher level modules.

## Module structure

- **main.tf** - Defines the Juju application to be deployed.
- **variables.tf** - Allows customization of the deployment. Except for exposing the deployment options (Juju model UUID, channel or application name) also models the charm configuration.
- **output.tf** - Responsible for integrating the module with other Terraform modules, primarily by defining potential integration endpoints (charm integrations), but also by exposing the application name.
- **versions.tf** - Defines the Terraform provider.

## Pre-requisites

The following tools needs to be installed and should be running in the environment. Please [set up your environment][set-up-environment] before deployment.

- A Kubernetes cluster
- Juju
- Juju controller bootstrapped onto the K8s cluster
- Terraform

## Using Self-signed-certificates-k8s root module in higher level modules

If you want to use `self-signed-certificates` root module as part of your Terraform module, import it like shown below. We recommend pinning to a specific git tag or commit SHA for stability.

```text
module "self-signed-certificates" {
  source = "git::https://github.com/canonical/self-signed-certificates-operator//terraform?ref=<COMMIT_HASH>"
  
  model_uuid = "juju_model.my-model.uuid"
  (Customize configuration variables here if needed)
}
```

The model UUID can easily be obtained with the [juju_model data source](https://registry.terraform.io/providers/juju/juju/latest/docs/data-sources/model). 

Then, create the integrations, for instance:

```text
resource "juju_integration" "certificates-endpoint-integration" {
  model_uuid = var.model_uuid

  application {
    name     = module.some-app.app_name
    endpoint = module.some-app.certificates_endpoint
  }

  application {
    name     = module.self-signed-certificates.app_name
    endpoint = module.self-signed-certificates.provides.certificates
  }
}
```

The complete list of available integrations can be found [here][self-signed-certificates-integrations].

[Terraform]: https://www.terraform.io/
[Terraform Juju provider]: https://registry.terraform.io/providers/juju/juju/latest
[Juju]: https://juju.is
[self-signed-certificates-integrations]: https://charmhub.io/self-signed-certificates/integrations
[set-up-environment]: [https://discourse.charmhub.io/t/set-up-your-development-environment-with-microk8s-for-juju-terraform-provider/13109#prepare-development-environment-2]