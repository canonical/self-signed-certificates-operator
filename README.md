# Self Signed Certificates Operator

An operator to provide self-signed X.509 certificates to your charms.

This charm relies on the `tls-certificates` charm relation interface. When a requirer charm 
inserts a Certificate Signing Request in its unit databag, the 
`self-signed-certificates-operator` will read it, generate a self-signed X.509 certificates and
inserts this certificate back into the relation data.

This charm is useful when developing charms or when deploying charms in non-production environment.

## Pre-requisites

- Juju >= 3.0

## Usage

Bootstrap a Kubernetes (e.g. [Multipass-based MicroK8s](https://discourse.charmhub.io/t/charmed-environment-charm-dev-with-canonical-multipass/8886)) and create a new model using Juju >= 3.1:

```shell
juju add-model certificates
juju deploy self-signed-certificates --channel edge
```

To confirm the deployment, you can run:

```shell
juju status --watch 1s
```

If required, you can remove the application by running:

```shell
juju remove-application self-signed-certificates
```

If required, you can remove the deployment completely by running:

```shell
juju destroy-model certificates
```

## Integrations

This charm provides `tls-certificates` interface.  To use the `self-signed-certificates` operator and provide certificates to another charm, the other charm needs to require the `tls-certificates` interface.

```shell
juju relate self-signed-certificates <your charm which needs tls certificates>
```

The relation status is shown by running following command:

```shell
juju status --relations
```

If the relation is established, the following output is expected:

```shell
Relation provider                      Requirer                             Interface                Type     
self-signed-certificates:certificates  amf:certificates                     tls-certificates         regular
```

## Get the certificates issued by the charm

This charm supports single action `get-issued-certificates` which shows all the issued certificates.

```shell
juju run self-signed-certificates/leader get-issued-certificates
```

The above command returns the task number and the task output is shown by running:

```shell
juju show-task <task number>
```
