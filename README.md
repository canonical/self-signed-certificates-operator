# self-signed-certificates-operator
![CI Status](https://github.com/canonical/self-signed-certificates-operator/actions/workflows/main.yaml/badge.svg)
[![CharmHub Badge](https://charmhub.io/self-signed-certificates/badge.svg)](https://charmhub.io/self-signed-certificates)

An operator to provide self-signed X.509 certificates to your charms.

This charm relies on the `tls-certificates` charm relation interface. When a requirer charm
inserts a Certificate Signing Request in its unit databag, the
`self-signed-certificates-operator` will read it, generate a self-signed X.509 certificates and
inserts this certificate back into the relation data.

This charm is useful when developing charms or when deploying charms in non-production environment.

## Pre-requisites

- Juju >= 3.0

## Usage

To use the `self-signed-certificates` operator and provide certificates to your charm, your charm
needs to support the `tls-certificates` interface.

```shell
juju deploy self-signed-certificates
juju deploy <your charm>
juju relate self-signed-certificates <your charm>
```

To obtain the CA certificate from this charm, your charm needs to support the
`certificate_transfer` interface.

```console
juju relate self-signed-certificates:send-ca-cert <your charm>
```
To get the CA certificate run:

```console
juju run self-signed-certificates/0 get-ca-certificate
```

## Get the certificates issued by the charm

```shell
juju run self-signed-certificates/leader get-issued-certificates
```
