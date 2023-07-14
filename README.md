# self-signed-certificates-operator

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

```console
juju deploy self-signed-certificates
juju deploy <your charm>
juju relate self-signed-certificates <your charm>
```

To get the CA certificate run:

```console
juju run self-signed-certificates/0 get-ca-cert
```
