The Self Signed Certificates Operator provides self-signed X.509 certificates to your charms.

This charm relies on the `tls-certificates` charm relation interface. When a requirer charm inserts a Certificate Signing Request in its unit databag, the `self-signed-certificates-operator` will read it, generate a self-signed X.509 certificates and
inserts this certificate back into the relation data.

The [Self-Signed-Certificates-Operator](https://github.com/canonical/self-signed-certificates-operator) is useful when developing charms or when deploying charms in non-production environment on top of [Juju](https://juju.is/).

## Usage

To deploy Self Signed X.509 Certificates Operator, all you need to do is run the following command, which will fetch the charm from [Charmhub](https://charmhub.io/self-signed-certificates?channel=edge) and deploy it to your model. Then relate it with an existing requirer charm.
```shell
juju deploy self-signed-certificates --channel edge
juju relate self-signed-certificates <your charm which needs tls certificates>
```

Juju will now fetch self-signed-certificates operator and begin deploying it to the local MicroK8s. This process can take several minutes depending on how provisioned (RAM, CPU, etc) your machine is. You can track the progress by running:
```shell
juju status --watch 1s
juju status --relations
```

The Self Signed Certificates Operator works with single replica for the moment and scale up operation is not supported yet.

## License:
The Self Signed X.509 Certificates Operator [is distributed](https://github.com/canonical/self-signed-certificates-operator/blob/main/LICENSE) under the Apache Software License, version 2.0.

## Project and community
The Self Signed Certificates Operator is an open-source project that welcomes community contributions, suggestions, fixes and constructive feedback.
- [Read our Code of Conduct](https://ubuntu.com/community/code-of-conduct)
- [Join the Discourse forum](https://discourse.charmhub.io/tag/self-signed-certificates)
- Contribute and report bugs to [Self-Signed-Certificates-Operator](https://github.com/canonical/self-signed-certificates-operator)
