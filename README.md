# self-signed-certificates-operator

![CI Status](https://github.com/canonical/self-signed-certificates-operator/actions/workflows/main.yaml/badge.svg)
[![CharmHub Badge](https://charmhub.io/self-signed-certificates/badge.svg)](https://charmhub.io/self-signed-certificates)

An operator to provide self-signed X.509 certificates to your charms.

This charm relies on the `tls-certificates` charm relation interface. When a requirer charm
inserts a Certificate Signing Request in its unit databag, the
`self-signed-certificates-operator` will read it, generate a self-signed X.509 certificate and
insert this certificate back into the relation data.

This charm is useful when developing charms or when deploying charms in non-production environment.

For more information, including guides, integrations, and configuration options, read the [Self-signed Certificates documentation](https://charmhub.io/self-signed-certificates).

## Project & Community

Self-signed Certificates Operator is an open source project that warmly welcomes community contributions, suggestions, fixes, and constructive feedback.

- To contribute to the code Please see [CONTRIBUTING.md](CONTRIBUTING.md) and the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines and best practices.
- Raise software issues or feature requests in [GitHub](https://github.com/canonical/self-signed-certificates-operator/issues)
- Meet the community and chat with us on [Matrix](https://matrix.to/#/#tls:ubuntu.com)
