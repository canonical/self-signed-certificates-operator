The Self Signed Certificates Operator provides self-signed X.509 certificates to your charms.

This charm relies on the `tls-certificates` charm relation interface. When a requirer charm inserts a Certificate Signing Request in its unit databag, the `self-signed-certificates-operator` will read it, generate a self-signed X.509 certificates and
inserts this certificate back into the relation data.

This charm [Self-Signed-Certificates-Operator](https://github.com/canonical/self-signed-certificates-operator) is useful when developing charms or when deploying charms in non-production environment on top of [Juju](https://juju.is/).

## Project and community
The Self Signed Certificates Operator is an open-source project that welcomes community contributions, suggestions, fixes and constructive feedback.
- [Read our Code of Conduct](https://ubuntu.com/community/code-of-conduct)
- [Join the Discourse forum](https://discourse.charmhub.io/tag/self-signed-certificates)
- Contribute and report bugs to [Self-Signed-Certificates-Operator](https://github.com/canonical/self-signed-certificates-operator)

## In this documentation
|                                                                                                                                                                                         |                                                                                                                                                      |
|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| [Tutorial](/t/self-signed-x-509-certificates-tutorial-overview/11600?channel=edge) </br>  Get started - a hands-on introduction to using Self Signed X.509 Certificates for new users </br> | [How-to guides]() </br> Step-by-step guides covering key operations and common tasks    |
| [Reference](https://charmhub.io/self-signed-certificates/actions?channel=edge) </br> Technical information - specifications, APIs, architecture                                         | [Explanation]() </br> Concepts - discussion and clarification of key topics |

# Navigation

| Level | Path                      | Navlink                                                                                                  |
| ----- |---------------------------|----------------------------------------------------------------------------------------------------------|
| 1 | tutorial                  | [Tutorial]()                                                                                             |
| 2 | t-overview                | [1. Introduction](/t/self-signed-x-509-certificates-tutorial-overview/11600)                             |
| 2 | t-deploy                  | [3. Deploy Self Signed Certificates Operator](/t/self-signed-x-509-certificates-tutorial-overview/11600) |
| 2 | t-get-signed-certificates | [4. Get Signed Certificates](https://charmhub.io/self-signed-certificates/actions?channel=edge)          |
| 1 | how-to                    | [How To]()                                                                                               |
| 1 | reference                 | [Reference]()                                                                                            |
| 2 | r-actions                 | [Actions](https://charmhub.io/self-signed-certificates/actions?channel=edge)                             |
| 2 | r-configurations          | [Configurations](https://charmhub.io/self-signed-certificates/configure?channel=edge)                    |
| 2 | r-libraries               | [Libraries](https://charmhub.io/self-signed-certificates/libraries?channel=edge)                         |
| 2 | r-integrations            | [Integrations](https://charmhub.io/self-signed-certificates/integrations?channel=edge)                   |
| 1 | explanation               | [Explanation]()                                                                                          |

