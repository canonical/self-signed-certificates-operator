# Self Signed X.509 Certificates tutorial

The Self Signed X.509 Certificates Operator provides self-signed X.509 certificates to your charms by setting up a relation with a requirer charm. This charm generates a self-signed X.509 certificates for a requirer by using Certificate Signing Request sent in the relation databag.

This charm is useful when developing charms or when deploying charms in non-production environment.In this tutorial we will walk through how to:
- Set up an environment using [Multipass](https://multipass.run/) with [MicroK8s](https://microk8s.io/) and [Juju](https://juju.is/).
- Deploy Self Signed X.509 Certificates Operator using a single command.
- Configuring charm
- Setting up relations with other charms
- Getting signed certificates
- Managing application and units

## Step-by-step guide

Here’s an overview of the steps required with links to our separate tutorials that deal with each individual step:
* [Set up the environment](/t/self-signed-x-509-certificates-tutorial-setup-environment/11599?channel=edge)
* [Deploy Self Signed Certificates Operator](/t/self-signed-x-509-certificates-tutorial-deploy/11596?channel=edge)
* [Configure Self Signed Certificates Operator](/t/self-signed-x-509-certificates-explanations-configure/11601?channel=edge)
* [Managing your units](/t/self-signed-x-509-certificates-how-to-manage-units/11594/9299?channel=edge)
* [Relate Self Signed Certificates Operator with other applications](/t/self-signed-x-509-certificates-explanations-interface-endpoints/11593?channel=edge)
* [Get Signed Certificates](/t/self-signed-x-509-certificates-tutorial-get-signed-certificates/11598?channel=edge)

# License:
The Self Signed X.509 Certificates Operator [is distributed](https://github.com/canonical/self-signed-certificates-operator/blob/main/LICENSE) under the Apache Software License, version 2.0.
