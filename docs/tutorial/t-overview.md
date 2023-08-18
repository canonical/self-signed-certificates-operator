# Self Signed X.509 Certificates tutorial

The Self Signed X.509 Certificates Operator provides self-signed X.509 certificates to your charms by setting up a relation with a requirer charm. This charm generates a self-signed X.509 certificates for a requirer by using Certificate Signing Request sent in the relation databag.

This charm is useful when developing charms or when deploying charms in non-production environment.In this tutorial we will walk through how to:
- Set up an environment using [Multipass](https://multipass.run/) with [MicroK8s](https://microk8s.io/) and [Juju](https://juju.is/).
- Deploy Self Signed X.509 Certificates Operator using a single command.
- Configuring charm
- Setting up relations with other charms
- Getting signed certificates
- Managing application and units

## Make Self Signed Certificates Operator up and running

To deploy Self Signed X.509 Certificates Operator, all you need to do is run the following command, which will fetch the charm from [Charmhub](https://charmhub.io/self-signed-certificates?channel=edge) and deploy it to your model:

```shell
juju deploy self-signed-certificates --channel edge
```

Juju will now fetch self-signed-certificates operator and begin deploying it to the local MicroK8s. This process can take several minutes depending on how provisioned (RAM, CPU, etc) your machine is. You can track the progress by running:
```shell
juju status --watch 1s
```

This command is useful for checking the status of self-signed-certificates operator. Some of the helpful information it displays include IP addresses, ports, state, etc. The command updates the status of Self Signed Certificates Operator every second and as the application starts you can watch the status and messages of operator change. Wait until the application is ready - when it is ready, `juju status` will show:
```
Model  Controller          Cloud/Region        Version  SLA          Timestamp
tutorial   microk8s-localhost  microk8s/localhost  3.1.5    unsupported  01:14:09+03:00

App                       Version  Status  Scale  Charm                     Channel        Rev  Address         Exposed  Message       
self-signed-certificates           active      1  self-signed-certificates  edge            17  10.152.183.40   no       
      

Unit                         Workload  Agent  Address      Ports  Message         
self-signed-certificates/0*  active    idle   10.1.146.12   
```
To exit the screen with `juju status --watch 1s`, enter `Ctrl+c`.
If you want to further inspect juju logs, can watch for logs with `juju debug-log`.
More info on logging at [juju logs](https://juju.is/docs/olm/juju-logs).

## How to manage units

If Self Signed Certificates Operator is deployed with its default configuration, single unit exists.
The Self Signed Certificates Operator works with single replica for the moment and scale up operation is not supported yet.

Scaling-down operation is performed using following command:
```shell
juju scale-application  self-signed-certificates 0
```

## Relating with other applications

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

## Step-by-step guide

Here’s an overview of the steps required with links to our separate tutorials that deal with each individual step:
* [Deploy Self Signed Certificates Operator](/t/self-signed-x-509-certificates-tutorial-overview/11600?channel=edge)
* [Configure Self Signed Certificates Operator](https://charmhub.io/self-signed-certificates/configure?channel=edge)
* [Managing your units](/t/self-signed-x-509-certificates-tutorial-overview/11600?channel=edge)
* [Relate Self Signed Certificates Operator with other applications](https://charmhub.io/self-signed-certificates/integrations?channel=edge)
* [Get Signed Certificates](https://charmhub.io/self-signed-certificates/actions?channel=edge)

# License:
The Self Signed X.509 Certificates Operator [is distributed](https://github.com/canonical/self-signed-certificates-operator/blob/main/LICENSE) under the Apache Software License, version 2.0.
