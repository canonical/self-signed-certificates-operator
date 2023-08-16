# Make Self Signed Certificates Operator up and running

This is part of the [Self Signed X.509 Certificates Operator Tutorial](/t/self-signed-x-509-certificates-tutorial-overview/11600?channel=edge). Please refer to this page for more information and the overview of the content.

## Deploy

To deploy Self Signed X.509 Certificates Operator, all you need to do is run the following command, which will fetch the charm from [Charmhub](https://charmhub.io/self-signed-certificates/integrations?channel=edge) and deploy it to your model:

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