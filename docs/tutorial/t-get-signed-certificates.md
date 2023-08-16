# Get Signed Certificates

This is part of the [Self Signed X.509 Certificates Operator Tutorial](/t/self-signed-x-509-certificates-tutorial-overview/11600?channel=edge). Please refer to this page for more information and the overview of the content.

## Certificates
The charm issues certificates and generated certificates are displayed by running an action named `get-issued-certificates`.

### Running action to get issued certificates

```shell
juju run self-signed-certificates/<leader unit number>  get-issued-certificates
```

Running the command should output:
```shell
Running operation 3 with 1 task
  - task 4 on unit-self-signed-certificates-0

Waiting for task 4...
```

The task result is shown by running following command:
```shell
juju show-task 4
```