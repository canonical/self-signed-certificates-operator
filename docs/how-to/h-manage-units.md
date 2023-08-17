# How to deploy and manage units

## Basic Usage

To deploy a single unit of Self Signed Certificates Operator using its default configuration.
```shell
juju deploy self-signed-certificates --channel edge
```

## Replication

Both scaling-up and scaling-down operations are performed using `juju scale-application`:
```shell
juju scale-application  self-signed-certificates <desired_num_of_units>
```

The Self Signed Certificates Operator works with single replica for the moment.