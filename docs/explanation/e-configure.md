# Set the operator configuration options

The following charm configuration options are set to desired values if needed.

- ca-common-name
- root-ca-validity
- certificate-validity

## Setting the configuration

The charm configuration are set by running following commands:

```shell
juju config self-signed-certificates root-ca-validity=180
juju config self-signed-certificates ca-common-name=mycompany.com
juju config self-signed-certificates certificate-validity=90
```

The updated charm configuration is displayed by running following command:
```shell
juju config self-signed-certificates
```

The command output is similar to following:

```yaml
charm: self-signed-certificates
settings: 
  ca-common-name: 
    default: self-signed-certificates-operator
    description: Common name to be used by the Certificate Authority.
    source: user
    type: string
    value: mycompany.com
  certificate-validity: 
    default: 365
    description: Certificate validity (in days).
    source: user
    type: int
    value: 90
  root-ca-validity: 
    default: 365
    description: RootCA certificate validity (in days).
    source: user
    type: int
    value: 180
```