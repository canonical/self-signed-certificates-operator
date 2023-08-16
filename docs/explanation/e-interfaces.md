# Interfaces/Endpoints

This charm provides `tls-certificates` interface.  To use the `self-signed-certificates` operator and provide certificates to another charm, the other charm needs to require the `tls-certificates` interface.

## Using tls-certificates interface

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

To remove a relation:

```shell
juju remove-relation self-signed-certificates <other-application>
```