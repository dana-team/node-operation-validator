# node-operation-validator
This project is a webhook that enforces restrictions on certain operations performed on nodes in a cluster. The webhook handles four operation cases: `delete`, `create`, `cordon`, `uncordon`. Depending on the operation and the user performing it, certain requirements must be met, such as adding a reason annotation or being a privileged user.

Each operation has its own set of requirements that must be met in order for the operation to be performed.

## Validated Operations

### Delete

Can only be performed by a privileged user who is not in the forbidden users list, and a reason annotation must be added to explain the reason for the deletion.

### Create

Can be performed by any privileged user, but including a reason annotation is not allowed.

### Cordon

Requires a reason annotation and can only be performed by a privileged user.

### Uncordon

Not allowed if there is a reason annotation present.

## Additional Features

### Forbidden Users

The webhook also maintains a list of forbidden users who are not allowed to perform certain operations.

### Logs

The logs of the webhook provide details about the operations performed on the nodes, including the user who performed the operation, the reason for doing it, and the date and time it occurred.

## Getting started

### Deploying the controller

```bash
$ make deploy IMG=ghcr.io/dana-team/node-operation-validator:<release>
```

### Install with Helm

Helm chart docs are available on `charts/node-operation-validator` directory.

Make sure `cert-manager` is [installed](https://cert-manager.io/docs/installation/helm/) as a prerequisite.

```
$ helm upgrade --install node-operation-validator --namespace node-operation-webhook-system --create-namespace oci://ghcr.io/dana-team/helm-charts/node-operation-validator --version <release>
```

#### Build your own image

```bash
$ make docker-build docker-push IMG=<registry>/node-operation-validator:<tag>
```