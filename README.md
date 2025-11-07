# function-deletion-protection

**Note** this function is in development. Please test in your environment before
using it with critical workloads.

`function-deletion-protection` is a Crossplane Composition Function that blocks deletion of resources by creating `ClusterUsage` or `Usage` objects when resources are labeled with `protection.fn.crossplane.io/block-deletion: "true"`.

When a Crossplane `Usage` is created for an Object, Crossplane creates a webhook that blocks any deletion
requests until the `Usage` has been removed from the Cluster. See [Usages](https://docs.crossplane.io/latest/managed-resources/usages/) for more information.

This function creates v2 `Usages` using the `protection.crossplane.io` API Group in Crossplane version
2.0 or higher. The function has the ability to generate v1 Usages by setting `enableV1Mode: true` in the
function `Input`.

## Overview

This function monitors resources in a composition for the `protection.fn.crossplane.io/block-deletion` label and creates corresponding `ClusterUsage` objects to prevent accidental deletion. It can protect:

- Composite resources (XRs) when labeled
- Composed resources when labeled. If a Composed resources is protected, the parent Composite will also be protected.

Resources can be labeled outside of the Composition using `kubectl label`. The function will check if either the
desired or observed state is labeled:

```yaml
apiVersion: ec2.aws.upbound.io/v1beta1
kind: VPC
metadata:
  labels:
    protection.fn.crossplane.io/block-deletion: "true"
  name: my-vpc
```

The function monitors the Composite and all Composed resources. In this case since the label
is applied to a Cluster-scoped resource it will generate a `ClusterUsage`:

```yaml
apiVersion: protection.crossplane.io/v1beta1
kind: ClusterUsage
metadata:
  name: my-vpc-2a782e-fn-protection
spec:
  of:
    apiVersion: ec2.aws.upbound.io/v1beta1
    kind: VPC
    resourceRef:
      name: my-vpc
  reason: created by function-deletion-protection via label protection.fn.crossplane.io/block-deletion
```

If the resources is Namespaced a `Usage` will be created in the Resource's namespace.

The label can be applied to the resource in the Composition (the "Desired" state), or it can be applied to the
Resource in the cluster (the "Observed" state). If the Desired and Observed labels conflict, the function will
default to creating the Usage.

## Installation

The function can be installed in a Crossplane [Composition Pipeline](https://docs.crossplane.io/latest/composition/compositions/). A test docker image is available from my repository at `index.docker.io/steve/function-deletion-protection` until the project migrates to Crossplane repositories.

The function can be installed into a Crossplane cluster using the following manifest:

```yaml
apiVersion: pkg.crossplane.io/v1
kind: Function
metadata:
  name: crossplane-contrib-function-deletion-protection
spec:
  package: index.docker.io/steve/function-deletion-protection:v0.1.0
```

### Function Customization

Setting `cacheTTL` configures the [Function Response Cache](https://docs.crossplane.io/latest/operations/operation/#function-response-cache). This can reduce the number of times the function is called.

```yaml
    - step: protect-resources
      functionRef:
        name: crossplane-contrib-function-protection
      input:
        apiVersion: protection.fn.crossplane.io/v1beta1
        kind: Input
        cacheTTL: 10m
```

### Creating Crossplane V1 Usages

There is a Compatibility mode for generating Crossplane v1 Usages by setting `enableV1Mode: true`
in the Function's input. When this setting is enabled, v1 Usages will be created. Please note that
this feature will be removed when upstream Crossplane deprecates v1 APIs.

```yaml
    - step: protect-resources
      functionRef:
        name: crossplane-contrib-function-protection
      input:
        apiVersion: protection.fn.crossplane.io/v1beta1
        kind: Input
        enableV1Mode: true
```

When this feature is enabled, the function will generate v1 Cluster-scoped `Usages` using the
`apiextensions.crossplane.io/v1beta1` API Group:

```yaml
apiVersion: apiextensions.crossplane.io/v1beta1
kind": Usage
metadata:
  name: ...
```

## Building

To build the Docker image for both arm64 and amd64 and save the results
in a `tar` file, run:

```shell
export VERSION=0.2.0
# Build the function's runtime image
$ docker buildx build --platform linux/amd64,linux/arm64 . --output type=oci,dest=function-deletion-protection-runtime-v${VERSION}.tar
```

Next, build the Crossplane Package:

```shell
export VERSION=0.2.0
crossplane xpkg build -f package --embed-runtime-image-tarball=function-deletion-protection-runtime-v${VERSION}.tar -o function-deletion-protection-v${VERSION}.xpkg
```
