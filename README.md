# function-deletion-protection <!-- omit from toc -->

**Note** this function is in development. Please test in your environment before
using it to protect critical workloads.

`function-deletion-protection` is a Crossplane function that blocks deletion of objects by creating
Crossplane [Usages](https://docs.crossplane.io/master/managed-resources/usages/).

When the function is run as a step in a Composition Pipeline, it looks for
resources with the label `protection.fn.crossplane.io/block-deletion: "true"`.

When run in an Operation, a Usage will be generated for any matched resource.

## Table of Contents <!-- omit from toc -->

- [Overview](#overview)
- [Crossplane v1 and v2 Compatibility](#crossplane-v1-and-v2-compatibility)
- [Installing and Using the Function](#installing-and-using-the-function)
  - [Installing the Function](#installing-the-function)
  - [Running this Function in a Composition Pipeline](#running-this-function-in-a-composition-pipeline)
  - [Usage Reason Strings](#usage-reason-strings)
- [Running as an Operation](#running-as-an-operation)
  - [Function Customization](#function-customization)
  - [Creating Crossplane v1 Usages](#creating-crossplane-v1-usages)
- [Building](#building)
- [Taskfile Support](#taskfile-support)

## Overview

The function works by creating a Crossplane `Usage` for an Object.
When a Usage is created, Crossplane will add the protected resource to a Webhook
that blocks any deletion requests until the `Usage` has been removed from the
Cluster. See
[Usages](https://docs.crossplane.io/latest/managed-resources/usages/) for more
information.

Attempts to delete an Object with a Usage will be rejected by an admission
webhook:

```shell
$ kubectl delete XNetwork/configuration-aws-network  
Error from server (This resource is in-use by 1 usage(s), including the *v1beta1.Usage "configuration-aws-network-26d898-fn-protection" with reason: "created by function-deletion-protection via label protection.fn.crossplane.io/block-deletion".): admission webhook "nousages.protection.crossplane.io" denied the request: This resource is in-use by 1 usage(s), including the *v1beta1.Usage "configuration-aws-network-26d898-fn-protection" with reason: "created by function-deletion-protection via label protection.fn.crossplane.io/block-deletion".
```

The Function can run in a Crossplane Composition, or as a Crossplane Operation.

## Crossplane v1 and v2 Compatibility

By default, this function creates v2 `Usages` using the
`protection.crossplane.io` API Group in Crossplane version 2.0 or higher. The
function has the ability to generate v1 Usages by setting `enableV1Mode: true`
in the function `Input`.

Crossplane v1 `Usages` are Cluster-scoped and cannot be used to protect
namespaced resources like Claims. The function validates this constraint and
will return a fatal error if it encounters a namespaced resource with the
deletion protection label when `enableV1Mode` is `true`. This validation ensures
users cannot accidentally attempt to create incompatible v1 Usages for namespaced
resources.

## Installing and Using the Function

### Installing the Function

The function can be installed into a Crossplane cluster using the following
manifest:

```yaml
apiVersion: pkg.crossplane.io/v1beta1
kind: Function
metadata:
  name: crossplane-contrib-function-deletion-protection
spec:
  package: xpkg.upbound.io/crossplane-contrib/function-deletion-protection:v0.2.1
```

Releases are posted to
[Releases](https://github.com/crossplane-contrib/function-deletion-protection/releases)
and the [Upbound
Marketplace](https://marketplace.upbound.io/functions/crossplane-contrib/function-deletion-protection).

### Running this Function in a Composition Pipeline

When run in a [Composition
Pipeline](https://docs.crossplane.io/latest/composition/compositions/#use-a-pipeline-of-functions-in-a-composition)
this function monitors resources in a Composition for the
`protection.fn.crossplane.io/block-deletion` label and creates corresponding
Usage objects to prevent accidental deletion.

See [examples/composition](examples/composition/) for a complete working example.

The function creates Usages for:

- Composite resources (XRs) when labeled
- Composed resources when labeled. If a Composed resources is protected, the
  parent Composite will also be protected.

Resources can be labeled outside of the Composition using `kubectl label`. The
function will check if either the desired or observed state is labeled:

```yaml
apiVersion: ec2.aws.upbound.io/v1beta1
kind: VPC
metadata:
  labels:
    protection.fn.crossplane.io/block-deletion: "true"
  name: my-vpc
```

The function monitors the Composite and all Composed resources. In this case
since the label is applied to a Cluster-scoped resource it will generate a
`ClusterUsage`:

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

If the resource is Namespaced a `Usage` will be created in the Resource's
namespace.

The label can be applied to the resource in the Composition (the "Desired"
state), or it can be applied to the Resource in the cluster (the "Observed"
state). If the Desired and Observed labels conflict, the function will default
to creating the Usage.

### Usage Reason Strings

The function provides granular reason strings to help identify why a Usage was
created:

- **`created by function-deletion-protection via label
  protection.fn.crossplane.io/block-deletion`** - A resource was protected
  because it has the `protection.fn.crossplane.io/block-deletion: "true"` label
- **`created by function-deletion-protection because a composed resource is
  protected`** - A Composite resource was protected because one of its composed
  resources is protected
- **`created by function-deletion-protection by an Operation`** - A resource was
  protected by a regular Operation (with the label)
- **`created by function-deletion-protection by a WatchOperation`** - A resource
  was protected by a WatchOperation (automatic protection)

These reason strings appear in the Usage's `spec.reason` field and in deletion
rejection messages, making it easy to understand why a resource cannot be
deleted.

## Running as an Operation

When invoked by a
[`WatchOperation`](https://docs.crossplane.io/latest/operations/watchoperation/)
any Kubernetes resource on the Cluster that matches the watch conditions will
have a Usage generated. In this example `Namespaces` with the `block-deletion:
"true"` label will trigger an Operation:

```yaml
---
apiVersion: ops.crossplane.io/v1alpha1
kind: WatchOperation
metadata:
  name: block-namespace-deletion
spec:
  watch:
    apiVersion: v1
    kind: Namespace
    matchLabels:
      block-deletion: "true"
  operationTemplate:
    spec:
      mode: Pipeline
      pipeline:
        - step: block-deletion
          functionRef:
            name: crossplane-contrib-function-deletion-protection
          input:
            apiVersion: protection.fn.crossplane.io/v1beta1
            kind: Input
            cacheTTL: 1h
            enableV1Mode: false
```

See [examples/operations](examples/operations/) for a complete working example with
RBAC configuration. Operations are a Crossplane 2.x feature.

### Function Customization

Setting `cacheTTL` configures the [Function Response
Cache](https://docs.crossplane.io/latest/operations/operation/#function-response-cache).
This can reduce the number of times the function is called.

```yaml
    - step: protect-resources
      functionRef:
        name: crossplane-contrib-function-protection
      input:
        apiVersion: protection.fn.crossplane.io/v1beta1
        kind: Input
        cacheTTL: 10m
```

### Creating Crossplane v1 Usages

There is a Compatibility mode for generating Crossplane v1 Usages by setting
`enableV1Mode: true` in the Function's input. When this setting is enabled, v1
Usages will be created. Please note that this feature will be removed when
upstream Crossplane deprecates v1 APIs.

**Important**: v1 Usages are cluster-scoped only. If you attempt to protect a
namespaced resource (like a Claim) with `enableV1Mode: true`, the function will
return a fatal error with a message explaining the incompatibility.

```yaml
    - step: protect-resources
      functionRef:
        name: crossplane-contrib-function-protection
      input:
        apiVersion: protection.fn.crossplane.io/v1beta1
        kind: Input
        enableV1Mode: true
```

When this feature is enabled, the function will generate v1 Cluster-scoped
`Usages` using the `apiextensions.crossplane.io/v1beta1` API Group:

```yaml
apiVersion: apiextensions.crossplane.io/v1beta1
kind: Usage
metadata:
  name: ...
```

If a Namespaced resource is encountered while `enableV1Mode: true`, you the function will return an error similar to the following:

```text
crossplane: error: cannot render composite resource: pipeline step "protect-resources" returned a fatal result: cannot process composed resources: cannot protect namespaced resource (kind: InternetGateway, name: configuration-aws-network-ff951409171d, namespace: test) with enableV1Mode=true. v1 usages only support cluster-scoped resources.
```

## Building

To build the Docker image for both arm64 and amd64 and save the results in a
`tar` file, run:

```shell
export VERSION=0.2.1
# Build the function's runtime image
docker buildx build --platform linux/amd64 . --tag=test:v1 --target=image --output type=docker,dest=function-deletion-protection-runtime-amd64-v${VERSION}.tar
docker buildx build --platform linux/arm64 . --tag=test:v1 --target=image --output type=docker,dest=function-deletion-protection-runtime-arm64-v${VERSION}.tar
```

Next, build the Crossplane Package:

```shell
export VERSION=0.2.1
crossplane xpkg build -f package --embed-runtime-image-tarball=function-deletion-protection-runtime-amd64-v${VERSION}.tar -o function-deletion-protection-amd64-v${VERSION}.xpkg
crossplane xpkg build -f package --embed-runtime-image-tarball=function-deletion-protection-runtime-arm64-v${VERSION}.tar -o function-deletion-protection-arm64-v${VERSION}.xpkg
```

These packages can be pushed to any Docker-compatible registry:

```shell
export VERSION=0.2.1
crossplane xpkg push index.docker.io/steve/function-deletion-protection:v0${VERSION} --package-files function-deletion-protection-amd64-v${VERSION}.xpkg,function-deletion-protection-arm64-v${VERSION}.xpkg
```

## Taskfile Support

This project has several [Taskfile](https://taskfile.dev) tasks:

```shell
task --list 
task: Available tasks for this project:
* build-docker:       Builds the function into a deployable Docker image and saves it as a tar file.
* build-xpkg:         Creates a Crossplane .xpkg file from a Docker tar file.
* clean:              Removes Artifacts
* push-xpkg:          Pushes Crossplane package to an OCI repository. Please ensure the repository exists before pushing.
```
