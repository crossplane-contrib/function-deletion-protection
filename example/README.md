# Example of Generating Usages

This is an example of creating Usages in a Composition.

In the [`observed`](observed/) directory are resources that represent provisioned
Managed Resources in a Crossplane cluster, based on [configuration-aws-network](https://github.com/upbound/configuration-aws-network).

The [VPC](observed/vpc.ec2.aws.upbound.io-configuration-aws-network-c82ef4fa3e45.yaml) has been labeled with `protection.fn.crossplane.io/block-deletion: "true"`:

```yaml
labels:
    protection.fn.crossplane.io/block-deletion: "true"
```

Run this example:

```shell
crossplane render \
  --observed-resources observed \
  --include-full-xr \
  xr.yaml composition.yaml functions.yaml
```

And the output will include the newly generated Usages. Because a Composed Resource has protection,
a `ClusterUsage` will be generated for the XNetwork composite.

```yaml
...
---
apiVersion: protection.crossplane.io/v1beta1
kind: ClusterUsage
metadata:
  annotations:
    crossplane.io/composition-resource-name: vpc-usage
  labels:
    crossplane.io/composite: configuration-aws-network
  name: -e3b0c4-fn-protection
  ownerReferences:
  - apiVersion: aws.platform.upbound.io/v1alpha1
    blockOwnerDeletion: true
    controller: true
    kind: XNetwork
    name: configuration-aws-network
    uid: ""
spec:
  of:
    apiVersion: ec2.aws.upbound.io/v1beta1
    kind: VPC
    resourceRef:
      name: ""
  reason: created by function-deletion-protection via label protection.fn.crossplane.io/block-deletion
---
apiVersion: protection.crossplane.io/v1beta1
kind: ClusterUsage
metadata:
  annotations:
    crossplane.io/composition-resource-name: xr-configuration-aws-network-usage
  labels:
    crossplane.io/composite: configuration-aws-network
  name: configuration-aws-network-26d898-fn-protection
  ownerReferences:
  - apiVersion: aws.platform.upbound.io/v1alpha1
    blockOwnerDeletion: true
    controller: true
    kind: XNetwork
    name: configuration-aws-network
    uid: ""
spec:
  of:
    apiVersion: aws.platform.upbound.io/v1alpha1
    kind: XNetwork
    resourceRef:
      name: configuration-aws-network
  reason: created by function-deletion-protection via label protection.fn.crossplane.io/block-deletion
```

## Enabling Crossplane v1 Mode

To simulate output on Crossplane v1 Clusters, update the [`composition.yaml`](composition.yaml)
file and set `enableV1Mode` to `true`:

```yaml
    - step: protect-resources
      functionRef:
        name: crossplane-contrib-function-protection
      input:
        apiVersion: protection.fn.crossplane.io/v1beta1
        kind: Input
        enableV1Mode: true
```

Rendering the manifests will now generate v1 `Usages`, which have an API Version of:
`apiextensions.crossplane.io/v1beta1`.

```yaml
---
apiVersion: apiextensions.crossplane.io/v1beta1
kind: Usage
metadata:
  annotations:
    crossplane.io/composition-resource-name: xr-configuration-aws-network-usage
  labels:
    crossplane.io/composite: configuration-aws-network
  name: configuration-aws-network-26d898-fn-protection
```

## Local Testing

If developing the Go code, enable the `render.crossplane.io/runtime: Development` annotation
in the [`functions.yaml`](functions.yaml) file:

```yaml
apiVersion: pkg.crossplane.io/v1beta1
kind: Function
metadata:
  name: crossplane-contrib-function-protection
  annotations:
    # This tells crossplane render to connect to the function locally.
    # Comment this out if updating the function's Go code.
    render.crossplane.io/runtime: Development
spec: {}
```

And then run the function in a terminal. `crossplane render` will connected to the local process.

```shell
go run . --insecure --debug
```

`crossplane render` commands will now connec to the local process. 

