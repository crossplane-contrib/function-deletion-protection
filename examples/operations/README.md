# Operations Function Support

Crossplane 2.x includes support for [Operations](https://docs.crossplane.io/latest/operations/operation/)
that run outside of the Composition Reconciliation loop.

In this example, a Crossplane `WatchOperation` is watching Kubernetes `Namespaces`. When a Namespace
is given the `block-deletion: "true"` label, the `WatchOperation` will invoke `function-deletion-protection`
and block deletion of the Namespace.

Note that Operations can only create and modify resources. Any `Usages` or `ClusterUsages` created by
this Operation need to be deleted manually before protected resources can be deleted.

## Reason Strings for Operations

The function uses different reason strings to distinguish between protection types:

- **WatchOperation Protection**: Resources matched by a `WatchOperation` automatically get protected with the reason `created by function-deletion-protection by a WatchOperation` (see `crossplane-system` namespace example below)
- **Operation with Label Protection**: Resources in an Operation's required resources that have the `protection.fn.crossplane.io/block-deletion: "true"` label get the reason `created by function-deletion-protection by an Operation` (see `kube-system` namespace example below)

This distinction makes it clear whether protection was triggered automatically by a watch condition or explicitly via a label.

## Running This Example on a Crossplane Cluster

### Installing the Function

Apply the following manifest to the cluster. Versions v0.2.x and higher of `function-deletion-protection` support Operations:

```yaml
apiVersion: pkg.crossplane.io/v1
kind: Function
metadata:
  name: crossplane-contrib-function-deletion-protection
spec:
  package: xpkg.upbound.io/crossplane-contrib/function-deletion-protection:v0.2.1
```

Ensure that the function is installed and healthy:

```shell
$ kubectl get function.pkg crossplane-contrib-function-deletion-protection
NAME                                              INSTALLED   HEALTHY   PACKAGE                                                                          AGE
crossplane-contrib-function-deletion-protection   True        True      xpkg.upbound.io/crossplane-contrib/function-deletion-protection:v0.2.1   57m
```

### Install the WatchOperation

The WatchOperation protects any Namespace with the label `block-deletion: "true"`.

To install this Operation onto a Crossplane cluster, apply the [`watchoperation.yaml`](watchoperation.yaml)
manifest.

```shell
$ kubectl apply -f watchoperation.yaml
watchoperation.ops.crossplane.io/block-namespace-deletion created
```

### Create RBAC Permissons for Crossplane

The Crossplane pod needs RBAC access to watch `Namespaces` in order to trigger the `Operation`. This
can be done using [Aggregation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#aggregated-clusterroles).

By adding the `rbac.crossplane.io/aggregate-to-crossplane: "true"` to a `ClusterRole`, the `crossplane` `ServiceAccount`
will automatically get the roles.

Create a `ClusterRole` to grant partial access to `Namespaces`:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: crossplane:operation-function-deletion-protection:aggregate-to-crossplane
  labels:
    rbac.crossplane.io/aggregate-to-crossplane: "true"
rules:
  - apiGroups: [""]
    resources: ["namespaces"]
    verbs: ["get", "list", "watch", "update", "patch"]
```

## Protecting Namespaces

Label any Namespace to trigger the `Operation`:

```shell
$ kubectl label namespace crossplane-system block-deletion="true" --overwrite
namespace/crossplane-system labeled
```

Check that the `WatchOperation` has been triggered:

```shell
$ kubectl get watchoperation  block-namespace-deletion                
NAME                       KIND        COUNT   SYNCED   WATCHING   LAST SCHEDULE   LAST SUCCESS   AGE
block-namespace-deletion   Namespace   1       True     True       8s              8s             46m
```

When a `WatchOperation` is triggered, it creates a corresponding `Operation`:

```shell
$ kubectl get operation 
NAME                               SYNCED   SUCCEEDED   AGE
block-namespace-deletion-03d6be2   True     True        95s
```

This operation will contain the `ClusterUsage` that was generated:

```shell
$ kubectl get operation block-namespace-deletion-03d6be2 -o yaml | yq .status.appliedResourceRefs
- apiVersion: protection.crossplane.io/v1beta1
  kind: ClusterUsage
  name: namespace-crossplane-system-e54c22-fn-protection
```

The `ClusterUsage` has been created:

```shell
$ kubectl get clusterusage                                
NAME                                               DETAILS                                                       READY   AGE
namespace-crossplane-system-e54c22-fn-protection   created by function-deletion-protection by a WatchOperation   True    56m
```

Deletion attempts on the protected Namespace should be rejected. Please test this carefully:

```shell
$ kubectl delete ns crossplane-system 
Error from server (This resource is in-use by 1 usage(s), including the *v1beta1.ClusterUsage "namespace-crossplane-system-e54c22-fn-protection" with reason: "created by function-deletion-protection by a WatchOperation".): admission webhook "nousages.protection.crossplane.io" denied the request: This resource is in-use by 1 usage(s), including the *v1beta1.ClusterUsage "namespace-crossplane-system-e54c22-fn-protection" with reason: "created by function-deletion-protection by a WatchOperation".
```

## Running the Operation Locally

The `Operation` can be simulated Locally using the `crossplane alpha op render` in CLI versions 2.0 and
higher. The [`operation.yaml`](operation.yaml) simulates resources from a `WatchOperation`
on the `crossplane-system` namespace.

The [`required`](required/) directory contains Namespace manifests, with `kube-system` labeled
for deletion protection. The `default` resources is included in `requiredResources`, but since
it is not labeled a `ClusterUsage` will not be created.

```shell
$ crossplane alpha render op operation.yaml functions.yaml \
        --required-resources=required
---
apiVersion: ops.crossplane.io/v1alpha1
kind: Operation
metadata:
  name: block-namespace-deletion
status:
  appliedResourceRefs:
  - apiVersion: protection.crossplane.io/v1beta1
    kind: ClusterUsage
    name: namespace-crossplane-system-e54c22-fn-protection
  - apiVersion: protection.crossplane.io/v1beta1
    kind: ClusterUsage
    name: namespace-kube-system-ec6eea-fn-protection
  pipeline: []
---
apiVersion: protection.crossplane.io/v1beta1
kind: ClusterUsage
metadata:
  name: namespace-crossplane-system-e54c22-fn-protection
spec:
  of:
    apiVersion: v1
    kind: Namespace
    resourceRef:
      name: crossplane-system
  reason: created by function-deletion-protection by a WatchOperation
---
apiVersion: protection.crossplane.io/v1beta1
kind: ClusterUsage
metadata:
  name: namespace-kube-system-ec6eea-fn-protection
spec:
  of:
    apiVersion: v1
    kind: Namespace
    resourceRef:
      name: kube-system
  reason: created by function-deletion-protection by an Operation
```

## Debugging

Run `kubectl describe watchoperation block-namespace-deletion` to get events from the `WatchOperation`.

### Insufficient RBAC

If the Crossplane pod does not have sufficient permissions to watch resources, the `WatchOperation` will
report this in events:

```shell
 Warning  EstablishWatched  48m (x10 over 67m)  watchoperation/watchoperation.ops.crossplane.io  cannot start watched resource controller watches: cannot get informer for "/v1, Kind=Namespace": Timeout: failed waiting for *unstructured.Unstructured Informer to sync
```
