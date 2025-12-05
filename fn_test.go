package main

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/crossplane/function-sdk-go/logging"
	fnv1 "github.com/crossplane/function-sdk-go/proto/v1"
	"github.com/crossplane/function-sdk-go/resource"
	"github.com/crossplane/function-sdk-go/resource/composed"
)

func TestRunFunction(t *testing.T) {
	type args struct {
		ctx context.Context
		req *fnv1.RunFunctionRequest
	}
	type want struct {
		rsp *fnv1.RunFunctionResponse
		err error
	}

	cases := map[string]struct {
		reason string
		args   args
		want   want
	}{
		"CacheTTLDefault": {
			reason: "The Function should set the function Response cache to default",
			args: args{
				req: &fnv1.RunFunctionRequest{
					Meta: &fnv1.RequestMeta{Tag: "hello"},
					Input: resource.MustStructJSON(`{
						"apiVersion": "template.fn.crossplane.io/v1beta1",
						"kind": "Input"
					}`),
				},
			},
			want: want{
				rsp: &fnv1.RunFunctionResponse{
					Desired:    &fnv1.State{},
					Meta:       &fnv1.ResponseMeta{Tag: "hello", Ttl: durationpb.New(1 * time.Minute)},
					Results:    []*fnv1.Result{},
					Conditions: []*fnv1.Condition{},
				},
			},
		},
		"CacheTTLSet": {
			reason: "The Function should set the function Response cache from the input",
			args: args{
				req: &fnv1.RunFunctionRequest{
					Meta: &fnv1.RequestMeta{Tag: "hello"},
					Input: resource.MustStructJSON(`{
						"apiVersion": "template.fn.crossplane.io/v1beta1",
						"kind": "Input",
						"cacheTTL": "5m"
					}`),
				},
			},
			want: want{
				rsp: &fnv1.RunFunctionResponse{
					Desired:    &fnv1.State{},
					Meta:       &fnv1.ResponseMeta{Tag: "hello", Ttl: durationpb.New(5 * time.Minute)},
					Results:    []*fnv1.Result{},
					Conditions: []*fnv1.Condition{},
				},
			},
		},
		"CacheTTLInvalid": {
			reason: "The Function should return an error if the CacheTTL duration is invalid",
			args: args{
				req: &fnv1.RunFunctionRequest{
					Meta: &fnv1.RequestMeta{Tag: "hello"},
					Input: resource.MustStructJSON(`{
						"apiVersion": "template.fn.crossplane.io/v1beta1",
						"kind": "Input",
						"cacheTTL": "5x"
					}`),
				},
			},
			want: want{
				rsp: &fnv1.RunFunctionResponse{
					Meta: &fnv1.ResponseMeta{Tag: "hello", Ttl: durationpb.New(1 * time.Minute)},
					Results: []*fnv1.Result{
						{
							Message:  "cannot set cacheTTL: time: unknown unit \"x\" in duration \"5x\"",
							Severity: fnv1.Severity_SEVERITY_FATAL,
							Target:   fnv1.Target_TARGET_COMPOSITE.Enum(),
						},
					},
					Conditions: []*fnv1.Condition{},
				},
			},
		},
		"NoResourcesToProtect": {
			reason: "The Function should not create any Usages when the label is not present",
			args: args{
				req: &fnv1.RunFunctionRequest{
					Meta: &fnv1.RequestMeta{Tag: "hello"},
					Input: resource.MustStructJSON(`{
						"apiVersion": "template.fn.crossplane.io/v1beta1",
						"kind": "Input"
					}`),
					Observed: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr"
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed"
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
						},
					},
				},
			},
			want: want{
				rsp: &fnv1.RunFunctionResponse{
					Desired:    &fnv1.State{},
					Meta:       &fnv1.ResponseMeta{Tag: "hello", Ttl: durationpb.New(1 * time.Minute)},
					Results:    []*fnv1.Result{},
					Conditions: []*fnv1.Condition{},
				},
			},
		},
		"ProtectCompositeResourceByCompositeLabel": {
			reason: "Cluster Usages Created for a Composite when a Desired Composite resource is labeled",
			args: args{
				req: &fnv1.RunFunctionRequest{
					Meta: &fnv1.RequestMeta{Tag: "hello"},
					Input: resource.MustStructJSON(`{
						"apiVersion": "template.fn.crossplane.io/v1beta1",
						"kind": "Input"
					}`),
					Desired: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr",
									"labels": {
										"protection.fn.crossplane.io/block-deletion": "true"
									}
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed"
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
						},
					},
					Observed: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr"
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed"
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
						},
					},
				},
			},
			want: want{
				rsp: &fnv1.RunFunctionResponse{
					Desired: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr",
									"labels": {
										"protection.fn.crossplane.io/block-deletion": "true"
									}
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed"
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
							"xr-my-test-xr-usage": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "protection.crossplane.io/v1beta1",
									"kind": "ClusterUsage",
									"metadata": {
										"name": "testxr-my-test-xr-23c942-fn-protection"
									},
									"spec": {
										"of": {
											"apiVersion": "test.crossplane.io/v1",
											"kind": "TestXR",
											"resourceRef": {
												"name": "my-test-xr"
											}
										},
										"reason": "created by function-deletion-protection via label protection.fn.crossplane.io/block-deletion"
									}
								}`),
							},
						},
					},
					Meta:       &fnv1.ResponseMeta{Tag: "hello", Ttl: durationpb.New(1 * time.Minute)},
					Results:    []*fnv1.Result{},
					Conditions: []*fnv1.Condition{},
				},
			},
		},
		"ProtectNamespacedCompositeResourceByCompositeLabel": {
			reason: "Namespaced Usages Created for a Composite when a Desired Composite resource is labeled",
			args: args{
				req: &fnv1.RunFunctionRequest{
					Meta: &fnv1.RequestMeta{Tag: "hello"},
					Input: resource.MustStructJSON(`{
						"apiVersion": "template.fn.crossplane.io/v1beta1",
						"kind": "Input"
					}`),
					Desired: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.m.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr",
									"namespace": "test",
									"labels": {
										"protection.fn.crossplane.io/block-deletion": "true"
									}
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.m.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed",
										"namespace": "test"
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
						},
					},
					Observed: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.m.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr",
									"namespace": "test"
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.m.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed",
										"namespace": "test"
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
						},
					},
				},
			},
			want: want{
				rsp: &fnv1.RunFunctionResponse{
					Desired: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.m.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr",
									"namespace": "test",
									"labels": {
										"protection.fn.crossplane.io/block-deletion": "true"
									}
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.m.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed",
										"namespace": "test"
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
							"xr-my-test-xr-usage": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "protection.crossplane.io/v1beta1",
									"kind": "Usage",
									"metadata": {
										"name": "testxr-my-test-xr-23c942-fn-protection",
										"namespace": "test"
									},
									"spec": {
										"of": {
											"apiVersion": "test.m.crossplane.io/v1",
											"kind": "TestXR",
											"resourceRef": {
												"name": "my-test-xr"
											}
										},
										"reason": "created by function-deletion-protection via label protection.fn.crossplane.io/block-deletion"
									}
								}`),
							},
						},
					},
					Meta:       &fnv1.ResponseMeta{Tag: "hello", Ttl: durationpb.New(1 * time.Minute)},
					Results:    []*fnv1.Result{},
					Conditions: []*fnv1.Condition{},
				},
			},
		},
		"ProtectComposedResourceAndCompositeResourceByDesiredComposed": {
			reason: "Cluster Usages Created for XR and Resource when a Desired Composed resource is labeled",
			args: args{
				req: &fnv1.RunFunctionRequest{
					Meta: &fnv1.RequestMeta{Tag: "hello"},
					Input: resource.MustStructJSON(`{
						"apiVersion": "template.fn.crossplane.io/v1beta1",
						"kind": "Input"
					}`),
					Desired: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr"
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed",
										"labels": {
										   "protection.fn.crossplane.io/block-deletion": "true"
										}
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
						},
					},

					Observed: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr"
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed"
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
						},
					},
				},
			},
			want: want{
				rsp: &fnv1.RunFunctionResponse{
					Desired: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr"
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed",
										"labels": {
										   "protection.fn.crossplane.io/block-deletion": "true"
										}
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
							"xr-my-test-xr-usage": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "protection.crossplane.io/v1beta1",
									"kind": "ClusterUsage",
									"metadata": {
										"name": "testxr-my-test-xr-23c942-fn-protection"
									},
									"spec": {
										"of": {
											"apiVersion": "test.crossplane.io/v1",
											"kind": "TestXR",
											"resourceRef": {
												"name": "my-test-xr"
											}
										},
										"reason": "created by function-deletion-protection because a composed resource is protected"
									}
								}`),
							},
							"ready-composed-resource-usage": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "protection.crossplane.io/v1beta1",
									"kind": "ClusterUsage",
									"metadata": {
										"name": "testcomposed-my-test-composed-601ab8-fn-protection"
									},
									"spec": {
										"of": {
											"apiVersion": "test.crossplane.io/v1",
											"kind": "TestComposed",
											"resourceRef": {
												"name": "my-test-composed"
											}
										},
										"reason": "created by function-deletion-protection via label protection.fn.crossplane.io/block-deletion"
									}
								}`),
							},
						},
					},
					Meta:       &fnv1.ResponseMeta{Tag: "hello", Ttl: durationpb.New(1 * time.Minute)},
					Results:    []*fnv1.Result{},
					Conditions: []*fnv1.Condition{},
				},
			},
		},
		"ProtectComposedResourceAndCompositeResourceByObservedComposed": {
			reason: "Cluster Usages Created for XR and Resource when an Observed Composed resource is labeled",
			args: args{
				req: &fnv1.RunFunctionRequest{
					Meta: &fnv1.RequestMeta{Tag: "hello"},
					Input: resource.MustStructJSON(`{
						"apiVersion": "template.fn.crossplane.io/v1beta1",
						"kind": "Input"
					}`),
					Desired: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr"
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed"
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
						},
					},

					Observed: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr"
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed",
										"labels": {
										   "protection.fn.crossplane.io/block-deletion": "true"
										}
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
						},
					},
				},
			},
			want: want{
				rsp: &fnv1.RunFunctionResponse{
					Desired: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr"
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed"
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
							"xr-my-test-xr-usage": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "protection.crossplane.io/v1beta1",
									"kind": "ClusterUsage",
									"metadata": {
										"name": "testxr-my-test-xr-23c942-fn-protection"
									},
									"spec": {
										"of": {
											"apiVersion": "test.crossplane.io/v1",
											"kind": "TestXR",
											"resourceRef": {
												"name": "my-test-xr"
											}
										},
										"reason": "created by function-deletion-protection because a composed resource is protected"
									}
								}`),
							},
							"ready-composed-resource-usage": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "protection.crossplane.io/v1beta1",
									"kind": "ClusterUsage",
									"metadata": {
										"name": "testcomposed-my-test-composed-601ab8-fn-protection"
									},
									"spec": {
										"of": {
											"apiVersion": "test.crossplane.io/v1",
											"kind": "TestComposed",
											"resourceRef": {
												"name": "my-test-composed"
											}
										},
										"reason": "created by function-deletion-protection via label protection.fn.crossplane.io/block-deletion"
									}
								}`),
							},
						},
					},
					Meta:       &fnv1.ResponseMeta{Tag: "hello", Ttl: durationpb.New(1 * time.Minute)},
					Results:    []*fnv1.Result{},
					Conditions: []*fnv1.Condition{},
				},
			},
		},
		"ProtectNamespacedComposedResourceAndCompositeResourceByDesiredComposed": {
			reason: "Namespaced Usages Created for XR and Resource when a Desired Composed resource is labeled",
			args: args{
				req: &fnv1.RunFunctionRequest{
					Meta: &fnv1.RequestMeta{Tag: "hello"},
					Input: resource.MustStructJSON(`{
						"apiVersion": "template.fn.crossplane.io/v1beta1",
						"kind": "Input"
					}`),
					Desired: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.m.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr",
									"namespace": "test"
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.m.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed",
										"namespace": "test",
										"labels": {
										   "protection.fn.crossplane.io/block-deletion": "true"
										}
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
						},
					},

					Observed: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.m.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr",
									"namespace": "test"
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.m.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed",
										"namespace": "test"
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
						},
					},
				},
			},
			want: want{
				rsp: &fnv1.RunFunctionResponse{
					Desired: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.m.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr",
									"namespace": "test"
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.m.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed",
										"namespace": "test",
										"labels": {
										   "protection.fn.crossplane.io/block-deletion": "true"
										}
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
							"xr-my-test-xr-usage": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "protection.crossplane.io/v1beta1",
									"kind": "Usage",
									"metadata": {
										"name": "testxr-my-test-xr-23c942-fn-protection",
										"namespace": "test"
									},
									"spec": {
										"of": {
											"apiVersion": "test.m.crossplane.io/v1",
											"kind": "TestXR",
											"resourceRef": {
												"name": "my-test-xr"
											}
										},
										"reason": "created by function-deletion-protection because a composed resource is protected"
									}
								}`),
							},
							"ready-composed-resource-usage": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "protection.crossplane.io/v1beta1",
									"kind": "Usage",
									"metadata": {
										"name": "testcomposed-my-test-composed-601ab8-fn-protection",
										"namespace": "test"
									},
									"spec": {
										"of": {
											"apiVersion": "test.m.crossplane.io/v1",
											"kind": "TestComposed",
											"resourceRef": {
												"name": "my-test-composed"
											}
										},
										"reason": "created by function-deletion-protection via label protection.fn.crossplane.io/block-deletion"
									}
								}`),
							},
						},
					},
					Meta:       &fnv1.ResponseMeta{Tag: "hello", Ttl: durationpb.New(1 * time.Minute)},
					Results:    []*fnv1.Result{},
					Conditions: []*fnv1.Condition{},
				},
			},
		},
		"ProtectCompositeResourceWithV1Usage": {
			reason: "V1 Usage Created for a Composite when EnableV1Mode is true",
			args: args{
				req: &fnv1.RunFunctionRequest{
					Meta: &fnv1.RequestMeta{Tag: "hello"},
					Input: resource.MustStructJSON(`{
						"apiVersion": "template.fn.crossplane.io/v1beta1",
						"kind": "Input",
						"enableV1Mode": true
					}`),
					Desired: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr",
									"labels": {
										"protection.fn.crossplane.io/block-deletion": "true"
									}
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed"
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
						},
					},
					Observed: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr"
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed"
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
						},
					},
				},
			},
			want: want{
				rsp: &fnv1.RunFunctionResponse{
					Desired: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr",
									"labels": {
										"protection.fn.crossplane.io/block-deletion": "true"
									}
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed"
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
							"xr-my-test-xr-usage": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "apiextensions.crossplane.io/v1beta1",
									"kind": "Usage",
									"metadata": {
										"name": "testxr-my-test-xr-23c942-fn-protection"
									},
									"spec": {
										"of": {
											"apiVersion": "test.crossplane.io/v1",
											"kind": "TestXR",
											"resourceRef": {
												"name": "my-test-xr"
											}
										},
										"reason": "created by function-deletion-protection via label protection.fn.crossplane.io/block-deletion"
									}
								}`),
							},
						},
					},
					Meta:       &fnv1.ResponseMeta{Tag: "hello", Ttl: durationpb.New(1 * time.Minute)},
					Results:    []*fnv1.Result{},
					Conditions: []*fnv1.Condition{},
				},
			},
		},
		"ProtectCompositeResourceWithV1UsageWhenProtectedResourcesExist": {
			reason: "V1 Usage Created for a Composite when CreateV1Usages is true and protected composed resources exist",
			args: args{
				req: &fnv1.RunFunctionRequest{
					Meta: &fnv1.RequestMeta{Tag: "hello"},
					Input: resource.MustStructJSON(`{
						"apiVersion": "template.fn.crossplane.io/v1beta1",
						"kind": "Input",
						"enableV1Mode": true
					}`),
					Desired: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr"
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed",
										"labels": {
											"protection.fn.crossplane.io/block-deletion": "true"
										}
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
						},
					},
					Observed: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr"
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed"
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
						},
					},
				},
			},
			want: want{
				rsp: &fnv1.RunFunctionResponse{
					Desired: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr"
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed",
										"labels": {
											"protection.fn.crossplane.io/block-deletion": "true"
										}
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
							"ready-composed-resource-usage": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "apiextensions.crossplane.io/v1beta1",
									"kind": "Usage",
									"metadata": {
										"name": "testcomposed-my-test-composed-601ab8-fn-protection"
									},
									"spec": {
										"of": {
											"apiVersion": "test.crossplane.io/v1",
											"kind": "TestComposed",
											"resourceRef": {
												"name": "my-test-composed"
											}
										},
										"reason": "created by function-deletion-protection via label protection.fn.crossplane.io/block-deletion"
									}
								}`),
							},
							"xr-my-test-xr-usage": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "apiextensions.crossplane.io/v1beta1",
									"kind": "Usage",
									"metadata": {
										"name": "testxr-my-test-xr-23c942-fn-protection"
									},
									"spec": {
										"of": {
											"apiVersion": "test.crossplane.io/v1",
											"kind": "TestXR",
											"resourceRef": {
												"name": "my-test-xr"
											}
										},
										"reason": "created by function-deletion-protection because a composed resource is protected"
									}
								}`),
							},
						},
					},
					Meta:       &fnv1.ResponseMeta{Tag: "hello", Ttl: durationpb.New(1 * time.Minute)},
					Results:    []*fnv1.Result{},
					Conditions: []*fnv1.Condition{},
				},
			},
		},
		"ProtectNamespacedCompositeResourceWithV1UsageError": {
			reason: "Should return error when trying to protect namespaced resource with EnableV1Mode (v1beta1 Usage is cluster-scoped only)",
			args: args{
				req: &fnv1.RunFunctionRequest{
					Meta: &fnv1.RequestMeta{Tag: "hello"},
					Input: resource.MustStructJSON(`{
						"apiVersion": "template.fn.crossplane.io/v1beta1",
						"kind": "Input",
						"enableV1Mode": true
					}`),
					Desired: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.m.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr",
									"namespace": "test",
									"labels": {
										"protection.fn.crossplane.io/block-deletion": "true"
									}
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.m.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed",
										"namespace": "test"
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
						},
					},
					Observed: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.m.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr",
									"namespace": "test"
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.m.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed",
										"namespace": "test"
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
						},
					},
				},
			},
			want: want{
				rsp: &fnv1.RunFunctionResponse{
					Desired: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.m.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr",
									"namespace": "test",
									"labels": {
										"protection.fn.crossplane.io/block-deletion": "true"
									}
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.m.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed",
										"namespace": "test"
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
						},
					},
					Meta: &fnv1.ResponseMeta{Tag: "hello", Ttl: durationpb.New(1 * time.Minute)},
					Results: []*fnv1.Result{
						{
							Message:  "cannot protect composite resource: cannot protect namespaced composite resource with enableV1Mode: apiextensions.crossplane.io/v1beta1 Usage is cluster-scoped only",
							Severity: fnv1.Severity_SEVERITY_FATAL,
							Target:   fnv1.Target_TARGET_COMPOSITE.Enum(),
						},
					},
					Conditions: []*fnv1.Condition{},
				},
			},
		},
		"ProtectNamespacedComposedResourceWithV1UsageError": {
			reason: "Should return error when trying to protect namespaced composed resource with EnableV1Mode",
			args: args{
				req: &fnv1.RunFunctionRequest{
					Meta: &fnv1.RequestMeta{Tag: "hello"},
					Input: resource.MustStructJSON(`{
						"apiVersion": "template.fn.crossplane.io/v1beta1",
						"kind": "Input",
						"enableV1Mode": true
					}`),
					Desired: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.m.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr",
									"namespace": "test"
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.m.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed",
										"namespace": "test",
										"labels": {
											"protection.fn.crossplane.io/block-deletion": "true"
										}
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
						},
					},
					Observed: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.m.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr",
									"namespace": "test"
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.m.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed",
										"namespace": "test"
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
						},
					},
				},
			},
			want: want{
				rsp: &fnv1.RunFunctionResponse{
					Desired: &fnv1.State{
						Composite: &fnv1.Resource{
							Resource: resource.MustStructJSON(`{
								"apiVersion": "test.m.crossplane.io/v1",
								"kind": "TestXR",
								"metadata": {
									"name": "my-test-xr",
									"namespace": "test"
								}
							}`),
						},
						Resources: map[string]*fnv1.Resource{
							"ready-composed-resource": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "test.m.crossplane.io/v1",
									"kind": "TestComposed",
									"metadata": {
										"name": "my-test-composed",
										"namespace": "test",
										"labels": {
											"protection.fn.crossplane.io/block-deletion": "true"
										}
									},
									"spec": {},
									"status": {
										"conditions": [
											{
												"type": "Ready",
												"status": "True"
											}
										]
									}
								}`),
							},
						},
					},
					Meta: &fnv1.ResponseMeta{Tag: "hello", Ttl: durationpb.New(1 * time.Minute)},
					Results: []*fnv1.Result{
						{
							Message:  "cannot process composed resources: cannot protect namespaced resource (kind: TestComposed, name: my-test-composed) in namespace: test with enableV1Mode: apiextensions.crossplane.io/v1beta1 Usage is cluster-scoped only",
							Severity: fnv1.Severity_SEVERITY_FATAL,
							Target:   fnv1.Target_TARGET_COMPOSITE.Enum(),
						},
					},
					Conditions: []*fnv1.Condition{},
				},
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := &Function{log: logging.NewNopLogger()}
			rsp, err := f.RunFunction(tc.args.ctx, tc.args.req)

			if diff := cmp.Diff(tc.want.rsp, rsp, protocmp.Transform()); diff != "" {
				t.Errorf("%s\nf.RunFunction(...): -want rsp, +got rsp:\n%s", tc.reason, diff)
			}

			if diff := cmp.Diff(tc.want.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s\nf.RunFunction(...): -want err, +got err:\n%s", tc.reason, diff)
			}
		})
	}
}

func TestProtectRequiredResources(t *testing.T) {
	type args struct {
		rr map[string][]resource.Required
	}
	type want struct {
		dc  map[resource.Name]*resource.DesiredComposed
		err error
	}

	cases := map[string]struct {
		reason string
		args   args
		want   want
	}{
		"EmptyRequiredResources": {
			reason: "Should return empty map when no required resources are provided",
			args: args{
				rr: map[string][]resource.Required{},
			},
			want: want{
				dc:  map[resource.Name]*resource.DesiredComposed{},
				err: nil,
			},
		},
		"WatchedResourceWithoutLabel": {
			reason: "Should create Usage for watched resources regardless of label",
			args: args{
				rr: map[string][]resource.Required{
					RequirementsNameWatchedResource: {
						{
							Resource: &unstructured.Unstructured{
								Object: map[string]any{
									"apiVersion": "test.crossplane.io/v1",
									"kind":       "TestResource",
									"metadata": map[string]any{
										"name": "test-watched-resource",
									},
								},
							},
						},
					},
				},
			},
			want: want{
				dc: map[resource.Name]*resource.DesiredComposed{
					"TestResource-test-watched-resource--required-resource-fn-protection": {
						Resource: &composed.Unstructured{
							Unstructured: unstructured.Unstructured{
								Object: map[string]any{
									"apiVersion": ProtectionGroupVersion,
									"kind":       "ClusterUsage",
									"metadata": map[string]any{
										"name": "testresource-test-watched-resource-bcd955-fn-protection",
									},
									"spec": map[string]any{
										"of": map[string]any{
											"apiVersion": "test.crossplane.io/v1",
											"kind":       "TestResource",
											"resourceRef": map[string]any{
												"name": "test-watched-resource",
											},
										},
										"reason": ProtectionReasonWatchOperation,
									},
								},
							},
						},
					},
				},
				err: nil,
			},
		},
		"RequiredResourceWithLabel": {
			reason: "Should create Usage for labeled required resources",
			args: args{
				rr: map[string][]resource.Required{
					"some-requirement": {
						{
							Resource: &unstructured.Unstructured{
								Object: map[string]any{
									"apiVersion": "test.crossplane.io/v1",
									"kind":       "TestResource",
									"metadata": map[string]any{
										"name": "test-labeled-resource",
										"labels": map[string]any{
											ProtectionLabelBlockDeletion: "true",
										},
									},
								},
							},
						},
					},
				},
			},
			want: want{
				dc: map[resource.Name]*resource.DesiredComposed{
					"TestResource-test-labeled-resource--required-resource-fn-protection": {
						Resource: &composed.Unstructured{
							Unstructured: unstructured.Unstructured{
								Object: map[string]any{
									"apiVersion": ProtectionGroupVersion,
									"kind":       "ClusterUsage",
									"metadata": map[string]any{
										"name": "testresource-test-labeled-resource-d0dacf-fn-protection",
									},
									"spec": map[string]any{
										"of": map[string]any{
											"apiVersion": "test.crossplane.io/v1",
											"kind":       "TestResource",
											"resourceRef": map[string]any{
												"name": "test-labeled-resource",
											},
										},
										"reason": ProtectionReasonOperation,
									},
								},
							},
						},
					},
				},
				err: nil,
			},
		},
		"RequiredResourceWithoutLabel": {
			reason: "Should not create Usage for unlabeled non-watched required resources",
			args: args{
				rr: map[string][]resource.Required{
					"some-requirement": {
						{
							Resource: &unstructured.Unstructured{
								Object: map[string]any{
									"apiVersion": "test.crossplane.io/v1",
									"kind":       "TestResource",
									"metadata": map[string]any{
										"name": "test-unlabeled-resource",
									},
								},
							},
						},
					},
				},
			},
			want: want{
				dc:  map[resource.Name]*resource.DesiredComposed{},
				err: nil,
			},
		},
		"NamespacedWatchedResource": {
			reason: "Should create namespaced Usage for namespaced watched resources",
			args: args{
				rr: map[string][]resource.Required{
					RequirementsNameWatchedResource: {
						{
							Resource: &unstructured.Unstructured{
								Object: map[string]any{
									"apiVersion": "test.crossplane.io/v1",
									"kind":       "TestResource",
									"metadata": map[string]any{
										"name":      "test-watched-resource",
										"namespace": "test-namespace",
									},
								},
							},
						},
					},
				},
			},
			want: want{
				dc: map[resource.Name]*resource.DesiredComposed{
					"TestResource-test-watched-resource-test-namespace-required-resource-fn-protection": {
						Resource: &composed.Unstructured{
							Unstructured: unstructured.Unstructured{
								Object: map[string]any{
									"apiVersion": ProtectionGroupVersion,
									"kind":       "Usage",
									"metadata": map[string]any{
										"name":      "testresource-test-watched-resource-bcd955-fn-protection",
										"namespace": "test-namespace",
									},
									"spec": map[string]any{
										"of": map[string]any{
											"apiVersion": "test.crossplane.io/v1",
											"kind":       "TestResource",
											"resourceRef": map[string]any{
												"name": "test-watched-resource",
											},
										},
										"reason": ProtectionReasonWatchOperation,
									},
								},
							},
						},
					},
				},
				err: nil,
			},
		},
		"MultipleRequiredResources": {
			reason: "Should create Usages for multiple required resources",
			args: args{
				rr: map[string][]resource.Required{
					RequirementsNameWatchedResource: {
						{
							Resource: &unstructured.Unstructured{
								Object: map[string]any{
									"apiVersion": "test.crossplane.io/v1",
									"kind":       "TestResource",
									"metadata": map[string]any{
										"name": "watched-resource-1",
									},
								},
							},
						},
						{
							Resource: &unstructured.Unstructured{
								Object: map[string]any{
									"apiVersion": "test.crossplane.io/v1",
									"kind":       "TestResource",
									"metadata": map[string]any{
										"name": "watched-resource-2",
									},
								},
							},
						},
					},
					"other-requirement": {
						{
							Resource: &unstructured.Unstructured{
								Object: map[string]any{
									"apiVersion": "test.crossplane.io/v1",
									"kind":       "TestResource",
									"metadata": map[string]any{
										"name": "labeled-resource",
										"labels": map[string]any{
											ProtectionLabelBlockDeletion: "true",
										},
									},
								},
							},
						},
					},
				},
			},
			want: want{
				dc: map[resource.Name]*resource.DesiredComposed{
					"TestResource-watched-resource-1--required-resource-fn-protection": {
						Resource: &composed.Unstructured{
							Unstructured: unstructured.Unstructured{
								Object: map[string]any{
									"apiVersion": ProtectionGroupVersion,
									"kind":       "ClusterUsage",
									"metadata": map[string]any{
										"name": "testresource-watched-resource-1-915899-fn-protection",
									},
									"spec": map[string]any{
										"of": map[string]any{
											"apiVersion": "test.crossplane.io/v1",
											"kind":       "TestResource",
											"resourceRef": map[string]any{
												"name": "watched-resource-1",
											},
										},
										"reason": ProtectionReasonWatchOperation,
									},
								},
							},
						},
					},
					"TestResource-watched-resource-2--required-resource-fn-protection": {
						Resource: &composed.Unstructured{
							Unstructured: unstructured.Unstructured{
								Object: map[string]any{
									"apiVersion": ProtectionGroupVersion,
									"kind":       "ClusterUsage",
									"metadata": map[string]any{
										"name": "testresource-watched-resource-2-47c204-fn-protection",
									},
									"spec": map[string]any{
										"of": map[string]any{
											"apiVersion": "test.crossplane.io/v1",
											"kind":       "TestResource",
											"resourceRef": map[string]any{
												"name": "watched-resource-2",
											},
										},
										"reason": ProtectionReasonWatchOperation,
									},
								},
							},
						},
					},
					"TestResource-labeled-resource--required-resource-fn-protection": {
						Resource: &composed.Unstructured{
							Unstructured: unstructured.Unstructured{
								Object: map[string]any{
									"apiVersion": ProtectionGroupVersion,
									"kind":       "ClusterUsage",
									"metadata": map[string]any{
										"name": "testresource-labeled-resource-b3e5fe-fn-protection",
									},
									"spec": map[string]any{
										"of": map[string]any{
											"apiVersion": "test.crossplane.io/v1",
											"kind":       "TestResource",
											"resourceRef": map[string]any{
												"name": "labeled-resource",
											},
										},
										"reason": ProtectionReasonOperation,
									},
								},
							},
						},
					},
				},
				err: nil,
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dc, err := ProtectRequiredResources(tc.args.rr)

			if diff := cmp.Diff(tc.want.dc, dc); diff != "" {
				t.Errorf("%s\nProtectRequiredResources(...): -want dc, +got dc:\n%s", tc.reason, diff)
			}

			if diff := cmp.Diff(tc.want.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s\nProtectRequiredResources(...): -want err, +got err:\n%s", tc.reason, diff)
			}
		})
	}
}
