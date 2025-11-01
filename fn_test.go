package main

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/crossplane/function-sdk-go/logging"
	fnv1 "github.com/crossplane/function-sdk-go/proto/v1"
	"github.com/crossplane/function-sdk-go/resource"
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
		"NoResourcesToProtect": {
			reason: "The Function should not create Usages when the label are not present",
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
							"testxr-my-test-xr-xr-protection": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "protection.crossplane.io/v1beta1",
									"kind": "ClusterUsage",
									"metadata": {
										"name": "my-test-xr-function-protection"
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
							"testcomposed-my-test-composed-protection": {
								Resource: resource.MustStructJSON(`{
									"apiVersion": "protection.crossplane.io/v1beta1",
									"kind": "ClusterUsage",
									"metadata": {
										"name": "my-test-composed-fn-protection"
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
