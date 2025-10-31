package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/crossplane/crossplane-runtime/pkg/fieldpath"
	protectionv1beta1 "github.com/crossplane/crossplane/v2/apis/protection/v1beta1"
	"github.com/crossplane/function-sdk-go/errors"
	"github.com/crossplane/function-sdk-go/logging"
	fnv1 "github.com/crossplane/function-sdk-go/proto/v1"
	"github.com/crossplane/function-sdk-go/request"
	"github.com/crossplane/function-sdk-go/resource"
	"github.com/crossplane/function-sdk-go/resource/composed"
	"github.com/crossplane/function-sdk-go/resource/composite"
	"github.com/crossplane/function-sdk-go/response"
)

type Function struct {
	fnv1.UnimplementedFunctionRunnerServiceServer

	log logging.Logger
}

const (
	ProtectionLabelBlockDeletion = "protection.fn.crossplane.io/block-deletion"
	ProtectionLabelEnabled       = "protection.fn.crossplane.io/enabled"
	ProtectionGroupVersion       = protectionv1beta1.Group + "/" + protectionv1beta1.Version
)

// RunFunction runs the Function.
func (f *Function) RunFunction(_ context.Context, req *fnv1.RunFunctionRequest) (*fnv1.RunFunctionResponse, error) {
	f.log.Info("Running function", "tag", req.GetMeta().GetTag())

	rsp := response.To(req, response.DefaultTTL)

	observedComposite, err := request.GetObservedCompositeResource(req)
	if err != nil {
		response.Fatal(rsp, errors.Wrap(err, "cannot get observed composite"))
		return rsp, nil
	}

	// Get observed composed resources to extract any that need to be protected
	observedComposed, err := request.GetObservedComposedResources(req)
	if err != nil {
		response.Fatal(rsp, errors.Wrap(err, "cannot get observed resources"))
		return rsp, nil
	}

	// requiredResources, err := request.GetRequiredResources(req)
	// if err != nil {
	// 	response.Fatal(rsp, errors.Wrap(err, "cannot get required resources"))
	// 	return rsp, nil
	// }

	// The composed resources desired by any previous Functions in the pipeline.
	desiredComposed, err := request.GetDesiredComposedResources(req)
	if err != nil {
		response.Fatal(rsp, errors.Wrapf(err, "cannot get desired composed resources from %T", req))
		return rsp, nil
	}
	var protectedCount int = 0
	for name, desired := range desiredComposed {
		// Does an Observed Resource Exist?
		if observed, ok := observedComposed[name]; ok {
			desired.Resource.GetObjectKind()
			// The label can either be defined in the pipeline or applied out-of-band
			if ProtectResource(desired.Resource, ProtectionLabelBlockDeletion) || ProtectResource(observed.Resource, ProtectionLabelBlockDeletion) {
				f.log.Debug("protecting desired resource", "name", name)
				usage := GenerateUsage(observed.Resource.DeepCopy())
				usageComposed := composed.New()
				if err := convertViaJSON(usageComposed, usage); err != nil {
					response.Fatal(rsp, errors.Wrap(err, "cannot convert usage to unstructured"))
					return rsp, nil
				}
				uname := resource.Name(observed.Resource.GetName() + "-protection")
				f.log.Debug("creating usage", "usage", uname, "kind", usageComposed.GetKind())
				protectedCount = protectedCount + 1
				desiredComposed[uname] = &resource.DesiredComposed{Resource: usageComposed}
			}
		}
	}

	// If any resources in the Composition are being
	if ProtectXR(observedComposite.Resource) || protectedCount > 0 {
		f.log.Debug("protecting Composite", "name", observedComposite.Resource.GetName())
		usage := GenerateXRUsage(observedComposite.Resource.DeepCopy())
		usageComposed := composed.New()
		if err := convertViaJSON(usageComposed, usage); err != nil {
			response.Fatal(rsp, errors.Wrap(err, "cannot convert usage to unstructured"))
			return rsp, nil
		}
		uname := resource.Name(observedComposite.Resource.GetName() + "-xr-protection")
		desiredComposed[uname] = &resource.DesiredComposed{Resource: usageComposed}
	}

	if err := response.SetDesiredComposedResources(rsp, desiredComposed); err != nil {
		response.Fatal(rsp, errors.Wrap(err, "cannot set desired resources"))
		return rsp, nil
	}

	// You can set a custom status condition on the claim. This allows you to
	// communicate with the user. See the link below for status condition
	// guidance.
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties
	response.ConditionTrue(rsp, "FunctionSuccess", "Success").
		TargetCompositeAndClaim()

	return rsp, nil
}

// ProtectXR
func ProtectXR(dc *composite.Unstructured) bool {
	labels := dc.GetLabels()
	val, ok := labels[ProtectionLabelBlockDeletion]
	if ok && strings.EqualFold(val, "true") {
		return true
	}

	return false
}

// ProtectResource determines if a resource should be procted
func ProtectResource(dc *composed.Unstructured, label string) bool {
	return MatchLabel(dc, label)
}

// MatchLabel determines if a Resource's label is both set and set to true
func MatchLabel(u *composed.Unstructured, label string) bool {
	if u.Object == nil {
		return false
	}
	var labels map[string]any
	err := fieldpath.Pave(u.Object).GetValueInto("metadata.labels", &labels)
	if err != nil {
		return false
	}
	val, ok := labels[label].(string)
	if ok && strings.EqualFold(val, "true") {
		return true
	}

	return false
}

// GenerateUsage creates a Usage for a desired composed resource
func GenerateUsage(u *composed.Unstructured) map[string]any {
	var usageType = protectionv1beta1.UsageKind
	var resourceRef map[string]any
	namespace := u.GetNamespace()

	if namespace == "" {
		usageType = protectionv1beta1.ClusterUsageKind
		resourceRef = map[string]interface{}{
			"name": u.GetName(),
		}
	} else {
		resourceRef = map[string]interface{}{
			"name":      u.GetName(),
			"namespace": u.GetNamespace(),
		}
	}
	usage := map[string]interface{}{
		"apiVersion": ProtectionGroupVersion,
		"kind":       usageType,
		"metadata": map[string]any{
			"name": u.GetName() + "-function-protection",
		},
		"spec": map[string]any{
			"of": map[string]any{
				"apiVersion":  u.GetAPIVersion(),
				"kind":        u.GetKind(),
				"resourceRef": resourceRef,
			},
			"reason": fmt.Sprintf("Created by function-deletion-protection via label %s", ProtectionLabelBlockDeletion),
		},
	}
	return usage
}

// GenerateUsage creates a Usage for a desired Composite resource
func GenerateXRUsage(u *composite.Unstructured) map[string]any {
	var usageType = protectionv1beta1.UsageKind
	var resourceRef map[string]any
	namespace := u.GetNamespace()

	if namespace == "" {
		usageType = protectionv1beta1.ClusterUsageKind
		resourceRef = map[string]interface{}{
			"name": u.GetName(),
		}
	} else {
		resourceRef = map[string]interface{}{
			"name":      u.GetName(),
			"namespace": u.GetNamespace(),
		}
	}
	usage := map[string]interface{}{
		"apiVersion": ProtectionGroupVersion,
		"kind":       usageType,
		"metadata": map[string]any{
			"name": u.GetName() + "-function-protection",
		},
		"spec": map[string]any{
			"of": map[string]any{
				"apiVersion":  u.GetAPIVersion(),
				"kind":        u.GetKind(),
				"resourceRef": resourceRef,
			},
			"reason": fmt.Sprintf("deletion blocked by function-deletion-protection via label %s", ProtectionLabelBlockDeletion),
		},
	}
	return usage
}

func convertViaJSON(to, from any) error {
	bs, err := json.Marshal(from)
	if err != nil {
		return err
	}
	return json.Unmarshal(bs, to)
}
