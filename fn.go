package main

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	protectionv1beta1 "github.com/crossplane/crossplane/v2/apis/protection/v1beta1"
	v1beta1 "github.com/upboundcare/function-deletion-protection/input/v1beta1"
	"google.golang.org/protobuf/types/known/durationpb"

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
	ProtectionReason             = "created by function-deletion-protection via label " + ProtectionLabelBlockDeletion
)

// RunFunction runs the Function.
func (f *Function) RunFunction(_ context.Context, req *fnv1.RunFunctionRequest) (*fnv1.RunFunctionResponse, error) {
	f.log.Info("Running function", "tag", req.GetMeta().GetTag())

	rsp := response.To(req, response.DefaultTTL)

	in := &v1beta1.Input{}
	if err := request.GetInput(req, in); err != nil {
		response.Fatal(rsp, errors.Wrapf(err, "cannot get Function input from %T", req))
		return rsp, nil
	}
	if in.CacheTTL != "" {
		dur, err := time.ParseDuration(in.CacheTTL)
		if err != nil {
			response.Fatal(rsp, errors.Wrapf(err, "cannot set cacheTTL"))
			return rsp, nil
		}
		rsp.Meta.Ttl = durationpb.New(dur)
	}

	desiredComposite, err := request.GetDesiredCompositeResource(req)
	if err != nil {
		response.Fatal(rsp, errors.Wrap(err, "cannot get desired composite"))
		return rsp, nil
	}

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

	// The composed resources desired by any previous Functions in the pipeline.
	desiredComposed, err := request.GetDesiredComposedResources(req)
	if err != nil {
		response.Fatal(rsp, errors.Wrapf(err, "cannot get desired composed resources from %T", req))
		return rsp, nil
	}
	var protectedCount int
	for name, desired := range desiredComposed {
		// Does an Observed Resource Exist?
		if observed, ok := observedComposed[name]; ok {
			// The label can either be defined in the pipeline or applied out-of-band
			if ProtectResource(desired.Resource) || ProtectResource(observed.Resource) {
				f.log.Debug("protecting Composed resource", "name", name)
				usage := GenerateUsage(observed.Resource.DeepCopy())
				usageComposed := composed.New()
				if err := convertViaJSON(usageComposed, usage); err != nil {
					response.Fatal(rsp, errors.Wrap(err, "cannot convert usage to unstructured"))
					return rsp, nil
				}
				uname := resource.Name(strings.ToLower(observed.Resource.GetKind() + "-" + observed.Resource.GetName() + "-protection"))
				f.log.Debug("creating usage", "usage", uname, "kind", usageComposed.GetKind())
				protectedCount++
				desiredComposed[uname] = &resource.DesiredComposed{Resource: usageComposed}
			}
		}
	}

	// Create a Usage on the Composite:
	// - If any resources in the Composition are being protected
	// - If the Composite has the label
	if ProtectXR(observedComposite.Resource) || ProtectXR(desiredComposite.Resource) || protectedCount > 0 {
		f.log.Debug("protecting Composite", "name", observedComposite.Resource.GetName())
		usage := GenerateXRUsage(observedComposite.Resource.DeepCopy())
		usageComposed := composed.New()
		if err := convertViaJSON(usageComposed, usage); err != nil {
			response.Fatal(rsp, errors.Wrap(err, "cannot convert usage to unstructured"))
			return rsp, nil
		}
		uname := resource.Name(strings.ToLower(observedComposite.Resource.GetKind() + "-" + observedComposite.Resource.GetName() + "-xr-protection"))
		desiredComposed[uname] = &resource.DesiredComposed{Resource: usageComposed}
	}

	// requiredResources, err := request.GetRequiredResources(req)
	// if err != nil {
	// 	response.Fatal(rsp, errors.Wrap(err, "cannot get required resources"))
	// 	return rsp, nil
	// }

	if err := response.SetDesiredComposedResources(rsp, desiredComposed); err != nil {
		response.Fatal(rsp, errors.Wrap(err, "cannot set desired resources"))
		return rsp, nil
	}
	f.log.Debug("protections generated", "number", protectedCount)

	return rsp, nil
}

// ProtectXR determines is a Composite Resource requires deletion protection.
func ProtectXR(u *composite.Unstructured) bool {
	if u == nil || u.Object == nil {
		return false
	}
	labels := u.GetLabels()
	val, ok := labels[ProtectionLabelBlockDeletion]
	if ok && strings.EqualFold(val, "true") {
		return true
	}
	return false
}

// ProtectResource determines if a Composed Resource should be protected.
func ProtectResource(u *composed.Unstructured) bool {
	if u == nil || u.Object == nil {
		return false
	}
	labels := u.GetLabels()
	val, ok := labels[ProtectionLabelBlockDeletion]
	if ok && strings.EqualFold(val, "true") {
		return true
	}
	return false
}

// GenerateUsage creates a Usage for a desired Composed resource.
func GenerateUsage(u *composed.Unstructured) map[string]any {
	usageType := protectionv1beta1.UsageKind
	var resourceRef map[string]any
	namespace := u.GetNamespace()

	if namespace == "" {
		usageType = protectionv1beta1.ClusterUsageKind
		resourceRef = map[string]any{
			"name": u.GetName(),
		}
	} else {
		resourceRef = map[string]any{
			"name":      u.GetName(),
			"namespace": u.GetNamespace(),
		}
	}
	usage := map[string]any{
		"apiVersion": ProtectionGroupVersion,
		"kind":       usageType,
		"metadata": map[string]any{
			"name": u.GetName() + "-fn-protection",
		},
		"spec": map[string]any{
			"of": map[string]any{
				"apiVersion":  u.GetAPIVersion(),
				"kind":        u.GetKind(),
				"resourceRef": resourceRef,
			},
			"reason": ProtectionReason,
		},
	}
	return usage
}

// GenerateXRUsage creates a Usage for a desired Composite resource.
func GenerateXRUsage(u *composite.Unstructured) map[string]any {
	usageType := protectionv1beta1.UsageKind
	var resourceRef map[string]any
	namespace := u.GetNamespace()

	if namespace == "" {
		usageType = protectionv1beta1.ClusterUsageKind
		resourceRef = map[string]any{
			"name": u.GetName(),
		}
	} else {
		resourceRef = map[string]any{
			"name":      u.GetName(),
			"namespace": u.GetNamespace(),
		}
	}
	usage := map[string]any{
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
			"reason": ProtectionReason,
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
