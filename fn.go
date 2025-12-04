package main

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"time"

	v1beta1 "github.com/crossplane-contrib/function-deletion-protection/input/v1beta1"
	apiextensionsv1beta1 "github.com/crossplane/crossplane/v2/apis/apiextensions/v1beta1"
	protectionv1beta1 "github.com/crossplane/crossplane/v2/apis/protection/v1beta1"
	"google.golang.org/protobuf/types/known/durationpb"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/crossplane/function-sdk-go/errors"
	"github.com/crossplane/function-sdk-go/logging"
	fnv1 "github.com/crossplane/function-sdk-go/proto/v1"
	"github.com/crossplane/function-sdk-go/request"
	"github.com/crossplane/function-sdk-go/resource"
	"github.com/crossplane/function-sdk-go/resource/composed"
	"github.com/crossplane/function-sdk-go/response"
)

type Function struct {
	fnv1.UnimplementedFunctionRunnerServiceServer

	log logging.Logger
}

const (
	ProtectionLabelBlockDeletion           = "protection.fn.crossplane.io/block-deletion"
	ProtectionGroupVersion                 = protectionv1beta1.Group + "/" + protectionv1beta1.Version
	ProtectionReason                       = "created by function-deletion-protection "
	ProtectionReasonLabel                  = ProtectionReason + "via label " + ProtectionLabelBlockDeletion
	ProtectionReasonCompositeChildResource = ProtectionReason + "because a composed resource is protected"
	ProtectionReasonOperation              = ProtectionReason + "by an Operation"
	ProtectionReasonWatchOperation         = ProtectionReason + "by a WatchOperation"
	ProtectionV1GroupVersion               = apiextensionsv1beta1.Group + "/" + apiextensionsv1beta1.Version
	// UsageNameSuffix is the suffix applied when generating Usage names.
	UsageNameSuffix = "fn-protection"
	// RequirementsNameWatchedResource is the name passed by a WatchOperation.
	RequirementsNameWatchedResource = "ops.crossplane.io/watched-resource"
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

	observedComposed, err := request.GetObservedComposedResources(req)
	if err != nil {
		response.Fatal(rsp, errors.Wrap(err, "cannot get observed resources"))
		return rsp, nil
	}

	desiredComposed, err := request.GetDesiredComposedResources(req)
	if err != nil {
		response.Fatal(rsp, errors.Wrapf(err, "cannot get desired composed resources from %T", req))
		return rsp, nil
	}

	// Process Composed Resources
	var protectedCount int
	composedUsages, err := f.ProtectComposedResources(desiredComposed, observedComposed, in.EnableV1Mode)
	if err != nil {
		response.Fatal(rsp, errors.Wrap(err, "cannot process composed resources"))
		return rsp, nil
	}
	maps.Copy(desiredComposed, composedUsages)
	protectedCount += len(composedUsages)

	// Create a Usage on the Composite:
	// - If any resources in the Composition are being protected
	// - If the Composite has the label
	compositeUsage, err := f.ProtectComposite(observedComposite, desiredComposite, protectedCount, in.EnableV1Mode)
	if err != nil {
		response.Fatal(rsp, errors.Wrap(err, "cannot protect composite resource"))
		return rsp, nil
	}
	if compositeUsage != nil {
		maps.Copy(desiredComposed, compositeUsage)
		protectedCount++
	}

	// Protect any required resources that are present.
	requiredResources, err := request.GetRequiredResources(req)
	if err != nil {
		response.Fatal(rsp, errors.Wrap(err, "cannot get required resources"))
		return rsp, nil
	}

	if len(requiredResources) > 0 {
		f.log.Debug("processing required resources")
		rr, err := ProtectRequiredResources(requiredResources)
		if err != nil {
			response.Fatal(rsp, errors.Wrap(err, "cannot process required resources"))
			return rsp, nil
		}
		maps.Copy(desiredComposed, rr)
		protectedCount += len(rr)
	}

	if err := response.SetDesiredComposedResources(rsp, desiredComposed); err != nil {
		response.Fatal(rsp, errors.Wrap(err, "cannot set desired resources"))
		return rsp, nil
	}
	f.log.Debug("usages created", "total", protectedCount)

	return rsp, nil
}

// ProtectResource determines if a Resource requires deletion protection.
func ProtectResource(u *unstructured.Unstructured) bool {
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

// ProtectComposedResources creates Usages for Composed Resources.
func (f *Function) ProtectComposedResources(desiredComposed map[resource.Name]*resource.DesiredComposed, observedComposed map[resource.Name]resource.ObservedComposed, enableV1Mode bool) (map[resource.Name]*resource.DesiredComposed, error) {
	dc := map[resource.Name]*resource.DesiredComposed{}
	for name, desired := range desiredComposed {
		// A Usage will be created if there is an Observed Resource on the Cluster
		if observed, ok := observedComposed[name]; ok {
			// The label can either be defined in the pipeline or applied outside of Crossplane
			if ProtectResource(&desired.Resource.Unstructured) || ProtectResource(&observed.Resource.Unstructured) {
				f.log.Debug("protecting Composed resource", "kind", observed.Resource.GetKind(), "name", observed.Resource.GetName(), "namespace", observed.Resource.GetNamespace())
				usage := GenerateUsage(&observed.Resource.Unstructured, ProtectionReasonLabel, enableV1Mode)
				usageComposed := composed.New()
				if err := convertViaJSON(usageComposed, usage); err != nil {
					return dc, err
				}
				f.log.Debug("created usage", "kind", usageComposed.GetKind(), "name", usageComposed.GetName(), "namespace", usageComposed.GetNamespace())
				dc[name+"-usage"] = &resource.DesiredComposed{Resource: usageComposed}
			}
		}
	}
	return dc, nil
}

// ProtectComposite creates a Usage for the Composite Resource if it should be protected.
// Protection occurs if:
// - The composite has the protection label, or
// - Any composed resources are being protected (protectedCount > 0).
func (f *Function) ProtectComposite(observedComposite *resource.Composite, desiredComposite *resource.Composite, protectedCount int, enableV1Mode bool) (map[resource.Name]*resource.DesiredComposed, error) {
	if !ProtectResource(&observedComposite.Resource.Unstructured) && !ProtectResource(&desiredComposite.Resource.Unstructured) && protectedCount == 0 {
		return nil, nil
	}

	f.log.Debug("protecting composite", "kind", observedComposite.Resource.GetKind(), "name", observedComposite.Resource.GetName(), "namespace", observedComposite.Resource.GetNamespace())

	var reason string
	if protectedCount > 0 {
		reason = ProtectionReasonCompositeChildResource
	} else {
		reason = ProtectionReasonLabel
	}

	usage := GenerateUsage(&observedComposite.Resource.Unstructured, reason, enableV1Mode)
	usageComposed := composed.New()
	if err := convertViaJSON(usageComposed, usage); err != nil {
		return nil, errors.Wrap(err, "cannot convert usage to unstructured")
	}

	uname := strings.ToLower("xr-" + observedComposite.Resource.GetName() + "-usage")
	f.log.Debug("creating usage", "kind", usageComposed.GetKind(), "name", usageComposed.GetName(), "namespace", usageComposed.GetNamespace())

	return map[resource.Name]*resource.DesiredComposed{
		resource.Name(uname): {Resource: usageComposed},
	}, nil
}

// ProtectRequiredResources creates usages for Required Resources in a Composition.
// Usages are generated for any Watched resource. Other required resources need to have the label.
func ProtectRequiredResources(rr map[string][]resource.Required) (map[resource.Name]*resource.DesiredComposed, error) {
	dc := map[resource.Name]*resource.DesiredComposed{}
	for resourceName, v := range rr {
		for _, r := range v {
			if resourceName == RequirementsNameWatchedResource || ProtectResource(r.Resource) {
				var reason string
				if resourceName == RequirementsNameWatchedResource {
					reason = ProtectionReasonWatchOperation
				} else {
					reason = ProtectionReasonOperation
				}
				usage := GenerateV2Usage(r.Resource, reason)
				usageComposed := composed.New()
				if err := convertViaJSON(usageComposed, usage); err != nil {
					return dc, errors.Wrap(err, "cannot convert usage to unstructured")
				}
				uname := fmt.Sprintf("%s-%s-%s-required-resource-fn-protection", r.Resource.GetKind(), r.Resource.GetName(), r.Resource.GetNamespace())
				dc[resource.Name(uname)] = &resource.DesiredComposed{Resource: usageComposed}
			}
		}
	}
	return dc, nil
}

// GenerateUsage determines whether to return a v1 or v2 Crossplane usage.
func GenerateUsage(u *unstructured.Unstructured, reason string, createV1Usages bool) map[string]any {
	if createV1Usages {
		return GenerateV1Usage(u, reason)
	}
	return GenerateV2Usage(u, reason)
}

// GenerateV2Usage creates a v2 Usage for a resource.
func GenerateV2Usage(u *unstructured.Unstructured, reason string) map[string]any {
	name := strings.ToLower(u.GetKind() + "-" + u.GetName())
	usageType := protectionv1beta1.ClusterUsageKind
	usageMeta := map[string]any{
		"name": GenerateName(name, UsageNameSuffix),
	}

	namespace := u.GetNamespace()
	if namespace != "" {
		usageType = protectionv1beta1.UsageKind
		usageMeta["namespace"] = namespace
	}

	usage := map[string]any{
		"apiVersion": ProtectionGroupVersion,
		"kind":       usageType,
		"metadata":   usageMeta,
		"spec": map[string]any{
			"of": map[string]any{
				"apiVersion": u.GetAPIVersion(),
				"kind":       u.GetKind(),
				"resourceRef": map[string]any{
					"name": u.GetName(),
				},
			},
			"reason": reason,
		},
	}
	return usage
}

// GenerateV1Usage creates a Crossplane v1 Usage for a resource.
// Only Cluster Scoped Resources are supported.
func GenerateV1Usage(u *unstructured.Unstructured, reason string) map[string]any {
	name := strings.ToLower(u.GetKind() + "-" + u.GetName())
	usage := map[string]any{
		"apiVersion": ProtectionV1GroupVersion,
		"kind":       apiextensionsv1beta1.UsageKind,
		"metadata": map[string]any{
			"name": GenerateName(name, UsageNameSuffix),
		},
		"spec": map[string]any{
			"of": map[string]any{
				"apiVersion": u.GetAPIVersion(),
				"kind":       u.GetKind(),
				"resourceRef": map[string]any{
					"name": u.GetName(),
				},
			},
			"reason": reason,
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
