package main

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	apiextensionsv1beta1 "github.com/crossplane/crossplane/v2/apis/apiextensions/v1beta1"
	protectionv1beta1 "github.com/crossplane/crossplane/v2/apis/protection/v1beta1"
	v1beta1 "github.com/stevendborrelli/function-deletion-protection/input/v1beta1"
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
	ProtectionLabelBlockDeletion = "protection.fn.crossplane.io/block-deletion"
	ProtectionGroupVersion       = protectionv1beta1.Group + "/" + protectionv1beta1.Version
	ProtectionReason             = "created by function-deletion-protection via label " + ProtectionLabelBlockDeletion
	ProtectionV1GroupVersion     = apiextensionsv1beta1.Group + "/" + apiextensionsv1beta1.Version
	// UsageNameSuffix is the suffix applied when generating Usage names.
	UsageNameSuffix = "fn-protection"
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
	var protectedCount int
	for name, desired := range desiredComposed {
		// A Usage will be created if there is an Observed Resource on the Cluster
		if observed, ok := observedComposed[name]; ok {
			// The label can either be defined in the pipeline or applied outside of Crossplane
			if ProtectResource(&desired.Resource.DeepCopy().Unstructured) || ProtectResource(&observed.Resource.DeepCopy().Unstructured) {
				f.log.Debug("protecting Composed resource", "kind", observed.Resource.GetKind(), "name", observed.Resource.GetName(), "namespace", observed.Resource.GetNamespace())
				usage := GenerateUsage(&observed.Resource.Unstructured, in.EnableV1Mode)
				usageComposed := composed.New()
				if err := convertViaJSON(usageComposed, usage); err != nil {
					response.Fatal(rsp, errors.Wrap(err, "cannot convert usage to unstructured"))
					return rsp, nil
				}
				f.log.Debug("creating usage", "kind", usageComposed.GetKind(), "name", usageComposed.GetName(), "namespace", usageComposed.GetNamespace())
				protectedCount++
				desiredComposed[name+"-usage"] = &resource.DesiredComposed{Resource: usageComposed}
			}
		}
	}

	// Create a Usage on the Composite:
	// - If any resources in the Composition are being protected
	// - If the Composite has the label
	if ProtectResource(&observedComposite.Resource.DeepCopy().Unstructured) || ProtectResource(&desiredComposite.Resource.DeepCopy().Unstructured) || protectedCount > 0 {
		f.log.Debug("protecting composite", "kind", observedComposite.Resource.GetKind(), "name", observedComposite.Resource.GetName(), "namespace", observedComposite.Resource.GetNamespace())
		usage := GenerateUsage(&observedComposite.Resource.DeepCopy().Unstructured, in.EnableV1Mode)
		usageComposed := composed.New()
		if err := convertViaJSON(usageComposed, usage); err != nil {
			response.Fatal(rsp, errors.Wrap(err, "cannot convert usage to unstructured"))
			return rsp, nil
		}
		uname := strings.ToLower("xr-" + observedComposite.Resource.GetName() + "-usage")
		desiredComposed[resource.Name(uname)] = &resource.DesiredComposed{Resource: usageComposed}
		protectedCount++
		f.log.Debug("creating usage", "kind", usageComposed.GetKind(), "name", usageComposed.GetName(), "namespace", usageComposed.GetNamespace())
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

// GenerateUsage determines whether to return a v1 or v2 Crossplane usage.
func GenerateUsage(u *unstructured.Unstructured, createV1Usages bool) map[string]any {
	if createV1Usages {
		return GenerateV1Usage(u)
	}
	return GenerateV2Usage(u)
}

// GenerateV2Usage creates a v2 Usage for a resource.
func GenerateV2Usage(u *unstructured.Unstructured) map[string]any {
	usageType := protectionv1beta1.ClusterUsageKind
	usageMeta := map[string]any{
		"name": GenerateName(u.GetName(), UsageNameSuffix),
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
			"reason": ProtectionReason,
		},
	}
	return usage
}

// GenerateV1Usage creates a Crossplane v1 Usage for a resource.
// Only Cluster Scoped Resources are supported.
func GenerateV1Usage(u *unstructured.Unstructured) map[string]any {
	usage := map[string]any{
		"apiVersion": ProtectionV1GroupVersion,
		"kind":       apiextensionsv1beta1.UsageKind,
		"metadata": map[string]any{
			"name": GenerateName(u.GetName(), UsageNameSuffix),
		},
		"spec": map[string]any{
			"of": map[string]any{
				"apiVersion": u.GetAPIVersion(),
				"kind":       u.GetKind(),
				"resourceRef": map[string]any{
					"name": u.GetName(),
				},
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
