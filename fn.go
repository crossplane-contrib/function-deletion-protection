package main

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"time"

	v1beta1 "github.com/crossplane-contrib/function-deletion-protection/input/v1beta1"
	apiextensionsv1beta1 "github.com/crossplane/crossplane/v2/apis/apiextensions/v1beta1"
	protectionv1beta1 "github.com/crossplane/crossplane/v2/apis/protection/v1beta1"
	"google.golang.org/protobuf/types/known/durationpb"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	ProtectionAnnotationGroup              = "protection.fn.crossplane.io"
	ProtectionAnnotationBlockDeletion      = ProtectionAnnotationGroup + "/block-deletion"
	ProtectionAnnotationReplayDeletion     = ProtectionAnnotationGroup + "/replay-deletion"
	ProtectionAnnotationCustomReason       = ProtectionAnnotationGroup + "/reason"
	ProtectionLabelBlockDeletion           = ProtectionAnnotationBlockDeletion
	ProtectionGroupVersion                 = protectionv1beta1.Group + "/" + protectionv1beta1.Version
	ProtectionReason                       = "created by function-deletion-protection "
	ProtectionReasonAnnotation             = ProtectionReason + "via annotation " + ProtectionAnnotationBlockDeletion
	ProtectionReasonLabel                  = ProtectionReason + "via label " + ProtectionLabelBlockDeletion
	ProtectionReasonCompositeChildResource = ProtectionReason + "because a composed resource is protected"
	ProtectionReasonOperation              = ProtectionReason + "by an Operation"
	ProtectionReasonWatchOperation         = ProtectionReason + "by a WatchOperation"
	ProtectionV1GroupVersion               = apiextensionsv1beta1.Group + "/" + apiextensionsv1beta1.Version
	// UsageNameSuffix is the suffix applied when generating Usage names.
	UsageNameSuffix = "fn-protection"
	// RequirementsNameWatchedResource is the name passed by a WatchOperation.
	RequirementsNameWatchedResource = "ops.crossplane.io/watched-resource"
	// V1ModeError Error when trying to protect a namespaced resource when in v1 mode.
	V1ModeError = "cannot protect namespaced resource (kind: %s, name: %s, namespace: %s) with enableV1Mode=true. v1 usages only support cluster-scoped resources."
)

type UsageOpts struct {
	// V1Mode determines if a v1 Usage should be generated.
	V1Mode bool
	// Reason is the Usage Reason.
	Reason string
	// ReplayDeletion is whether Usage replay deletion should be activated.
	ReplayDeletion bool
}

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

	// Register schemes for v1 and v2 Usage types
	// protectionv1beta1 contains both ClusterUsage and Usage
	_ = protectionv1beta1.AddToScheme(composed.Scheme)
	_ = apiextensionsv1beta1.AddToScheme(composed.Scheme)

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

// ProtectResource determines if a resource requires protection via annotation or label.
func ProtectResource(u *unstructured.Unstructured) bool {
	return ProtectResourceViaAnnotation(u) || ProtectResourceViaLabel(u)
}

// ProtectResourceViaAnnotation determines if the resource protection annotation is set.
func ProtectResourceViaAnnotation(u *unstructured.Unstructured) bool {
	if u == nil || u.Object == nil {
		return false
	}
	annotations := u.GetAnnotations()
	aval, ok := annotations[ProtectionAnnotationBlockDeletion]
	if ok && strings.EqualFold(aval, "true") {
		return true
	}
	return false
}

// ProtectResourceViaLabel determines if the resource protection label is set.
// This is for legacy compatibility, please use the annotation instead.
func ProtectResourceViaLabel(u *unstructured.Unstructured) bool {
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
				// Validate that v1 mode is not used with namespaced resources
				if enableV1Mode && observed.Resource.GetNamespace() != "" {
					return dc, errors.Errorf(V1ModeError, observed.Resource.GetKind(), observed.Resource.GetName(), observed.Resource.GetNamespace())
				}
				f.log.Debug("protecting Composed resource", "kind", observed.Resource.GetKind(), "name", observed.Resource.GetName(), "namespace", observed.Resource.GetNamespace())

				// Determine the reason
				var reason string

				customReason, hasCustomReason := GetReason(&desired.Resource.Unstructured)
				if !hasCustomReason {
					customReason, hasCustomReason = GetReason(&observed.Resource.Unstructured)
				}
				switch {
				case hasCustomReason:
					reason = customReason
				case ProtectResourceViaAnnotation(&desired.Resource.Unstructured) || ProtectResourceViaAnnotation(&observed.Resource.Unstructured):
					reason = ProtectionReasonAnnotation
				default:
					reason = ProtectionReasonLabel
				}

				// Check for replay deletion annotation in desired or observed
				replayDeletion := GetReplayDeletion(&desired.Resource.Unstructured) || GetReplayDeletion(&observed.Resource.Unstructured)

				uo := UsageOpts{
					V1Mode:         enableV1Mode,
					Reason:         reason,
					ReplayDeletion: replayDeletion,
				}
				usageComposed, err := GenerateUsage(&observed.Resource.Unstructured, uo)
				if err != nil {
					return dc, errors.Wrap(err, "cannot generate usage for composed resource")
				}
				f.log.Debug("created usage", "kind", usageComposed.GetKind(), "name", usageComposed.GetName(), "namespace", usageComposed.GetNamespace())
				dc[name+"-usage"] = &resource.DesiredComposed{
					Resource: usageComposed,
					Ready:    resource.ReadyTrue,
				}
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

	// Validate that v1 mode is not used with namespaced composite resources
	if enableV1Mode && observedComposite.Resource.GetNamespace() != "" {
		return nil, errors.Errorf(V1ModeError, observedComposite.Resource.GetKind(), observedComposite.Resource.GetName(), observedComposite.Resource.GetNamespace())
	}

	f.log.Debug("protecting composite", "kind", observedComposite.Resource.GetKind(), "name", observedComposite.Resource.GetName(), "namespace", observedComposite.Resource.GetNamespace())

	// Check for custom reason in desired or observed composite
	customReason, hasCustomReason := GetReason(&desiredComposite.Resource.Unstructured)
	if !hasCustomReason {
		customReason, hasCustomReason = GetReason(&observedComposite.Resource.Unstructured)
	}

	// Determine the reason
	var reason string

	if hasCustomReason {
		reason = customReason
	} else {
		switch {
		case protectedCount > 0:
			reason = ProtectionReasonCompositeChildResource
		case ProtectResourceViaAnnotation(&observedComposite.Resource.Unstructured) || ProtectResourceViaAnnotation(&desiredComposite.Resource.Unstructured):
			reason = ProtectionReasonAnnotation
		default:
			reason = ProtectionReasonLabel
		}
	}

	// Check for replay deletion annotation in desired or observed composite
	replayDeletion := GetReplayDeletion(&desiredComposite.Resource.Unstructured) || GetReplayDeletion(&observedComposite.Resource.Unstructured)

	uo := UsageOpts{
		V1Mode:         enableV1Mode,
		Reason:         reason,
		ReplayDeletion: replayDeletion,
	}

	usageComposed, err := GenerateUsage(&observedComposite.Resource.Unstructured, uo)
	if err != nil {
		return nil, errors.Wrap(err, "cannot generate usage for composite resource")
	}

	uname := strings.ToLower("xr-" + observedComposite.Resource.GetName() + "-usage")
	f.log.Debug("creating usage", "kind", usageComposed.GetKind(), "name", usageComposed.GetName(), "namespace", usageComposed.GetNamespace())

	return map[resource.Name]*resource.DesiredComposed{
		resource.Name(uname): {
			Resource: usageComposed,
			Ready:    resource.ReadyTrue,
		},
	}, nil
}

// ProtectRequiredResources creates usages for Required Resources in a Composition.
// Usages are generated for any Watched resource. Other required resources need to have the label.
func ProtectRequiredResources(rr map[string][]resource.Required) (map[resource.Name]*resource.DesiredComposed, error) {
	dc := map[resource.Name]*resource.DesiredComposed{}
	for resourceName, v := range rr {
		for _, r := range v {
			if resourceName == RequirementsNameWatchedResource || ProtectResource(r.Resource) {
				uo := UsageOpts{
					ReplayDeletion: GetReplayDeletion(r.Resource),
				}

				reasonAnnotation, ok := GetReason(r.Resource)
				switch {
				case ok:
					uo.Reason = reasonAnnotation
				case resourceName == RequirementsNameWatchedResource:
					uo.Reason = ProtectionReasonWatchOperation
				default:
					uo.Reason = ProtectionReasonOperation
				}

				usageComposed, err := GenerateUsage(r.Resource, uo)
				if err != nil {
					return dc, errors.Wrap(err, "cannot generate usage for required resource")
				}
				uname := fmt.Sprintf("%s-%s-%s-required-resource-fn-protection", r.Resource.GetKind(), r.Resource.GetName(), r.Resource.GetNamespace())
				dc[resource.Name(uname)] = &resource.DesiredComposed{
					Resource: usageComposed,
					Ready:    resource.ReadyTrue,
				}
			}
		}
	}
	return dc, nil
}

// GenerateUsage determines whether to return a v1 or v2 Crossplane usage.
func GenerateUsage(u *unstructured.Unstructured, uo UsageOpts) (*composed.Unstructured, error) {
	if uo.V1Mode {
		return GenerateV1Usage(u, uo)
	}

	namespace := u.GetNamespace()
	if namespace != "" {
		return GenerateV2Usage(u, uo)
	}
	return GenerateV2ClusterUsage(u, uo)
}

// GenerateV2ClusterUsage creates a v2 ClusterUsage for a resource.
func GenerateV2ClusterUsage(u *unstructured.Unstructured, uo UsageOpts) (*composed.Unstructured, error) {
	name := strings.ToLower(u.GetKind() + "-" + u.GetName())

	cu := protectionv1beta1.ClusterUsage{
		ObjectMeta: v1.ObjectMeta{
			Name: GenerateName(name, UsageNameSuffix),
		},
		TypeMeta: v1.TypeMeta{
			APIVersion: ProtectionGroupVersion,
			Kind:       protectionv1beta1.ClusterUsageKind,
		},
		Spec: protectionv1beta1.ClusterUsageSpec{
			Of: protectionv1beta1.Resource{
				APIVersion: u.GetAPIVersion(),
				Kind:       u.GetKind(),
				ResourceRef: &protectionv1beta1.ResourceRef{
					Name: u.GetName(),
				},
			},
			Reason:         &uo.Reason,
			ReplayDeletion: &uo.ReplayDeletion,
		},
	}

	return composed.From(&cu)
}

// GenerateV2Usage creates a v2 Usage for a resource.
func GenerateV2Usage(u *unstructured.Unstructured, uo UsageOpts) (*composed.Unstructured, error) {
	name := strings.ToLower(u.GetKind() + "-" + u.GetName())
	usage := protectionv1beta1.Usage{
		ObjectMeta: v1.ObjectMeta{
			Name:      GenerateName(name, UsageNameSuffix),
			Namespace: u.GetNamespace(),
		},
		Spec: protectionv1beta1.UsageSpec{
			Of: protectionv1beta1.NamespacedResource{
				APIVersion: u.GetAPIVersion(),
				Kind:       u.GetKind(),
				ResourceRef: &protectionv1beta1.NamespacedResourceRef{
					Name: u.GetName(),
				},
			},
			Reason:         &uo.Reason,
			ReplayDeletion: &uo.ReplayDeletion,
		},
	}
	return composed.From(&usage)
}

// GenerateV1Usage creates a Crossplane v1 Usage for a resource.
// Only Cluster Scoped Resources are supported.
func GenerateV1Usage(u *unstructured.Unstructured, uo UsageOpts) (*composed.Unstructured, error) {
	name := strings.ToLower(u.GetKind() + "-" + u.GetName())

	usage := apiextensionsv1beta1.Usage{ //nolint:staticcheck // keep deprecated v1 Usage until it is removed from upstream XP
		ObjectMeta: v1.ObjectMeta{
			Name: GenerateName(name, UsageNameSuffix),
		},

		Spec: apiextensionsv1beta1.UsageSpec{
			Of: apiextensionsv1beta1.Resource{
				APIVersion: u.GetAPIVersion(),
				Kind:       u.GetKind(),
				ResourceRef: &apiextensionsv1beta1.ResourceRef{
					Name: u.GetName(),
				},
			},
			Reason:         &uo.Reason,
			ReplayDeletion: &uo.ReplayDeletion,
		},
	}
	return composed.From(&usage)
}

// GetReason checks if the reason annotation is set.
// If so, return the string in the annotation.
func GetReason(u *unstructured.Unstructured) (string, bool) {
	if u == nil || u.Object == nil {
		return "", false
	}
	annotations := u.GetAnnotations()
	val, ok := annotations[ProtectionAnnotationCustomReason]
	return val, ok
}

// GetReplayDeletion checks if the replay-deletion annotation is set.
func GetReplayDeletion(u *unstructured.Unstructured) bool {
	if u == nil || u.Object == nil {
		return false
	}
	annotations := u.GetAnnotations()

	val, ok := annotations[ProtectionAnnotationReplayDeletion]
	if ok {
		return strings.EqualFold(val, "true")
	}
	return false
}
