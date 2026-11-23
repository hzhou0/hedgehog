package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync/atomic"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/prometheus/client_golang/prometheus"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// snapshot is what admission decides from, so that only inline scans are slow.
type snapshot struct {
	Active bool // a mitigation is in progress: unknown images are scanned inline
	Images map[string]imageState
	Tags   map[string]string // as seen on running Pods
}

type webhooks struct {
	exclude map[string]bool
	store   *store
	inv     *inventory
	scanner *scanner
	snap    atomic.Pointer[snapshot]
}

type imageState struct {
	Actionable  bool
	Patched     string
	DenyMessage string
}

var admissionTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "hedgehog_admission_total", Help: "Admission decisions by webhook, kind and reason.",
}, []string{"webhook", "kind", "reason"})

func init() { metrics.Registry.MustRegister(admissionTotal) }

// templatePaths says where each kind keeps its pod template. Objects are generic maps so Argo Rollouts work too.
var templatePaths = map[string][]string{
	"Deployment":  {"spec", "template"},
	"StatefulSet": {"spec", "template"},
	"DaemonSet":   {"spec", "template"},
	"ReplicaSet":  {"spec", "template"},
	"Job":         {"spec", "template"},
	"CronJob":     {"spec", "jobTemplate", "spec", "template"},
	"Rollout":     {"spec", "template"},
}

type obj = map[string]any

func (w *webhooks) validate(ctx context.Context, req admission.Request) admission.Response {
	kind := req.Kind.Kind
	if w.exclude[req.Namespace] {
		return admission.Allowed("")
	}
	var o, old obj
	if err := json.Unmarshal(req.Object.Raw, &o); err != nil {
		return admission.Errored(400, err)
	}
	controlled := false // admitted through its owner; checking again would block the owner's rollouts
	meta, _ := nestedMap(o, "metadata")
	refs, _ := meta["ownerReferences"].([]any)
	for _, r := range refs {
		if ref, ok := r.(obj); ok && ref["controller"] == true {
			controlled = true
		}
	}
	var spec obj
	switch {
	case kind == "Pod":
		spec, _ = nestedMap(o, "spec")
	case controlled:
	default:
		tmpl, ok := nestedMap(o, templatePaths[kind]...)
		if !ok {
			break
		}
		if req.Operation == admissionv1.Update && json.Unmarshal(req.OldObject.Raw, &old) == nil {
			// Allow updates that leave the template unchanged apart from a restart. Objects are post-defaulting, so
			// DeepEqual is a semantic comparison.
			oldTmpl, _ := nestedMap(old, templatePaths[kind]...)
			for _, t := range []obj{oldTmpl, tmpl} {
				if m, ok := nestedMap(t, "metadata"); ok {
					ann, _ := m["annotations"].(obj)
					delete(ann, restartAnnotation)
					if len(ann) == 0 {
						delete(m, "annotations")
					}
				}
			}
			if reflect.DeepEqual(oldTmpl, tmpl) {
				break
			}
		}
		spec, _ = nestedMap(tmpl, "spec")
	}
	if spec == nil {
		admissionTotal.WithLabelValues("validate", kind, "allowed").Inc()
		return admission.Allowed("")
	}
	reason, msg := w.checkImages(ctx, spec)
	admissionTotal.WithLabelValues("validate", kind, reason).Inc()
	if msg != "" {
		slog.Info("denied", "kind", kind, "namespace", req.Namespace, "name", req.Name, "reason", reason)
		return admission.Denied(msg)
	}
	return admission.Allowed("")
}

// checkImages returns the metrics reason of the last denied image, and a deny message naming each one.
func (w *webhooks) checkImages(ctx context.Context, spec obj) (reason, msg string) {
	snap := w.snap.Load()
	if snap == nil {
		return "error", "Hedgehog is starting; retry shortly"
	}
	var images []string
	for _, key := range []string{"initContainers", "containers", "ephemeralContainers"} {
		list, _ := spec[key].([]any)
		for _, ct := range list {
			if img, _ := ct.(obj)["image"].(string); img != "" {
				images = append(images, img)
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, inlineScanTimeout)
	defer cancel()
	var denied []string
	reason = "allowed"
	for _, img := range images {
		if st, ok := snap.Images[snap.digestOf(img)]; ok {
			if st.Actionable {
				denied, reason = append(denied, img+": "+st.DenyMessage), "actionable"
			}
			continue
		}
		if !snap.Active {
			continue // idle: unknown images are admitted and picked up by the background scan
		}
		rec, err := w.scanner.inlineScan(ctx, img)
		switch {
		case ctx.Err() != nil:
			denied, reason = append(denied, img+": Hedgehog is scanning it; retry in about a minute"), "scanning"
		case err != nil:
			denied, reason = append(denied, fmt.Sprintf("%s: Hedgehog could not scan it (%v); retry", img, err)), "error"
		case len(rec.Findings) > 0:
			denied, reason = append(denied, img+": "+describeFindings(rec)), "actionable"
		}
	}
	if len(denied) == 0 {
		return reason, ""
	}
	return reason, "Hedgehog blocked this change:\n  " + strings.Join(denied, "\n  ")
}

// mutate rewrites Pod images to their patches. It never scans: every Pod creation waits on it.
func (w *webhooks) mutate(_ context.Context, req admission.Request) admission.Response {
	snap := w.snap.Load()
	if snap == nil || req.Kind.Kind != "Pod" || w.exclude[req.Namespace] {
		return admission.Allowed("")
	}
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return admission.Errored(400, err)
	}
	sources := map[string]sourceImage{}
	for _, list := range [][]corev1.Container{pod.Spec.InitContainers, pod.Spec.Containers} {
		for i := range list {
			ct := &list[i]
			digest := snap.digestOf(ct.Image)
			if st := snap.Images[digest]; st.Patched != "" && st.Patched != ct.Image {
				sources[ct.Name] = sourceImage{Ref: ct.Image, Digest: digest}
				ct.Image = st.Patched
			}
		}
	}
	if len(sources) == 0 {
		admissionTotal.WithLabelValues("mutate", "Pod", "unchanged").Inc()
		return admission.Allowed("")
	}
	ann, _ := json.Marshal(sources)
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[sourceAnnotation] = string(ann)
	mutated, err := json.Marshal(pod)
	if err != nil {
		return admission.Errored(500, err)
	}
	admissionTotal.WithLabelValues("mutate", "Pod", "rewritten").Inc()
	return admission.PatchResponseFromRaw(req.Object.Raw, mutated)
}

func (s *snapshot) digestOf(img string) string {
	if _, d, ok := strings.Cut(img, "@"); ok {
		return d
	}
	if r, err := name.ParseReference(img); err == nil {
		return s.Tags[r.Name()]
	}
	return ""
}

func nestedMap(o obj, path ...string) (obj, bool) {
	for _, p := range path {
		next, ok := o[p].(obj)
		if !ok {
			return nil, false
		}
		o = next
	}
	return o, len(path) > 0
}

func (w *webhooks) refresh() {
	recs := w.store.all()
	snap := &snapshot{Images: map[string]imageState{}, Tags: w.inv.tagDigests()}
	for d, r := range recs {
		snap.Images[d] = imageState{Actionable: len(r.Findings) > 0, Patched: r.Patched, DenyMessage: describeFindings(r)}
		if _, scanned := recs[r.patchedDigest()]; r.Patched != "" && !scanned {
			snap.Images[r.patchedDigest()] = imageState{} // allowed until its own scan says otherwise
		}
	}
	rewrites, actionable := 0, 0
	for d := range w.inv.usages() {
		if r := recs[d]; len(r.Findings) > 0 {
			snap.Active = true
			actionable++
			if r.Patched != "" {
				rewrites++
			}
		}
	}
	w.snap.Store(snap)
	activeGauge.Set(0)
	if snap.Active {
		activeGauge.Set(1)
	}
	rewritesGauge.Set(float64(rewrites))
	actionableGauge.Set(float64(actionable))
}

func describeFindings(r record) string {
	var parts []string
	for i, f := range r.Findings {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("and %d more", len(r.Findings)-3))
			break
		}
		kev := ""
		if f.KEV {
			kev = ", known exploited"
		}
		parts = append(parts, fmt.Sprintf("%s in %s %s (risk %.1f%s), fixed in %s", f.VulnID, f.Package, f.Version, f.Risk, kev, f.Target))
	}
	msg := strings.Join(parts, "; ")
	if r.Patched != "" {
		msg += ". Hedgehog-patched image: " + r.Patched
	}
	return msg
}
