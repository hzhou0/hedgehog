package internal

import (
	"context"
	"encoding/json"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	vulnDigest    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	patchedDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	patchedRef    = "registry.example.com/hedgehog/library/node@" + patchedDigest
)

// testWebhooks has only a snapshot: enough for every decision that doesn't scan. Inline scans of unknown images in
// active mode are covered by the e2e test.
func testWebhooks(active bool) *webhooks {
	w := &webhooks{}
	w.snap.Store(&snapshot{
		Active: active,
		Images: map[string]imageState{
			vulnDigest:    {Actionable: true, Patched: patchedRef, Message: "CVE-2026-111497 in node"},
			patchedDigest: {},
		},
		Tags: map[string]string{"index.docker.io/library/node:16-alpine": vulnDigest},
	})
	return w
}

func TestCheck(t *testing.T) {
	for _, tc := range []struct {
		name    string
		active  bool
		image   string
		allowed bool
	}{
		{"known actionable tag denied", false, "node:16-alpine", false},
		{"known actionable digest denied", false, "node@" + vulnDigest, false},
		{"active: known actionable tag denied", true, "node:16-alpine", false},
		{"patched digest allowed", true, patchedRef, true},
		{"idle: unknown allowed without a scan", false, "busybox:1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, msg := testWebhooks(tc.active).check(context.Background(), obj{"containers": []any{obj{"image": tc.image}}}); (msg == "") != tc.allowed {
				t.Errorf("allowed=%v (%s)", msg == "", msg)
			}
		})
	}
}

func request(kind string, op admissionv1.Operation, o, old any) admission.Request {
	raw := func(v any) runtime.RawExtension {
		if v == nil {
			return runtime.RawExtension{}
		}
		b, _ := json.Marshal(v)
		return runtime.RawExtension{Raw: b}
	}
	r := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: op, Namespace: "app", Object: raw(o), OldObject: raw(old)}}
	r.Kind.Kind = kind
	return r
}

func deployment(image string, ann obj) obj {
	return obj{"metadata": obj{"name": "web"}, "spec": obj{"template": obj{
		"metadata": obj{"annotations": ann},
		"spec":     obj{"containers": []any{obj{"name": "app", "image": image}}},
	}}}
}

func TestValidateWorkload(t *testing.T) {
	w := testWebhooks(true)
	ctx := context.Background()
	old := deployment("node:16-alpine", nil)
	for _, tc := range []struct {
		name    string
		req     admission.Request
		allowed bool
	}{
		{"create with actionable image", request("Deployment", admissionv1.Create, old, nil), false},
		{"restart-only update", request("Deployment", admissionv1.Update, deployment("node:16-alpine", obj{restartAnnotation: "now"}), old), true},
		{"template change keeping the image", request("Deployment", admissionv1.Update, deployment("node:16-alpine", obj{"x": "y"}), old), false},
		{"update to a clean image", request("Deployment", admissionv1.Update, deployment("node@"+patchedDigest, nil), old), true},
		{"controller-owned ReplicaSet", request("ReplicaSet", admissionv1.Create, func() obj {
			rs := deployment("node:16-alpine", nil)
			rs["metadata"].(obj)["ownerReferences"] = []any{obj{"kind": "Deployment", "controller": true}}
			return rs
		}(), nil), true},
	} {
		if got := w.validate(ctx, tc.req).Allowed; got != tc.allowed {
			t.Errorf("%s: allowed = %v", tc.name, got)
		}
	}
}

func TestMutateRewritesPod(t *testing.T) {
	pod := obj{"metadata": obj{"name": "p"}, "spec": obj{"containers": []any{
		obj{"name": "app", "image": "node:16-alpine"},
		obj{"name": "side", "image": "busybox:1"},
	}}}
	resp := testWebhooks(true).mutate(context.Background(), request("Pod", admissionv1.Create, pod, nil))
	if !resp.Allowed {
		t.Fatal("denied")
	}
	got := map[string]any{}
	for _, p := range resp.Patches {
		got[p.Path] = p.Value
	}
	if got["/spec/containers/0/image"] != patchedRef {
		t.Errorf("image not rewritten: %v", got)
	}
	if _, ok := got["/spec/containers/1/image"]; ok {
		t.Error("rewrote the untouched container")
	}
	if got["/metadata/annotations"] == nil {
		t.Errorf("missing annotation: %v", got)
	}
	if _, ok := got["/spec/imagePullSecrets"]; ok {
		t.Error("added a pull secret; patched images are pulled without one")
	}
}
