//go:build e2e

// Package e2e runs Hedgehog end to end against the k3d cluster set up by the Tiltfile. It only runs against the
// k3d-hedgehog-e2e context.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	kubeContext = "k3d-hedgehog-e2e"
	ns          = "hedgehog-e2e"
	// Node2Shell (CVE-2026-111497, KEV, risk ~97): fixed in 22.23.4, so the node handler should land on the latest
	// 22.x release.
	vulnID     = "CVE-2026-111497"
	vulnerable = "node:22.23.3-alpine"        // musl build: unofficial-builds
	unseen     = "node:22.23.3-bookworm-slim" // never run in the cluster: scanned inline at admission
	registry   = "10.43.200.200:5000"         // in-cluster address; the host reaches it at localhost:5000
	patchedRef = registry + "/patched/"
	// The host's grype checks the images independently of Hedgehog. It must match the version pinned in the Dockerfile:
	// risk scores differ between versions.
	grypeVersion = "0.122.1"
)

func TestNode2Shell(t *testing.T) {
	ctx := t.Context()
	cs := client(t)
	resetNamespace(ctx, t, cs)

	// 1. The cluster is idle, so the vulnerable Deployment is admitted and picked up by the background scan.
	if _, err := createDeployment(ctx, cs, "node2shell", vulnerable); err != nil {
		t.Fatalf("idle cluster should admit %s: %v", vulnerable, err)
	}

	// 2. Hedgehog patches the image and restarts the Deployment; the new Pods are rewritten at creation.
	var pod corev1.Pod
	waitFor(ctx, t, cs, 30*time.Minute, "a Running Pod with the patched image", func() (bool, error) {
		pods, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: "app=node2shell"})
		if err != nil {
			return false, err
		}
		for _, p := range pods.Items {
			if p.Status.Phase == corev1.PodRunning && p.DeletionTimestamp == nil &&
				strings.HasPrefix(p.Spec.Containers[0].Image, patchedRef) {
				pod = p
				return true, nil
			}
		}
		return false, nil
	})
	t.Logf("patched Pod %s runs %s", pod.Name, pod.Spec.Containers[0].Image)

	var sources map[string]struct{ Ref, Digest string }
	if err := json.Unmarshal([]byte(pod.Annotations["hedgehog.io/source-images"]), &sources); err != nil ||
		sources["node"].Ref != vulnerable {
		t.Fatalf("source-images annotation = %q, want the original %s", pod.Annotations["hedgehog.io/source-images"], vulnerable)
	}
	source := "index.docker.io/library/node@" + sources["node"].Digest
	dep, err := cs.AppsV1().Deployments(ns).Get(ctx, "node2shell", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if img := dep.Spec.Template.Spec.Containers[0].Image; img != vulnerable {
		t.Errorf("Deployment image changed to %s; Hedgehog must never edit workload specs", img)
	}
	if dep.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] == "" {
		t.Error("Deployment has no restartedAt annotation")
	}

	// The container prints process.version on start.
	logs, err := cs.CoreV1().Pods(ns).GetLogs(pod.Name, &corev1.PodLogOptions{}).DoRaw(ctx)
	if err != nil {
		t.Fatal(err)
	}
	version := strings.TrimSpace(string(logs))
	if !strings.HasPrefix(version, "v22.") || compareSemver(version, "v22.23.4") < 0 {
		t.Errorf("patched node is %q, want >= v22.23.4", version)
	}
	t.Logf("patched node version: %s", version)

	// 3. A new Deployment with the known vulnerable image is denied outright.
	if _, err := createDeployment(ctx, cs, "node2shell-new", vulnerable); err == nil || !strings.Contains(err.Error(), vulnID) {
		t.Errorf("new Deployment with %s: got %v, want a denial naming %s", vulnerable, err, vulnID)
	}

	// 4. An image never seen in the cluster is scanned inline (active mode) and denied. A slow scan answers "retry",
	// like a user would see; by then the background scan has finished.
	waitFor(ctx, t, cs, 5*time.Minute, "an inline-scan denial naming "+vulnID, func() (bool, error) {
		_, err := createDeployment(ctx, cs, "node2shell-glibc", unseen)
		switch {
		case err == nil:
			return false, fmt.Errorf("%s was admitted", unseen)
		case strings.Contains(err.Error(), vulnID):
			return true, nil
		case strings.Contains(err.Error(), "retry"):
			t.Logf("not yet: %v", err)
			return false, nil
		}
		return false, err
	})

	// 5. Independent check with the host's grype and Hedgehog's filter (risk > 90 with a fix): the source image is
	// flagged for Node2Shell, the patched image for nothing.
	if got := flagged(ctx, t, source); !slices.Contains(got, vulnID) {
		t.Errorf("source image %s: flagged %v, want %s among them", source, got, vulnID)
	}
	patched := "localhost:5000/" + strings.TrimPrefix(pod.Spec.Containers[0].Image, registry+"/")
	if got := flagged(ctx, t, patched); len(got) > 0 {
		t.Errorf("patched image %s still has flagged vulnerabilities: %v", patched, got)
	}

	// 6. The image denied in step 4 was scanned but not patched: patches are only built for images in use. A build
	// logs "patching" as soon as it starts, and step 5 gave it time to.
	for _, img := range patchesStarted(ctx, t, cs) {
		if img != source {
			t.Errorf("Hedgehog built a patch for %s, which no workload runs", img)
		}
	}
}

// flagged runs the host's grype on ref and returns the findings Hedgehog's filter selects.
func flagged(ctx context.Context, t *testing.T, ref string) []string {
	t.Helper()
	out, err := exec.CommandContext(ctx, "grype", "version", "-o", "json").Output()
	if err != nil {
		t.Fatalf("grype %s is needed on the host: %v", grypeVersion, err)
	}
	var ver struct{ Version string }
	if json.Unmarshal(out, &ver); ver.Version != grypeVersion {
		t.Fatalf("host grype is %q, want %s (the version Hedgehog ships)", ver.Version, grypeVersion)
	}
	out, err = exec.CommandContext(ctx, "grype", "registry:"+ref, "--platform", "linux/"+runtime.GOARCH, "-o", "json", "-q").Output()
	if err != nil {
		t.Fatalf("grype %s: %v", ref, err)
	}
	var doc struct {
		Matches []struct {
			Vulnerability struct {
				ID   string
				Risk float64
				Fix  struct{ State string }
			}
			Artifact struct{ Name, Version string }
		}
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, m := range doc.Matches {
		if v := m.Vulnerability; v.Risk > 90 && v.Fix.State == "fixed" {
			ids = append(ids, v.ID)
			t.Logf("%s: %s in %s %s (risk %.1f)", ref, v.ID, m.Artifact.Name, m.Artifact.Version, v.Risk)
		}
	}
	return ids
}

// patchesStarted returns the source image of every patch build in Hedgehog's log.
func patchesStarted(ctx context.Context, t *testing.T, cs kubernetes.Interface) []string {
	t.Helper()
	logs, err := cs.CoreV1().Pods("hedgehog-system").GetLogs("hedgehog-0", &corev1.PodLogOptions{Container: "hedgehog"}).DoRaw(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var images []string
	for _, line := range strings.Split(string(logs), "\n") {
		var l struct{ Msg, Image string }
		if json.Unmarshal([]byte(line), &l) == nil && l.Msg == "patching" {
			images = append(images, l.Image)
		}
	}
	return images
}

func client(t *testing.T) kubernetes.Interface {
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{CurrentContext: kubeContext}).ClientConfig()
	if err != nil {
		t.Fatalf("kube context %s (create it with: k3d cluster create --config e2e/k3d.yaml --kubeconfig-switch-context=false): %v", kubeContext, err)
	}
	return kubernetes.NewForConfigOrDie(cfg)
}

// resetNamespace starts from an empty namespace. It's deleted at the start, not the end, so a failed run can be
// inspected.
func resetNamespace(ctx context.Context, t *testing.T, cs kubernetes.Interface) {
	err := cs.CoreV1().Namespaces().Delete(ctx, ns, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
	waitFor(ctx, t, cs, 3*time.Minute, "namespace "+ns+" to be recreated", func() (bool, error) {
		_, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			return false, nil // still terminating
		}
		return err == nil, err
	})
}

func createDeployment(ctx context.Context, cs kubernetes.Interface, name, image string) (*appsv1.Deployment, error) {
	labels := map[string]string{"app": name}
	return cs.AppsV1().Deployments(ns).Create(ctx, &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{
					Name:    "node",
					Image:   image,
					Command: []string{"node", "-e", "console.log(process.version); setInterval(() => {}, 1 << 30)"},
				}}},
			},
		},
	}, metav1.CreateOptions{})
}

// waitFor polls cond every 5 s. On timeout it fails the test with the tail of Hedgehog's log.
func waitFor(ctx context.Context, t *testing.T, cs kubernetes.Interface, timeout time.Duration, what string, cond func() (bool, error)) {
	t.Helper()
	t.Logf("waiting up to %s for %s", timeout, what)
	err := wait.PollUntilContextTimeout(ctx, 5*time.Second, timeout, true, func(context.Context) (bool, error) { return cond() })
	if err == nil {
		return
	}
	tail := int64(60)
	r, logErr := cs.CoreV1().Pods("hedgehog-system").GetLogs("hedgehog-0", &corev1.PodLogOptions{Container: "hedgehog", TailLines: &tail}).Stream(context.Background())
	if logErr == nil {
		defer r.Close()
		b, _ := io.ReadAll(r)
		t.Logf("hedgehog-0 log tail:\n%s", b)
	}
	t.Fatalf("%s: %v", what, err)
}

// compareSemver compares vMAJOR.MINOR.PATCH versions numerically.
func compareSemver(a, b string) int {
	var x, y [3]int
	fmt.Sscanf(a, "v%d.%d.%d", &x[0], &x[1], &x[2])
	fmt.Sscanf(b, "v%d.%d.%d", &y[0], &y[1], &y[2])
	for i := range x {
		if x[i] != y[i] {
			return x[i] - y[i]
		}
	}
	return 0
}
