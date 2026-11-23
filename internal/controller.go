package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	appsac "k8s.io/client-go/applyconfigurations/apps/v1"
	coreac "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// controller is the reconcile loop: it turns inventory, scan, DB and patch changes into scan, patch and restart work,
// and keeps the admission snapshot current. Each component owns its own state; the controller only holds references.
type controller struct {
	cs       kubernetes.Interface
	cache    cache.Cache // workloads, for their last restart
	store    *store
	inv      *inventory
	scanner  *scanner
	patcher  *patcher
	webhooks *webhooks
	changed  <-chan struct{} // signalled by the inventory, the scanner and the patcher

	unrefSince map[string]time.Time // digest → since when nothing references it (memory only; reconcile goroutine)
}

var (
	activeGauge     = prometheus.NewGauge(prometheus.GaugeOpts{Name: "hedgehog_active", Help: "1 while a mitigation is active."})
	rewritesGauge   = prometheus.NewGauge(prometheus.GaugeOpts{Name: "hedgehog_rewrites", Help: "In-use images with an active rewrite."})
	actionableGauge = prometheus.NewGauge(prometheus.GaugeOpts{Name: "hedgehog_actionable_images", Help: "In-use images with actionable findings."})
	patchTotal      = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "hedgehog_patch_total", Help: "Patch builds by result."}, []string{"result"})
	restartTotal    = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "hedgehog_restart_total", Help: "Workload restarts by result."}, []string{"result"})
	scanSeconds     = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "hedgehog_scan_seconds", Help: "Scan duration by priority and result.", Buckets: []float64{1, 2, 5, 10, 20, 30, 60, 120, 300},
	}, []string{"priority", "result"})
)

func init() {
	metrics.Registry.MustRegister(activeGauge, rewritesGauge, actionableGauge, patchTotal, restartTotal, scanSeconds)
}

// loop reconciles on every change, and hourly so garbage is collected even when nothing changes.
func (c *controller) loop(ctx context.Context) {
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			c.reconcile(ctx)
		case <-c.changed:
			c.reconcile(ctx)
			sleep(ctx, time.Second) // collapse bursts of Pod events
		}
	}
}

// reconcile queues scans for in-use digests with missing or stale results, queues patches for in-use digests that
// need one, rolls out and checks live patches, and refreshes the admission snapshot. Only images in use are patched:
// patches only rewrite Pods of running workloads.
func (c *controller) reconcile(ctx context.Context) {
	built := c.scanner.built()
	defer c.webhooks.refresh()
	usages := c.inv.usages()
	defer c.collect(usages)
	for digest, u := range usages {
		rec, ok := c.store.get(digest)
		if ok && rec.Patched != "" {
			rec = c.checkPatch(ctx, digest, rec, built)
		}
		switch {
		case built == "":
		case !ok:
			c.scanner.request(digest, u.Image, prioNew)
		case rec.DBBuilt != built:
			c.scanner.request(digest, u.Image, prioRematch)
		case rec.needsPatch() && rec.Error == "":
			c.patcher.enqueue(digest)
		}
	}
}

// collect deletes Hedgehog's own state that nothing references any more, by reference count. An image's references
// are the running Pods using it (as their source or as their running digest) and, for a patched image, its source's
// record while that source is referenced. After gcGrace with no references, its record and SBOM are deleted. Registries
// are never touched: pushed images are the registry owner's to clean up. The grace period covers workloads that only
// run sometimes (CronJobs, scaled to zero), which would otherwise lose their patch between runs.
func (c *controller) collect(usages map[string]usage) {
	refs := c.inv.running()
	for d := range usages {
		refs[d] = true
	}
	recs := c.store.all()
	for d, r := range recs {
		if _, pd, ok := strings.Cut(r.Patched, "@"); ok && refs[d] {
			refs[pd] = true
		}
	}
	now := time.Now()
	for d, r := range recs {
		if refs[d] {
			delete(c.unrefSince, d)
			continue
		}
		since, seen := c.unrefSince[d]
		if !seen {
			c.unrefSince[d] = now
		}
		if !seen || now.Sub(since) < gcGrace {
			continue
		}
		if err := c.store.delete(d); err != nil {
			slog.Error("garbage collection", "image", r.Source, "err", err)
			continue
		}
		_ = os.Remove(sbomPath(d))
		delete(c.unrefSince, d)
		slog.Info("garbage collected", "image", r.Source)
	}
}

// checkPatch rolls out a live patch and scans the patched image like any other. If the patched image still has a
// finding the patch was for, the patch didn't work: the image becomes unpatchable (no rewrite, denied, retried once
// per new DB). Findings the patch wasn't for are new: the source has them too, and gets re-patched.
func (c *controller) checkPatch(ctx context.Context, digest string, rec record, built string) record {
	_, current, _ := strings.Cut(rec.Patched, "@")
	pr, scanned := c.store.get(current)
	switch {
	case built == "":
	case !scanned:
		c.scanner.request(current, rec.Patched, prioNew)
	case pr.DBBuilt != built:
		c.scanner.request(current, rec.Patched, prioRematch)
	default:
		var left []string
		for _, f := range pr.Findings {
			if slices.Contains(rec.PatchedFor, f.VulnID) {
				left = append(left, f.VulnID)
			}
		}
		if len(left) > 0 {
			err := fmt.Errorf("patched image %s still has %s", rec.Patched, strings.Join(left, ", "))
			slog.Error("patch ineffective; image unpatchable", "image", rec.Source, "err", err)
			patchTotal.WithLabelValues("ineffective").Inc()
			rec, _ = c.store.update(digest, func(r *record) { r.Patched, r.PatchedFor, r.Error = "", nil, err.Error() })
			return rec
		}
	}
	c.restart(ctx, digest, rec.Patched)
	return rec
}

// restart does what `kubectl rollout restart` does to each workload whose Pods run digest, or an earlier patch of it,
// instead of its current patch (patched, repo@sha256:...): set the restart annotation (server-side apply, Hedgehog's
// own field manager, nothing else), and the workload's controller rolls out its own way. It restarts only when such a
// Pod was created after the workload's last restart: then it hasn't been restarted since this patch, or the webhook
// missed that Pod (Hedgehog was down). Pods older than the last restart belong to a rollout in progress or stalled,
// which a new restart wouldn't help. Kinds kubectl can't restart are left alone; their Pods are rewritten whenever
// they're recreated.
func (c *controller) restart(ctx context.Context, digest, patched string) {
	_, current, _ := strings.Cut(patched, "@")
	apps := c.cs.AppsV1()
	for w, newest := range c.inv.outdated(digest, current) {
		key := types.NamespacedName{Namespace: w.Namespace, Name: w.Name}
		var tmpl corev1.PodTemplateSpec
		var err error
		switch w.Kind {
		case "Deployment":
			var d appsv1.Deployment
			err = c.cache.Get(ctx, key, &d)
			tmpl = d.Spec.Template
		case "StatefulSet":
			var s appsv1.StatefulSet
			err = c.cache.Get(ctx, key, &s)
			tmpl = s.Spec.Template
		case "DaemonSet":
			var d appsv1.DaemonSet
			err = c.cache.Get(ctx, key, &d)
			tmpl = d.Spec.Template
		default:
			continue
		}
		if err != nil {
			slog.Error("read workload", "workload", w.String(), "err", err)
			continue
		}
		last, _ := time.Parse(time.RFC3339, tmpl.Annotations[restartAnnotation]) // zero if never restarted
		if !newest.After(last) {
			continue
		}
		now := coreac.PodTemplateSpec().WithAnnotations(map[string]string{restartAnnotation: time.Now().UTC().Format(time.RFC3339)})
		opts := metav1.ApplyOptions{FieldManager: ownName, Force: true}
		switch w.Kind {
		case "Deployment":
			_, err = apps.Deployments(w.Namespace).Apply(ctx, appsac.Deployment(w.Name, w.Namespace).WithSpec(appsac.DeploymentSpec().WithTemplate(now)), opts)
		case "StatefulSet":
			_, err = apps.StatefulSets(w.Namespace).Apply(ctx, appsac.StatefulSet(w.Name, w.Namespace).WithSpec(appsac.StatefulSetSpec().WithTemplate(now)), opts)
		case "DaemonSet":
			_, err = apps.DaemonSets(w.Namespace).Apply(ctx, appsac.DaemonSet(w.Name, w.Namespace).WithSpec(appsac.DaemonSetSpec().WithTemplate(now)), opts)
		}
		if err != nil {
			restartTotal.WithLabelValues("failed").Inc()
			slog.Error("restart", "workload", w.String(), "err", err)
			continue
		}
		restartTotal.WithLabelValues("ok").Inc()
		slog.Info("restarted", "workload", w.String(), "image", digest)
	}
}

// serveStatus reports images with findings or patches, who uses them, and which workloads still run the vulnerable
// digest itself: a rollout in progress or stalled, or a kind Hedgehog doesn't restart (read-only, on the metrics port).
func (c *controller) serveStatus(w http.ResponseWriter, _ *http.Request) {
	type image struct {
		Digest string `json:"digest"`
		record
		Users    []workload `json:"users"`
		Outdated []workload `json:"outdated,omitempty"` // Pods not yet on the current patch
	}
	out := struct {
		DBBuilt string  `json:"dbBuilt"`
		Active  bool    `json:"active"`
		Images  []image `json:"images"`
	}{DBBuilt: c.scanner.built()}
	if snap := c.webhooks.snap.Load(); snap != nil {
		out.Active = snap.Active
	}
	usages := c.inv.usages()
	for d, r := range c.store.all() {
		if len(r.Findings) > 0 || r.Patched != "" {
			img := image{Digest: d, record: r, Users: usages[d].Users}
			if r.Patched != "" {
				_, current, _ := strings.Cut(r.Patched, "@")
				for w := range c.inv.outdated(d, current) {
					img.Outdated = append(img.Outdated, w)
				}
			}
			out.Images = append(out.Images, img)
		}
	}
	sort.Slice(out.Images, func(i, j int) bool { return out.Images[i].Source < out.Images[j].Source })
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}
