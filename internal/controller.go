package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
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

// controller turns changes into scan, patch and restart work. The components own their state.
type controller struct {
	backgroundScanInterval time.Duration
	keepUnreferenced       time.Duration

	client   kubernetes.Interface
	cache    cache.Cache
	store    *store
	inv      *inventory
	scanner  *scanner
	patcher  *patcher
	webhooks *webhooks
	changed  <-chan struct{}

	unreferencedSince map[string]time.Time // by digest
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

// loop reconciles on every change, and every backgroundScanInterval for what no event signals (garbage collection, retries).
func (c *controller) loop(ctx context.Context) {
	tick := time.NewTicker(c.backgroundScanInterval)
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

// reconcile scans the running images and the sources in use, patches and rolls out the sources, and refreshes
// admission.
func (c *controller) reconcile(ctx context.Context) {
	dbBuilt := c.scanner.dbBuilt()
	defer c.webhooks.refresh()
	usages := c.inv.usages()
	running := c.inv.runningImages()
	defer c.collectGarbage(usages, running)

	toScan := maps.Clone(running)
	for digest, u := range usages {
		toScan[digest] = u.Image
	}
	for digest, image := range toScan {
		rec, ok := c.store.get(digest)
		switch {
		case dbBuilt == "":
		case !ok:
			c.scanner.request(digest, image, prioNew)
		case rec.DBBuilt != dbBuilt:
			c.scanner.request(digest, image, prioRematch)
		}
	}
	for digest := range usages {
		rec, ok := c.store.get(digest)
		if !ok {
			continue
		}
		if rec.Patched != "" {
			rec = c.rolloutPatch(ctx, digest, rec)
		}
		if rec.DBBuilt == dbBuilt && rec.needsPatch() && rec.PatchError == "" {
			c.patcher.enqueue(digest)
		}
	}
}

// collectGarbage deletes the records and SBOMs of images unreferenced for keepUnreferenced. Pods reference the
// images they run, as source or as patch, and a referenced source references its patch. Registries are never touched.
func (c *controller) collectGarbage(usages map[string]usage, running map[string]string) {
	refs := map[string]bool{}
	for d := range running {
		refs[d] = true
	}
	for d := range usages {
		refs[d] = true
	}
	recs := c.store.all()
	for d, r := range recs {
		if r.Patched != "" && refs[d] {
			refs[r.patchedDigest()] = true
		}
	}
	now := time.Now()
	for d, r := range recs {
		if refs[d] {
			delete(c.unreferencedSince, d)
			continue
		}
		since, seen := c.unreferencedSince[d]
		if !seen {
			c.unreferencedSince[d] = now
		}
		if !seen || now.Sub(since) < c.keepUnreferenced {
			continue
		}
		if err := c.store.delete(d); err != nil {
			slog.Error("garbage collection", "image", r.Source, "err", err)
			continue
		}
		_ = os.Remove(sbomPath(d))
		delete(c.unreferencedSince, d)
		slog.Info("garbage collected", "image", r.Source)
	}
}

// rolloutPatch restarts workloads onto the patch. Once the running patch has been scanned, a patch that still has a
// finding it was for is dropped, leaving the image unpatchable until the next DB.
func (c *controller) rolloutPatch(ctx context.Context, digest string, rec record) record {
	patched := rec.patchedDigest()
	if pr, scanned := c.store.get(patched); scanned {
		var unfixed []string
		for _, f := range pr.Findings {
			if slices.Contains(rec.PatchedFor, f.VulnID) {
				unfixed = append(unfixed, f.VulnID)
			}
		}
		if len(unfixed) > 0 {
			err := fmt.Errorf("patched image %s still has %s", rec.Patched, strings.Join(unfixed, ", "))
			slog.Error("patch ineffective; image unpatchable", "image", rec.Source, "err", err)
			patchTotal.WithLabelValues("ineffective").Inc()
			rec, _ = c.store.update(digest, func(r *record) { r.Patched, r.PatchedFor, r.PatchError = "", nil, err.Error() })
			return rec
		}
	}
	c.restartOutdated(ctx, digest, patched)
	return rec
}

// restartOutdated does `kubectl rollout restart` on each workload with a Pod not running patched that was created
// after the workload's last restart. Older Pods belong to a rollout already under way.
func (c *controller) restartOutdated(ctx context.Context, digest, patched string) {
	apps := c.client.AppsV1()
	for w, newest := range c.inv.outdated(digest, patched) {
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
		lastRestart, _ := time.Parse(time.RFC3339, tmpl.Annotations[restartAnnotation])
		if !newest.After(lastRestart) {
			continue
		}
		restarted := coreac.PodTemplateSpec().WithAnnotations(map[string]string{restartAnnotation: time.Now().UTC().Format(time.RFC3339)})
		opts := metav1.ApplyOptions{FieldManager: ownName, Force: true}
		switch w.Kind {
		case "Deployment":
			_, err = apps.Deployments(w.Namespace).Apply(ctx, appsac.Deployment(w.Name, w.Namespace).WithSpec(appsac.DeploymentSpec().WithTemplate(restarted)), opts)
		case "StatefulSet":
			_, err = apps.StatefulSets(w.Namespace).Apply(ctx, appsac.StatefulSet(w.Name, w.Namespace).WithSpec(appsac.StatefulSetSpec().WithTemplate(restarted)), opts)
		case "DaemonSet":
			_, err = apps.DaemonSets(w.Namespace).Apply(ctx, appsac.DaemonSet(w.Name, w.Namespace).WithSpec(appsac.DaemonSetSpec().WithTemplate(restarted)), opts)
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

// serveStatus reports images with findings or patches, their users, and the workloads not yet on the patch.
func (c *controller) serveStatus(w http.ResponseWriter, _ *http.Request) {
	type image struct {
		Digest string `json:"digest"`
		record
		Users    []workload `json:"users"`
		Outdated []workload `json:"outdated,omitempty"`
	}
	out := struct {
		DBBuilt string  `json:"dbBuilt"`
		Active  bool    `json:"active"`
		Images  []image `json:"images"`
	}{DBBuilt: c.scanner.dbBuilt()}
	if snap := c.webhooks.snap.Load(); snap != nil {
		out.Active = snap.Active
	}
	usages := c.inv.usages()
	for d, r := range c.store.all() {
		if len(r.Findings) > 0 || r.Patched != "" {
			img := image{Digest: d, record: r, Users: usages[d].Users}
			if r.Patched != "" {
				for w := range c.inv.outdated(d, r.patchedDigest()) {
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
