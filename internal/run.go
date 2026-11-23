// Package internal is all of Hedgehog: inventory, scanning, patching, rollout and the admission webhooks, in one
// process. See docs/design.md.
package internal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	bolt "go.etcd.io/bbolt"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// Fixed behaviour. The only settings are the destination and its credentials, the scan concurrency and language
// updates (see Run).
const (
	riskThreshold = 90.0               // act on grype risk strictly above this
	scanBudget    = 20 * time.Second   // inline admission scan; the webhook timeout is 25 s
	gcGrace       = 7 * 24 * time.Hour // how long an image must go unreferenced before it's deleted

	dataDir = "/data"    // PersistentVolume: bbolt file, SBOMs, grype DB, scratch
	certDir = "/certs"   // webhook serving cert, written by cert-controller
	ownName = "hedgehog" // field manager and webhook configuration names
	tlsName = "hedgehog-webhook-tls"

	buildkitAddr = "tcp://127.0.0.1:1234" // the buildkitd sidecar, loopback only
	svcName      = "hedgehog-webhook"

	sourceAnnotation  = "hedgehog.io/source-images"
	restartAnnotation = "kubectl.kubernetes.io/restartedAt"
)

// Run runs Hedgehog until ctx is cancelled.
func Run(ctx context.Context) error {
	ns, dest := os.Getenv("POD_NAMESPACE"), os.Getenv("DESTINATION")
	if ns == "" || dest == "" {
		return errors.New("POD_NAMESPACE and DESTINATION must be set")
	}
	if _, err := name.NewRepository(dest); err != nil {
		return fmt.Errorf("DESTINATION: %w", err)
	}
	// Push credentials for the destination, used only for Hedgehog's own push; unset means anonymous. Everything else
	// pulls anonymously: sources, syft, copa, and nodes pulling patched images.
	auth := authn.Anonymous
	if u := os.Getenv("DESTINATION_USERNAME"); u != "" {
		auth = authn.FromConfig(authn.AuthConfig{Username: u, Password: os.Getenv("DESTINATION_PASSWORD")})
	}
	// Each scan worker runs its own syft and grype, and both load the vulnerability DB: size the memory limit with it.
	scanWorkers := 2
	if v := os.Getenv("SCAN_WORKERS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return fmt.Errorf("SCAN_WORKERS must be a positive integer, got %q", v)
		}
		scanWorkers = n
	}
	// Namespaces Hedgehog leaves alone entirely: not scanned, patched or restarted, and not gated by the webhooks.
	exclude := map[string]bool{}
	for _, n := range strings.Split(os.Getenv("EXCLUDE_NAMESPACES"), ",") {
		if n = strings.TrimSpace(n); n != "" {
			exclude[n] = true
		}
	}
	// copa's language package updates are experimental, so they're off unless asked for.
	var languageUpdates bool
	if v := os.Getenv("LANGUAGE_UPDATES"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("LANGUAGE_UPDATES must be true or false, got %q", v)
		}
		languageUpdates = b
	}
	cfg := ctrl.GetConfigOrDie()
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}

	var status atomic.Pointer[controller] // set once everything is wired up
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Metrics: metricsserver.Options{
			BindAddress: ":8080",
			ExtraHandlers: map[string]http.Handler{"/status": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if c := status.Load(); c != nil {
					c.serveStatus(w, r)
					return
				}
				http.Error(w, "starting", http.StatusServiceUnavailable)
			})},
		},
		HealthProbeBindAddress: ":8081",
	})
	if err != nil {
		return err
	}

	// cert-controller creates and rotates the serving cert (stored in a Secret mounted at certDir) and injects the
	// CA into both webhook configurations.
	certsReady := make(chan struct{})
	if err := rotator.AddRotator(mgr, &rotator.CertRotator{
		SecretKey:      types.NamespacedName{Namespace: ns, Name: tlsName},
		CertDir:        certDir,
		CAName:         "hedgehog-ca",
		CAOrganization: ownName,
		DNSName:        fmt.Sprintf("%s.%s.svc", svcName, ns),
		IsReady:        certsReady,
		FieldOwner:     ownName,
		Webhooks: []rotator.WebhookInfo{
			{Name: ownName, Type: rotator.Validating},
			{Name: ownName, Type: rotator.Mutating},
		},
	}); err != nil {
		return err
	}

	// Ready once the webhook server (added below, after the certs exist) is serving.
	var srv atomic.Pointer[webhook.DefaultServer]
	_ = mgr.AddHealthzCheck("ping", healthz.Ping)
	_ = mgr.AddReadyzCheck("webhook", func(req *http.Request) error {
		if s := srv.Load(); s != nil {
			return s.StartedChecker()(req)
		}
		return errors.New("webhook not serving yet")
	})

	errc := make(chan error, 1)
	go func() { errc <- mgr.Start(ctx) }()
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		return errors.New("cache did not sync")
	}

	// State on the PV: scratch space, SBOMs, the grype DB and the bbolt store.
	for _, d := range []string{"grype-db", "sbom"} {
		if err := os.MkdirAll(filepath.Join(dataDir, d), 0o755); err != nil {
			return err
		}
	}
	work := filepath.Join(dataDir, "work")
	_ = os.RemoveAll(work) // scratch left by a previous run
	if err := os.MkdirAll(work, 0o755); err != nil {
		return err
	}
	db, err := bolt.Open(filepath.Join(dataDir, "hedgehog.db"), 0o600, &bolt.Options{Timeout: 10 * time.Second})
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error { _, err := tx.CreateBucketIfNotExists(bucket); return err }); err != nil {
		return err
	}
	st := &store{db: db}

	// Builds run natively (rootless buildkitd can't emulate other architectures), so Hedgehog scans and patches for
	// the platform it runs on.
	platform := v1.Platform{OS: runtime.GOOS, Architecture: runtime.GOARCH}

	// The components, each owning its own state. The inventory and the scanner signal changed; the controller
	// reconciles on it.
	changed := make(chan struct{}, 1)
	inv, err := watchInventory(ctx, mgr.GetCache(), exclude, changed)
	if err != nil {
		return err
	}
	sc := &scanner{store: st, platform: platform, changed: changed, queue: newScanQueue(ctx)}
	wh := &webhooks{exclude: exclude, store: st, inv: inv, scanner: sc}
	pa := &patcher{dest: dest, auth: auth, platform: platform,
		languageUpdates: languageUpdates, store: st, webhooks: wh, changed: changed, queue: make(chan string, 1024)}
	c := &controller{unrefSince: map[string]time.Time{}, cs: cs, cache: mgr.GetCache(), store: st, inv: inv, scanner: sc, patcher: pa, webhooks: wh, changed: changed}

	// Admission works from persisted state right away, before the DB download or any scan.
	wh.refresh()
	sc.run(ctx, scanWorkers)
	go pa.run(ctx)
	go c.loop(ctx)
	status.Store(c)

	// The webhook server needs the cert files, so it's added once cert-controller has written them.
	select {
	case <-certsReady:
	case err := <-errc:
		return err
	}
	s := webhook.NewServer(webhook.Options{Port: 8443, CertDir: certDir}).(*webhook.DefaultServer)
	s.Register("/mutate", &webhook.Admission{Handler: admission.HandlerFunc(wh.mutate)})
	s.Register("/validate", &webhook.Admission{Handler: admission.HandlerFunc(wh.validate)})
	if err := mgr.Add(s); err != nil {
		return err
	}
	srv.Store(s)
	return <-errc
}
