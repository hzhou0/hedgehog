// Package internal is Hedgehog. See docs/design.md.
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

const (
	scanTimeout       = 10 * time.Minute
	inlineScanTimeout = 20 * time.Second // below the validating webhook's 25 s timeout

	dataDir = "/data" // the PersistentVolume
	certDir = "/certs"
	ownName = "hedgehog" // field manager and webhook configuration names
	tlsName = "hedgehog-webhook-tls"
	svcName = "hedgehog-webhook"

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
	pushAuth := authn.Anonymous // all pulls are anonymous
	if u := os.Getenv("DESTINATION_USERNAME"); u != "" {
		pushAuth = authn.FromConfig(authn.AuthConfig{Username: u, Password: os.Getenv("DESTINATION_PASSWORD")})
	}
	exclude := map[string]bool{}
	for _, n := range strings.Split(os.Getenv("EXCLUDE_NAMESPACES"), ",") {
		if n = strings.TrimSpace(n); n != "" {
			exclude[n] = true
		}
	}
	var errs []error
	var (
		scanWorkers            = env(&errs, "SCAN_WORKERS", 2, positiveInt)
		patchDependencies      = env(&errs, "PATCH_DEPENDENCIES", false, strconv.ParseBool)
		riskThreshold          = env(&errs, "RISK_THRESHOLD", 90.0, float)
		maxScanBackoff         = env(&errs, "MAX_SCAN_BACKOFF", time.Hour, positiveDuration)
		dbUpdateInterval       = env(&errs, "DB_UPDATE_INTERVAL", 15*time.Minute, positiveDuration)
		buildTimeout           = env(&errs, "PATCH_BUILD_TIMEOUT", 45*time.Minute, positiveDuration)
		backgroundScanInterval = env(&errs, "BACKGROUND_SCAN_INTERVAL", time.Hour, positiveDuration)
		keepUnreferenced       = env(&errs, "KEEP_UNREFERENCED", 7*24*time.Hour, positiveDuration)
		buildkitAddr           = env(&errs, "BUILDKIT_ADDR", "tcp://127.0.0.1:1234", str)
		nodeDistURL            = env(&errs, "NODE_DIST_URL", "https://nodejs.org/dist", str)
		nodeMuslDistURL        = env(&errs, "NODE_MUSL_DIST_URL", "https://unofficial-builds.nodejs.org/download/release", str)
		metricsAddr            = env(&errs, "METRICS_ADDR", ":8080", str)
		probeAddr              = env(&errs, "PROBE_ADDR", ":8081", str)
		webhookPort            = env(&errs, "WEBHOOK_PORT", 8443, positiveInt)
	)
	if err := errors.Join(errs...); err != nil {
		return err
	}
	cfg := ctrl.GetConfigOrDie()
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}

	var status atomic.Pointer[controller]
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
			ExtraHandlers: map[string]http.Handler{"/status": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if c := status.Load(); c != nil {
					c.serveStatus(w, r)
					return
				}
				http.Error(w, "starting", http.StatusServiceUnavailable)
			})},
		},
		HealthProbeBindAddress: probeAddr,
	})
	if err != nil {
		return err
	}

	// cert-controller rotates the serving cert and injects the CA into both webhook configurations.
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

	for _, d := range []string{"grype-db", "sbom"} {
		if err := os.MkdirAll(filepath.Join(dataDir, d), 0o755); err != nil {
			return err
		}
	}
	work := filepath.Join(dataDir, "work")
	_ = os.RemoveAll(work)
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

	// Rootless buildkitd can't emulate, so images are scanned and patched for Hedgehog's own platform.
	platform := v1.Platform{OS: runtime.GOOS, Architecture: runtime.GOARCH}

	changed := make(chan struct{}, 1)
	inv, err := watchInventory(ctx, mgr.GetCache(), exclude, changed)
	if err != nil {
		return err
	}
	sc := &scanner{
		riskThreshold: riskThreshold, maxBackoff: maxScanBackoff, dbUpdateInterval: dbUpdateInterval,
		store: st, platform: platform, changed: changed, queue: newScanQueue(ctx),
	}
	wh := &webhooks{exclude: exclude, store: st, inv: inv, scanner: sc}
	pa := &patcher{
		dest: dest, pushAuth: pushAuth, platform: platform, patchDependencies: patchDependencies, buildTimeout: buildTimeout,
		buildkitAddr: buildkitAddr, nodeDistURL: nodeDistURL, nodeMuslDistURL: nodeMuslDistURL,
		store: st, webhooks: wh, changed: changed, queue: make(chan string, 1024),
	}
	c := &controller{
		backgroundScanInterval: backgroundScanInterval, keepUnreferenced: keepUnreferenced, unreferencedSince: map[string]time.Time{},
		client: cs, cache: mgr.GetCache(), store: st, inv: inv, scanner: sc, patcher: pa, webhooks: wh, changed: changed,
	}

	wh.refresh()
	sc.run(ctx, scanWorkers)
	go pa.run(ctx)
	go c.loop(ctx)
	status.Store(c)

	select {
	case <-certsReady:
	case err := <-errc:
		return err
	}
	s := webhook.NewServer(webhook.Options{Port: webhookPort, CertDir: certDir}).(*webhook.DefaultServer)
	s.Register("/mutate", &webhook.Admission{Handler: admission.HandlerFunc(wh.mutate)})
	s.Register("/validate", &webhook.Admission{Handler: admission.HandlerFunc(wh.validate)})
	if err := mgr.Add(s); err != nil {
		return err
	}
	srv.Store(s)
	return <-errc
}

// env parses the environment variable name, or returns def if it's unset. A parse error is added to errs.
func env[T any](errs *[]error, name string, def T, parse func(string) (T, error)) T {
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return def
	}
	t, err := parse(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s=%q: %w", name, v, err))
		return def
	}
	return t
}

func str(s string) (string, error) { return s, nil }

func float(s string) (float64, error) { return strconv.ParseFloat(s, 64) }

func positiveInt(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err == nil && n < 1 {
		err = errors.New("must be positive")
	}
	return n, err
}

func positiveDuration(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err == nil && d <= 0 {
		err = errors.New("must be positive")
	}
	return d, err
}
