package internal

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// patcher builds one patch at a time: builds are heavy and share the buildkitd sidecar.
type patcher struct {
	dest              string // repository prefix
	pushAuth          authn.Authenticator
	platform          v1.Platform
	patchDependencies bool
	buildTimeout      time.Duration
	buildkitAddr      string
	nodeDistURL       string
	nodeMuslDistURL   string
	store             *store
	webhooks          *webhooks
	changed           chan<- struct{}

	queue            chan string
	queuedOrBuilding sync.Map // digest → struct{}
}

func (p *patcher) enqueue(digest string) {
	if _, loaded := p.queuedOrBuilding.LoadOrStore(digest, struct{}{}); loaded {
		return
	}
	select {
	case p.queue <- digest:
	default:
		p.queuedOrBuilding.Delete(digest) // full; the next reconcile retries
	}
}

func (p *patcher) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case d := <-p.queue:
			pctx, cancel := context.WithTimeout(ctx, p.buildTimeout)
			p.patchImage(pctx, d)
			cancel()
			p.queuedOrBuilding.Delete(d)
		}
	}
}

func (p *patcher) patchImage(ctx context.Context, digest string) {
	rec, ok := p.store.get(digest)
	if !ok || !rec.needsPatch() {
		return
	}
	log := slog.With("image", rec.Source)
	log.Info("patching", "ids", vulnIDs(rec.Findings))
	ref, err := p.build(ctx, digest, rec)
	if err != nil {
		log.Error("patch failed", "err", err)
		patchTotal.WithLabelValues("failed").Inc()
		_, _ = p.store.update(digest, func(r *record) { r.PatchError = err.Error() })
		return
	}
	if _, err := p.store.update(digest, func(r *record) { r.Patched, r.PatchedFor, r.PatchError = ref, vulnIDs(rec.Findings), "" }); err != nil {
		log.Error("store patch", "err", err)
		return
	}
	patchTotal.WithLabelValues("ok").Inc()
	log.Info("patched", "patched", ref)
	p.webhooks.refresh() // rewrite before restarting
	notify(p.changed)
}

// build pushes the source plus one layer of copa's patch and the node replacement to
// <dest>/<source repo>:sha256-<source hex>, and returns it as repo@sha256:...
func (p *patcher) build(ctx context.Context, digest string, rec record) (string, error) {
	work, err := os.MkdirTemp(filepath.Join(dataDir, "work"), "patch-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)
	doc, err := matchSBOM(ctx, sbomPath(digest))
	if err != nil {
		return "", err
	}
	src, err := name.NewDigest(rec.Source)
	if err != nil {
		return "", err
	}
	tag, err := name.NewTag(fmt.Sprintf("%s/%s:sha256-%s", strings.TrimSuffix(p.dest, "/"),
		src.Context().RepositoryStr(), strings.TrimPrefix(src.DigestStr(), "sha256:")))
	if err != nil {
		return "", err
	}

	// Plan before building, so unpatchable images fail fast.
	var nodeFindings, copaFindings []finding
	for _, f := range rec.Findings {
		if fixedByNodeReplacement(f) {
			nodeFindings = append(nodeFindings, f)
		} else {
			copaFindings = append(copaFindings, f)
		}
	}
	var node *nodeReplacement
	if len(nodeFindings) > 0 {
		if node, err = planNodeReplacement(ctx, doc, p.platform, nodeFindings, p.nodeDistURL, p.nodeMuslDistURL); err != nil {
			return "", err
		}
	}
	report, hasDependencyUpdates, skipped := copaReport(doc.Distro, p.platform, copaFindings, p.patchDependencies)
	if len(skipped) > 0 {
		return "", fmt.Errorf("no way to patch %s", strings.Join(vulnIDs(skipped), ", "))
	}

	layerPath := filepath.Join(work, "patch-layer.tar")
	f, err := os.Create(layerPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	if report != nil {
		// copa's output context holds the changed files under patch/, whiteouts included. They're copied into the
		// layer directly: building copa's Dockerfile (`COPY patch/ /`) would lose the whiteouts.
		reportPath, ctxTar := filepath.Join(work, "copa-report.json"), filepath.Join(work, "copa-context.tar")
		b, err := json.Marshal(report)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(reportPath, b, 0o600); err != nil {
			return "", err
		}
		args := []string{"generate", "--image", rec.Source, "--report", reportPath, "--scanner", "native", "--addr", p.buildkitAddr,
			"--output-context", ctxTar, "--working-folder", work, "--timeout", p.buildTimeout.String(), "--progress", "plain"}
		var env []string
		if hasDependencyUpdates {
			args = append(args, "--pkg-types", "os,library")
			env = append(env, "COPA_EXPERIMENTAL=1")
		}
		if _, err := runTool(ctx, env, "copa", args...); err != nil {
			return "", err
		}
		if err := copyCopaPatch(ctxTar, tw); err != nil {
			return "", err
		}
	}
	if node != nil { // last, so it wins over copa
		if err := node.writeLayer(ctx, work, tw); err != nil {
			return "", fmt.Errorf("%s: %w", node, err)
		}
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	layer, err := tarball.LayerFromFile(layerPath)
	if err != nil {
		return "", err
	}

	base, err := remote.Image(src, remote.WithContext(ctx), remote.WithPlatform(p.platform))
	if err != nil {
		return "", fmt.Errorf("pull %s: %w", rec.Source, err)
	}
	img, err := mutate.AppendLayers(base, layer)
	if err != nil {
		return "", err
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return "", err
	}
	cfg := *cf.Config.DeepCopy()
	if node != nil {
		node.editConfig(&cfg)
	}
	if cfg.Labels == nil {
		cfg.Labels = map[string]string{}
	}
	cfg.Labels["io.hedgehog.source"] = rec.Source
	if img, err = mutate.Config(img, cfg); err != nil {
		return "", err
	}
	if err := remote.Write(tag, img, remote.WithContext(ctx), remote.WithAuth(p.pushAuth)); err != nil {
		return "", fmt.Errorf("push %s: %w", tag, err)
	}
	d, err := img.Digest()
	if err != nil {
		return "", err
	}
	return tag.Context().Digest(d.String()).Name(), nil
}

// copaManifest is copa's v1alpha2 UpdateManifest (copacetic pkg/types/v1alpha2), read by `--scanner native`.
type copaManifest struct {
	APIVersion string `json:"apiVersion"`
	Metadata   struct {
		OS struct {
			Type    string `json:"type"`
			Version string `json:"version"`
		} `json:"os"`
		Config struct {
			Arch    string `json:"arch"`
			Variant string `json:"variant,omitempty"`
		} `json:"config"`
	} `json:"metadata"`
	OSUpdates   []copaPackage `json:"osupdates"`
	LangUpdates []copaPackage `json:"langupdates"`
}

type copaPackage struct {
	Name             string `json:"name"`
	InstalledVersion string `json:"installedVersion"`
	FixedVersion     string `json:"fixedVersion"`
	VulnerabilityID  string `json:"vulnerabilityID"`
	Type             string `json:"type"`
	Class            string `json:"class"`
}

// copaDependencyTypes maps grype artifact types to copa's application dependency types (copacetic pkg/utils).
var copaDependencyTypes = map[string]string{"python": "python-pkg", "npm": "node-pkg", "go-module": "gomod", "dotnet": "dotnet-core"}

// copaReport returns copa's manifest for findings (nil if empty), and the findings copa can't patch.
func copaReport(d distro, p v1.Platform, findings []finding, patchDependencies bool) (m *copaManifest, hasDependencyUpdates bool, skipped []finding) {
	byPkg := map[string]copaPackage{}
	for _, f := range findings {
		pkg := copaPackage{Name: f.Package, InstalledVersion: f.Version, FixedVersion: f.Target, VulnerabilityID: f.VulnID}
		switch {
		case f.Target == "":
			skipped = append(skipped, f)
			continue
		case f.Type == "apk" || f.Type == "deb" || f.Type == "rpm":
			pkg.Type, pkg.Class = d.Name, "os-pkgs"
		case patchDependencies && copaDependencyTypes[f.Type] != "":
			pkg.Type, pkg.Class = copaDependencyTypes[f.Type], "lang-pkgs"
		default:
			skipped = append(skipped, f)
			continue
		}
		// One entry per package, at its highest target.
		key := pkg.Class + "/" + f.Package + "@" + f.Version
		if prev, ok := byPkg[key]; !ok || compareVersions(pkg.FixedVersion, prev.FixedVersion) > 0 {
			byPkg[key] = pkg
		}
	}
	if len(byPkg) == 0 {
		return nil, false, skipped
	}
	m = &copaManifest{APIVersion: "v1alpha2"}
	m.Metadata.OS.Type, m.Metadata.OS.Version = d.Name, d.Version
	m.Metadata.Config.Arch, m.Metadata.Config.Variant = p.Architecture, p.Variant
	for _, pkg := range byPkg {
		if pkg.Class == "os-pkgs" {
			m.OSUpdates = append(m.OSUpdates, pkg)
		} else {
			m.LangUpdates = append(m.LangUpdates, pkg)
			hasDependencyUpdates = true
		}
	}
	return m, hasDependencyUpdates, skipped
}

func copyCopaPatch(contextTar string, tw *tar.Writer) error {
	f, err := os.Open(contextTar)
	if err != nil {
		return err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		rel, ok := strings.CutPrefix(hdr.Name, "patch/")
		if !ok || rel == "" {
			continue
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := io.Copy(tw, tr); err != nil {
			return err
		}
	}
}
