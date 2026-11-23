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

// A patched image is the source image plus one layer holding copa's package-manager patch and, if needed, a
// replacement node runtime (nodejs.go), pushed to <dest>/<source repo>:sha256-<source hex>.

// patcher owns patching: its queue and the single worker that builds a patch and makes the rewrite live. One build at
// a time: builds are heavy and share the buildkitd sidecar. Restarts are the reconcile loop's (controller.go).
type patcher struct {
	dest     string              // repository prefix for patched images
	auth     authn.Authenticator // push credentials for the destination (anonymous if none)
	platform v1.Platform
	// languageUpdates turns on copa's experimental language package updates (npm, pip, …) (LANGUAGE_UPDATES).
	// Off, language findings are unpatchable.
	languageUpdates bool
	store           *store
	webhooks        *webhooks       // refreshed so the rewrite is live before the restarts
	changed         chan<- struct{} // a new patch triggers a reconcile, which restarts its workloads

	queue   chan string
	pending sync.Map // digest → struct{}: queued or building
}

func (p *patcher) enqueue(digest string) {
	if _, loaded := p.pending.LoadOrStore(digest, struct{}{}); loaded {
		return
	}
	select {
	case p.queue <- digest:
	default:
		p.pending.Delete(digest) // full; the next reconcile retries
	}
}

func (p *patcher) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case d := <-p.queue:
			// Still pending while it builds, so reconciles during the build don't queue it again.
			pctx, cancel := context.WithTimeout(ctx, 45*time.Minute)
			p.mitigate(pctx, d)
			cancel()
			p.pending.Delete(d)
		}
	}
}

func (p *patcher) mitigate(ctx context.Context, digest string) {
	rec, ok := p.store.get(digest)
	if !ok || !rec.needsPatch() {
		return
	}
	log := slog.With("image", rec.Source)
	log.Info("patching", "ids", vulnIDs(rec.Findings))
	ref, err := p.patch(ctx, digest, rec)
	if err != nil {
		log.Error("patch failed", "err", err)
		patchTotal.WithLabelValues("failed").Inc()
		_, _ = p.store.update(digest, func(r *record) { r.Error = err.Error() })
		return
	}
	if _, err := p.store.update(digest, func(r *record) { r.Patched, r.PatchedFor, r.Error = ref, vulnIDs(rec.Findings), "" }); err != nil {
		log.Error("store patch", "err", err)
		return
	}
	patchTotal.WithLabelValues("ok").Inc()
	log.Info("patched", "patched", ref)
	p.webhooks.refresh() // new Pods are rewritten from here on
	notify(p.changed)    // the reconcile loop restarts the workloads still on the vulnerable image
}

// patch builds the patched image of digest and pushes it, returning it as repo@sha256:... It isn't verified here:
// the patched image is rolled out and then scanned like any other image (controller.reconcile).
func (p *patcher) patch(ctx context.Context, digest string, rec record) (string, error) {
	work, err := os.MkdirTemp(filepath.Join(dataDir, "work"), "patch-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)
	doc, err := match(ctx, sbomPath(digest))
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

	// Plan everything before building anything, so unpatchable images fail fast. Node runtime findings are fixed by
	// replacing the runtime; copa gets the rest.
	var nodeFs, rest []finding
	for _, f := range rec.Findings {
		if isNode(f) {
			nodeFs = append(nodeFs, f)
		} else {
			rest = append(rest, f)
		}
	}
	var node *nodeSwap
	if len(nodeFs) > 0 {
		if node, err = planNode(ctx, doc, p.platform, nodeFs); err != nil {
			return "", err
		}
	}
	report, library, skipped := copaReport(doc.Distro, p.platform, rest, p.languageUpdates)
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
		// copa runs the package manager in BuildKit and outputs a build context: a Dockerfile plus the changed files
		// under patch/. Hedgehog copies the patch/ entries into its layer instead of building that Dockerfile: copa
		// writes the diff's whiteouts (.wh.*) as ordinary entries, which become layer whiteouts again once the prefix
		// is stripped, whereas `COPY patch/ /` would lose those deletions.
		reportPath, ctxTar := filepath.Join(work, "copa-report.json"), filepath.Join(work, "copa-context.tar")
		b, err := json.Marshal(report)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(reportPath, b, 0o600); err != nil {
			return "", err
		}
		args := []string{"generate", "--image", rec.Source, "--report", reportPath, "--scanner", "native", "--addr", buildkitAddr,
			"--output-context", ctxTar, "--working-folder", work, "--timeout", "30m", "--progress", "plain"}
		var env []string
		if library { // language packages are an experimental copa feature
			args = append(args, "--pkg-types", "os,library")
			env = append(env, "COPA_EXPERIMENTAL=1")
		}
		if _, err := execTool(ctx, env, "copa", args...); err != nil {
			return "", err
		}
		if err := copyPatch(ctxTar, tw); err != nil {
			return "", err
		}
	}
	if node != nil { // after copa's entries, so the node runtime wins on any path both touch
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

	base, err := remote.Image(src, remote.WithContext(ctx), remote.WithPlatform(p.platform)) // sources pull anonymously
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
	if err := remote.Write(tag, img, remote.WithContext(ctx), remote.WithAuth(p.auth)); err != nil {
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

// copaLangTypes maps grype artifact types to copa's language package types (copacetic pkg/utils).
var copaLangTypes = map[string]string{"python": "python-pkg", "npm": "node-pkg", "go-module": "gomod", "dotnet": "dotnet-core"}

// copaReport turns findings into a copa manifest (nil if copa has nothing to do). Findings copa can't handle are
// returned as skipped.
// copaReport converts findings to copa's manifest. Language packages are included only with lang (copa's experimental
// language updates, LANGUAGE_UPDATES); otherwise they're skipped, like anything copa can't patch.
func copaReport(d distro, p v1.Platform, fs []finding, lang bool) (m *copaManifest, library bool, skipped []finding) {
	byPkg := map[string]copaPackage{}
	for _, f := range fs {
		pkg := copaPackage{Name: f.Package, InstalledVersion: f.Version, FixedVersion: f.Target, VulnerabilityID: f.VulnID}
		switch {
		case f.Target == "":
			skipped = append(skipped, f)
			continue
		case f.Type == "apk" || f.Type == "deb" || f.Type == "rpm":
			pkg.Type, pkg.Class = d.Name, "os-pkgs"
		case lang && copaLangTypes[f.Type] != "":
			pkg.Type, pkg.Class = copaLangTypes[f.Type], "lang-pkgs"
		default:
			skipped = append(skipped, f)
			continue
		}
		// One entry per package: its highest target fixes all of its findings.
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
			library = true
		}
	}
	return m, library, skipped
}

func copyPatch(contextTar string, tw *tar.Writer) error {
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
