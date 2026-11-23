package internal

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/ulikunitz/xz"
)

// No package manager tracks the node runtime, so copa can't update it. Hedgehog replaces the node binary and the
// bundled npm and corepack directories itself, at the paths grype reports.

// nodeBundled are paths in the release tarball.
var nodeBundled = []string{"lib/node_modules/npm", "lib/node_modules/corepack"}

func fixedByNodeReplacement(f finding) bool {
	return f.Type == "binary" && f.Package == "node" ||
		strings.Contains(f.Path, "/lib/node_modules/npm/") || strings.Contains(f.Path, "/lib/node_modules/corepack/")
}

type nodeReplacement struct {
	fromVersion, toVersion string
	targets                map[string]string // release tarball path → absolute path in the image
	arch                   string            // x64, arm64
	musl                   bool
	distURL                string
}

func (s *nodeReplacement) String() string {
	libc := "glibc"
	if s.musl {
		libc = "musl"
	}
	return fmt.Sprintf("node %s → %s at %s (%s, %s)", s.fromVersion, s.toVersion, s.targets["bin/node"], libc, s.arch)
}

func (s *nodeReplacement) tarballName() string {
	name := fmt.Sprintf("node-v%s-linux-%s", s.toVersion, s.arch)
	if s.musl {
		name += "-musl"
	}
	return name + ".tar.xz"
}

func planNodeReplacement(ctx context.Context, doc *grypeDoc, platform v1.Platform, findings []finding, distURL, muslDistURL string) (*nodeReplacement, error) {
	s := &nodeReplacement{musl: doc.Distro.Name == "alpine", distURL: distURL, targets: map[string]string{}}
	if s.musl {
		s.distURL = muslDistURL
	}
	for _, m := range doc.Matches {
		if m.Artifact.Type == "binary" && m.Artifact.Name == "node" && len(m.Artifact.Locations) > 0 {
			s.fromVersion, s.targets["bin/node"] = m.Artifact.Version, m.Artifact.Locations[0].Path
		}
	}
	if s.targets["bin/node"] == "" {
		return nil, errors.New("grype reports no node binary to take the version from")
	}
	for _, f := range findings {
		for _, d := range nodeBundled {
			if dir, _, ok := strings.Cut(f.Path, "/"+d+"/"); ok {
				s.targets[d] = dir + "/" + d
			}
		}
	}
	switch platform.Architecture {
	case "amd64":
		s.arch = "x64"
	case "arm64":
		s.arch = "arm64"
	default:
		return nil, fmt.Errorf("node: unsupported architecture %q", platform.Architecture)
	}

	// Install the latest release in the major line of the highest fix.
	minVer := s.fromVersion
	for _, f := range findings {
		if f.Package == "node" && compareVersions(f.Target, minVer) > 0 {
			minVer = f.Target
		}
	}
	var releases []struct {
		Version string   `json:"version"`
		Files   []string `json:"files"`
	}
	var index bytes.Buffer
	if _, err := httpGet(ctx, s.distURL+"/index.json", &index); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(index.Bytes(), &releases); err != nil {
		return nil, err
	}
	build := "linux-" + s.arch
	if s.musl {
		build += "-musl"
	}
	major, _, _ := strings.Cut(minVer, ".")
	for _, r := range releases {
		v := strings.TrimPrefix(r.Version, "v")
		if strings.HasPrefix(v, major+".") && compareVersions(v, minVer) >= 0 && slices.Contains(r.Files, build) &&
			(s.toVersion == "" || compareVersions(v, s.toVersion) > 0) {
			s.toVersion = v
		}
	}
	if s.toVersion == "" {
		return nil, fmt.Errorf("no node release >= %s in its major line with a %s build", minVer, build)
	}
	return s, nil
}

// editConfig updates NODE_VERSION, as the official images set it.
func (s *nodeReplacement) editConfig(cfg *v1.Config) {
	for i, e := range cfg.Env {
		if strings.HasPrefix(e, "NODE_VERSION=") {
			cfg.Env[i] = "NODE_VERSION=" + s.toVersion
		}
	}
}

func (s *nodeReplacement) writeLayer(ctx context.Context, work string, tw *tar.Writer) error {
	url := fmt.Sprintf("%s/v%s/", s.distURL, s.toVersion)
	sums, err := httpGet(ctx, url+"SHASUMS256.txt", nil)
	if err != nil {
		return err
	}
	want := ""
	for _, line := range strings.Split(string(sums), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[1] == s.tarballName() {
			want = f[0]
		}
	}
	if want == "" {
		return fmt.Errorf("%s not in SHASUMS256.txt", s.tarballName())
	}
	tarXZ := filepath.Join(work, s.tarballName())
	out, err := os.Create(tarXZ)
	if err != nil {
		return err
	}
	defer out.Close()
	sum := sha256.New()
	if _, err := httpGet(ctx, url+s.tarballName(), io.MultiWriter(out, sum)); err != nil {
		return err
	}
	if got := hex.EncodeToString(sum.Sum(nil)); got != want {
		return fmt.Errorf("%s: sha256 %s, want %s", s.tarballName(), got, want)
	}
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return writeNodeRuntime(out, tw, s.targets)
}

// writeNodeRuntime copies each target from the release .tar.xz into tw. Replaced directories are made opaque, and
// targets the release lacks (corepack from node 25) are deleted.
func writeNodeRuntime(tarXZ io.Reader, tw *tar.Writer, targets map[string]string) error {
	xr, err := xz.NewReader(bufio.NewReader(tarXZ))
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	tr := tar.NewReader(xr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		_, rel, _ := strings.Cut(strings.TrimSuffix(hdr.Name, "/"), "/") // strip "node-vX-linux-arch/"
		key := ""
		for k := range targets {
			if rel == k || strings.HasPrefix(rel, k+"/") {
				key = k
			}
		}
		if key == "" {
			continue
		}
		dest := strings.TrimPrefix(targets[key]+strings.TrimPrefix(rel, key), "/")
		if key != "bin/node" && !seen[key] {
			if err := tw.WriteHeader(&tar.Header{Name: path.Join(strings.TrimPrefix(targets[key], "/"), ".wh..wh..opq"), Typeflag: tar.TypeReg, Mode: 0o644}); err != nil {
				return err
			}
		}
		seen[key] = true
		hdr.Name = dest
		if hdr.Typeflag == tar.TypeDir {
			hdr.Name += "/"
		}
		hdr.Uname, hdr.Gname, hdr.Uid, hdr.Gid = "", "", 0, 0
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := io.Copy(tw, tr); err != nil {
			return err
		}
	}
	if !seen["bin/node"] {
		return errors.New("release tarball has no bin/node")
	}
	for k, p := range targets {
		if !seen[k] {
			p = strings.TrimPrefix(p, "/")
			if err := tw.WriteHeader(&tar.Header{Name: path.Join(path.Dir(p), ".wh."+path.Base(p)), Typeflag: tar.TypeReg, Mode: 0o644}); err != nil {
				return err
			}
		}
	}
	return nil
}

// httpGet returns the body (up to 1 MiB), or streams it into w if set.
func httpGet(ctx context.Context, url string, w io.Writer) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	if w != nil {
		_, err = io.Copy(w, resp.Body)
		return nil, err
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
