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

// Node runtimes aren't tracked by a package manager, so copa can't update them. Hedgehog replaces what grype found
// itself: the node binary at the path grype reports, and the bundled npm or corepack directory when grype reports
// findings inside it. Nothing else about the install layout is assumed.

const (
	nodeOfficial   = "https://nodejs.org/dist"
	nodeUnofficial = "https://unofficial-builds.nodejs.org/download/release" // musl builds
)

// The bundled package directories, as paths in the release tarball. In an image they're found from grype's locations.
var nodeBundled = []string{"lib/node_modules/npm", "lib/node_modules/corepack"}

// isNode reports whether replacing the node runtime fixes f: the node binary itself, or a package inside the bundled
// npm or corepack (copa skips globally installed npm).
func isNode(f finding) bool {
	return f.Type == "binary" && f.Package == "node" ||
		strings.Contains(f.Path, "/lib/node_modules/npm/") || strings.Contains(f.Path, "/lib/node_modules/corepack/")
}

// nodeSwap is a planned node runtime replacement for one image.
type nodeSwap struct {
	installed, version string            // e.g. 16.20.2 → 22.23.4
	targets            map[string]string // release tarball path → absolute path in the image, as grype found it
	arch               string            // node's name: x64, arm64
	musl               bool
}

func (s *nodeSwap) String() string {
	libc := "glibc"
	if s.musl {
		libc = "musl"
	}
	return fmt.Sprintf("node %s → %s at %s (%s, %s)", s.installed, s.version, s.targets["bin/node"], libc, s.arch)
}

func (s *nodeSwap) base() string {
	if s.musl {
		return nodeUnofficial
	}
	return nodeOfficial
}

func (s *nodeSwap) tarball() string {
	name := fmt.Sprintf("node-v%s-linux-%s", s.version, s.arch)
	if s.musl {
		name += "-musl"
	}
	return name + ".tar.xz"
}

// planNode picks the replacement for the node findings fs: what to replace where (from grype's locations), for which
// libc and arch, and the release to install. It runs before anything is built, so an image that can't be patched
// fails fast.
func planNode(ctx context.Context, doc *grypeDoc, platform v1.Platform, fs []finding) (*nodeSwap, error) {
	s := &nodeSwap{musl: doc.Distro.Name == "alpine", targets: map[string]string{}}
	for _, m := range doc.Matches {
		if m.Artifact.Type == "binary" && m.Artifact.Name == "node" && len(m.Artifact.Locations) > 0 {
			s.installed, s.targets["bin/node"] = m.Artifact.Version, m.Artifact.Locations[0].Path
		}
	}
	if s.targets["bin/node"] == "" {
		return nil, errors.New("grype reports no node binary to take the version from")
	}
	for _, f := range fs {
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

	// Minimum version: the highest target among node findings (nearest fix, across majors if needed). npm-only
	// findings just need a newer release. Then take the latest patch release of that major line.
	minVer := s.installed
	for _, f := range fs {
		if f.Package == "node" && compareVersions(f.Target, minVer) > 0 {
			minVer = f.Target
		}
	}
	var releases []struct {
		Version string   `json:"version"`
		Files   []string `json:"files"`
	}
	var index bytes.Buffer
	if _, err := get(ctx, s.base()+"/index.json", &index); err != nil {
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
			(s.version == "" || compareVersions(v, s.version) > 0) {
			s.version = v
		}
	}
	if s.version == "" {
		return nil, fmt.Errorf("no node release >= %s in its major line with a %s build", minVer, build)
	}
	return s, nil
}

// editConfig updates ENV NODE_VERSION, as the official images set it.
func (s *nodeSwap) editConfig(cfg *v1.Config) {
	for i, e := range cfg.Env {
		if strings.HasPrefix(e, "NODE_VERSION=") {
			cfg.Env[i] = "NODE_VERSION=" + s.version
		}
	}
}

// writeLayer downloads and verifies the release and writes its runtime paths into tw at the original prefix.
func (s *nodeSwap) writeLayer(ctx context.Context, work string, tw *tar.Writer) error {
	url := fmt.Sprintf("%s/v%s/", s.base(), s.version)
	// The checksum file is trusted over TLS; it guards the tarball against corruption and truncation.
	sums, err := get(ctx, url+"SHASUMS256.txt", nil)
	if err != nil {
		return err
	}
	want := ""
	for _, line := range strings.Split(string(sums), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[1] == s.tarball() {
			want = f[0]
		}
	}
	if want == "" {
		return fmt.Errorf("%s not in SHASUMS256.txt", s.tarball())
	}
	tarXZ := filepath.Join(work, s.tarball())
	out, err := os.Create(tarXZ)
	if err != nil {
		return err
	}
	defer out.Close()
	sum := sha256.New()
	if _, err := get(ctx, url+s.tarball(), io.MultiWriter(out, sum)); err != nil {
		return err
	}
	if got := hex.EncodeToString(sum.Sum(nil)); got != want {
		return fmt.Errorf("%s: sha256 %s, want %s", s.tarball(), got, want)
	}
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return writeNodeRuntime(out, tw, s.targets)
}

// writeNodeRuntime copies the release tarball's (.tar.xz) entries for each target into tw at the target's path in
// the image. A replaced directory gets an opaque whiteout so old files can't linger; a target the release doesn't
// ship (corepack, from node 25) is deleted.
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
		// Opaque marker on the first entry under a replaced directory. It only hides lower layers, so where it sits
		// in this layer doesn't matter.
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

// get fetches url, bounded by ctx (the patch timeout). With w nil it returns the body (up to 1 MiB); otherwise it
// streams the body into w.
func get(ctx context.Context, url string, w io.Writer) ([]byte, error) {
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
