package internal

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/ulikunitz/xz"
)

func TestCopaReport(t *testing.T) {
	fs := []finding{
		{VulnID: "CVE-1", Package: "libssl3", Version: "3.1.2-r0", Type: "apk", Target: "3.1.4-r0"},
		{VulnID: "CVE-2", Package: "libssl3", Version: "3.1.2-r0", Type: "apk", Target: "3.1.6-r0"},
		{VulnID: "GHSA-1", Package: "tar", Version: "6.1.11", Type: "npm", Target: "7.5.19"},
		{VulnID: "CVE-3", Package: "node", Version: "16.20.2", Type: "binary", Target: "22.23.4"},
		{VulnID: "CVE-4", Package: "zlib", Version: "1.2", Type: "apk"}, // no fix version above installed
	}
	m, library, skipped := copaReport(distro{"alpine", "3.18.3"}, v1.Platform{Architecture: "amd64"}, fs, true)
	if m == nil || m.APIVersion != "v1alpha2" || m.Metadata.OS.Type != "alpine" || m.Metadata.Config.Arch != "amd64" {
		t.Fatalf("manifest %+v", m)
	}
	if len(m.OSUpdates) != 1 || m.OSUpdates[0].FixedVersion != "3.1.6-r0" || m.OSUpdates[0].Class != "os-pkgs" {
		t.Errorf("os updates %+v (want one libssl3 entry at the highest target)", m.OSUpdates)
	}
	if len(m.LangUpdates) != 1 || m.LangUpdates[0].Type != "node-pkg" || !library {
		t.Errorf("lang updates %+v library=%v", m.LangUpdates, library)
	}
	if len(skipped) != 2 {
		t.Errorf("skipped %+v, want the binary and the target-less finding", skipped)
	}
	if m, _, _ := copaReport(distro{}, v1.Platform{}, fs[3:4], true); m != nil {
		t.Error("manifest for binary-only findings")
	}
	// Language updates off: the npm finding is unpatchable and no library mode is requested.
	if m, library, skipped := copaReport(distro{"alpine", "3.18.3"}, v1.Platform{}, fs, false); len(m.LangUpdates) != 0 || library || len(skipped) != 3 {
		t.Errorf("lang off: lang updates %+v library=%v skipped %d", m.LangUpdates, library, len(skipped))
	}
}

func TestCopyPatchKeepsWhiteouts(t *testing.T) {
	ctxTar := writeTar(t, filepath.Join(t.TempDir(), "ctx.tar"), map[string]string{
		"Dockerfile":                  "FROM x\nCOPY patch/ /\n",
		"patch/usr/lib/libssl.so.3":   "new",
		"patch/usr/lib/.wh.libold.so": "",
	})
	var layer bytes.Buffer
	tw := tar.NewWriter(&layer)
	if err := copyPatch(ctxTar, tw); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	got := tarNames(t, &layer)
	if len(got) != 2 || !got["usr/lib/libssl.so.3"] || !got["usr/lib/.wh.libold.so"] {
		t.Errorf("layer entries %v", got)
	}
}

func TestWriteNodeRuntime(t *testing.T) {
	// A minimal release without corepack (like node 25+).
	var release bytes.Buffer
	xw, _ := xz.NewWriter(&release)
	tw := tar.NewWriter(xw)
	for _, e := range []struct {
		name string
		typ  byte
		link string
	}{
		{"bin/", tar.TypeDir, ""}, {"bin/node", tar.TypeReg, ""},
		{"bin/npm", tar.TypeSymlink, "../lib/node_modules/npm/bin/npm-cli.js"},
		{"include/node/node.h", tar.TypeReg, ""}, // no explicit directory entry
		{"lib/node_modules/npm/", tar.TypeDir, ""}, {"lib/node_modules/npm/package.json", tar.TypeReg, ""},
		{"share/doc/node/README.md", tar.TypeReg, ""}, {"README.md", tar.TypeReg, ""},
	} {
		_ = tw.WriteHeader(&tar.Header{Name: "node-v22.23.4-linux-x64/" + e.name, Typeflag: e.typ, Linkname: e.link, Mode: 0o755, Uname: "builder"})
	}
	_ = tw.Close()
	_ = xw.Close()

	// Targets as grype located them: a binary outside any <prefix>/bin layout, npm and corepack where they were found.
	var layer bytes.Buffer
	lw := tar.NewWriter(&layer)
	targets := map[string]string{
		"bin/node":                  "/opt/node22/node",
		"lib/node_modules/npm":      "/usr/local/lib/node_modules/npm",
		"lib/node_modules/corepack": "/usr/local/lib/node_modules/corepack",
	}
	if err := writeNodeRuntime(&release, lw, targets); err != nil {
		t.Fatal(err)
	}
	_ = lw.Close()
	got := tarNames(t, &layer)
	for _, want := range []string{
		"opt/node22/node",
		"usr/local/lib/node_modules/npm/.wh..wh..opq", // old npm files removed
		"usr/local/lib/node_modules/npm/package.json",
		"usr/local/lib/node_modules/.wh.corepack", // not in the new release: deleted
	} {
		if !got[want] {
			t.Errorf("missing %s", want)
		}
	}
	for name := range got { // only the targets: no headers, docs or bin/ symlinks
		if !strings.HasPrefix(name, "opt/node22/node") && !strings.HasPrefix(name, "usr/local/lib/node_modules/") {
			t.Errorf("unexpected entry %s", name)
		}
	}
}

func TestNodeOwns(t *testing.T) {
	for _, tc := range []struct {
		f    finding
		want bool
	}{
		{finding{Type: "binary", Package: "node"}, true},
		{finding{Type: "npm", Path: "/usr/local/lib/node_modules/npm/node_modules/tar/package.json"}, true},
		{finding{Type: "npm", Path: "/app/node_modules/tar/package.json"}, false},
		{finding{Type: "apk", Package: "libssl3"}, false},
	} {
		if got := isNode(tc.f); got != tc.want {
			t.Errorf("isNode(%+v) = %v", tc.f, got)
		}
	}
}

func writeTar(t *testing.T, path string, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for n, body := range files {
		_ = tw.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func tarNames(t *testing.T, r io.Reader) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Uname != "" || h.Uid != 0 {
			t.Errorf("%s keeps owner %q/%d", h.Name, h.Uname, h.Uid)
		}
		out[h.Name] = true
	}
}
