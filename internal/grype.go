package internal

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
)

// grypeDoc is the subset of grype's `-o json` output Hedgehog reads (checked against grype v0.122.1).
type grypeDoc struct {
	Matches []grypeMatch `json:"matches"`
	Distro  distro       `json:"distro"`
}

type distro struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type grypeMatch struct {
	Vulnerability struct {
		ID       string  `json:"id"`
		Severity string  `json:"severity"`
		Risk     float64 `json:"risk"`
		Fix      struct {
			Versions []string `json:"versions"`
			State    string   `json:"state"`
		} `json:"fix"`
		EPSS []struct {
			EPSS float64 `json:"epss"`
		} `json:"epss"`
		KnownExploited []struct {
			KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		} `json:"knownExploited"`
		CVSS []struct {
			Metrics struct {
				BaseScore float64 `json:"baseScore"`
			} `json:"metrics"`
		} `json:"cvss"`
	} `json:"vulnerability"`
	Artifact struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Type      string `json:"type"` // apk, deb, rpm, npm, python, binary, ...
		Locations []struct {
			Path string `json:"path"`
		} `json:"locations"`
	} `json:"artifact"`
}

// finding is one actionable vulnerability in one package of an image.
type finding struct {
	VulnID      string   `json:"vulnID"`
	Package     string   `json:"package"`
	Version     string   `json:"version"`
	Type        string   `json:"type"`
	Path        string   `json:"path"`
	Risk        float64  `json:"risk"`
	KEV         bool     `json:"kev"`
	FixVersions []string `json:"fixVersions"`
	Target      string   `json:"target"` // nearest fixed version above Version; "" if none
}

// actionable applies the fixed scope rule: grype risk > 90 and a fix exists. Highest risk first.
func actionable(doc *grypeDoc) []finding {
	var out []finding
	for _, m := range doc.Matches {
		v, a := m.Vulnerability, m.Artifact
		if v.Risk <= riskThreshold || v.Fix.State != "fixed" {
			continue
		}
		f := finding{
			VulnID: v.ID, Package: a.Name, Version: a.Version, Type: a.Type, Risk: v.Risk,
			KEV: len(v.KnownExploited) > 0, FixVersions: v.Fix.Versions, Target: nearestFix(a.Version, v.Fix.Versions),
		}
		if len(a.Locations) > 0 {
			f.Path = a.Locations[0].Path
		}
		out = append(out, f)
	}
	slices.SortStableFunc(out, func(a, b finding) int { return cmp.Compare(b.Risk, a.Risk) })
	return out
}

// nearestFix picks the lowest fix version above installed, even across major versions. grype can list fixes from
// release lines below the installed one (11.0.0 for node 16.20.2); those are ignored.
func nearestFix(installed string, fixes []string) string {
	best := ""
	for _, f := range fixes {
		if compareVersions(f, installed) > 0 && (best == "" || compareVersions(f, best) < 0) {
			best = f
		}
	}
	return best
}

func vulnIDs(fs []finding) []string {
	ids := make([]string, 0, len(fs))
	for _, f := range fs {
		ids = append(ids, f.VulnID)
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

// compareVersions is an ecosystem-agnostic ordering, good enough within one package (semver, apk -rN, deb/rpm
// epochs and revisions). Versions are compared run by run (digits, letters; separators ignored). copa does the
// authoritative per-package-manager resolution.
func compareVersions(a, b string) int {
	ea, ta := versionTokens(a)
	eb, tb := versionTokens(b)
	if ea != eb {
		return cmp.Compare(ea, eb)
	}
	for i := range max(len(ta), len(tb)) {
		ra, na := tokenRank(ta, i)
		rb, nb := tokenRank(tb, i)
		switch {
		case ra != rb:
			return cmp.Compare(ra, rb)
		case ra == rankNumber && na != nb:
			return cmp.Compare(na, nb)
		case ra == rankLetters && ta[i] != tb[i]:
			return strings.Compare(ta[i], tb[i])
		}
	}
	return 0
}

// Token kinds in sort order: a letter run after the end of the other version is a pre-release (1.0rc1 < 1.0), a
// number is a later release (1.0 < 1.0.1).
const (
	rankLetters = iota
	rankEnd
	rankNumber
)

func tokenRank(tokens []string, i int) (rank int, n uint64) {
	if i >= len(tokens) {
		return rankEnd, 0
	}
	if n, err := strconv.ParseUint(tokens[i], 10, 64); err == nil {
		return rankNumber, n
	}
	return rankLetters, 0
}

// versionTokens splits off a deb/rpm epoch ("1:") and returns the digit and letter runs of the rest.
func versionTokens(v string) (epoch int, tokens []string) {
	v = strings.TrimPrefix(v, "v")
	if e, rest, ok := strings.Cut(v, ":"); ok {
		if n, err := strconv.Atoi(e); err == nil {
			epoch, v = n, rest
		}
	}
	start, kind := 0, 0 // kind: 0 separator, 1 digit, 2 letter
	for i, r := range v + "." {
		k := 0
		switch {
		case r >= '0' && r <= '9':
			k = 1
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			k = 2
		}
		if k != kind {
			if kind != 0 {
				tokens = append(tokens, v[start:i])
			}
			start, kind = i, k
		}
	}
	return epoch, tokens
}

// The syft and grype binaries ship pinned in the image. The vulnerability DB lives on the PV and is only updated
// explicitly (updateDB), never as a side effect of a scan.

// sbom writes a syft-json SBOM of ref, pulled straight from the registry, to out.
func sbom(ctx context.Context, ref, platform, dockerConfigDir, out string) error {
	var env []string
	if dockerConfigDir != "" {
		env = []string{"DOCKER_CONFIG=" + dockerConfigDir}
	}
	_, err := execTool(ctx, env, "syft", "registry:"+ref, "-o", "syft-json="+out, "-q", "--platform", platform)
	return err
}

// match matches a saved SBOM against the local vulnerability DB.
func match(ctx context.Context, sbomPath string) (*grypeDoc, error) {
	out, err := execTool(ctx, nil, "grype", "sbom:"+sbomPath, "-o", "json", "-q")
	if err != nil {
		return nil, err
	}
	var doc grypeDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("parse grype output: %w", err)
	}
	return &doc, nil
}

// execTool runs one of the bundled CLIs with Hedgehog's fixed settings plus env.
func execTool(ctx context.Context, env []string, bin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(),
		"GRYPE_DB_CACHE_DIR="+dataDir+"/grype-db",
		"GRYPE_DB_AUTO_UPDATE=false",
		"GRYPE_CHECK_FOR_APP_UPDATE=false",
		"SYFT_CHECK_FOR_APP_UPDATE=false",
	)
	cmd.Env = append(cmd.Env, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := bytes.TrimSpace(stderr.Bytes())
		if len(msg) > 2048 {
			msg = msg[len(msg)-2048:]
		}
		return nil, fmt.Errorf("%s %s: %w: %s", bin, args[0], err, msg)
	}
	return stdout.Bytes(), nil
}
