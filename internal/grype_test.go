package internal

import (
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
)

// testdata/node16-alpine.json is grype v0.122.1 output for node:16-alpine, trimmed to the fields Hedgehog reads.
func loadNode16(t *testing.T) *grypeDoc {
	t.Helper()
	b, err := os.ReadFile("testdata/node16-alpine.json")
	if err != nil {
		t.Fatal(err)
	}
	var d grypeDoc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return &d
}

// Hedgehog gates on grype's risk score. If this fails after a grype upgrade, grype changed the formula
// (grype/vulnerability/metadata.go): re-check what `risk > 90` means before shipping the upgrade.
func TestRiskFormulaUnchanged(t *testing.T) {
	for _, m := range loadNode16(t).Matches {
		v := m.Vulnerability
		threat, kevMod := 0.0, 1.0
		if len(v.EPSS) > 0 {
			threat = v.EPSS[0].EPSS
		}
		if len(v.KnownExploited) > 0 {
			threat, kevMod = 1.0, 1.05
			for _, k := range v.KnownExploited {
				if strings.EqualFold(k.KnownRansomwareCampaignUse, "known") {
					kevMod = 1.1
				}
			}
		}
		label := map[string]float64{"negligible": 0.5, "low": 3, "medium": 5, "high": 7.5, "critical": 9}[strings.ToLower(v.Severity)]
		if label == 0 {
			label = 5
		}
		severity, sum, n := label/10, 0.0, 0
		for _, c := range v.CVSS {
			if c.Metrics.BaseScore != 0 {
				sum, n = sum+c.Metrics.BaseScore, n+1
			}
		}
		if n > 0 {
			severity = (severity + sum/float64(n)/10) / 2
		}
		if got := min(threat*severity*kevMod, 1) * 100; math.Abs(got-v.Risk) > 1e-6 {
			t.Errorf("%s %s: recomputed risk %.6f, grype says %.6f", v.ID, m.Artifact.Name, got, v.Risk)
		}
	}
}

func TestActionableNode16(t *testing.T) {
	fs := actionable(loadNode16(t), 90)
	if len(fs) != 1 {
		t.Fatalf("want exactly 1 actionable finding, got %+v", fs)
	}
	f := fs[0]
	if f.VulnID != "CVE-2026-111497" || f.Package != "node" || f.Type != "binary" || !f.KEV || f.Path != "/usr/local/bin/node" {
		t.Errorf("unexpected finding %+v", f)
	}
	// Fixes are 11.0.0, 22.23.4, 24.22.1, 26.12.1 for installed 16.20.2: the nearest above is 22.23.4.
	if f.Target != "22.23.4" {
		t.Errorf("target = %q", f.Target)
	}
}

func TestRiskThresholdIsStrict(t *testing.T) {
	doc := &grypeDoc{Matches: make([]grypeMatch, 3)}
	for i, risk := range []float64{90, 95, 90.5} {
		m := &doc.Matches[i]
		m.Vulnerability.ID, m.Vulnerability.Risk = []string{"A", "B", "C"}[i], risk
		m.Vulnerability.Fix.State, m.Vulnerability.Fix.Versions = "fixed", []string{"2"}
		m.Artifact.Version = "1"
	}
	doc.Matches[1].Vulnerability.Fix.State = "not-fixed"
	if fs := actionable(doc, 90); len(fs) != 1 || fs[0].VulnID != "C" {
		t.Fatalf("got %+v", fs)
	}
}

func TestNearestFix(t *testing.T) {
	for _, tc := range []struct {
		installed string
		fixes     []string
		want      string
	}{
		{"16.20.2", []string{"11.0.0", "24.22.1", "22.23.4"}, "22.23.4"},
		{"3.1.2-r0", []string{"3.1.6-r0"}, "3.1.6-r0"},
		{"1:11.8.6-0+deb13u1", []string{"1:11.8.6-0+deb13u2"}, "1:11.8.6-0+deb13u2"},
		{"1.0", []string{"1.0rc1"}, ""},
		{"2.0.0", []string{"1.9.0"}, ""},
	} {
		if got := nearestFix(tc.installed, tc.fixes); got != tc.want {
			t.Errorf("nearestFix(%q, %v) = %q, want %q", tc.installed, tc.fixes, got, tc.want)
		}
	}
}
