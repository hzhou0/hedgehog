package internal

import (
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"k8s.io/apimachinery/pkg/types"
)

func TestCollectReferenceCounting(t *testing.T) {
	db, err := bolt.Open(filepath.Join(t.TempDir(), "hedgehog.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error { _, err := tx.CreateBucketIfNotExists(bucket); return err }); err != nil {
		t.Fatal(err)
	}
	st := &store{db: db}
	const (
		src     = "sha256:aaaa" // in use, rewritten to its patch
		patched = "sha256:bbbb" // its patch: referenced through src
		stale   = "sha256:cccc" // unreferenced past the grace period
		fresh   = "sha256:dddd" // unreferenced, still within it
	)
	for d, r := range map[string]record{
		src:     {Source: "docker.io/library/node@" + src, Patched: "dest.example/library/node@" + patched},
		patched: {Source: "dest.example/library/node@" + patched},
		stale:   {Source: "docker.io/library/busybox@" + stale},
		fresh:   {Source: "docker.io/library/alpine@" + fresh},
	} {
		if _, err := st.update(d, func(rec *record) { *rec = r }); err != nil {
			t.Fatal(err)
		}
	}
	// One Pod, rewritten: it runs the patch, and its source is src.
	inv := &inventory{pods: map[types.UID]podInfo{"p": {owner: workload{"Deployment", "app", "web"},
		containers: []container{{Digest: patched, SourceDigest: src, SourceImage: "docker.io/library/node@" + src}}}}}
	c := &controller{store: st, inv: inv, unrefSince: map[string]time.Time{
		stale: time.Now().Add(-gcGrace - time.Minute),
		fresh: time.Now().Add(-time.Minute),
	}}

	c.collect(inv.usages())

	for d, want := range map[string]bool{src: true, patched: true, stale: false, fresh: true} {
		if _, ok := st.get(d); ok != want {
			t.Errorf("record %s kept = %v, want %v", d, ok, want)
		}
	}
	if _, ok := c.unrefSince[src]; ok {
		t.Error("a referenced image is counted as unreferenced")
	}
}
