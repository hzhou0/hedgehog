package internal

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	bolt "go.etcd.io/bbolt"
)

// record is what Hedgehog knows about one image, keyed by digest.
type record struct {
	Source     string    `json:"source"` // repo@sha256:...
	DBBuilt    string    `json:"dbBuilt"`
	Findings   []finding `json:"findings"` // actionable only
	Patched    string    `json:"patched"`  // repo@sha256:... Pods are rewritten to
	PatchedFor []string  `json:"patchedFor"`
	PatchError string    `json:"patchError"` // cleared on success and on each new DB
}

func (r record) patchedDigest() string {
	_, d, _ := strings.Cut(r.Patched, "@")
	return d
}

func (r record) needsPatch() bool {
	for _, f := range r.Findings {
		if r.Patched == "" || !slices.Contains(r.PatchedFor, f.VulnID) {
			return true
		}
	}
	return false
}

// store is a single bbolt bucket of JSON records.
type store struct{ db *bolt.DB }

var bucket = []byte("images")

func (s *store) get(digest string) (record, bool) {
	var r record
	found := false
	_ = s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucket).Get([]byte(digest))
		found = v != nil && json.Unmarshal(v, &r) == nil
		return nil
	})
	return r, found
}

func (s *store) all() map[string]record {
	recs := map[string]record{}
	_ = s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).ForEach(func(k, v []byte) error {
			var r record
			if json.Unmarshal(v, &r) == nil {
				recs[string(k)] = r
			}
			return nil
		})
	})
	return recs
}

func (s *store) update(digest string, fn func(*record)) (record, error) {
	var r record
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if v := b.Get([]byte(digest)); v != nil {
			if err := json.Unmarshal(v, &r); err != nil {
				return fmt.Errorf("record %s: %w", digest, err)
			}
		}
		fn(&r)
		v, err := json.Marshal(r)
		if err != nil {
			return err
		}
		return b.Put([]byte(digest), v)
	})
	return r, err
}

func (s *store) delete(digest string) error {
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucket).Delete([]byte(digest)) })
}
