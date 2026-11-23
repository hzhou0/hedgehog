package internal

import (
	"encoding/json"
	"fmt"
	"slices"

	bolt "go.etcd.io/bbolt"
)

// record is everything Hedgehog knows about one source image, keyed by digest.
type record struct {
	Source     string    `json:"source"`     // repo@sha256:..., used to pull the image
	DBBuilt    string    `json:"dbBuilt"`    // vulnerability DB the findings came from
	Findings   []finding `json:"findings"`   // actionable only; empty = clean
	Patched    string    `json:"patched"`    // patched repo@sha256:...; set = active rewrite
	PatchedFor []string  `json:"patchedFor"` // vuln IDs the current patch addresses
	Error      string    `json:"error"`      // last patch failure; cleared on success and on each new DB
}

// needsPatch reports whether some actionable finding isn't covered by the current patch.
func (r record) needsPatch() bool {
	for _, f := range r.Findings {
		if r.Patched == "" || !slices.Contains(r.PatchedFor, f.VulnID) {
			return true
		}
	}
	return false
}

// store is a single bbolt bucket of JSON records. bbolt locks the file, which enforces the single replica.
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

// update applies fn to the digest's record (zero if absent) and persists it in one transaction.
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
