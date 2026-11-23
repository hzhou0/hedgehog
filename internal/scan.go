package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Scan priorities, highest first.
const (
	prioInline  = iota // an admission request is waiting
	prioNew            // never scanned
	prioRematch        // new vulnerability DB
	numPrio
)

var prioNames = [numPrio]string{"inline", "new", "rematch"}

type scanJob struct {
	digest, image string // image is repo@digest
	prio          int
	waiters       []chan error
}

// scanQueue is a priority queue keyed by digest. Pushing a queued digest at a higher priority promotes it; pushing a
// running digest waits for that run.
type scanQueue struct {
	mu      sync.Mutex
	cond    *sync.Cond
	queued  map[string]*scanJob
	running map[string]*scanJob
	fifo    [numPrio][]string
}

func newScanQueue(ctx context.Context) *scanQueue {
	q := &scanQueue{queued: map[string]*scanJob{}, running: map[string]*scanJob{}}
	q.cond = sync.NewCond(&q.mu)
	context.AfterFunc(ctx, func() { q.mu.Lock(); q.cond.Broadcast(); q.mu.Unlock() })
	return q
}

// push enqueues a scan; the returned channel receives its result once.
func (q *scanQueue) push(digest, image string, prio int) <-chan error {
	ch := make(chan error, 1)
	q.mu.Lock()
	defer q.mu.Unlock()
	if j := q.running[digest]; j != nil {
		j.waiters = append(j.waiters, ch)
		return ch
	}
	j := q.queued[digest]
	if j == nil {
		j = &scanJob{digest: digest, image: image, prio: numPrio}
		q.queued[digest] = j
	}
	j.waiters = append(j.waiters, ch)
	if prio < j.prio {
		j.prio = prio
		q.fifo[prio] = append(q.fifo[prio], digest) // an older, lower-priority entry is skipped by pop
		q.cond.Signal()
	}
	return ch
}

// pop blocks until a job is available; it returns nil once ctx is done.
func (q *scanQueue) pop(ctx context.Context) *scanJob {
	q.mu.Lock()
	defer q.mu.Unlock()
	for ctx.Err() == nil {
		for p := range numPrio {
			for len(q.fifo[p]) > 0 {
				d := q.fifo[p][0]
				q.fifo[p] = q.fifo[p][1:]
				if j := q.queued[d]; j != nil && j.prio == p {
					delete(q.queued, d)
					q.running[d] = j
					return j
				}
			}
		}
		q.cond.Wait()
	}
	return nil
}

func (q *scanQueue) done(j *scanJob, err error) {
	q.mu.Lock()
	delete(q.running, j.digest)
	q.mu.Unlock()
	for _, w := range j.waiters {
		w <- err
	}
}

// scanner owns scanning: the priority queue, its workers, and the vulnerability DB they match against. A finished
// scan or a new DB signals changed, the reconcile loop's trigger.
type scanner struct {
	store    *store
	platform v1.Platform
	changed  chan<- struct{}
	queue    *scanQueue
	dbBuilt  atomic.Value // string; "" until the first DB download

	failMu sync.Mutex
	failed map[string]backoff // digest → when its failed scan may be retried (memory only)
}

type backoff struct {
	n     int // consecutive failures
	retry time.Time
}

// run starts the DB updates and the scan workers.
func (s *scanner) run(ctx context.Context, workers int) {
	s.dbBuilt.Store("")
	s.failed = map[string]backoff{}
	go s.updateDBs(ctx)
	for range workers {
		go s.worker(ctx)
	}
}

func (s *scanner) built() string { return s.dbBuilt.Load().(string) }

// request queues a background scan, unless the digest's last scan failed and its backoff hasn't passed: an image that
// can't be pulled (private, or not built for Hedgehog's platform) would otherwise be retried on every reconcile.
// Inline admission scans don't go through here.
func (s *scanner) request(digest, image string, prio int) {
	s.failMu.Lock()
	b, failed := s.failed[digest]
	s.failMu.Unlock()
	if failed && time.Now().Before(b.retry) {
		return
	}
	s.queue.push(digest, image, prio)
}

// updateDBs downloads the vulnerability DB (retrying until it works), then checks for a new one every 15 minutes.
// A new DB triggers a re-match of every in-use image.
func (s *scanner) updateDBs(ctx context.Context) {
	for ctx.Err() == nil {
		_, err := execTool(ctx, nil, "grype", "db", "update", "-q")
		var out []byte
		if err == nil {
			out, err = execTool(ctx, nil, "grype", "db", "status", "-o", "json")
		}
		var st struct {
			Built string `json:"built"`
			Valid bool   `json:"valid"`
		}
		if err == nil {
			err = json.Unmarshal(out, &st)
		}
		if err == nil && !st.Valid {
			err = errors.New("grype reports the DB as invalid")
		}
		if err != nil {
			slog.Error("vulnerability DB update failed", "err", err)
			sleep(ctx, 30*time.Second)
			continue
		}
		if st.Built != s.built() {
			slog.Info("vulnerability DB", "built", st.Built)
			s.dbBuilt.Store(st.Built)
			notify(s.changed)
		}
		sleep(ctx, 15*time.Minute)
	}
}

func (s *scanner) worker(ctx context.Context) {
	for j := s.queue.pop(ctx); j != nil; j = s.queue.pop(ctx) {
		start := time.Now()
		sctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		err := s.scan(sctx, j)
		cancel()
		s.queue.done(j, err)
		result := "ok"
		s.failMu.Lock()
		if err != nil {
			// Back off 1, 2, 4, … minutes, at most an hour, and reconcile when it's over.
			result = "error"
			b := s.failed[j.digest]
			b.n++
			delay := min(time.Minute<<min(b.n-1, 6), time.Hour)
			b.retry = time.Now().Add(delay)
			s.failed[j.digest] = b
			time.AfterFunc(delay, func() { notify(s.changed) })
			slog.Error("scan failed", "image", j.image, "err", err, "retryIn", delay)
		} else {
			delete(s.failed, j.digest)
		}
		s.failMu.Unlock()
		scanSeconds.WithLabelValues(prioNames[j.prio], result).Observe(time.Since(start).Seconds())
		notify(s.changed)
	}
}

// scan makes (or reuses) the digest's SBOM, matches it against the current DB, and stores the actionable findings.
// Patching is the reconcile loop's decision: it only patches images in use.
func (s *scanner) scan(ctx context.Context, j *scanJob) error {
	built := s.built()
	if built == "" {
		return errors.New("vulnerability DB not ready")
	}
	sbomPath := sbomPath(j.digest)
	if _, err := os.Stat(sbomPath); err != nil {
		if err := sbom(ctx, j.image, s.platform.OS+"/"+s.platform.Architecture, "", sbomPath+".tmp"); err != nil {
			return err
		}
		if err := os.Rename(sbomPath+".tmp", sbomPath); err != nil {
			return err
		}
	}
	doc, err := match(ctx, sbomPath)
	if err != nil {
		return err
	}
	fs := actionable(doc)
	if _, err := s.store.update(j.digest, func(r *record) {
		if r.DBBuilt != built {
			r.Error = "" // a failed patch is retried once per new DB
		}
		r.Source, r.DBBuilt, r.Findings = j.image, built, fs
	}); err != nil {
		return err
	}
	if len(fs) > 0 {
		slog.Info("actionable findings", "image", j.image, "ids", vulnIDs(fs))
	}
	return nil
}

// inlineScan is the admission path for unknown images in active mode: resolve the tag, scan at top priority, and
// give up when the admission budget (ctx) runs out.
func (s *scanner) inlineScan(ctx context.Context, image string) (record, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return record{}, err
	}
	desc, err := remote.Head(ref, remote.WithContext(ctx))
	if err != nil {
		return record{}, fmt.Errorf("resolve: %w", err)
	}
	digest := desc.Digest.String()
	if rec, ok := s.store.get(digest); ok && rec.DBBuilt == s.built() {
		return rec, nil
	}
	select {
	case err := <-s.queue.push(digest, ref.Context().Digest(digest).Name(), prioInline):
		if err != nil {
			return record{}, err
		}
	case <-ctx.Done():
		return record{}, ctx.Err()
	}
	rec, _ := s.store.get(digest)
	return rec, nil
}

func sbomPath(digest string) string {
	return filepath.Join(dataDir, "sbom", strings.TrimPrefix(digest, "sha256:")+".json")
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
