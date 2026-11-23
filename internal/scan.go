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
	prioInline = iota
	prioNew
	prioRematch
	numPrio
)

var prioNames = [numPrio]string{"inline", "new", "rematch"}

type scanJob struct {
	digest, image string
	prio          int
	waiters       []chan error
}

// scanQueue is a priority queue keyed by digest. Pushing a queued digest promotes it; pushing a running one joins it.
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

type scanner struct {
	riskThreshold    float64
	maxBackoff       time.Duration
	dbUpdateInterval time.Duration

	store     *store
	platform  v1.Platform
	changed   chan<- struct{}
	queue     *scanQueue
	currentDB atomic.Value // string, the DB's build time; "" until downloaded

	backoffMu sync.Mutex
	backoffs  map[string]backoff // by digest
}

type backoff struct {
	failures int
	until    time.Time
}

func (s *scanner) run(ctx context.Context, workers int) {
	s.currentDB.Store("")
	s.backoffs = map[string]backoff{}
	go s.updateDBs(ctx)
	for range workers {
		go s.worker(ctx)
	}
}

func (s *scanner) dbBuilt() string { return s.currentDB.Load().(string) }

// request queues a scan unless the digest is backing off from a failure.
func (s *scanner) request(digest, image string, prio int) {
	s.backoffMu.Lock()
	b := s.backoffs[digest]
	s.backoffMu.Unlock()
	if time.Now().Before(b.until) {
		return
	}
	s.queue.push(digest, image, prio)
}

// updateDBs checks for a new vulnerability DB every dbUpdateInterval.
func (s *scanner) updateDBs(ctx context.Context) {
	for ctx.Err() == nil {
		_, err := runTool(ctx, nil, "grype", "db", "update", "-q")
		var out []byte
		if err == nil {
			out, err = runTool(ctx, nil, "grype", "db", "status", "-o", "json")
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
		if st.Built != s.dbBuilt() {
			slog.Info("vulnerability DB", "built", st.Built)
			s.currentDB.Store(st.Built)
			notify(s.changed)
		}
		sleep(ctx, s.dbUpdateInterval)
	}
}

func (s *scanner) worker(ctx context.Context) {
	for j := s.queue.pop(ctx); j != nil; j = s.queue.pop(ctx) {
		start := time.Now()
		sctx, cancel := context.WithTimeout(ctx, scanTimeout)
		err := s.scan(sctx, j)
		cancel()
		s.queue.done(j, err)
		result := "ok"
		s.backoffMu.Lock()
		if err != nil {
			result = "error"
			b := s.backoffs[j.digest]
			b.failures++
			delay := min(time.Minute<<min(b.failures-1, 16), s.maxBackoff)
			b.until = time.Now().Add(delay)
			s.backoffs[j.digest] = b
			time.AfterFunc(delay, func() { notify(s.changed) })
			slog.Error("scan failed", "image", j.image, "err", err, "retryIn", delay)
		} else {
			delete(s.backoffs, j.digest)
		}
		s.backoffMu.Unlock()
		scanSeconds.WithLabelValues(prioNames[j.prio], result).Observe(time.Since(start).Seconds())
		notify(s.changed)
	}
}

// scan matches the digest's SBOM, made once, against the current DB.
func (s *scanner) scan(ctx context.Context, j *scanJob) error {
	dbBuilt := s.dbBuilt()
	if dbBuilt == "" {
		return errors.New("vulnerability DB not ready")
	}
	path := sbomPath(j.digest)
	if _, err := os.Stat(path); err != nil {
		if err := generateSBOM(ctx, j.image, s.platform.OS+"/"+s.platform.Architecture, path+".tmp"); err != nil {
			return err
		}
		if err := os.Rename(path+".tmp", path); err != nil {
			return err
		}
	}
	doc, err := matchSBOM(ctx, path)
	if err != nil {
		return err
	}
	findings := actionable(doc, s.riskThreshold)
	if _, err := s.store.update(j.digest, func(r *record) {
		if r.DBBuilt != dbBuilt {
			r.PatchError = "" // retry failed patches once per DB
		}
		r.Source, r.DBBuilt, r.Findings = j.image, dbBuilt, findings
	}); err != nil {
		return err
	}
	if len(findings) > 0 {
		slog.Info("actionable findings", "image", j.image, "ids", vulnIDs(findings))
	}
	return nil
}

// inlineScan resolves image and scans it at top priority, until ctx is done.
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
	if rec, ok := s.store.get(digest); ok && rec.DBBuilt == s.dbBuilt() {
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
