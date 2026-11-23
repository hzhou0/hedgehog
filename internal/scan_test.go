package internal

import (
	"context"
	"testing"
)

func TestScanQueuePriorityAndDedup(t *testing.T) {
	ctx := context.Background()
	q := newScanQueue(ctx)
	q.push("a", "img-a", prioRematch)
	q.push("b", "img-b", prioNew)
	waitA := q.push("a", "img-a", prioInline) // promotes a

	j := q.pop(ctx)
	if j.digest != "a" || j.prio != prioInline {
		t.Fatalf("first pop = %s/%d, want promoted a", j.digest, j.prio)
	}
	waitRunning := q.push("a", "img-a", prioNew) // joins the running scan
	q.done(j, nil)
	for _, w := range []<-chan error{waitA, waitRunning} {
		if err := <-w; err != nil {
			t.Fatal(err)
		}
	}
	if j := q.pop(ctx); j.digest != "b" {
		t.Fatalf("second pop = %s, want b (the stale rematch entry for a is skipped)", j.digest)
	}
}
