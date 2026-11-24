package app

import (
	"testing"
	"time"
)

func TestRouteStatsAndReselect(t *testing.T) {
	st := &RouteStats{}
	t0 := time.Now()

	st.OnProbeSent(1, t0)
	rtt, ok := st.OnPong(1, t0.Add(50*time.Millisecond))
	if !ok || rtt < 49 || rtt > 51 {
		t.Fatalf("unexpected rtt: %v, ok: %v", rtt, ok)
	}

	score, ok := st.Score(t0.Add(100 * time.Millisecond))
	if !ok || score <= 0 {
		t.Fatalf("unexpected score: %v, ok: %v", score, ok)
	}

	// Test ReselectRoutes
	scores := map[uint16]float64{
		0: 50.0,
		1: 45.0,
		2: 80.0,
	}
	current := []uint16{0}
	active := ReselectRoutes(scores, current, 2, 5.0)
	if len(active) != 2 {
		t.Fatalf("expected 2 active routes, got %d (%v)", len(active), active)
	}

	// Route 2 is 80ms, replacing with 45ms should happen if margin is satisfied
	scores[3] = 40.0 // 40ms vs 50ms (diff 10 > margin 5)
	active2 := ReselectRoutes(scores, []uint16{0, 2}, 2, 5.0)
	// Route 2 (80ms) should be replaced by route 1 or 3
	has2 := false
	for _, id := range active2 {
		if id == 2 {
			has2 = true
		}
	}
	if has2 {
		t.Fatalf("route 2 should have been dropped: %v", active2)
	}
}
