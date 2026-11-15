package main

import (
	"testing"
	"time"
)

func TestRTTJitterUsesSuccessiveSampleVariation(t *testing.T) {
	got := rttJitter([]time.Duration{10 * time.Millisecond, 14 * time.Millisecond, 12 * time.Millisecond})
	if got != 3*time.Millisecond {
		t.Fatalf("jitter = %v, want 3ms", got)
	}
}
