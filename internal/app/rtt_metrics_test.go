package app

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

func TestRTTPercentileDoesNotMutateSamples(t *testing.T) {
	samples := []time.Duration{40 * time.Millisecond, 10 * time.Millisecond, 30 * time.Millisecond, 20 * time.Millisecond}
	if got := rttPercentile(samples, 50); got != 20*time.Millisecond {
		t.Fatalf("p50 = %v, want 20ms", got)
	}
	if samples[0] != 40*time.Millisecond {
		t.Fatal("percentile calculation mutated the sample order")
	}
}
