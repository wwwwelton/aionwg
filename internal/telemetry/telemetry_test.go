package telemetry

import "testing"

func TestSamplerReportsRuntimeMetrics(t *testing.T) {
	var sampler Sampler
	got := sampler.Sample()
	if got.MemoryBytes == 0 {
		t.Fatal("memory metric must be reported")
	}
	if got.Goroutines == 0 {
		t.Fatal("goroutine metric must be reported")
	}
}
