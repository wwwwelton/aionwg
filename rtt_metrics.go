package main

import (
	"sort"
	"time"
)

func rttJitter(samples []time.Duration) time.Duration {
	if len(samples) < 2 {
		return 0
	}
	var total time.Duration
	for i := 1; i < len(samples); i++ {
		delta := samples[i] - samples[i-1]
		if delta < 0 {
			delta = -delta
		}
		total += delta
	}
	return total / time.Duration(len(samples)-1)
}

func rttPercentile(samples []time.Duration, percentile int) time.Duration {
	if len(samples) == 0 || percentile <= 0 || percentile > 100 {
		return 0
	}
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	index := (len(sorted)*percentile+99)/100 - 1
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}
