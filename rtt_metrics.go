package main

import "time"

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
