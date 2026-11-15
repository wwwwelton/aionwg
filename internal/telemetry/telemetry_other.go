//go:build !windows

package telemetry

import "time"

func processCPUTime() (time.Duration, bool) { return 0, false }

func processMemoryBytes() (uint64, bool) { return 0, false }
