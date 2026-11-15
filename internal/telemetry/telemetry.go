// Package telemetry collects low-cost process metrics for the dashboard.
package telemetry

import (
	"runtime"
	"sync"
	"time"
)

type Snapshot struct {
	At            time.Time
	CPUPercent    float64
	CPUAvailable  bool
	MemoryBytes   uint64
	MemoryWorking bool
	Goroutines    int
}

type Sampler struct {
	mu       sync.Mutex
	lastAt   time.Time
	lastCPU  time.Duration
	cpuReady bool
}

func (s *Sampler) Sample() Snapshot {
	now := time.Now()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	memory, working := processMemoryBytes()
	if !working {
		memory = mem.Sys
	}
	cpu, cpuOK := processCPUTime()
	out := Snapshot{
		At:            now,
		MemoryBytes:   memory,
		MemoryWorking: working,
		Goroutines:    runtime.NumGoroutine(),
	}

	s.mu.Lock()
	if cpuOK && s.cpuReady {
		wall := now.Sub(s.lastAt)
		if wall > 0 && cpu >= s.lastCPU {
			out.CPUPercent = float64(cpu-s.lastCPU) / float64(wall) * 100 / float64(runtime.NumCPU())
			if out.CPUPercent < 0 {
				out.CPUPercent = 0
			}
			if out.CPUPercent > 100 {
				out.CPUPercent = 100
			}
			out.CPUAvailable = true
		}
	}
	if cpuOK {
		s.lastAt, s.lastCPU, s.cpuReady = now, cpu, true
	}
	s.mu.Unlock()
	return out
}
