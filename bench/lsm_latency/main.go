// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

// Command lsm-latency measures open()+close() latency on an ALLOWED path over
// many iterations and reports the distribution as JSON. Run it twice — once
// with the NeuroSentry agent active (LSM file_open hook attached) and once with
// it stopped — and diff the p50/p99 to isolate the per-open kernel-hook
// overhead. See bench/lsm_latency.sh for the A/B orchestration and
// docs/benchmarks.md for the methodology.
//
//	lsm-latency -path /tmp/nsbench.probe -iterations 200000 -label agent-on
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"
)

type result struct {
	Label        string  `json:"label"`
	Path         string  `json:"path"`
	Iterations   int     `json:"iterations"`
	P50Nanos     int64   `json:"p50_ns"`
	P95Nanos     int64   `json:"p95_ns"`
	P99Nanos     int64   `json:"p99_ns"`
	MeanNanos    int64   `json:"mean_ns"`
	MaxNanos     int64   `json:"max_ns"`
	ThroughputHz float64 `json:"throughput_ops_per_sec"`
}

func main() {
	path := flag.String("path", "/tmp/nsbench.probe", "benign, allowed file to open")
	iters := flag.Int("iterations", 200000, "open()/close() iterations")
	label := flag.String("label", "run", "label for this run (e.g. agent-on / agent-off)")
	flag.Parse()

	// Ensure the probe file exists and is allowed (not a protected extension).
	if err := os.WriteFile(*path, []byte("nsbench"), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "prepare probe: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(*path)

	// Warm up the page cache / dentry cache so we measure the hook, not I/O.
	for i := 0; i < 1000; i++ {
		f, err := os.Open(*path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warmup open: %v\n", err)
			os.Exit(1)
		}
		f.Close()
	}

	lat := make([]int64, *iters)
	start := time.Now()
	for i := 0; i < *iters; i++ {
		t0 := time.Now()
		f, err := os.Open(*path)
		d := time.Since(t0).Nanoseconds()
		if err != nil {
			fmt.Fprintf(os.Stderr, "open: %v\n", err)
			os.Exit(1)
		}
		f.Close()
		lat[i] = d
	}
	wall := time.Since(start).Seconds()

	sort.Slice(lat, func(a, b int) bool { return lat[a] < lat[b] })
	var sum int64
	for _, v := range lat {
		sum += v
	}
	r := result{
		Label:        *label,
		Path:         *path,
		Iterations:   *iters,
		P50Nanos:     lat[int(0.50*float64(*iters-1))],
		P95Nanos:     lat[int(0.95*float64(*iters-1))],
		P99Nanos:     lat[int(0.99*float64(*iters-1))],
		MeanNanos:    sum / int64(*iters),
		MaxNanos:     lat[*iters-1],
		ThroughputHz: float64(*iters) / wall,
	}
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
}
