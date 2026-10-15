package main

import (
	"context"
	"fmt"
	"io"
	"time"
)

func heartbeat(out io.Writer, name string, limit time.Duration) func() {
	done := make(chan struct{})
	stopped := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(stopped)
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				fmt.Fprintf(out, "%s: %s elapsed (limit %s)\n", name, time.Since(start).Round(time.Second), limit)
			}
		}
	}()
	return func() { close(done); <-stopped }
}

// waitFor gives every transition a deadline, cancellation, and visible progress.
// Each probe must observe ctx too; cancellation cannot interrupt arbitrary code.
func waitFor(ctx context.Context, out io.Writer, name string, timeout, interval time.Duration, probe func(context.Context) (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	started := time.Now()
	fmt.Fprintf(out, "Waiting for %s (limit %s)\n", name, timeout)
	tick := time.NewTicker(interval)
	defer tick.Stop()
	var last error
	var lastReport time.Time
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%s: %w (last observation: %v)", name, err, last)
		}
		ready, err := probe(ctx)
		if err != nil {
			last = err
		}
		if ready && err == nil {
			fmt.Fprintf(out, "%s ready after %s\n", name, time.Since(started).Round(time.Millisecond))
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s: %w (last observation: %v)", name, ctx.Err(), last)
		case <-tick.C:
			if !lastReport.IsZero() && time.Since(lastReport) < time.Second {
				continue
			}
			lastReport = time.Now()
			fmt.Fprintf(out, "%s: %s elapsed, %s remaining", name, time.Since(started).Round(time.Second), (timeout - time.Since(started)).Round(time.Second))
			if last != nil {
				fmt.Fprintf(out, "; %v", last)
			}
			fmt.Fprintln(out)
		}
	}
}
