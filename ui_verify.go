package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"image"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	uiVerifyDefaultSettle = time.Second
	uiVerifyMaximumSettle = 30 * time.Second
	uiVerifyStageTimeout  = 15 * time.Second
	uiVerifyRetainedRuns  = 10
	uiVerifyMaximumAge    = 7 * 24 * time.Hour
)

type uiVerifyOptions struct {
	X      int
	Y      int
	Settle time.Duration
}

type uiVerifyFrame struct {
	Path           string `json:"path"`
	Pixels         uint64 `json:"pixels"`
	NonBlackPixels uint64 `json:"nonblack_pixels"`
	RGBA256        string `json:"rgba_sha256"`
}

type uiVerifyReport struct {
	Schema     string         `json:"schema"`
	Status     string         `json:"status"`
	Stage      string         `json:"stage"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt *time.Time     `json:"finished_at,omitempty"`
	Desktop    string         `json:"desktop,omitempty"`
	Width      uint16         `json:"width,omitempty"`
	Height     uint16         `json:"height,omitempty"`
	TapX       uint16         `json:"tap_x,omitempty"`
	TapY       uint16         `json:"tap_y,omitempty"`
	Settle     string         `json:"settle"`
	Before     *uiVerifyFrame `json:"before,omitempty"`
	After      *uiVerifyFrame `json:"after,omitempty"`
	Error      string         `json:"error,omitempty"`
}

type uiVerifySession interface {
	dimensions() (uint16, uint16, string)
	capture(context.Context) (*image.RGBA, rfbFrameStats, error)
	tap(context.Context, uint16, uint16) error
	close() error
}

type uiVerifyRFBSession struct{ session *rfbSession }

func (s uiVerifyRFBSession) dimensions() (uint16, uint16, string) {
	return s.session.width, s.session.height, s.session.name
}

func (s uiVerifyRFBSession) capture(ctx context.Context) (*image.RGBA, rfbFrameStats, error) {
	return s.session.capture(ctx)
}

func (s uiVerifyRFBSession) tap(ctx context.Context, x, y uint16) error {
	return s.session.tap(ctx, x, y)
}

func (s uiVerifyRFBSession) close() error { return s.session.close() }

type uiVerifyDependencies struct {
	connect func(context.Context, *cache) (uiVerifySession, error)
	settle  func(context.Context, io.Writer, time.Duration) error
	now     func() time.Time
}

func defaultUIVerifyDependencies() uiVerifyDependencies {
	return uiVerifyDependencies{
		connect: func(ctx context.Context, c *cache) (uiVerifySession, error) {
			session, err := connectUIRFB(ctx, c)
			if err != nil {
				return nil, err
			}
			return uiVerifyRFBSession{session: session}, nil
		},
		settle: waitUIVerifySettle,
		now:    time.Now,
	}
}

func parseUIVerifyOptions(args []string) (uiVerifyOptions, error) {
	options := uiVerifyOptions{X: -1, Y: -1, Settle: uiVerifyDefaultSettle}
	flags := flag.NewFlagSet("ui verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.IntVar(&options.X, "x", -1, "tap x coordinate (defaults to frame center)")
	flags.IntVar(&options.Y, "y", -1, "tap y coordinate (defaults to frame center)")
	flags.DurationVar(&options.Settle, "settle", uiVerifyDefaultSettle, "bounded delay between tap and second capture")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return options, errors.New("usage: ui verify [--x X --y Y --settle DURATION]")
	}
	if (options.X < 0) != (options.Y < 0) {
		return options, errors.New("ui verify requires both --x and --y, or neither")
	}
	if options.X > 65535 || options.Y > 65535 {
		return options, errors.New("ui verify coordinates must be unsigned 16-bit integers")
	}
	if options.Settle < 0 || options.Settle > uiVerifyMaximumSettle {
		return options, fmt.Errorf("ui verify --settle must be between 0 and %s", uiVerifyMaximumSettle)
	}
	return options, nil
}

func verifyUICommand(ctx context.Context, c *cache, args []string) error {
	options, err := parseUIVerifyOptions(args)
	if err != nil {
		return err
	}
	_, err = verifyUI(ctx, c, options, defaultUIVerifyDependencies())
	return err
}

func verifyUI(ctx context.Context, c *cache, options uiVerifyOptions, dependencies uiVerifyDependencies) (string, error) {
	if dependencies.connect == nil || dependencies.settle == nil || dependencies.now == nil {
		return "", errors.New("ui verify dependencies are incomplete")
	}
	started := dependencies.now().UTC()
	runDirectory, err := newUIVerifyRunDirectory(c, started)
	if err != nil {
		return "", fmt.Errorf("ui verify artifacts: %w", err)
	}
	reportPath := filepath.Join(runDirectory, "report.json")
	report := uiVerifyReport{
		Schema:    "15-plus-kernel-poc.ui-verification.v1",
		Status:    "running",
		Stage:     "connect",
		StartedAt: started,
		Settle:    options.Settle.String(),
	}
	if err = writeUIVerifyJSONAtomic(reportPath, report); err != nil {
		return reportPath, fmt.Errorf("ui verify initialize report: %w", err)
	}
	fail := func(stage string, cause error) (string, error) {
		finished := dependencies.now().UTC()
		report.Status = "failed"
		report.Stage = stage
		report.FinishedAt = &finished
		report.Error = cause.Error()
		if reportErr := writeUIVerifyJSONAtomic(reportPath, report); reportErr != nil {
			return reportPath, fmt.Errorf("ui verify %s: %w (also failed to write report: %v)", stage, cause, reportErr)
		}
		return reportPath, fmt.Errorf("ui verify %s: %w (report: %s)", stage, cause, reportPath)
	}

	fmt.Fprintf(c.out, "UI verify started: stage=connect deadline=%s artifacts=%s\n", uiVerifyStageTimeout, runDirectory)
	connectCtx, cancelConnect := context.WithTimeout(ctx, uiVerifyStageTimeout)
	stopConnect := heartbeat(c.out, "UI verify RFB connect", uiVerifyStageTimeout)
	session, err := dependencies.connect(connectCtx, c)
	stopConnect()
	cancelConnect()
	if err != nil {
		return fail("connect", err)
	}
	defer session.close()

	width, height, desktop := session.dimensions()
	if width == 0 || height == 0 {
		return fail("geometry", fmt.Errorf("invalid RFB geometry %dx%d", width, height))
	}
	report.Width, report.Height, report.Desktop = width, height, desktop
	if options.X < 0 {
		report.TapX, report.TapY = width/2, height/2
	} else {
		report.TapX, report.TapY = uint16(options.X), uint16(options.Y)
	}
	if report.TapX >= width || report.TapY >= height {
		return fail("tap-coordinate", fmt.Errorf("tap %d,%d is outside %dx%d", report.TapX, report.TapY, width, height))
	}

	report.Stage = "capture-before"
	if err = writeUIVerifyJSONAtomic(reportPath, report); err != nil {
		return reportPath, fmt.Errorf("ui verify update report: %w", err)
	}
	beforeCtx, cancelBefore := context.WithTimeout(ctx, uiVerifyStageTimeout)
	stopBefore := heartbeat(c.out, "UI verify capture before tap", uiVerifyStageTimeout)
	beforeImage, _, err := session.capture(beforeCtx)
	stopBefore()
	cancelBefore()
	if err != nil {
		return fail("capture-before", err)
	}
	beforeStats, err := validateUIVerifyFrame(beforeImage, width, height)
	if err != nil {
		return fail("validate-before", err)
	}
	beforePath := filepath.Join(runDirectory, "before.png")
	if err = writeUIVerifyPNGAtomic(beforePath, beforeImage); err != nil {
		return fail("persist-before", err)
	}
	report.Before = &uiVerifyFrame{
		Path:           filepath.Base(beforePath),
		Pixels:         beforeStats.Pixels,
		NonBlackPixels: beforeStats.NonBlackPixels,
		RGBA256:        beforeStats.RGBA256,
	}
	report.Stage = "tap"
	if err = writeUIVerifyJSONAtomic(reportPath, report); err != nil {
		return reportPath, fmt.Errorf("ui verify persist before report: %w", err)
	}

	tapCtx, cancelTap := context.WithTimeout(ctx, 5*time.Second)
	err = session.tap(tapCtx, report.TapX, report.TapY)
	cancelTap()
	if err != nil {
		return fail("tap", err)
	}
	report.Stage = "settle"
	if err = writeUIVerifyJSONAtomic(reportPath, report); err != nil {
		return reportPath, fmt.Errorf("ui verify update settle report: %w", err)
	}
	if err = dependencies.settle(ctx, c.out, options.Settle); err != nil {
		return fail("settle", err)
	}

	report.Stage = "capture-after"
	if err = writeUIVerifyJSONAtomic(reportPath, report); err != nil {
		return reportPath, fmt.Errorf("ui verify update after report: %w", err)
	}
	afterCtx, cancelAfter := context.WithTimeout(ctx, uiVerifyStageTimeout)
	stopAfter := heartbeat(c.out, "UI verify capture after tap", uiVerifyStageTimeout)
	afterImage, _, err := session.capture(afterCtx)
	stopAfter()
	cancelAfter()
	if err != nil {
		return fail("capture-after", err)
	}
	afterStats, err := validateUIVerifyFrame(afterImage, width, height)
	if err != nil {
		return fail("validate-after", err)
	}
	if afterStats.RGBA256 == beforeStats.RGBA256 {
		return fail("validate-after", errors.New("RFB frame did not change after pointer input"))
	}
	afterPath := filepath.Join(runDirectory, "after.png")
	if err = writeUIVerifyPNGAtomic(afterPath, afterImage); err != nil {
		return fail("persist-after", err)
	}
	report.After = &uiVerifyFrame{
		Path:           filepath.Base(afterPath),
		Pixels:         afterStats.Pixels,
		NonBlackPixels: afterStats.NonBlackPixels,
		RGBA256:        afterStats.RGBA256,
	}
	finished := dependencies.now().UTC()
	report.Status = "passed"
	report.Stage = "complete"
	report.FinishedAt = &finished
	if err = writeUIVerifyJSONAtomic(reportPath, report); err != nil {
		return reportPath, fmt.Errorf("ui verify finalize report: %w", err)
	}
	fmt.Fprintf(c.out, "UI verified: geometry=%dx%d desktop=%q tap=%d,%d before_nonblack=%d after_nonblack=%d changed_rgba=true report=%s\n",
		width, height, desktop, report.TapX, report.TapY, beforeStats.NonBlackPixels, afterStats.NonBlackPixels, reportPath)
	return reportPath, nil
}

func validateUIVerifyFrame(frame *image.RGBA, width, height uint16) (rfbFrameStats, error) {
	var stats rfbFrameStats
	if frame == nil {
		return stats, errors.New("RFB capture returned no frame")
	}
	want := image.Rect(0, 0, int(width), int(height))
	if frame.Bounds() != want || frame.Stride != int(width)*4 || len(frame.Pix) != int(width)*int(height)*4 {
		return stats, fmt.Errorf("RFB frame layout does not match geometry %dx%d", width, height)
	}
	stats.Pixels = uint64(width) * uint64(height)
	for offset := 0; offset < len(frame.Pix); offset += 4 {
		if frame.Pix[offset] != 0 || frame.Pix[offset+1] != 0 || frame.Pix[offset+2] != 0 {
			stats.NonBlackPixels++
		}
	}
	if stats.NonBlackPixels == 0 {
		return stats, errors.New("RFB frame is completely black")
	}
	hash := sha256.Sum256(frame.Pix)
	stats.RGBA256 = hex.EncodeToString(hash[:])
	return stats, nil
}

func newUIVerifyRunDirectory(c *cache, started time.Time) (string, error) {
	parent := filepath.Join(c.root, "private", "ui-verifications")
	if err := os.MkdirAll(parent, 0700); err != nil {
		return "", err
	}
	if err := pruneUIVerifyRuns(parent, started); err != nil {
		return "", err
	}
	return os.MkdirTemp(parent, started.Format("20060102T150405.000000000Z-")+"run-")
}

func pruneUIVerifyRuns(parent string, now time.Time) error {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return err
	}
	type candidate struct {
		name    string
		modTime time.Time
	}
	var runs []candidate
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		runs = append(runs, candidate{name: entry.Name(), modTime: info.ModTime()})
	}
	sort.Slice(runs, func(i, j int) bool {
		if runs[i].modTime.Equal(runs[j].modTime) {
			return runs[i].name > runs[j].name
		}
		return runs[i].modTime.After(runs[j].modTime)
	})
	// Leave room for the run about to be created. Every deletion is confined
	// to a direct child of the owned ui-verifications directory.
	for index, run := range runs {
		if index < uiVerifyRetainedRuns-1 && now.Sub(run.modTime) <= uiVerifyMaximumAge {
			continue
		}
		name := filepath.Join(parent, run.name)
		if filepath.Dir(name) != parent || name == parent {
			return errors.New("UI verification retention candidate escaped owned directory")
		}
		if err = os.RemoveAll(name); err != nil {
			return err
		}
	}
	return nil
}

func writeUIVerifyPNGAtomic(name string, frame image.Image) error {
	return writeUIVerifyAtomic(name, func(writer io.Writer) error { return png.Encode(writer, frame) })
}

func writeUIVerifyJSONAtomic(name string, value any) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return writeUIVerifyAtomic(name, func(writer io.Writer) error {
		_, err := writer.Write(body)
		return err
	})
}

func writeUIVerifyAtomic(name string, write func(io.Writer) error) error {
	temporary, err := os.CreateTemp(filepath.Dir(name), ".ui-verify-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	defer temporary.Close()
	if err = temporary.Chmod(0600); err != nil {
		return err
	}
	if err = write(temporary); err != nil {
		return err
	}
	if err = temporary.Sync(); err != nil {
		return err
	}
	if err = temporary.Close(); err != nil {
		return err
	}
	if err = os.Rename(temporaryName, name); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(name))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func waitUIVerifySettle(ctx context.Context, out io.Writer, duration time.Duration) error {
	if duration == 0 {
		return nil
	}
	fmt.Fprintf(out, "Waiting for UI response after pointer input (limit %s)\n", duration)
	var stop func()
	if duration > 5*time.Second {
		stop = heartbeat(out, "UI verify post-tap settle", duration)
		defer stop()
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
