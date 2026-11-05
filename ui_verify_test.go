package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeUIVerifySession struct {
	width, height uint16
	desktop       string
	frames        []*image.RGBA
	captureError  error
	captures      int
	taps          [][2]uint16
	closed        int
}

func (s *fakeUIVerifySession) dimensions() (uint16, uint16, string) {
	return s.width, s.height, s.desktop
}

func (s *fakeUIVerifySession) capture(context.Context) (*image.RGBA, rfbFrameStats, error) {
	s.captures++
	if s.captureError != nil {
		return nil, rfbFrameStats{}, s.captureError
	}
	if len(s.frames) == 0 {
		return nil, rfbFrameStats{}, errors.New("no fake frame")
	}
	frame := s.frames[0]
	s.frames = s.frames[1:]
	return frame, rfbFrameStats{}, nil
}

func (s *fakeUIVerifySession) tap(_ context.Context, x, y uint16) error {
	s.taps = append(s.taps, [2]uint16{x, y})
	return nil
}

func (s *fakeUIVerifySession) close() error {
	s.closed++
	return nil
}

func uiVerifyTestFrame(width, height int, pixel color.RGBA) *image.RGBA {
	frame := image.NewRGBA(image.Rect(0, 0, width, height))
	frame.SetRGBA(0, 0, pixel)
	return frame
}

func uiVerifyTestCache(t *testing.T) (*cache, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	return &cache{root: t.TempDir(), out: out}, out
}

func uiVerifyTestDependencies(session uiVerifySession) uiVerifyDependencies {
	return uiVerifyDependencies{
		connect: func(context.Context, *cache) (uiVerifySession, error) { return session, nil },
		settle:  func(context.Context, io.Writer, time.Duration) error { return nil },
		now:     func() time.Time { return time.Date(2026, 11, 5, 7, 0, 0, 0, time.UTC) },
	}
}

func readUIVerifyReport(t *testing.T, name string) uiVerifyReport {
	t.Helper()
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var report uiVerifyReport
	if err = json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	return report
}

func TestUIVerifyRejectsBlackFrame(t *testing.T) {
	c, _ := uiVerifyTestCache(t)
	session := &fakeUIVerifySession{width: 2, height: 1, desktop: "black", frames: []*image.RGBA{image.NewRGBA(image.Rect(0, 0, 2, 1))}}
	reportPath, err := verifyUI(context.Background(), c, uiVerifyOptions{X: -1, Y: -1}, uiVerifyTestDependencies(session))
	if err == nil || !strings.Contains(err.Error(), "validate-before") {
		t.Fatalf("error=%v", err)
	}
	report := readUIVerifyReport(t, reportPath)
	if report.Status != "failed" || report.Stage != "validate-before" || !strings.Contains(report.Error, "completely black") {
		t.Fatalf("report=%+v", report)
	}
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(reportPath), "before.png")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("black frame was published: %v", statErr)
	}
	if session.captures != 1 || session.closed != 1 {
		t.Fatalf("captures=%d closed=%d", session.captures, session.closed)
	}
}

func TestUIVerifyRejectsUnchangedFrame(t *testing.T) {
	c, _ := uiVerifyTestCache(t)
	frame := uiVerifyTestFrame(2, 1, color.RGBA{R: 1, A: 255})
	session := &fakeUIVerifySession{width: 2, height: 1, desktop: "same", frames: []*image.RGBA{frame, frame}}
	reportPath, err := verifyUI(context.Background(), c, uiVerifyOptions{X: -1, Y: -1}, uiVerifyTestDependencies(session))
	if err == nil || !strings.Contains(err.Error(), "validate-after") || !strings.Contains(err.Error(), "did not change") {
		t.Fatalf("error=%v", err)
	}
	report := readUIVerifyReport(t, reportPath)
	if report.Status != "failed" || report.Stage != "validate-after" || report.Before == nil || report.After != nil {
		t.Fatalf("report=%+v", report)
	}
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(reportPath), "before.png")); statErr != nil {
		t.Fatal(statErr)
	}
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(reportPath), "after.png")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("unchanged after frame was published: %v", statErr)
	}
}

func TestUIVerifyRejectsGeometryAndCaptureErrorsWithStages(t *testing.T) {
	t.Run("geometry", func(t *testing.T) {
		c, _ := uiVerifyTestCache(t)
		session := &fakeUIVerifySession{}
		reportPath, err := verifyUI(context.Background(), c, uiVerifyOptions{X: -1, Y: -1}, uiVerifyTestDependencies(session))
		if err == nil || !strings.Contains(err.Error(), "geometry") {
			t.Fatalf("error=%v", err)
		}
		if report := readUIVerifyReport(t, reportPath); report.Stage != "geometry" || report.Status != "failed" {
			t.Fatalf("report=%+v", report)
		}
		if session.captures != 0 {
			t.Fatalf("capture called %d times", session.captures)
		}
	})
	t.Run("capture", func(t *testing.T) {
		c, _ := uiVerifyTestCache(t)
		session := &fakeUIVerifySession{width: 1, height: 1, captureError: errors.New("wire broke")}
		reportPath, err := verifyUI(context.Background(), c, uiVerifyOptions{X: -1, Y: -1}, uiVerifyTestDependencies(session))
		if err == nil || !strings.Contains(err.Error(), "capture-before") {
			t.Fatalf("error=%v", err)
		}
		if report := readUIVerifyReport(t, reportPath); report.Stage != "capture-before" || !strings.Contains(report.Error, "wire broke") {
			t.Fatalf("report=%+v", report)
		}
	})
}

func TestUIVerifyPublishesChangedFramesWithoutClobberingPriorRun(t *testing.T) {
	c, out := uiVerifyTestCache(t)
	options := uiVerifyOptions{X: 1, Y: 0, Settle: 7 * time.Millisecond}
	newSession := func() *fakeUIVerifySession {
		return &fakeUIVerifySession{
			width: 2, height: 1, desktop: "ProductOS",
			frames: []*image.RGBA{
				uiVerifyTestFrame(2, 1, color.RGBA{R: 255, A: 255}),
				uiVerifyTestFrame(2, 1, color.RGBA{B: 255, A: 255}),
			},
		}
	}
	firstSession := newSession()
	firstDependencies := uiVerifyTestDependencies(firstSession)
	var settled time.Duration
	firstDependencies.settle = func(_ context.Context, _ io.Writer, duration time.Duration) error {
		settled = duration
		return nil
	}
	firstPath, err := verifyUI(context.Background(), c, options, firstDependencies)
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	first := readUIVerifyReport(t, firstPath)
	if first.Status != "passed" || first.Stage != "complete" || first.Before == nil || first.After == nil || first.Before.RGBA256 == first.After.RGBA256 {
		t.Fatalf("report=%+v", first)
	}
	if settled != options.Settle || len(firstSession.taps) != 1 || firstSession.taps[0] != [2]uint16{1, 0} {
		t.Fatalf("settled=%s taps=%v", settled, firstSession.taps)
	}
	for _, name := range []string{"before.png", "after.png"} {
		info, statErr := os.Stat(filepath.Join(filepath.Dir(firstPath), name))
		if statErr != nil || info.Size() == 0 || info.Mode().Perm() != 0600 {
			t.Fatalf("%s info=%v err=%v", name, info, statErr)
		}
	}

	secondSession := newSession()
	secondPath, err := verifyUI(context.Background(), c, options, uiVerifyTestDependencies(secondSession))
	if err != nil {
		t.Fatal(err)
	}
	if secondPath == firstPath || filepath.Dir(secondPath) == filepath.Dir(firstPath) {
		t.Fatalf("runs reused artifacts: first=%s second=%s", firstPath, secondPath)
	}
	afterFirst, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, afterFirst) {
		t.Fatal("second run clobbered first report")
	}
	if !strings.Contains(out.String(), "UI verified:") {
		t.Fatalf("output=%q", out.String())
	}
}

func TestParseUIVerifyOptions(t *testing.T) {
	options, err := parseUIVerifyOptions([]string{"--x", "12", "--y", "34", "--settle", "2s"})
	if err != nil || options.X != 12 || options.Y != 34 || options.Settle != 2*time.Second {
		t.Fatalf("options=%+v err=%v", options, err)
	}
	for _, args := range [][]string{{"--x", "1"}, {"--settle", "31s"}, {"extra"}} {
		if _, err = parseUIVerifyOptions(args); err == nil {
			t.Fatalf("accepted %q", args)
		}
	}
}

func TestUIVerifyRetentionDeletesOnlyOldOwnedRuns(t *testing.T) {
	parent := t.TempDir()
	now := time.Now()
	for index := 0; index < uiVerifyRetainedRuns+3; index++ {
		name := filepath.Join(parent, fmt.Sprintf("run-%02d", index))
		if err := os.Mkdir(name, 0700); err != nil {
			t.Fatal(err)
		}
		stamp := now.Add(-time.Duration(index) * time.Hour)
		if err := os.Chtimes(name, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	protected := filepath.Join(parent, "not-a-run.txt")
	if err := os.WriteFile(protected, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := pruneUIVerifyRuns(parent, now); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	directories := 0
	for _, entry := range entries {
		if entry.IsDir() {
			directories++
		}
	}
	if directories != uiVerifyRetainedRuns-1 {
		t.Fatalf("retained %d directories, want %d", directories, uiVerifyRetainedRuns-1)
	}
	if body, err := os.ReadFile(protected); err != nil || string(body) != "keep" {
		t.Fatalf("non-run file changed: %q %v", body, err)
	}
}
