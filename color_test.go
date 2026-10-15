package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestProgressColorsPreserveTextAndLineState(t *testing.T) {
	var output bytes.Buffer
	w := &colorWriter{out: &output, enabled: true, lineStart: true}
	fmt.Fprint(w, "Waiting for kernel")
	fmt.Fprint(w, " (limit 1m)\n")
	fmt.Fprintln(w, "verified root ready after 2s")
	fmt.Fprintln(w, "error: failed")
	got := output.String()
	if !strings.Contains(got, ansiCyan+"Waiting for kernel (limit 1m)\n"+ansiReset) ||
		!strings.Contains(got, ansiGreen+"verified root ready after 2s\n"+ansiReset) ||
		!strings.Contains(got, ansiRed+"error: failed\n"+ansiReset) {
		t.Fatalf("unexpected colored output %q", got)
	}
	plain := strings.NewReplacer(ansiCyan, "", ansiGreen, "", ansiRed, "", ansiReset, "").Replace(got)
	if plain != "Waiting for kernel (limit 1m)\nverified root ready after 2s\nerror: failed\n" {
		t.Fatalf("colors changed text: %q", plain)
	}
}

func TestProgressColorsCanBeDisabled(t *testing.T) {
	var output bytes.Buffer
	w := &colorWriter{out: &output, enabled: false, lineStart: true}
	fmt.Fprintln(w, "Waiting for kernel")
	if got := output.String(); got != "Waiting for kernel\n" {
		t.Fatalf("disabled color writer changed output: %q", got)
	}
}
