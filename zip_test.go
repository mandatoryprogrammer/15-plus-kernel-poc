package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFirmwareMemberFetchAndRangeValidation(t *testing.T) {
	var archive bytes.Buffer
	w := zip.NewWriter(&archive)
	f, _ := w.Create("Firmware/item")
	f.Write([]byte("verified firmware"))
	w.Close()
	for _, valid := range []bool{true, false} {
		t.Run(fmt.Sprint(valid), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var begin, end int64
				if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &begin, &end); err != nil {
					t.Error(err)
					return
				}
				if !valid {
					w.WriteHeader(200)
					w.Write(archive.Bytes())
					return
				}
				w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", begin, end, archive.Len()))
				w.Header().Set("Content-Length", fmt.Sprint(end-begin+1))
				w.WriteHeader(206)
				w.Write(archive.Bytes()[begin : end+1])
			}))
			defer server.Close()
			c := testCache(t)
			c.client = server.Client()
			a := testAsset([]byte("verified firmware"))
			a.URL = server.URL
			a.Member = "Firmware/item"
			a.ArchiveSize = int64(archive.Len())
			_, err := c.resolve(t.Context(), a)
			if (err == nil) != valid {
				t.Fatalf("valid=%t: %v", valid, err)
			}
		})
	}
}

func TestMemberPaths(t *testing.T) {
	for _, s := range []string{"../x", "/tmp/x", "a/../x", "a\\b", "..", ""} {
		if safeMember(s) {
			t.Errorf("accepted %q", s)
		}
	}
	if !safeMember("Firmware/a.im4p") {
		t.Fatal("valid member rejected")
	}
}
