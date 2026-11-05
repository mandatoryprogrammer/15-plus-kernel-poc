package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func completeTrustRow(version uint32, value byte) []byte {
	row, _, err := trustCacheRow(version, bytes.Repeat([]byte{value}, 20))
	if err != nil {
		panic(err)
	}
	return row
}

func trustImageWithRows(kind string, version uint32, rows ...[]byte) []byte {
	payload := make([]byte, 24)
	binary.LittleEndian.PutUint32(payload, version)
	copy(payload[4:20], bytes.Repeat([]byte{0x55}, 16))
	binary.LittleEndian.PutUint32(payload[20:24], uint32(len(rows)))
	for _, row := range rows {
		payload = append(payload, row...)
	}
	body := bytes.Join([][]byte{
		encodeDER(0x16, []byte("IM4P")), encodeDER(0x16, []byte(kind)),
		encodeDER(0x16, []byte("1")), encodeDER(4, payload),
	}, nil)
	return encodeDER(0x30, body)
}

func wrapTrustForImport(t *testing.T, im4p []byte) []byte {
	t.Helper()
	manifest := encodeDER(0x30, encodeDER(0x16, []byte("IM4M")))
	wrapper, err := wrapImage(im4p, manifest)
	if err != nil {
		t.Fatal(err)
	}
	return wrapper
}

func TestSystemTrustMergeUsesCompleteSortedTable(t *testing.T) {
	base := trustImageWithRows("rtsc", 2, completeTrustRow(2, 0x10), completeTrustRow(2, 0x30))
	system := trustImageWithRows("trst", 2, completeTrustRow(2, 0x20), completeTrustRow(2, 0x30))
	merged, count, err := mergeSystemTrustCache(base, system)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseTrustCacheImage(merged, "rtsc")
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 || len(parsed.rows) != 3 || parsed.rows[0][0] != 0x10 || parsed.rows[1][0] != 0x20 || parsed.rows[2][0] != 0x30 {
		t.Fatalf("merged rows changed: count=%d rows=%x", count, parsed.rows)
	}
	baseParsed, _ := parseTrustCacheImage(base, "rtsc")
	if !bytes.Equal(parsed.header[:20], baseParsed.header[:20]) {
		t.Fatal("base restore trust-cache header identity changed")
	}
}

func TestSystemTrustMergePromotesCompleteV1RowsToV2(t *testing.T) {
	base := trustImageWithRows("rtsc", 1, completeTrustRow(1, 0x10), completeTrustRow(1, 0x30))
	system := trustImageWithRows("trst", 2, completeTrustRow(2, 0x20))
	merged, count, err := mergeSystemTrustCache(base, system)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseTrustCacheImage(merged, "rtsc")
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 || parsed.version != 2 || parsed.rowSize != 24 || parsed.rows[0][20] != 2 || parsed.rows[0][21] != 0 || parsed.rows[0][22] != 0 || parsed.rows[0][23] != 0 {
		t.Fatalf("v1 row promotion changed: count=%d parsed=%+v first=%x", count, parsed, parsed.rows[0])
	}
}

func TestSystemTrustMergeFailsClosed(t *testing.T) {
	base := trustImageWithRows("rtsc", 2, completeTrustRow(2, 0x10), completeTrustRow(2, 0x30))
	t.Run("wrong-type", func(t *testing.T) {
		if _, _, err := mergeSystemTrustCache(base, trustImageWithRows("rtsc", 2, completeTrustRow(2, 0x20))); err == nil {
			t.Fatal("restore trust cache accepted as a system static context")
		}
	})
	t.Run("version-mismatch", func(t *testing.T) {
		if _, _, err := mergeSystemTrustCache(base, trustImageWithRows("trst", 1, completeTrustRow(1, 0x20))); err == nil {
			t.Fatal("mismatched trust-cache version accepted")
		}
	})
	t.Run("unsorted", func(t *testing.T) {
		bad := trustImageWithRows("trst", 2, completeTrustRow(2, 0x30), completeTrustRow(2, 0x20))
		if _, _, err := mergeSystemTrustCache(base, bad); err == nil {
			t.Fatal("unsorted system table accepted")
		}
	})
	t.Run("metadata-conflict", func(t *testing.T) {
		conflict := completeTrustRow(2, 0x10)
		conflict[len(conflict)-1] = 1
		if _, _, err := mergeSystemTrustCache(base, trustImageWithRows("trst", 2, conflict)); err == nil {
			t.Fatal("conflicting row metadata accepted")
		}
	})
	t.Run("count-mismatch", func(t *testing.T) {
		bad := trustImageWithRows("trst", 2, completeTrustRow(2, 0x20))
		fields, _ := imageFields(bad, "IM4P")
		payload := bytes.Clone(fields[3].body)
		binary.LittleEndian.PutUint32(payload[20:24], 2)
		bad, _ = replacePayload(bad, "trst", payload)
		if _, _, err := mergeSystemTrustCache(base, bad); err == nil {
			t.Fatal("malformed system table count accepted")
		}
	})
}

func TestSystemTrustImportChangesOnlyContextFingerprint(t *testing.T) {
	root := t.TempDir()
	c, err := newCache(root)
	if err != nil {
		t.Fatal(err)
	}
	c.out = io.Discard
	before, err := payloadAdmissionFingerprint(c)
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "StaticTrustCache.img4")
	wrapper := wrapTrustForImport(t, trustImageWithRows("trst", 2, completeTrustRow(2, 0x20)))
	if err = os.WriteFile(input, wrapper, 0600); err != nil {
		t.Fatal(err)
	}
	if err = importSystemTrustContext(context.Background(), c, []string{input}); err != nil {
		t.Fatal(err)
	}
	value, im4p, err := loadSystemTrustContext(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if value == nil || value.Object.SHA256 != digest(wrapper) || value.EntryCount != 1 || value.Version != 2 || len(im4p) == 0 {
		t.Fatalf("imported context changed: value=%+v im4p=%d", value, len(im4p))
	}
	after, err := payloadAdmissionFingerprint(c)
	if err != nil || after == before {
		t.Fatalf("system trust did not change admission fingerprint: before=%s after=%s err=%v", before, after, err)
	}
	if err = clearSystemTrustContext(c); err != nil {
		t.Fatal(err)
	}
	cleared, err := payloadAdmissionFingerprint(c)
	if err != nil || cleared != before {
		t.Fatalf("clear did not restore admission fingerprint: before=%s cleared=%s err=%v", before, cleared, err)
	}
}

func TestSystemTrustImportRejectsUnwrappedInput(t *testing.T) {
	root := t.TempDir()
	c, err := newCache(root)
	if err != nil {
		t.Fatal(err)
	}
	c.out = io.Discard
	input := filepath.Join(root, "not-an-img4")
	if err = os.WriteFile(input, trustImageWithRows("trst", 2, completeTrustRow(2, 0x20)), 0600); err != nil {
		t.Fatal(err)
	}
	if err = importSystemTrustContext(context.Background(), c, []string{input}); err == nil {
		t.Fatal("unwrapped IM4P accepted as a complete system trust context")
	}
}
