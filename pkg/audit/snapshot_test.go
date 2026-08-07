package audit

import (
	"testing"
	"time"
)

func TestKVSnapshotRoundTrip(t *testing.T) {
	s, err := OpenSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, ok, _ := s.LoadSnapshot("cases"); ok {
		t.Fatal("empty store should have no snapshot")
	}
	if err := s.SaveSnapshot("cases", []byte(`[{"id":"c1"}]`), time.Now()); err != nil {
		t.Fatal(err)
	}
	data, ok, err := s.LoadSnapshot("cases")
	if err != nil || !ok || string(data) != `[{"id":"c1"}]` {
		t.Fatalf("roundtrip failed ok=%v data=%s err=%v", ok, data, err)
	}
	// upsert overwrites
	s.SaveSnapshot("cases", []byte(`[{"id":"c2"}]`), time.Now())
	data, _, _ = s.LoadSnapshot("cases")
	if string(data) != `[{"id":"c2"}]` {
		t.Errorf("upsert failed: %s", data)
	}
}
