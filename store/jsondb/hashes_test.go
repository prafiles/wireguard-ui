package jsondb

import (
	"testing"

	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/ngoduykhanh/wireguard-ui/util"
)

// TestHashesRoundTrip exercises util.GetCurrentHash/HashesChanged/UpdateHashes
// against a real scribble-backed store in a temp dir.
func TestHashesRoundTrip(t *testing.T) {
	db := newTestStore(t)

	// fresh store: stored hashes are "none", so they must differ from computed
	if util.HashesChanged(db) == false {
		t.Fatal("HashesChanged should be true before first UpdateHashes")
	}
	if err := util.UpdateHashes(db); err != nil {
		t.Fatal(err)
	}
	if util.HashesChanged(db) {
		t.Fatal("HashesChanged should be false right after UpdateHashes")
	}

	// adding a client changes the client hash
	if err := db.SaveClient(model.Client{ID: "h1", Name: "hashme"}); err != nil {
		t.Fatal(err)
	}
	if !util.HashesChanged(db) {
		t.Fatal("HashesChanged should be true after saving a client")
	}

	client, server := util.GetCurrentHash(db)
	if client == "" || server == "" {
		t.Fatalf("GetCurrentHash returned empty values: %q %q", client, server)
	}
}
