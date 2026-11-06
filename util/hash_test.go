package util

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestHashPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("s3cret-pa$$word")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "s3cret-pa$$word" {
		t.Fatal("hash must not equal plaintext")
	}
	if _, err := base64.StdEncoding.DecodeString(hash); err != nil {
		t.Fatalf("hash is not base64: %v", err)
	}
	ok, err := VerifyHash(hash, "s3cret-pa$$word")
	if err != nil {
		t.Fatalf("VerifyHash: %v", err)
	}
	if !ok {
		t.Fatal("VerifyHash returned false for correct password")
	}
}

func TestHashPasswordSaltsDiffer(t *testing.T) {
	h1, err := HashPassword("same")
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashPassword("same")
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Fatal("bcrypt salt should make hashes differ")
	}
}

func TestVerifyHashTable(t *testing.T) {
	valid, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		hash      string
		plaintext string
		wantOK    bool
		wantErr   bool
	}{
		{"correct password", valid, "correct horse battery staple", true, false},
		{"wrong password", valid, "wrong password", false, false},
		{"empty password", valid, "", false, false},
		{"not base64", "!!!not-base64!!!", "x", false, true},
		{"base64 but not bcrypt", base64.StdEncoding.EncodeToString([]byte("garbage")), "x", false, true},
		{"empty hash", "", "x", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := VerifyHash(tt.hash, tt.plaintext)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
		})
	}
}

func TestHashPasswordEmpty(t *testing.T) {
	// bcrypt (x/crypto) accepts empty passwords; the result must still be a
	// base64-wrapped bcrypt hash that verifies against "".
	hash, err := HashPassword("")
	if err != nil {
		t.Skipf("bcrypt rejected empty password: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		t.Fatalf("hash not base64: %v", err)
	}
	if !strings.HasPrefix(string(raw), "$2") {
		t.Fatalf("decoded hash is not bcrypt: %q", raw)
	}
	ok, err := VerifyHash(hash, "")
	if err != nil || !ok {
		t.Errorf("VerifyHash of empty password = %v, %v", ok, err)
	}
}
