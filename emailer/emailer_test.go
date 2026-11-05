package emailer

import (
	"testing"

	mail "github.com/xhit/go-simple-mail/v2"
)

func TestAuthTypeMapping(t *testing.T) {
	tests := []struct {
		in   string
		want mail.AuthType
	}{
		{"PLAIN", mail.AuthPlain},
		{"plain", mail.AuthPlain},
		{"Plain", mail.AuthPlain},
		{"LOGIN", mail.AuthLogin},
		{"login", mail.AuthLogin},
		{"", mail.AuthNone},
		{"bogus", mail.AuthNone},
	}
	for _, tt := range tests {
		if got := authType(tt.in); got != tt.want {
			t.Errorf("authType(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestEncryptionTypeMapping(t *testing.T) {
	tests := []struct {
		in   string
		want mail.Encryption
	}{
		{"NONE", mail.EncryptionNone},
		{"none", mail.EncryptionNone},
		{"SSL", mail.EncryptionSSL},
		{"ssl", mail.EncryptionSSL},
		{"SSLTLS", mail.EncryptionSSLTLS},
		{"ssltls", mail.EncryptionSSLTLS},
		{"TLS", mail.EncryptionTLS},
		{"tls", mail.EncryptionTLS},
		{"", mail.EncryptionSTARTTLS},        // default
		{"garbage", mail.EncryptionSTARTTLS}, // default
	}
	for _, tt := range tests {
		if got := encryptionType(tt.in); got != tt.want {
			t.Errorf("encryptionType(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestAddressField(t *testing.T) {
	if got := addressField("a@b.c", ""); got != "a@b.c" {
		t.Errorf("addressField without name = %q", got)
	}
	if got := addressField("a@b.c", "Alice"); got != "Alice <a@b.c>" {
		t.Errorf("addressField with name = %q", got)
	}
}

func TestConstructorsSatisfyInterface(t *testing.T) {
	var e Emailer = NewSmtpMail("localhost", 25, "u", "p", false, "PLAIN", "n", "f@x.io", "TLS")
	if e == nil {
		t.Fatal("NewSmtpMail returned nil")
	}
	var e2 Emailer = NewSendgridApiMail("key", "from", "from@x.io")
	if e2 == nil {
		t.Fatal("NewSendgridApiMail returned nil")
	}
}

// TestSmtpSendConnectFailure documents that Send surfaces connection errors
// instead of panicking when no SMTP server is reachable. Port 1 on localhost
// is reliably refused (no external network involved).
func TestSmtpSendConnectFailure(t *testing.T) {
	m := NewSmtpMail("127.0.0.1", 1, "", "", false, "NONE", "n", "f@x.io", "NONE")
	err := m.Send("to", "to@x.io", "subj", "body", nil)
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
}
