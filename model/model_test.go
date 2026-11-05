package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestWakeOnLanHostResolveResourceName(t *testing.T) {
	tests := []struct {
		name    string
		mac     string
		want    string
		wantErr bool
	}{
		{"already upper with dashes", "AA-BB-CC-DD-EE-FF", "AA-BB-CC-DD-EE-FF", false},
		{"lower with colons uppercased and replaced", "aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", false},
		{"mixed separators", "aA:bB:Cc:dD:eE:fF", "AA-BB-CC-DD-EE-FF", false},
		{"surrounding whitespace trimmed", "  aa:bb:cc:dd:ee:ff\t\r\n", "AA-BB-CC-DD-EE-FF", false},
		{"NUL padding trimmed", "\x00aa-bb-cc-dd-ee-ff\x00", "AA-BB-CC-DD-EE-FF", false},
		{"empty", "", "", true},
		{"whitespace only", "   ", "", true},
		{"NUL only", "\x00", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := WakeOnLanHost{MacAddress: tt.mac}
			got, err := host.ResolveResourceName()
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ResolveResourceName(%q) = %q, want %q", tt.mac, got, tt.want)
			}
			// resource names become file names in the jsondb store: they must
			// never contain path separators.
			if strings.ContainsAny(got, "/\\") {
				t.Errorf("resource name %q contains a path separator", got)
			}
		})
	}
}

func TestServerInterfaceJSONListenPortString(t *testing.T) {
	// listen_port is tagged ,string: JSON must carry it as a string.
	raw := `{"addresses":["10.252.1.0/24"],"listen_port":"51820","post_up":"up.sh","post_down":"down.sh"}`
	var si ServerInterface
	if err := json.Unmarshal([]byte(raw), &si); err != nil {
		t.Fatal(err)
	}
	if si.ListenPort != 51820 {
		t.Errorf("ListenPort = %d, want 51820", si.ListenPort)
	}
	out, err := json.Marshal(si)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"listen_port":"51820"`) {
		t.Errorf("marshalled JSON should quote listen_port: %s", out)
	}
}

func TestGlobalSettingJSONRoundTrip(t *testing.T) {
	in := GlobalSetting{
		EndpointAddress:     "demo.example.com",
		DNSServers:          []string{"1.1.1.1"},
		MTU:                 1450,
		PersistentKeepalive: 15,
		FirewallMark:        "0xca6c",
		Table:               "auto",
		ConfigFilePath:      "/etc/wireguard/wg0.conf",
		UpdatedAt:           time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	// MTU / PersistentKeepalive are tagged ,string too
	if !strings.Contains(string(b), `"mtu":"1450"`) || !strings.Contains(string(b), `"persistent_keepalive":"15"`) {
		t.Errorf("expected string-encoded numeric fields, got %s", b)
	}
	var out GlobalSetting
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.MTU != in.MTU || out.PersistentKeepalive != in.PersistentKeepalive ||
		out.EndpointAddress != in.EndpointAddress || out.FirewallMark != in.FirewallMark {
		t.Errorf("round trip mismatch: %+v vs %+v", out, in)
	}
}

func TestClientJSONRoundTrip(t *testing.T) {
	now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	in := Client{
		ID: "id1", PrivateKey: "pk", PublicKey: "pub", PresharedKey: "psk",
		Name: "phone", Email: "a@b.c",
		AllocatedIPs: []string{"10.0.0.2/32"}, AllowedIPs: []string{"0.0.0.0/0"},
		ExtraAllowedIPs: []string{""}, UseServerDNS: true, Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Client
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.ID != in.ID || out.Name != in.Name || !out.Enabled || !out.UseServerDNS ||
		len(out.AllocatedIPs) != 1 || out.AllocatedIPs[0] != "10.0.0.2/32" ||
		!out.CreatedAt.Equal(in.CreatedAt) {
		t.Errorf("client round trip mismatch: %+v vs %+v", out, in)
	}
}
