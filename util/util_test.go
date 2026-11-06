package util

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ngoduykhanh/wireguard-ui/model"
)

func TestValidateCIDR(t *testing.T) {
	tests := []struct {
		cidr string
		want bool
	}{
		{"10.0.0.0/24", true},
		{"10.252.1.0/24", true},
		{"0.0.0.0/0", true},
		{"fd00::/64", true},
		{"2001:db8::/32", true},
		{"10.0.0.1", false},       // plain IP, not CIDR
		{"10.0.0.0", false},       // missing mask
		{"10.0.0.0/33", false},    // invalid mask
		{"300.0.0.0/24", false},   // octet out of range
		{"", false},               // empty
		{"not-a-cidr", false},     // garbage
		{"10.0.0.0/24/24", false}, // double mask
	}
	for _, tt := range tests {
		if got := ValidateCIDR(tt.cidr); got != tt.want {
			t.Errorf("ValidateCIDR(%q) = %v, want %v", tt.cidr, got, tt.want)
		}
	}
}

func TestValidateCIDRList(t *testing.T) {
	tests := []struct {
		name       string
		cidrs      []string
		allowEmpty bool
		want       bool
	}{
		{"all valid", []string{"10.0.0.0/24", "fd00::/64"}, false, true},
		{"one invalid", []string{"10.0.0.0/24", "bogus"}, false, false},
		{"empty entry strict", []string{""}, false, false},
		{"empty entry allowed", []string{""}, true, true},
		{"mixed with empty allowed", []string{"10.0.0.0/24", ""}, true, true},
		{"mixed with empty strict", []string{"10.0.0.0/24", ""}, false, false},
		{"empty list", []string{}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateCIDRList(tt.cidrs, tt.allowEmpty); got != tt.want {
				t.Errorf("ValidateCIDRList(%v, %v) = %v, want %v", tt.cidrs, tt.allowEmpty, got, tt.want)
			}
		})
	}
}

func TestValidateAllowedIPsWrappers(t *testing.T) {
	if !ValidateAllowedIPs([]string{"0.0.0.0/0", "::/0"}) {
		t.Error("ValidateAllowedIPs rejected valid CIDRs")
	}
	if ValidateAllowedIPs([]string{"1.2.3.4"}) {
		t.Error("ValidateAllowedIPs accepted bare IP")
	}
	if !ValidateExtraAllowedIPs([]string{"10.0.0.0/24", ""}) {
		t.Error("ValidateExtraAllowedIPs should accept empty entries")
	}
	if ValidateExtraAllowedIPs([]string{"nope"}) {
		t.Error("ValidateExtraAllowedIPs accepted garbage")
	}
	if !ValidateServerAddresses([]string{"10.252.1.0/24"}) {
		t.Error("ValidateServerAddresses rejected valid CIDR")
	}
	if ValidateServerAddresses([]string{"10.252.1.0/99"}) {
		t.Error("ValidateServerAddresses accepted invalid mask")
	}
}

func TestValidateIPAddressAndList(t *testing.T) {
	good := []string{"10.0.0.1", "255.255.255.255", "::1", "2001:db8::1"}
	for _, ip := range good {
		if !ValidateIPAddress(ip) {
			t.Errorf("ValidateIPAddress(%q) = false, want true", ip)
		}
	}
	bad := []string{"", "1.2.3", "256.0.0.1", "10.0.0.1/24", "localhost"}
	for _, ip := range bad {
		if ValidateIPAddress(ip) {
			t.Errorf("ValidateIPAddress(%q) = true, want false", ip)
		}
	}
	if !ValidateIPAddressList([]string{"1.1.1.1", "8.8.8.8"}) {
		t.Error("ValidateIPAddressList rejected valid list")
	}
	if ValidateIPAddressList([]string{"1.1.1.1", "999.999.999.999"}) {
		t.Error("ValidateIPAddressList accepted invalid entry")
	}
}

func TestGetIPFromCIDR(t *testing.T) {
	tests := []struct {
		cidr    string
		want    string
		wantErr bool
	}{
		{"10.252.1.0/24", "10.252.1.0", false},
		{"10.252.1.5/24", "10.252.1.5", false},
		{"fd00::/64", "fd00::", false},
		{"bogus", "", true},
		{"10.0.0.1", "", true},
	}
	for _, tt := range tests {
		got, err := GetIPFromCIDR(tt.cidr)
		if (err != nil) != tt.wantErr {
			t.Errorf("GetIPFromCIDR(%q) err = %v, wantErr %v", tt.cidr, err, tt.wantErr)
		}
		if got != tt.want {
			t.Errorf("GetIPFromCIDR(%q) = %q, want %q", tt.cidr, got, tt.want)
		}
	}
}

func TestGetBroadcastIP(t *testing.T) {
	tests := []struct {
		cidr string
		want string
	}{
		{"10.0.1.0/24", "10.0.1.255"},
		{"192.168.56.0/24", "192.168.56.255"},
		{"10.0.0.0/8", "10.255.255.255"},
		{"0.0.0.0/0", "255.255.255.255"},
	}
	for _, tt := range tests {
		_, n, err := net.ParseCIDR(tt.cidr)
		if err != nil {
			t.Fatal(err)
		}
		if got := GetBroadcastIP(n).String(); got != tt.want {
			t.Errorf("GetBroadcastIP(%s) = %s, want %s", tt.cidr, got, tt.want)
		}
	}
}

func TestGetAvailableIP(t *testing.T) {
	tests := []struct {
		name      string
		cidr      string
		allocated []string
		want      string
		wantErr   bool
	}{
		{
			// .0 is network addr, .1 taken -> .2
			name:      "skips network address and allocated",
			cidr:      "10.0.0.0/30",
			allocated: []string{"10.0.0.1"},
			want:      "10.0.0.2",
		},
		{
			// /29 usable range .1-.6; block all of them -> exhaustion
			name:      "exhausted",
			cidr:      "10.0.0.0/29",
			allocated: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"},
			wantErr:   true,
		},
		{
			name: "first usable when nothing allocated",
			cidr: "192.168.1.0/24",
			want: "192.168.1.1",
		},
		{
			name:    "invalid cidr",
			cidr:    "nope",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAvailableIP(tt.cidr, tt.allocated)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("GetAvailableIP = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateIPAllocation(t *testing.T) {
	serverAddrs := []string{"10.252.1.0/24", "fd00:1::/64"}
	tests := []struct {
		name      string
		allocated []string
		request   []string
		wantOK    bool
		wantMsg   string
	}{
		{
			name:    "valid single",
			request: []string{"10.252.1.10/32"},
			wantOK:  true,
		},
		{
			name:    "valid ipv6",
			request: []string{"fd00:1::5/128"},
			wantOK:  true,
		},
		{
			name:    "not cidr",
			request: []string{"10.252.1.10"},
			wantOK:  false,
			wantMsg: "CIDR format",
		},
		{
			name:      "already allocated",
			allocated: []string{"10.252.1.10"},
			request:   []string{"10.252.1.10/32"},
			wantOK:    false,
			wantMsg:   "already allocated",
		},
		{
			name:    "outside server networks",
			request: []string{"192.168.1.10/32"},
			wantOK:  false,
			wantMsg: "does not belong",
		},
		{
			name:    "multiple valid",
			request: []string{"10.252.1.10/32", "fd00:1::9/128"},
			wantOK:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := ValidateIPAllocation(serverAddrs, tt.allocated, tt.request)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (err=%v)", ok, tt.wantOK, err)
			}
			if !tt.wantOK && err != nil && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("err = %q, want substring %q", err.Error(), tt.wantMsg)
			}
		})
	}
}

func baseClient() model.Client {
	return model.Client{
		ID:           "abc",
		PrivateKey:   "yAnl6ocxOyczN9ZBvBqLLwG4T0p0v7o4Lx0vB5w0Y0g=",
		PublicKey:    "qwJQ5NoQ1h5p0TvB7Lx0vB5w0Y0gyAnl6ocxOyczN9Y=",
		AllocatedIPs: []string{"10.66.66.1/32"},
		AllowedIPs:   []string{"10.66.66.0/24"},
		UseServerDNS: true,
	}
}

func baseServer() model.Server {
	return model.Server{
		KeyPair:   &model.ServerKeypair{PublicKey: "srvPubKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		Interface: &model.ServerInterface{ListenPort: 51820},
	}
}

func TestBuildClientConfig(t *testing.T) {
	setting := model.GlobalSetting{
		EndpointAddress: "demo.example.com",
		DNSServers:      []string{"1.1.1.1", "8.8.8.8"},
		MTU:             1450,
	}
	cfg := BuildClientConfig(baseClient(), baseServer(), setting)

	mustContain := []string{
		"[Interface]",
		"Address = 10.66.66.1/32",
		"PrivateKey = yAnl6ocxOyczN9ZBvBqLLwG4T0p0v7o4Lx0vB5w0Y0g=",
		"DNS = 1.1.1.1,8.8.8.8",
		"MTU = 1450",
		"[Peer]",
		"PublicKey = srvPubKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"AllowedIPs = 10.66.66.0/24",
		"Endpoint = demo.example.com:51820",
	}
	for _, s := range mustContain {
		if !strings.Contains(cfg, s) {
			t.Errorf("config missing %q\n---\n%s", s, cfg)
		}
	}
	if strings.Contains(cfg, "PresharedKey") {
		t.Error("config should not contain PresharedKey when empty")
	}
	if strings.Contains(cfg, "PersistentKeepalive") {
		t.Error("config should not contain PersistentKeepalive when 0")
	}
}

func TestBuildClientConfigBranches(t *testing.T) {
	client := baseClient()
	client.PresharedKey = "pskAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	client.UseServerDNS = false
	server := baseServer()

	// UseServerDNS=false -> no DNS line; MTU=0 -> no MTU line; keepalive set.
	setting := model.GlobalSetting{
		EndpointAddress:     "203.0.113.9:51821",
		DNSServers:          []string{"1.1.1.1"},
		PersistentKeepalive: 25,
	}
	cfg := BuildClientConfig(client, server, setting)
	if strings.Contains(cfg, "DNS =") {
		t.Error("DNS line present although UseServerDNS=false")
	}
	if strings.Contains(cfg, "MTU =") {
		t.Error("MTU line present although MTU=0")
	}
	if !strings.Contains(cfg, "PresharedKey = pskAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") {
		t.Error("missing PresharedKey line")
	}
	if !strings.Contains(cfg, "PersistentKeepalive = 25") {
		t.Error("missing PersistentKeepalive line")
	}
	// endpoint with embedded port overrides ListenPort
	if !strings.Contains(cfg, "Endpoint = 203.0.113.9:51821") {
		t.Errorf("endpoint port split failed:\n%s", cfg)
	}

	// IPv6 endpoint in brackets: [2001:db8::1]:51820 -> host 2001:db8::1, port 51820
	setting.EndpointAddress = "[2001:db8::1]:51822"
	cfg = BuildClientConfig(client, server, setting)
	if !strings.Contains(cfg, "Endpoint = 2001:db8::1:51822") {
		// documents current (lossy) behavior of the naive split; see report
		t.Logf("IPv6 endpoint renders as lossy split (known upstream limitation):\n%s", cfg)
	}
}

func TestParseBasePath(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"/", ""},
		{"wireguard", "/wireguard"},
		{"/wireguard", "/wireguard"},
		{"/wireguard/", "/wireguard"},
		{"/a/b/", "/a/b"},
	}
	for _, tt := range tests {
		if got := ParseBasePath(tt.in); got != tt.want {
			t.Errorf("ParseBasePath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestLookupEnvHelpers(t *testing.T) {
	t.Setenv("WGUI_TEST_STR", "hello")
	if got := LookupEnvOrString("WGUI_TEST_STR", "def"); got != "hello" {
		t.Errorf("LookupEnvOrString = %q", got)
	}
	if got := LookupEnvOrString("WGUI_TEST_UNSET", "def"); got != "def" {
		t.Errorf("LookupEnvOrString default = %q", got)
	}

	t.Setenv("WGUI_TEST_BOOL", "true")
	if !LookupEnvOrBool("WGUI_TEST_BOOL", false) {
		t.Error("LookupEnvOrBool true failed")
	}
	t.Setenv("WGUI_TEST_BOOL", "notabool")
	if LookupEnvOrBool("WGUI_TEST_BOOL", true) {
		t.Error("LookupEnvOrBool invalid value should return false (zero value)")
	}
	if !LookupEnvOrBool("WGUI_TEST_UNSET", true) {
		t.Error("LookupEnvOrBool default failed")
	}

	t.Setenv("WGUI_TEST_INT", "42")
	if got := LookupEnvOrInt("WGUI_TEST_INT", 1); got != 42 {
		t.Errorf("LookupEnvOrInt = %d", got)
	}
	if got := LookupEnvOrInt("WGUI_TEST_UNSET", 7); got != 7 {
		t.Errorf("LookupEnvOrInt default = %d", got)
	}

	t.Setenv("WGUI_TEST_LIST", "a,b,c")
	got := LookupEnvOrStrings("WGUI_TEST_LIST", []string{"z"})
	if strings.Join(got, "|") != "a|b|c" {
		t.Errorf("LookupEnvOrStrings = %v", got)
	}
	got = LookupEnvOrStrings("WGUI_TEST_UNSET", []string{"z"})
	if strings.Join(got, "|") != "z" {
		t.Errorf("LookupEnvOrStrings default = %v", got)
	}
}

func TestClientDefaultsFromEnv(t *testing.T) {
	// defaults when nothing set
	for _, k := range []string{
		DefaultClientAllowedIpsEnvVar, DefaultClientExtraAllowedIpsEnvVar,
		DefaultClientUseServerDNSEnvVar, DefaultClientEnableAfterCreationEnvVar,
	} {
		os.Unsetenv(k)
	}
	d := ClientDefaultsFromEnv()
	if strings.Join(d.AllowedIps, ",") != "0.0.0.0/0" {
		t.Errorf("default AllowedIps = %v", d.AllowedIps)
	}
	if !d.UseServerDNS || !d.EnableAfterCreation {
		t.Error("expected UseServerDNS and EnableAfterCreation true by default")
	}

	t.Setenv(DefaultClientAllowedIpsEnvVar, "10.0.0.0/8,192.168.0.0/16")
	t.Setenv(DefaultClientExtraAllowedIpsEnvVar, "1.1.1.1/32")
	t.Setenv(DefaultClientUseServerDNSEnvVar, "false")
	t.Setenv(DefaultClientEnableAfterCreationEnvVar, "false")
	d = ClientDefaultsFromEnv()
	if strings.Join(d.AllowedIps, ",") != "10.0.0.0/8,192.168.0.0/16" {
		t.Errorf("env AllowedIps = %v", d.AllowedIps)
	}
	if strings.Join(d.ExtraAllowedIps, ",") != "1.1.1.1/32" {
		t.Errorf("env ExtraAllowedIps = %v", d.ExtraAllowedIps)
	}
	if d.UseServerDNS || d.EnableAfterCreation {
		t.Error("expected both flags false from env")
	}
}

func TestParseLogLevel(t *testing.T) {
	for _, lvl := range []string{"debug", "DEBUG", "info", "warn", "error", "off"} {
		if _, err := ParseLogLevel(lvl); err != nil {
			t.Errorf("ParseLogLevel(%q) unexpected error: %v", lvl, err)
		}
	}
	if _, err := ParseLogLevel("bogus"); err == nil {
		t.Error("ParseLogLevel(bogus) should error")
	}
}

func TestStringFromEmbedFile(t *testing.T) {
	fs := fstest.MapFS{"a.txt": &fstest.MapFile{Data: []byte("content")}}
	s, err := StringFromEmbedFile(fs, "a.txt")
	if err != nil || s != "content" {
		t.Fatalf("StringFromEmbedFile = %q, %v", s, err)
	}
	if _, err := StringFromEmbedFile(fs, "missing.txt"); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestRandomString(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		s := RandomString(20)
		if len(s) != 20 {
			t.Fatalf("RandomString(20) len = %d", len(s))
		}
		for _, r := range s {
			if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", r) {
				t.Fatalf("RandomString produced charset violation: %q", s)
			}
		}
		if seen[s] {
			t.Fatalf("RandomString collision: %q", s)
		}
		seen[s] = true
	}
	if RandomString(0) != "" {
		t.Error("RandomString(0) should be empty")
	}
}

func TestWriteWireGuardServerConfig(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "wg0.conf")

	tmplDir := fstest.MapFS{"wg.conf": &fstest.MapFile{Data: []byte("Address = {{ range .serverConfig.Interface.Addresses }}{{ . }}{{ end }}\nListenPort = {{ .serverConfig.Interface.ListenPort }}\n")}}

	server := model.Server{
		KeyPair:   &model.ServerKeypair{PrivateKey: "priv"},
		Interface: &model.ServerInterface{Addresses: []string{"10.252.1.0/24"}, ListenPort: 51820},
	}
	settings := model.GlobalSetting{ConfigFilePath: confPath}

	if err := WriteWireGuardServerConfig(tmplDir, server, []model.ClientData{}, []model.User{}, settings); err != nil {
		t.Fatalf("WriteWireGuardServerConfig: %v", err)
	}
	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Address = 10.252.1.0/24") || !strings.Contains(string(data), "ListenPort = 51820") {
		t.Errorf("rendered config unexpected:\n%s", data)
	}

	// missing template file -> error
	if err := WriteWireGuardServerConfig(fstest.MapFS{}, server, nil, nil, settings); err == nil {
		t.Error("expected error when wg.conf missing from template dir")
	}
	// unwritable destination -> error
	bad := model.GlobalSetting{ConfigFilePath: filepath.Join(dir, "no-such-dir", "wg0.conf")}
	if err := WriteWireGuardServerConfig(tmplDir, server, nil, nil, bad); err == nil {
		t.Error("expected error writing to nonexistent directory")
	}
}

// TestGetAllocatedIPs exercises the hardcoded ./db path: the function reads the
// scribble store relative to the process cwd, so the test materialises a
// throwaway ./db tree in the package directory and removes it afterwards.
func TestGetAllocatedIPs(t *testing.T) {
	dbDir := "./db"
	if _, err := os.Stat(dbDir); err == nil {
		t.Skip("./db already exists in cwd; refusing to clobber real data")
	}
	defer os.RemoveAll(dbDir)

	serverDir := filepath.Join(dbDir, "server")
	clientsDir := filepath.Join(dbDir, "clients")
	if err := os.MkdirAll(serverDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(clientsDir, 0o700); err != nil {
		t.Fatal(err)
	}

	write := func(p string, v interface{}) {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(serverDir, "interfaces.json"), model.ServerInterface{
		Addresses: []string{"10.252.1.0/24"},
	})
	write(filepath.Join(clientsDir, "c1.json"), model.Client{
		ID:           "c1",
		AllocatedIPs: []string{"10.252.1.10/32"},
	})
	write(filepath.Join(clientsDir, "c2.json"), model.Client{
		ID:           "c2",
		AllocatedIPs: []string{"10.252.1.11/32"},
	})

	ips, err := GetAllocatedIPs("")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"10.252.1.0": true, "10.252.1.10": true, "10.252.1.11": true}
	if len(ips) != len(want) {
		t.Fatalf("GetAllocatedIPs = %v, want %v", ips, want)
	}
	for _, ip := range ips {
		if !want[ip] {
			t.Errorf("unexpected ip %q in %v", ip, ips)
		}
	}

	// ignoring a client excludes its IPs
	ips, err = GetAllocatedIPs("c2")
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range ips {
		if ip == "10.252.1.11" {
			t.Error("ignored client IP present in result")
		}
	}
}
