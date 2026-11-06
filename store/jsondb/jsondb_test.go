package jsondb

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ngoduykhanh/wireguard-ui/model"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// newTestStore returns a JsonDB backed by a real scribble driver over a temp
// directory. WGUI_ENDPOINT_ADDRESS is set so Init() does not attempt to
// discover a public IP over the network.
func newTestStore(t *testing.T) *JsonDB {
	t.Helper()
	t.Setenv("WGUI_ENDPOINT_ADDRESS", "203.0.113.7")
	db := newTestDB(t.TempDir(), t)
	if err := db.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return db
}

// newTestDB wraps New and fails the test on error.
func newTestDB(path string, t *testing.T) *JsonDB {
	t.Helper()
	db, err := New(path)
	if err != nil {
		t.Fatalf("New(%s): %v", path, err)
	}
	return db
}

func TestInitCreatesStructure(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WGUI_ENDPOINT_ADDRESS", "203.0.113.7")
	db, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Init(); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{
		"clients", "server", "wake_on_lan_hosts",
		filepath.Join("server", "interfaces.json"),
		filepath.Join("server", "keypair.json"),
		filepath.Join("server", "global_settings.json"),
		filepath.Join("server", "hashes.json"),
	} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Errorf("Init did not create %s: %v", p, err)
		}
	}

	if db.GetPath() != dir {
		t.Errorf("GetPath = %q, want %q", db.GetPath(), dir)
	}

	// default admin user must exist with a bcrypt hash of "admin"
	users, err := db.GetUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].Username != "admin" || !users[0].Admin {
		t.Fatalf("unexpected default users: %+v", users)
	}
	if users[0].PasswordHash == "" || users[0].PasswordHash == "admin" {
		t.Errorf("default user password should be hashed, got %q", users[0].PasswordHash)
	}

	// server keypair must be valid wireguard keys
	srv, err := db.GetServer()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := wgtypes.ParseKey(srv.KeyPair.PrivateKey)
	if err != nil {
		t.Fatalf("stored private key invalid: %v", err)
	}
	if _, err := wgtypes.ParseKey(srv.KeyPair.PublicKey); err != nil {
		t.Fatalf("stored public key invalid: %v", err)
	}
	if priv.PublicKey().String() != srv.KeyPair.PublicKey {
		t.Error("stored public key does not match private key")
	}
	if srv.Interface.ListenPort != 51820 {
		t.Errorf("default listen port = %d, want 51820", srv.Interface.ListenPort)
	}

	// global settings from env defaults
	gs, err := db.GetGlobalSettings()
	if err != nil {
		t.Fatal(err)
	}
	if gs.EndpointAddress != "203.0.113.7" {
		t.Errorf("endpoint = %q", gs.EndpointAddress)
	}
	if gs.MTU != 1450 || gs.PersistentKeepalive != 15 || gs.Table != "auto" {
		t.Errorf("unexpected global settings defaults: %+v", gs)
	}

	// Init must be idempotent
	if err := db.Init(); err != nil {
		t.Fatalf("second Init: %v", err)
	}
	if users, err := db.GetUsers(); err != nil || len(users) != 1 {
		t.Errorf("users after second Init: %v (err %v)", users, err)
	}
}

func TestInitRespectsEnvOverrides(t *testing.T) {
	t.Setenv("WGUI_ENDPOINT_ADDRESS", "198.51.100.2")
	t.Setenv("WGUI_SERVER_INTERFACE_ADDRESSES", "10.10.0.0/24,10.11.0.0/24")
	t.Setenv("WGUI_SERVER_LISTEN_PORT", "60000")
	t.Setenv("WGUI_USERNAME", "root")
	t.Setenv("WGUI_PASSWORD_HASH", "prehashed")

	db := newTestDB(t.TempDir(), t)
	if err := db.Init(); err != nil {
		t.Fatal(err)
	}

	srv, err := db.GetServer()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(srv.Interface.Addresses, ",") != "10.10.0.0/24,10.11.0.0/24" {
		t.Errorf("addresses = %v", srv.Interface.Addresses)
	}
	if srv.Interface.ListenPort != 60000 {
		t.Errorf("port = %d", srv.Interface.ListenPort)
	}
	u, err := db.GetUserByName("root")
	if err != nil {
		t.Fatal(err)
	}
	if u.PasswordHash != "prehashed" {
		t.Errorf("PasswordHash = %q, want the env-provided hash", u.PasswordHash)
	}
}

func TestUserCRUD(t *testing.T) {
	db := newTestStore(t)

	user := model.User{Username: "alice", PasswordHash: "hash1", Admin: false}
	if err := db.SaveUser(user); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetUserByName("alice")
	if err != nil {
		t.Fatal(err)
	}
	if got.Username != "alice" || got.PasswordHash != "hash1" || got.Admin {
		t.Errorf("GetUserByName = %+v", got)
	}

	// user files are permission-hardened
	if fi, err := os.Stat(filepath.Join(db.GetPath(), "users", "alice.json")); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("user file mode = %v, want 0600", fi.Mode().Perm())
	}

	users, err := db.GetUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 { // admin + alice
		t.Fatalf("GetUsers len = %d, want 2 (%+v)", len(users), users)
	}

	// update in place
	user.Admin = true
	if err := db.SaveUser(user); err != nil {
		t.Fatal(err)
	}
	if got, err := db.GetUserByName("alice"); err != nil || !got.Admin {
		t.Errorf("update failed: %+v %v", got, err)
	}

	if err := db.DeleteUser("alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetUserByName("alice"); err == nil {
		t.Error("expected error reading deleted user")
	}
	if err := db.DeleteUser("ghost"); err == nil {
		t.Error("expected error deleting nonexistent user")
	}
}

func TestClientCRUDAndQRCode(t *testing.T) {
	db := newTestStore(t)

	client := model.Client{
		ID: "cid1", Name: "phone", Email: "u@example.com",
		AllocatedIPs: []string{"10.252.1.10/32"}, AllowedIPs: []string{"0.0.0.0/0"},
		UseServerDNS: true, Enabled: true,
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	client.PrivateKey = key.String()
	client.PublicKey = key.PublicKey().String()

	if err := db.SaveClient(client); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(db.GetPath(), "clients", "cid1.json")); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("client file mode = %v, want 0600", fi.Mode().Perm())
	}

	// single client without QR
	cd, err := db.GetClientByID("cid1", model.QRCodeSettings{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	if cd.Client == nil || cd.Client.Name != "phone" || cd.QRCode != "" {
		t.Errorf("GetClientByID = %+v", cd)
	}

	// single client with QR enabled -> data URL
	cd, err = db.GetClientByID("cid1", model.QRCodeSettings{Enabled: true, IncludeDNS: true, IncludeMTU: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cd.QRCode, "data:image/png;base64,") {
		t.Errorf("QRCode not a png data URL: %.40s", cd.QRCode)
	}

	// list with QR codes
	list, err := db.GetClients(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].QRCode == "" || list[0].Client.ID != "cid1" {
		t.Errorf("GetClients = %+v", list)
	}
	list, err = db.GetClients(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].QRCode != "" {
		t.Errorf("GetClients(false) should omit QR: %+v", list)
	}

	if _, err := db.GetClientByID("ghost", model.QRCodeSettings{Enabled: false}); err == nil {
		t.Error("expected error for missing client")
	}

	if err := db.DeleteClient("cid1"); err != nil {
		t.Fatal(err)
	}
	if list, err := db.GetClients(false); err != nil || len(list) != 0 {
		t.Errorf("after delete: %v %v", list, err)
	}
}

func TestServerAndSettingsSave(t *testing.T) {
	db := newTestStore(t)

	si := model.ServerInterface{
		Addresses:  []string{"10.9.9.0/24"},
		ListenPort: 51999,
		PostUp:     "echo up",
		PostDown:   "echo down",
	}
	if err := db.SaveServerInterface(si); err != nil {
		t.Fatal(err)
	}
	srv, err := db.GetServer()
	if err != nil {
		t.Fatal(err)
	}
	if srv.Interface.ListenPort != 51999 || srv.Interface.PostUp != "echo up" ||
		strings.Join(srv.Interface.Addresses, ",") != "10.9.9.0/24" {
		t.Errorf("server interface not persisted: %+v", srv.Interface)
	}
	if fi, err := os.Stat(filepath.Join(db.GetPath(), "server", "interfaces.json")); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("interfaces.json mode = %v, want 0600", fi.Mode().Perm())
	}

	kp := model.ServerKeypair{PrivateKey: "p", PublicKey: "q"}
	if err := db.SaveServerKeyPair(kp); err != nil {
		t.Fatal(err)
	}
	srv, _ = db.GetServer()
	if srv.KeyPair.PrivateKey != "p" || srv.KeyPair.PublicKey != "q" {
		t.Errorf("keypair not persisted: %+v", srv.KeyPair)
	}

	gs := model.GlobalSetting{
		EndpointAddress: "host.example", DNSServers: []string{"9.9.9.9"},
		MTU: 1420, PersistentKeepalive: 10, FirewallMark: "0x1", Table: "main",
		ConfigFilePath: "/tmp/wg0.conf",
	}
	if err := db.SaveGlobalSettings(gs); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetGlobalSettings()
	if err != nil {
		t.Fatal(err)
	}
	if got.EndpointAddress != "host.example" || got.MTU != 1420 || got.Table != "main" {
		t.Errorf("global settings not persisted: %+v", got)
	}
}

func TestWakeOnLanHostCRUD(t *testing.T) {
	db := newTestStore(t)

	host := model.WakeOnLanHost{MacAddress: "aa:bb:cc:dd:ee:ff", Name: "desktop"}
	if err := db.SaveWakeOnLanHost(host); err != nil {
		t.Fatal(err)
	}

	// lookup is normalized: lowercase+colons must find the stored record
	got, err := db.GetWakeOnLanHost("AA-BB-CC-DD-EE-FF")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "desktop" {
		t.Errorf("host = %+v", got)
	}

	hosts, err := db.GetWakeOnLanHosts()
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].Name != "desktop" {
		t.Fatalf("GetWakeOnLanHosts = %+v", hosts)
	}

	// empty MAC -> resource name error
	if _, err := db.GetWakeOnLanHost("  "); err == nil {
		t.Error("expected error for blank mac")
	}
	if err := db.SaveWakeOnLanHost(model.WakeOnLanHost{MacAddress: ""}); err == nil {
		t.Error("expected error saving host with blank mac")
	}

	if err := db.DeleteWakeOnHost(host); err != nil {
		t.Fatal(err)
	}
	hosts, _ = db.GetWakeOnLanHosts()
	if len(hosts) != 0 {
		t.Errorf("host still present: %+v", hosts)
	}
	if err := db.DeleteWakeOnHostLanHost("aa:bb:cc:dd:ee:ff"); err == nil {
		t.Error("expected error deleting nonexistent host")
	}
}

func TestHashesSaveLoad(t *testing.T) {
	db := newTestStore(t)

	h, err := db.GetHashes()
	if err != nil {
		t.Fatal(err)
	}
	if h.Client != "none" || h.Server != "none" {
		t.Errorf("initial hashes = %+v, want none/none", h)
	}
	if err := db.SaveHashes(model.ClientServerHashes{Client: "c1", Server: "s1"}); err != nil {
		t.Fatal(err)
	}
	h, err = db.GetHashes()
	if err != nil {
		t.Fatal(err)
	}
	if h.Client != "c1" || h.Server != "s1" {
		t.Errorf("hashes = %+v", h)
	}
}
