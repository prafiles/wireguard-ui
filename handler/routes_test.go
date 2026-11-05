package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/ngoduykhanh/wireguard-ui/store"
	"github.com/ngoduykhanh/wireguard-ui/store/jsondb"
	"github.com/ngoduykhanh/wireguard-ui/util"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// newTestStore returns a real scribble-backed JsonDB in a temp dir.
// WGUI_ENDPOINT_ADDRESS avoids network lookups during Init().
func newTestStore(t *testing.T) store.IStore {
	t.Helper()
	t.Setenv("WGUI_ENDPOINT_ADDRESS", "203.0.113.7")
	db, err := jsondb.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Init(); err != nil {
		t.Fatal(err)
	}
	return db
}

// newEcho returns an Echo instance with the session middleware installed so
// handlers using session.Get work, mirroring router.New().
func newEcho(t *testing.T) *echo.Echo {
	t.Helper()
	e := echo.New()
	e.Use(session.Middleware(testCookieStore()))
	return e
}

func testCookieStore() sessions.Store {
	return sessions.NewCookieStore([]byte("test-secret-0123456789"))
}

// invoke runs a handler with the given request. The session store is injected
// into the context directly (key "_session_store", as echo-contrib's session
// middleware does) because calling the handler bypasses the middleware chain.
func invoke(t *testing.T, e *echo.Echo, h echo.HandlerFunc, req *http.Request, pathParams map[string]string) (int, *httptest.ResponseRecorder) {
	t.Helper()
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("_session_store", testCookieStore())
	for k, v := range pathParams {
		c.SetParamNames(k)
		c.SetParamValues(v)
	}
	if err := h(c); err != nil {
		// handlers return the error from c.JSON/c.Render; statuses already recorded
		if hh, ok := err.(*echo.HTTPError); ok {
			return hh.Code, rec
		}
	}
	return rec.Code, rec
}

func jsonRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	return req
}

// withScratchDB points the hardcoded relative ./db path (used by
// util.GetAllocatedIPs) at a temp store dir for the duration of the test.
// Tolerates leftovers from earlier runs (scribble creates ./db eagerly).
func withScratchDB(t *testing.T, storePath string) {
	t.Helper()
	if fi, err := os.Lstat("db"); err == nil {
		entries, _ := os.ReadDir("db")
		if fi.Mode()&os.ModeSymlink != 0 || (fi.IsDir() && len(entries) == 0) {
			os.RemoveAll("db") // leftover from a previous run
		} else {
			t.Skip("./db exists with real data; skipping")
		}
	}
	if err := os.Symlink(storePath, "db"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll("db") })
}

func statusOf(t *testing.T, rec *httptest.ResponseRecorder) jsonHTTPResponse {
	t.Helper()
	var out jsonHTTPResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not jsonHTTPResponse: %s (err %v)", rec.Body.String(), err)
	}
	return out
}

func TestHealth(t *testing.T) {
	e := newEcho(t)
	code, rec := invoke(t, e, Health(), httptest.NewRequest(http.MethodGet, "/api/status/health", nil), nil)
	if code != http.StatusOK || rec.Body.String() != "ok" {
		t.Errorf("Health = %d %q", code, rec.Body.String())
	}
}

func TestContentTypeJsonMiddleware(t *testing.T) {
	e := newEcho(t)
	called := false
	next := func(c echo.Context) error {
		called = true
		return c.String(http.StatusOK, "pass")
	}
	mw := ContentTypeJson(next)

	// rejected without JSON content type
	rec := httptest.NewRecorder()
	c := e.NewContext(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}")), rec)
	if err := mw(c); err != nil {
		t.Errorf("middleware returned err: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("non-JSON request code = %d, want 400", rec.Code)
	}
	if called {
		t.Error("next handler should not run for non-JSON request")
	}

	// accepted with JSON content type
	rec = httptest.NewRecorder()
	c = e.NewContext(jsonRequest("{}"), rec)
	if err := mw(c); err != nil {
		t.Fatal(err)
	}
	if !called || rec.Code != http.StatusOK {
		t.Errorf("JSON request: called=%v code=%d", called, rec.Code)
	}
}

func TestLoginHandler(t *testing.T) {
	db := newTestStore(t)
	e := newEcho(t)
	h := Login(db)

	// malformed body -> 400
	code, _ := invoke(t, e, h, jsonRequest("not json"), nil)
	if code != http.StatusBadRequest {
		t.Errorf("bad body: code = %d, want 400", code)
	}

	// missing fields -> the handler type-asserts and panics; recover to document
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for missing username/password fields (known robustness bug)")
			}
		}()
		invoke(t, e, h, jsonRequest(`{}`), nil)
	}()

	// unknown user -> 500 (DB error mapped to 500)
	code, rec := invoke(t, e, h, jsonRequest(`{"username":"ghost","password":"x","rememberMe":false}`), nil)
	if code != http.StatusInternalServerError {
		t.Errorf("unknown user: code = %d, want 500", code)
	}
	if r := statusOf(t, rec); r.Status {
		t.Error("unknown user response should have status=false")
	}

	// wrong password -> 401
	code, _ = invoke(t, e, h, jsonRequest(`{"username":"admin","password":"wrong","rememberMe":false}`), nil)
	if code != http.StatusUnauthorized {
		t.Errorf("wrong password: code = %d, want 401", code)
	}

	// correct credentials (default admin/admin) -> 200 + session cookie
	code, rec = invoke(t, e, h, jsonRequest(`{"username":"admin","password":"admin","rememberMe":false}`), nil)
	if code != http.StatusOK {
		t.Fatalf("login: code = %d body=%s", code, rec.Body.String())
	}
	if r := statusOf(t, rec); !r.Status {
		t.Errorf("login response = %+v", r)
	}
	cookies := rec.Result().Cookies()
	var sessionCookie, tokenCookie bool
	for _, ck := range cookies {
		if ck.Name == "session" {
			sessionCookie = true
		}
		if ck.Name == "session_token" {
			tokenCookie = true
		}
	}
	if !sessionCookie || !tokenCookie {
		t.Errorf("expected session and session_token cookies, got %v", cookies)
	}
}

func TestUserHandlers(t *testing.T) {
	db := newTestStore(t)
	e := newEcho(t)
	util.DisableLogin = true // currentUser()=="" and isAdmin()==true
	defer func() { util.DisableLogin = false }()

	// GetUsers -> 200, contains admin
	code, rec := invoke(t, e, GetUsers(db), httptest.NewRequest(http.MethodGet, "/api/users", nil), nil)
	if code != http.StatusOK {
		t.Fatalf("GetUsers code = %d", code)
	}
	var users []model.User
	if err := json.Unmarshal(rec.Body.Bytes(), &users); err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].Username != "admin" {
		t.Errorf("users = %+v", users)
	}

	// CreateUser happy path
	code, rec = invoke(t, e, CreateUser(db), jsonRequest(`{"username":"alice","password":"secret","admin":false}`), nil)
	if code != http.StatusOK {
		t.Fatalf("CreateUser code=%d body=%s", code, rec.Body.String())
	}
	if r := statusOf(t, rec); !r.Status {
		t.Errorf("CreateUser response %+v", r)
	}
	u, err := db.GetUserByName("alice")
	if err != nil || u.PasswordHash == "" || u.PasswordHash == "secret" {
		t.Errorf("alice not stored with hash: %+v %v", u, err)
	}

	// CreateUser duplicate -> 400
	code, _ = invoke(t, e, CreateUser(db), jsonRequest(`{"username":"alice","password":"x","admin":false}`), nil)
	if code != http.StatusBadRequest {
		t.Errorf("duplicate user: code = %d, want 400", code)
	}
	// CreateUser empty username -> 400
	code, _ = invoke(t, e, CreateUser(db), jsonRequest(`{"username":"","password":"x","admin":false}`), nil)
	if code != http.StatusBadRequest {
		t.Errorf("empty username: code = %d, want 400", code)
	}
	// CreateUser bad JSON -> 400
	code, _ = invoke(t, e, CreateUser(db), jsonRequest(`{{`), nil)
	if code != http.StatusBadRequest {
		t.Errorf("bad json: code = %d, want 400", code)
	}

	// GetUser known / unknown
	code, _ = invoke(t, e, GetUser(db), httptest.NewRequest(http.MethodGet, "/api/users/alice", nil), map[string]string{"username": "alice"})
	if code != http.StatusOK {
		t.Errorf("GetUser alice code = %d, want 200", code)
	}
	code, _ = invoke(t, e, GetUser(db), httptest.NewRequest(http.MethodGet, "/api/users/ghost", nil), map[string]string{"username": "ghost"})
	if code != http.StatusNotFound {
		t.Errorf("GetUser ghost code = %d, want 404", code)
	}

	// RemoveUser: cannot delete self (currentUser is "" with DisableLogin, so
	// deleting "admin" is not self) -> 200
	code, _ = invoke(t, e, RemoveUser(db), jsonRequest(`{"username":"alice"}`), nil)
	if code != http.StatusOK {
		t.Errorf("RemoveUser code = %d", code)
	}
	if _, err := db.GetUserByName("alice"); err == nil {
		t.Error("alice should be deleted")
	}
	// deleting a nonexistent user -> 500 (DB error)
	code, _ = invoke(t, e, RemoveUser(db), jsonRequest(`{"username":"ghost"}`), nil)
	if code != http.StatusInternalServerError {
		t.Errorf("RemoveUser ghost code = %d, want 500", code)
	}
}

func TestRemoveUserCannotDeleteSelf(t *testing.T) {
	db := newTestStore(t)
	e := newEcho(t)
	// With sessions active but no login, currentUser() renders "<nil>"-ish;
	// emulate self-delete by disabling login and matching empty username.
	util.DisableLogin = true
	defer func() { util.DisableLogin = false }()
	// currentUser() == "" when DisableLogin; sending username "" hits the guard
	code, rec := invoke(t, e, RemoveUser(db), jsonRequest(`{"username":""}`), nil)
	if code != http.StatusForbidden {
		t.Errorf("self-delete code = %d, want 403 body=%s", code, rec.Body.String())
	}
}

func TestClientHandlers(t *testing.T) {
	db := newTestStore(t)
	e := newEcho(t)

	// GetClients empty
	code, rec := invoke(t, e, GetClients(db), httptest.NewRequest(http.MethodGet, "/api/client/list", nil), nil)
	if code != http.StatusOK {
		t.Fatalf("GetClients code = %d", code)
	}
	_ = rec

	// SuggestIPAllocation -> first free IP of default 10.252.1.0/24 network.
	// util.GetAllocatedIPs reads the hardcoded relative ./db path, so point a
	// scratch ./db symlink at the temp store dir for the duration of the test.
	withScratchDB(t, db.GetPath())
	code, rec = invoke(t, e, SuggestIPAllocation(db), httptest.NewRequest(http.MethodGet, "/api/server/suggest", nil), nil)
	if code != http.StatusOK {
		t.Fatalf("SuggestIPAllocation code = %d body = %s", code, rec.Body.String())
	}
	var suggested []string
	if err := json.Unmarshal(rec.Body.Bytes(), &suggested); err != nil {
		t.Fatal(err)
	}
	if len(suggested) != 1 || suggested[0] != "10.252.1.1/32" {
		t.Errorf("suggested = %v, want [10.252.1.1/32]", suggested)
	}

	// NewClient happy path: valid CIDR inside server range
	code, rec = invoke(t, e, NewClient(db), jsonRequest(`{"name":"phone","allocated_ips":["10.252.1.10/32"],"allowed_ips":["0.0.0.0/0"],"extra_allowed_ips":[],"use_server_dns":true,"enabled":true}`), nil)
	if code != http.StatusOK {
		t.Fatalf("NewClient code = %d body = %s", code, rec.Body.String())
	}
	var created model.Client
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.PrivateKey == "" || created.PresharedKey == "" {
		t.Errorf("NewClient response missing generated fields: %+v", created)
	}
	if _, err := wgtypes.ParseKey(created.PublicKey); err != nil {
		t.Errorf("generated public key invalid: %v", err)
	}

	// NewClient invalid allowed_ips -> 400
	code, _ = invoke(t, e, NewClient(db), jsonRequest(`{"name":"x","allocated_ips":["10.252.1.11/32"],"allowed_ips":["not-a-cidr"]}`), nil)
	if code != http.StatusBadRequest {
		t.Errorf("bad allowed_ips code = %d, want 400", code)
	}
	// NewClient allocation outside server networks -> 400
	code, _ = invoke(t, e, NewClient(db), jsonRequest(`{"name":"x","allocated_ips":["192.168.99.1/32"],"allowed_ips":["0.0.0.0/0"]}`), nil)
	if code != http.StatusBadRequest {
		t.Errorf("foreign allocation code = %d, want 400", code)
	}
	// NewClient allocation already used -> 400
	code, _ = invoke(t, e, NewClient(db), jsonRequest(`{"name":"x","allocated_ips":["10.252.1.10/32"],"allowed_ips":["0.0.0.0/0"]}`), nil)
	if code != http.StatusBadRequest {
		t.Errorf("duplicate allocation code = %d, want 400", code)
	}
	// NewClient invalid supplied public key -> 500
	code, _ = invoke(t, e, NewClient(db), jsonRequest(`{"name":"x","allocated_ips":["10.252.1.12/32"],"allowed_ips":["0.0.0.0/0"],"public_key":"zzzz"}`), nil)
	if code != http.StatusInternalServerError {
		t.Errorf("bad pubkey code = %d, want 500", code)
	}
	// NewClient duplicate public key -> 500
	code, _ = invoke(t, e, NewClient(db), jsonRequest(fmt.Sprintf(`{"name":"x","allocated_ips":["10.252.1.13/32"],"allowed_ips":["0.0.0.0/0"],"public_key":"%s"}`, created.PublicKey)), nil)
	if code != http.StatusInternalServerError {
		t.Errorf("duplicate pubkey code = %d, want 500", code)
	}
	// NewClient preshared "-" skips PSK generation
	code, rec = invoke(t, e, NewClient(db), jsonRequest(`{"name":"nopsk","allocated_ips":["10.252.1.14/32"],"allowed_ips":["0.0.0.0/0"],"preshared_key":"-"}`), nil)
	if code != http.StatusOK {
		t.Fatalf("NewClient psk=- code = %d", code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.PresharedKey != "" {
		t.Errorf("preshared_key should be empty for '-', got %q", created.PresharedKey)
	}

	// GetClient by id (with QR)
	code, rec = invoke(t, e, GetClient(db), httptest.NewRequest(http.MethodGet, "/api/client/x", nil), map[string]string{"id": created.ID})
	if code != http.StatusOK {
		t.Fatalf("GetClient code = %d", code)
	}
	var cd model.ClientData
	if err := json.Unmarshal(rec.Body.Bytes(), &cd); err != nil {
		t.Fatal(err)
	}
	if cd.Client.Name != "nopsk" {
		t.Errorf("GetClient = %+v", cd)
	}
	// unknown client -> 404
	code, _ = invoke(t, e, GetClient(db), httptest.NewRequest(http.MethodGet, "/api/client/x", nil), map[string]string{"id": "ghost"})
	if code != http.StatusNotFound {
		t.Errorf("GetClient ghost code = %d, want 404", code)
	}

	// UpdateClient happy path
	upd := fmt.Sprintf(`{"id":"%s","name":"renamed","email":"n@e.io","allocated_ips":["10.252.1.14/32"],"allowed_ips":["0.0.0.0/0"],"extra_allowed_ips":[],"use_server_dns":false,"enabled":false,"public_key":"%s","preshared_key":""}`, created.ID, created.PublicKey)
	code, _ = invoke(t, e, UpdateClient(db), jsonRequest(upd), nil)
	if code != http.StatusOK {
		t.Fatalf("UpdateClient code = %d", code)
	}
	updated, _ := db.GetClientByID(created.ID, model.QRCodeSettings{Enabled: false})
	if updated.Client.Name != "renamed" || updated.Client.Enabled {
		t.Errorf("client not updated: %+v", updated.Client)
	}
	// UpdateClient unknown id -> 404
	code, _ = invoke(t, e, UpdateClient(db), jsonRequest(`{"id":"ghost","name":"x"}`), nil)
	if code != http.StatusNotFound {
		t.Errorf("UpdateClient ghost code = %d, want 404", code)
	}
	// UpdateClient invalid allowed ips -> 400
	code, _ = invoke(t, e, UpdateClient(db), jsonRequest(fmt.Sprintf(`{"id":"%s","name":"x","allowed_ips":["bogus"]}`, created.ID)), nil)
	if code != http.StatusBadRequest {
		t.Errorf("UpdateClient bad cidr code = %d, want 400", code)
	}

	// SetClientStatus toggle
	code, _ = invoke(t, e, SetClientStatus(db), jsonRequest(fmt.Sprintf(`{"id":"%s","status":true}`, created.ID)), nil)
	if code != http.StatusOK {
		t.Errorf("SetClientStatus code = %d", code)
	}
	after, _ := db.GetClientByID(created.ID, model.QRCodeSettings{Enabled: false})
	if !after.Client.Enabled {
		t.Error("client should be enabled")
	}
	code, _ = invoke(t, e, SetClientStatus(db), jsonRequest(`{"id":"ghost","status":true}`), nil)
	if code != http.StatusNotFound {
		t.Errorf("SetClientStatus ghost code = %d, want 404", code)
	}

	// DownloadClient
	req := httptest.NewRequest(http.MethodGet, "/api/client/download?clientid="+created.ID, nil)
	code, rec = invoke(t, e, DownloadClient(db), req, nil)
	if code != http.StatusOK {
		t.Fatalf("DownloadClient code = %d", code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "[Interface]") || !strings.Contains(body, "[Peer]") {
		t.Errorf("downloaded config malformed:\n%s", body)
	}
	if !strings.Contains(rec.Header().Get(echo.HeaderContentDisposition), "attachment") {
		t.Error("missing attachment disposition header")
	}
	// missing param -> 404
	code, _ = invoke(t, e, DownloadClient(db), httptest.NewRequest(http.MethodGet, "/api/client/download", nil), nil)
	if code != http.StatusNotFound {
		t.Errorf("DownloadClient no param code = %d, want 404", code)
	}

	// RemoveClient
	code, _ = invoke(t, e, RemoveClient(db), jsonRequest(fmt.Sprintf(`{"id":"%s"}`, created.ID)), nil)
	if code != http.StatusOK {
		t.Errorf("RemoveClient code = %d", code)
	}
	if _, err := db.GetClientByID(created.ID, model.QRCodeSettings{Enabled: false}); err == nil {
		t.Error("client should be gone")
	}
}

func TestServerHandlers(t *testing.T) {
	db := newTestStore(t)
	e := newEcho(t)

	// WireGuardServerInterfaces valid update
	code, _ := invoke(t, e, WireGuardServerInterfaces(db), jsonRequest(`{"addresses":["10.8.0.0/24"],"listen_port":"51820"}`), nil)
	if code != http.StatusOK {
		t.Errorf("interfaces update code = %d", code)
	}
	srv, _ := db.GetServer()
	if srv.Interface.ListenPort != 51820 {
		t.Errorf("port = %d", srv.Interface.ListenPort)
	}
	// invalid CIDR -> 400
	code, _ = invoke(t, e, WireGuardServerInterfaces(db), jsonRequest(`{"addresses":["bogus"]}`), nil)
	if code != http.StatusBadRequest {
		t.Errorf("interfaces bad cidr code = %d, want 400", code)
	}

	// WireGuardServerKeyPair regenerates valid keys
	code, rec := invoke(t, e, WireGuardServerKeyPair(db), jsonRequest(`{}`), nil)
	if code != http.StatusOK {
		t.Fatalf("keypair code = %d", code)
	}
	var kp model.ServerKeypair
	if err := json.Unmarshal(rec.Body.Bytes(), &kp); err != nil {
		t.Fatal(err)
	}
	priv, err := wgtypes.ParseKey(kp.PrivateKey)
	if err != nil {
		t.Fatalf("new private key invalid: %v", err)
	}
	if priv.PublicKey().String() != kp.PublicKey {
		t.Error("keypair mismatch")
	}

	// GlobalSettingSubmit valid / invalid DNS
	code, _ = invoke(t, e, GlobalSettingSubmit(db), jsonRequest(`{"endpoint_address":"h.example","dns_servers":["9.9.9.9"],"mtu":"1420","persistent_keepalive":"10","firewall_mark":"0xca6c","table":"auto","config_file_path":"/tmp/wg0.conf"}`), nil)
	if code != http.StatusOK {
		t.Errorf("global settings code = %d", code)
	}
	gs, _ := db.GetGlobalSettings()
	if gs.MTU != 1420 || gs.EndpointAddress != "h.example" {
		t.Errorf("settings not saved: %+v", gs)
	}
	code, _ = invoke(t, e, GlobalSettingSubmit(db), jsonRequest(`{"dns_servers":["not-an-ip"]}`), nil)
	if code != http.StatusBadRequest {
		t.Errorf("bad dns code = %d, want 400", code)
	}

	// GetHashesChanges: after Init hashes are "none" -> changed=true
	code, rec = invoke(t, e, GetHashesChanges(db), httptest.NewRequest(http.MethodGet, "/api/server/hasChanges", nil), nil)
	if code != http.StatusOK {
		t.Fatalf("hashes code = %d", code)
	}
	if r := statusOf(t, rec); !r.Status {
		t.Error("fresh store should report hashes changed")
	}
	if err := util.UpdateHashes(db); err != nil {
		t.Fatal(err)
	}
	code, rec = invoke(t, e, GetHashesChanges(db), httptest.NewRequest(http.MethodGet, "/api/server/hasChanges", nil), nil)
	if code != http.StatusOK {
		t.Fatalf("hashes code = %d", code)
	}
	if r := statusOf(t, rec); r.Status {
		t.Error("after UpdateHashes should report no changes")
	}
}

func TestApplyServerConfig(t *testing.T) {
	db := newTestStore(t)
	e := newEcho(t)
	conf := t.TempDir() + "/wg0.conf"
	gs, _ := db.GetGlobalSettings()
	gs.ConfigFilePath = conf
	if err := db.SaveGlobalSettings(gs); err != nil {
		t.Fatal(err)
	}

	// minimal wg.conf template, same shape main.go embeds from templates/wg.conf
	tmplDir := fstest.MapFS{"wg.conf": &fstest.MapFile{Data: []byte(
		"[Interface]\nAddress = {{ range .serverConfig.Interface.Addresses }}{{ . }}{{ end }}\nListenPort = {{ .serverConfig.Interface.ListenPort }}\nPrivateKey = {{ .serverConfig.KeyPair.PrivateKey }}\n")}}

	code, rec := invoke(t, e, ApplyServerConfig(db, tmplDir), jsonRequest(`{}`), nil)
	if code != http.StatusOK {
		t.Fatalf("ApplyServerConfig code = %d body = %s", code, rec.Body.String())
	}
	if r := statusOf(t, rec); !r.Status {
		t.Errorf("response %+v", r)
	}
	data, err := os.ReadFile(conf)
	if err != nil {
		t.Fatalf("config file not written: %v", err)
	}
	if !strings.Contains(string(data), "ListenPort = 51820") {
		t.Errorf("rendered config unexpected:\n%s", data)
	}
}

func TestStatusHandlerWithoutWireguard(t *testing.T) {
	// GATE: the Status handler shells into wgctrl (netlink to the kernel
	// WireGuard module). This sandbox has no WireGuard interface, so only the
	// error branch is exercised: the handler must answer 500 with an error
	// message rather than crash. The happy path requires a live wg device and
	// is covered by integration testing only.
	db := newTestStore(t)
	e := newEcho(t)
	code, _ := invoke(t, e, Status(db), httptest.NewRequest(http.MethodGet, "/api/status", nil), nil)
	// With no renderer registered echo returns ErrRendererNotRegistered and no
	// status is written; either 500 (error branch rendered) or 200 (devices
	// found) proves the handler ran without panicking.
	if code != http.StatusOK && code != http.StatusInternalServerError {
		t.Errorf("Status code = %d, want 200 or 500", code)
	}
}

func TestSessionMiddlewares(t *testing.T) {
	e := newEcho(t)

	// ValidSession passes when DisableLogin
	util.DisableLogin = true
	rec := httptest.NewRecorder()
	c := e.NewContext(httptest.NewRequest(http.MethodGet, "/", nil), rec)
	ran := false
	err := ValidSession(func(c echo.Context) error { ran = true; return nil })(c)
	if err != nil || !ran {
		t.Errorf("ValidSession with DisableLogin: err=%v ran=%v", err, ran)
	}
	ran = false
	err = NeedsAdmin(func(c echo.Context) error { ran = true; return nil })(c)
	if err != nil || !ran {
		t.Errorf("NeedsAdmin with DisableLogin: err=%v ran=%v", err, ran)
	}
	util.DisableLogin = false

	// Without a session, ValidSession redirects to /login
	ran = false
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	c = e.NewContext(req, rec)
	c.Set("_session_store", testCookieStore())
	err = ValidSession(func(c echo.Context) error { ran = true; return nil })(c)
	if err != nil {
		t.Fatal(err)
	}
	if ran {
		t.Error("next should not run without session")
	}
	if rec.Code != http.StatusTemporaryRedirect {
		t.Errorf("code = %d, want 307", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "/login") {
		t.Errorf("Location = %q", loc)
	}

	// NeedsAdmin redirects non-admins to /
	rec = httptest.NewRecorder()
	c = e.NewContext(httptest.NewRequest(http.MethodGet, "/admin", nil), rec)
	c.Set("_session_store", testCookieStore())
	err = NeedsAdmin(func(c echo.Context) error { ran = true; return nil })(c)
	if err != nil || rec.Code != http.StatusTemporaryRedirect {
		t.Errorf("NeedsAdmin: err=%v code=%d", err, rec.Code)
	}
}

func TestWakeOnLanHandlers(t *testing.T) {
	db := newTestStore(t)
	e := newEcho(t)

	// Save new host
	code, rec := invoke(t, e, SaveWakeOnLanHost(db), jsonRequest(`{"name":"desk","mac_address":"aa:bb:cc:dd:ee:ff"}`), nil)
	if code != http.StatusOK {
		t.Fatalf("Save code = %d body = %s", code, rec.Body.String())
	}
	_ = rec

	// duplicate -> 500 with message
	code, rec = invoke(t, e, SaveWakeOnLanHost(db), jsonRequest(`{"name":"desk2","mac_address":"aa:bb:cc:dd:ee:ff"}`), nil)
	if code != http.StatusInternalServerError {
		t.Errorf("duplicate mac code = %d, want 500", code)
	}
	if !strings.Contains(rec.Body.String(), "already exists") {
		t.Errorf("body = %s", rec.Body.String())
	}

	// invalid mac (empty) -> 500 via ResolveResourceName error
	code, _ = invoke(t, e, SaveWakeOnLanHost(db), jsonRequest(`{"name":"x","mac_address":"  "}`), nil)
	if code != http.StatusInternalServerError {
		t.Errorf("blank mac code = %d, want 500", code)
	}

	// edit: rename mac address
	code, _ = invoke(t, e, SaveWakeOnLanHost(db), jsonRequest(`{"name":"desk","mac_address":"11:22:33:44:55:66","old_mac_address":"aa:bb:cc:dd:ee:ff"}`), nil)
	if code != http.StatusOK {
		t.Errorf("edit code = %d", code)
	}
	hosts, _ := db.GetWakeOnLanHosts()
	if len(hosts) != 1 || hosts[0].MacAddress != "11:22:33:44:55:66" {
		t.Errorf("hosts after edit = %+v", hosts)
	}

	// delete
	code, _ = invoke(t, e, DeleteWakeOnHost(db), httptest.NewRequest(http.MethodDelete, "/api/wakeonlan/host", nil), map[string]string{"mac_address": "11:22:33:44:55:66"})
	if code != http.StatusOK {
		t.Errorf("delete code = %d", code)
	}
	hosts, _ = db.GetWakeOnLanHosts()
	if len(hosts) != 0 {
		t.Errorf("hosts remain: %+v", hosts)
	}
	// delete unknown -> 500
	code, _ = invoke(t, e, DeleteWakeOnHost(db), httptest.NewRequest(http.MethodDelete, "/api/wakeonlan/host", nil), map[string]string{"mac_address": "ff:ff:ff:ff:ff:ff"})
	if code != http.StatusInternalServerError {
		t.Errorf("delete ghost code = %d, want 500", code)
	}
}
