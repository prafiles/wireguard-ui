package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/ngoduykhanh/wireguard-ui/emailer"
	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/ngoduykhanh/wireguard-ui/util"
)

// recordingMailer captures Send() arguments instead of talking to SMTP/SendGrid.
type recordingMailer struct {
	sent         []sentMail
	forceFailure bool
}

type sentMail struct {
	ToName, To, Subject, Content string
	Attachments                  []emailer.Attachment
}

func (m *recordingMailer) Send(toName, to, subject, content string, attachments []emailer.Attachment) error {
	if m.forceFailure {
		return errFakeMailer
	}
	m.sent = append(m.sent, sentMail{toName, to, subject, content, attachments})
	return nil
}

var errFakeMailer = &mailError{"smtp connection refused"}

type mailError struct{ msg string }

func (e *mailError) Error() string { return e.msg }

func TestEmailClientHandler(t *testing.T) {
	db := newTestStore(t)
	e := newEcho(t)

	// create a client with a private key so the QR attachment path runs
	code, rec := invoke(t, e, NewClient(db), jsonRequest(`{"name":"mailme","email":"user@example.com","allocated_ips":["10.252.1.20/32"],"allowed_ips":["0.0.0.0/0"],"use_server_dns":true,"enabled":true}`), nil)
	if code != http.StatusOK {
		t.Fatalf("NewClient code = %d body = %s", code, rec.Body.String())
	}
	clientID := strings.TrimSuffix(strings.Split(strings.Split(rec.Body.String(), `"id":"`)[1], `"`)[0], "")

	m := &recordingMailer{}
	h := EmailClient(db, m, "wg config", "hello")

	// unknown client -> 404
	code, _ = invoke(t, e, h, jsonRequest(`{"id":"ghost","email":"x@y.z"}`), nil)
	if code != http.StatusNotFound {
		t.Errorf("unknown client code = %d, want 404", code)
	}

	// happy path: config + QR attachments
	code, rec = invoke(t, e, h, jsonRequest(`{"id":"`+clientID+`","email":"user@example.com"}`), nil)
	if code != http.StatusOK {
		t.Fatalf("EmailClient code = %d body = %s", code, rec.Body.String())
	}
	if len(m.sent) != 1 {
		t.Fatalf("mailer captured %d messages", len(m.sent))
	}
	msg := m.sent[0]
	if msg.To != "user@example.com" || msg.Subject != "wg config" {
		t.Errorf("mail envelope = %+v", msg)
	}
	names := map[string]bool{}
	for _, a := range msg.Attachments {
		names[a.Name] = true
	}
	if !names["wg0.conf"] || !names["wg.png"] {
		t.Errorf("attachments = %v", names)
	}

	// mailer failure -> 500
	m2 := &recordingMailer{forceFailure: true}
	code, _ = invoke(t, e, EmailClient(db, m2, "s", "c"), jsonRequest(`{"id":"`+clientID+`","email":"user@example.com"}`), nil)
	if code != http.StatusInternalServerError {
		t.Errorf("mailer failure code = %d, want 500", code)
	}
}

// stubRenderer records render calls so handlers using c.Render can be asserted
// without the full HTML template set.
type stubRenderer struct {
	calls []renderCall
	body  string
}

type renderCall struct {
	code int
	name string
}

func (r *stubRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	r.calls = append(r.calls, renderCall{0, name})
	_, _ = io.WriteString(w, r.body)
	return nil
}

func TestGetWakeOnLanHostsRenders(t *testing.T) {
	db := newTestStore(t)
	e := newEcho(t)
	r := &stubRenderer{body: "hosts"}
	e.Renderer = r

	if err := db.SaveWakeOnLanHost(model.WakeOnLanHost{MacAddress: "AA-BB-CC-DD-EE-FF", Name: "one"}); err != nil {
		t.Fatal(err)
	}

	code, rec := invoke(t, e, GetWakeOnLanHosts(db), httptest.NewRequest(http.MethodGet, "/api/wakeonlan/hosts", nil), nil)
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	if len(r.calls) != 1 || r.calls[0].name != "wake_on_lan_hosts.html" {
		t.Errorf("renderer calls = %+v", r.calls)
	}
	if !strings.Contains(rec.Body.String(), "hosts") {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestStatusHandlerWithStubRenderer(t *testing.T) {
	// GATE: no WireGuard kernel device exists in this sandbox, so wgctrl
	// returns zero devices (or an error where netlink is unavailable). Either
	// way the handler must render status.html and never panic; the populated
	// happy path needs a live wg interface and is left to integration tests.
	db := newTestStore(t)
	e := newEcho(t)
	r := &stubRenderer{body: "status"}
	e.Renderer = r

	code, _ := invoke(t, e, Status(db), httptest.NewRequest(http.MethodGet, "/api/status", nil), nil)
	if code != http.StatusOK && code != http.StatusInternalServerError {
		t.Errorf("Status code = %d, want 200/500", code)
	}
	if len(r.calls) != 1 || r.calls[0].name != "status.html" {
		t.Errorf("status.html not rendered: %+v", r.calls)
	}
}

func TestRenderOnlyHandlers(t *testing.T) {
	db := newTestStore(t)
	e := newEcho(t)
	r := &stubRenderer{body: "ok"}
	e.Renderer = r

	tests := []struct {
		name string
		h    echo.HandlerFunc
		tmpl string
	}{
		{"LoginPage", LoginPage(), "login.html"},
		{"WireGuardServer", WireGuardServer(db), "server.html"},
		{"GlobalSettings", GlobalSettings(db), "global_settings.html"},
		{"AboutPage", AboutPage(), "about.html"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r.calls = nil
			code, _ := invoke(t, e, tt.h, httptest.NewRequest(http.MethodGet, "/", nil), nil)
			if code != http.StatusOK {
				t.Errorf("%s code = %d", tt.name, code)
			}
			if len(r.calls) != 1 || r.calls[0].name != tt.tmpl {
				t.Errorf("%s rendered %+v, want %s", tt.name, r.calls, tt.tmpl)
			}
		})
	}
}

func TestLogoutRedirectsToLogin(t *testing.T) {
	e := newEcho(t)
	saved := util.BasePath
	defer func() { util.BasePath = saved }()
	util.BasePath = "/wg"

	code, rec := invoke(t, e, Logout(), httptest.NewRequest(http.MethodGet, "/logout", nil), nil)
	if code != http.StatusTemporaryRedirect {
		t.Fatalf("code = %d, want 307", code)
	}
	if loc := rec.Header().Get("Location"); loc != "/wg/login" {
		t.Errorf("Location = %q, want /wg/login", loc)
	}
}

func TestFaviconRedirectsByDefault(t *testing.T) {
	e := newEcho(t)
	os.Unsetenv("WGUI_FAVICON_FILE_PATH")
	code, rec := invoke(t, e, Favicon(), httptest.NewRequest(http.MethodGet, "/favicon.ico", nil), nil)
	if code != http.StatusFound {
		t.Fatalf("code = %d, want 302", code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "favicon.ico") {
		t.Errorf("Location = %q", loc)
	}
}
