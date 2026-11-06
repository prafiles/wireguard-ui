package router

import (
	"bytes"
	"strings"
	"testing"
	"text/template"

	"github.com/labstack/echo/v4"
)

type tagged struct {
	Name  string `validate:"required"`
	Count int    `validate:"min=1"`
}

func TestValidator(t *testing.T) {
	v := NewValidator()

	if err := v.Validate(tagged{Name: "ok", Count: 2}); err != nil {
		t.Errorf("valid struct rejected: %v", err)
	}
	if err := v.Validate(tagged{}); err == nil {
		t.Error("invalid struct accepted (required/min violations)")
	}
	// structs without validation tags pass trivially (models have none)
	type bare struct{ A string }
	if err := v.Validate(bare{}); err != nil {
		t.Errorf("bare struct rejected: %v", err)
	}
}

func TestTemplateRegistryUnknownTemplate(t *testing.T) {
	e := echo.New()
	rec := &bytes.Buffer{}
	reg := &TemplateRegistry{templates: map[string]*template.Template{}, extraData: map[string]interface{}{}}
	err := reg.Render(rec, "nope.html", map[string]interface{}{}, e.NewContext(nil, nil))
	if err == nil || !strings.Contains(err.Error(), "Template not found") {
		t.Errorf("expected template-not-found error, got %v", err)
	}
}

func TestTemplateRegistryInjectsExtraData(t *testing.T) {
	e := echo.New()
	tmpl := template.Must(template.New("login").Parse("{{ .appVersion }}/{{ .client_defaults.UseServerDNS }}"))
	reg := &TemplateRegistry{
		templates: map[string]*template.Template{"login.html": tmpl},
		extraData: map[string]interface{}{"appVersion": "v9.9"},
	}
	buf := &bytes.Buffer{}
	data := map[string]interface{}{}
	if err := reg.Render(buf, "login.html", data, e.NewContext(nil, nil)); err != nil {
		t.Fatal(err)
	}
	// extraData injected and client_defaults populated from env defaults
	if buf.String() != "v9.9/true" {
		t.Errorf("rendered %q, want %q", buf.String(), "v9.9/true")
	}
}

func TestTemplateRegistryBaseLayout(t *testing.T) {
	// non-login templates execute the "base.html" sub-template
	base := template.Must(template.New("page").Parse(`{{define "base.html"}}base:{{ .who }}{{end}}`))
	reg := &TemplateRegistry{
		templates: map[string]*template.Template{"about.html": base},
		extraData: map[string]interface{}{},
	}
	buf := &bytes.Buffer{}
	if err := reg.Render(buf, "about.html", map[string]interface{}{"who": "world"}, echo.New().NewContext(nil, nil)); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "base:world" {
		t.Errorf("rendered %q, want base:world", buf.String())
	}
}
