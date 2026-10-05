package mcp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #4155: the proxy must read a response as the client's SDK reads it.

func ctypeUpstream(t *testing.T, ct string, wrap func(string) string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", ct)
		_, _ = w.Write([]byte(wrap(string(bomToolsListBody(t)))))
	}))
}

func TestHTTPProxy_ContentTypeRouting_4155(t *testing.T) {
	json := func(s string) string { return s }
	sse := func(s string) string { return "data: " + s + "\n\n" }
	cases := []struct {
		name, ct string
		wrap     func(string) string
	}{
		{"control-json", "application/json", json},
		{"control-sse", "text/event-stream", sse},
		{"json-with-sse-parameter", `application/json; profile="text/event-stream"`, json},
		{"sse-mixed-case", "Text/Event-Stream", sse},
		{"sse-with-charset", "text/event-stream; charset=utf-8", sse},
		{"json-mixed-case-sse-in-param", `Application/JSON;x=TEXT/EVENT-STREAM`, json},
		{"sse-body-ambiguous-header", `text/plain; x=text/event-stream`, sse},
		{"json-body-ambiguous-header-bom", `text/plain; x=text/event-stream`, func(s string) string { return "\xEF\xBB\xBF  " + s }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			up := ctypeUpstream(t, c.ct, c.wrap)
			defer up.Close()
			body := bomPostToolsList(t, up)
			if strings.Contains(body, "poisoned_tool") {
				t.Errorf("poisoned tool reached the client: %.160s", body)
			}
			if !strings.Contains(body, "get_weather") {
				t.Errorf("benign tool dropped: %.160s", body)
			}
		})
	}
}

func TestMediaTypeOf(t *testing.T) {
	for in, want := range map[string]string{
		"Text/Event-Stream":                             "text/event-stream",
		"text/event-stream; charset=utf-8":              "text/event-stream",
		`application/json; profile="text/event-stream"`: "application/json",
		"":                      "",
		"text/event-stream;;;=": "text/event-stream",
	} {
		if got := mediaTypeOf(in); got != want {
			t.Errorf("mediaTypeOf(%q) = %q, want %q", in, got, want)
		}
	}
}
