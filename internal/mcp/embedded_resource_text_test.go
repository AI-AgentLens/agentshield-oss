package mcp

import (
	"encoding/base64"
	"reflect"
	"testing"
)

func TestWithEmbeddedResourceText4296(t *testing.T) {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	hidden := &ContentAnnotations{Audience: []string{"assistant"}}

	t.Run("wire items first and unchanged, projected text appended in order", func(t *testing.T) {
		items := []ContentItem{
			{Type: "resource", Annotations: hidden, Resource: &ResourceContentItem{URI: "file:///a.md", MIMEType: "text/markdown", Text: "alpha"}},
			{Type: "text", Text: "beta"},
			{Type: "resource", Resource: &ResourceContentItem{URI: "file:///c.txt", MIMEType: "text/plain", Blob: b64("gamma")}},
		}
		got := withEmbeddedResourceText(items)
		want := append(append([]ContentItem{}, items...),
			ContentItem{Type: "text", Text: "alpha", Annotations: hidden},
			ContentItem{Type: "text", Text: "gamma"},
		)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got  %+v\nwant %+v", got, want)
		}
	})

	t.Run("nothing to project returns the wire items as they are", func(t *testing.T) {
		items := []ContentItem{
			{Type: "text", Text: "plain"},
			{Type: "image", Data: b64("png"), MIMEType: "image/png"},
			{Type: "resource_link", URI: "file:///x"},
			{Type: "resource"}, // no resource object
			{Type: "resource", Resource: &ResourceContentItem{URI: "file:///empty"}},
			{Type: "text", Resource: &ResourceContentItem{Text: "a text item's stray resource is not a carrier"}},
		}
		got := withEmbeddedResourceText(items)
		if !reflect.DeepEqual(got, items) {
			t.Fatalf("got %+v, want the input unchanged", got)
		}
	})

	t.Run("text and blob on one resource are both projected", func(t *testing.T) {
		got := withEmbeddedResourceText([]ContentItem{{Type: "resource", Resource: &ResourceContentItem{
			URI: "file:///both", MIMEType: "text/plain", Text: "one", Blob: b64("two"),
		}}})
		if len(got) != 3 || got[1].Text != "one" || got[2].Text != "two" {
			t.Fatalf("got %+v, want the resource then its text then its decoded blob", got)
		}
	})

	t.Run("resource text is projected whatever its mimeType", func(t *testing.T) {
		got := withEmbeddedResourceText([]ContentItem{{Type: "resource", Resource: &ResourceContentItem{
			URI: "file:///x.png", MIMEType: "image/png", Text: "described as png",
		}}})
		if len(got) != 2 || got[1].Text != "described as png" {
			t.Fatalf("got %+v", got)
		}
	})
}

func TestTextualBlobText4296(t *testing.T) {
	const text = "hello, world"
	cases := []struct {
		name, mime, blob string
		want             string
		ok               bool
	}{
		{"padded standard alphabet", "text/plain", base64.StdEncoding.EncodeToString([]byte(text)), text, true},
		{"unpadded", "text/plain", base64.RawStdEncoding.EncodeToString([]byte(text)), text, true},
		{"line-wrapped", "text/plain", "aGVsbG8s\nIHdvcmxk", text, true},
		{"url-safe alphabet", "application/json", base64.URLEncoding.EncodeToString([]byte("{\"k\":\"??>\"}")), "{\"k\":\"??>\"}", true},
		{"invalid UTF-8 becomes U+FFFD, as encoding/json does to a text field", "text/plain",
			base64.StdEncoding.EncodeToString([]byte("ok\xffok")), "ok\uFFFDok", true},
		{"not base64", "text/plain", "%%%not-base64%%%", "", false},
		{"empty blob", "text/plain", "", "", false},
		{"decodes to nothing", "text/plain", "====", "", false},
		{"binary type", "application/octet-stream", base64.StdEncoding.EncodeToString([]byte(text)), "", false},
		{"untyped", "", base64.StdEncoding.EncodeToString([]byte(text)), "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := textualBlobText(&ResourceContentItem{MIMEType: tc.mime, Blob: tc.blob})
			if got != tc.want || ok != tc.ok {
				t.Fatalf("textualBlobText = (%q, %v), want (%q, %v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestIsTextualMIME4296(t *testing.T) {
	textual := []string{
		"text/plain", "text/markdown", "text/html", "text/csv", "TEXT/PLAIN",
		"text/plain; charset=utf-8", " text/plain ;charset=UTF-8", "application/json; charset=utf-8", "Application/LD+JSON;profile=x",
		"application/json", "application/xml", "application/yaml", "application/x-yaml",
		"application/toml", "application/javascript", "application/sql", "application/x-sh",
		"application/ld+json", "application/atom+xml", "application/vnd.api+json",
	}
	notTextual := []string{
		"", "text", "text/", "/plain", "plain",
		"application/octet-stream", "application/pdf", "application/zip",
		"application/x-www-form-urlencoded", "application/jsonx",
		"image/png", "image/svg+xml", "audio/mpeg", "video/mp4",
		"message/rfc822", "multipart/mixed",
	}
	for _, m := range textual {
		if !isTextualMIME(m) {
			t.Errorf("isTextualMIME(%q) = false, want true", m)
		}
	}
	for _, m := range notTextual {
		if isTextualMIME(m) {
			t.Errorf("isTextualMIME(%q) = true, want false", m)
		}
	}
}
