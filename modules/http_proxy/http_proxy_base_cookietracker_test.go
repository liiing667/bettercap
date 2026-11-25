package http_proxy

import (
	"net/http"
	"strings"
	"testing"
)

func newCookieTrackerRequest(host string) *http.Request {
	req := &http.Request{
		Method:     http.MethodGet,
		Host:       host,
		RemoteAddr: "192.0.2.10:49152",
		Header:     make(http.Header),
	}
	req.Header.Set("Cookie", "session=secret")
	return req
}

func TestCookieExpiryBindsRealOriginWithoutEmptyDomain(t *testing.T) {
	tracker := NewCookieTracker()
	req := newCookieTrackerRequest("auth.eu.example.com")

	resp := tracker.Expire(req)
	headers := resp.Header.Values("Set-Cookie")
	if len(headers) == 0 {
		t.Fatal("expected expiry cookies")
	}

	expected := []string{
		"domain=auth.eu.example.com",
		"domain=eu.example.com",
		"domain=example.com",
	}
	joined := strings.ToLower(strings.Join(headers, "\n"))
	for _, domain := range expected {
		if !strings.Contains(joined, domain) {
			t.Fatalf("expected %q in expiry headers: %v", domain, headers)
		}
	}

	for _, header := range headers {
		lower := strings.ToLower(header)
		if strings.Contains(lower, "domain=;") || strings.HasSuffix(strings.TrimSpace(lower), "domain=") {
			t.Fatalf("expiry header contains empty domain: %q", header)
		}
	}
}

func TestCookieExpirySuccessCommitsTrackerState(t *testing.T) {
	stripper := &SSLStripper{
		enabled: true,
		cookies: NewCookieTracker(),
		hosts:   NewHostTracker(),
	}
	req := newCookieTrackerRequest("example.com")

	if stripper.cookies.IsClean(req) {
		t.Fatal("cookie should start unknown")
	}
	if redir := stripper.Preprocess(req, nil); redir == nil {
		t.Fatal("expected expiry redirect")
	}
	if !stripper.cookies.IsClean(req) {
		t.Fatal("successful expiry should mark the request clean")
	}
}

func TestCookieExpiryOriginFailureKeepsTrackerUnknown(t *testing.T) {
	stripper := &SSLStripper{
		enabled: true,
		cookies: NewCookieTracker(),
		hosts:   NewHostTracker(),
	}
	req := newCookieTrackerRequest("not a valid cookie host")

	if redir := stripper.Preprocess(req, nil); redir != nil {
		t.Fatalf("unsafe origin should not be published as an expiry redirect: %v", redir.Header)
	}
	if stripper.cookies.IsClean(req) {
		t.Fatal("failed origin binding should not commit clean state")
	}
}
