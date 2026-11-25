package http_proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bettercap/bettercap/v2/session"
	btls "github.com/bettercap/bettercap/v2/tls"
)

func newTestCA(t *testing.T, name string) *tls.Certificate {
	t.Helper()
	dir := t.TempDir()
	ca, err := btls.GenerateAndLoad(btls.CertConfig{Bits: 2048, CommonName: name},
		filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"), true)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestProxySignerIsolation(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()

	newProxy := func(ca *tls.Certificate) (*HTTPProxy, *url.URL) {
		t.Helper()
		sess, _ := createMockSession()
		p := NewHTTPProxy(sess, "test")
		if ca != nil {
			if err := p.ConfigureTLS("127.0.0.1", 0, 0, false, "", ca, "", false, 2048); err != nil {
				t.Fatal(err)
			}
		}
		p.Proxy.Tr = origin.Client().Transport.(*http.Transport).Clone()
		t.Cleanup(p.Proxy.Tr.CloseIdleConnections)
		listener := httptest.NewServer(p.Proxy)
		t.Cleanup(listener.Close)
		addr, err := url.Parse(listener.URL)
		if err != nil {
			t.Fatal(err)
		}
		return p, addr
	}
	check := func(addr *url.URL, ca *tls.Certificate, trusted bool) {
		t.Helper()
		roots := x509.NewCertPool()
		roots.AddCert(ca.Leaf)
		tr := &http.Transport{Proxy: http.ProxyURL(addr), TLSClientConfig: &tls.Config{RootCAs: roots}}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		resp, err := client.Get(origin.URL)
		if err != nil {
			var unknown x509.UnknownAuthorityError
			if trusted || !errors.As(err, &unknown) {
				t.Fatalf("unexpected TLS result: %v", err)
			}
			return
		}
		defer resp.Body.Close()
		if !trusted || resp.StatusCode != http.StatusNoContent {
			t.Fatalf("trusted=%t, got HTTP %s", trusted, resp.Status)
		}
	}

	firstCA, secondCA := newTestCA(t, "first"), newTestCA(t, "second")
	_, plain := newProxy(nil)
	first, firstURL := newProxy(firstCA)
	_, secondURL := newProxy(secondCA)
	check(firstURL, firstCA, true)
	check(secondURL, secondCA, true)
	check(plain, secondCA, false)
	check(firstURL, secondCA, false)

	if err := first.ConfigureTLS("127.0.0.1", 0, 0, false, "", secondCA, "", false, 2048); err != nil {
		t.Fatal(err)
	}
	check(firstURL, firstCA, false)
	check(firstURL, secondCA, true)
}

func TestRejectedHandshakeHasNoSuccessEvent(t *testing.T) {
	sess, _ := createMockSession()
	proxy := NewHTTPProxy(sess, "test")
	origin := httptest.NewTLSServer(http.NotFoundHandler())
	defer origin.Close()
	cfg, err := proxy.TLSConfigFromCA(newTestCA(t, "private test CA"))(origin.Listener.Addr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	deadline := time.Now().Add(5 * time.Second)
	server.SetDeadline(deadline)
	client.SetDeadline(deadline)
	done := make(chan error, 1)
	go func() { done <- tls.Server(server, cfg).Handshake() }()
	untrusted := &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13}
	var unknown x509.UnknownAuthorityError
	if err := tls.Client(client, untrusted).Handshake(); !errors.As(err, &unknown) {
		t.Fatalf("expected the client to reject the test CA, got %v", err)
	}
	if err := <-done; err == nil {
		t.Fatal("expected the server handshake to fail")
	}
	for _, e := range sess.Events.Sorted() {
		if msg, ok := e.Data.(session.LogMessage); ok && strings.Contains(msg.Message, "handshake established") {
			t.Fatalf("premature success event: %s", msg.Message)
		}
	}
}

func TestWildcardCertificateIsNotCached(t *testing.T) {
	sess, _ := createMockSession()
	proxy := NewHTTPProxy(sess, "test")

	// Port 1 on loopback is refused immediately, so SignCertificateForHost
	// takes its offline fallback path and the test stays hermetic.
	signer := proxy.TLSConfigFromCA(newTestCA(t, "wildcard test CA"))

	leafDER := func(cfg *tls.Config) []byte {
		t.Helper()
		if len(cfg.Certificates) == 0 || len(cfg.Certificates[0].Certificate) == 0 {
			t.Fatal("signed config carries no certificate")
		}
		return cfg.Certificates[0].Certificate[0]
	}

	// A concrete host is cached: both calls must return the same leaf.
	firstConcrete, err := signer("concrete.example.com:1", nil)
	if err != nil {
		t.Fatalf("first concrete signing failed: %v", err)
	}
	secondConcrete, err := signer("concrete.example.com:1", nil)
	if err != nil {
		t.Fatalf("second concrete signing failed: %v", err)
	}
	if !bytes.Equal(leafDER(firstConcrete), leafDER(secondConcrete)) {
		t.Fatal("concrete host certificates were not reused from the cache")
	}

	// IPs are concrete names too and keep being cached.
	firstIP, err := signer("127.0.0.1:1", nil)
	if err != nil {
		t.Fatalf("first IP signing failed: %v", err)
	}
	secondIP, err := signer("127.0.0.1:1", nil)
	if err != nil {
		t.Fatalf("second IP signing failed: %v", err)
	}
	if !bytes.Equal(leafDER(firstIP), leafDER(secondIP)) {
		t.Fatal("IP certificates were not reused from the cache")
	}

	// Wildcard names must never be cached: every connection gets a freshly
	// signed leaf with its own key, so no two tenants share a certificate.
	wildcardCerts := make(map[string]bool)
	for i := 0; i < 3; i++ {
		cfg, err := signer("*.shared.example.com:1", nil)
		if err != nil {
			t.Fatalf("wildcard signing %d failed: %v", i, err)
		}
		der := leafDER(cfg)
		if wildcardCerts[string(der)] {
			t.Fatalf("wildcard certificate reused on connection %d", i)
		}
		wildcardCerts[string(der)] = true

		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse wildcard leaf %d: %v", i, err)
		}
		if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "*.shared.example.com" {
			t.Fatalf("connection %d: wildcard SAN not preserved, got %v", i, leaf.DNSNames)
		}
	}
}

func TestCALookupLeavesRevocationRequestsAlone(t *testing.T) {
	sess, _ := createMockSession()
	p := NewHTTPProxy(sess, "test")
	cfg := btls.CAConfig{Mode: "emudhra", Emudhra: "auto", Chain: "emSign"}
	if _, err := cfg.Resolve(); err != nil {
		t.Fatal(err)
	}
	for _, excluded := range []bool{false, true} {
		if excluded {
			p.Blacklist = []string{"*"}
		}
		for _, u := range []string{"http://ocsp.emsign.com/", "http://crl.comodoca.com/example.crl"} {
			req := httptest.NewRequest(http.MethodGet, u, nil)
			got, resp := p.onRequestFilter(req, nil)
			if got != req || resp != nil {
				t.Fatalf("revocation request replaced for %s (excluded=%t)", u, excluded)
			}
		}
	}
}
