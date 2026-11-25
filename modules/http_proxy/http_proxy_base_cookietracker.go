package http_proxy

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/elazarl/goproxy"
	"github.com/jpillora/go-tld"
	"golang.org/x/net/idna"
)

const cookieExpires = "Mon, 01-Jan-1990 00:00:00 GMT"

var errUnknownCookieOrigin = errors.New("could not determine cookie origin")

type CookieTracker struct {
	sync.RWMutex
	set map[string]bool
}

func NewCookieTracker() *CookieTracker {
	return &CookieTracker{
		set: make(map[string]bool),
	}
}

func normalizeHost(req *http.Request) string {
	if req == nil {
		return ""
	}

	host := (&url.URL{Host: req.Host}).Hostname()
	if host == "" && req.URL != nil {
		host = req.URL.Hostname()
	}

	host = strings.Trim(strings.TrimSpace(strings.ToLower(host)), ".")
	if asciiHost, err := idna.ToASCII(host); err == nil {
		host = asciiHost
	}

	return host
}

func cookieOrigin(req *http.Request) (string, error) {
	host := normalizeHost(req)
	if host == "" {
		return "", errUnknownCookieOrigin
	}

	// IP literals are valid origins. A Domain attribute is only emitted when
	// net/http considers that literal a legal cookie domain.
	if net.ParseIP(host) != nil {
		return host, nil
	}

	if !validCookieDomain(host) {
		return "", fmt.Errorf("%w: %q", errUnknownCookieOrigin, host)
	}

	return host, nil
}

func validCookieDomain(domain string) bool {
	if domain == "" {
		return false
	}
	return (&http.Cookie{Name: "bettercap-domain-check", Value: "1", Domain: domain}).Valid() == nil
}

func clientIPFromRemoteAddr(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil && host != "" {
		return host
	}
	return remoteAddr
}

func (t *CookieTracker) domainOf(req *http.Request) string {
	host := normalizeHost(req)
	if host == "" {
		return ""
	}
	// tld.Parse delegates to url.Parse; a bare "example.com" is parsed as a
	// path rather than a host. Give it an explicit scheme so registrable
	// domain extraction works for server requests.
	if parsed, err := tld.Parse("http://" + host); err == nil && parsed.Domain != "" && parsed.TLD != "" {
		domain := strings.ToLower(parsed.Domain + "." + parsed.TLD)
		if validCookieDomain(domain) {
			return domain
		}
	}
	return host
}

func (t *CookieTracker) keyOf(req *http.Request) string {
	client := clientIPFromRemoteAddr(req.RemoteAddr)

	// Bind state to the exact origin. The registrable domain alone would
	// incorrectly share cleanup state between sibling hosts such as
	// tenant-a.example.com and tenant-b.example.com.
	domain, err := cookieOrigin(req)
	if err != nil {
		domain = t.domainOf(req)
	}

	return fmt.Sprintf("%s-%s", client, domain)
}

func (t *CookieTracker) IsClean(req *http.Request) bool {
	// we only clean GET requests
	if req.Method != "GET" {
		return true
	}

	// does the request have any cookie?
	cookie := req.Header.Get("Cookie")
	if cookie == "" {
		return true
	}

	t.RLock()
	defer t.RUnlock()

	// was it already processed?
	if _, found := t.set[t.keyOf(req)]; found {
		return true
	}

	// unknown session cookie
	return false
}

func (t *CookieTracker) Track(req *http.Request) {
	t.Lock()
	defer t.Unlock()
	t.set[t.keyOf(req)] = true
}

// expiryDomains returns the legal Domain attributes which can address the
// cookie scopes visible from req. The exact origin covers host-only and
// exact-domain cookies, while parent domains cover explicit multi-domain
// cookies. The registrable domain is the broadest normal scope emitted.
func (t *CookieTracker) expiryDomains(req *http.Request) (string, []string, error) {
	origin, err := cookieOrigin(req)
	if err != nil {
		return "", nil, err
	}

	domains := make([]string, 0)
	seen := make(map[string]bool)
	add := func(domain string) {
		domain = strings.TrimPrefix(strings.ToLower(domain), ".")
		if domain == "" || seen[domain] || !validCookieDomain(domain) {
			return
		}
		seen[domain] = true
		domains = append(domains, domain)
	}

	add(origin)

	registrable := t.domainOf(req)
	if registrable != "" && registrable != origin && strings.HasSuffix(origin, "."+registrable) {
		suffix := origin
		for suffix != registrable {
			idx := strings.Index(suffix, ".")
			if idx < 0 {
				break
			}
			suffix = suffix[idx+1:]
			add(suffix)
			if suffix == registrable {
				break
			}
		}
	} else {
		add(registrable)
	}

	return origin, domains, nil
}

func addExpiredCookie(header http.Header, name, domain string) {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("%s=EXPIRED; path=/", name))
	if domain != "" {
		builder.WriteString("; domain=")
		builder.WriteString(domain)
	}
	builder.WriteString("; Expires=")
	builder.WriteString(cookieExpires)
	header.Add("Set-Cookie", builder.String())
}

func expiryLocation(req *http.Request) string {
	scheme := "http"
	host := ""
	if req != nil {
		if req.URL != nil {
			if req.URL.Scheme == "https" {
				scheme = "https"
			}
			host = req.URL.Host
		}
		if req.TLS != nil {
			scheme = "https"
		}
		if req.Host != "" {
			host = req.Host
		}
	}
	return fmt.Sprintf("%s://%s/", scheme, host)
}

func (t *CookieTracker) expire(req *http.Request) (*http.Response, error) {
	redir := goproxy.NewResponse(req, "text/plain", http.StatusFound, "")

	_, domains, originErr := t.expiryDomains(req)

	for _, cookie := range req.Cookies() {
		if originErr != nil || len(domains) == 0 {
			// Omitting Domain creates a host-only expiry. Never serialize
			// an empty Domain= attribute.
			addExpiredCookie(redir.Header, cookie.Name, "")
			continue
		}

		for _, domain := range domains {
			addExpiredCookie(redir.Header, cookie.Name, domain)
		}
	}

	redir.Header.Add("Location", expiryLocation(req))
	redir.Header.Add("Connection", "close")

	return redir, originErr
}

// Expire keeps the historical one-value API. The request preprocessing path
// uses expire directly so it can avoid committing state when the origin
// cannot be determined.
func (t *CookieTracker) Expire(req *http.Request) *http.Response {
	resp, _ := t.expire(req)
	return resp
}
