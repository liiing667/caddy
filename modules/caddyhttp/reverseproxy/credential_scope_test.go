package reverseproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
)

// gsb39206CredentialTransport answers requests without opening sockets and
// records the Authorization value sent to each upstream.
type gsb39206CredentialTransport struct {
	mu       sync.Mutex
	status   map[string]int
	received map[string]string
}

func (t *gsb39206CredentialTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	if t.received == nil {
		t.received = make(map[string]string)
	}
	t.received[req.URL.Host] = req.Header.Get("Authorization")
	status := t.status[req.URL.Host]
	t.mu.Unlock()

	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}, nil
}

func (t *gsb39206CredentialTransport) authorizationFor(upstream string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.received[upstream]
}

func TestGSB39206ClientCredentialsNotReplayedToNewUpstream(t *testing.T) {
	transport := &gsb39206CredentialTransport{
		status: map[string]int{
			"first.example:80":  http.StatusServiceUnavailable,
			"second.example:80": http.StatusOK,
		},
	}

	// RoundRobin starts at index 1, so the first selection is the upstream
	// which asks for a retry; the retry then goes to second.example.
	upstreams := []*Upstream{
		{Host: new(Host), Dial: "second.example:80"},
		{Host: new(Host), Dial: "first.example:80"},
	}
	h := &Handler{
		logger:    zap.NewNop(),
		Transport: transport,
		Upstreams: upstreams,
		LoadBalancing: &LoadBalancing{
			Retries:         1,
			SelectionPolicy: &RoundRobinSelection{},
			RetryMatch: caddyhttp.MatcherSets{{
				newExpressionMatcher(t, `{http.reverse_proxy.status_code} == 503`),
			}},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Authorization", "Bearer client-token")
	req = prepareTestRequest(req)

	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusOK)
	}

	if got := transport.authorizationFor("first.example:80"); got != "Bearer client-token" {
		t.Errorf("first upstream Authorization: got %q, want %q", got, "Bearer client-token")
	}
	if got := transport.authorizationFor("second.example:80"); got != "" {
		t.Errorf("Authorization leaked to second upstream: %q", got)
	}
}

func TestGSB39206ExplicitHeaderUpKeepsAuthorizationAcrossUpstreams(t *testing.T) {
	transport := &gsb39206CredentialTransport{
		status: map[string]int{
			"first.example:80":  http.StatusServiceUnavailable,
			"second.example:80": http.StatusOK,
		},
	}

	upstreams := []*Upstream{
		{Host: new(Host), Dial: "second.example:80"},
		{Host: new(Host), Dial: "first.example:80"},
	}
	h := &Handler{
		logger:    zap.NewNop(),
		Transport: transport,
		Headers: &headers.Handler{
			Request: &headers.HeaderOps{
				Set: http.Header{
					"Authorization": []string{"{http.request.header.Authorization}"},
				},
			},
		},
		Upstreams: upstreams,
		LoadBalancing: &LoadBalancing{
			Retries:         1,
			SelectionPolicy: &RoundRobinSelection{},
			RetryMatch: caddyhttp.MatcherSets{{
				newExpressionMatcher(t, `{http.reverse_proxy.status_code} == 503`),
			}},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Authorization", "Bearer client-token")
	req = prepareTestRequest(req)

	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, upstream := range []string{"first.example:80", "second.example:80"} {
		if got := transport.authorizationFor(upstream); got != "Bearer client-token" {
			t.Errorf("%s Authorization: got %q, want %q", upstream, got, "Bearer client-token")
		}
	}
}

func TestGSB39206ClientCredentialsDoNotCrossHandlers(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Authorization", "Bearer client-token")
	req = prepareTestRequest(req)

	first := new(Handler)
	second := new(Handler)
	first.scopeClientCredentials(req, DialInfo{Address: "first.example:80"}, nil)
	second.scopeClientCredentials(req, DialInfo{Address: "second.example:80"}, nil)

	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization crossed handler boundary: %q", got)
	}
}

func TestGSB39206ClientCredentialsWithoutAuthorizationAreUnaffected(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = prepareTestRequest(req)

	first := new(Handler)
	second := new(Handler)
	first.scopeClientCredentials(req, DialInfo{Address: "first.example:80"}, nil)
	second.scopeClientCredentials(req, DialInfo{Address: "second.example:80"}, nil)

	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("unexpected Authorization header: %q", got)
	}
}
