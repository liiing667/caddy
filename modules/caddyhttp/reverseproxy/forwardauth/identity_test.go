// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package forwardauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestCaddyfileIdentityPolicy(t *testing.T) {
	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		t.Fatal("caddyfile adapter not registered")
	}

	for _, tc := range []struct {
		name       string
		directive  string
		wantGuard  bool
		wantSubstr string
	}{
		{
			name:      "unsigned headers are guarded by default",
			directive: "",
			wantGuard: true,
		},
		{
			name:       "signing key is wired into guard",
			directive:  "identity_signing_key secret",
			wantGuard:  true,
			wantSubstr: `"signing_key":"secret"`,
		},
		{
			name:      "explicit trust omits guard",
			directive: "trust_unsigned_identity_headers",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := `:8080 {
				forward_auth 127.0.0.1:9000 {
					uri /auth
					copy_headers X-User
					` + tc.directive + `
				}
			}`
			data, _, err := adapter.Adapt([]byte(config), nil)
			if err != nil {
				t.Fatalf("adapt failed: %v", err)
			}

			gotGuard := strings.Contains(string(data), `"handler":"forward_auth_identity_guard"`)
			if gotGuard != tc.wantGuard {
				t.Fatalf("guard present = %v, want %v; config: %s", gotGuard, tc.wantGuard, data)
			}
			if tc.wantSubstr != "" && !strings.Contains(string(data), tc.wantSubstr) {
				t.Fatalf("adapted config missing %q: %s", tc.wantSubstr, data)
			}
		})
	}
}

func TestIdentityGuard(t *testing.T) {
	const signingKey = "test-signing-key"

	signature := func(value string) string {
		mac := hmac.New(sha256.New, []byte(signingKey))
		writeLengthPrefixed(mac, "caddy-forward-auth-identity-v1")
		writeLengthPrefixed(mac, "X-User")
		writeLengthPrefixed(mac, "X-User")
		writeLengthPrefixed(mac, value)
		return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}

	for _, tc := range []struct {
		name          string
		authUser      string
		signature     string
		signingKey    string
		allowUnsigned bool
		wantStatus    int
		wantNext      bool
		wantHeader    string
	}{
		{
			name:       "missing signature is rejected",
			authUser:   "unsigned",
			signingKey: signingKey,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "empty signing key cannot validate",
			authUser:   "unsigned",
			signature:  signature("unsigned"),
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "invalid signature is rejected",
			authUser:   "alice",
			signature:  signature("bob"),
			signingKey: signingKey,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "valid signature is allowed",
			authUser:   "alice",
			signature:  signature("alice"),
			signingKey: signingKey,
			wantNext:   true,
		},
		{
			name:       "absent auth identity clears client value and continues",
			signingKey: signingKey,
			wantNext:   true,
		},
		{
			name:          "explicit unsigned trust continues",
			authUser:      "alice",
			allowUnsigned: true,
			wantNext:      true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-User", "attacker")

			repl := caddy.NewReplacer()
			if tc.authUser != "" {
				repl.Set("http.reverse_proxy.header.X-User", tc.authUser)
			}
			if tc.signature != "" {
				repl.Set("http.reverse_proxy.header.X-User-Signature", tc.signature)
			}
			req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))

			nextCalled := false
			next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
				nextCalled = true
				return nil
			})

			guard := IdentityGuard{
				Identities:    []IdentityHeader{{Source: "X-User", Target: "X-User"}},
				SigningKey:    tc.signingKey,
				AllowUnsigned: tc.allowUnsigned,
			}
			err := guard.ServeHTTP(httptest.NewRecorder(), req, next)

			if tc.wantStatus != 0 {
				var handlerErr caddyhttp.HandlerError
				if !errors.As(err, &handlerErr) {
					t.Fatalf("expected HandlerError, got %T: %v", err, err)
				}
				if handlerErr.StatusCode != tc.wantStatus {
					t.Fatalf("status = %d, want %d", handlerErr.StatusCode, tc.wantStatus)
				}
				if got := req.Header.Get("X-User"); got != "" {
					t.Fatalf("client identity survived rejection: %q", got)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if nextCalled != tc.wantNext {
				t.Fatalf("next called = %v, want %v", nextCalled, tc.wantNext)
			}
		})
	}
}
