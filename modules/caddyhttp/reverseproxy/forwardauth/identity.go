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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(IdentityGuard{})
}

// IdentityGuard verifies detached signatures on identity headers returned
// by a forward-auth responder before the headers are copied into the
// original request.
type IdentityGuard struct {
	// Identities are the auth-response headers that are allowed to carry
	// identity into the request handled by the rest of the route chain.
	Identities []IdentityHeader `json:"identities,omitempty"`

	// SigningKey is the shared HMAC key used to verify detached signatures.
	// It may contain Caddy placeholders, for example an environment variable.
	SigningKey string `json:"signing_key,omitempty"`

	// AllowUnsigned explicitly disables verification. It is only emitted for
	// configurations that opt into trusting the auth responder's headers
	// without a detached signature.
	AllowUnsigned bool `json:"allow_unsigned,omitempty"`
}

// IdentityHeader describes one copied identity header.
type IdentityHeader struct {
	// Source is the canonical auth-response header name.
	Source string `json:"source,omitempty"`

	// Target is the canonical request header name that receives the value.
	Target string `json:"target,omitempty"`

	// SignatureHeader optionally overrides the detached signature header.
	// The default is Source + "-Signature".
	SignatureHeader string `json:"signature_header,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (IdentityGuard) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.forward_auth_identity_guard",
		New: func() caddy.Module { return new(IdentityGuard) },
	}
}

// ServeHTTP verifies all non-empty identity values before later response
// routes copy them onto the original request.
func (g IdentityGuard) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if g.AllowUnsigned {
		return next.ServeHTTP(w, r)
	}

	repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok || repl == nil {
		return caddyhttp.Error(http.StatusInternalServerError, errors.New("missing replacer for forward_auth identity verification"))
	}

	signingKey := []byte(repl.ReplaceAll(g.SigningKey, ""))

	for _, identity := range g.Identities {
		source := http.CanonicalHeaderKey(identity.Source)
		target := http.CanonicalHeaderKey(identity.Target)
		value := authResponseHeader(repl, source)

		// An absent identity is safe: the generated route has already deleted
		// the client-supplied value and the conditional Set operation will be
		// skipped by its empty-value matcher.
		if value == "" {
			r.Header.Del(target)
			continue
		}

		signatureHeader := identity.SignatureHeader
		if signatureHeader == "" {
			signatureHeader = source + "-Signature"
		}
		signature := authResponseHeader(repl, http.CanonicalHeaderKey(signatureHeader))

		if len(signingKey) == 0 || signature == "" || !validIdentitySignature(signingKey, identity, value, signature) {
			// Do not leave a stale client value behind if this guard is used
			// in a chain that recovers from the returned error.
			if r.Header != nil {
				r.Header.Del(target)
			}
			return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("forward_auth identity header %q does not have a valid signature", target))
		}
	}

	return next.ServeHTTP(w, r)
}

func authResponseHeader(repl *caddy.Replacer, name string) string {
	placeholder := "http.reverse_proxy.header." + http.CanonicalHeaderKey(name)
	return repl.ReplaceAll("{"+placeholder+"}", "")
}

func validIdentitySignature(key []byte, identity IdentityHeader, value, encodedSignature string) bool {
	encodedSignature = strings.TrimPrefix(strings.TrimSpace(encodedSignature), "sha256=")

	signature, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil {
		signature, err = base64.StdEncoding.DecodeString(encodedSignature)
		if err != nil {
			return false
		}
	}

	mac := hmac.New(sha256.New, key)
	writeLengthPrefixed(mac, "caddy-forward-auth-identity-v1")
	writeLengthPrefixed(mac, http.CanonicalHeaderKey(identity.Source))
	writeLengthPrefixed(mac, http.CanonicalHeaderKey(identity.Target))
	writeLengthPrefixed(mac, value)

	return hmac.Equal(signature, mac.Sum(nil))
}

func writeLengthPrefixed(h hash.Hash, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = h.Write(length[:])
	_, _ = h.Write([]byte(value))
}

var (
	_ caddy.Module                = (*IdentityGuard)(nil)
	_ caddyhttp.MiddlewareHandler = (*IdentityGuard)(nil)
)
