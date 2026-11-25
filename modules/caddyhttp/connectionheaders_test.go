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

package caddyhttp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInvalidConnectionCredential(t *testing.T) {
	for _, tc := range []struct {
		name       string
		connection []string
		want       string
	}{
		{
			name:       "authorization token",
			connection: []string{"Authorization"},
			want:       "Authorization",
		},
		{
			name:       "case insensitive token",
			connection: []string{"authorization"},
			want:       "Authorization",
		},
		{
			name:       "comma list with whitespace",
			connection: []string{"keep-alive, authorization , X-Trace"},
			want:       "Authorization",
		},
		{
			name:       "multiple connection fields",
			connection: []string{"keep-alive", "Upgrade, Authorization"},
			want:       "Authorization",
		},
		{
			name:       "standard upgrade",
			connection: []string{"Upgrade"},
		},
		{
			name:       "ordinary connection option",
			connection: []string{"close, X-Internal"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := make(http.Header)
			for _, value := range tc.connection {
				h.Add("Connection", value)
			}
			if got := InvalidConnectionCredential(h); got != tc.want {
				t.Fatalf("InvalidConnectionCredential() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestServerServeHTTPRejectsAuthorizationConnectionOption(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Connection", "Authorization")
	req.Header.Set("Authorization", "Bearer must-not-cross")

	err := (&Server{}).serveHTTP(nil, req)
	var handlerErr HandlerError
	if !errors.As(err, &handlerErr) {
		t.Fatalf("serveHTTP() error = %v, want HandlerError", err)
	}
	if handlerErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("serveHTTP() status = %d, want %d", handlerErr.StatusCode, http.StatusBadRequest)
	}
}
