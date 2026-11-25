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

package reverseproxy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
)

func TestConnectionNominationOfAuthorizationIsRejectedBeforeProxying(t *testing.T) {
	var roundTrips atomic.Int32
	h := minimalHandler(2, &Upstream{Host: new(Host), Dial: "unused.invalid"})

	// Header operations are reapplied on retry and can recompute a credential.
	// The request must fail before the retry loop rather than allowing this op
	// to recreate the protected header.
	h.Headers = &headers.Handler{Request: &headers.HeaderOps{
		Set: http.Header{"Authorization": []string{"Bearer recomputed-credential"}},
	}}
	h.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		roundTrips.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       http.NoBody,
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Connection", "Authorization")
	req.Header.Set("Authorization", "Bearer client-credential")
	req = prepareTestRequest(req)

	_, err := h.prepareRequest(req, caddy.NewReplacer())
	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) {
		t.Fatalf("prepareRequest() error = %v, want HandlerError", err)
	}
	if handlerErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("prepareRequest() status = %d, want %d", handlerErr.StatusCode, http.StatusBadRequest)
	}

	err = h.ServeHTTP(httptest.NewRecorder(), req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		t.Fatal("next handler called after invalid Connection header")
		return nil
	}))
	if !errors.As(err, &handlerErr) {
		t.Fatalf("ServeHTTP() error = %v, want HandlerError", err)
	}
	if handlerErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("ServeHTTP() status = %d, want %d", handlerErr.StatusCode, http.StatusBadRequest)
	}
	if got := roundTrips.Load(); got != 0 {
		t.Fatalf("upstream round trips = %d, want 0", got)
	}
}

func TestPrepareRequestAllowsStandardUpgrade(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req = prepareTestRequest(req)

	prepared, err := (Handler{}).prepareRequest(req, caddy.NewReplacer())
	if err != nil {
		t.Fatalf("prepareRequest() error = %v, want nil", err)
	}
	if got := prepared.Header.Get("Connection"); got != "Upgrade" {
		t.Errorf("Connection = %q, want Upgrade", got)
	}
	if got := prepared.Header.Get("Upgrade"); got != "websocket" {
		t.Errorf("Upgrade = %q, want websocket", got)
	}
}
