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

package caddy

import "testing"

func TestAdminConfigValidateLocalListen(t *testing.T) {
	for i, tc := range []struct {
		name    string
		listen  string
		origins []string // nil means the origins field is unset
		wantErr bool
	}{
		{
			name:   "default loopback hostname",
			listen: "localhost:2019",
		},
		{
			name:   "IPv4 loopback",
			listen: "127.0.0.1:2019",
		},
		{
			name:   "IPv6 loopback",
			listen: "[::1]:2019",
		},
		{
			name:   "unix socket relies on filesystem permissions",
			listen: "unix//run/caddy-admin.sock",
		},
		{
			name:   "fd network relies on the inherited listener",
			listen: "fd/3",
		},
		{
			name:    "wildcard IPv4 without origins is rejected",
			listen:  "0.0.0.0:2019",
			wantErr: true,
		},
		{
			name:    "wildcard IPv6 without origins is rejected",
			listen:  "[::]:2019",
			wantErr: true,
		},
		{
			name:    "bare port wildcard without origins is rejected",
			listen:  ":2019",
			wantErr: true,
		},
		{
			name:    "specific LAN address without origins is rejected",
			listen:  "192.168.1.10:2019",
			wantErr: true,
		},
		{
			name:    "non-loopback hostname without origins is rejected",
			listen:  "admin.example.com:2019",
			wantErr: true,
		},
		{
			name:    "wildcard address with explicit origins is allowed",
			listen:  "0.0.0.0:2019",
			origins: []string{"admin.example.com:2019"},
		},
		{
			name:    "LAN address with explicit origins is allowed",
			listen:  "192.168.1.10:2019",
			origins: []string{"192.168.1.10:2019"},
		},
		{
			name:    "explicitly empty origins counts as a deliberate policy",
			listen:  "0.0.0.0:2019",
			origins: []string{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := parseAdminListenAddr(tc.listen, DefaultAdminListen)
			if err != nil {
				t.Fatalf("test %d: unexpected parse error for %q: %v", i, tc.listen, err)
			}
			adminCfg := AdminConfig{Listen: tc.listen}
			if tc.origins != nil {
				adminCfg.Origins = tc.origins
			}
			err = adminCfg.validateLocalListen(addr)
			if tc.wantErr && err == nil {
				t.Errorf("test %d (%s): validateLocalListen(%q) = nil, want error", i, tc.name, tc.listen)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("test %d (%s): validateLocalListen(%q) = %v, want nil", i, tc.name, tc.listen, err)
			}
		})
	}
}

// TestReplaceLocalAdminServerRejectsOpenListener verifies the validation
// runs on the actual startup path, so an unauthenticated admin endpoint
// bound to a non-loopback interface is refused rather than started with a
// mere warning. The error must be returned before any listener is created;
// the accepted (explicit-origins and loopback) cases are covered by
// TestAdminConfigValidateLocalListen.
func TestReplaceLocalAdminServerRejectsOpenListener(t *testing.T) {
	cfg := &Config{
		Admin: &AdminConfig{
			Listen: "0.0.0.0:2999",
		},
	}

	if err := replaceLocalAdminServer(cfg, Context{}); err == nil {
		t.Fatal("replaceLocalAdminServer with a wildcard listener and no origins: expected error, got nil")
	}
}
