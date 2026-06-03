package auth

import "testing"

func TestOIDCClaimsHasRole(t *testing.T) {
	tests := []struct {
		name   string
		claims oidcClaims
		want   bool
	}{
		{
			name: "realm admin role",
			claims: oidcClaims{
				RealmAccess: oidcRoleAccess{Roles: []string{"admin"}},
			},
			want: true,
		},
		{
			name: "client admin role",
			claims: oidcClaims{
				ResourceAccess: map[string]oidcRoleAccess{
					"scriberr": {Roles: []string{"admin"}},
				},
			},
			want: true,
		},
		{
			name: "admin group",
			claims: oidcClaims{
				Groups: []string{"/admin"},
			},
			want: true,
		},
		{
			name: "non-admin role",
			claims: oidcClaims{
				RealmAccess: oidcRoleAccess{Roles: []string{"user"}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := tt.claims.hasRole("admin", parseOIDCRoleClaims(""))
			if got != tt.want {
				t.Fatalf("hasRole(admin) = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOIDCClaimsHasRoleUsesConfiguredRoleName(t *testing.T) {
	claims := oidcClaims{
		RealmAccess: oidcRoleAccess{Roles: []string{"scriberr-admin"}},
	}

	got, _ := claims.hasRole("scriberr-admin", parseOIDCRoleClaims(""))
	if !got {
		t.Fatal("expected configured role to grant admin")
	}
	got, _ = claims.hasRole("admin", parseOIDCRoleClaims(""))
	if got {
		t.Fatal("did not expect hardcoded admin role to match when only configured role is present")
	}
}

func TestOIDCClaimsHasRoleUsesConfiguredClaimLocations(t *testing.T) {
	claims := oidcClaims{
		RealmAccess: oidcRoleAccess{Roles: []string{"admin"}},
		ResourceAccess: map[string]oidcRoleAccess{
			"scriberr": {Roles: []string{"admin"}},
		},
	}

	got, adminClaim := claims.hasRole("admin", parseOIDCRoleClaims("resource_access.scriberr.roles"))
	if !got {
		t.Fatal("expected configured client role claim to grant admin")
	}
	if adminClaim != "resource_access.scriberr.roles" {
		t.Fatalf("admin claim = %q, want resource_access.scriberr.roles", adminClaim)
	}
	got, _ = claims.hasRole("admin", parseOIDCRoleClaims("groups"))
	if got {
		t.Fatal("did not expect disabled role claim locations to grant admin")
	}
}

func TestParseOIDCRoleClaims(t *testing.T) {
	claims := parseOIDCRoleClaims(" groups, realm_access.roles,groups ,,resource_access.scriberr.roles ")
	want := []string{"groups", "realm_access.roles", "resource_access.scriberr.roles"}
	if len(claims) != len(want) {
		t.Fatalf("parseOIDCRoleClaims length = %d, want %d (%v)", len(claims), len(want), claims)
	}
	for i := range want {
		if claims[i] != want[i] {
			t.Fatalf("parseOIDCRoleClaims[%d] = %q, want %q", i, claims[i], want[i])
		}
	}
}
