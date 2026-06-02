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
			if got := tt.claims.hasRole("admin"); got != tt.want {
				t.Fatalf("hasRole(admin) = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOIDCClaimsHasRoleUsesConfiguredRoleName(t *testing.T) {
	claims := oidcClaims{
		RealmAccess: oidcRoleAccess{Roles: []string{"scriberr-admin"}},
	}

	if !claims.hasRole("scriberr-admin") {
		t.Fatal("expected configured role to grant admin")
	}
	if claims.hasRole("admin") {
		t.Fatal("did not expect hardcoded admin role to match when only configured role is present")
	}
}
