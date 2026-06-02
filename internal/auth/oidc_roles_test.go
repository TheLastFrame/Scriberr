package auth

import "testing"

func TestOIDCClaimsHasAdminRole(t *testing.T) {
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
			if got := tt.claims.hasAdminRole(); got != tt.want {
				t.Fatalf("hasAdminRole() = %v, want %v", got, tt.want)
			}
		})
	}
}
