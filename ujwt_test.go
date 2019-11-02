package ujwt_test

import (
	"reflect"
	"testing"

	"github.com/aslrousta/ujwt"
)

func TestClaims_HasRole(t *testing.T) {
	c := ujwt.Claims{
		Roles: []string{"member"},
	}

	tests := []struct {
		name string
		c    ujwt.Claims
		r    string
		want bool
	}{
		{"Exist", c, "member", true},
		{"Absent", c, "admin", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.HasRole(tt.r); got != tt.want {
				t.Errorf("Claims.HasRole() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIssue(t *testing.T) {
	t.Run("InvalidSecretKey", func(t *testing.T) {
		_, err := ujwt.Issue("", "user", "domain", []string{"member"})
		if err != ujwt.ErrInvalidSecretKey {
			t.Errorf("expect ErrInvalidSecretKey, got %v", err)
		}
	})

	t.Run("InvalidUser", func(t *testing.T) {
		_, err := ujwt.Issue("somerandomkey", "", "domain", []string{"member"})
		if err != ujwt.ErrInvalidUser {
			t.Errorf("expected ErrInvalidUser, got %v", err)
		}
	})

	t.Run("Valid", func(t *testing.T) {
		token, err := ujwt.Issue("somerandomkey", "user", "domain", []string{"member"})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if token == "" {
			t.Error("token is empty")
		}
	})
}

func TestParse(t *testing.T) {
	t.Run("InvalidSecretKey", func(t *testing.T) {
		err := ujwt.Parse("", "", nil)
		if err != ujwt.ErrInvalidSecretKey {
			t.Errorf("expected ErrInvalidSecretKey, got %v", err)
		}
	})

	key := "somerandomkey"
	user := "user"
	domain := "example.com"
	roles := []string{"member"}

	token, _ := ujwt.Issue(key, user, domain, roles)

	t.Run("Valid", func(t *testing.T) {
		var c ujwt.Claims

		if err := ujwt.Parse(key, token, &c); err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if err := c.Valid(); err != nil {
			t.Errorf("unexpected validation error: %v", err)
		}

		if c.Subject != user {
			t.Errorf("expected subject = %q, got %q", user, c.Subject)
		}

		if c.Issuer != domain {
			t.Errorf("expected issuer = %q, got %q", domain, c.Issuer)
		}

		if !reflect.DeepEqual(c.Roles, roles) {
			t.Errorf("expected roles = %v, got %v", roles, c.Roles)
		}
	})
}
