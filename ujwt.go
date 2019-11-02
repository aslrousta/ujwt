package ujwt

import (
	"errors"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	// ErrInvalidSecretKey reports that secret key is empty.
	ErrInvalidSecretKey = errors.New("secret key is empty")

	// ErrInvalidSiginingMethod reports that signing method is invalid.
	ErrInvalidSiginingMethod = errors.New("invalid signing method")

	// ErrInvalidUser reports that user is empty.
	ErrInvalidUser = errors.New("user is empty")
)

// Claims is the payload for JWT.
type Claims struct {
	jwt.StandardClaims
	Roles []string `json:"roles,omitempty"`
}

// User returns the authenticated user.
func (c *Claims) User() string {
	return c.Subject
}

// HasRole returns true if claim has a specific role, and false otherwise.
func (c *Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// Issue creates a new JWT.
func Issue(secretKey, user, domain string, roles []string) (string, error) {
	if secretKey == "" {
		return "", ErrInvalidSecretKey
	}

	if user == "" {
		return "", ErrInvalidUser
	}

	c := Claims{
		StandardClaims: jwt.StandardClaims{
			IssuedAt: time.Now().Unix(),
			Issuer:   domain,
			Subject:  user,
		},
		Roles: roles,
	}

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, c)

	token, err := t.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}

	return token, nil
}

// Parse validates and decrypts a JWT and fills c with its payload.
func Parse(secretKey, token string, c *Claims) error {
	if secretKey == "" {
		return ErrInvalidSecretKey
	}

	_, err := jwt.ParseWithClaims(token, c, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, ErrInvalidSiginingMethod
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return err
	}

	return nil
}
