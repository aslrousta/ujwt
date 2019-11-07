# uJWT

![Go Version](https://img.shields.io/github/go-mod/go-version/aslrousta/ujwt)
[![GoDoc](https://godoc.org/github.com/aslrousta/ujwt?status.svg)](https://godoc.org/github.com/aslrousta/ujwt)
![License](https://img.shields.io/github/license/aslrousta/ujwt)

uJWT is a dead simple JWT claim with user metadata. It currently contains user's name and roles.

## Quick Start

In order to generate a new token, use `Issue` function, e.g.:

```go
func generateMemberToken(user string) (string, error) {
  secretKey := os.Getenv("SECRET_KEY")
  domain := os.Getenv("DOMAIN")
  
  return ujwt.Issue(secretKey, user, domain, []string{"member"})
}
```

And, to decode a token, use `Parse` function, e.g.:

```go
func isMember(token string) (bool, error) {
  secretKey := os.Getenv("SECRET_KEY")
  
  var c ujwt.Claims
  if err := ujwt.Parse(secretKey, token, &c); err != nil {
    return false, err
  }
  
  return c.HasRole("member"), nil
}
```

## License

uJWT is published under MIT license.
