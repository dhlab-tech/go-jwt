package gojwt

import jwtgo "github.com/dgrijalva/jwt-go"

// JWT represents a parsed and verified access token.
type JWT struct {
	Original []byte   `json:"original"` // contains original jwt
	Links    [][]byte `json:"links"`
}

// ClaimsJWT ...
type ClaimsJWT struct {
	jwtgo.StandardClaims
	JWT
}
