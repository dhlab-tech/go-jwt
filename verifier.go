package gojwt

import (
	"crypto/rsa"
	"fmt"

	jwtgo "github.com/dgrijalva/jwt-go"
)

var (
	ErrNotValidToken  = fmt.Errorf("token is not valid")
	ErrFailedGetClaim = fmt.Errorf("failed to get token claims")
)

// Verifier ...
type Verifier interface {
	Verify(token []byte) (jwt JWT, err error)
}

type verifier struct {
	key *rsa.PublicKey
}

// Verify parses and verifies an access token string.
func (v *verifier) Verify(token []byte) (jwt JWT, err error) {
	var (
		jwtToken *jwtgo.Token
		claims   *ClaimsJWT
		ok       bool
	)

	if jwtToken, err = jwtgo.ParseWithClaims(
		string(token),
		&ClaimsJWT{},
		func(token *jwtgo.Token) (key interface{}, err error) {
			if _, ok := token.Method.(*jwtgo.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			key = v.key
			return
		},
	); err != nil {
		return
	}
	if !jwtToken.Valid {
		err = ErrNotValidToken
		return
	}
	if claims, ok = jwtToken.Claims.(*ClaimsJWT); !ok {
		err = ErrFailedGetClaim
		return
	}

	jwt.Original = token
	jwt.Links = claims.Links
	return
}

// NewVerifier creates a new Generator verifier.
func NewVerifier(key *rsa.PublicKey) Verifier {
	return &verifier{
		key: key,
	}
}
