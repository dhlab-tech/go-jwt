package gojwt

import (
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
	"gopkg.in/square/go-jose.v2"
)

// Generator ...
type Generator struct {
	privateKey jose.JSONWebKey
	expireIn   time.Duration
	timeFunc   func() time.Time
}

// Generate ...
func (g *Generator) Generate(links ...[]byte) (token []byte, err error) {
	var (
		t           *jwtgo.Token
		claims      ClaimsJWT
		signedToken string
	)

	now := g.timeFunc()

	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = now.Add(g.expireIn).Unix()
	claims.Links = links

	t = jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)

	signedToken, err = t.SignedString(g.privateKey.Key)
	if err != nil {
		return
	}

	return []byte(signedToken), nil
}

// NewGenerator ...
func NewGenerator(privateKey jose.JSONWebKey, expireIn time.Duration, timeFunc func() time.Time) *Generator {
	return &Generator{
		privateKey: privateKey,
		expireIn:   expireIn,
		timeFunc:   timeFunc,
	}
}
