package gojwt

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io/ioutil"

	jwtgo "github.com/dgrijalva/jwt-go"
	"gopkg.in/square/go-jose.v2"
)

// PublicKeyLoader ...
type PublicKeyLoader struct {
	jwkUse       string
	jwkAlgorithm string
	hash         crypto.Hash
}

// Load ...
func (p *PublicKeyLoader) Load(file string) (publicKey jose.JSONWebKey, err error) {
	var (
		thumb    []byte
		keyBytes []byte
		pem      *rsa.PublicKey
	)

	keyBytes, err = ioutil.ReadFile(file)
	if err != nil {
		err = fmt.Errorf("failed to read public key file (%s): %v", file, err)
		return
	}
	pem, err = jwtgo.ParseRSAPublicKeyFromPEM(keyBytes)
	if err != nil {
		err = fmt.Errorf("failed to parse public key (%s): %v", file, err)
		return
	}

	publicKey.Key = pem
	publicKey.Use = p.jwkUse
	publicKey.Algorithm = p.jwkAlgorithm
	thumb, err = publicKey.Thumbprint(p.hash)
	if err != nil {
		err = fmt.Errorf("failed to generate public key thumbprint (%s): %v", file, err)
		return
	}
	publicKey.KeyID = base64.RawURLEncoding.EncodeToString(thumb)

	return
}

// NewPublicKeyLoader ...
// example:
// 	jwkUse       	= "sig"
// 	jwkAlgorithm 	= "RS256"
// 	hash 			= crypto.SHA256
func NewPublicKeyLoader(jwkUse string, jwkAlgorithm string, hash crypto.Hash) *PublicKeyLoader {
	return &PublicKeyLoader{
		jwkUse:       jwkUse,
		jwkAlgorithm: jwkAlgorithm,
		hash:         hash,
	}
}
