package gojwt

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io/ioutil"

	"github.com/dgrijalva/jwt-go"
	"gopkg.in/square/go-jose.v2"
)

// PrivateKeyLoader ...
type PrivateKeyLoader struct {
	jwkUse       string
	jwkAlgorithm string
	hash         crypto.Hash
}

// Load ...
func (p *PrivateKeyLoader) Load(file string) (privateKey jose.JSONWebKey, err error) {
	var (
		keyBytes []byte
		thumb    []byte
		pem      *rsa.PrivateKey
	)

	keyBytes, err = ioutil.ReadFile(file)
	if err != nil {
		err = fmt.Errorf("failed to read private key file (%s): %v", file, err)
		return
	}
	pem, err = jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	if err != nil {
		err = fmt.Errorf("failed to parse private key (%s): %v", file, err)
		return
	}

	privateKey.Key = pem
	privateKey.Use = p.jwkUse
	privateKey.Algorithm = p.jwkAlgorithm
	thumb, err = privateKey.Thumbprint(p.hash)
	if err != nil {
		err = fmt.Errorf("failed to generate private key thumbprint (%s): %v", file, err)
		return
	}
	privateKey.KeyID = base64.RawURLEncoding.EncodeToString(thumb)

	return
}

// NewPrivateKeyLoader ...
// 	jwkUse       	= "sig"
// 	jwkAlgorithm 	= "RS256"
// 	hash 			= crypto.SHA256
func NewPrivateKeyLoader(jwkUse string, jwkAlgorithm string, hash crypto.Hash) *PrivateKeyLoader {
	return &PrivateKeyLoader{
		jwkUse:       jwkUse,
		jwkAlgorithm: jwkAlgorithm,
		hash:         hash,
	}
}
