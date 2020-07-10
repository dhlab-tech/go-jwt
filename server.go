package gojwt

import (
	"bytes"
	"context"
	"net/http"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/valyala/fasthttp"
)

var (
	empty                           = []byte("")
	space                           = []byte(" ")
	msgAccessTokenIsNotValid        = "access token is not valid"
	msgAccessTokenIsExpired         = "access token is expired"
	msgAccessTokenNotAuthorizedPath = "access token is not authorized for the path"
)

type ErrorProcessor interface {
	Encode(ctx context.Context, r *fasthttp.Response, err error)
}

type ErrorCreator func(status int, format string, v ...interface{}) error

type Server struct {
	srv                 fasthttp.RequestHandler
	errorProcessor      ErrorProcessor
	errorCreator        ErrorCreator
	jwtHeaderName       string
	authHeaderScheme    []byte
	verifier            Verifier
	contextTokenStorage ContextTokenStorage
}

func (s *Server) ServeHTTP(ctx *fasthttp.RequestCtx) {
	var (
		found          bool
		jwtHeaderValue []byte
		authHeader     [][]byte
		err            error
		errMsg         string
		token          JWT
	)

	// peek generator from headers
	if jwtHeaderValue = ctx.Request.Header.Peek(s.jwtHeaderName); !bytes.Equal(jwtHeaderValue, empty) {
		authHeader = bytes.Split(jwtHeaderValue, space)
		if len(authHeader) == 2 &&
			bytes.EqualFold(authHeader[0], s.authHeaderScheme) &&
			!bytes.Equal(authHeader[1], empty) {
			// verify generator with RSA public key
			token, err = s.verifier.Verify(authHeader[1])
			if err != nil {
				errMsg = msgAccessTokenIsNotValid
				if ve, ok := err.(*jwtgo.ValidationError); ok {
					if ve.Errors&jwtgo.ValidationErrorExpired != 0 {
						errMsg = msgAccessTokenIsExpired
					}
				}
				s.errorProcessor.Encode(ctx, &ctx.Response, s.errorCreator(http.StatusUnauthorized, errMsg))
				return
			}
			// verify signed links from token with URI path
			for i := 0; i < len(token.Links); i++ {
				if bytes.EqualFold(token.Links[i], ctx.Request.URI().Path()) {
					found = true
					break
				}
			}
			if !found {
				s.errorProcessor.Encode(ctx, &ctx.Response, s.errorCreator(http.StatusUnauthorized, msgAccessTokenNotAuthorizedPath))
				return
			}
		}
		// set token to request context
		s.contextTokenStorage.Set(ctx, token)
	}

	// call next http handler
	s.srv(ctx)
}

// NewServer ...
func NewServer(
	srv fasthttp.RequestHandler,
	errorProcessor ErrorProcessor,
	errorCreator ErrorCreator,
	jwtHeaderName string,
	authHeaderScheme []byte,
	verifier Verifier,
	contextTokenStorage ContextTokenStorage,
) fasthttp.RequestHandler {
	s := &Server{
		srv:                 srv,
		errorProcessor:      errorProcessor,
		errorCreator:        errorCreator,
		jwtHeaderName:       jwtHeaderName,
		authHeaderScheme:    authHeaderScheme,
		verifier:            verifier,
		contextTokenStorage: contextTokenStorage,
	}
	return s.ServeHTTP
}
