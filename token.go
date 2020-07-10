package gojwt

import (
	"context"

	"github.com/valyala/fasthttp"
)

// ContextTokenStorage represents interface for token set and get methods to request context
type ContextTokenStorage interface {
	Set(ctx *fasthttp.RequestCtx, token JWT)
	Get(ctx context.Context) (token JWT, found bool)
}

type contextTokenStorage struct {
	ctxJWTKey string
}

// SetToken returns a copy of context associated with the given access token.
func (s *contextTokenStorage) Set(ctx *fasthttp.RequestCtx, token JWT) {
	ctx.SetUserValue(s.ctxJWTKey, token)
}

// GetToken returns an access token associated with the given context (if any).
func (s *contextTokenStorage) Get(ctx context.Context) (token JWT, found bool) {
	var t interface{}
	t = ctx.Value(s.ctxJWTKey)
	if t == nil {
		return
	}
	return t.(JWT), true
}

// NewContextTokenStorage creates new ContextTokenStorage
func NewContextTokenStorage(ctxJWTKey string) ContextTokenStorage {
	return &contextTokenStorage{
		ctxJWTKey: ctxJWTKey,
	}
}
