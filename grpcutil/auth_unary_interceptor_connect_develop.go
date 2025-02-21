//go:build develop

package grpcutil

import (
	"context"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/grpc/codes"

	"github.com/taomics/go-pkg/auth"
)

// AuthUnaryInterceptor is used to set user in development, DONT USE PRODUCTION
func AuthUnaryInterceptorConnect(opts ...auth.Option) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			email := "unknown"
			ah := req.Header().Get(hAuthorization)

			if !strings.HasPrefix(ah, "email ") {
				return nil, Error(codes.Unauthenticated, "no email", "auth_develop: no email")
			}

			email = ah[len("email "):]

			return next(auth.SetEmail(ctx, email), req)
		}
	}
}
