//go:build !develop

package grpcutil

import (
	"context"

	"connectrpc.com/connect"
	"github.com/taomics/go-pkg/auth"
	"google.golang.org/grpc/codes"
)

func AuthUnaryInterceptorConnect(opts ...auth.Option) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			ah := req.Header().Get(hAuthorization)

			ctx, err := auth.Authenticate(ctx, ah, opts...)
			if err != nil {
				return nil, Error(codes.Unauthenticated, "invalid token", "auth: "+err.Error())
			}

			return next(ctx, req)
		}
	}
}
