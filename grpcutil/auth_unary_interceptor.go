//go:build !develop

package grpcutil

import (
	"context"

	"github.com/taomics/go-pkg/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

func AuthUnaryInterceptor(opts ...auth.Option) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ah, err := extractGRPCAuthHeader(ctx)
		if err != nil {
			return nil, Error(codes.Unauthenticated, "invalid authorization header", "auth: "+err.Error())
		}

		ctx, err = auth.Authenticate(ctx, ah, opts...)
		if err != nil {
			return nil, Error(codes.Unauthenticated, "invalid token", "auth: "+err.Error())
		}

		return handler(ctx, req)
	}
}
