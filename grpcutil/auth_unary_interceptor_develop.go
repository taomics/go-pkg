//go:build develop

package grpcutil

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/taomics/go-pkg/auth"
)

// AuthUnaryInterceptor is used to set user in development, DONT USE PRODUCTION
func AuthUnaryInterceptor(_ ...auth.Option) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		email := "unknown"

		ah, err := extractGRPCAuthHeader(ctx)
		if err != nil {
			return nil, Error(codes.Unauthenticated, "invalid authorization header", "auth_develop: "+err.Error())
		}

		if !strings.HasPrefix(ah, "email ") {
			return nil, Error(codes.Unauthenticated, "no email", "auth_develop: no email")
		}

		email = ah[len("email "):]

		return handler(auth.SetEmail(ctx, email), req)
	}
}
