package grpcutil

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

type grpcError struct {
	code    codes.Code
	grpcMsg string
	logMsg  string
}

func (e *grpcError) Error() string {
	return e.logMsg
}

func Error(c codes.Code, grpcMsg, logMsg string) error {
	return &grpcError{code: c, grpcMsg: grpcMsg, logMsg: logMsg}
}

func Errorf(c codes.Code, grpcMsg, logFormat string, v ...any) error {
	return &grpcError{code: c, grpcMsg: grpcMsg, logMsg: fmt.Sprintf(logFormat, v...)}
}

func extractGRPCAuthHeader(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", fmt.Errorf("failed to get grpc metadata")
	}

	arr := md.Get(hAuthorization)
	switch len(arr) {
	case 0:
		return "", nil
	case 1:
		return arr[0], nil
	default:
		return "", fmt.Errorf("authorization header should be 1, got %d", len(arr))
	}
}
