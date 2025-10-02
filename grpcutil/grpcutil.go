package grpcutil

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

type grpcError struct {
	code    codes.Code
	details []proto.Message
	grpcMsg string
	logMsg  string
}

func (e *grpcError) Error() string {
	return e.logMsg
}

func Error(c codes.Code, grpcMsg, logMsg string, details ...proto.Message) error {
	return &grpcError{code: c, details: details, grpcMsg: grpcMsg, logMsg: logMsg}
}

func Errorf(c codes.Code, grpcMsg, logFormat string, v ...any) error {
	return &grpcError{code: c, details: nil, grpcMsg: grpcMsg, logMsg: fmt.Sprintf(logFormat, v...)}
}

func WithDetails(err error, details ...proto.Message) error {
	if ge, ok := err.(*grpcError); ok {
		ge.details = append(ge.details, details...)
		return ge
	}

	return &grpcError{code: codes.Unknown, details: details, grpcMsg: err.Error(), logMsg: err.Error()}
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
