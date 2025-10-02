package grpcutil

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"connectrpc.com/connect"
	"github.com/taomics/go-pkg/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/protoadapt"
)

type grpcError struct {
	code    codes.Code
	details []proto.Message
	grpcMsg string
	logMsg  string
}

func (gerr *grpcError) Error() string {
	return gerr.logMsg
}

func (gerr *grpcError) GRPCStatusError() error {
	sdetails := make([]protoadapt.MessageV1, len(gerr.details))
	for i, d := range gerr.details {
		sdetails[i] = protoadapt.MessageV1Of(d)
	}

	s := status.New(gerr.code, gerr.grpcMsg)
	if s2, e := s.WithDetails(sdetails...); e == nil {
		return s2.Err() //nolint:wrapcheck
	} else { //nolint:revive
		log.Errorf("failed to add error details: %v", e)
	}

	return s.Err() //nolint:wrapcheck
}

func (gerr *grpcError) ConnectError() *connect.Error {
	cerr := connect.NewError(connect.Code(gerr.code), errors.New(gerr.grpcMsg))

	for _, detail := range gerr.details {
		if cdetail, err := connect.NewErrorDetail(detail); err == nil {
			cerr.AddDetail(cdetail)
		} else {
			log.Errorf("failed to add error detail: %v", err)
		}
	}

	return cerr
}

func Error(c codes.Code, grpcMsg, logMsg string, details ...proto.Message) error {
	return &grpcError{code: c, details: details, grpcMsg: grpcMsg, logMsg: logMsg}
}

func Errorf(c codes.Code, grpcMsg, logFormat string, v ...any) error {
	return &grpcError{code: c, details: nil, grpcMsg: grpcMsg, logMsg: fmt.Sprintf(logFormat, v...)}
}

func WithDetails(err error, details ...proto.Message) error {
	var ge *grpcError
	if errors.As(err, &ge) {
		newErr := *ge
		newErr.details = append(slices.Clone(ge.details), details...)

		return &newErr
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
