package grpcutil

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/protoadapt"
)

func ErrorUnaryInterceptor(interceptors ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, res interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) { //nolint:nonamedreturns
		var (
			chain   = handler
			lastCtx context.Context
		)

		for i := len(interceptors) - 1; i >= 0; i-- {
			chain = buildChain(info, chain, interceptors[i], &lastCtx) //nolint:contextcheck
		}

		defer func() {
			if rerr := recover(); rerr != nil {
				st := string(debug.Stack())
				slog.Error(fmt.Sprintf("%v", rerr), "stack_trace", st)
				err = status.Error(codes.Aborted, "internal error")
			}
		}()

		resp, err = chain(ctx, res)
		if err == nil {
			return resp, nil
		}

		if gerr := new(grpcError); errors.As(err, &gerr) {
			slog.Error(gerr.Error())

			sdetails := make([]protoadapt.MessageV1, len(gerr.details))
			for i, d := range gerr.details {
				sdetails[i] = protoadapt.MessageV1Of(d)
			}

			s := status.New(gerr.code, gerr.grpcMsg)
			if s2, e := s.WithDetails(sdetails...); e == nil {
				err = s2.Err()
			} else {
				err = s.Err()
			}
		}

		return nil, err //nolint:wrapcheck
	}
}
