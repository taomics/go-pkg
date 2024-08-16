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
)

func ErrorUnaryInterceptor(interceptors ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, res interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
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
		if err != nil {
			if gerr := new(grpcError); errors.As(err, &gerr) {
				slog.Error(gerr.Error())
				err = gerr.s.Err()
			}

			return nil, err
		}

		return resp, nil
	}
}
