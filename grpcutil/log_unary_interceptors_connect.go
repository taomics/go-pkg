package grpcutil

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"

	"connectrpc.com/connect"
	"github.com/taomics/go-pkg/log"
	"google.golang.org/grpc/codes"
)

func LogUnaryInterceptorConnect() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		//nolint:nonamedreturns /// need override err values
		return func(ctx context.Context, req connect.AnyRequest) (resp connect.AnyResponse, err error) {
			e := log.Entry{
				Severity: log.Severity_INFO,
				Message:  "",
				Labels:   map[string]string{keyGRPCMethod: req.Spec().Procedure, keyGRPCStatus: "OK"},
			}

			defer func(e *log.Entry) {
				if rerr := recover(); rerr != nil {
					st := string(debug.Stack())
					e.Severity = log.Severity_CRITICAL
					e.Message = fmt.Sprintf("panic: %+v", rerr)
					e.Labels[keyStackTrace] = st
					e.Labels[keyGRPCStatus] = codes.Aborted.String()
					err = connect.NewError(connect.CodeAborted, errors.New("internal error"))
				}

				log.Log(e)
			}(&e)

			resp, err = next(ctx, req)
			if err != nil {
				e.Severity = log.Severity_ERROR
				e.Message = err.Error()

				if gerr := new(grpcError); errors.As(err, &gerr) {
					err = connect.NewError(connect.Code(gerr.code), errors.New(gerr.grpcMsg))
					e.Labels[keyGRPCStatus] = gerr.code.String()
				} else {
					e.Labels[keyGRPCStatus] = connect.CodeUnknown.String()
				}
			}

			return resp, err //nolint:wrapcheck
		}
	}
}
