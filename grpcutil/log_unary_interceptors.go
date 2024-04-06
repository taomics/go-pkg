package grpcutil

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/taomics/go-pkg/auth"
	"github.com/taomics/go-pkg/log"
)

const (
	keyGRPCMethod = "grpc_method"
	keyGRPCStatus = "grpc_status"
	keyIP         = "ip"
	keyUser       = "user"
	keyUserAgent  = "user_agent"
	keyStackTrace = "stack_trace"

	hAuthorization = "authorization"
	hForwardedFor  = "x-forwarded-for"
	hUserAgent     = "user-agent"
)

func LogUnaryInterceptors(interceptors ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, res interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		var (
			chain   = handler
			lastCtx context.Context
		)

		for i := len(interceptors) - 1; i >= 0; i-- {
			chain = buildChain(info, chain, interceptors[i], &lastCtx)
		}

		var e = log.Entry{
			Severity: log.Severity_INFO,
			Labels:   map[string]string{keyGRPCMethod: info.FullMethod, keyGRPCStatus: codes.OK.String()},
		}

		defer func(e *log.Entry) {
			if rerr := recover(); rerr != nil {
				st := string(debug.Stack())
				e.Severity = log.Severity_CRITICAL
				e.Message = fmt.Sprintf("panic: %+v", rerr)
				e.Labels[keyStackTrace] = st
				e.Labels[keyGRPCStatus] = codes.Aborted.String()
				err = status.Error(codes.Aborted, "internal error")
			}

			log.Log(e)
		}(&e)

		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if arr := md.Get(hForwardedFor); len(arr) > 0 {
				if ip := log.MaskIPAddress(arr[0]); ip != "" {
					e.Labels[keyIP] = ip
				}
			}

			if arr := md.Get(hUserAgent); len(arr) > 0 {
				e.Labels[keyUserAgent] = arr[0]
			}
		}

		defer func(ctx *context.Context) {
			if email, err := auth.Email(lastCtx); err == nil {
				if m := log.MaskEmail(email); m != "" {
					e.Labels[keyUser] = m
				}
			}
		}(&lastCtx)

		resp, err = chain(ctx, res)
		if err != nil {
			e.Severity = log.Severity_ERROR
			e.Message = err.Error()

			if gerr := new(grpcErr); errors.As(err, &gerr) {
				err = gerr.s.Err()
				e.Labels[keyGRPCStatus] = gerr.s.Code().String()
			} else {
				e.Labels[keyGRPCStatus] = codes.Unknown.String()
			}
		}

		return resp, err
	}
}

func buildChain(info *grpc.UnaryServerInfo, handle grpc.UnaryHandler, intr grpc.UnaryServerInterceptor, lastCtx *context.Context) grpc.UnaryHandler {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		*lastCtx = ctx
		return intr(ctx, req, info, handle)
	}
}

// Azure Container Apps headers
// accept-encoding
// content-type
// grpc-accept-encoding
// user-agent
// x-arr-ssl
// x-envoy-expected-rq-timeout-ms
// x-envoy-external-address
// x-forwarded-for
// x-forwarded-proto
// x-k8se-app-kind
// x-k8se-app-name
// x-k8se-app-namespace
// x-k8se-protocol
// x-ms-containerapp-name
// x-ms-containerapp-revision-name
// x-request-id
