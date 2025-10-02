package grpcutil

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"

	"github.com/taomics/go-pkg/auth"
	"github.com/taomics/go-pkg/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/protoadapt"
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

//nolint:cyclop,gocognit,funlen /// FIXME: refactor this function
func LogUnaryInterceptors(interceptors ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, res interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) { //nolint:contextcheck,nonamedreturns
		var (
			chain   = handler
			lastCtx context.Context
		)

		for i := len(interceptors) - 1; i >= 0; i-- {
			chain = buildChain(info, chain, interceptors[i], &lastCtx) //nolint:contextcheck
		}

		e := log.Entry{
			Severity: log.Severity_INFO,
			Message:  "",
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

		defer func() {
			if email, err := auth.Email(lastCtx); err == nil {
				if m := log.MaskEmail(email); m != "" {
					e.Labels[keyUser] = m
				}
			}
		}()

		resp, err = chain(ctx, res)
		if err == nil {
			return resp, nil
		}

		e.Severity = log.Severity_ERROR
		e.Message = err.Error()

		var gerr *grpcError
		if errors.As(err, &gerr) {
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

			e.Labels[keyGRPCStatus] = gerr.code.String()
		} else {
			e.Labels[keyGRPCStatus] = codes.Unknown.String()
		}

		return nil, err //nolint:wrapcheck
	}
}

func buildChain(info *grpc.UnaryServerInfo, handle grpc.UnaryHandler, intr grpc.UnaryServerInterceptor, lastCtx *context.Context) grpc.UnaryHandler {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		*lastCtx = ctx //nolint:fatcontext
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
