package grpcutil

import (
	"unicode"

	"github.com/taomics/go-pkg/log"
	"google.golang.org/grpc/codes"
)

func AuthError(format string, args ...any) error {
	return Errorf(codes.Unauthenticated, "auth error", format, args...)
}

func DBError(format string, args ...any) error {
	return Errorf(codes.Internal, "db error", format, args...)
}

func RequiredError(key string) error {
	if len(key) > 0 {
		runes := []rune(key)
		runes[0] = unicode.ToUpper(runes[0])
		key = string(runes)
	}

	return Error(codes.InvalidArgument, key+" is required", "req.Get"+key+" is nil")
}

func NotFoundError(key string, value any) error {
	return Errorf(codes.NotFound, "not found", "no such %s: %v", key, value)
}

func NotUserError(email string) error {
	return Errorf(codes.PermissionDenied, "not user", "no such user: %s", log.MaskEmail(email))
}

func NotAdvisorError(email string) error {
	return Errorf(codes.PermissionDenied, "not advisor", "no such advisor: %s", log.MaskEmail(email))
}
