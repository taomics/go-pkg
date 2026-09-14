// Package auth provides utilities for validating OpenID Connect (OIDC) tokens
// and managing authenticated user identity (email) within the context.
//
// It supports token validation for major identity providers including Google,
// Apple, and Azure AD B2C.
//
// # Usage
//
// To authenticate an incoming request, use the Authenticate function with the
// Authorization header:
//
//	ctx, err := auth.Authenticate(ctx, authHeader)
//	if err != nil {
//		// handle authentication error
//	}
//
// Once authenticated, you can retrieve the user's email from the context:
//
//	email, err := auth.Email(ctx)
//	if err != nil {
//		// handle error
//	}
package auth
