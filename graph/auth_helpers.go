package graph

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// extractTokenFromContext extracts JWT token from the Authorization header
func extractTokenFromContext(ctx context.Context) (string, error) {
	// Try to get the HTTP request from the context
	// In GraphQL, the request context should contain the HTTP request
	if req, ok := ctx.Value("request").(*http.Request); ok {
		authHeader := req.Header.Get("Authorization")
		if authHeader == "" {
			return "", fmt.Errorf("authorization header missing")
		}

		// Expected format: "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return "", fmt.Errorf("invalid authorization header format, expected 'Bearer <token>'")
		}

		return parts[1], nil
	}

	// Alternative: Check if token is in a custom context key
	if token, ok := ctx.Value("token").(string); ok {
		return token, nil
	}

	return "", fmt.Errorf("no authentication token found in context")
}
