package middleware

import "net/http"

// SecurityHeaders sets defense-in-depth response headers on every response.
// Covers OWASP A03/A05, PCI DSS Req 4.1/6.5.9.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME-type sniffing (content-type confusion attacks).
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Block framing to prevent clickjacking.
		w.Header().Set("X-Frame-Options", "DENY")

		// Enforce HTTPS for 1 year including subdomains.
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// Restrict resource loading to same origin.
		w.Header().Set("Content-Security-Policy", "default-src 'self'")

		// Disable legacy XSS filter (superseded by CSP; old filter is exploitable).
		w.Header().Set("X-XSS-Protection", "0")

		// Limit referrer leakage on cross-origin navigation.
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Disable unnecessary browser features.
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")

		// Prevent caching of API responses containing user-specific data.
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")

		next.ServeHTTP(w, r)
	})
}
