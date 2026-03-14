package middleware

import "net/http"

// SecurityHeaders adds security-related HTTP response headers to every response.
//
// SECURITY CONTEXT:
//   These headers are a critical defense layer against several OWASP Top 10 attacks.
//   They instruct the browser to enforce security policies. Without them,
//   your application is vulnerable to clickjacking, XSS, MIME-type confusion,
//   and downgrade attacks — even if your application code is perfect.
//
// PCI DSS Req 6.5.9: Requires protection against cross-site request forgery.
// PCI DSS Req 4.1: Requires encryption of data in transit (HSTS).
//
// NOTE: These are API-focused headers. If serving a web UI, you'd add additional
// headers like Content-Security-Policy with script-src directives.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// =====================================================================
		// X-Content-Type-Options: nosniff
		// =====================================================================
		// WHAT: Prevents the browser from "MIME sniffing" — guessing the content
		//       type by inspecting the response body instead of trusting the
		//       Content-Type header.
		//
		// WHY:  An attacker could upload a file that looks like HTML but is served
		//       as text/plain. Without nosniff, the browser might render it as
		//       HTML, executing embedded JavaScript (XSS attack).
		//
		// OWASP: A03 (Injection) — prevents content-type-based injection.
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// =====================================================================
		// X-Frame-Options: DENY
		// =====================================================================
		// WHAT: Prevents this page from being embedded in an <iframe>.
		//
		// WHY:  Clickjacking attack — an attacker embeds your page in a transparent
		//       iframe overlaid on a malicious page. The user thinks they're clicking
		//       on the attacker's page, but they're actually clicking buttons on YOUR
		//       page (e.g., "Delete Account", "Transfer Funds").
		//
		// DENY vs SAMEORIGIN: DENY blocks all framing. SAMEORIGIN allows framing
		// from the same domain. For an API, DENY is appropriate.
		//
		// NOTE: CSP frame-ancestors is the modern replacement, but X-Frame-Options
		// is still needed for older browsers.
		w.Header().Set("X-Frame-Options", "DENY")

		// =====================================================================
		// Strict-Transport-Security (HSTS)
		// =====================================================================
		// WHAT: Tells the browser to ONLY communicate with this server over HTTPS
		//       for the next year (31536000 seconds). includeSubDomains extends
		//       this to all subdomains.
		//
		// WHY:  Prevents SSL stripping attacks. Without HSTS:
		//       1. User types "example.com" in browser → HTTP request to port 80
		//       2. Attacker intercepts and serves a fake HTTP version
		//       3. User's credentials are sent over unencrypted HTTP
		//       With HSTS, the browser refuses to make any HTTP requests.
		//
		// PCI DSS Req 4.1: Requires strong cryptography for data in transit.
		// The max-age should be at least 6 months for production.
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// =====================================================================
		// Content-Security-Policy (CSP)
		// =====================================================================
		// WHAT: Tells the browser which sources of content are allowed to load.
		//       "default-src 'self'" means only load resources from our own domain.
		//
		// WHY:  The most powerful defense against XSS. Even if an attacker manages
		//       to inject a <script> tag, CSP prevents it from loading external
		//       scripts, sending data to attacker-controlled servers, or executing
		//       inline JavaScript.
		//
		// For an API that returns JSON, this is a safety net — if someone
		// accidentally navigates to an API endpoint in their browser, CSP
		// prevents any injected content from executing.
		//
		// OWASP: A03 (Injection), specifically XSS mitigation.
		w.Header().Set("Content-Security-Policy", "default-src 'self'")

		// =====================================================================
		// X-XSS-Protection: 0
		// =====================================================================
		// WHAT: Disables the browser's built-in XSS filter.
		//
		// WHY:  This seems counterintuitive! The old XSS filter (X-XSS-Protection: 1)
		//       was actually exploitable — it could be tricked into removing
		//       legitimate content, creating a different XSS vector. Modern browsers
		//       have deprecated it. CSP is the proper replacement.
		//       Setting it to "0" explicitly disables the filter to prevent
		//       the exploitable "1; mode=block" behavior in older browsers.
		//
		// Reference: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
		w.Header().Set("X-XSS-Protection", "0")

		// =====================================================================
		// Referrer-Policy: strict-origin-when-cross-origin
		// =====================================================================
		// WHAT: Controls how much referrer information (the URL of the previous page)
		//       is sent when navigating away from this page.
		//
		// WHY:  API URLs might contain sensitive data (tokens, user IDs).
		//       strict-origin-when-cross-origin sends only the origin (domain)
		//       on cross-origin requests, and the full URL on same-origin requests.
		//       This prevents leaking sensitive URL paths to third-party services.
		//
		// PCI DSS Req 3: Protect stored cardholder data — URL parameters
		// could contain tokens or session identifiers.
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// =====================================================================
		// Permissions-Policy
		// =====================================================================
		// WHAT: Controls which browser features (camera, microphone, geolocation,
		//       payment APIs) this page is allowed to use.
		//
		// WHY:  Even though we're an API, if a response is rendered in a browser,
		//       we don't want it to access sensitive device features. This is
		//       defense-in-depth — blocking features we'll never need.
		//
		// The ()= syntax means "disallow for all origins."
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")

		// =====================================================================
		// Cache-Control
		// =====================================================================
		// WHAT: Instructs browsers and proxies not to cache responses.
		//
		// WHY:  API responses often contain user-specific data (chat messages,
		//       PII, tokens). Caching these responses could expose one user's
		//       data to another user on shared computers or through proxy caches.
		//
		// PCI DSS Req 3.4: Sensitive data must not be stored unnecessarily.
		// Browser caches count as "storage."
		//
		// no-store: Don't store the response at all.
		// no-cache: Always revalidate with the server before using cached version.
		// must-revalidate: If the cache is stale, must revalidate (don't serve stale).
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")

		// Pass the request to the next handler in the chain.
		next.ServeHTTP(w, r)
	})
}
