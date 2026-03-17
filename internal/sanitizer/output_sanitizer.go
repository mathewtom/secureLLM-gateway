package sanitizer

import (
	"html"
	"regexp"
	"strconv"
	"strings"
)

// RedactionTag constants used in replacement strings.
// These are intentionally conspicuous so downstream consumers (logs, UIs)
// can easily detect that redaction occurred.
const (
	RedactedSSN    = "[REDACTED-SSN]"
	RedactedCC     = "[REDACTED-CC]"
	RedactedEmail  = "[REDACTED-EMAIL]"
	RedactedPhone  = "[REDACTED-PHONE]"
	RedactedAWSKey = "[REDACTED-AWS-KEY]"
	RedactedIBAN   = "[REDACTED-IBAN]"
)

// ContentCategory classifies flagged content in LLM output.
type ContentCategory string

const (
	ContentCodeExecution ContentCategory = "code_execution"
	ContentDataExfil     ContentCategory = "data_exfiltration"
	ContentSystemCommand ContentCategory = "system_command"
)

// ContentFlag represents a single flagged content match in the output.
type ContentFlag struct {
	Category    ContentCategory `json:"category"`
	Description string          `json:"description"`
	Matched     string          `json:"matched"`
}

// SanitizeResult contains the sanitized output and metadata about
// what was redacted, encoded, or flagged.
type SanitizeResult struct {
	Output       string        // The sanitized text.
	PIIRedacted  int           // Count of PII patterns replaced.
	HTMLEncoded  bool          // Whether HTML encoding was applied.
	ContentFlags []ContentFlag // Flagged content patterns found.
}

// piiPattern defines a PII detection rule with an optional validator
// for patterns that need extra verification (e.g., Luhn check for CCs).
type piiPattern struct {
	regex       *regexp.Regexp
	tag         string                // Replacement tag, e.g., "[REDACTED-SSN]".
	description string
	validate    func(match string) bool // Optional secondary validation.
}

// contentPattern defines a harmful content detection rule.
type contentPattern struct {
	regex       *regexp.Regexp
	category    ContentCategory
	description string
}

// OutputSanitizer sanitizes LLM responses through three stages:
// PII redaction, HTML output encoding, and content filtering.
// Safe for concurrent use — all state is read-only after construction.
type OutputSanitizer struct {
	piiPatterns     []piiPattern
	contentPatterns []contentPattern
	enableEncoding  bool // Whether to HTML-encode output.
}

// NewOutputSanitizer creates a sanitizer with default PII patterns,
// content filters, and optional HTML output encoding.
func NewOutputSanitizer(enableHTMLEncoding bool) *OutputSanitizer {
	return &OutputSanitizer{
		piiPatterns:     defaultPIIPatterns(),
		contentPatterns: defaultContentPatterns(),
		enableEncoding:  enableHTMLEncoding,
	}
}

// Sanitize runs PII redaction, HTML output encoding, and content filtering
// in sequence. Order matters: redaction before encoding preserves tags.
func (os *OutputSanitizer) Sanitize(input string) SanitizeResult {
	result := SanitizeResult{}

	// Stage 1: PII redaction.
	output := input
	for _, p := range os.piiPatterns {
		if p.validate != nil {
			// Validate each match individually to reduce false positives.
			output = p.regex.ReplaceAllStringFunc(output, func(match string) string {
				if p.validate(match) {
					result.PIIRedacted++
					return p.tag
				}
				return match
			})
		} else {
			// Count matches before replacing.
			matches := p.regex.FindAllString(output, -1)
			if len(matches) > 0 {
				result.PIIRedacted += len(matches)
				output = p.regex.ReplaceAllString(output, p.tag)
			}
		}
	}

	// Stage 2: HTML output encoding (XSS prevention).
	if os.enableEncoding {
		// Preserve redaction tags through encoding via placeholders.
		output = encodeWithPreservedTags(output)
		result.HTMLEncoded = true
	}

	// Stage 3: Content filtering (flag but don't remove).
	normalized := strings.ToLower(output)
	for _, p := range os.contentPatterns {
		matches := p.regex.FindAllString(normalized, -1)
		for _, m := range matches {
			result.ContentFlags = append(result.ContentFlags, ContentFlag{
				Category:    p.category,
				Description: p.description,
				Matched:     m,
			})
		}
	}

	result.Output = output
	return result
}

// encodeWithPreservedTags HTML-encodes text while preserving [REDACTED-*] tags.
func encodeWithPreservedTags(input string) string {
	// Swap redaction tags for null-byte placeholders before encoding.
	tags := []string{
		RedactedSSN, RedactedCC, RedactedEmail,
		RedactedPhone, RedactedAWSKey, RedactedIBAN,
	}

	placeholders := make(map[string]string)
	output := input
	for i, tag := range tags {
		placeholder := "\x00REDACT" + strconv.Itoa(i) + "\x00"
		placeholders[placeholder] = tag
		output = strings.ReplaceAll(output, tag, placeholder)
	}

	// HTML-encode everything.
	output = html.EscapeString(output)

	// Restore redaction tags.
	for placeholder, tag := range placeholders {
		output = strings.ReplaceAll(output, html.EscapeString(placeholder), tag)
	}

	return output
}

// defaultPIIPatterns returns PII detection rules. Patterns are ordered
// from most specific to least specific to avoid partial matches.
// Credit card validation uses the Luhn algorithm to reduce false positives.
func defaultPIIPatterns() []piiPattern {
	return []piiPattern{
		// US Social Security Numbers: XXX-XX-XXXX format.
		// Excludes known invalid prefixes (000, 666, 900-999).
		{
			regex:       regexp.MustCompile(`\b(?:0[1-9]\d|[1-578]\d{2}|6[0-57-9]\d)-\d{2}-\d{4}\b`),
			tag:         RedactedSSN,
			description: "US Social Security Number",
		},

		// Credit card numbers: 13–19 digits, optionally separated by
		// spaces or dashes. Validated with Luhn algorithm.
		{
			regex:       regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`),
			tag:         RedactedCC,
			description: "credit card number",
			validate:    validateLuhn,
		},

		// Email addresses.
		{
			regex:       regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`),
			tag:         RedactedEmail,
			description: "email address",
		},

		// US/international phone numbers in common formats.
		{
			regex:       regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`),
			tag:         RedactedPhone,
			description: "phone number",
		},

		// AWS access key IDs (AKIA prefix, 20 uppercase alphanumeric chars).
		{
			regex:       regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
			tag:         RedactedAWSKey,
			description: "AWS access key ID",
		},

		// International Bank Account Numbers (IBAN).
		{
			regex:       regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?\d{0,16})\b`),
			tag:         RedactedIBAN,
			description: "IBAN",
		},
	}
}

// validateLuhn checks if a numeric string passes the Luhn algorithm
// for credit card validation. Reduces false positives on random digits.
func validateLuhn(s string) bool {
	// Strip non-digit characters.
	var digits []int
	for _, ch := range s {
		if ch >= '0' && ch <= '9' {
			digits = append(digits, int(ch-'0'))
		}
	}

	// Credit cards are 13–19 digits.
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	// Luhn: double every second digit from right, subtract 9 if >9, sum all.
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}

	return sum%10 == 0
}

// defaultContentPatterns returns content filtering rules that detect
// harmful content in LLM responses.
func defaultContentPatterns() []contentPattern {
	return []contentPattern{
		// Shell command execution patterns.
		{
			regex:       regexp.MustCompile(`\b(rm\s+-rf|sudo\s+rm|mkfs\s|dd\s+if=|chmod\s+777|:\(\)\s*\{\s*:\|:\s*&\s*\})\b`),
			category:    ContentSystemCommand,
			description: "destructive system command",
		},
		{
			regex:       regexp.MustCompile(`\b(curl|wget|fetch)\s+.{5,}\|\s*(bash|sh|zsh|python)`),
			category:    ContentCodeExecution,
			description: "remote code execution via pipe",
		},

		// Data exfiltration patterns.
		{
			regex:       regexp.MustCompile(`\b(curl|wget|nc|netcat)\s+.{0,50}(password|secret|token|key|credential)`),
			category:    ContentDataExfil,
			description: "potential credential exfiltration command",
		},

		// Script injection in output.
		{
			regex:       regexp.MustCompile(`<script[\s>]|javascript\s*:|on(load|error|click)\s*=`),
			category:    ContentCodeExecution,
			description: "script injection in output",
		},

		// Reverse shell patterns.
		{
			regex:       regexp.MustCompile(`\b(bash\s+-i|nc\s+-e|python\s+-c\s+.*socket|\/dev\/tcp\/)`),
			category:    ContentCodeExecution,
			description: "reverse shell pattern",
		},
	}
}
