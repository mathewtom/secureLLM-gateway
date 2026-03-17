// Package sanitizer provides input/output security filters for LLM traffic.
package sanitizer

import (
	"regexp"
	"strings"
)

// Category classifies the type of injection technique.
type Category string

const (
	CategoryRoleOverride        Category = "role_override"
	CategoryDelimiterInjection  Category = "delimiter_injection"
	CategoryInstructionOverride Category = "instruction_override"
	CategoryInfoExtraction      Category = "info_extraction"
	CategoryJailbreak           Category = "jailbreak"
	CategoryEncodingBypass      Category = "encoding_bypass"
)

// pattern defines a single detection rule with a compiled regex,
// risk score, category, and description for audit logging.
type pattern struct {
	regex       *regexp.Regexp
	score       int
	category    Category
	description string
}

// DetectionResult contains the scan verdict and matched patterns.
type DetectionResult struct {
	Blocked    bool
	TotalScore int
	Threshold  int
	Matches    []Match
}

// Match represents a single pattern that fired during scanning.
type Match struct {
	Category    Category `json:"category"`
	Description string   `json:"description"`
	Score       int      `json:"score"`
}

// PromptGuard is the injection detection engine. It holds compiled regex
// patterns and a scoring threshold. Safe for concurrent use.
type PromptGuard struct {
	patterns  []pattern
	threshold int
}

// NewPromptGuard creates a detector with default patterns and the given
// scoring threshold. Lower thresholds block more aggressively.
func NewPromptGuard(threshold int) *PromptGuard {
	return &PromptGuard{
		patterns:  defaultPatterns(),
		threshold: threshold,
	}
}

// Scan checks input against all registered patterns and returns a
// DetectionResult. Input is lowercased before matching to defeat
// mixed-case evasion.
func (pg *PromptGuard) Scan(input string) DetectionResult {
	normalized := strings.ToLower(input)

	result := DetectionResult{
		Threshold: pg.threshold,
	}

	for _, p := range pg.patterns {
		if p.regex.MatchString(normalized) {
			result.TotalScore += p.score
			result.Matches = append(result.Matches, Match{
				Category:    p.category,
				Description: p.description,
				Score:       p.score,
			})
		}
	}

	result.Blocked = result.TotalScore >= pg.threshold

	return result
}

// defaultPatterns returns detection rules based on OWASP LLM01:2025
// documented attack categories. Patterns use Go RE2 syntax, validated
// against regex101.com (Golang flavor) and verified via automated tests
// (prompt_guard_test.go) covering known attack payloads and legitimate
// inputs for false-positive validation.
//
// Scores are proportional to specificity: generic phrases that may appear
// in legitimate text score low (3–5), specific injection phrases score
// medium (6–7), and high-confidence attack signatures score high (8–9).
// Single low-confidence signals pass; compound signals trigger a block.
func defaultPatterns() []pattern {
	return []pattern{
		// ── Instruction Override ─────────────────────────────────────
		{
			regex:       regexp.MustCompile(`ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?)`),
			score:       8,
			category:    CategoryInstructionOverride,
			description: "direct instruction override attempt",
		},
		{
			regex:       regexp.MustCompile(`disregard\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|prompts?|rules?|guidelines?)`),
			score:       8,
			category:    CategoryInstructionOverride,
			description: "disregard instructions attempt",
		},
		{
			regex:       regexp.MustCompile(`forget\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|context|rules?)`),
			score:       7,
			category:    CategoryInstructionOverride,
			description: "forget instructions attempt",
		},
		{
			regex:       regexp.MustCompile(`do\s+not\s+follow\s+(your|the|any)\s+(previous|original|initial)\s+(instructions?|rules?|guidelines?)`),
			score:       8,
			category:    CategoryInstructionOverride,
			description: "instruction negation attempt",
		},
		{
			regex:       regexp.MustCompile(`override\s+(your|the|all|any)\s+(previous|current|existing)?\s*(instructions?|rules?|settings?|guidelines?)`),
			score:       7,
			category:    CategoryInstructionOverride,
			description: "explicit override attempt",
		},

		// ── Role Override ────────────────────────────────────────────
		{
			regex:       regexp.MustCompile(`you\s+are\s+now\s+(a|an|the)\b`),
			score:       6,
			category:    CategoryRoleOverride,
			description: "role reassignment attempt",
		},
		{
			regex:       regexp.MustCompile(`(new|updated|revised)\s+(system\s+)?(prompt|instruction|role|persona)\s*:`),
			score:       7,
			category:    CategoryRoleOverride,
			description: "system prompt replacement attempt",
		},
		{
			regex:       regexp.MustCompile(`\bact\s+as\s+(a|an|if)\b`),
			score:       3,
			category:    CategoryRoleOverride,
			description: "role play directive",
		},
		{
			regex:       regexp.MustCompile(`(pretend|imagine|assume)\s+(you|that\s+you)\s+(are|have|can|were)\b`),
			score:       5,
			category:    CategoryRoleOverride,
			description: "identity manipulation attempt",
		},
		{
			regex:       regexp.MustCompile(`switch\s+(to|into)\s+(a\s+)?(new|different|unrestricted)\s+(mode|persona|role)`),
			score:       7,
			category:    CategoryRoleOverride,
			description: "mode switch attempt",
		},

		// ── Delimiter Injection ──────────────────────────────────────
		{
			regex:       regexp.MustCompile(`(---|===|~~~|\*\*\*)\s*(system|admin|instruction|prompt)`),
			score:       6,
			category:    CategoryDelimiterInjection,
			description: "delimiter with system keyword",
		},
		{
			regex:       regexp.MustCompile(`<\s*/?\s*(system|instruction|prompt|admin|context)\s*>`),
			score:       7,
			category:    CategoryDelimiterInjection,
			description: "fake XML system tag injection",
		},
		{
			regex:       regexp.MustCompile(`\[\/?(system|inst|instruction|prompt)\]`),
			score:       7,
			category:    CategoryDelimiterInjection,
			description: "fake bracket tag injection",
		},
		{
			regex:       regexp.MustCompile(`(begin|start|end)\s+(of\s+)?(system|admin|hidden)\s+(prompt|message|instruction|section)`),
			score:       7,
			category:    CategoryDelimiterInjection,
			description: "fake prompt boundary marker",
		},

		// ── Information Extraction ───────────────────────────────────
		{
			regex:       regexp.MustCompile(`(repeat|show|reveal|display|print|output|tell\s+me)\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules?|guidelines?|configuration)`),
			score:       7,
			category:    CategoryInfoExtraction,
			description: "system prompt extraction attempt",
		},
		{
			regex:       regexp.MustCompile(`what\s+(are|is|were)\s+your\s+(system\s+)?(instructions?|prompt|rules?|guidelines?|directives?)`),
			score:       6,
			category:    CategoryInfoExtraction,
			description: "instruction inquiry",
		},
		{
			regex:       regexp.MustCompile(`(copy|paste|dump|leak|exfiltrate)\s+(the\s+)?(system|hidden|secret|internal)\s+(prompt|message|instructions?|config)`),
			score:       9,
			category:    CategoryInfoExtraction,
			description: "explicit exfiltration attempt",
		},

		// ── Jailbreak ────────────────────────────────────────────────
		{
			regex:       regexp.MustCompile(`\b(dan|do\s+anything\s+now)\b`),
			score:       6,
			category:    CategoryJailbreak,
			description: "DAN jailbreak pattern",
		},
		{
			regex:       regexp.MustCompile(`\bjailbreak(ed|ing)?\b`),
			score:       5,
			category:    CategoryJailbreak,
			description: "explicit jailbreak reference",
		},
		{
			regex:       regexp.MustCompile(`(bypass|disable|remove|turn\s+off)\s+(your\s+)?(safety|security|content|ethical)\s*(filter|restriction|guardrail|limit|check)s?`),
			score:       8,
			category:    CategoryJailbreak,
			description: "safety bypass attempt",
		},
		{
			regex:       regexp.MustCompile(`(without|no|ignore)\s+(any\s+)?(safety|security|ethical|content)\s*(filter|restriction|guideline|limit|concern|check)s?`),
			score:       7,
			category:    CategoryJailbreak,
			description: "unrestricted mode request",
		},
		{
			regex:       regexp.MustCompile(`\b(evil|unfiltered|uncensored|unrestricted|developer)\s+mode\b`),
			score:       8,
			category:    CategoryJailbreak,
			description: "known jailbreak mode name",
		},

		// ── Encoding Bypass ──────────────────────────────────────────
		{
			regex:       regexp.MustCompile(`(decode|interpret|execute|run|follow)\s+(this|the\s+following)\s+(base64|hex|encoded|rot13|binary)`),
			score:       7,
			category:    CategoryEncodingBypass,
			description: "encoded instruction execution request",
		},
		{
			regex:       regexp.MustCompile(`(base64|hex|rot13)\s*:\s*[a-zA-Z0-9+/=]{20,}`),
			score:       6,
			category:    CategoryEncodingBypass,
			description: "suspicious encoded payload",
		},
	}
}
