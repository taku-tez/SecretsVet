package detector

import "regexp"

// SecretPattern is a named regex pattern for a known secret format.
type SecretPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

// Patterns is the catalog of known secret patterns, pre-compiled at init time.
var Patterns []SecretPattern

func init() {
	defs := []struct {
		name    string
		pattern string
	}{
		{"aws-access-key-id", `AKIA[0-9A-Z]{16}`},
		{"aws-secret-access-key", `(?i)aws.{0,20}secret.{0,20}['\"]?[0-9a-zA-Z/+]{40}['\"]?`},
		{"github-app-token", `(ghu|ghs)_[A-Za-z0-9]{36}`},
		{"github-oauth", `gho_[A-Za-z0-9]{36}`},
		{"github-pat", `ghp_[A-Za-z0-9]{36}`},
		{"slack-token", `xox[baprs]-[0-9A-Za-z\-]{10,48}`},
		{"slack-webhook", `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`},
		{"stripe-secret-key", `sk_live_[0-9a-zA-Z]{24,}`},
		{"stripe-restricted-key", `rk_live_[0-9a-zA-Z]{24,}`},
		{"google-api-key", `AIza[0-9A-Za-z\-_]{35}`},
		{"twilio-api-key", `SK[0-9a-fA-F]{32}`},
		{"private-key-header", `-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY`},
		{"generic-password", `(?i)(password|passwd|secret|token|api[_-]?key|auth[_-]?key|credentials?)['\"]?\s*[=:]\s*['\"]?[^\s'\"]{8,}`},
		{"basic-auth-header", `(?i)basic\s+[A-Za-z0-9+/]{20,}={0,2}`},
		{"bearer-token", `(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}`},
		{"connection-string", `(?i)(mongodb|mysql|postgres|postgresql|redis|amqp)://[^@\s]+:[^@\s]+@`},
	}

	for _, d := range defs {
		Patterns = append(Patterns, SecretPattern{
			Name:    d.name,
			Pattern: regexp.MustCompile(d.pattern),
		})
	}
}

// MatchResult holds the result of a pattern match.
type MatchResult struct {
	PatternName string
	// Matched value is not stored to avoid leaking secrets in memory longer than needed.
}

// MatchAny checks value against all patterns and returns the first match, or nil.
func MatchAny(value string) *MatchResult {
	for _, p := range Patterns {
		if p.Pattern.MatchString(value) {
			return &MatchResult{PatternName: p.Name}
		}
	}
	return nil
}

// MaskValue returns a masked version of the value safe to include in output.
// It shows the first 4 characters and replaces the rest with [REDACTED].
func MaskValue(value string) string {
	runes := []rune(value)
	if len(runes) <= 4 {
		return "[REDACTED]"
	}
	if len(runes) > 8 {
		return string(runes[:4]) + "...[REDACTED]"
	}
	return string(runes[:4]) + "[REDACTED]"
}

// SuspiciousKeyName returns true if the key name suggests it may contain a secret.
func SuspiciousKeyName(key string) bool {
	pattern := regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|auth|credential|private[_-]?key|access[_-]?key|signing[_-]?key|encryption[_-]?key)`)
	return pattern.MatchString(key)
}
