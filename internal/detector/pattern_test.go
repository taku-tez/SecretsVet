package detector

import "testing"

func TestMatchAny(t *testing.T) {
	// Build token strings in parts to avoid GitHub push protection false positives.
	// These are test-only values that match the regex patterns but are not real secrets.
	slackToken := "xoxb-" + "NOTAREALTOKEN1-NOTAREALTOKEN2-NOTAREALTOKEN3XXXXX"
	stripeKey := "sk_" + "live_NOTAREALKEY00000000000000000"

	tests := []struct {
		input       string
		wantPattern string // empty string means no match expected
	}{
		{"AKIAIOSFODNN7EXAMPLE", "aws-access-key-id"},
		{"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234", "github-pat"},
		{"ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234", "github-app-token"},
		{slackToken, "slack-token"},
		{"AIzaSyDx9ej4jSmBK0zq6dXN3q2Jb9wF8wA_abc", "google-api-key"},
		{stripeKey, "stripe-secret-key"},
		{"-----BEGIN RSA PRIVATE KEY", "private-key-header"},
		{"hello-world", ""},
		{"normal-value-123", ""},
	}

	for _, tt := range tests {
		m := MatchAny(tt.input)
		if tt.wantPattern == "" {
			if m != nil {
				t.Errorf("MatchAny(%q) matched %q, want no match", tt.input, m.PatternName)
			}
		} else {
			if m == nil {
				t.Errorf("MatchAny(%q) = nil, want match for %q", tt.input, tt.wantPattern)
			} else if m.PatternName != tt.wantPattern {
				t.Errorf("MatchAny(%q) matched %q, want %q", tt.input, m.PatternName, tt.wantPattern)
			}
		}
	}
}

func TestMaskValue(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"abc", "[REDACTED]"},
		{"abcd", "[REDACTED]"},
		{"abcde", "abcd[REDACTED]"},
		{"AKIAIOSFODNN7EXAMPLE", "AKIA...[REDACTED]"},
	}
	for _, tt := range tests {
		got := MaskValue(tt.input)
		if got != tt.want {
			t.Errorf("MaskValue(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSuspiciousKeyName(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"DB_PASSWORD", true},
		{"API_KEY", true},
		{"AUTH_TOKEN", true},
		{"PRIVATE_KEY", true},
		{"DATABASE_URL", false},
		{"LOG_LEVEL", false},
		{"APP_NAME", false},
	}
	for _, tt := range tests {
		got := SuspiciousKeyName(tt.key)
		if got != tt.want {
			t.Errorf("SuspiciousKeyName(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}
