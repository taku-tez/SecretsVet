package detector

import (
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		input    string
		wantHigh bool
	}{
		{"", false},
		{"aaaaaaaaaa", false},                                      // all same chars, entropy=0
		// Note: AKIAIOSFODNN7EXAMPLE is a known pattern (caught by regex), but low entropy by design
		{"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", true},       // AWS secret - high entropy
		{"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234", true},        // GitHub PAT
		{"hello", false},                                           // too short
		{"not-a-secret-value", false},                              // low entropy
	}

	for _, tt := range tests {
		got := IsHighEntropy(tt.input, EntropyMinLength)
		if got != tt.wantHigh {
			h := ShannonEntropy(tt.input)
			t.Errorf("IsHighEntropy(%q) = %v, want %v (entropy=%.2f)", tt.input, got, tt.wantHigh, h)
		}
	}
}

func TestCharsetType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"deadbeef", "hex"},
		{"DEADBEEF01234567", "hex"},
		{"ABCDEFGHIJKLMNOPabcdef0123+/==", "base64"},
		{"hello world!", "general"},
	}
	for _, tt := range tests {
		got := charsetType(tt.input)
		if got != tt.want {
			t.Errorf("charsetType(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
