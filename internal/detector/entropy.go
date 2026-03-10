package detector

import "math"

const (
	EntropyThresholdBase64 = 4.5
	EntropyThresholdHex    = 3.0
	EntropyThresholdGeneral = 4.0
	EntropyMinLength       = 20
)

// ShannonEntropy computes H(s) in bits per character.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, count := range freq {
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

// IsHighEntropy returns true if the string has suspiciously high entropy.
// It uses charset-aware thresholds to reduce false positives.
func IsHighEntropy(s string, minLen int) bool {
	if len(s) < minLen {
		return false
	}
	h := ShannonEntropy(s)
	switch charsetType(s) {
	case "base64":
		return h >= EntropyThresholdBase64
	case "hex":
		return h >= EntropyThresholdHex
	default:
		return h >= EntropyThresholdGeneral
	}
}

// charsetType identifies whether s consists only of base64 or hex characters.
func charsetType(s string) string {
	isHex := true
	isBase64 := true
	for _, c := range s {
		if !isHexChar(c) {
			isHex = false
		}
		if !isBase64Char(c) {
			isBase64 = false
		}
	}
	if isHex {
		return "hex"
	}
	if isBase64 {
		return "base64"
	}
	return "general"
}

func isHexChar(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isBase64Char(c rune) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='
}
