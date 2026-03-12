// Package baseline provides fingerprint-based suppression of known findings.
// A baseline lets teams adopt SecretsVet incrementally: save the current state,
// then only fail CI on newly introduced issues.
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/SecretsVet/secretsvet/internal/rule"
	"github.com/SecretsVet/secretsvet/internal/version"
)

// Entry describes a single suppressed finding in the baseline file.
// It is human-readable so reviewers can audit what is being suppressed.
type Entry struct {
	RuleID       string `json:"rule_id"`
	File         string `json:"file"`
	ResourceKind string `json:"resource_kind,omitempty"`
	ResourceName string `json:"resource_name,omitempty"`
	Namespace    string `json:"namespace,omitempty"`
	Message      string `json:"message"`
}

// Baseline is the serialised form written to .secretsvet-baseline.json.
type Baseline struct {
	CreatedAt         string             `json:"created_at"`
	SecretsVetVersion string             `json:"secretsvet_version"`
	TotalSuppressed   int                `json:"total_suppressed"`
	Entries           map[string]*Entry  `json:"entries"` // key = fingerprint
}

// Load reads a baseline file. Returns an empty Baseline if the file does not exist.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Baseline{Entries: map[string]*Entry{}}, nil
		}
		return nil, fmt.Errorf("read baseline %s: %w", path, err)
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	if b.Entries == nil {
		b.Entries = map[string]*Entry{}
	}
	return &b, nil
}

// Save writes a baseline from a set of findings to path.
func Save(path string, findings []rule.Finding) error {
	b := &Baseline{
		CreatedAt:         time.Now().UTC().Format(time.RFC3339),
		SecretsVetVersion: version.Version(),
		Entries:           make(map[string]*Entry, len(findings)),
	}
	for _, f := range findings {
		fp := Fingerprint(f)
		b.Entries[fp] = &Entry{
			RuleID:       f.RuleID,
			File:         f.File,
			ResourceKind: f.ResourceKind,
			ResourceName: f.ResourceName,
			Namespace:    f.Namespace,
			Message:      f.Message,
		}
	}
	b.TotalSuppressed = len(b.Entries)

	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		return fmt.Errorf("write baseline %s: %w", path, err)
	}
	return nil
}

// Contains returns true if the finding is suppressed by this baseline.
func (b *Baseline) Contains(f rule.Finding) bool {
	if b == nil || len(b.Entries) == 0 {
		return false
	}
	_, ok := b.Entries[Fingerprint(f)]
	return ok
}

// Filter returns only findings that are NOT in the baseline (i.e. newly introduced).
func Filter(findings []rule.Finding, b *Baseline) []rule.Finding {
	if b == nil || len(b.Entries) == 0 {
		return findings
	}
	var result []rule.Finding
	for _, f := range findings {
		if !b.Contains(f) {
			result = append(result, f)
		}
	}
	return result
}

// Fingerprint returns a stable identifier for a finding.
// It uses resource-level fields (not line numbers, which shift with edits).
// For non-resource findings (HelmValues, etc.) the message is included.
func Fingerprint(f rule.Finding) string {
	// Build a stable composite key
	s := f.RuleID + "\x00" + f.File + "\x00" + f.ResourceKind + "\x00" + f.ResourceName + "\x00" + f.Namespace
	// For findings without a named resource, add the message to disambiguate
	if f.ResourceName == "" {
		s += "\x00" + f.Message
	}
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:16]
}
