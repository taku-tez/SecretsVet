// Package config loads and applies .secretsvet.yaml project configuration.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level structure of .secretsvet.yaml.
type Config struct {
	Rules      map[string]RuleConfig `yaml:"rules"`
	Thresholds ThresholdConfig       `yaml:"thresholds"`
	Ignore     IgnoreConfig          `yaml:"ignore"`
}

// RuleConfig allows per-rule overrides.
type RuleConfig struct {
	Disabled bool   `yaml:"disabled"`
	Severity string `yaml:"severity"` // override: CRITICAL, HIGH, MEDIUM, LOW
}

// ThresholdConfig controls detection sensitivity.
type ThresholdConfig struct {
	// EntropyMinLength sets the minimum string length for entropy checks (default 20).
	EntropyMinLength int `yaml:"entropy_min_length"`
}

// IgnoreConfig specifies paths to exclude from scanning.
type IgnoreConfig struct {
	Paths []string `yaml:"paths"` // glob patterns (e.g. "tests/**", "**/*_test.yaml")
}

// DefaultConfigFile is the conventional config filename.
const DefaultConfigFile = ".secretsvet.yaml"

// Load reads a .secretsvet.yaml file from the given path.
// Returns a zero-value Config (with no overrides) if the file does not exist.
func Load(cfgPath string) (*Config, error) {
	if cfgPath == "" {
		cfgPath = DefaultConfigFile
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", cfgPath, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", cfgPath, err)
	}
	return &cfg, nil
}

// IsRuleDisabled returns true if the given rule ID is disabled in the config.
func (c *Config) IsRuleDisabled(ruleID string) bool {
	if c == nil {
		return false
	}
	if rc, ok := c.Rules[ruleID]; ok {
		return rc.Disabled
	}
	return false
}

// SeverityOverride returns the configured severity override for a rule, or "" if none.
func (c *Config) SeverityOverride(ruleID string) string {
	if c == nil {
		return ""
	}
	if rc, ok := c.Rules[ruleID]; ok {
		return rc.Severity
	}
	return ""
}

// IsPathIgnored returns true if the given file path matches any ignore glob.
func (c *Config) IsPathIgnored(filePath string) bool {
	if c == nil {
		return false
	}
	for _, pattern := range c.Ignore.Paths {
		// Try matching the full path and just the base name
		if matched, _ := filepath.Match(pattern, filePath); matched {
			return true
		}
		if matched, _ := filepath.Match(pattern, filepath.Base(filePath)); matched {
			return true
		}
		// Support ** by checking each path segment
		if matchDoublestar(pattern, filePath) {
			return true
		}
		// Also try matching against each trailing subpath so that relative
		// patterns like "tests/**" match absolute paths containing "/tests/".
		rel := filePath
		for {
			if matchDoublestar(pattern, rel) {
				return true
			}
			if matched, _ := filepath.Match(pattern, rel); matched {
				return true
			}
			idx := strings.IndexByte(rel, '/')
			if idx < 0 {
				break
			}
			rel = rel[idx+1:]
		}
	}
	return false
}

// EntropMinLength returns the configured minimum length for entropy checks,
// or 0 if not set (callers should use their own default).
func (c *Config) EntropyMinLength() int {
	if c == nil {
		return 0
	}
	return c.Thresholds.EntropyMinLength
}

// matchDoublestar handles simple ** glob matching against a path.
// Only supports patterns of the form "prefix/**" or "**/suffix".
func matchDoublestar(pattern, path string) bool {
	if idx := indexOf(pattern, "**"); idx >= 0 {
		// prefix/**/suffix
		prefix := pattern[:idx]
		suffix := pattern[idx+2:]
		if suffix != "" && suffix[0] == '/' {
			suffix = suffix[1:]
		}
		if prefix != "" {
			if !hasPathPrefix(path, prefix) {
				return false
			}
			path = path[len(prefix):]
		}
		if suffix == "" {
			return true
		}
		// suffix must match the end of path
		matched, _ := filepath.Match(suffix, filepath.Base(path))
		return matched
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func hasPathPrefix(path, prefix string) bool {
	if len(path) < len(prefix) {
		return false
	}
	return path[:len(prefix)] == prefix
}
