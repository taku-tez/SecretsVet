package fixer

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/rule"
	"github.com/anthropics/anthropic-sdk-go"
)

// LLMFix generates a fix suggestion using the Claude API.
// Returns nil if ANTHROPIC_API_KEY is not set.
func LLMFix(finding rule.Finding, lang string) (*FixSuggestion, error) {
	if os.Getenv("ANTHROPIC_API_KEY") == "" {
		return nil, nil
	}

	client := anthropic.NewClient()

	langInstruction := ""
	if strings.ToLower(lang) == "ja" {
		langInstruction = "Provide the explanation in Japanese. The YAML snippet may remain in English (it's code)."
	}

	prompt := fmt.Sprintf(`You are a Kubernetes security expert. A security scanner found the following issue:

Rule ID: %s
Severity: %s
Message: %s
File: %s
Resource: %s/%s (namespace: %s)
Detail: %s

%s

Please provide:
1. A brief "Problem" explanation (1-2 sentences)
2. A concise "Solution" explanation (1-2 sentences)
3. A "YAML Snippet" showing the fix (a concrete, minimal YAML example)

Format your response EXACTLY as:
PROBLEM: <problem explanation>
SOLUTION: <solution explanation>
YAML:
<yaml snippet here>`,
		finding.RuleID, finding.Severity, finding.Message,
		finding.File, finding.ResourceKind, finding.ResourceName, finding.Namespace,
		finding.Detail, langInstruction)

	resp, err := client.Messages.New(context.Background(), anthropic.MessageNewParams{
		Model:     anthropic.ModelClaudeOpus4_6,
		MaxTokens: 1024,
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(prompt)),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("claude api: %w", err)
	}

	var text string
	for _, block := range resp.Content {
		if tb, ok := block.AsAny().(anthropic.TextBlock); ok {
			text = tb.Text
			break
		}
	}

	return parseLLMResponse(finding, text), nil
}

// parseLLMResponse extracts the structured fix from Claude's response.
func parseLLMResponse(finding rule.Finding, text string) *FixSuggestion {
	fix := &FixSuggestion{
		RuleID:   finding.RuleID,
		Severity: string(finding.Severity),
		Source:   "llm",
	}

	lines := strings.Split(text, "\n")
	var yamlLines []string
	inYAML := false

	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "PROBLEM:"):
			fix.Problem = strings.TrimSpace(strings.TrimPrefix(line, "PROBLEM:"))
		case strings.HasPrefix(line, "SOLUTION:"):
			fix.Solution = strings.TrimSpace(strings.TrimPrefix(line, "SOLUTION:"))
		case strings.TrimSpace(line) == "YAML:":
			inYAML = true
		case inYAML:
			yamlLines = append(yamlLines, line)
		}
	}

	if len(yamlLines) > 0 {
		fix.YAMLSnippet = strings.TrimSpace(strings.Join(yamlLines, "\n"))
	}

	// Fallback if parsing failed
	if fix.Problem == "" {
		fix.Problem = finding.Message
	}
	if fix.Solution == "" {
		fix.Solution = text
	}

	return fix
}

// GenerateFix tries static template first, then falls back to LLM.
func GenerateFix(finding rule.Finding, lang string, useLLM bool) (*FixSuggestion, error) {
	// Try static template first (faster, no API cost)
	if fix := StaticFix(finding, lang); fix != nil {
		return fix, nil
	}

	// Fall back to LLM if enabled and API key available
	if useLLM {
		return LLMFix(finding, lang)
	}

	return nil, nil
}
