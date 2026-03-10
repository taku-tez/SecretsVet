package output

import (
	"encoding/json"
	"io"

	"github.com/SecretsVet/secretsvet/internal/rule"
	"github.com/SecretsVet/secretsvet/internal/scanner"
	"github.com/SecretsVet/secretsvet/internal/version"
)

// SARIFFormatter writes SARIF 2.1.0 output.
type SARIFFormatter struct{}

// SARIF 2.1.0 structs (subset needed for our use case)
type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool    `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	InformationURI  string      `json:"informationUri"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	ShortDescription sarifMessage           `json:"shortDescription"`
	HelpURI          string                 `json:"helpUri,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

var sarifRuleCatalog = []sarifRule{
	// v0.1.0 — Static manifest detection
	{ID: "SV1010", Name: "EnvValueSecretPattern", ShortDescription: sarifMessage{Text: "Secret pattern detected in env[].value"}},
	{ID: "SV1020", Name: "EnvValueHighEntropy", ShortDescription: sarifMessage{Text: "High-entropy string in env[].value"}},
	{ID: "SV1030", Name: "ArgsCommandSecret", ShortDescription: sarifMessage{Text: "Secret detected in args[] or command[]"}},
	{ID: "SV1040", Name: "ConfigMapPlaintextSecret", ShortDescription: sarifMessage{Text: "Plaintext secret in ConfigMap data"}},
	{ID: "SV1050", Name: "EnvFromConfigMapRef", ShortDescription: sarifMessage{Text: "envFrom references a ConfigMap instead of Secret"}},
	{ID: "SV1060", Name: "SecretDataHighEntropy", ShortDescription: sarifMessage{Text: "High-entropy value in Secret data"}},
	{ID: "SV1070", Name: "SecretNotImmutable", ShortDescription: sarifMessage{Text: "Secret missing immutable: true"}},
	{ID: "SV1080", Name: "CrossNamespaceSecretRef", ShortDescription: sarifMessage{Text: "Cross-namespace Secret reference detected"}},
	// v0.2.0 — External Secrets validation
	{ID: "SV2010", Name: "ESKeyRefInvalid", ShortDescription: sarifMessage{Text: "ExternalSecret key reference is empty or malformed"}},
	{ID: "SV2020", Name: "StoreConfigMissing", ShortDescription: sarifMessage{Text: "SecretStore provider configuration is incomplete"}},
	{ID: "SV2030", Name: "RefreshIntervalTooLong", ShortDescription: sarifMessage{Text: "ExternalSecret refreshInterval exceeds 24h"}},
	{ID: "SV2040", Name: "CreationPolicyMerge", ShortDescription: sarifMessage{Text: "ExternalSecret uses risky creationPolicy: Merge"}},
	{ID: "SV2050", Name: "KeyPathTypo", ShortDescription: sarifMessage{Text: "Possible typo in ExternalSecret remoteRef.key path"}},
	{ID: "SV2060", Name: "VaultPathMissing", ShortDescription: sarifMessage{Text: "VaultSecret path or mount configuration is missing"}},
	{ID: "SV2070", Name: "VaultRoleOverprivileged", ShortDescription: sarifMessage{Text: "VaultAuth role grants excessive permissions"}},
	{ID: "SV2080", Name: "LeaseRenewalMissing", ShortDescription: sarifMessage{Text: "VaultDynamicSecret missing leaseRenewalPercent"}},
	{ID: "SV2090", Name: "IAMOverPermission", ShortDescription: sarifMessage{Text: "SecretStore IAM role has overly broad permissions"}},
	{ID: "SV2100", Name: "RotationDisabled", ShortDescription: sarifMessage{Text: "ExternalSecret auto-rotation is disabled or pinned"}},
}

func severityToSarifLevel(s rule.Severity) string {
	switch s {
	case rule.SeverityCritical, rule.SeverityHigh:
		return "error"
	case rule.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func (f *SARIFFormatter) Write(w io.Writer, result *scanner.ScanResult) error {
	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "secretsvet",
						Version:        version.Version(),
						InformationURI: "https://github.com/SecretsVet/secretsvet",
						Rules:          sarifRuleCatalog,
					},
				},
			},
		},
	}

	for _, finding := range result.Findings {
		loc := sarifLocation{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: finding.File},
			},
		}
		if finding.Line > 0 {
			loc.PhysicalLocation.Region = &sarifRegion{StartLine: finding.Line}
		}

		msg := finding.Message
		if finding.Detail != "" {
			msg = msg + " — " + finding.Detail
		}

		log.Runs[0].Results = append(log.Runs[0].Results, sarifResult{
			RuleID:    finding.RuleID,
			Level:     severityToSarifLevel(finding.Severity),
			Message:   sarifMessage{Text: msg},
			Locations: []sarifLocation{loc},
		})
	}

	if log.Runs[0].Results == nil {
		log.Runs[0].Results = []sarifResult{}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
