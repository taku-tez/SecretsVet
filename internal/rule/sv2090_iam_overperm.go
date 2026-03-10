package rule

import (
	"fmt"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/k8s"
	"gopkg.in/yaml.v3"
)

// SV2090 detects overly broad IAM role permissions in SecretStore/ClusterSecretStore
// for AWS Secrets Manager and GCP Secret Manager backends.
type iamOverPermRule struct{}

func NewIAMOverPermRule() Rule { return &iamOverPermRule{} }
func (r *iamOverPermRule) ID() string { return "SV2090" }

func (r *iamOverPermRule) Check(res *k8s.Resource) []Finding {
	switch res.Kind {
	case "SecretStore", "ClusterSecretStore":
	default:
		return nil
	}

	m := res.MappingNode()
	if m == nil {
		return nil
	}

	var findings []Finding

	// AWS: check roleArn
	awsNode, hasAWS := k8s.NodeAt(m, "spec", "provider", "aws")
	if hasAWS && awsNode != nil {
		findings = append(findings, checkAWSRoleArn(res, awsNode)...)
	}

	// GCP: check workloadIdentity serviceAccountRef
	gcpNode, hasGCP := k8s.NodeAt(m, "spec", "provider", "gcpsm")
	if hasGCP && gcpNode != nil {
		findings = append(findings, checkGCPServiceAccount(res, gcpNode)...)
	}

	return findings
}

func checkAWSRoleArn(res *k8s.Resource, awsNode *yaml.Node) []Finding {
	var findings []Finding

	// Check auth.jwt.serviceAccountRef or auth.secretRef
	roleArn, arnLine, arnOk := k8s.StringAt(awsNode, "auth", "jwt", "serviceAccountRef", "annotations", "eks.amazonaws.com/role-arn")
	if !arnOk {
		// Try alternate path
		roleArn, arnLine, arnOk = k8s.StringAt(awsNode, "roleArn")
	}

	if arnOk && roleArn != "" {
		// Wildcard or admin-level role names are suspicious
		if isOverlyBroadARN(roleArn) {
			findings = append(findings, Finding{
				RuleID:       "SV2090",
				Severity:     SeverityMedium,
				Message:      fmt.Sprintf("SecretStore AWS roleArn appears to grant broad access: %s", maskARN(roleArn)),
				File:         res.File,
				Line:         arnLine,
				ResourceKind: res.Kind,
				ResourceName: res.Name,
				Namespace:    res.Namespace,
				Detail:       "use an IAM role scoped to read-only access on specific secrets (e.g. secretsmanager:GetSecretValue on specific ARNs)",
			})
		}
	}

	return findings
}

func checkGCPServiceAccount(res *k8s.Resource, gcpNode *yaml.Node) []Finding {
	var findings []Finding

	sa, saLine, saOk := k8s.StringAt(gcpNode, "auth", "workloadIdentity", "serviceAccountRef", "name")
	if saOk && sa != "" {
		if strings.Contains(strings.ToLower(sa), "admin") ||
			strings.Contains(strings.ToLower(sa), "owner") ||
			strings.Contains(strings.ToLower(sa), "editor") {
			findings = append(findings, Finding{
				RuleID:       "SV2090",
				Severity:     SeverityMedium,
				Message:      fmt.Sprintf("SecretStore GCP serviceAccount %q name suggests broad permissions", sa),
				File:         res.File,
				Line:         saLine,
				ResourceKind: res.Kind,
				ResourceName: res.Name,
				Namespace:    res.Namespace,
				Detail:       "use a GCP service account with only 'roles/secretmanager.secretAccessor' on specific secrets",
			})
		}
	}

	return findings
}

func isOverlyBroadARN(arn string) bool {
	lower := strings.ToLower(arn)
	// Wildcards in ARN resource part
	if strings.HasSuffix(arn, "*") {
		return true
	}
	// Admin-level role names
	for _, term := range []string{"admin", "poweruser", "fullaccess", "root"} {
		if strings.Contains(lower, term) {
			return true
		}
	}
	return false
}

func maskARN(arn string) string {
	// Show only account and role name, mask account ID partially
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		accountID := parts[4]
		if len(accountID) > 4 {
			parts[4] = accountID[:4] + "****"
		}
		return strings.Join(parts, ":")
	}
	return arn
}
