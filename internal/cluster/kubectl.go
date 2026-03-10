// Package cluster provides utilities for interacting with a live Kubernetes cluster via kubectl.
package cluster

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// Client wraps kubectl calls for a specific context and namespace.
type Client struct {
	Context       string // kubeconfig context name (empty = current-context)
	Namespace     string // empty = default namespace
	AllNamespaces bool
}

// run executes a kubectl command and returns stdout.
func (c *Client) run(args ...string) ([]byte, error) {
	base := []string{"kubectl"}
	if c.Context != "" {
		base = append(base, "--context", c.Context)
	}
	cmd := exec.Command(base[0], append(base[1:], args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("kubectl %s: %w\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// Get fetches resources of the given kind and returns the raw JSON list.
func (c *Client) Get(kind string) (json.RawMessage, error) {
	args := []string{"get", kind, "-o", "json"}
	if c.AllNamespaces {
		args = append(args, "--all-namespaces")
	} else if c.Namespace != "" {
		args = append(args, "-n", c.Namespace)
	}
	out, err := c.run(args...)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(out), nil
}

// GetRaw fetches a specific resource by name in a specific namespace, returning raw JSON.
func (c *Client) GetRaw(kind, name, namespace string) (json.RawMessage, error) {
	args := []string{"get", kind, name, "-o", "json"}
	if namespace != "" {
		args = append(args, "-n", namespace)
	}
	out, err := c.run(args...)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(out), nil
}

// GetAPIServerPod returns the kube-apiserver pod spec (from kube-system).
func (c *Client) GetAPIServerPod() (json.RawMessage, error) {
	// kube-apiserver pods are typically named kube-apiserver-<node>
	out, err := c.run("get", "pod", "-n", "kube-system",
		"-l", "component=kube-apiserver", "-o", "json")
	if err != nil {
		return nil, fmt.Errorf("get kube-apiserver pod: %w", err)
	}
	return json.RawMessage(out), nil
}

// GetEncryptionConfig fetches the EncryptionConfiguration from the cluster
// by reading the kube-apiserver pod's command arguments.
func (c *Client) GetEncryptionConfig() (json.RawMessage, error) {
	out, err := c.run("get", "encryptionconfigurations", "-o", "json",
		"-n", "kube-system", "--ignore-not-found")
	if err != nil {
		return nil, err
	}
	return json.RawMessage(out), nil
}

// IsAvailable returns true if kubectl is installed and the cluster is reachable.
func (c *Client) IsAvailable() error {
	args := []string{"cluster-info"}
	if c.Context != "" {
		args = append([]string{"--context", c.Context}, args...)
	}
	cmd := exec.Command("kubectl", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cluster not reachable: %w\n%s", err, stderr.String())
	}
	return nil
}

// K8sList is a generic Kubernetes list response.
type K8sList struct {
	Items []json.RawMessage `json:"items"`
}

// ParseList unmarshals a Kubernetes list JSON into items.
func ParseList(data json.RawMessage) ([]json.RawMessage, error) {
	var list K8sList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	return list.Items, nil
}
