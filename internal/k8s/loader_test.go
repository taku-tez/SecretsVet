package k8s

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── ParseYAMLString ───────────────────────────────────────────────────────────

func TestParseYAMLString_Basic(t *testing.T) {
	yaml := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  namespace: production`

	resources, err := ParseYAMLString(yaml, "test.yaml")
	if err != nil {
		t.Fatalf("ParseYAMLString: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	r := resources[0]
	if r.Kind != "Deployment" {
		t.Errorf("Kind: got %q, want %q", r.Kind, "Deployment")
	}
	if r.Name != "myapp" {
		t.Errorf("Name: got %q, want %q", r.Name, "myapp")
	}
	if r.Namespace != "production" {
		t.Errorf("Namespace: got %q, want %q", r.Namespace, "production")
	}
	if r.File != "test.yaml" {
		t.Errorf("File: got %q, want %q", r.File, "test.yaml")
	}
}

func TestParseYAMLString_MultiDocument(t *testing.T) {
	yaml := `apiVersion: v1
kind: Secret
metadata:
  name: sec1
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: cm1`

	resources, err := ParseYAMLString(yaml, "multi.yaml")
	if err != nil {
		t.Fatalf("ParseYAMLString: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(resources))
	}
	if resources[0].Kind != "Secret" {
		t.Errorf("doc 0 Kind: got %q, want Secret", resources[0].Kind)
	}
	if resources[1].Kind != "ConfigMap" {
		t.Errorf("doc 1 Kind: got %q, want ConfigMap", resources[1].Kind)
	}
}

func TestParseYAMLString_Empty(t *testing.T) {
	resources, err := ParseYAMLString("", "empty.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resources) != 0 {
		t.Errorf("expected 0 resources for empty YAML, got %d", len(resources))
	}
}

func TestParseYAMLString_NoKind(t *testing.T) {
	// Non-K8s YAML (like values.yaml) — should still parse with empty Kind
	yaml := `database:
  host: postgres.svc
  password: secret123`

	resources, err := ParseYAMLString(yaml, "values.yaml")
	if err != nil {
		t.Fatalf("ParseYAMLString: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	if resources[0].Kind != "" {
		t.Errorf("Kind should be empty for non-K8s YAML, got %q", resources[0].Kind)
	}
}

func TestParseYAMLString_LineNumbers(t *testing.T) {
	yaml := `apiVersion: v1
kind: Secret
metadata:
  name: mysecret
data:
  password: c2VjcmV0`

	resources, err := ParseYAMLString(yaml, "secret.yaml")
	if err != nil {
		t.Fatalf("ParseYAMLString: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	r := resources[0]
	m := r.MappingNode()
	if m == nil {
		t.Fatal("MappingNode() returned nil")
	}
	// Verify we can get a value with a line number
	name, line, ok := StringAt(m, "metadata", "name")
	if !ok {
		t.Fatal("StringAt metadata.name returned false")
	}
	if name != "mysecret" {
		t.Errorf("name: got %q, want mysecret", name)
	}
	if line < 1 {
		t.Errorf("line number should be >= 1, got %d", line)
	}
}

// ── LoadPath ──────────────────────────────────────────────────────────────────

func TestLoadPath_SingleFile(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: v1
kind: ConfigMap
metadata:
  name: test-cm
data:
  key: value`
	path := filepath.Join(dir, "cm.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	resources, err := LoadPath(path, LoadOptions{})
	if err != nil {
		t.Fatalf("LoadPath: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	if resources[0].Kind != "ConfigMap" {
		t.Errorf("Kind: got %q, want ConfigMap", resources[0].Kind)
	}
}

func TestLoadPath_Directory(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"deploy.yaml": `apiVersion: apps/v1
kind: Deployment
metadata:
  name: app`,
		"secret.yaml": `apiVersion: v1
kind: Secret
metadata:
  name: sec`,
		"notes.txt": "ignored",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}

	resources, err := LoadPath(dir, LoadOptions{Recursive: false})
	if err != nil {
		t.Fatalf("LoadPath dir: %v", err)
	}
	if len(resources) != 2 {
		t.Errorf("expected 2 resources, got %d", len(resources))
	}
}

func TestLoadPath_DirectoryRecursive(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "sub")
	if err := os.MkdirAll(subdir, 0700); err != nil {
		t.Fatal(err)
	}

	for _, p := range []struct{ path, content string }{
		{filepath.Join(dir, "root.yaml"), `apiVersion: v1
kind: ConfigMap
metadata:
  name: root`},
		{filepath.Join(subdir, "sub.yaml"), `apiVersion: v1
kind: ConfigMap
metadata:
  name: sub`},
	} {
		if err := os.WriteFile(p.path, []byte(p.content), 0600); err != nil {
			t.Fatal(err)
		}
	}

	// Non-recursive: only root
	resources, err := LoadPath(dir, LoadOptions{Recursive: false})
	if err != nil {
		t.Fatalf("LoadPath non-recursive: %v", err)
	}
	if len(resources) != 1 {
		t.Errorf("non-recursive: expected 1, got %d", len(resources))
	}

	// Recursive: both
	resources, err = LoadPath(dir, LoadOptions{Recursive: true})
	if err != nil {
		t.Fatalf("LoadPath recursive: %v", err)
	}
	if len(resources) != 2 {
		t.Errorf("recursive: expected 2, got %d", len(resources))
	}
}

func TestLoadPath_Stdin(t *testing.T) {
	// Write YAML to a temp file and use it as stdin
	yaml := `apiVersion: v1
kind: Secret
metadata:
  name: stdin-secret`

	// Save stdin and restore
	origStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	if _, err := w.WriteString(yaml); err != nil {
		t.Fatal(err)
	}
	w.Close()
	defer func() { os.Stdin = origStdin }()

	resources, err := LoadPath("-", LoadOptions{})
	if err != nil {
		t.Fatalf("LoadPath stdin: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource from stdin, got %d", len(resources))
	}
	if resources[0].Kind != "Secret" {
		t.Errorf("Kind: got %q, want Secret", resources[0].Kind)
	}
}

func TestLoadPath_NotFound(t *testing.T) {
	_, err := LoadPath("/nonexistent/path.yaml", LoadOptions{})
	if err == nil {
		t.Error("expected error for nonexistent path, got nil")
	}
}

// ── Resource navigation helpers ───────────────────────────────────────────────

func TestNodeAt_NestedPath(t *testing.T) {
	resources, _ := ParseYAMLString(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  namespace: default
spec:
  replicas: 1`, "test.yaml")

	m := resources[0].MappingNode()
	n, ok := NodeAt(m, "spec", "replicas")
	if !ok {
		t.Fatal("NodeAt spec.replicas: not found")
	}
	if n.Value != "1" {
		t.Errorf("replicas: got %q, want 1", n.Value)
	}
}

func TestNodeAt_Missing(t *testing.T) {
	resources, _ := ParseYAMLString(`apiVersion: v1
kind: Secret
metadata:
  name: x`, "test.yaml")

	m := resources[0].MappingNode()
	_, ok := NodeAt(m, "spec", "nonexistent", "deep")
	if ok {
		t.Error("NodeAt should return false for missing path")
	}
}

func TestSequenceAt(t *testing.T) {
	resources, _ := ParseYAMLString(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
        - name: main
          image: nginx`, "test.yaml")

	m := resources[0].MappingNode()
	items, ok := SequenceAt(m, "spec", "template", "spec", "containers")
	if !ok {
		t.Fatal("SequenceAt containers: not found")
	}
	if len(items) != 1 {
		t.Errorf("expected 1 container, got %d", len(items))
	}
}

func TestMappingPairs(t *testing.T) {
	resources, _ := ParseYAMLString(`apiVersion: v1
kind: ConfigMap
metadata:
  name: cm
data:
  key1: val1
  key2: val2`, "test.yaml")

	m := resources[0].MappingNode()
	dataNode, ok := NodeAt(m, "data")
	if !ok {
		t.Fatal("data not found")
	}
	pairs := MappingPairs(dataNode)
	if len(pairs) != 2 {
		t.Errorf("expected 2 pairs, got %d", len(pairs))
	}
}

func TestContainerPaths_Deployment(t *testing.T) {
	resources, _ := ParseYAMLString(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
        - name: main
      initContainers:
        - name: init`, "test.yaml")

	paths := ContainerPaths(resources[0].Node)
	// Should find both containers and initContainers
	total := 0
	for _, p := range paths {
		total += len(p)
	}
	if total != 2 {
		t.Errorf("expected 2 containers total, got %d", total)
	}
}

func TestContainerPaths_CronJob(t *testing.T) {
	resources, _ := ParseYAMLString(`apiVersion: batch/v1
kind: CronJob
metadata:
  name: myjob
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: worker`, "test.yaml")

	paths := ContainerPaths(resources[0].Node)
	total := 0
	for _, p := range paths {
		total += len(p)
	}
	if total != 1 {
		t.Errorf("CronJob: expected 1 container, got %d", total)
	}
}

func TestMappingNode_NilSafe(t *testing.T) {
	r := &Resource{}
	if r.MappingNode() != nil {
		t.Error("MappingNode on empty resource should return nil")
	}
}

// ── Multi-document with separator ────────────────────────────────────────────

func TestParseYAMLString_EmptySections(t *testing.T) {
	yaml := `---
apiVersion: v1
kind: Secret
metadata:
  name: s1
---
# comment only section
---
apiVersion: v1
kind: Secret
metadata:
  name: s2`

	resources, err := ParseYAMLString(yaml, "multi.yaml")
	if err != nil {
		t.Fatalf("ParseYAMLString: %v", err)
	}
	if len(resources) != 2 {
		t.Errorf("expected 2 resources, got %d", len(resources))
	}
}

// ── Scalar type edge cases ────────────────────────────────────────────────────

func TestStringAt_BoolValue(t *testing.T) {
	resources, _ := ParseYAMLString(`apiVersion: v1
kind: Secret
metadata:
  name: x
immutable: true`, "test.yaml")

	m := resources[0].MappingNode()
	val, _, ok := StringAt(m, "immutable")
	if !ok {
		t.Fatal("StringAt immutable: not found")
	}
	if !strings.Contains(val, "true") {
		t.Errorf("immutable: got %q, want 'true'", val)
	}
}
