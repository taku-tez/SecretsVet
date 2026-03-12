package k8s

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadOptions controls how paths are loaded.
type LoadOptions struct {
	Recursive bool
	Kustomize bool
}

// LoadPath loads all Kubernetes resources from the given path.
// If path is "-", resources are read from os.Stdin (for use with helm template | secretsvet scan -).
// If path is a directory, it walks the directory (and subdirs if Recursive).
// If Kustomize is true and a kustomization.yaml is found, it runs kustomize build.
func LoadPath(path string, opts LoadOptions) ([]*Resource, error) {
	if path == "-" {
		return parseYAML(os.Stdin, "<stdin>")
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	if !info.IsDir() {
		return loadFile(path)
	}

	// Directory
	if opts.Kustomize {
		kustomizationExists := false
		for _, name := range []string{"kustomization.yaml", "kustomization.yml"} {
			if _, err := os.Stat(filepath.Join(path, name)); err == nil {
				kustomizationExists = true
				break
			}
		}
		if kustomizationExists {
			return loadKustomize(path)
		}
	}

	return loadDir(path, opts.Recursive)
}

// loadFile parses a single YAML file (possibly multi-document).
func loadFile(path string) ([]*Resource, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	return parseYAML(f, path)
}

// loadDir walks a directory and loads all .yaml/.yml files.
func loadDir(dir string, recursive bool) ([]*Resource, error) {
	var resources []*Resource

	walkFn := func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != dir && !recursive {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(d.Name())
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		res, err := loadFile(path)
		if err != nil {
			// Non-fatal: warn and continue
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", path, err)
			return nil
		}
		resources = append(resources, res...)
		return nil
	}

	if err := filepath.WalkDir(dir, walkFn); err != nil {
		return nil, err
	}
	return resources, nil
}

// loadKustomize runs `kustomize build <dir>` and parses the output.
func loadKustomize(dir string) ([]*Resource, error) {
	cmd := exec.Command("kustomize", "build", dir)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("kustomize build %s: %w", dir, err)
	}
	return parseYAML(bytes.NewReader(out), fmt.Sprintf("kustomize:%s", dir))
}

// ParseYAMLString parses a YAML string and returns the resources. Useful in tests.
func ParseYAMLString(content, path string) ([]*Resource, error) {
	return parseYAML(strings.NewReader(content), path)
}

// parseYAML decodes all documents from a reader into Resources.
func parseYAML(r io.Reader, path string) ([]*Resource, error) {
	var resources []*Resource
	dec := yaml.NewDecoder(r)
	for {
		var node yaml.Node
		if err := dec.Decode(&node); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		// Unwrap DocumentNode
		m := &node
		if m.Kind == yaml.DocumentNode && len(m.Content) > 0 {
			m = m.Content[0]
		}
		if m.Kind != yaml.MappingNode {
			continue
		}

		res := &Resource{
			File: path,
			Node: &node,
		}

		// Extract kind, name, namespace
		if v, _, ok := StringAt(m, "kind"); ok {
			res.Kind = v
		}
		if v, _, ok := StringAt(m, "metadata", "name"); ok {
			res.Name = v
		}
		if v, _, ok := StringAt(m, "metadata", "namespace"); ok {
			res.Namespace = v
		}

		resources = append(resources, res)
	}
	return resources, nil
}
