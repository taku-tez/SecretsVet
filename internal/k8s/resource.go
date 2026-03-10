package k8s

import "gopkg.in/yaml.v3"

// Resource holds a single parsed Kubernetes manifest document.
type Resource struct {
	Kind      string
	Name      string
	Namespace string
	File      string
	Node      *yaml.Node // DocumentNode → MappingNode
}

// MappingNode returns the root MappingNode (unwrapping DocumentNode if needed).
func (r *Resource) MappingNode() *yaml.Node {
	if r.Node == nil {
		return nil
	}
	n := r.Node
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	if n.Kind == yaml.MappingNode {
		return n
	}
	return nil
}

// NodeAt traverses a path of keys in a MappingNode and returns the value node.
func NodeAt(m *yaml.Node, keys ...string) (*yaml.Node, bool) {
	if m == nil {
		return nil, false
	}
	cur := m
	if cur.Kind == yaml.DocumentNode && len(cur.Content) > 0 {
		cur = cur.Content[0]
	}
	for _, key := range keys {
		if cur.Kind != yaml.MappingNode {
			return nil, false
		}
		found := false
		for i := 0; i+1 < len(cur.Content); i += 2 {
			if cur.Content[i].Value == key {
				cur = cur.Content[i+1]
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return cur, true
}

// StringAt traverses a path and returns the string value and line number.
func StringAt(m *yaml.Node, keys ...string) (string, int, bool) {
	n, ok := NodeAt(m, keys...)
	if !ok || n == nil {
		return "", 0, false
	}
	if n.Kind == yaml.ScalarNode {
		return n.Value, n.Line, true
	}
	return "", 0, false
}

// SequenceAt traverses a path and returns the items of a sequence node.
func SequenceAt(m *yaml.Node, keys ...string) ([]*yaml.Node, bool) {
	n, ok := NodeAt(m, keys...)
	if !ok || n == nil || n.Kind != yaml.SequenceNode {
		return nil, false
	}
	return n.Content, true
}

// MappingPairs returns key/value node pairs from a MappingNode.
func MappingPairs(m *yaml.Node) [][2]*yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	var pairs [][2]*yaml.Node
	for i := 0; i+1 < len(m.Content); i += 2 {
		pairs = append(pairs, [2]*yaml.Node{m.Content[i], m.Content[i+1]})
	}
	return pairs
}

// ContainerPaths returns the list of container arrays from known workload paths.
// Works for Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob, ReplicaSet.
func ContainerPaths(root *yaml.Node) [][]*yaml.Node {
	m := root
	if m != nil && m.Kind == yaml.DocumentNode && len(m.Content) > 0 {
		m = m.Content[0]
	}

	var results [][]*yaml.Node

	// Direct Pod spec
	if containers, ok := SequenceAt(m, "spec", "containers"); ok {
		results = append(results, containers)
	}
	if containers, ok := SequenceAt(m, "spec", "initContainers"); ok {
		results = append(results, containers)
	}

	// Workloads with spec.template.spec.containers
	if containers, ok := SequenceAt(m, "spec", "template", "spec", "containers"); ok {
		results = append(results, containers)
	}
	if containers, ok := SequenceAt(m, "spec", "template", "spec", "initContainers"); ok {
		results = append(results, containers)
	}

	// CronJob: spec.jobTemplate.spec.template.spec.containers
	if containers, ok := SequenceAt(m, "spec", "jobTemplate", "spec", "template", "spec", "containers"); ok {
		results = append(results, containers)
	}
	if containers, ok := SequenceAt(m, "spec", "jobTemplate", "spec", "template", "spec", "initContainers"); ok {
		results = append(results, containers)
	}

	return results
}
