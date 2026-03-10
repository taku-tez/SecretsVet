package output

import (
	"io"

	"github.com/SecretsVet/secretsvet/internal/scanner"
)

// Formatter writes scan results to a writer.
type Formatter interface {
	Write(w io.Writer, result *scanner.ScanResult) error
}
