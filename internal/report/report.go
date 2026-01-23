package report

import (
	_ "embed" // Required for go:embed
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/Serdar715/xsshunt/internal/config"
)

//go:embed report.html
var reportTemplate string

// Reporter generates scan reports in various formats
type Reporter struct {
	format string
}

// New creates a new reporter with the specified format
func New(format string) *Reporter {
	return &Reporter{format: strings.ToLower(format)}
}

// Generate creates a report in the specified format
func (r *Reporter) Generate(result *config.ScanResult, outputPath string) error {
	switch r.format {
	case "json":
		return r.generateJSON(result, outputPath)
	case "html":
		return r.generateHTML(result, outputPath)
	default:
		return r.generateJSON(result, outputPath)
	}
}

// generateJSON creates a JSON report
func (r *Reporter) generateJSON(result *config.ScanResult, outputPath string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return os.WriteFile(outputPath, data, 0644)
}

// generateHTML creates a professional HTML report
func (r *Reporter) generateHTML(result *config.ScanResult, outputPath string) error {
	funcMap := template.FuncMap{
		"lower": strings.ToLower,
		"now": func() time.Time {
			return time.Now()
		},
	}

	t, err := template.New("report").Funcs(funcMap).Parse(reportTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	return t.Execute(file, result)
}
