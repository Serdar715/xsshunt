package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"strings"

	"xsshunt/internal/config"
)

// Reporter generates scan reports
type Reporter struct {
	format string
}

// New creates a new reporter
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

func (r *Reporter) generateJSON(result *config.ScanResult, outputPath string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return os.WriteFile(outputPath, data, 0644)
}

func (r *Reporter) generateHTML(result *config.ScanResult, outputPath string) error {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSSHunt Scan Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: #eee; min-height: 100vh; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { text-align: center; padding: 40px 0; background: rgba(255,255,255,0.05); border-radius: 20px; margin-bottom: 30px; backdrop-filter: blur(10px); }
        .header h1 { font-size: 2.5rem; background: linear-gradient(90deg, #00d4ff, #7b2cbf); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 10px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: rgba(255,255,255,0.05); padding: 25px; border-radius: 15px; text-align: center; border: 1px solid rgba(255,255,255,0.1); }
        .stat-card h3 { font-size: 2rem; color: #00d4ff; }
        .stat-card p { color: #aaa; margin-top: 5px; }
        .vuln-list { background: rgba(255,255,255,0.05); border-radius: 15px; padding: 20px; }
        .vuln-item { background: rgba(255,0,0,0.1); border-left: 4px solid #ff4444; padding: 20px; margin-bottom: 15px; border-radius: 0 10px 10px 0; }
        .vuln-item h4 { color: #ff6b6b; margin-bottom: 10px; }
        .vuln-item .detail { margin: 5px 0; }
        .vuln-item .label { color: #aaa; font-size: 0.9rem; }
        .vuln-item .value { color: #fff; word-break: break-all; }
        .severity-critical { color: #ff0000; font-weight: bold; }
        .severity-high { color: #ff4444; }
        .severity-medium { color: #ffaa00; }
        .severity-low { color: #00aaff; }
        .no-vulns { text-align: center; padding: 50px; color: #00ff88; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕵️ XSSHunt Scan Report</h1>
            <p>Target: {{.TargetURL}}</p>
            <p>Scan Duration: {{.ScanDuration}}</p>
        </div>
        <div class="stats">
            <div class="stat-card">
                <h3>{{len .Vulnerabilities}}</h3>
                <p>Vulnerabilities Found</p>
            </div>
            <div class="stat-card">
                <h3>{{.TestedPayloads}}</h3>
                <p>Payloads Tested</p>
            </div>
            <div class="stat-card">
                <h3>{{if .WAFDetected}}{{.WAFDetected}}{{else}}None{{end}}</h3>
                <p>WAF Detected</p>
            </div>
        </div>
        <div class="vuln-list">
            <h2 style="margin-bottom: 20px;">Vulnerabilities</h2>
            {{if .Vulnerabilities}}
                {{range .Vulnerabilities}}
                <div class="vuln-item">
                    <h4>{{.Type}}</h4>
                    <div class="detail"><span class="label">Payload:</span> <span class="value">{{.Payload}}</span></div>
                    <div class="detail"><span class="label">URL:</span> <span class="value">{{.URL}}</span></div>
                    <div class="detail"><span class="label">Parameter:</span> <span class="value">{{.Parameter}}</span></div>
                    <div class="detail"><span class="label">Context:</span> <span class="value">{{.Context}}</span></div>
                    <div class="detail"><span class="label">Severity:</span> <span class="severity-{{.Severity | lower}}">{{.Severity}}</span></div>
                </div>
                {{end}}
            {{else}}
                <div class="no-vulns">✓ No vulnerabilities found</div>
            {{end}}
        </div>
    </div>
</body>
</html>`

	funcMap := template.FuncMap{
		"lower": strings.ToLower,
	}

	t, err := template.New("report").Funcs(funcMap).Parse(tmpl)
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
