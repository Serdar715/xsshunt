package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"xsshunt/internal/config"
)

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
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSSHunt Scan Report - {{.TargetURL}}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0f0f1a;
            --bg-secondary: #1a1a2e;
            --bg-card: #16213e;
            --accent-primary: #00d4ff;
            --accent-secondary: #7b2cbf;
            --text-primary: #ffffff;
            --text-secondary: #a0a0b0;
            --success: #00ff88;
            --warning: #ffaa00;
            --danger: #ff4444;
            --critical: #ff0055;
            --border-color: rgba(255, 255, 255, 0.1);
            --glow-primary: 0 0 20px rgba(0, 212, 255, 0.3);
            --glow-danger: 0 0 20px rgba(255, 68, 68, 0.3);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, var(--bg-primary) 0%, var(--bg-secondary) 50%, var(--bg-primary) 100%);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.6;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 40px 20px;
        }

        /* Header Section */
        .header {
            text-align: center;
            padding: 60px 40px;
            background: linear-gradient(135deg, rgba(123, 44, 191, 0.1) 0%, rgba(0, 212, 255, 0.1) 100%);
            border-radius: 24px;
            margin-bottom: 40px;
            border: 1px solid var(--border-color);
            backdrop-filter: blur(10px);
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--accent-primary), var(--accent-secondary), var(--accent-primary));
        }

        .header h1 {
            font-size: 3rem;
            font-weight: 700;
            background: linear-gradient(90deg, var(--accent-primary), var(--accent-secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 15px;
            letter-spacing: -1px;
        }

        .header .logo {
            font-size: 4rem;
            margin-bottom: 10px;
        }

        .header .subtitle {
            font-size: 1.1rem;
            color: var(--text-secondary);
            margin-bottom: 20px;
        }

        .header .target-url {
            display: inline-block;
            background: rgba(0, 212, 255, 0.1);
            padding: 12px 24px;
            border-radius: 12px;
            border: 1px solid rgba(0, 212, 255, 0.3);
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.95rem;
            word-break: break-all;
            max-width: 100%;
        }

        .header .scan-meta {
            margin-top: 20px;
            display: flex;
            justify-content: center;
            gap: 30px;
            flex-wrap: wrap;
        }

        .header .meta-item {
            display: flex;
            align-items: center;
            gap: 8px;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        .header .meta-item .icon {
            font-size: 1.2rem;
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }

        .stat-card {
            background: var(--bg-card);
            padding: 30px;
            border-radius: 16px;
            text-align: center;
            border: 1px solid var(--border-color);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: var(--glow-primary);
            border-color: var(--accent-primary);
        }

        .stat-card.danger:hover {
            box-shadow: var(--glow-danger);
            border-color: var(--danger);
        }

        .stat-card .icon {
            font-size: 2.5rem;
            margin-bottom: 15px;
        }

        .stat-card .value {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 8px;
        }

        .stat-card .label {
            color: var(--text-secondary);
            font-size: 0.95rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .stat-card.danger .value {
            color: var(--danger);
        }

        .stat-card.success .value {
            color: var(--success);
        }

        .stat-card.warning .value {
            color: var(--warning);
        }

        .stat-card.info .value {
            color: var(--accent-primary);
        }

        /* Vulnerabilities Section */
        .section {
            background: var(--bg-card);
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 30px;
            border: 1px solid var(--border-color);
        }

        .section-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 1px solid var(--border-color);
        }

        .section-header h2 {
            font-size: 1.5rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .section-header .count {
            background: var(--danger);
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.9rem;
            font-weight: 600;
        }

        /* Vulnerability Cards */
        .vuln-card {
            background: linear-gradient(135deg, rgba(255, 68, 68, 0.05) 0%, rgba(255, 68, 68, 0.02) 100%);
            border: 1px solid rgba(255, 68, 68, 0.2);
            border-left: 4px solid var(--danger);
            border-radius: 0 12px 12px 0;
            padding: 25px;
            margin-bottom: 20px;
            transition: all 0.3s ease;
        }

        .vuln-card:hover {
            border-color: var(--danger);
            box-shadow: var(--glow-danger);
            transform: translateX(5px);
        }

        .vuln-card:last-child {
            margin-bottom: 0;
        }

        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 15px;
        }

        .vuln-type {
            font-size: 1.2rem;
            font-weight: 600;
            color: var(--danger);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .severity-badge {
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .severity-critical {
            background: linear-gradient(135deg, var(--critical) 0%, #ff0088 100%);
            color: white;
            animation: pulse 2s infinite;
        }

        .severity-high {
            background: linear-gradient(135deg, var(--danger) 0%, #ff6666 100%);
            color: white;
        }

        .severity-medium {
            background: linear-gradient(135deg, var(--warning) 0%, #ffcc00 100%);
            color: #000;
        }

        .severity-low {
            background: linear-gradient(135deg, #4a9eff 0%, #00ccff 100%);
            color: white;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.8; }
        }

        .vuln-details {
            display: grid;
            gap: 12px;
        }

        .detail-row {
            display: grid;
            grid-template-columns: 120px 1fr;
            gap: 15px;
            align-items: start;
        }

        .detail-label {
            color: var(--text-secondary);
            font-size: 0.9rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .detail-value {
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.9rem;
            word-break: break-all;
            background: rgba(0, 0, 0, 0.2);
            padding: 10px 15px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }

        .detail-value.payload {
            background: rgba(255, 68, 68, 0.1);
            border-color: rgba(255, 68, 68, 0.2);
            color: var(--danger);
        }

        .detail-value.url {
            color: var(--accent-primary);
        }

        /* Success State */
        .no-vulns {
            text-align: center;
            padding: 60px 40px;
        }

        .no-vulns .icon {
            font-size: 5rem;
            margin-bottom: 20px;
        }

        .no-vulns h3 {
            font-size: 1.8rem;
            color: var(--success);
            margin-bottom: 10px;
        }

        .no-vulns p {
            color: var(--text-secondary);
        }

        /* Footer */
        .footer {
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        .footer a {
            color: var(--accent-primary);
            text-decoration: none;
        }

        .footer a:hover {
            text-decoration: underline;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .header h1 {
                font-size: 2rem;
            }

            .detail-row {
                grid-template-columns: 1fr;
                gap: 5px;
            }

            .vuln-header {
                flex-direction: column;
            }
        }

        /* Animations */
        .fade-in {
            animation: fadeIn 0.5s ease-out forwards;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .stat-card:nth-child(1) { animation-delay: 0.1s; }
        .stat-card:nth-child(2) { animation-delay: 0.2s; }
        .stat-card:nth-child(3) { animation-delay: 0.3s; }
        .stat-card:nth-child(4) { animation-delay: 0.4s; }
    </style>
</head>
<body>
    <div class="container">
        <header class="header fade-in">
            <div class="logo">🕵️</div>
            <h1>XSSHunt Scan Report</h1>
            <p class="subtitle">Advanced Cross-Site Scripting Vulnerability Analysis</p>
            <div class="target-url">{{.TargetURL}}</div>
            <div class="scan-meta">
                <div class="meta-item">
                    <span class="icon">📅</span>
                    <span>{{.ScanStartTime.Format "2006-01-02 15:04:05"}}</span>
                </div>
                <div class="meta-item">
                    <span class="icon">⏱️</span>
                    <span>Duration: {{.ScanDuration}}</span>
                </div>
                {{if .WAFDetected}}
                <div class="meta-item">
                    <span class="icon">🛡️</span>
                    <span>WAF: {{.WAFDetected}}</span>
                </div>
                {{end}}
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card {{if gt (len .Vulnerabilities) 0}}danger{{else}}success{{end}} fade-in">
                <div class="icon">⚠️</div>
                <div class="value">{{len .Vulnerabilities}}</div>
                <div class="label">Vulnerabilities Found</div>
            </div>
            <div class="stat-card info fade-in">
                <div class="icon">🎯</div>
                <div class="value">{{.TestedPayloads}}</div>
                <div class="label">Payloads Tested</div>
            </div>
            <div class="stat-card {{if .WAFDetected}}warning{{else}}success{{end}} fade-in">
                <div class="icon">🛡️</div>
                <div class="value">{{if .WAFDetected}}{{.WAFDetected}}{{else}}None{{end}}</div>
                <div class="label">WAF Detected</div>
            </div>
            <div class="stat-card {{if gt .ErrorCount 0}}warning{{else}}success{{end}} fade-in">
                <div class="icon">📊</div>
                <div class="value">{{.ErrorCount}}</div>
                <div class="label">Errors</div>
            </div>
        </div>

        <section class="section fade-in">
            <div class="section-header">
                <h2>
                    <span>🔍</span>
                    Vulnerability Details
                </h2>
                {{if .Vulnerabilities}}
                <span class="count">{{len .Vulnerabilities}} found</span>
                {{end}}
            </div>

            {{if .Vulnerabilities}}
                {{range $i, $vuln := .Vulnerabilities}}
                <div class="vuln-card">
                    <div class="vuln-header">
                        <span class="vuln-type">
                            <span>🐛</span>
                            {{$vuln.Type}}
                        </span>
                        <span class="severity-badge severity-{{$vuln.Severity | lower}}">{{$vuln.Severity}}</span>
                    </div>
                    <div class="vuln-details">
                        <div class="detail-row">
                            <span class="detail-label">Payload</span>
                            <span class="detail-value payload">{{$vuln.Payload}}</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">URL</span>
                            <span class="detail-value url">{{$vuln.URL}}</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Parameter</span>
                            <span class="detail-value">{{$vuln.Parameter}}</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Context</span>
                            <span class="detail-value">{{$vuln.Context}}</span>
                        </div>
                        {{if $vuln.Evidence}}
                        <div class="detail-row">
                            <span class="detail-label">Evidence</span>
                            <span class="detail-value">{{$vuln.Evidence}}</span>
                        </div>
                        {{end}}
                        {{if $vuln.WAFBypassed}}
                        <div class="detail-row">
                            <span class="detail-label">WAF Bypass</span>
                            <span class="detail-value" style="color: var(--warning);">✓ WAF Successfully Bypassed</span>
                        </div>
                        {{end}}
                    </div>
                </div>
                {{end}}
            {{else}}
                <div class="no-vulns">
                    <div class="icon">✅</div>
                    <h3>No Vulnerabilities Detected</h3>
                    <p>No XSS vulnerabilities were found during this scan.</p>
                </div>
            {{end}}
        </section>

        <footer class="footer">
            <p>Report generated by <strong>XSSHunt</strong> • 
               <a href="https://github.com/Serdar715/xsshunt" target="_blank">GitHub</a> • 
               Generated on {{now.Format "2006-01-02 15:04:05 MST"}}</p>
        </footer>
    </div>
</body>
</html>`

	funcMap := template.FuncMap{
		"lower": strings.ToLower,
		"now": func() time.Time {
			return time.Now()
		},
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
