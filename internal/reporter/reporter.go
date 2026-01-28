package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Serdar715/xsshunt/internal/config"
	"github.com/fatih/color"
)

// Reporter handles scan result output
type Reporter struct {
	config *config.ScanConfig
}

// New creates a new reporter
func New(cfg *config.ScanConfig) *Reporter {
	return &Reporter{config: cfg}
}

// SaveResults saves results to file in specified format
func (r *Reporter) SaveResults(result *config.ScanResult) error {
	if r.config.OutputFile == "" {
		return nil
	}

	var data []byte
	var err error

	switch r.config.OutputFormat {
	case "json":
		data, err = json.MarshalIndent(result, "", "  ")
	case "markdown", "md":
		data = []byte(r.generateMarkdownReport(result))
	default:
		// Default to JSON
		data, err = json.MarshalIndent(result, "", "  ")
	}

	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	return os.WriteFile(r.config.OutputFile, data, 0644)
}

// SendWebhook sends a summary to a webhook (e.g. Discord/Slack)
func (r *Reporter) SendWebhook(result *config.ScanResult, webhookURL string) error {
	if webhookURL == "" || len(result.Vulnerabilities) == 0 {
		return nil
	}

	vulnCount := len(result.Vulnerabilities)
	message := fmt.Sprintf("🏹 **XSSHunt Scan Completed**\nTarget: %s\nVulnerabilities Found: **%d**\nDuration: %s",
		result.TargetURL, vulnCount, result.ScanDuration)

	payload := map[string]string{
		"content": message,
	}

	// Add details for first few vulns
	if vulnCount > 0 {
		payload["content"] += "\n\n**Top Findings:**"
		for i, v := range result.Vulnerabilities {
			if i >= 5 {
				break
			}
			payload["content"] += fmt.Sprintf("\n- [%s] %s (%s)", v.Severity, v.Parameter, v.Type)
		}
	}

	jsonPayload, _ := json.Marshal(payload)
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook failed with status: %d", resp.StatusCode)
	}

	color.Green("[+] Webhook notification sent!")
	return nil
}

func (r *Reporter) generateMarkdownReport(result *config.ScanResult) string {
	report := fmt.Sprintf("# XSSHunt Scan Report\n\n")
	report += fmt.Sprintf("**Target:** %s\n", result.TargetURL)
	report += fmt.Sprintf("**Date:** %s\n", result.ScanStartTime.Format(time.RFC1123))
	report += fmt.Sprintf("**Duration:** %s\n", result.ScanDuration)
	report += fmt.Sprintf("**Payloads Tested:** %d\n", result.TestedPayloads)
	report += fmt.Sprintf("**WAF Detected:** %s\n\n", result.WAFDetected)

	report += "## Vulnerabilities Found\n\n"

	if len(result.Vulnerabilities) == 0 {
		report += "_No vulnerabilities found._\n"
	} else {
		for i, v := range result.Vulnerabilities {
			report += fmt.Sprintf("### %d. %s (%s)\n", i+1, v.Type, v.Severity)
			report += fmt.Sprintf("- **URL:** `%s`\n", v.URL)
			report += fmt.Sprintf("- **Parameter:** `%s`\n", v.Parameter)
			report += fmt.Sprintf("- **Context:** `%s`\n", v.Context)
			report += fmt.Sprintf("- **Evidence:** `%s`\n", v.Evidence)
			report += fmt.Sprintf("- **Verified:** %v\n", v.Verified)
			report += fmt.Sprintf("- **Payload:**\n```\n%s\n```\n\n", v.Payload)
		}
	}

	return report
}
