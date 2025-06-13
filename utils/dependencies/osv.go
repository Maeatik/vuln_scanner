package dependencies

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	v1 "vuln-scanner/internal/entity"
)

type OsvQuery struct {
	Version string            `json:"version"`
	Package map[string]string `json:"package"`
}

type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type OSVVulnerability struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Details  string        `json:"details"`
	Severity []OSVSeverity `json:"severity,omitempty"`
	Aliases  []string      `json:"aliases"`
}

type OsvResponse struct {
	Vulns []OSVVulnerability `json:"vulns"`
}

func QueryOSV(pkg, ver string) (OsvResponse, error) {
	q := OsvQuery{
		Version: ver,
		Package: map[string]string{
			"name":      pkg,
			"ecosystem": detectEcosystem(pkg),
		},
	}
	body, _ := json.Marshal(q)
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post("https://api.osv.dev/v1/query",
		"application/json", bytes.NewReader(body))
	if err != nil {
		return OsvResponse{}, fmt.Errorf("OSV API error: %w", err)
	}
	defer resp.Body.Close()

	var r OsvResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return OsvResponse{}, fmt.Errorf("parsing OSV JSON: %w", err)
	}
	return r, nil
}

func detectEcosystem(pkg string) string {
	switch {
	case strings.Contains(pkg, "/"):
		return "Go"
	case strings.Contains(pkg, ":"):
		return "Maven"
	default:
		return "PyPI"
	}
}

func MapOSVSeverity(v OSVVulnerability) v1.SeverityLevel {
	if len(v.Severity) == 0 {
		return v1.SevMedium
	}
	score := parseCVSSScore(v.Severity[0].Score)
	switch {
	case score >= 7.0:
		return v1.SevHigh
	case score >= 4.0:
		return v1.SevMedium
	default:
		return v1.SevLow
	}
}

func parseCVSSScore(vec string) float64 {
	parts := strings.SplitN(vec, ":", 2)
	if len(parts) != 2 {
		return 0
	}
	num := strings.SplitN(parts[1], "/", 2)[0]
	if f, err := strconv.ParseFloat(num, 64); err == nil {
		return f
	}
	return 0
}
