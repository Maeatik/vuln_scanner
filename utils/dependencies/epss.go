package dependencies

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
	v1 "vuln-scanner/internal/entity"
)

type epssEntry struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
}

type epssResponse struct {
	Status string      `json:"status"`
	Data   []epssEntry `json:"data"`
}

func FetchEPSS(cve string) (float64, error) {
	if cve == "" {
		return 0, nil
	}

	url := "https://api.first.org/data/v1/epss?cve=" + cve

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return 0, fmt.Errorf("EPSS request failed: %w", err)
	}
	defer resp.Body.Close()

	var r epssResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return 0, fmt.Errorf("failed to decode EPSS JSON: %w", err)
	}

	if len(r.Data) == 0 {
		return 0, fmt.Errorf("no EPSS data for %s", cve)
	}

	epss, err := strconv.ParseFloat(r.Data[0].EPSS, 64)
	if err != nil {
		return 0, fmt.Errorf("failed parse EPSS data: %v", err)

	}
	return epss, nil
}

func MapEPSS(v float64) v1.SeverityLevel {
	switch {
	case v >= 0.1:
		return v1.SevHigh
	case v >= 0.01:
		return v1.SevMedium
	default:
		return v1.SevLow
	}
}
