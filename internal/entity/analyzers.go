package v1

import "time"

type AnalyzeResponse struct {
	RepositoryName string
	AuthorName     string
	ScanDate       time.Time
	Findings       []Finding
}

type Finding struct {
	Branch   string
	File     string
	Line     int
	Content  string
	Severity SeverityLevel
	Details  string
	EPSS     float64
}
