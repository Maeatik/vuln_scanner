package v1

import (
	"encoding/json"
	"time"
)

type Job struct {
	Text   string `json:"text"`
	ChatID int64  `json:"chat_id"`
}

func (r Job) MarshalBinary() ([]byte, error) {
	return json.Marshal(r)
}

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
