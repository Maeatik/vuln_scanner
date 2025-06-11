package v1

import "time"

type AnalyzeResponse struct {
	RepositoryName string
	AuthorName     string
	ScanDate       time.Time
	Findings       []Finding
}

type Finding struct {
	Branch   string        // имя ветки
	File     string        // путь до файла
	Line     int           // номер строки
	Content  string        // сам текст строки
	Severity SeverityLevel // приоритет / серьёзность
	Details  string
	EPSS     float64
}
