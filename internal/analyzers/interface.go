package analyzers

import v1 "vuln-scanner/internal/entity"

type Analyzer interface {
	Name() string
	Run(repoName, path, branch string) ([]v1.Finding, error)
	Classify(match string) v1.SeverityLevel
}
