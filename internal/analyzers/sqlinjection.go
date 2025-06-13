package analyzers

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	v1 "vuln-scanner/internal/entity"
)

type SQLInjectionAnalyzer struct{}

func NewSQLInjectionAnalyzer() Analyzer {
	return &SQLInjectionAnalyzer{}
}

func (s *SQLInjectionAnalyzer) Name() string {
	return "Проверка SQL-инъекций"
}

func (s *SQLInjectionAnalyzer) Run(repoName, repoPath, branch string) ([]v1.Finding, error) {
	var findings []v1.Finding

	err := filepath.Walk(repoPath, func(file string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(file))
		patterns, ok := v1.SqlPatternsByExt[ext]
		if !ok {
			return nil
		}

		if isTestOrMock(file) {
			return nil
		}

		f, err := os.Open(file)
		if err != nil {
			return nil
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		lineNum := 0

		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			for _, pat := range patterns {
				if pat.MatchString(line) {
					findings = append(findings, v1.Finding{
						Branch:   branch,
						File:     file,
						Line:     lineNum,
						Content:  strings.TrimSpace(line),
						Severity: v1.SevMedium,
					})
					break
				}
			}
		}
		return nil
	})
	return findings, err
}
