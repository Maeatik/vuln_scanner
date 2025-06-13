package analyzers

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	v1 "vuln-scanner/internal/entity"
)

type DDoSAnalyzer struct{}

func NewDDoSAnalyzer() Analyzer {
	return &DDoSAnalyzer{}
}

func (s *DDoSAnalyzer) Name() string {
	return "Проверка DDoS-угроз"
}

func (s *DDoSAnalyzer) Run(repoName, repoPath, branch string) ([]v1.Finding, error) {
	var findings []v1.Finding

	filepath.Walk(repoPath, func(file string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(file, ".go") || !strings.HasSuffix(file, ".py") || !strings.HasSuffix(file, ".java") || isTestOrMock(file) {
			return nil
		}

		f, err := os.Open(file)
		if err != nil {
			return nil
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}

		for i, line := range lines {
			// 1) прямой ListenAndServe
			if v1.ListenPattern.MatchString(line) {
				findings = append(findings, v1.Finding{
					Branch:   branch,
					File:     file,
					Line:     i + 1,
					Content:  strings.TrimSpace(line),
					Severity: v1.SevMedium,
				})
				continue
			}
			// 2) &http.Server{ ... } без таймаутов
			if v1.ServerPattern.MatchString(line) {
				hasTimeout := false
				for j := i; j < i+15 && j < len(lines); j++ {
					if v1.TimeoutPattern.MatchString(lines[j]) || v1.PyDDOSPattern.MatchString(lines[j]) || v1.JavaDDOSPattern.MatchString(lines[j]) {
						hasTimeout = true
						break
					}
					if strings.Contains(lines[j], "}") {
						break
					}
				}
				if !hasTimeout {
					findings = append(findings, v1.Finding{
						Branch:   branch,
						File:     file,
						Line:     i + 1,
						Content:  strings.TrimSpace(line),
						Severity: v1.SevMedium,
					})
				}
			}
		}
		return nil
	})

	return findings, nil
}
