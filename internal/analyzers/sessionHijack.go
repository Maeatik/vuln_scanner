package analyzers

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	v1 "vuln-scanner/internal/entity"
)

type SessionHijackAnalyzer struct{}

func NewSessionHijackAnalyzer() Analyzer {
	return &SessionHijackAnalyzer{}
}

func (s *SessionHijackAnalyzer) Name() string {
	return "Проверка угона сессии"
}

func (s *SessionHijackAnalyzer) Run(repoName, repoPath, branch string) ([]v1.Finding, error) {
	var findings []v1.Finding

	filepath.Walk(repoPath, func(file string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(file))
		pats, ok := v1.SessionPatterns[ext]
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
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}

		for i, line := range lines {
			if !v1.SetCookieCall.MatchString(line) {
				continue
			}
			switch ext {
			case "go":
				ok := GoCheckSession(lines, line, i)
				if !ok {
					findings = append(findings, v1.Finding{
						Branch:   branch,
						File:     file,
						Line:     i + 1,
						Content:  strings.TrimSpace(line),
						Severity: v1.SevHigh,
					})
				}
			default:
				ok := NoGoCheckSession(lines, line, i, pats)
				if !ok {
					findings = append(findings, v1.Finding{
						Branch:   branch,
						File:     file,
						Line:     i + 1,
						Content:  strings.TrimSpace(line),
						Severity: v1.SevHigh,
					})
				}
			}

		}
		return nil
	})

	if len(findings) == 0 {
		return nil, nil
	}
	return findings, nil
}

func GoCheckSession(allLines []string, line string, lineNum int) bool {
	ok := false

	if v1.SetCookiePattern.MatchString(line) {
		for j := lineNum; j < lineNum+10 && j < len(allLines); j++ {
			if v1.HttpOnlyPattern.MatchString(allLines[j]) {
				ok = true
				break
			}
		}
	}

	return ok
}

func NoGoCheckSession(allLines []string, line string, lineNum int, pats []*regexp.Regexp) bool {
	ok := false

	for _, re := range pats {
		if re.MatchString(line) {
			ok = true
			break
		}
	}

	return ok
}
