package analyzers

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	v1 "vuln-scanner/internal/entity"
	utils "vuln-scanner/utils/util"

	"github.com/rs/zerolog/log"
)

type SecretsAnalyzer struct{}

func NewSecretsAnalyzer() Analyzer {
	return &SecretsAnalyzer{}
}
func (s *SecretsAnalyzer) Name() string {
	return "Поиск секретов"
}

func (s *SecretsAnalyzer) Run(repoName, path, branch string) ([]v1.Finding, error) {
	var findings []v1.Finding

	log.Info().Msgf("[%v] walk for secret leaks started", repoName)
	err := filepath.Walk(path, func(file string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}

		if isTestOrMock(file) {
			return nil
		}

		if isTestOrMock(file) || !hasIgnoredExtension(file) || isIgnoredFilename(file) {
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

			if strings.Contains(line, "Access-Control-Allow-Credentials") {
				continue
			}

			// 2) Пропустить сигнатуры функций
			if v1.ReFuncSignature.MatchString(line) {
				continue
			}

			// 3) Пропустить простые вызовы методов/функций
			if v1.ReMethodCall.MatchString(line) {
				continue
			}

			for _, pattern := range v1.SecretPatterns {
				matches := pattern.FindAllString(line, -1)
				for _, match := range matches {
					cleaned := strings.Trim(match, `"' `)
					if v1.ReConstant.MatchString(cleaned) {
						continue
					}

					sev := s.Classify(cleaned)

					if strings.HasSuffix(strings.ToLower(file), ".env") {
						sev = v1.SevHigh
					}

					findings = append(findings, v1.Finding{
						Branch:   branch,
						File:     file,
						Line:     lineNum,
						Content:  strings.TrimSpace(line),
						Severity: sev,
					})

					// после первого валидного совпадения в строке — выходим к следующей строке
					break
				}
			}

			for _, outPat := range v1.OutputPatterns {
				if !outPat.MatchString(line) {
					continue
				}

				for _, namePat := range v1.VarNamePatterns {
					if !namePat.MatchString(line) {
						continue
					}

					findings = append(findings, v1.Finding{
						Branch:   branch,
						File:     file,
						Line:     lineNum,
						Content:  strings.TrimSpace(line),
						Severity: v1.SevHigh,
					})

					break
				}
			}

		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	log.Info().Msgf("[%v] walk for secret leaks ended", repoName)

	return findings, nil
}

func (s *SecretsAnalyzer) Classify(match string) v1.SeverityLevel {
	switch {
	case v1.ReAWSKey.MatchString(match), v1.ReGHToken.MatchString(match):
		return v1.SevHigh
	}

	e := utils.GetGeneratedProbability(match)
	switch {
	case e >= 0.75:
		return v1.SevHigh
	case e >= 0.5:
		return v1.SevMedium
	default:
		return v1.SevLow
	}
}

func hasIgnoredExtension(path string) bool {
	for _, ext := range v1.SupportedExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func isIgnoredFilename(filename string) bool {
	for _, ignored := range v1.IgnoredFilenames {
		if strings.EqualFold(filepath.Base(filename), ignored) {
			return true
		}
	}
	return false
}

func isTestOrMock(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "mock") ||
		strings.Contains(lower, "test") ||
		strings.HasSuffix(lower, "_test.go")
}
