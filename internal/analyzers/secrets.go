package analyzers

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
)

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)password\s*[:=]\s*["']?[\w\-!@#$%^&*()_+=]{4,}["']?`),
	regexp.MustCompile(`(?i)secret\s*[:=]\s*["']?[\w\-!@#$%^&*()_+=]{4,}["']?`),
	regexp.MustCompile(`(?i)api[_-]?key\s*[:=]\s*["']?[A-Za-z0-9_\-]{10,}["']?`),
	regexp.MustCompile(`(?i)token\s*[:=]\s*["']?[A-Za-z0-9\.\-_]{10,}["']?`),
	regexp.MustCompile(`(?i)Authorization\s*[:=]\s*["']?Bearer\s+[A-Za-z0-9\.\-_]{10,}["']?`),
	regexp.MustCompile(`(?i)[a-zA-Z0-9_\-]{32,}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),    // AWS Access Key
	regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`), // GitHub token
}

var supportedExtensions = []string{
	".go", ".py", ".js", ".ts", ".java", ".c", ".cpp", ".h", ".hpp", ".php", ".sh",
	".env", ".yml", ".yaml", ".json",
}

func hasIgnoredExtension(path string) bool {
	for _, ext := range supportedExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

var ignoredFilenames = []string{
	"go.mod", "go.sum",
	"requirements.txt", "Pipfile", "Pipfile.lock",
	"package.json", "package-lock.json", "yarn.lock",
	"pom.xml", "build.gradle", "build.gradle.kts",
	"composer.lock", "composer.json",
}

func isIgnoredFilename(filename string) bool {
	for _, ignored := range ignoredFilenames {
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

type SecretsAnalyzer struct{}

func NewSecretsAnalyzer() *SecretsAnalyzer {
	return &SecretsAnalyzer{}
}
func (s *SecretsAnalyzer) Name() string {
	return "Поиск секретов"
}

func (s *SecretsAnalyzer) Run(repoName, path string) (string, error) {
	var findings []string

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
			for _, pattern := range secretPatterns {
				if pattern.MatchString(line) {
					findings = append(findings,
						fmt.Sprintf("Возможный секрет в файле `%s`, строка %d:\n%s\n",
							file, lineNum, line))
				}
			}
		}

		return nil
	})

	log.Info().Msgf("[%v] walk for secret leaks ended", repoName)

	if err != nil {
		return "", err
	}

	log.Info().Msgf("[%v] number of findings = %d", repoName, len(findings))
	if len(findings) == 0 {
		return "Секреты не найдены", nil
	}

	return "Обнаружены возможные утечки:\n\n" + joinFindings(findings), nil
}

func joinFindings(findings []string) string {
	result := ""
	for _, f := range findings {
		result += f + "\n"
	}

	return result
}
