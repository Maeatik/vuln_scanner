package analyzers

import (
	"context"
	"fmt"
	"os"
	"strings"
	"vuln-scanner/internal/gitutil"
	utils "vuln-scanner/utils/util"

	"github.com/rs/zerolog/log"
)

var analyzes []Analyzer = []Analyzer{
	NewSecretsAnalyzer(),
}

func AnalyzeRepo(ctx context.Context, repoURL string) (string, error) {
	dir, err := gitutil.Clone(repoURL)
	if err != nil {
		return "", fmt.Errorf("не удалось клонировать репозиторий: %v", err)
	}
	defer os.RemoveAll(dir)

	repoName := utils.ExtractRepoName(repoURL)

	branches, err := gitutil.GetBranches(dir)
	if err != nil {
		return "", fmt.Errorf("не удалось получить список веток: %w", err)
	}

	var fullReport strings.Builder
	fullReport.WriteString(fmt.Sprintf("Анализ репозитория `%s` по всем веткам:\n\n", repoName))

	for _, branch := range branches {
		// Переключаемся на ветку
		if err := gitutil.CheckoutBranch(dir, branch); err != nil {
			log.Warn().Msgf("не удалось чек-аутить ветку %s: %v", branch, err)
			continue
		}

		fullReport.WriteString(fmt.Sprintf("Ветка `%s`:\n", branch))

		for _, analyzer := range analyzes {
			log.Info().Msgf("запуск %q на ветке %s", analyzer.Name(), branch)
			res, err := analyzer.Run(repoName, dir)
			if err != nil {
				fullReport.WriteString(fmt.Sprintf("%s: ошибка: %v\n\n", analyzer.Name(), err))
				continue
			}
			// Добавляем результат конкретного анализатора
			fullReport.WriteString(res + "\n")
		}
		fullReport.WriteString("\n")
	}

	report := fullReport.String()
	if strings.TrimSpace(report) == fmt.Sprintf("🔍 Анализ репозитория `%s` по всем веткам:", repoName) {
		// ничего не нашлось кроме заголовка
		return "Секретов не найдено ни в одной ветке", nil
	}

	return report, nil
}
