package analyzers

import (
	"context"
	"fmt"
	"os"
	"vuln-scanner/internal/gitutil"
	utils "vuln-scanner/utils/util"

	"github.com/rs/zerolog/log"
)

var analyzes []Analyzer = []Analyzer{NewSecretsAnalyzer()}

func AnalyzeRepo(ctx context.Context, repoURL string) (string, error) {
	dir, err := gitutil.Clone(repoURL)
	if err != nil {
		return "", fmt.Errorf("не удалось клонировать репозиторий: %v", err)
	}
	defer os.RemoveAll(dir)

	repoName := utils.ExtractRepoName(repoURL)
	// Здесь может быть вызов конкретных анализаторов (секреты, зависимости и т.п.)
	// Пока заглушка:
	report := fmt.Sprintf("Репозиторий %s успешно клонирован.", repoURL)

	for _, analyze := range analyzes {
		log.Info().Msgf("start %v", analyze.Name())
		report, err = analyze.Run(repoName, dir)
		if err != nil {
			return "", fmt.Errorf("Ошибка проверки %v", err)
		}
	}

	return report, nil
}

